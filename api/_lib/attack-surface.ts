/**
 * VibeSecure — Attack Surface Map.
 *
 * Builds a flat, machine-readable picture of what the site exposes:
 *   - primary + base domain
 *   - CDN/edge in front
 *   - endpoints referenced in HTML, bundles, sitemap
 *   - third-party scripts loaded into the page
 *   - <form> entry points
 *   - auth providers + data backends
 *
 * Pure function: takes everything the scanner already collected and returns
 * a derived view. No new fetches. The cost is one HTML+bundle pass over
 * regex patterns — bounded and fast.
 *
 * Subdomain discovery (passive cert-transparency) is TODO — left empty
 * for v1.2 to keep latency under control. Ship the structure first;
 * fill subdomains in the next round once we accept the extra ~600ms call.
 */

import type { AttackSurface, CdnProvider } from '../../src/lib/scanner-types.js'

interface BuildInput {
  primaryDomain: string
  baseDomain: string
  finalUrl: string
  html: string
  bundleTextAll: string
  responseHeaders: Headers
  detected: {
    supabaseProjectIds: string[]
    s3BucketHosts: string[]
    firebaseIds: string[]
    aiEndpoints: string[]
  }
}

const MAX_ENDPOINTS = 80
const MAX_THIRD_PARTY = 40
const MAX_FORMS = 20

/**
 * Detect CDN/edge from response headers. Order matters: a Cloudflare-fronted
 * Vercel deploy still says `cf-ray`, so check Cloudflare first.
 */
function detectCdn(headers: Headers): CdnProvider {
  if (headers.get('cf-ray')) return 'cloudflare'
  if (headers.get('x-amz-cf-id')) return 'aws-cloudfront'
  if ((headers.get('server') || '').toLowerCase().includes('cloudfront')) return 'aws-cloudfront'
  if ((headers.get('x-served-by') || '').toLowerCase().includes('fastly')) return 'fastly'
  if (headers.get('x-cache') && headers.get('x-akamai-transformed')) return 'akamai'
  if ((headers.get('x-akamai-request-id') || '').length > 0) return 'akamai'
  if ((headers.get('server') || '').toLowerCase() === 'vercel') return 'vercel'
  if ((headers.get('server') || '').toLowerCase() === 'netlify') return 'netlify'
  if ((headers.get('x-sucuri-id') || '').length > 0) return 'sucuri'
  return null
}

/**
 * Extract auth/identity providers from bundle text. Heuristic — matches the
 * provider's globals or import paths that appear in shipped JS.
 */
function detectAuthProviders(html: string, bundleText: string): string[] {
  const providers = new Set<string>()
  const corpus = html + '\n' + bundleText
  const checks: { name: string; re: RegExp }[] = [
    { name: 'supabase', re: /@supabase\/(?:auth-js|supabase-js|ssr)|window\.supabase\b|supabase\.auth/i },
    { name: 'firebase', re: /firebase\/auth|getAuth\s*\(\s*\)|firebaseauth/i },
    { name: 'auth0', re: /@auth0\/(?:auth0-react|auth0-spa-js|nextjs-auth0)|auth0\.com\/api/i },
    { name: 'clerk', re: /@clerk\/(?:clerk-js|nextjs|clerk-react)|clerk\.dev|clerk\.com/i },
    { name: 'cognito', re: /AmazonCognitoIdentity|cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i },
    { name: 'okta', re: /@okta\/okta-(?:auth-js|signin-widget|react)|okta\.com\/oauth2/i },
    { name: 'google-identity', re: /accounts\.google\.com\/gsi\/client|gsi\.iframe/i },
    { name: 'magic', re: /@magic-(?:sdk|ext)\/|magic\.link/i },
    { name: 'firebase-app-check', re: /firebase\/app-check|appcheck/i },
  ]
  for (const c of checks) {
    if (c.re.test(corpus)) providers.add(c.name)
  }
  return Array.from(providers).sort()
}

/**
 * Extract API endpoints from HTML + bundles. Two strategies:
 *   1. fetch/axios call patterns that point at relative `/api/...` or absolute URLs
 *   2. anchor / form / iframe `href`/`src`/`action` to same-origin paths
 *
 * Output is deduped by path and capped at MAX_ENDPOINTS.
 */
function extractEndpoints(
  html: string,
  bundleText: string,
  primaryDomain: string,
  detectedAi: string[],
): AttackSurface['endpoints'] {
  const seen = new Map<string, AttackSurface['endpoints'][number]>()

  const add = (path: string, source: AttackSurface['endpoints'][number]['source']) => {
    if (!path) return
    const trimmed = path.split('#')[0].split('?')[0].trim()
    if (!trimmed || trimmed.length > 200) return
    if (seen.has(trimmed)) return
    seen.set(trimmed, { path: trimmed, source })
  }

  // From HTML — anchors, forms, iframes
  for (const m of html.matchAll(/<(?:a|form|iframe|link)\b[^>]*\b(?:href|action|src)\s*=\s*["']([^"']+)["']/gi)) {
    const url = m[1]
    if (url.startsWith('/') && !url.startsWith('//')) add(url, 'html')
    else if (url.includes(primaryDomain)) {
      try {
        const u = new URL(url)
        add(u.pathname, 'html')
      } catch {
        // invalid URL — skip
      }
    }
  }

  // From bundles — fetch / axios call sites
  // Strict-ish: require 'fetch(' or 'axios.<verb>(' or '"/api/' / '`/api/'
  const corpus = bundleText.slice(0, 1.5 * 1024 * 1024) // cap regex work
  // Pattern A: explicit fetch/axios calls with string literal first arg
  for (const m of corpus.matchAll(
    /(?:\bfetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*["'`](\/[^"'`\s,)]+|https?:\/\/[^"'`\s,)]+)["'`]/gi,
  )) {
    const arg = m[1]
    if (arg.startsWith('/')) add(arg, 'bundle')
    else if (arg.includes(primaryDomain)) {
      try {
        const u = new URL(arg)
        add(u.pathname, 'bundle')
      } catch {
        // skip
      }
    }
  }
  // Pattern B: bare /api/... or /v1/... path strings
  for (const m of corpus.matchAll(/["'`](\/(?:api|v1|v2|graphql|trpc)\/[A-Za-z0-9_\-./]+)["'`]/g)) {
    add(m[1], 'bundle')
  }

  // From AI endpoint detector — already classified
  for (const ep of detectedAi) {
    try {
      const url = ep.startsWith('http') ? new URL(ep) : null
      add(url ? url.pathname : ep, 'detected')
    } catch {
      add(ep, 'detected')
    }
  }

  return Array.from(seen.values())
    .sort((a, b) => a.path.localeCompare(b.path))
    .slice(0, MAX_ENDPOINTS)
}

/**
 * Third-party (cross-origin) <script src=...> URLs. First-party scripts on
 * the same primary domain are excluded — the surface map is about who else
 * gets to run JS in the page, which is the supply-chain question.
 */
function extractThirdPartyScripts(html: string, primaryDomain: string): string[] {
  const out = new Set<string>()
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    const src = m[1]
    if (!src.startsWith('http')) continue
    try {
      const u = new URL(src)
      if (u.hostname === primaryDomain) continue
      out.add(u.origin + u.pathname)
    } catch {
      // skip invalid
    }
    if (out.size >= MAX_THIRD_PARTY) break
  }
  return Array.from(out).sort()
}

/**
 * <form> entry points: action + method. Forms are interesting because
 * they're auth surfaces (login, signup), state-mutating endpoints (CSRF
 * targets), and data-collection endpoints (PII concerns).
 */
function extractForms(html: string): AttackSurface['forms'] {
  const out: AttackSurface['forms'] = []
  for (const m of html.matchAll(/<form\b([^>]*)>/gi)) {
    const attrs = m[1]
    const actionMatch = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)
    const methodMatch = attrs.match(/\bmethod\s*=\s*["']([^"']+)["']/i)
    out.push({
      action: actionMatch?.[1] || '(self)',
      method: (methodMatch?.[1] || 'GET').toUpperCase(),
    })
    if (out.length >= MAX_FORMS) break
  }
  return out
}

export function buildAttackSurface(input: BuildInput): AttackSurface {
  const cdn = detectCdn(input.responseHeaders)
  const authProviders = detectAuthProviders(input.html, input.bundleTextAll)
  const endpoints = extractEndpoints(
    input.html,
    input.bundleTextAll,
    input.primaryDomain,
    input.detected.aiEndpoints,
  )
  const thirdPartyScripts = extractThirdPartyScripts(input.html, input.primaryDomain)
  const forms = extractForms(input.html)

  const dataStores: AttackSurface['dataStores'] = []
  for (const id of input.detected.supabaseProjectIds) {
    dataStores.push({ kind: 'supabase', ref: `${id}.supabase.co` })
  }
  for (const host of input.detected.s3BucketHosts) {
    dataStores.push({ kind: 's3', ref: host })
  }
  for (const id of input.detected.firebaseIds) {
    dataStores.push({ kind: 'firebase', ref: id })
  }

  return {
    primaryDomain: input.primaryDomain,
    baseDomain: input.baseDomain,
    cdn,
    endpoints,
    thirdPartyScripts,
    forms,
    authProviders,
    dataStores,
    subdomains: [], // TODO v1.3: passive CT lookup via crt.sh
  }
}
