/**
 * Vguard scanner core. Server-side only — uses Node fetch + Buffer + DNS + TLS.
 * Pure function: runScan(url) → ScanResponse. No HTTP/Express coupling.
 */
import { promises as dns } from 'node:dns'
import * as tls from 'node:tls'
import { getDomain } from 'tldts'
import type { Finding, ScanResponse, Severity } from '../../src/lib/scanner-types.js'
import { enrichFindings } from './fix-prompt-composer.js'
import { aggregateBand, applyRisk, classifyRouteContext, computeAggregateRisk } from './risk-scorer.js'
import { applyEngine, defaultContext } from './scoring-engine.js'
import { buildAttackSurface, discoverSubdomainsFromCT } from './attack-surface.js'
import { analyzeBundles as analyzeBundlesAst } from './js-ast.js'

const FETCH_TIMEOUT_MS = 4000
const PROBE_TIMEOUT_MS = 2500
const MAX_BUNDLE_SIZE = 2 * 1024 * 1024 // 2 MB
const MAX_BUNDLES = 4

// WAFs (Cloudflare, Akamai, AWS WAF, Imperva) auto-block any UA that doesn't
// match a known browser shape — `Vguard-Scanner/0.1` would always 403 on them.
// Industry-standard approach for security scanners (Burp, ZAP, Acunetix) is a
// real Chrome UA. We append a `Vguard/1.0` token so site owners reading their
// access logs can still attribute the traffic.
const SCANNER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vguard/1.0 (+https://v-guards.com)'
// "Stealthier" UA used as a one-shot retry when the first request 4xx'd. No
// Vguard token, full Sec-Ch-Ua headers — looks indistinguishable from a real
// Chrome browser. Only used after an explicit block; not the default to keep
// us honest in normal-path access logs.
const STEALTH_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
const BROWSER_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
const BROWSER_ACCEPT_LANGUAGE = 'en-US,en;q=0.9,he;q=0.8'

// Headers a real Chrome 131 sends that bot detectors specifically look for.
// Their absence is itself a fingerprint — Cloudflare's "managed challenge"
// scores requests that lack `Sec-Fetch-*` and `Sec-Ch-Ua-*` as suspicious.
const STEALTH_HEADERS: Record<string, string> = {
  'User-Agent': STEALTH_UA,
  Accept: BROWSER_ACCEPT,
  'Accept-Language': BROWSER_ACCEPT_LANGUAGE,
  'Accept-Encoding': 'gzip, deflate, br, zstd',
  'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
  'Sec-Ch-Ua-Mobile': '?0',
  'Sec-Ch-Ua-Platform': '"Windows"',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
  'Cache-Control': 'max-age=0',
}

import type { WafVendor, SuggestedAction } from '../../src/lib/scanner-types.js'

/**
 * Identify the WAF/edge vendor from response headers + body sniff. Returns
 * `null` when no signals match (caller should treat as a generic block).
 *
 * Each branch is ordered by signal strength. We prefer specific identifying
 * headers (`cf-ray`, `x-amz-cf-id`) over generic ones (`server: cloudflare`)
 * because the specific ones are harder to spoof / misattribute.
 */
function detectWafVendor(resp: Response, body: string): WafVendor {
  const h = (name: string) => resp.headers.get(name) ?? ''
  const server = h('server').toLowerCase()
  const via = h('via').toLowerCase()
  const xPoweredBy = h('x-powered-by').toLowerCase()
  const lowerBody = body.slice(0, 4096).toLowerCase()

  // Cloudflare — most common WAF in our user base
  if (h('cf-ray') || h('cf-cache-status') || /\bcloudflare\b/.test(server)) return 'cloudflare'
  if (lowerBody.includes('attention required! | cloudflare') || lowerBody.includes('__cf_bm') ||
      lowerBody.includes('cf-error-details')) return 'cloudflare'

  // Akamai
  if (/akamai|akamaighost/.test(server) || h('x-akamai-transformed') || h('akamai-grn')) return 'akamai'
  if (lowerBody.includes('reference&#32;&#35;') && lowerBody.includes('akamai')) return 'akamai'

  // Imperva / Incapsula
  if (h('x-iinfo') || h('x-cdn') === 'Incapsula' || /imperva|incapsula/.test(server)) return 'imperva'
  if (lowerBody.includes('incapsula incident id')) return 'imperva'

  // Fastly — uses Varnish under the hood
  if (h('fastly-debug-digest') || /^fastly/i.test(h('x-served-by')) ||
      (/varnish/.test(via) && /^cache-/.test(h('x-served-by')))) return 'fastly'

  // AWS CloudFront (with or without AWS WAF in front)
  const isCloudFront = h('x-amz-cf-id') || /cloudfront/.test(via) || /cloudfront/.test(server)
  if (isCloudFront) {
    // AWS WAF returns 403 with a body containing this exact phrase
    if (resp.status === 403 && /request blocked/i.test(body.slice(0, 2048))) return 'aws-waf'
    return 'aws-cloudfront'
  }

  // Vercel BotID / Bot Protection — Vercel-hosted apps with bot protection on
  if (h('x-vercel-id') || /vercel/.test(server)) {
    if (lowerBody.includes('security checkpoint') || lowerBody.includes('botid:')) {
      return 'vercel-bot-protection'
    }
  }

  // Sucuri
  if (h('x-sucuri-id') || /sucuri/.test(server)) return 'sucuri'
  if (lowerBody.includes('sucuri website firewall')) return 'sucuri'

  // StackPath / MaxCDN
  if (/stackpath/i.test(h('x-cdn')) || /stackpath/i.test(server)) return 'stackpath'

  // DDoS-Guard
  if (/ddos-guard/.test(server) || h('x-ddosguard')) return 'ddos-guard'
  if (lowerBody.includes('ddos-guard.net')) return 'ddos-guard'

  // Generic AWS WAF (when CloudFront wasn't the intermediate)
  if (h('x-amzn-requestid') && resp.status === 403 && /request blocked|forbidden/i.test(body.slice(0, 2048))) {
    return 'aws-waf'
  }

  // Suspicious enough to flag as WAF without naming
  if (resp.status === 403 || resp.status === 406 || resp.status === 429 || resp.status === 451) {
    return 'unknown'
  }

  // 4xx without WAF signals — let caller treat as generic blocked_by_target
  return 'unknown'
}

const VENDOR_LABELS: Record<WafVendor, string> = {
  cloudflare: 'Cloudflare',
  akamai: 'Akamai',
  imperva: 'Imperva (Incapsula)',
  fastly: 'Fastly',
  'aws-cloudfront': 'AWS CloudFront',
  'aws-waf': 'AWS WAF',
  'vercel-bot-protection': 'Vercel Bot Protection',
  sucuri: 'Sucuri',
  stackpath: 'StackPath',
  'ddos-guard': 'DDoS-Guard',
  unknown: 'a WAF / firewall',
}

function suggestedActionFor(vendor: WafVendor, status: number): SuggestedAction {
  // Vercel Bot Protection only fires on heavy automation; a real user / Stage 2
  // browser bypasses it instantly.
  if (vendor === 'vercel-bot-protection') return 'stage2-bookmarklet'
  // Rate-limited responses → wait + retry, but a browser-origin run resolves it.
  if (status === 429) return 'stage2-bookmarklet'
  // 451 = legal block; not bypassable, no actionable next step.
  if (status === 451) return 'fix-target'
  // Default for any WAF: bookmarklet runs from user's origin → no WAF.
  return 'stage2-bookmarklet'
}

interface SecretPattern {
  name: string
  re: RegExp
  severity: Severity
  fixHint: string
  rotateUrl?: string
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'Anthropic API key',
    re: /sk-ant-api03-[A-Za-z0-9_-]{40,}/g,
    severity: 'critical',
    fixHint: 'Anthropic',
    rotateUrl: 'https://console.anthropic.com/settings/keys',
  },
  {
    name: 'OpenAI project key',
    re: /sk-proj-[A-Za-z0-9_-]{40,}/g,
    severity: 'critical',
    fixHint: 'OpenAI',
    rotateUrl: 'https://platform.openai.com/api-keys',
  },
  {
    name: 'OpenAI legacy secret key',
    re: /(?<![\w-])sk-[A-Za-z0-9]{48}(?![\w-])/g,
    severity: 'critical',
    fixHint: 'OpenAI',
    rotateUrl: 'https://platform.openai.com/api-keys',
  },
  {
    name: 'Google API key',
    re: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'warn',
    fixHint: 'Google',
    rotateUrl: 'https://console.cloud.google.com/apis/credentials',
  },
  {
    name: 'GitHub personal access token',
    re: /ghp_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    fixHint: 'GitHub',
    rotateUrl: 'https://github.com/settings/tokens',
  },
  {
    name: 'GitHub fine-grained PAT',
    re: /github_pat_[A-Za-z0-9_]{82}/g,
    severity: 'critical',
    fixHint: 'GitHub',
    rotateUrl: 'https://github.com/settings/tokens',
  },
  {
    name: 'Stripe live secret',
    re: /sk_live_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    fixHint: 'Stripe',
    rotateUrl: 'https://dashboard.stripe.com/apikeys',
  },
  {
    name: 'Slack bot token',
    re: /xoxb-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+/g,
    severity: 'critical',
    fixHint: 'Slack',
  },
  {
    name: 'Resend API key',
    re: /re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    fixHint: 'Resend',
    rotateUrl: 'https://resend.com/api-keys',
  },
  {
    name: 'AWS access key ID',
    re: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    fixHint: 'AWS',
    rotateUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  },
]

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g

const PATHS_TO_PROBE: { path: string; severity: Severity; label: string }[] = [
  { path: '/.env', severity: 'critical', label: '.env file' },
  { path: '/.env.production', severity: 'critical', label: '.env.production' },
  { path: '/.env.local', severity: 'critical', label: '.env.local' },
  { path: '/.git/HEAD', severity: 'critical', label: '.git/HEAD' },
  { path: '/.git/config', severity: 'warn', label: '.git/config' },
  { path: '/.DS_Store', severity: 'info', label: '.DS_Store' },
  { path: '/admin', severity: 'warn', label: '/admin route' },
  { path: '/wp-admin/', severity: 'info', label: 'WordPress admin' },
  { path: '/phpmyadmin/', severity: 'warn', label: 'phpMyAdmin' },
  { path: '/backup.zip', severity: 'critical', label: 'backup.zip' },
  { path: '/backup.sql', severity: 'critical', label: 'backup.sql' },
  { path: '/database.sql', severity: 'critical', label: 'database.sql' },
  { path: '/dump.sql', severity: 'critical', label: 'dump.sql' },
  { path: '/.aws/credentials', severity: 'critical', label: 'AWS credentials' },
  { path: '/config.json', severity: 'warn', label: 'config.json' },
  { path: '/composer.json', severity: 'info', label: 'composer.json (PHP)' },
  { path: '/package.json', severity: 'info', label: 'package.json' },
  { path: '/package-lock.json', severity: 'info', label: 'package-lock.json' },
  { path: '/yarn.lock', severity: 'info', label: 'yarn.lock' },
  { path: '/Dockerfile', severity: 'info', label: 'Dockerfile' },
  { path: '/docker-compose.yml', severity: 'warn', label: 'docker-compose.yml' },
  { path: '/server-status', severity: 'warn', label: 'Apache server-status' },
  { path: '/swagger.json', severity: 'info', label: 'swagger.json (API spec)' },
  { path: '/openapi.json', severity: 'info', label: 'openapi.json (API spec)' },
  { path: '/api-docs', severity: 'info', label: 'API docs route' },
  { path: '/graphql', severity: 'info', label: 'GraphQL endpoint' },
  { path: '/_health', severity: 'info', label: 'health-check endpoint' },
  { path: '/debug', severity: 'warn', label: '/debug route' },
  { path: '/.svn/entries', severity: 'critical', label: '.svn/entries' },
  { path: '/.hg/hgrc', severity: 'warn', label: '.hg/hgrc (Mercurial)' },
  { path: '/web.config', severity: 'info', label: 'web.config (IIS)' },
]

const HEADER_REQS: {
  name: string
  label: string
  severity: Severity
  fixPrompt: (url: string) => string
}[] = [
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy',
    severity: 'warn',
    fixPrompt: () =>
      `Add a strict Content-Security-Policy header. If this is a Vite/React app on Vercel, add it in vercel.json under "headers": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none'; base-uri 'self'; form-action 'self'". For Next.js, set it in next.config.ts headers(). Test with securityheaders.com after deploy.`,
  },
  {
    name: 'strict-transport-security',
    label: 'Strict-Transport-Security (HSTS)',
    severity: 'warn',
    fixPrompt: () =>
      `Add the Strict-Transport-Security header. Recommended value: "max-age=63072000; includeSubDomains; preload". On Vercel add it under headers in vercel.json. Once you ship it for 6+ months, submit your domain to https://hstspreload.org/.`,
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    severity: 'info',
    fixPrompt: () =>
      `Add the header "X-Content-Type-Options: nosniff" to every response. This blocks MIME-type sniffing attacks where a browser interprets a file as a different type than what was served. One line in vercel.json.`,
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    severity: 'info',
    fixPrompt: () =>
      `Add the header "Referrer-Policy: strict-origin-when-cross-origin". This stops your URLs (including any tokens you accidentally put in querystrings) from leaking to third parties via the Referer header on outgoing links.`,
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    severity: 'warn',
    fixPrompt: () =>
      `Add "X-Frame-Options: DENY" (or "SAMEORIGIN" if you legitimately iframe yourself) to block clickjacking. Modern browsers also honor "frame-ancestors 'none'" inside CSP — if your CSP already sets that, X-Frame-Options is belt-and-suspenders. On Vercel set it in vercel.json under headers.`,
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    severity: 'info',
    fixPrompt: () =>
      `Add a Permissions-Policy header to disable browser APIs you don't use. Conservative default: "Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()". Add only the features your app actually needs. This stops 3rd-party scripts from silently using device APIs.`,
  },
  {
    name: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy (COOP)',
    severity: 'info',
    fixPrompt: () =>
      `Add "Cross-Origin-Opener-Policy: same-origin" to isolate your top-level browsing context from cross-origin documents. Together with COEP, this enables process isolation that protects against Spectre-style cross-origin info leaks. Required if you want to use SharedArrayBuffer or high-resolution timers.`,
  },
  {
    name: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy (COEP)',
    severity: 'info',
    fixPrompt: () =>
      `Add "Cross-Origin-Embedder-Policy: require-corp" if your app needs cross-origin isolation (Spectre mitigation, SharedArrayBuffer, high-res timers). NOTE: this BLOCKS cross-origin sub-resources unless they explicitly opt in via CORP. If you load lots of 3rd-party scripts/images and don't need isolation, you can skip this.`,
  },
  {
    name: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy (CORP)',
    severity: 'info',
    fixPrompt: () =>
      `Add "Cross-Origin-Resource-Policy: same-origin" to declare that your resources should not be embedded by other origins. This is the resource-side counterpart to COEP. For public CDN content set "cross-origin"; for private content set "same-origin" (default-strict).`,
  },
]

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = FETCH_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController()
  const t = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, {
      redirect: 'follow',
      ...init,
      signal: controller.signal,
    })
  } finally {
    clearTimeout(t)
  }
}

function redactSecret(s: string): string {
  if (s.length < 12) return '***redacted***'
  return s.slice(0, 8) + '…' + s.slice(-4)
}

function shortPath(u: string): string {
  try {
    const url = new URL(u)
    const last = url.pathname.split('/').filter(Boolean).pop() || url.pathname
    return last
  } catch {
    return u
  }
}

/**
 * Legacy static scorer — kept only as a sanity floor / debug compare.
 * The live vibe score now comes from `scoring-engine.applyEngine`, which
 * does dynamic trait-based classification + diminishing returns. See
 * `api/_lib/scoring-engine.ts` for the design doc.
 */
function scoreFromTotals(t: { critical: number; warn: number; info: number }): number {
  return Math.max(0, 100 - t.critical * 20 - t.warn * 7 - t.info * 2)
}

async function readBoundedText(resp: Response, max: number): Promise<{ text: string; size: number }> {
  if (!resp.body) {
    const text = await resp.text()
    return { text: text.slice(0, max), size: text.length }
  }
  const reader = resp.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    chunks.push(value)
    total += value.byteLength
    if (total >= max) {
      try {
        await reader.cancel()
      } catch {
        // ignore
      }
      break
    }
  }
  const merged = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { text: new TextDecoder('utf-8').decode(merged), size: total }
}

function isPrivateHost(host: string): boolean {
  if (host === 'localhost' || host === '0.0.0.0') return true
  if (/^127\./.test(host)) return true
  if (/^10\./.test(host)) return true
  if (/^192\.168\./.test(host)) return true
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)) return true
  if (/^169\.254\./.test(host)) return true
  if (host.endsWith('.local')) return true
  return false
}

// === DNS / TLS / Methods helpers ===

const TAKEOVER_PRONE_HOSTS: { suffix: string; provider: string }[] = [
  { suffix: '.github.io', provider: 'GitHub Pages' },
  { suffix: '.herokuapp.com', provider: 'Heroku' },
  { suffix: '.vercel.app', provider: 'Vercel' },
  { suffix: '.netlify.app', provider: 'Netlify' },
  { suffix: '.cloudfront.net', provider: 'CloudFront' },
  { suffix: '.s3.amazonaws.com', provider: 'AWS S3' },
  { suffix: '.azurewebsites.net', provider: 'Azure App Service' },
  { suffix: '.elasticbeanstalk.com', provider: 'AWS Elastic Beanstalk' },
  { suffix: '.bitbucket.io', provider: 'Bitbucket' },
  { suffix: '.firebaseapp.com', provider: 'Firebase' },
  { suffix: '.pages.dev', provider: 'Cloudflare Pages' },
  { suffix: '.fly.dev', provider: 'Fly.io' },
]

// Platform-shared subdomains where the apex DNS is owned by the platform,
// not the user. DMARC/SPF/DNSSEC/CAA on the apex are NOT findings against
// the user — only the platform can publish them. We detect these explicitly
// so we don't generate fix-prompts that ask the user to add records on a
// domain they don't own.
const SHARED_PLATFORM_APEX: { suffix: string; provider: string }[] = [
  { suffix: '.vercel.app', provider: 'Vercel' },
  { suffix: '.netlify.app', provider: 'Netlify' },
  { suffix: '.pages.dev', provider: 'Cloudflare Pages' },
  { suffix: '.github.io', provider: 'GitHub Pages' },
  { suffix: '.fly.dev', provider: 'Fly.io' },
  { suffix: '.up.railway.app', provider: 'Railway' },
  { suffix: '.web.app', provider: 'Firebase Hosting' },
  { suffix: '.firebaseapp.com', provider: 'Firebase Hosting' },
  { suffix: '.herokuapp.com', provider: 'Heroku' },
  { suffix: '.azurewebsites.net', provider: 'Azure App Service' },
  { suffix: '.replit.app', provider: 'Replit' },
  { suffix: '.repl.co', provider: 'Replit' },
  { suffix: '.replit.dev', provider: 'Replit' },
  { suffix: '.lovable.app', provider: 'Lovable' },
  { suffix: '.lovable.dev', provider: 'Lovable' },
  { suffix: '.glitch.me', provider: 'Glitch' },
  { suffix: '.surge.sh', provider: 'Surge' },
  { suffix: '.bitbucket.io', provider: 'Bitbucket Pages' },
  { suffix: '.gitlab.io', provider: 'GitLab Pages' },
]

function detectSharedPlatform(host: string): { provider: string; apex: string } | null {
  const h = host.toLowerCase()
  for (const { suffix, provider } of SHARED_PLATFORM_APEX) {
    // Must be a *subdomain* of the platform apex, not the apex itself.
    const apex = suffix.slice(1)
    if (h.endsWith(suffix) && h !== apex) return { provider, apex }
  }
  return null
}

interface DnsSnapshot {
  spf: string | null
  dmarc: string | null
  hasDnskey: boolean
  caa: string[]
  cname: string | null
  baseDomain: string
}

function getBaseDomain(host: string): string {
  // Use the Public Suffix List to get the registrable domain.
  // The naive last-2-labels approach broke on every two-label eTLD
  // (`roiai.co.il` → `co.il`, `example.co.uk` → `co.uk`, `.com.au`, `.com.br`,
  // `.co.jp`, `.org.il`, `.ac.uk`, etc.), turning DMARC/SPF/DNSSEC/CAA queries
  // into eTLD lookups that always failed and produced false-positive findings.
  // `allowPrivateDomains` makes tldts treat platform suffixes (vercel.app,
  // netlify.app, pages.dev, …) as eTLDs, so `my-site.vercel.app` resolves to
  // itself rather than the platform-owned apex.
  const domain = getDomain(host, { allowPrivateDomains: true })
  if (domain) return domain
  // Fallback: keep the host as-is (raw IPs, localhost, eTLD-only inputs).
  return host
}

async function withDnsTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  let to: NodeJS.Timeout | undefined
  const timeout = new Promise<T>((resolve) => {
    to = setTimeout(() => resolve(fallback), ms)
  })
  try {
    return await Promise.race([p, timeout])
  } finally {
    if (to) clearTimeout(to)
  }
}

// Cloudflare DoH: probe DNSKEY records over HTTPS, since Node's dns.resolve
// rejects 'DNSKEY' as an rrtype (ERR_INVALID_ARG_VALUE on Node 24+).
async function probeDnskeyDoh(domain: string): Promise<boolean> {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DNSKEY`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(2500) },
    )
    if (!r.ok) return false
    const j = (await r.json()) as { Answer?: { type: number }[] }
    // DNSKEY rrtype = 48
    return Array.isArray(j.Answer) && j.Answer.some((a) => a.type === 48)
  } catch {
    return false
  }
}

async function gatherDns(host: string): Promise<DnsSnapshot> {
  const baseDomain = getBaseDomain(host)
  const dmarcHost = `_dmarc.${baseDomain}`

  // 3000ms upstream-DNS timeout. Vercel functions resolve through their own
  // resolver which is occasionally slow on country-code TLDs (.co.il, .co.uk
  // measured at 1.5–2.5s on cold start) — at 1500ms we'd false-positive
  // "no SPF" / "no DMARC" on legitimate records.
  const DNS_TIMEOUT_MS = 3000

  const txtRoot = await withDnsTimeout(
    dns.resolveTxt(baseDomain).catch(() => [] as string[][]),
    DNS_TIMEOUT_MS,
    [] as string[][],
  )
  const txtDmarc = await withDnsTimeout(
    dns.resolveTxt(dmarcHost).catch(() => [] as string[][]),
    DNS_TIMEOUT_MS,
    [] as string[][],
  )
  const hasDnskey = await probeDnskeyDoh(baseDomain)
  const caa = await withDnsTimeout(
    dns
      .resolveCaa(baseDomain)
      .catch(() => [] as { issue?: string; issuewild?: string; iodef?: string }[]),
    DNS_TIMEOUT_MS,
    [] as { issue?: string; issuewild?: string; iodef?: string }[],
  )
  const cname = await withDnsTimeout(
    dns.resolveCname(host).catch(() => [] as string[]),
    DNS_TIMEOUT_MS,
    [] as string[],
  )

  const spfRecord =
    txtRoot.map((parts) => parts.join('')).find((rec) => /^v=spf1\b/i.test(rec)) ?? null
  const dmarcRecord =
    txtDmarc.map((parts) => parts.join('')).find((rec) => /^v=DMARC1\b/i.test(rec)) ?? null

  return {
    spf: spfRecord,
    dmarc: dmarcRecord,
    hasDnskey,
    caa: caa
      .map((r) => `${r.issue ? 'issue ' + r.issue : ''}${r.issuewild ? 'issuewild ' + r.issuewild : ''}`.trim())
      .filter(Boolean),
    cname: cname[0] ?? null,
    baseDomain,
  }
}

interface TlsSnapshot {
  protocol: string | null
  cipher: string | null
  cert: { subject: string; issuer: string; valid_to: string } | null
  error: string | null
}

async function probeTls(host: string): Promise<TlsSnapshot> {
  return new Promise((resolve) => {
    let resolved = false
    const done = (snap: TlsSnapshot) => {
      if (resolved) return
      resolved = true
      resolve(snap)
    }
    const t = setTimeout(
      () => done({ protocol: null, cipher: null, cert: null, error: 'tls timeout' }),
      3000,
    )
    try {
      const sock = tls.connect(
        {
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false,
        },
        () => {
          const protocol = sock.getProtocol()
          const cipher = sock.getCipher()
          const peerCert = sock.getPeerCertificate()
          clearTimeout(t)
          sock.end()
          const subjectCN = peerCert?.subject?.CN
          const issuerCN = peerCert?.issuer?.CN
          done({
            protocol,
            cipher: cipher?.name ?? null,
            cert: peerCert
              ? {
                  subject: Array.isArray(subjectCN) ? subjectCN[0] ?? '' : subjectCN ?? '',
                  issuer: Array.isArray(issuerCN) ? issuerCN[0] ?? '' : issuerCN ?? '',
                  valid_to: peerCert.valid_to ?? '',
                }
              : null,
            error: null,
          })
        },
      )
      sock.on('error', (e) => {
        clearTimeout(t)
        done({ protocol: null, cipher: null, cert: null, error: e.message })
      })
    } catch (e) {
      clearTimeout(t)
      const msg = e instanceof Error ? e.message : 'unknown tls error'
      done({ protocol: null, cipher: null, cert: null, error: msg })
    }
  })
}

async function probeOptions(targetUrl: string): Promise<{ allow: string | null; trace: boolean }> {
  let allow: string | null = null
  let trace = false
  try {
    const r = await fetchWithTimeout(targetUrl, { method: 'OPTIONS' }, 2500)
    allow = r.headers.get('allow')
  } catch {
    // ignore
  }
  if (allow && /\bTRACE\b/i.test(allow)) trace = true
  return { allow, trace }
}

// Firebase RTDB probe — `/.json` returns the full root if rules allow read
async function probeFirebaseRTDB(
  origin: string,
): Promise<{ exposed: boolean; sample: string; bytes: number } | null> {
  try {
    const url = new URL('/.json', origin).toString()
    const r = await fetchWithTimeout(url, { method: 'GET' }, PROBE_TIMEOUT_MS)
    if (!r.ok) return null
    const ctype = r.headers.get('content-type') ?? ''
    if (!ctype.toLowerCase().includes('application/json')) return null
    const text = (await r.text()).slice(0, 1024)
    if (text.trim() === 'null' || text.trim() === '{}' || text.length < 8) return null
    try {
      JSON.parse(text)
      return { exposed: true, sample: text.slice(0, 200), bytes: text.length }
    } catch {
      return null
    }
  } catch {
    return null
  }
}

// Robots.txt + sitemap analysis
const SUSPICIOUS_ROBOT_PATHS = [
  /\/admin/i,
  /\/api\//i,
  /\/internal/i,
  /\/private/i,
  /\/debug/i,
  /\/staging/i,
  /\/dev\b/i,
  /\/test\b/i,
  /\/_next\/data\//i,
  /\/backup/i,
  /\/secret/i,
  /\/wp-admin/i,
]

async function fetchRobots(origin: string): Promise<string | null> {
  try {
    const r = await fetchWithTimeout(new URL('/robots.txt', origin).toString(), {}, 2000)
    if (!r.ok) return null
    const txt = await r.text()
    if (txt.length > 16 * 1024) return txt.slice(0, 16 * 1024)
    return txt
  } catch {
    return null
  }
}

// Sitemap.xml analyzer — fetch sitemap, extract <loc>, flag internal-looking URLs
const SUSPICIOUS_SITEMAP_PATHS = [
  /\/admin\b/i,
  /\/internal\b/i,
  /\/staging\b/i,
  /\/dev\b/i,
  /\/test\b/i,
  /\/draft\b/i,
  /\/preview\b/i,
  /\/api\/internal\b/i,
  /\/api\/admin\b/i,
  /\/_/i, // _next, _admin etc.
]

async function fetchSitemap(origin: string, robotsTxt: string | null): Promise<string | null> {
  // Prefer the sitemap from robots.txt if present
  let sitemapUrl: string
  if (robotsTxt) {
    const m = /Sitemap:\s*(\S+)/i.exec(robotsTxt)
    if (m) {
      sitemapUrl = m[1].trim()
    } else {
      sitemapUrl = new URL('/sitemap.xml', origin).toString()
    }
  } else {
    sitemapUrl = new URL('/sitemap.xml', origin).toString()
  }
  try {
    const r = await fetchWithTimeout(sitemapUrl, {}, 2500)
    if (!r.ok) return null
    const txt = await r.text()
    if (txt.length > 256 * 1024) return txt.slice(0, 256 * 1024)
    return txt
  } catch {
    return null
  }
}

// DKIM common-selector enumeration
const DKIM_COMMON_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  's1',
  's2',
  'dkim',
  'mail',
  'email',
  'mxvault',
  'k1',
  'k2',
  'mandrill',
  'pm-bounces',
  'mta',
  // Vendor-specific selectors observed in the wild (2026-05). Each provider
  // uses its own fixed selector — without these in the probe set, sites that
  // *do* have DKIM via Resend/SES/Postmark/etc. would falsely fail the check.
  'resend',         // Resend (resend._domainkey)
  'amazonses',      // AWS SES standalone
  'postmark',       // Postmark legacy
  'sg',             // SendGrid (sg._domainkey)
  'sm',             // SparkPost / Mailtrap
  'mailgun',        // Mailgun (mailgun._domainkey)
  'fm1',            // Fastmail (fm1._domainkey)
  'fm2',
  'fm3',
  'protonmail',     // ProtonMail
  'protonmail2',
  'protonmail3',
  'zoho',           // Zoho Mail
]

// A valid DKIM TXT record must contain a public key (p=...). The version tag
// (v=DKIM1) is RECOMMENDED but OPTIONAL per RFC 6376 §3.6.1 — major providers
// like Resend and AWS SES publish records WITHOUT the v= tag (just p=<base64>).
// Filtering on `v=DKIM1` alone false-fails those records. Match either pattern.
const DKIM_RECORD_RE = /(?:\bv=DKIM1\b)|(?:\bp=[A-Za-z0-9+/=]{40,})/i

async function probeDkim(baseDomain: string): Promise<{ selector: string; record: string } | null> {
  const probes = await Promise.all(
    DKIM_COMMON_SELECTORS.map(async (selector) => {
      const records = await withDnsTimeout(
        dns.resolveTxt(`${selector}._domainkey.${baseDomain}`).catch(() => [] as string[][]),
        700,
        [] as string[][],
      )
      const flat = records.map((parts) => parts.join('')).find((rec) => DKIM_RECORD_RE.test(rec))
      return flat ? { selector, record: flat } : null
    }),
  )
  return probes.find((p): p is { selector: string; record: string } => p !== null) ?? null
}

// Auth signup endpoint probing (passive — GET only)
const SIGNUP_ENDPOINTS = [
  { path: '/auth/v1/signup', label: 'Supabase signup' },
  { path: '/auth/signup', label: 'Generic /auth/signup' },
  { path: '/api/auth/signup', label: 'NextAuth-style signup' },
  { path: '/api/signup', label: 'Generic API signup' },
  { path: '/api/register', label: 'Generic API register' },
]

async function probeSignupEndpoints(
  origin: string,
): Promise<{ path: string; label: string; status: number }[]> {
  const found: { path: string; label: string; status: number }[] = []
  await Promise.all(
    SIGNUP_ENDPOINTS.map(async (ep) => {
      try {
        const url = new URL(ep.path, origin).toString()
        const r = await fetchWithTimeout(url, { method: 'GET' }, 2000)
        if (r.status === 404 || r.status === 0) return
        // Many SPAs (Vite/CRA on Vercel/Netlify) have a catch-all rewrite that returns
        // index.html for every unknown path → 200 with HTML body. Without filtering
        // those out, this detector fires on every SPA regardless of whether a real
        // signup endpoint exists. Treat HTML responses on the scanned origin as
        // SPA catch-all, not a signup endpoint.
        const ct = (r.headers.get('content-type') ?? '').toLowerCase()
        if (ct.includes('text/html')) return
        found.push({ path: ep.path, label: ep.label, status: r.status })
      } catch {
        // network/timeout — skip
      }
    }),
  )
  return found
}

// Supabase storage public bucket probe
const COMMON_SUPABASE_BUCKETS = [
  'avatars',
  'public',
  'images',
  'uploads',
  'files',
  'media',
  'attachments',
  'profiles',
  'documents',
  'assets',
]

async function probeSupabaseStorage(
  projectRef: string,
): Promise<{ bucket: string; status: number }[]> {
  const found: { bucket: string; status: number }[] = []
  await Promise.all(
    COMMON_SUPABASE_BUCKETS.map(async (bucket) => {
      try {
        // Listing endpoint: POST /storage/v1/object/list/<bucket> with anon key
        // Public read: GET /storage/v1/bucket/<bucket> requires service role
        // Easier passive check: GET /storage/v1/object/public/<bucket>/ — if bucket public + dir listing allowed, returns JSON listing
        const url = `https://${projectRef}.supabase.co/storage/v1/object/public/${bucket}/`
        const r = await fetchWithTimeout(url, { method: 'GET' }, 2000)
        // 200 with JSON array = bucket public + directory listing exposed (rare but bad)
        // 400 — Supabase returns 400 BOTH for "exists, listing blocked" AND for
        //       "bucket not found" (body distinguishes them). We must read the body.
        // 404 = sometimes also "not found"
        if (r.status === 200) {
          const ct = r.headers.get('content-type') ?? ''
          if (ct.includes('application/json')) {
            const text = (await r.text()).slice(0, 500)
            if (text.startsWith('[') || text.includes('"name"')) {
              found.push({ bucket, status: 200 })
            }
          }
        } else if (r.status === 400) {
          // Read body to distinguish "exists" vs "not found".
          // Supabase storage error shapes seen in the wild:
          //   not found: {"statusCode":"404","error":"not_found","message":"Bucket not found"}
          //   not found: {"statusCode":"404","error":"Not Found","message":"Bucket not found"}
          //   exists/blocked: {"statusCode":"400","error":"InvalidRequest","message":"object name is not provided"}
          // Without this filter, we fire on every common bucket name regardless of whether the bucket actually exists.
          const text = (await r.text()).slice(0, 500).toLowerCase()
          const looksLikeNotFound =
            text.includes('bucket not found') ||
            text.includes('"statuscode":"404"') ||
            text.includes('"error":"not_found"') ||
            text.includes('"error":"not found"')
          if (!looksLikeNotFound) {
            found.push({ bucket, status: 400 })
          }
        }
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// S3 bucket probing — find s3 references in HTML/bundles, probe each for ListBucket
async function probeS3Buckets(
  bucketHosts: string[],
): Promise<{ bucket: string; listAllowed: boolean }[]> {
  const found: { bucket: string; listAllowed: boolean }[] = []
  await Promise.all(
    bucketHosts.slice(0, 5).map(async (bucketHost) => {
      try {
        const url = `https://${bucketHost}/?list-type=2&max-keys=1`
        const r = await fetchWithTimeout(url, { method: 'GET' }, 2000)
        if (r.status === 200) {
          const text = (await r.text()).slice(0, 1024)
          if (text.includes('<ListBucketResult') || text.includes('<Contents>')) {
            found.push({ bucket: bucketHost, listAllowed: true })
          }
        }
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// npm CVE table — focused on packages we can fingerprint by version-string in bundles
interface NpmCve {
  pkg: string
  match: RegExp
  severity: Severity
  cve: string
  note: string
}
const NPM_CVES: NpmCve[] = [
  {
    pkg: 'axios',
    match: /"axios"\s*:\s*"[\^~]?(0\.[0-9]\.|0\.1[0-9]\.|0\.2[0-5]\.)/i,
    severity: 'warn',
    cve: 'CVE-2023-45857',
    note: 'axios <1.6.0 has SSRF/CSRF in cookie handling',
  },
  {
    pkg: 'lodash',
    match: /"lodash"\s*:\s*"[\^~]?[0-3]\./i,
    severity: 'warn',
    cve: 'CVE-2019-10744',
    note: 'lodash <4.17.21 has prototype pollution',
  },
  {
    pkg: 'next',
    match: /"next"\s*:\s*"[\^~]?(1[0-2]\.|13\.0\.|13\.1\.|13\.2\.|13\.3\.|13\.4\.[0-9]\.)/i,
    severity: 'warn',
    cve: 'CVE-2024-34351',
    note: 'next <13.5.1 has SSRF in image optimization',
  },
  {
    pkg: 'jsonwebtoken',
    match: /"jsonwebtoken"\s*:\s*"[\^~]?[0-7]\./i,
    severity: 'critical',
    cve: 'CVE-2022-23529',
    note: 'jsonwebtoken <9.0.0 has signature verification bypass',
  },
  {
    pkg: 'jquery',
    match: /"jquery"\s*:\s*"[\^~]?[12]\./i,
    severity: 'warn',
    cve: 'CVE-2020-11023',
    note: 'jQuery <3.5.0 has XSS via HTML parsing',
  },
  {
    pkg: 'express',
    match: /"express"\s*:\s*"[\^~]?[0-3]\./i,
    severity: 'warn',
    cve: 'multiple',
    note: 'Express 0/1/2/3.x are end-of-life with multiple unpatched issues',
  },
  {
    pkg: 'moment',
    match: /"moment"\s*:\s*"[\^~]?2\.(?:[0-9]|1[0-9]|2[0-8])\./i,
    severity: 'info',
    cve: 'CVE-2022-31129',
    note: 'moment <2.29.4 has ReDoS; also moment is deprecated, prefer date-fns / dayjs',
  },
  {
    pkg: 'minimist',
    match: /"minimist"\s*:\s*"[\^~]?(?:0\.|1\.[0-1]\.|1\.2\.[0-5][^0-9])/i,
    severity: 'warn',
    cve: 'CVE-2021-44906',
    note: 'minimist <1.2.6 has prototype pollution',
  },
  {
    pkg: 'node-fetch',
    match: /"node-fetch"\s*:\s*"[\^~]?(?:1\.|2\.[0-5]\.|2\.6\.[0-6])/i,
    severity: 'warn',
    cve: 'CVE-2022-0235',
    note: 'node-fetch <2.6.7 leaks cookies on cross-site redirect',
  },
  {
    pkg: 'follow-redirects',
    match: /"follow-redirects"\s*:\s*"[\^~]?(?:0\.|1\.1[0-5]\.[0-9]+)/i,
    severity: 'warn',
    cve: 'CVE-2024-28849',
    note: 'follow-redirects <1.15.6 leaks Authorization header on cross-host redirect',
  },
  {
    pkg: 'semver',
    match: /"semver"\s*:\s*"[\^~]?(?:[0-4]\.|5\.[0-6]\.|6\.[0-2]\.|7\.[0-4]\.)/i,
    severity: 'info',
    cve: 'CVE-2022-25883',
    note: 'semver <7.5.2 has ReDoS in range parsing',
  },
  {
    pkg: 'webpack',
    match: /"webpack"\s*:\s*"[\^~]?[0-4]\./i,
    severity: 'info',
    cve: 'multiple',
    note: 'webpack <5 is no longer actively maintained for security',
  },
  {
    pkg: 'xml2js',
    match: /"xml2js"\s*:\s*"[\^~]?(?:0\.[0-3]\.|0\.4\.[0-1][0-9]|0\.4\.2[0-2])/i,
    severity: 'warn',
    cve: 'CVE-2023-0842',
    note: 'xml2js <0.5.0 has prototype pollution',
  },
  {
    pkg: 'tar',
    match: /"tar"\s*:\s*"[\^~]?(?:[0-5]\.|6\.[0-1]\.[0-9]+)/i,
    severity: 'warn',
    cve: 'CVE-2024-28863',
    note: 'tar <6.2.1 has DoS during file extraction',
  },
  {
    pkg: 'undici',
    match: /"undici"\s*:\s*"[\^~]?(?:[0-4]\.|5\.[0-1][0-9]\.|5\.2[0-7]\.)/i,
    severity: 'warn',
    cve: 'CVE-2024-24750',
    note: 'undici <5.28.4 has memory leak / data leak via headers',
  },
  {
    pkg: 'cookie',
    match: /"cookie"\s*:\s*"[\^~]?0\.[0-6]\./i,
    severity: 'info',
    cve: 'CVE-2024-47764',
    note: 'cookie <0.7.0 has sloppy parsing of name/value/domain',
  },
  {
    pkg: 'cross-spawn',
    match: /"cross-spawn"\s*:\s*"[\^~]?(?:[0-6]\.|7\.0\.[0-4][^0-9])/i,
    severity: 'warn',
    cve: 'CVE-2024-21538',
    note: 'cross-spawn <7.0.5 has ReDoS',
  },
  {
    pkg: 'react',
    match: /"react"\s*:\s*"[\^~]?(?:1[0-5]\.|16\.[0-12]\.)/i,
    severity: 'info',
    cve: 'multiple',
    note: 'React <16.13 has known XSS issues; also out-of-support',
  },
  {
    pkg: 'vite',
    match: /"vite"\s*:\s*"[\^~]?(?:[0-3]\.|4\.[0-4]\.|4\.5\.[0-1])/i,
    severity: 'warn',
    cve: 'CVE-2024-31207',
    note: 'vite <4.5.2 / <5.0.12 has path traversal in dev server',
  },
]

// Open Redirect probing
const OPEN_REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri', 'continue']
const REDIRECT_CANARY = 'https://example.com/'

async function probeOpenRedirect(
  baseUrl: string,
): Promise<{ param: string; redirectsTo: string }[]> {
  const found: { param: string; redirectsTo: string }[] = []
  await Promise.all(
    OPEN_REDIRECT_PARAMS.map(async (param) => {
      try {
        const u = new URL(baseUrl)
        u.searchParams.set(param, REDIRECT_CANARY)
        const r = await fetchWithTimeout(u.toString(), { method: 'GET', redirect: 'manual' }, 2500)
        if (r.status >= 300 && r.status < 400) {
          const loc = r.headers.get('location')
          if (loc && loc.startsWith(REDIRECT_CANARY)) {
            found.push({ param, redirectsTo: loc })
          }
        }
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// Firebase Storage public probe
async function probeFirebaseStorage(
  projectId: string,
): Promise<{ exposed: boolean; sample: string } | null> {
  try {
    const url = `https://firebasestorage.googleapis.com/v0/b/${projectId}.appspot.com/o?maxResults=5`
    const r = await fetchWithTimeout(url, { method: 'GET' }, 2500)
    if (!r.ok) return null
    const text = (await r.text()).slice(0, 1024)
    if (text.includes('"items"') || text.includes('"name"')) {
      return { exposed: true, sample: text.slice(0, 200) }
    }
    return null
  } catch {
    return null
  }
}

// Supabase Edge Function discovery
const COMMON_EDGE_FUNCTIONS = [
  'chat',
  'ai',
  'webhook',
  'email',
  'send-email',
  'auth',
  'admin',
  'process',
  'callback',
  'notify',
  'sync',
  'export',
]

async function probeEdgeFunctions(
  projectRef: string,
): Promise<{ name: string; status: number; cors: string | null }[]> {
  const found: { name: string; status: number; cors: string | null }[] = []
  await Promise.all(
    COMMON_EDGE_FUNCTIONS.map(async (name) => {
      try {
        const url = `https://${projectRef}.supabase.co/functions/v1/${name}`
        // OPTIONS first to check CORS without invoking
        const r = await fetchWithTimeout(url, { method: 'OPTIONS' }, 2000)
        if (r.status !== 404 && r.status !== 0) {
          const cors = r.headers.get('access-control-allow-origin')
          found.push({ name, status: r.status, cors })
        }
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// Reflected XSS canary probing
const XSS_CANARY = 'vsxsscanary7q3'
const XSS_PARAMS = ['q', 'search', 'query', 's', 'name', 'id']

async function probeReflectedXss(
  baseUrl: string,
): Promise<{ param: string; reflectedRaw: boolean }[]> {
  const found: { param: string; reflectedRaw: boolean }[] = []
  await Promise.all(
    XSS_PARAMS.map(async (param) => {
      try {
        const u = new URL(baseUrl)
        u.searchParams.set(param, `<${XSS_CANARY}>`)
        const r = await fetchWithTimeout(u.toString(), { method: 'GET' }, 2500)
        if (!r.ok) return
        const ct = r.headers.get('content-type') ?? ''
        if (!ct.toLowerCase().includes('text/html')) return
        const body = (await r.text()).slice(0, 256 * 1024)
        const reflectedRaw = body.includes(`<${XSS_CANARY}>`)
        if (reflectedRaw) found.push({ param, reflectedRaw })
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// SQLi error-based detection
const SQLI_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /unclosed quotation mark/i,
  /ORA-\d{5}/,
  /PG(?:::|\s)SyntaxError/i,
  /sqlite3\.(?:Operational|Programming)Error/,
  /SQLSTATE\[\w+\]/i,
  /MySQLSyntaxErrorException/i,
  /SQLException/,
  /Microsoft OLE DB Provider for ODBC Drivers/i,
  /unterminated quoted string/i,
]
const SQLI_PARAMS = ['id', 'q', 'search', 'page', 'category']

async function probeSqliErrors(
  baseUrl: string,
): Promise<{ param: string; pattern: string }[]> {
  const found: { param: string; pattern: string }[] = []
  await Promise.all(
    SQLI_PARAMS.map(async (param) => {
      try {
        const u = new URL(baseUrl)
        u.searchParams.set(param, "'")
        const r = await fetchWithTimeout(u.toString(), { method: 'GET' }, 2500)
        if (!r.ok && r.status < 500) return
        const body = (await r.text()).slice(0, 64 * 1024)
        for (const pat of SQLI_ERROR_PATTERNS) {
          const m = pat.exec(body)
          if (m) {
            found.push({ param, pattern: m[0].slice(0, 80) })
            return
          }
        }
      } catch {
        // ignore
      }
    }),
  )
  return found
}

// AI endpoint passive detection
const AI_ENDPOINT_PATTERNS = [
  /\/api\/chat\b/gi,
  /\/api\/ai\b/gi,
  /\/api\/completion\b/gi,
  /\/api\/generate\b/gi,
  /\/api\/llm\b/gi,
  /\/v1\/chat\/completions\b/gi,
  /\/api\/agent\b/gi,
  /\/api\/copilot\b/gi,
]

function detectAiEndpoints(html: string, bundlesText: string): string[] {
  const haystack = html + bundlesText
  const matches = new Set<string>()
  for (const pat of AI_ENDPOINT_PATTERNS) {
    pat.lastIndex = 0
    for (const m of haystack.matchAll(pat)) {
      matches.add(m[0])
      if (matches.size >= 6) return Array.from(matches)
    }
  }
  return Array.from(matches)
}

// HTTP→HTTPS redirect check
async function probeHttpToHttps(
  hostname: string,
): Promise<{ redirects: boolean; finalProtocol: string | null }> {
  try {
    const r = await fetchWithTimeout(
      `http://${hostname}/`,
      { method: 'GET', redirect: 'manual' },
      2500,
    )
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location')
      if (loc && loc.startsWith('https://')) {
        return { redirects: true, finalProtocol: 'https' }
      }
    }
    if (r.status === 200) {
      return { redirects: false, finalProtocol: 'http' }
    }
    return { redirects: false, finalProtocol: null }
  } catch {
    return { redirects: false, finalProtocol: null }
  }
}

// Server CVE lookup table — known-bad versions
interface ServerCve {
  match: RegExp
  severity: Severity
  cves: string[]
  note: string
}
const SERVER_CVES: ServerCve[] = [
  {
    match: /^Apache\/2\.4\.49\b/i,
    severity: 'critical',
    cves: ['CVE-2021-41773'],
    note: 'Path traversal + RCE in mod_alias',
  },
  {
    match: /^Apache\/2\.4\.50\b/i,
    severity: 'critical',
    cves: ['CVE-2021-42013'],
    note: 'Incomplete fix for CVE-2021-41773 — still vulnerable',
  },
  {
    match: /^Apache\/2\.4\.5[12]\b/i,
    severity: 'warn',
    cves: ['CVE-2022-22720'],
    note: 'HTTP request smuggling in mod_proxy_ajp, fixed in 2.4.53',
  },
  {
    match: /^Apache\/2\.[0-3]\./i,
    severity: 'warn',
    cves: ['multiple-EOL'],
    note: 'Apache 2.0/2.1/2.2/2.3 are end-of-life with multiple unpatched issues',
  },
  {
    match: /^nginx\/1\.(?:1[0-5]|[0-9])\.\d+/i,
    severity: 'warn',
    cves: ['CVE-2019-9511', 'CVE-2019-9513', 'CVE-2019-9516'],
    note: 'HTTP/2 DoS family, fixed in nginx 1.16.1+',
  },
  {
    match: /^nginx\/1\.18\.0\b/i,
    severity: 'info',
    cves: ['CVE-2021-23017'],
    note: 'DNS resolver heap-buffer overflow, fixed in 1.20.1',
  },
  {
    match: /^nginx\/1\.20\.0\b|^nginx\/1\.21\.[0-5]\b/i,
    severity: 'info',
    cves: ['CVE-2022-41741', 'CVE-2022-41742'],
    note: 'mp4 module memory corruption, fixed in 1.23.2',
  },
  {
    match: /\bIIS\/[6-9]\./i,
    severity: 'warn',
    cves: ['various-EOL'],
    note: 'IIS 6/7/8/9 are end-of-life — multiple unpatched issues',
  },
  {
    match: /\bIIS\/10\.0\b/i,
    severity: 'info',
    cves: ['CVE-2022-21907'],
    note: 'HTTP Protocol Stack RCE, fully patched on Win Server 2019/2022 only with KB5009557+',
  },
  {
    match: /\bExpress\/3\.|\bExpress\/2\./i,
    severity: 'warn',
    cves: ['multiple-EOL'],
    note: 'Express 2.x/3.x are end-of-life since 2014',
  },
  {
    match: /^Werkzeug\/(?:[0-1]\.|2\.[0-2]\.)/i,
    severity: 'info',
    cves: ['CVE-2023-25577'],
    note: 'Werkzeug <2.2.3 has DoS via multipart parsing',
  },
  {
    match: /^gunicorn\/(?:1[6-9]\.|20\.[0-1]\.|21\.[01]\.)/i,
    severity: 'info',
    cves: ['CVE-2024-1135'],
    note: 'gunicorn <22.0.0 has HTTP request smuggling via TE header',
  },
  {
    match: /^WSGIServer\/0\.[01]\b/i,
    severity: 'critical',
    cves: ['development-server'],
    note: 'Django dev server in production — never. Switch to gunicorn / uvicorn.',
  },
  {
    match: /\bExpress\/4\.(?:1[0-6]|[0-9])\./i,
    severity: 'info',
    cves: ['CVE-2022-24999'],
    note: 'Express <4.17.3 has qs prototype-pollution via deeply nested objects',
  },
  {
    match: /\bPHP\/(?:[0-6]\.|7\.[0-3]\.|8\.0\.)/i,
    severity: 'warn',
    cves: ['multiple-EOL'],
    note: 'PHP <8.1 is end-of-life, multiple unpatched CVEs',
  },
  {
    match: /\bASP\.NET\b.*\b1\.[0-1]\b|\bASP\.NET\b.*\b2\.0\b/i,
    severity: 'warn',
    cves: ['multiple-EOL'],
    note: 'ASP.NET 1.x/2.0 is end-of-life — upgrade to .NET 6+',
  },
  {
    match: /\bcaddy\/(?:[01]\.|2\.[0-5]\.)/i,
    severity: 'info',
    cves: ['CVE-2022-29718'],
    note: 'Caddy <2.6 had HTTP/2 reverse-proxy issues',
  },
  {
    match: /\bOpenSSL\/(?:0\.|1\.0\.|1\.1\.0[a-i]?)/i,
    severity: 'critical',
    cves: ['multiple-EOL'],
    note: 'OpenSSL <1.1.1 is end-of-life with known unpatched issues',
  },
  {
    match: /\bnginx\/1\.21\.[6-9]|\bnginx\/1\.22\.0\b/i,
    severity: 'info',
    cves: ['CVE-2022-41741'],
    note: 'nginx <1.23.2 mp4 module memory corruption',
  },
  {
    match: /\bcouchdb\/(?:[0-2]\.|3\.[0-2]\.)/i,
    severity: 'critical',
    cves: ['CVE-2022-24706'],
    note: 'CouchDB <3.2.2 has Erlang cookie auth bypass — RCE',
  },
]

/**
 * Stage 2.5 / S2+5 — Privilege leak signals.
 *
 * Discovers admin / internal route paths referenced inside the JS bundles
 * (react-router <Route path>, next.js page chunks, raw string literals on
 * sensitive prefixes), then probes each candidate without auth. A 200 from
 * an unauthenticated GET on an admin route is the smoking-gun for broken
 * access control — much stronger signal than the generic `/admin` path
 * probe in PATHS_TO_PROBE because these are routes the developer's own
 * code references, not blind dictionary guesses.
 *
 * Cap: 10 candidates per scan, 2.5s per probe, parallel — total ~3-4s.
 */
const ADMIN_PREFIX_RE = /(\/(?:admin|internal|private|dashboard|backoffice|control|console|cms|manage|management|backend|sysadmin|root|superuser|impersonate|users\/admin|settings\/admin|tenants|orgs)\b[^"'\`?#\s]*)/i

const ADMIN_HARD_PREFIXES = [
  '/admin',
  '/internal',
  '/private',
  '/backoffice',
  '/management',
]

/**
 * S1+4 — API / behavior analysis (passive + lightweight active).
 *
 * Three probes: OpenAPI/Swagger spec exposure, GraphQL endpoint presence,
 * and tRPC client signature in the bundle. None require user consent —
 * GET-only against well-known paths, no payloads.
 *
 *   - OpenAPI spec: if /openapi.json or /swagger.json or /api-docs returns
 *     JSON with the right shape, extract { path, methods } pairs. Public
 *     specs are extremely common in Next.js + tRPC + FastAPI projects.
 *   - GraphQL: GET /graphql returns 400 with PersistedQueryNotSupported /
 *     "GET requests only support" / "Must provide query" → endpoint exists.
 *   - tRPC: bundle text contains '@trpc/client' or 'createTRPCNext'.
 */
interface ApiSurfaceProbeResult {
  openapi: {
    foundAt: string | null
    endpoints: { path: string; methods: string[] }[]
  }
  graphql: {
    foundAt: string | null
    introspection: 'allowed' | 'denied' | 'unknown'
  }
  trpcDetected: boolean
}

async function probeApiSurface(
  origin: string,
  bundleText: string,
): Promise<ApiSurfaceProbeResult> {
  const out: ApiSurfaceProbeResult = {
    openapi: { foundAt: null, endpoints: [] },
    graphql: { foundAt: null, introspection: 'unknown' },
    trpcDetected: /@trpc\/(?:client|next|react-query|server)|createTRPCNext|createTRPCReact/.test(
      bundleText,
    ),
  }

  // OpenAPI/Swagger probes
  const specPaths = ['/openapi.json', '/swagger.json', '/api-docs', '/api/openapi.json', '/swagger/v1/swagger.json']
  for (const p of specPaths) {
    try {
      const target = new URL(p, origin).toString()
      const r = await fetchWithTimeout(
        target,
        {
          method: 'GET',
          headers: { Accept: 'application/json' },
          redirect: 'manual',
        },
        2000,
      )
      if (r.status !== 200) continue
      const ct = r.headers.get('content-type') || ''
      if (!ct.includes('json')) continue
      // Cap body at 512KB — OpenAPI specs >1MB exist but are rare.
      const text = await readBoundedText(r, 512 * 1024).then((x) => x.text)
      let spec: unknown
      try {
        spec = JSON.parse(text)
      } catch {
        continue
      }
      // Confirm shape — must have `paths` (OpenAPI 3) or `swagger` field
      if (typeof spec !== 'object' || spec === null) continue
      const obj = spec as Record<string, unknown>
      const paths = obj['paths']
      if (!paths || typeof paths !== 'object') continue
      out.openapi.foundAt = target
      // Extract first ~40 endpoint definitions
      const endpoints: { path: string; methods: string[] }[] = []
      for (const [path, methods] of Object.entries(paths as Record<string, unknown>)) {
        if (endpoints.length >= 40) break
        if (typeof methods !== 'object' || methods === null) continue
        const verbs = Object.keys(methods).filter((k) =>
          /^(get|post|put|patch|delete|options|head)$/i.test(k),
        )
        if (verbs.length > 0) endpoints.push({ path, methods: verbs.map((v) => v.toUpperCase()) })
      }
      out.openapi.endpoints = endpoints
      break // first hit wins
    } catch {
      // skip
    }
  }

  // GraphQL probe — GET /graphql usually 400s with a recognizable error
  try {
    const target = new URL('/graphql', origin).toString()
    const r = await fetchWithTimeout(
      target,
      { method: 'GET', headers: { Accept: 'application/json' }, redirect: 'manual' },
      2000,
    )
    if (r.status === 400 || r.status === 405 || r.status === 200) {
      const txt = (await readBoundedText(r, 8 * 1024).then((x) => x.text)).slice(0, 4096)
      if (
        /must provide (?:a )?query|persistedquerynotsupported|graphql.*must be a post|get requests.*only|introspectionquery|GraphQL operation/i.test(
          txt,
        )
      ) {
        out.graphql.foundAt = target
        // Try a tiny introspection query
        try {
          const introResp = await fetchWithTimeout(
            target,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
              body: JSON.stringify({ query: '{__schema{queryType{name}}}' }),
            },
            2000,
          )
          if (introResp.status === 200) {
            const introTxt = await readBoundedText(introResp, 4096).then((x) => x.text)
            if (/__schema/.test(introTxt) && /queryType/.test(introTxt)) {
              out.graphql.introspection = 'allowed'
            } else {
              out.graphql.introspection = 'denied'
            }
          } else {
            out.graphql.introspection = 'denied'
          }
        } catch {
          out.graphql.introspection = 'unknown'
        }
      }
    }
  } catch {
    // skip — graphql endpoint just doesn't exist or is offline
  }

  return out
}

/**
 * Fingerprint of the homepage HTML, used to detect SPA shells masquerading
 * as real routes. SPA frameworks (Vite + React, Next.js without SSR for the
 * matched route, Vue Router fallback, SvelteKit static, etc.) serve the
 * SAME index.html for every path so the client router can mount; an admin
 * probe then sees HTTP 200 but the body is just the shell — no privileged
 * data ever crossed the wire. Comparing body length + a content prefix
 * rules out the shell case without false-negatives on real admin pages,
 * which always differ in body or are bigger.
 */
function makeHomepageFingerprint(html: string): { length: number; head: string } {
  return { length: html.length, head: html.slice(0, 256) }
}

function isSpaShellResponse(
  body: string,
  fp: { length: number; head: string },
): boolean {
  if (Math.abs(body.length - fp.length) > 16) return false
  return body.slice(0, 256) === fp.head
}

async function discoverAndProbeAdminRoutes(
  bundleText: string,
  html: string,
  origin: string,
): Promise<{ path: string; status: number; contentLength: number | null; isSpaShell: boolean }[]> {
  const homepageFp = makeHomepageFingerprint(html)
  const candidates = new Set<string>()
  // Pattern 1: react-router style — `<Route path="/admin/...">` or path:"/admin..."
  for (const m of (bundleText + html).matchAll(
    /(?:[<\s]Route\s+[^>]*\s|["']\s*)path\s*[:=]\s*["'\`](\/[A-Za-z0-9_\-./:?]+)["'\`]/gi,
  )) {
    const p = m[1]
    if (ADMIN_PREFIX_RE.test(p)) candidates.add(p.split(/[?#]/)[0])
  }
  // Pattern 2: any string literal on a sensitive prefix
  for (const prefix of ADMIN_HARD_PREFIXES) {
    const re = new RegExp(`["'\`](${prefix}\\/[A-Za-z0-9_\\-./]+)["'\`]`, 'g')
    for (const m of (bundleText + html).matchAll(re)) {
      candidates.add(m[1])
    }
  }
  // Pattern 3: HTML anchor tags pointing at admin
  for (const m of html.matchAll(
    /<a\b[^>]*\bhref\s*=\s*["'](\/[A-Za-z0-9_\-./?#=&]+)["']/gi,
  )) {
    if (ADMIN_PREFIX_RE.test(m[1])) candidates.add(m[1].split(/[?#]/)[0])
  }

  // Drop trivial / noise paths
  const filtered = Array.from(candidates)
    .filter((p) => p.length >= 5 && p.length <= 200)
    .filter((p) => !/\.(?:js|css|map|png|jpg|svg|webp|ico)$/i.test(p))
    .slice(0, 10)
  if (filtered.length === 0) return []

  const results = await Promise.all(
    filtered.map(async (path) => {
      try {
        const target = new URL(path, origin).toString()
        const r = await fetchWithTimeout(
          target,
          {
            method: 'GET',
            headers: {
              'User-Agent': SCANNER_UA,
              'Accept-Language': BROWSER_ACCEPT_LANGUAGE,
              Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
            },
            redirect: 'manual',
          },
          2500,
        )
        const lengthHeader = r.headers.get('content-length')
        const contentLength = lengthHeader ? parseInt(lengthHeader, 10) : null
        // Read the body bounded so SPA-shell detection has something to compare.
        // Cap at the homepage length plus a small slack — anything larger is
        // definitely not the shell, and we don't need to download a full
        // /admin page just to know it isn't.
        const bodyBudget = Math.max(homepageFp.length + 1024, 4096)
        let body = ''
        try {
          const probeBody = await readBoundedText(r, bodyBudget)
          body = probeBody.text
        } catch {
          body = ''
        }
        const isSpaShell = body.length > 0 && isSpaShellResponse(body, homepageFp)
        return {
          path,
          status: r.status,
          contentLength: Number.isFinite(contentLength) ? contentLength : null,
          isSpaShell,
        }
      } catch {
        return null
      }
    }),
  )
  return results.filter(
    (x): x is { path: string; status: number; contentLength: number | null; isSpaShell: boolean } =>
      x !== null,
  )
}

function detectFramework(html: string): string | null {
  if (html.includes('__NEXT_DATA__') || html.includes('/_next/')) return 'Next.js'
  if (html.includes('window.__NUXT__')) return 'Nuxt'
  if (html.includes('id="root"') && html.includes('type="module"')) return 'Vite + React'
  if (html.includes('SvelteKit') || html.includes('/_app/immutable/')) return 'SvelteKit'
  if (html.includes('window.__remixContext')) return 'Remix'
  if (html.includes('astro-island')) return 'Astro'
  return null
}

/**
 * S1+2 — Deep fingerprinting (versions).
 *
 * Looks for explicit version strings in HTML + bundles. Order matters —
 * earlier patterns win because they tend to be more authoritative (meta
 * generator > __NEXT_DATA__ buildId > bundle string match).
 *
 * Returns { name, version } when both are known, just `name` when only
 * the framework is identified, null when nothing matches.
 */
function detectFrameworkAndVersion(
  html: string,
  bundleText: string,
): { name: string; version: string | null } | null {
  // 1. <meta name="generator" content="Framework X.Y.Z">
  const genMatch = html.match(
    /<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i,
  )
  if (genMatch) {
    const content = genMatch[1].trim()
    const verMatch = content.match(/^([A-Za-z][A-Za-z0-9. -]+?)\s+v?(\d+(?:\.\d+){0,2}[A-Za-z0-9.\-+]*)\b/)
    if (verMatch) return { name: verMatch[1].trim(), version: verMatch[2] }
    return { name: content, version: null }
  }

  // 2. Next.js — buildId is just a hash but the bundle path patterns reveal
  //    the major. `_next/static/chunks/pages/_app-` is App-Router-era; the
  //    react-server-dom-webpack version often appears verbatim.
  if (html.includes('__NEXT_DATA__') || html.includes('/_next/')) {
    const corpus = html + bundleText
    // explicit `next/${version}` lines or version constants
    const m1 = corpus.match(/"next"\s*:\s*"(\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?)"/)
    if (m1) return { name: 'Next.js', version: m1[1] }
    const m2 = corpus.match(/next\/dist\/[^"'\s]*\bversion\s*["']\s*:?\s*["'](\d+\.\d+\.\d+)["']/)
    if (m2) return { name: 'Next.js', version: m2[1] }
    return { name: 'Next.js', version: null }
  }

  // 3. Nuxt — window.__NUXT__ + nuxt: { version }
  if (html.includes('window.__NUXT__')) {
    const m = (html + bundleText).match(/"nuxt"\s*:\s*"(\d+\.\d+\.\d+)"/)
    if (m) return { name: 'Nuxt', version: m[1] }
    return { name: 'Nuxt', version: null }
  }

  // 4. SvelteKit
  if (html.includes('SvelteKit') || html.includes('/_app/immutable/')) {
    const m = (html + bundleText).match(/"@sveltejs\/kit"\s*:\s*"(\d+\.\d+\.\d+)"/)
    if (m) return { name: 'SvelteKit', version: m[1] }
    return { name: 'SvelteKit', version: null }
  }

  // 5. Remix
  if (html.includes('window.__remixContext')) {
    const m = (html + bundleText).match(/"@remix-run\/(?:react|node)"\s*:\s*"(\d+\.\d+\.\d+)"/)
    if (m) return { name: 'Remix', version: m[1] }
    return { name: 'Remix', version: null }
  }

  // 6. Astro
  if (html.includes('astro-island')) {
    const m = (html + bundleText).match(/"astro"\s*:\s*"(\d+\.\d+\.\d+)"/)
    if (m) return { name: 'Astro', version: m[1] }
    return { name: 'Astro', version: null }
  }

  // 7. Vite — version sometimes embedded in dev-mode banners (skip in prod)
  if (html.includes('id="root"') && html.includes('type="module"')) {
    return { name: 'Vite + React', version: null }
  }

  // 8. WordPress — generator meta usually catches this in #1, but also check
  //    wp-content paths
  if (/\/wp-(?:content|includes)\//.test(html)) {
    return { name: 'WordPress', version: null }
  }

  return null
}

/**
 * Extract React version from the bundle. React doesn't tag its bundles
 * with the version directly, but `__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher`
 * presence + `react/jsx-runtime` import paths and a few known version
 * tags get us close.
 */
function detectReactVersion(bundleText: string): string | null {
  const m = bundleText.match(/"react"\s*:\s*"(\d+\.\d+\.\d+)"/)
  if (m) return m[1]
  const m2 = bundleText.match(/react@(\d+\.\d+\.\d+)/)
  if (m2) return m2[1]
  return null
}

export async function runScan(rawUrl: string): Promise<ScanResponse> {
  const t0 = Date.now()

  const trimmed = (rawUrl ?? '').trim()
  if (!trimmed) {
    return { ok: false, error: { code: 'invalid_url', message: 'No URL provided.' } }
  }

  let url: URL
  try {
    url = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`)
  } catch {
    return { ok: false, error: { code: 'invalid_url', message: 'That URL is not valid.' } }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      ok: false,
      error: { code: 'invalid_url', message: 'Only http:// and https:// are supported.' },
    }
  }
  if (isPrivateHost(url.hostname)) {
    return {
      ok: false,
      error: {
        code: 'invalid_url',
        message: 'Private/local addresses cannot be scanned.',
      },
    }
  }

  // Kick off DNS + TLS + OPTIONS probes in parallel with main fetch.
  const dnsP =
    url.protocol === 'https:'
      ? gatherDns(url.hostname).catch(
          (): DnsSnapshot => ({
            spf: null,
            dmarc: null,
            hasDnskey: false,
            caa: [],
            cname: null,
            baseDomain: getBaseDomain(url.hostname),
          }),
        )
      : Promise.resolve<DnsSnapshot>({
          spf: null,
          dmarc: null,
          hasDnskey: false,
          caa: [],
          cname: null,
          baseDomain: getBaseDomain(url.hostname),
        })
  const tlsP =
    url.protocol === 'https:'
      ? probeTls(url.hostname).catch(
          (): TlsSnapshot => ({ protocol: null, cipher: null, cert: null, error: 'tls failed' }),
        )
      : Promise.resolve<TlsSnapshot>({
          protocol: null,
          cipher: null,
          cert: null,
          error: 'http only',
        })
  const optionsP = probeOptions(url.toString()).catch(() => ({ allow: null, trace: false }))
  const firebaseP = probeFirebaseRTDB(url.origin).catch(() => null)
  const robotsP = fetchRobots(url.origin).catch(() => null)
  const signupP = probeSignupEndpoints(url.origin).catch(
    () => [] as { path: string; label: string; status: number }[],
  )
  const openRedirectP = probeOpenRedirect(url.toString()).catch(
    () => [] as { param: string; redirectsTo: string }[],
  )
  const httpRedirectP = probeHttpToHttps(url.hostname).catch(() => ({
    redirects: false,
    finalProtocol: null as string | null,
  }))
  const xssP = probeReflectedXss(url.toString()).catch(
    () => [] as { param: string; reflectedRaw: boolean }[],
  )
  const sqliP = probeSqliErrors(url.toString()).catch(() => [] as { param: string; pattern: string }[])
  // S1+3 — passive subdomain discovery via crt.sh, capped at 4s timeout.
  // Runs in parallel; failure → empty list (don't block the scan).
  const subdomainsP = discoverSubdomainsFromCT(getBaseDomain(url.hostname)).catch(() => [] as string[])

  // WAF state captured across both fetch phases. Surfaced in the result via
  // attackSurface.wafVendor + a synthetic `meta-waf-detected` finding so the
  // user sees what's in front of their origin (and whether we had to bypass
  // an initial block to even reach the page).
  const wafState: {
    vendor: WafVendor | null
    blocked: boolean
    stealthRetryAttempted: boolean
    stealthRetrySucceeded: boolean
  } = {
    vendor: null,
    blocked: false,
    stealthRetryAttempted: false,
    stealthRetrySucceeded: false,
  }

  let mainResp: Response
  try {
    mainResp = await fetchWithTimeout(url.toString(), {
      method: 'GET',
      headers: {
        'User-Agent': SCANNER_UA,
        'Accept-Language': BROWSER_ACCEPT_LANGUAGE,
        Accept: BROWSER_ACCEPT,
      },
    })
  } catch (e: unknown) {
    const isAbort =
      e instanceof Error && (e.name === 'AbortError' || e.message.includes('aborted'))
    if (isAbort) {
      return { ok: false, error: { code: 'timeout', message: 'The site took too long to respond.' } }
    }
    const msg = e instanceof Error ? e.message : 'unknown error'
    return {
      ok: false,
      error: { code: 'unreachable', message: `Could not reach ${url.host}: ${msg}` },
    }
  }

  if (mainResp.status >= 400 && mainResp.status < 500) {
    // 403 / 406 / 429 / 451 from a 4xx range strongly suggests a WAF
    // (Cloudflare, Akamai, AWS WAF, Imperva, Fastly, Vercel Bot Protection,
    // Sucuri, StackPath, DDoS-Guard) flagged our outbound IP — Vercel Lambda
    // IP ranges are a known bot signal. Two-phase response:
    //   (1) Retry once with stealth headers (Sec-Ch-Ua + Sec-Fetch-*). Some
    //       Cloudflare "managed challenge" rules score on header completeness
    //       alone, so a more browser-faithful request slips through.
    //   (2) If still blocked: return `blocked_by_waf` with the vendor name and
    //       a suggested next step. This is NOT a scanner failure — the target
    //       chose to deny automated access. The frontend renders this as a
    //       distinct UX with a one-click handoff to Stage 2.
    const wafLikely = [403, 406, 429, 451].includes(mainResp.status)

    if (wafLikely) {
      // (1) Stealth retry — only on WAF-likely codes; 404 / 410 / 400 don't
      // benefit from a different UA so we skip the extra round-trip.
      wafState.blocked = true
      // Sniff vendor from the initial blocked response headers so we still
      // report it on the success path (when stealth retry passes).
      const initialBlockBody = await mainResp.clone().text().catch(() => '')
      wafState.vendor = detectWafVendor(mainResp, initialBlockBody.slice(0, 8192))
      try {
        wafState.stealthRetryAttempted = true
        const stealthResp = await fetchWithTimeout(url.toString(), {
          method: 'GET',
          headers: STEALTH_HEADERS,
        })
        if (stealthResp.status >= 200 && stealthResp.status < 400) {
          // Stealth retry succeeded — continue with this response as if it
          // were the primary. This is correct: WAFs that pass on stealth
          // are not blocking the user's real visitors either.
          wafState.stealthRetrySucceeded = true
          mainResp = stealthResp
        } else {
          // Still blocked — read body for vendor sniff, then return structured
          // error. Cap body read at 8KB; WAF block pages are tiny.
          const blockBody = await stealthResp.text().catch(() => '')
          const vendor = detectWafVendor(stealthResp, blockBody.slice(0, 8192))
          const status = stealthResp.status
          const suggestedAction = suggestedActionFor(vendor, status)
          return {
            ok: false,
            error: {
              code: 'blocked_by_waf',
              httpStatus: status,
              wafVendor: vendor,
              suggestedAction,
              message: `${url.host} blocked the scan with HTTP ${status}. ${VENDOR_LABELS[vendor]} flagged our IP as automated traffic — this is not a scanner failure, the target denied access. ${suggestedAction === 'stage2-bookmarklet' ? 'Run Stage 2 (browser-assisted) instead — it executes inside your own browser session, so the WAF can\'t block it.' : suggestedAction === 'fix-target' ? 'HTTP 451 indicates a legal block; this URL is unavailable for legal reasons in our region.' : 'Try Stage 2 to bypass the block.'}`,
            },
          }
        }
      } catch {
        // Stealth retry threw (timeout/abort) — fall through to generic 4xx.
      }
    }

    if (mainResp.status >= 400 && mainResp.status < 500) {
      // Generic 4xx without WAF signals: 404, 410, 400 — site is reachable
      // but rejected this URL. Different from a WAF block.
      const blockBody = await mainResp.text().catch(() => '')
      const vendor = detectWafVendor(mainResp, blockBody.slice(0, 8192))
      const isWaf = wafLikely && vendor !== 'unknown'
      return {
        ok: false,
        error: {
          code: isWaf ? 'blocked_by_waf' : 'blocked_by_target',
          httpStatus: mainResp.status,
          wafVendor: isWaf ? vendor : undefined,
          suggestedAction: isWaf ? suggestedActionFor(vendor, mainResp.status) : undefined,
          message: isWaf
            ? `${url.host} blocked the scan with HTTP ${mainResp.status}. ${VENDOR_LABELS[vendor]} flagged our IP as automated traffic — this is not a scanner failure, the target denied access. Run Stage 2 (browser-assisted) instead.`
            : `${url.host} returned HTTP ${mainResp.status}. The site is reachable but rejected this URL — check the path is correct, or try the canonical host (www vs apex).`,
        },
      }
    }
  }

  const html = (await mainResp.text()).slice(0, 1024 * 1024) // cap HTML at 1MB
  const finalUrl = mainResp.url || url.toString()
  const findings: Finding[] = []
  const detectedFramework = detectFramework(html)

  // If we haven't already pinned a WAF vendor (no initial block), sniff the
  // successful response headers + body. Many sites front Cloudflare/Akamai/
  // Vercel without ever 4xx'ing us — surfacing the vendor in the attack
  // surface map is still useful intel.
  if (!wafState.vendor) {
    const sniffed = detectWafVendor(mainResp, html.slice(0, 8192))
    if (sniffed !== 'unknown') wafState.vendor = sniffed
  }

  // === HEADERS ===
  for (const req of HEADER_REQS) {
    const value = mainResp.headers.get(req.name)
    if (!value) {
      findings.push({
        id: `headers-${req.name}`,
        severity: req.severity,
        category: 'headers',
        title: `Missing ${req.label} header`,
        description: `The response does not set ${req.label}. ${
          req.severity === 'warn'
            ? 'This is a hardening header that protects against a class of attacks.'
            : 'This is a defense-in-depth hardening header.'
        }`,
        evidence: `GET ${finalUrl} → response is missing ${req.name}`,
        fixPrompt: req.fixPrompt(finalUrl),
      })
    }
  }
  // CSP weakness analyzer — only fires if CSP IS present
  const cspHeader = mainResp.headers.get('content-security-policy') ?? ''
  if (cspHeader) {
    const cspIssues: string[] = []
    // Token-based directive parsing: split each directive into space-separated
    // tokens so 'wasm-unsafe-eval' isn't conflated with 'unsafe-eval', and the
    // unsafe-inline check is scoped to script-src (not style-src).
    const directiveTokens = (name: string): string[] => {
      const matched = new RegExp(`\\b${name}\\b([^;]*)`, 'i').test(cspHeader)
      if (!matched) return []
      const segment = (cspHeader.match(new RegExp(`\\b${name}\\b([^;]*)`, 'i')) ?? [])[1] ?? ''
      return segment.trim().split(/\s+/).filter(Boolean)
    }
    const scriptTokens = directiveTokens('script-src')
    const defaultTokens = directiveTokens('default-src')
    const effective = scriptTokens.length > 0 ? scriptTokens : defaultTokens
    const hasStrictDynamic = effective.includes("'strict-dynamic'")
    const hasNonce = effective.some((t) => t.startsWith("'nonce-"))
    // 'strict-dynamic' tells the browser to ignore 'unsafe-inline' / allowlists,
    // trusting only nonced scripts and scripts they spawn — the modern strict
    // pattern. So when both are present, 'unsafe-inline' / allowlists are inert.
    const strictByDynamic = hasStrictDynamic && hasNonce
    if (effective.includes("'unsafe-inline'") && !strictByDynamic) {
      cspIssues.push("script-src includes 'unsafe-inline' (no 'strict-dynamic'+nonce to neutralize)")
    }
    if (effective.includes("'unsafe-eval'")) {
      cspIssues.push("script-src includes 'unsafe-eval'")
    }
    // Wildcard host source — only meaningful when allowlists actually count
    // (i.e. no 'strict-dynamic'); strict-dynamic ignores host expressions.
    if (!strictByDynamic && effective.some((t) => t === '*' || t.startsWith('*.'))) {
      cspIssues.push("script-src contains a wildcard host")
    }
    if (!/\bframe-ancestors\b/i.test(cspHeader)) {
      cspIssues.push("missing frame-ancestors directive (use 'none' or 'self')")
    }
    if (!/\bbase-uri\b/i.test(cspHeader)) {
      cspIssues.push("missing base-uri directive (use 'self')")
    }
    if (!/\bform-action\b/i.test(cspHeader)) {
      cspIssues.push("missing form-action directive (use 'self')")
    }
    if (cspIssues.length > 0) {
      const isCritical = cspIssues.some((i) => i.includes('unsafe-') || i.includes('wildcard'))
      findings.push({
        id: 'headers-csp-weak',
        severity: isCritical ? 'warn' : 'info',
        category: 'headers',
        title: `Content-Security-Policy is set but has ${cspIssues.length} weakness${
          cspIssues.length === 1 ? '' : 'es'
        }`,
        description: `A CSP exists, but its directives leave gaps. ${
          isCritical
            ? "Allowing 'unsafe-inline' or wildcard sources defeats most of CSP's XSS protection."
            : "Missing fallback directives (frame-ancestors / base-uri / form-action) leaves clickjacking, base-tag injection, and form hijacking partially open."
        }`,
        evidence: `Issues:\n  - ${cspIssues.slice(0, 6).join('\n  - ')}\nCSP: ${cspHeader.slice(0, 200)}`,
        fixPrompt: `Tighten your CSP. Replace inline scripts with external files or use a CSP nonce/hash. Then write: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'". Test with the Mozilla Observatory or csp-evaluator.withgoogle.com after deploy. Aim for "Strict CSP" rating.`,
      })
    }
  }

  // HSTS strength analyzer — only fires if HSTS IS present
  const hstsHeader = mainResp.headers.get('strict-transport-security')
  if (hstsHeader) {
    const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(hstsHeader)
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0
    const hasIncludeSub = /\bincludeSubDomains\b/i.test(hstsHeader)
    const hasPreload = /\bpreload\b/i.test(hstsHeader)
    const sixMonths = 60 * 60 * 24 * 180
    const oneYear = 60 * 60 * 24 * 365

    const issues: string[] = []
    if (maxAge === 0) {
      issues.push('max-age is 0 (HSTS effectively disabled)')
    } else if (maxAge < sixMonths) {
      issues.push(`max-age is ${Math.round(maxAge / 86400)} days — recommended ≥180 days`)
    }
    if (!hasIncludeSub) issues.push('missing includeSubDomains')
    if (!hasPreload && maxAge >= oneYear && hasIncludeSub) issues.push('eligible for preload but not opted in')

    if (issues.length > 0) {
      findings.push({
        id: 'headers-hsts-weak',
        severity: maxAge === 0 ? 'warn' : 'info',
        category: 'headers',
        title: `HSTS is set but ${issues.length === 1 ? 'has a weakness' : `has ${issues.length} weaknesses`}`,
        description: `HSTS is present but not at full strength: ${issues.join(', ')}. Browsers cache the policy for max-age seconds — short max-age + no includeSubDomains leaves windows where MITM can downgrade users to HTTP.`,
        evidence: `Strict-Transport-Security: ${hstsHeader}`,
        fixPrompt: `Strengthen HSTS to: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload". 63072000 seconds = 2 years. Once you've shipped this for 6+ months and confirmed nothing breaks on subdomains, submit your domain to https://hstspreload.org/ to be baked into Chrome/Firefox/Edge. Once preloaded, browsers REFUSE plain HTTP on your domain even on first visit.`,
      })
    }
  }

  // CORS open check (if Access-Control-Allow-Origin: *)
  const corsOrigin = mainResp.headers.get('access-control-allow-origin')
  if (corsOrigin === '*') {
    const acac = mainResp.headers.get('access-control-allow-credentials')
    findings.push({
      id: 'headers-cors-wildcard',
      severity: acac === 'true' ? 'critical' : 'info',
      category: 'headers',
      title: 'CORS is open to any origin',
      description:
        acac === 'true'
          ? 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true is rejected by browsers, but signals a configuration mistake. Any other origin can read responses.'
          : 'Access-Control-Allow-Origin: * means any other website can fetch your API and read responses. Acceptable for truly public data, but verify it.',
      evidence: `Access-Control-Allow-Origin: ${corsOrigin}`,
      fixPrompt: `Audit your CORS policy. If this endpoint serves user data, replace "Access-Control-Allow-Origin: *" with an explicit allowlist of your own origins (e.g. "https://app.example.com"). If it serves truly public data and Allow-Credentials is not set to true, this is acceptable — but document it.`,
    })
  }

  // === COOKIES ===
  type HeadersWithSetCookie = Headers & { getSetCookie?: () => string[] }
  const headersWithSC = mainResp.headers as HeadersWithSetCookie
  const setCookies: string[] =
    typeof headersWithSC.getSetCookie === 'function'
      ? headersWithSC.getSetCookie()
      : (() => {
          const raw = mainResp.headers.get('set-cookie')
          return raw ? [raw] : []
        })()

  for (const cookieStr of setCookies) {
    const semiParts = cookieStr.split(';').map((s) => s.trim())
    const namePart = semiParts[0] ?? ''
    const cookieName = namePart.split('=')[0]?.trim() || '(unknown)'
    const lower = cookieStr.toLowerCase()
    const hasSecure = /;\s*secure(\s|;|$)/i.test(';' + lower)
    const hasHttpOnly = /;\s*httponly(\s|;|$)/i.test(';' + lower)
    const sameSiteMatch = /samesite=([a-z]+)/i.exec(cookieStr)
    const sameSite = sameSiteMatch?.[1]?.toLowerCase() ?? null
    const isSensitiveName = /sess|auth|token|jwt|sid|csrf/i.test(cookieName)

    const issues: string[] = []
    if (!hasSecure) issues.push('no Secure flag')
    if (!hasHttpOnly && isSensitiveName) issues.push('no HttpOnly flag')
    if (sameSite === 'none' && !hasSecure) {
      issues.push('SameSite=None without Secure (browsers reject)')
    } else if (sameSite === null) {
      issues.push('no explicit SameSite (browsers default to Lax)')
    }

    if (issues.length > 0) {
      const severity: Severity =
        isSensitiveName && (!hasHttpOnly || !hasSecure) ? 'warn' : 'info'
      findings.push({
        id: `cookie-${cookieName}`,
        severity,
        category: 'cookies',
        title: `Cookie "${cookieName}" is missing hardening flags`,
        description: `Set-Cookie for "${cookieName}" is missing: ${issues.join(
          ', ',
        )}. ${
          isSensitiveName
            ? 'This cookie name suggests session/auth state — without HttpOnly + Secure + SameSite, it can be stolen via XSS or CSRF.'
            : 'Even non-sensitive cookies should ship with hardening flags as a baseline.'
        }`,
        evidence: lower.slice(0, 240),
        fixPrompt: `Update where this cookie is set. For session/auth cookies always send: Secure; HttpOnly; SameSite=Lax (or Strict if your auth flow doesn't need cross-site navigation). For SameSite=None you MUST also include Secure or browsers reject the cookie. If the cookie is set by a framework (Express, Hono, NextAuth, Supabase), find the cookie config and set the flags there — don't try to rewrite the Set-Cookie header at the proxy.`,
      })
    }
  }

  // === MIXED CONTENT ===
  if (url.protocol === 'https:') {
    const httpResources = Array.from(
      html.matchAll(/<(?:script|link|img|iframe|video|audio|source)\b[^>]*\b(?:src|href)\s*=\s*["'](http:\/\/[^"'\s]+)["']/gi),
    )
    const httpForms = Array.from(html.matchAll(/<form\b[^>]*\baction\s*=\s*["'](http:\/\/[^"'\s]+)["']/gi))
    const allHttp = [...httpResources.map((m) => m[1]), ...httpForms.map((m) => m[1])]
    const uniqueHttp = Array.from(new Set(allHttp)).slice(0, 8)
    if (uniqueHttp.length > 0) {
      const hasForm = httpForms.length > 0
      findings.push({
        id: 'mixed-content',
        severity: hasForm ? 'critical' : 'warn',
        category: 'mixed-content',
        title: hasForm
          ? 'HTTPS page submits a form over plain HTTP'
          : 'HTTPS page loads resources over plain HTTP (mixed content)',
        description: hasForm
          ? 'A form action points to http://. Browsers may warn or block, and any data the user submits travels in cleartext.'
          : 'Some scripts/styles/images are loaded over http:// from an https:// page. Modern browsers block active mixed content (scripts, iframes) and may warn on passive content (images).',
        evidence: uniqueHttp.slice(0, 4).join('\n'),
        fixPrompt: `Replace every http:// reference in your HTML/JSX with https://. If a third-party host doesn't support HTTPS, find an alternative — every major CDN does. If you can't replace it, add an "upgrade-insecure-requests" directive to your CSP so browsers auto-upgrade. For form actions over HTTP — change them to HTTPS immediately, this is leaking user input in cleartext.`,
      })
    }
  }

  // === SRI on external scripts ===
  // Hosts that intentionally do NOT support SRI: anti-bot / CAPTCHA scripts
  // are silently auto-updated by the provider; pinning a hash would lock the
  // user to a stale (insecure) version. The provider takes responsibility for
  // the script body, the user takes responsibility for the host trust. Skip.
  const SRI_EXEMPT_HOSTS = new Set<string>([
    'challenges.cloudflare.com', // Cloudflare Turnstile
    'js.hcaptcha.com',
    'hcaptcha.com',
    'www.google.com', // reCAPTCHA loader
    'www.gstatic.com', // reCAPTCHA assets
    'www.recaptcha.net',
    'recaptcha.net',
  ])
  const allScriptTags = Array.from(html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi))
  const externalNoSri: string[] = []
  for (const m of allScriptTags) {
    const tag = m[0]
    const src = m[1]
    if (!src) continue
    let absUrl: string
    try {
      absUrl = new URL(src, finalUrl).toString()
    } catch {
      continue
    }
    let scriptHost: string
    try {
      scriptHost = new URL(absUrl).host
    } catch {
      continue
    }
    if (scriptHost === url.host) continue
    if (SRI_EXEMPT_HOSTS.has(scriptHost)) continue
    if (/\bintegrity\s*=/i.test(tag)) continue
    externalNoSri.push(absUrl)
  }
  if (externalNoSri.length > 0) {
    findings.push({
      id: 'integrity-no-sri',
      severity: 'warn',
      category: 'integrity',
      title: 'External scripts loaded without Subresource Integrity (SRI)',
      description: `${externalNoSri.length} external <script src=...> tag${
        externalNoSri.length === 1 ? '' : 's'
      } do not have an "integrity" attribute. If the third-party host is compromised, the attacker's script runs with full privileges on your origin.`,
      evidence: externalNoSri.slice(0, 4).join('\n'),
      fixPrompt: `Add an "integrity" attribute (and crossorigin="anonymous") to every <script src> that points to a third-party host. The integrity value is a SHA-384 hash of the script body, base64-encoded, prefixed with "sha384-". Most CDNs (jsDelivr, unpkg, cdnjs) publish the hash next to the URL — copy it from there. Then write: <script src="..." integrity="sha384-..." crossorigin="anonymous"></script>. If you control the script (served from your own CDN), SRI is optional. Re-generate the hash whenever the script content changes.`,
    })
  }

  // === BUNDLES ===
  const scriptMatches = Array.from(
    html.matchAll(/<script[^>]+src=["']([^"']+)["'][^>]*>/gi),
  )
  const seen = new Set<string>()
  const bundleUrls: string[] = []
  for (const m of scriptMatches) {
    const src = m[1]
    if (!src) continue
    let abs: string
    try {
      abs = new URL(src, finalUrl).toString()
    } catch {
      continue
    }
    if (!/\.js(\?|$)/.test(abs.split('#')[0])) continue
    if (seen.has(abs)) continue
    seen.add(abs)
    bundleUrls.push(abs)
    if (bundleUrls.length >= MAX_BUNDLES) break
  }

  let bundlesFetched = 0
  let bundlesSizeBytes = 0
  const supabaseProjectIds = new Set<string>()
  const s3BucketHosts = new Set<string>()
  const npmCveHits: { cve: NpmCve; sample: string }[] = []
  const localhostHits: string[] = []
  let bundleTextAll = ''
  // S1+6 — keep individual bundle texts (capped) for AST parsing.
  const bundleTexts: string[] = []
  let detectedAnonKey: string | null = null
  const firebaseIdsCollected = new Set<string>()

  // Pre-scan HTML for s3 hosts (since we already have html)
  for (const m of html.matchAll(/https?:\/\/([\w.-]+\.s3[.\w-]*\.amazonaws\.com)/gi)) {
    s3BucketHosts.add(m[1])
  }
  for (const m of html.matchAll(/https?:\/\/s3[.\w-]*\.amazonaws\.com\/([\w.-]+)/gi)) {
    s3BucketHosts.add(`${m[1]}.s3.amazonaws.com`)
  }
  for (const m of html.matchAll(/https:\/\/([a-z0-9]{20,})\.supabase\.co/gi)) {
    supabaseProjectIds.add(m[1])
  }

  for (const bundleUrl of bundleUrls) {
    let bundleText = ''
    try {
      const r = await fetchWithTimeout(bundleUrl, { method: 'GET' })
      if (!r.ok) continue
      const { text, size } = await readBoundedText(r, MAX_BUNDLE_SIZE)
      bundleText = text
      bundlesFetched++
      bundlesSizeBytes += size
    } catch {
      continue
    }

    const fileSlug = shortPath(bundleUrl)

    // Secret patterns
    for (const pat of SECRET_PATTERNS) {
      pat.re.lastIndex = 0
      const matches = bundleText.match(pat.re)
      if (matches && matches.length > 0) {
        const sample = matches[0]
        const rotateLine = pat.rotateUrl
          ? ` Then rotate the leaked key at ${pat.rotateUrl} — assume it is fully compromised.`
          : ' Then rotate the leaked key — assume it is fully compromised.'
        findings.push({
          id: `secret-${pat.fixHint.toLowerCase()}-${fileSlug}`,
          severity: pat.severity,
          category: 'secrets',
          title: `${pat.name} exposed in JS bundle`,
          description: `A live ${pat.name.toLowerCase()} is shipped in your client-side bundle. Anyone visiting the site can extract and abuse it.`,
          evidence: `${fileSlug} → "${redactSecret(sample)}"`,
          fixPrompt: `Remove the hardcoded ${pat.name} from the JS bundle. Find every direct call to the ${pat.fixHint} SDK from the client and move them behind a server endpoint (Vercel Edge Function or Supabase Edge Function) that reads the key from process.env. The client should call your own /api/* endpoint, never the ${pat.fixHint} API directly.${rotateLine}`,
        })
      }
    }

    // JWTs — service-role + anon-key detection
    JWT_RE.lastIndex = 0
    const jwts = bundleText.match(JWT_RE) ?? []
    for (const jwt of jwts) {
      const parts = jwt.split('.')
      if (parts.length !== 3) continue
      try {
        const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/')
        const decoded = Buffer.from(padded, 'base64').toString('utf-8')
        const payload = JSON.parse(decoded) as { role?: string; iss?: string; ref?: string }
        // Anon key — legitimate to ship to client, but we capture it for Stage 3 RLS probes
        if (payload.role === 'anon' && !detectedAnonKey) {
          detectedAnonKey = jwt
          if (payload.ref) supabaseProjectIds.add(payload.ref)
        }
        if (payload.role === 'service_role') {
          findings.push({
            id: `secret-supabase-service-role-${fileSlug}`,
            severity: 'critical',
            category: 'secrets',
            title: 'Supabase service-role JWT exposed in JS bundle',
            description:
              'The Supabase service-role key bypasses ALL row-level security. With this in the client bundle, anyone can read, write, or delete every row in your database.',
            evidence: `${fileSlug} → "${redactSecret(jwt)}" (role=service_role)`,
            fixPrompt: `Remove the hardcoded Supabase service-role key from your client bundle immediately. Move every call that needs the service role to a server endpoint (Edge Function or Vercel API route) and read the key from process.env.SUPABASE_SERVICE_ROLE_KEY. The client must only ever use the anon key. Then go to Supabase Dashboard → Project Settings → API and rotate the service_role key — assume it is fully compromised.`,
          })
        }
      } catch {
        // not a parseable JWT
      }
    }

    // Accumulate up to 1 MB of bundle text for cross-bundle pattern detection
    if (bundleTextAll.length < 1024 * 1024) {
      bundleTextAll += bundleText.slice(0, 1024 * 1024 - bundleTextAll.length)
    }
    // S1+6 — keep first 4 bundles up to 1 MB each for AST parse (cheap, scoped)
    if (bundleTexts.length < 4) {
      bundleTexts.push(bundleText.slice(0, 1024 * 1024))
    }
    // Extract Supabase IDs + S3 hosts from this bundle
    for (const m of bundleText.matchAll(/https:\/\/([a-z0-9]{20,})\.supabase\.co/gi)) {
      supabaseProjectIds.add(m[1])
    }
    for (const m of bundleText.matchAll(/https?:\/\/([\w.-]+\.s3[.\w-]*\.amazonaws\.com)/gi)) {
      s3BucketHosts.add(m[1])
    }
    for (const m of bundleText.matchAll(/https?:\/\/s3[.\w-]*\.amazonaws\.com\/([\w.-]+)/gi)) {
      s3BucketHosts.add(`${m[1]}.s3.amazonaws.com`)
    }
    // localhost references in production
    // The supabase-js SDK ships `GOTRUE_URL = 'http://localhost:9999'` and
    // `STORAGE_KEY = 'supabase.auth.token'` as bundled defaults — they exist
    // in every Supabase project's bundle whether or not the user has any dev
    // config leaked. When the surrounding context shows these constants are
    // adjacent to the auth-token storage key OR the literal "9999" port, the
    // hit is the SDK default, not a leak the developer can fix.
    for (const m of bundleText.matchAll(/https?:\/\/localhost:\d{2,5}/gi)) {
      const ctxStart = Math.max(0, (m.index ?? 0) - 80)
      const ctxEnd = Math.min(bundleText.length, (m.index ?? 0) + m[0].length + 80)
      const context = bundleText.slice(ctxStart, ctxEnd)
      const isSupabaseGoTrueDefault =
        /:9999\b/.test(m[0]) &&
        (/supabase\.auth\.token/.test(context) ||
          /\bGOTRUE_URL\b/.test(context) ||
          /["']supabase["']/.test(context))
      if (isSupabaseGoTrueDefault) continue
      localhostHits.push(m[0])
      if (localhostHits.length >= 5) break
    }
    // npm CVE matchers
    for (const cve of NPM_CVES) {
      cve.match.lastIndex = 0
      const match = cve.match.exec(bundleText)
      if (match && !npmCveHits.some((h) => h.cve.cve === cve.cve)) {
        npmCveHits.push({ cve, sample: match[0] })
      }
    }

    // Source map probe
    const smMatch = bundleText.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/)
    if (smMatch) {
      let mapUrl = ''
      try {
        mapUrl = new URL(smMatch[1], bundleUrl).toString()
      } catch {
        // ignore
      }
      if (mapUrl) {
        try {
          const smResp = await fetchWithTimeout(
            mapUrl,
            { method: 'GET' },
            PROBE_TIMEOUT_MS,
          )
          if (smResp.ok) {
            const sample = (await smResp.text()).slice(0, 256)
            const looksLikeMap = sample.includes('"version"') && sample.includes('"sources"')
            if (looksLikeMap) {
              findings.push({
                id: `sourcemap-${fileSlug}`,
                severity: 'warn',
                category: 'sourcemaps',
                title: 'Production source map is publicly served',
                description:
                  'Source maps reveal your full original source code, comments, and any secrets that were inlined at build time. They should not ship to production.',
                evidence: `GET ${mapUrl} → ${smResp.status} OK (sourcemap)`,
                fixPrompt: `In vite.config.ts (or next.config.ts) set "build.sourcemap: false" for production. If you need source maps for error tracking (Sentry / Vercel), use "hidden-source-map" so the .map is generated for upload but no sourceMappingURL comment is appended to the JS — making the .map unreachable from the browser. Then redeploy and confirm ${mapUrl} returns 404.`,
              })
            }
          }
        } catch {
          // probe failed, no finding
        }
      }
    }
  }

  // === PATH PROBES (in parallel) ===
  const probeResults = await Promise.allSettled(
    PATHS_TO_PROBE.map(async (probe) => {
      const probeUrl = new URL(probe.path, finalUrl).toString()
      const r = await fetchWithTimeout(probeUrl, { method: 'GET' }, PROBE_TIMEOUT_MS)
      if (!r.ok) return null
      const sample = (await r.text()).slice(0, 256).toLowerCase()
      const looksLikeIndex = sample.includes('<!doctype') || sample.includes('<html')
      if (looksLikeIndex) return null
      return { probe, status: r.status, statusText: r.statusText, probeUrl }
    }),
  )
  for (const res of probeResults) {
    if (res.status === 'fulfilled' && res.value) {
      const { probe, status, statusText, probeUrl } = res.value
      findings.push({
        id: `path-${probe.path.replaceAll('/', '-').replaceAll('.', '-')}`,
        severity: probe.severity,
        category: 'paths',
        title: `${probe.label} is reachable at ${probe.path}`,
        description: `${probe.path} responds with ${status} and is not the SPA fallback. Files like this should never be public.`,
        evidence: `GET ${probeUrl} → ${status} ${statusText}`,
        fixPrompt: `Make sure ${probe.path} is not being deployed. Confirm .gitignore excludes it and your deploy output (public/, dist/, .next/, etc.) does not contain it. Add a rewrite rule that returns 404 for ${probe.path} and similar paths (/.env*, /.git/*, /.DS_Store, *.bak, *.swp, *~). On Vercel put this in vercel.json under "redirects". Redeploy and verify with: curl -I ${probeUrl}`,
      })
    }
  }

  // === HTML HYGIENE (inline scripts, on* handlers, target=_blank) ===
  const inlineScriptTags = (html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) ?? []).filter((tag) => {
    // Skip empty <script type="application/ld+json"> data blocks — these are not XSS surfaces
    return !/type\s*=\s*["']application\/(ld\+)?json["']/i.test(tag)
  })
  // Inline <script> with nonce= attribute is safe — the browser only runs it
  // when the value matches the CSP nonce. Don't count nonced inlines as XSS surface.
  const inlineScriptCount = inlineScriptTags.filter((tag) => !/\bnonce=/i.test(tag)).length
  const onHandlers = Array.from(
    html.matchAll(/\bon[a-z]+\s*=\s*["'][^"']{1,200}["']/gi),
  ).slice(0, 20)
  // Reuse the token-aware analysis from the CSP weakness section: only count
  // 'unsafe-inline' as a problem when it's in script-src AND not neutralized
  // by 'strict-dynamic'+nonce.
  const cspScriptDirective = (cspHeader.match(/\bscript-src\b([^;]*)/i) ?? ['', ''])[1]
  const cspScriptTokens = cspScriptDirective.trim().split(/\s+/).filter(Boolean)
  const cspAllowsInline =
    cspScriptTokens.includes("'unsafe-inline'") &&
    !(
      cspScriptTokens.includes("'strict-dynamic'") &&
      cspScriptTokens.some((t) => t.startsWith("'nonce-"))
    )
  const inlineSurface = inlineScriptCount + onHandlers.length

  if (inlineSurface >= 1 && (cspHeader === '' || cspAllowsInline)) {
    findings.push({
      id: 'html-inline-xss-surface',
      severity: cspHeader === '' ? 'warn' : 'info',
      category: 'html',
      title: 'Inline scripts / event handlers without strict CSP',
      description: `Found ${inlineScriptCount} inline <script> block${
        inlineScriptCount === 1 ? '' : 's'
      } and ${onHandlers.length} inline event handler${
        onHandlers.length === 1 ? '' : 's'
      } (e.g. onclick=). ${
        cspHeader === ''
          ? 'There is no Content-Security-Policy at all, so any reflected/stored XSS payload runs immediately.'
          : 'Your CSP allows "unsafe-inline", which neutralises script-src protection.'
      }`,
      evidence: onHandlers.slice(0, 3).map((m) => m[0].slice(0, 80)).join('\n') ||
        '(inline <script> blocks present)',
      fixPrompt: `Move every inline <script> body and every inline event handler (onclick=, onerror=, etc.) to an external .js file or to a script with a CSP nonce. Then ship a strict CSP that does NOT include 'unsafe-inline' on script-src. For React/Vite this is usually painless — they don't emit inline scripts. The danger is hand-edited HTML or third-party widgets. Once cleaned up, set CSP to: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'".`,
    })
  }

  // target="_blank" without rel="noopener"
  const blankAnchors = Array.from(
    html.matchAll(/<a\b[^>]*\btarget\s*=\s*["']_blank["'][^>]*>/gi),
  )
  const unsafeBlanks: string[] = []
  for (const m of blankAnchors) {
    const tag = m[0]
    if (!/\brel\s*=\s*["'][^"']*\bnoopener\b/i.test(tag)) {
      const hrefMatch = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)
      if (hrefMatch) unsafeBlanks.push(hrefMatch[1])
      if (unsafeBlanks.length >= 5) break
    }
  }
  if (unsafeBlanks.length > 0) {
    findings.push({
      id: 'html-target-blank-no-rel',
      severity: 'info',
      category: 'html',
      title: 'External links use target="_blank" without rel="noopener noreferrer"',
      description: `${unsafeBlanks.length} link${
        unsafeBlanks.length === 1 ? '' : 's'
      } open in a new tab without rel="noopener". The new tab can use window.opener to navigate the original tab to a phishing page (reverse tabnabbing).`,
      evidence: unsafeBlanks.slice(0, 4).join('\n'),
      fixPrompt: `Add rel="noopener noreferrer" to every <a target="_blank">. In React/JSX projects, write: <a href="..." target="_blank" rel="noopener noreferrer">. Most linters can autofix this — enable react/jsx-no-target-blank. The "noreferrer" part also stops Referer leaking to the destination.`,
    })
  }

  // === SERVER HEADER (information disclosure + CVE lookup) ===
  const serverHeader = mainResp.headers.get('server')
  const xPoweredBy = mainResp.headers.get('x-powered-by')
  if (serverHeader && /\d/.test(serverHeader) && !/^cloudflare\b/i.test(serverHeader)) {
    findings.push({
      id: 'headers-server-disclosure',
      severity: 'info',
      category: 'headers',
      title: `Server header reveals software version: ${serverHeader}`,
      description: `The Server response header includes a specific version. Attackers use this to look up known CVEs for your exact stack version. CDNs like Cloudflare, Vercel, Fly mask this automatically — if you're seeing a version, you're behind a self-managed proxy.`,
      evidence: `Server: ${serverHeader}`,
      fixPrompt: `Strip the Server header (or replace it with a generic value) at your reverse proxy. Nginx: "server_tokens off;" in the http {} block. Apache: "ServerTokens Prod" + "ServerSignature Off". Cloudflare/Vercel handle this automatically. Same goes for X-Powered-By — disable it at the framework level (Express: app.disable('x-powered-by')).`,
    })
  }
  // CVE table lookup against Server + X-Powered-By
  const stackString = `${serverHeader ?? ''} ${xPoweredBy ?? ''}`.trim()
  if (stackString) {
    for (const cve of SERVER_CVES) {
      if (cve.match.test(stackString)) {
        findings.push({
          id: `deps-server-cve-${cve.cves[0]}`,
          severity: cve.severity,
          category: 'deps',
          title: `Server stack matches known-vulnerable version: ${cve.cves.join(', ')}`,
          description: `The Server / X-Powered-By header indicates "${stackString.slice(0, 80)}", which matches a known-vulnerable signature. ${cve.note}.`,
          evidence: `${stackString.slice(0, 200)}\nMatched CVE${cve.cves.length === 1 ? '' : 's'}: ${cve.cves.join(', ')}`,
          fixPrompt: `Upgrade the affected component immediately. CVEs flagged: ${cve.cves.join(', ')} — ${cve.note}. Look up the patched version at https://nvd.nist.gov/vuln/search and https://www.cvedetails.com. If you can't upgrade right now, put a CDN/WAF in front (Cloudflare with managed rules) to virtual-patch the most exploited vectors. Then strip the Server/X-Powered-By header so attackers stop fingerprinting you.`,
        })
        break
      }
    }
  }
  if (xPoweredBy) {
    findings.push({
      id: 'headers-x-powered-by',
      severity: 'info',
      category: 'headers',
      title: `X-Powered-By header reveals stack: ${xPoweredBy}`,
      description: `The X-Powered-By response header announces the framework (e.g. Express, PHP, ASP.NET). It serves no client purpose — it just helps attackers fingerprint your stack.`,
      evidence: `X-Powered-By: ${xPoweredBy}`,
      fixPrompt: `Disable X-Powered-By at the framework level. Express: app.disable('x-powered-by'). Next.js: set "poweredByHeader: false" in next.config.js. PHP: set "expose_php = Off" in php.ini. ASP.NET: remove via web.config customHeaders.`,
    })
  }

  // === HTTP METHODS (TRACE / OPTIONS) ===
  const optionsResult = await optionsP
  if (optionsResult.trace) {
    findings.push({
      id: 'methods-trace-enabled',
      severity: 'warn',
      category: 'methods',
      title: 'HTTP TRACE method is enabled',
      description: `The server accepts TRACE requests (announced via the Allow header). TRACE echoes the request back, which can be combined with XSS to leak HttpOnly cookies and authentication headers (Cross-Site Tracing).`,
      evidence: `OPTIONS / → Allow: ${optionsResult.allow ?? '(none)'}`,
      fixPrompt: `Disable TRACE at the proxy/server. Nginx: it's off by default unless you explicitly added it — remove any TRACE handling. Apache: "TraceEnable Off" in httpd.conf. CloudFront / Vercel / Cloudflare: TRACE is blocked by default. If you can't change the origin, put a CDN in front that drops TRACE.`,
    })
  } else if (optionsResult.allow) {
    const methods = optionsResult.allow.split(',').map((s) => s.trim().toUpperCase())
    const hasDangerous = methods.some((m) => ['DELETE', 'PUT', 'PATCH'].includes(m))
    if (hasDangerous) {
      findings.push({
        id: 'methods-options-disclosure',
        severity: 'info',
        category: 'methods',
        title: 'OPTIONS reveals all supported HTTP methods',
        description: `The server's OPTIONS response lists state-changing methods (${methods.join(', ')}). This is normal for REST APIs but should be authenticated — verify each method requires auth, especially DELETE/PUT/PATCH on user data.`,
        evidence: `OPTIONS / → Allow: ${optionsResult.allow}`,
        fixPrompt: `This is informational. Action: pick one DELETE/PUT/PATCH endpoint that operates on user data and confirm it returns 401/403 when called without auth. If your framework auto-routes OPTIONS responses, verify the methods listed match what the endpoint actually allows — surprising methods sometimes leak from default router config.`,
      })
    }
  }

  // === DNS / TLS findings ===
  const dnsSnap = await dnsP
  const tlsSnap = await tlsP

  // TLS version + cipher
  if (tlsSnap.protocol) {
    const proto = tlsSnap.protocol
    if (proto === 'TLSv1' || proto === 'TLSv1.1') {
      findings.push({
        id: 'tls-old-version',
        severity: 'critical',
        category: 'tls',
        title: `Connection negotiated ${proto} — outdated and insecure`,
        description: `${proto} has known weaknesses (BEAST, CRIME, padding oracle). All major browsers removed support in 2020. If a real client connected with this version, something is misconfigured.`,
        evidence: `tls.connect → protocol=${proto}, cipher=${tlsSnap.cipher ?? '?'}`,
        fixPrompt: `Disable TLS 1.0 and 1.1 at the proxy/CDN. On Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version → set to TLS 1.2 or 1.2. On Nginx: "ssl_protocols TLSv1.2 TLSv1.3;" in the server {} block. On Vercel/Netlify: this is handled automatically — if you're seeing old TLS, you're not behind those.`,
      })
    } else if (proto === 'TLSv1.2' && tlsSnap.cipher && /RC4|3DES|NULL|EXPORT|MD5/i.test(tlsSnap.cipher)) {
      findings.push({
        id: 'tls-weak-cipher',
        severity: 'warn',
        category: 'tls',
        title: `TLS 1.2 with weak cipher: ${tlsSnap.cipher}`,
        description: `Cipher ${tlsSnap.cipher} contains a deprecated primitive (RC4, 3DES, NULL, EXPORT, or MD5). Even on TLS 1.2, these ciphers are broken or near-broken.`,
        evidence: `tls.connect → ${proto}, cipher=${tlsSnap.cipher}`,
        fixPrompt: `Update your TLS cipher list to modern AEAD suites: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305". Or upgrade to TLS 1.3, which only has secure ciphers by design.`,
      })
    }
    // Cert near-expiry
    if (tlsSnap.cert?.valid_to) {
      const exp = new Date(tlsSnap.cert.valid_to).getTime()
      if (!Number.isNaN(exp)) {
        const daysLeft = Math.round((exp - Date.now()) / (1000 * 60 * 60 * 24))
        if (daysLeft < 14 && daysLeft >= 0) {
          findings.push({
            id: 'tls-cert-near-expiry',
            severity: 'warn',
            category: 'tls',
            title: `TLS certificate expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
            description: `The certificate is valid until ${tlsSnap.cert.valid_to}. If renewal isn't automated, the site will start serving an invalid cert and browsers will block it.`,
            evidence: `cert valid_to=${tlsSnap.cert.valid_to}`,
            fixPrompt: `Renew the certificate now. If you're on Cloudflare, Vercel, Netlify, or Let's Encrypt with certbot — renewal should be automatic; verify the auto-renew job ran. If you're using a manually-issued cert, set up auto-renewal via certbot or your CA's automation now. Alert someone in the team that the cert expires soon.`,
          })
        } else if (daysLeft < 0) {
          findings.push({
            id: 'tls-cert-expired',
            severity: 'critical',
            category: 'tls',
            title: 'TLS certificate has expired',
            description: `The certificate expired ${-daysLeft} days ago. Most browsers refuse to load the site.`,
            evidence: `cert valid_to=${tlsSnap.cert.valid_to}`,
            fixPrompt: `Renew the cert immediately. Until renewed, the site is broken for end users. If on Vercel/Netlify/Cloudflare, force a fresh issuance from the dashboard. If self-managed, run "certbot renew" and reload your proxy.`,
          })
        }
      }
    }
  }

  // === Platform-shared subdomain detection ===
  // If the user is on *.vercel.app, *.netlify.app, *.pages.dev, etc., the apex
  // DNS records (DMARC/SPF/DNSSEC/CAA) belong to the platform — only the
  // platform can publish them. Suppress those findings and emit one ok-level
  // finding explaining the situation, with a real path to fix (custom domain).
  const sharedPlatform = detectSharedPlatform(url.hostname)
  if (sharedPlatform) {
    findings.push({
      id: 'platform-shared-subdomain',
      severity: 'ok',
      category: 'dns',
      title: `Hosted on ${sharedPlatform.provider} shared subdomain`,
      description: `${url.hostname} sits on the .${sharedPlatform.apex} apex which ${sharedPlatform.provider} owns. DNS-level controls (DMARC, SPF, DNSSEC, CAA) live on that apex and only ${sharedPlatform.provider} can publish them — so this scan won't flag missing records on the shared apex against you.`,
      evidence: `${url.hostname} ends in .${sharedPlatform.apex} (${sharedPlatform.provider}-managed apex)`,
      fixPrompt: `These DNS-level controls (DMARC / SPF / DNSSEC / CAA) require ownership of the apex domain. To gain control: buy a custom domain (~$10-15/yr at Cloudflare or Namecheap), point it at your ${sharedPlatform.provider} project, and publish the records there. Until then, this is intentional and not a finding against your app.`,
    })
  }

  // DNSSEC
  if (!sharedPlatform && !dnsSnap.hasDnskey) {
    findings.push({
      id: 'dns-no-dnssec',
      severity: 'info',
      category: 'dns',
      title: `DNSSEC is not enabled for ${dnsSnap.baseDomain}`,
      description: `No DNSKEY record was found for ${dnsSnap.baseDomain}. Without DNSSEC, your DNS responses are not authenticated — an attacker on a weak network can poison the cache and redirect your users to a malicious server.`,
      evidence: `dns.resolve("${dnsSnap.baseDomain}", "DNSKEY") → no records`,
      fixPrompt: `Enable DNSSEC at your DNS provider. Cloudflare: DNS → DNSSEC → Enable, then add the DS record at your registrar. Route 53: similar flow. After enabling, verify with "dig +dnssec ${dnsSnap.baseDomain}" and at https://dnsviz.net/d/${dnsSnap.baseDomain}/dnssec/.`,
    })
  }

  // CAA
  if (!sharedPlatform && dnsSnap.caa.length === 0) {
    findings.push({
      id: 'dns-no-caa',
      severity: 'info',
      category: 'dns',
      title: `No CAA record for ${dnsSnap.baseDomain}`,
      description: `CAA records say which CAs are allowed to issue certificates for your domain. Without one, ANY CA in the public CA pool can issue a cert for your domain — increasing the blast radius if any CA is compromised.`,
      evidence: `dns.resolveCaa("${dnsSnap.baseDomain}") → no records`,
      fixPrompt: `Add a CAA record. For typical Vercel/Cloudflare setups: "0 issue letsencrypt.org" and "0 issue sectigo.com" (or whoever issues your certs). At Cloudflare: DNS → Add record → CAA → tag=issue, value="letsencrypt.org". Repeat for backup CAs. Also add "0 iodef mailto:security@${dnsSnap.baseDomain}" so CAs can report issuance attempts.`,
    })
  }

  // DMARC + SPF — only check on user-owned apex (skip on shared platforms)
  if (!sharedPlatform) {
    // DMARC
    if (!dnsSnap.dmarc) {
      findings.push({
        id: 'email-no-dmarc',
        severity: 'warn',
        category: 'email',
        title: `No DMARC record for ${dnsSnap.baseDomain}`,
        description: `Without DMARC, anyone can send email pretending to be from @${dnsSnap.baseDomain}. SPF and DKIM alone don't tell receivers what to do with failures — DMARC does.`,
        evidence: `dns.resolveTxt("_dmarc.${dnsSnap.baseDomain}") → no DMARC record`,
        fixPrompt: `Publish a DMARC TXT record at _dmarc.${dnsSnap.baseDomain}. Start in monitor mode: "v=DMARC1; p=none; rua=mailto:dmarc-reports@${dnsSnap.baseDomain}". Wait 1-2 weeks for reports to confirm legitimate senders pass, then ramp to "p=quarantine" and finally "p=reject". Use a service like Postmark, Easydmarc or dmarcian to parse the reports.`,
      })
    } else if (/\bp=none\b/i.test(dnsSnap.dmarc)) {
      findings.push({
        id: 'email-dmarc-monitor',
        severity: 'info',
        category: 'email',
        title: `DMARC is in monitor mode (p=none)`,
        description: `DMARC is published but with p=none — receivers will report failures but will NOT reject spoofed mail. Fine as a 1-2 week monitoring step, but not as a final state.`,
        evidence: `_dmarc.${dnsSnap.baseDomain} → ${dnsSnap.dmarc.slice(0, 200)}`,
        fixPrompt: `Once DMARC reports show your legitimate senders are aligned, ramp the policy. First: "p=quarantine; pct=25" — only quarantine 25% of spoofed mail. Verify nothing legitimate breaks for a week. Then increase pct to 50, 75, 100. Finally switch to "p=reject". Total ramp: ~4 weeks.`,
      })
    }

    // SPF
    if (!dnsSnap.spf) {
      findings.push({
        id: 'email-no-spf',
        severity: 'warn',
        category: 'email',
        title: `No SPF record for ${dnsSnap.baseDomain}`,
        description: `SPF tells receiving mail servers which IPs are allowed to send mail for your domain. Missing SPF means anyone can send "From: anyone@${dnsSnap.baseDomain}" without server-level checks failing.`,
        evidence: `TXT records on ${dnsSnap.baseDomain} contain no "v=spf1"`,
        fixPrompt: `Add an SPF TXT record on ${dnsSnap.baseDomain}. Inventory every service that sends mail as you (Google Workspace, Resend, Mailgun, SendGrid, your transactional ESP, your CRM). Then publish: "v=spf1 include:_spf.google.com include:amazonses.com -all" (replace with your actual senders). End with -all (hard fail), not ~all (soft fail) or ?all (neutral).`,
      })
    } else if (/[~?]all\s*$/i.test(dnsSnap.spf)) {
      findings.push({
        id: 'email-spf-soft-fail',
        severity: 'info',
        category: 'email',
        title: `SPF policy ends with soft-fail (${/~all/.test(dnsSnap.spf) ? '~all' : '?all'})`,
        description: `Your SPF record exists but ends with a non-strict directive. Receivers may still accept mail from unauthorized IPs.`,
        evidence: dnsSnap.spf.slice(0, 200),
        fixPrompt: `Once you're confident your SPF includes every legitimate sender, change the trailing "~all" or "?all" to "-all" (hard fail). Test first by checking your DMARC reports for any legitimate sender that would now fail SPF.`,
      })
    }
  }

  // === REFLECTED XSS canary ===
  const xssHits = await xssP
  if (xssHits.length > 0) {
    findings.push({
      id: 'paths-reflected-xss',
      severity: 'critical',
      category: 'paths',
      title: `Reflected XSS via ${xssHits.length} URL parameter${xssHits.length === 1 ? '' : 's'}`,
      description: `Sending a benign canary tag (<${XSS_CANARY}>) as a URL parameter caused it to be reflected unescaped in the HTML response. An attacker can replace the canary with a malicious script tag and execute arbitrary JS in your users' browsers via a crafted link.`,
      evidence: xssHits
        .map((h) => `?${h.param}=<${XSS_CANARY}> → reflected raw in response body`)
        .join('\n'),
      fixPrompt: `Escape every user-controlled value before rendering it in HTML. Modern frameworks (React, Vue, Svelte, Astro) escape by default — if you are seeing reflection, either you used a raw-HTML escape hatch (the React unsafe inner-HTML prop, Vue v-html, Svelte at-html), OR the HTML is server-rendered without templating (e.g. plain Express + res.send). Switch to a templating engine that escapes (Handlebars, EJS auto-escape, JSX). For specific data that must contain HTML, sanitize with DOMPurify before insertion. Then add a strict Content-Security-Policy WITHOUT unsafe-inline so even an XSS payload cannot run.`,
    })
  }

  // === SQLi error-based ===
  const sqliHits = await sqliP
  if (sqliHits.length > 0) {
    findings.push({
      id: 'paths-sqli-error',
      severity: 'critical',
      category: 'paths',
      title: `SQL error leaked when sending a single quote in ${sqliHits.length} parameter${
        sqliHits.length === 1 ? '' : 's'
      }`,
      description: `Sending a single-quote character as a URL parameter caused the server to respond with a database error message. This means user input is being concatenated into SQL without parameterization — classic SQL injection territory.`,
      evidence: sqliHits.map((h) => `?${h.param}=quote → response contained: ${h.pattern}`).join('\n'),
      fixPrompt: `STOP concatenating user input into SQL. Use parameterized queries (a.k.a. prepared statements) everywhere: db.query('SELECT * FROM users WHERE id = $1', [userId]). All major DB clients support this — pg, mysql2, sqlite3, Prisma, Drizzle, Supabase. Then make the error pages stop leaking stack traces in production: catch the error, log it server-side, return a generic "500 Internal Server Error" to the client. Audit every endpoint that accepts user input — the params we tested (id, q, search, page, category) are common but you may have others.`,
    })
  }

  // === HTTP→HTTPS redirect check ===
  if (url.protocol === 'https:') {
    const httpRedirect = await httpRedirectP
    if (httpRedirect.finalProtocol === 'http') {
      findings.push({
        id: 'tls-no-http-redirect',
        severity: 'warn',
        category: 'tls',
        title: 'http:// version of the site is reachable without redirect to https://',
        description: `The same hostname served plain HTTP without redirecting to HTTPS. A user typing the bare domain into a browser may end up on the unencrypted version, where session cookies and form data leak in cleartext. HSTS only kicks in AFTER the first HTTPS visit.`,
        evidence: `GET http://${url.hostname}/ → 200 (no 301/302 to https)`,
        fixPrompt: `Configure your origin/proxy to ALWAYS 308 redirect http://${url.hostname} to https://${url.hostname}. Then add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (so future visits skip the HTTP step entirely). On Vercel/Netlify/Cloudflare Pages this is automatic — if you're seeing HTTP working, you're not behind those.`,
      })
    }
  }

  // === OPEN REDIRECT ===
  const openRedirects = await openRedirectP
  if (openRedirects.length > 0) {
    findings.push({
      id: 'paths-open-redirect',
      severity: 'warn',
      category: 'paths',
      title: `Open redirect found in ${openRedirects.length} URL parameter${
        openRedirects.length === 1 ? '' : 's'
      }`,
      description: `Sending a benign canary URL (${REDIRECT_CANARY}) as the redirect target caused the server to 30x with our canary in the Location header. Attackers use this to phish — "https://your-trusted-site/?redirect=https://evil.example" looks legit until clicked.`,
      evidence: openRedirects
        .map((r) => `?${r.param}=${REDIRECT_CANARY} → 302 Location: ${r.redirectsTo}`)
        .slice(0, 4)
        .join('\n'),
      fixPrompt: `Treat every redirect parameter as untrusted input. Two patterns: (1) allow-list — keep a list of internal paths you redirect to, reject anything not in the list. (2) origin-restriction — parse the redirect target as a URL, ensure its origin matches yours, otherwise drop it. Specific to OAuth flows: use the OAuth state parameter and validate it on return. Never redirect to a user-supplied absolute URL without validation.`,
    })
  }

  // === FIREBASE RTDB EXPOSURE ===
  const firebase = await firebaseP
  if (firebase?.exposed) {
    findings.push({
      id: 'paths-firebase-rtdb',
      severity: 'critical',
      category: 'paths',
      title: 'Firebase Realtime Database root is publicly readable',
      description: `GET /.json returned ${firebase.bytes} bytes of JSON. Your Firebase Realtime Database rules allow unauthenticated reads from the root, exposing the entire database. This is a textbook misconfiguration — usually a leftover "allow read: if true" from a tutorial.`,
      evidence: `GET /.json → ${firebase.bytes} bytes\n${firebase.sample}`,
      fixPrompt: `Open the Firebase Console → Realtime Database → Rules and replace any "allow read: if true" or ".read": true with proper rules: ".read": "auth != null && root.child('users').child(auth.uid).exists()" (or whatever ownership rule your data model uses). Default to deny. Then test from an unauthenticated client — /.json should return 401. Also audit Cloud Firestore rules and Storage rules for the same anti-pattern.`,
    })
  }

  // === ROBOTS.TXT ANALYSIS ===
  const robots = await robotsP
  if (robots) {
    const disallowLines = robots.match(/^Disallow:\s*(\S+)/gim) ?? []
    const sensitive: string[] = []
    for (const line of disallowLines) {
      const pathMatch = /Disallow:\s*(\S+)/i.exec(line)
      if (!pathMatch) continue
      const p = pathMatch[1]
      if (SUSPICIOUS_ROBOT_PATHS.some((re) => re.test(p))) {
        sensitive.push(p)
        if (sensitive.length >= 8) break
      }
    }
    if (sensitive.length > 0) {
      findings.push({
        id: 'paths-robots-disclosure',
        severity: 'info',
        category: 'paths',
        title: `robots.txt advertises sensitive paths`,
        description: `robots.txt is meant to control crawlers, not security. Listing /admin or /api/internal in Disallow rules tells an attacker exactly where to look. ${sensitive.length} suspicious-looking path${sensitive.length === 1 ? '' : 's'} found.`,
        evidence: sensitive.slice(0, 5).join('\n'),
        fixPrompt: `Don't put sensitive paths in robots.txt. Either (a) make them genuinely unguessable (long random tokens) and rely on auth, or (b) leave them out of robots.txt entirely — search engines wouldn't find them anyway if they're behind auth. The ONLY thing robots.txt should disallow is content you want to hide from search engines but is fine for humans (e.g. /search results, /print views). Real access control belongs in your auth middleware.`,
      })
    }
  }

  // === SITEMAP.XML ANALYSIS ===
  const sitemap = await fetchSitemap(url.origin, robots).catch(() => null)
  if (sitemap) {
    const locs = Array.from(sitemap.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi))
      .map((m) => m[1].trim())
      .slice(0, 200)
    const internal: string[] = []
    for (const loc of locs) {
      if (SUSPICIOUS_SITEMAP_PATHS.some((re) => re.test(loc))) {
        internal.push(loc)
        if (internal.length >= 8) break
      }
    }
    if (internal.length > 0) {
      findings.push({
        id: 'paths-sitemap-internal',
        severity: 'info',
        category: 'paths',
        title: 'sitemap.xml lists internal-looking URLs',
        description: `Found ${internal.length} URL${
          internal.length === 1 ? '' : 's'
        } in sitemap.xml that look internal (admin / staging / dev / draft / preview / _internal). Sitemaps are crawled by search engines AND attackers. If any of these are auth-protected, fine — but verify.`,
        evidence: internal.slice(0, 5).join('\n'),
        fixPrompt: `Audit your sitemap.xml. For each URL listed: confirm it's intentional public content. Internal pages (admin panels, staging routes, draft posts) should NOT be in the sitemap. If your CMS auto-generates the sitemap, configure it to exclude paths matching /admin, /staging, /draft, /preview. For Next.js: add a custom getServerSideSitemap or filter in next-sitemap config. The simpler fix: don't expose admin under guessable URLs in the first place — use a long random subpath.`,
      })
    }
  }

  // === DKIM ===
  const dkim =
    url.protocol === 'https:' ? await probeDkim(dnsSnap.baseDomain).catch(() => null) : null
  if (!sharedPlatform && !dkim && (dnsSnap.dmarc || dnsSnap.spf)) {
    // Only flag if DMARC or SPF exists — otherwise the domain probably doesn't send mail at all.
    findings.push({
      id: 'email-no-dkim',
      severity: 'info',
      category: 'email',
      title: `No DKIM record found for ${dnsSnap.baseDomain} (common selectors)`,
      description: `Probed ${DKIM_COMMON_SELECTORS.length} common DKIM selectors (incl. provider-specific: resend, amazonses, postmark, sg/SendGrid, sm/SparkPost, mailgun, fm1-3/Fastmail, protonmail, zoho, google) — none returned a TXT record matching DKIM key shape. SPF and/or DMARC are present, which means the domain *is* set up to send mail; DKIM should be signed alongside or DMARC alignment will fail.`,
      evidence: `Probed: ${DKIM_COMMON_SELECTORS.map((s) => `${s}._domainkey.${dnsSnap.baseDomain}`).slice(0, 6).join(', ')}, +${DKIM_COMMON_SELECTORS.length - 6} more — none matched /v=DKIM1/i or /p=<base64>/i.`,
      fixPrompt: [
        `STEP 1 — IDENTIFY YOUR MAIL PROVIDERS.`,
        `Inventory every service that sends mail FROM @${dnsSnap.baseDomain}: transactional ESP (Resend / Postmark / Mailgun / SendGrid / SES / Mandrill / SparkPost), marketing platform (Mailchimp / ConvertKit), CRM auto-replies (HubSpot / Salesforce), Google Workspace if you use it, your app's own SMTP if any. Each ONE needs its own DKIM key published.`,
        ``,
        `STEP 2 — FETCH THE EXACT DNS RECORDS PER PROVIDER.`,
        `Each provider's dashboard has a "Verify domain" or "DKIM" section that shows the EXACT records to publish. They'll typically show:`,
        `  • TXT  resend._domainkey      → "p=MIGfMA0GCSqGSIb3DQEBAQUAA..."`,
        `  • TXT  google._domainkey      → "v=DKIM1; k=rsa; p=MIGfMA0..."`,
        `  • TXT  mail._domainkey        → "v=DKIM1; k=rsa; p=MIGfMA0..."`,
        `  • TXT  sg._domainkey          → "k=rsa; t=s; p=MIGfMA0..."`,
        `Note the selector NAME the provider tells you to use — it is FIXED per provider, you do not invent it.`,
        ``,
        `STEP 3 — PUBLISH AT YOUR DNS PROVIDER.`,
        `If GoDaddy: dcc.godaddy.com/control/dnsmanagement?domainName=${dnsSnap.baseDomain} → Add Record → TXT → Name = "<selector>._domainkey" (just the prefix, GoDaddy auto-appends domain) → Value = the exact string from your provider → TTL 600. Repeat for each provider.`,
        `If Cloudflare: API call \`POST /zones/<zone>/dns_records {"type":"TXT","name":"<selector>._domainkey","content":"<exact value>"}\`. CLI: \`flarectl dns create --zone ${dnsSnap.baseDomain} --type TXT --name <selector>._domainkey --content '<value>'\`.`,
        `If Route 53: \`aws route53 change-resource-record-sets --hosted-zone-id <id> --change-batch '{"Changes":[{"Action":"CREATE","ResourceRecordSet":{"Name":"<selector>._domainkey.${dnsSnap.baseDomain}","Type":"TXT","TTL":600,"ResourceRecords":[{"Value":"\\\"<value>\\\""}]}}]}'\`.`,
        ``,
        `STEP 4 — VERIFY EACH SELECTOR PROPAGATED.`,
        `For every selector you added: \`dig +short TXT <selector>._domainkey.${dnsSnap.baseDomain}\` should return the public-key string within 5-30 minutes. If it returns empty after 30 min, the record didn't save — check the registrar dashboard.`,
        ``,
        `STEP 5 — VALIDATE END-TO-END WITH A REAL SEND.`,
        `Send one test email from each provider TO mail-tester.com (free, no signup) and view the report. The DKIM section MUST show "DKIM signature: passed" with the correct selector AND domain alignment with ${dnsSnap.baseDomain}. If "neutral" or "fail" — the public key in DNS doesn't match the private key the provider is signing with (typically a copy-paste error in step 3).`,
        ``,
        `WHY DMARC ALIGNMENT MATTERS:`,
        `Your DMARC record (\`_dmarc.${dnsSnap.baseDomain}\`) tells receivers what to do when SPF or DKIM fail. With p=quarantine or p=reject, an UNALIGNED message lands in spam (or bounces). With DKIM published correctly per provider, "dkim=pass + aligned" satisfies DMARC even if the message routes through a forwarder that breaks SPF — which is why DKIM is the more durable of the two.`,
        ``,
        `COMMON MISTAKES TO AVOID:`,
        `• Pasting the value WITHOUT the surrounding quotes when the registrar UI shows quotes in their example. Most registrars want the bare value.`,
        `• Pasting the value WITH the leading/trailing whitespace from the provider's copy button.`,
        `• Adding "v=DKIM1; k=rsa;" prefix yourself — Resend / SES intentionally omit \`v=\` and just publish \`p=...\`. RFC 6376 §3.6.1 makes \`v=\` OPTIONAL. Use exactly what the provider shows.`,
        `• Truncating long records — DKIM TXT records often exceed the 255-char single-string limit and are split into chunks. Most registrars handle this automatically; if yours doesn't, manually chunk and put each in quotes.`,
      ].join('\n'),
    })
  }

  // === FORM CSRF token ===
  const forms = Array.from(html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi))
  let formsWithoutCsrf = 0
  let formsTotalPost = 0
  const sampleFormActions: string[] = []
  for (const m of forms) {
    const formTag = m[0].slice(0, m[0].indexOf('>') + 1)
    const isPost = /\bmethod\s*=\s*["']?post["']?/i.test(formTag)
    if (!isPost) continue
    formsTotalPost++
    const inner = m[1]
    const hasCsrfField =
      /name\s*=\s*["'](?:_csrf|csrf|csrf_token|authenticity_token|_token|csrfmiddlewaretoken|__RequestVerificationToken)["']/i.test(
        inner,
      )
    if (!hasCsrfField) {
      formsWithoutCsrf++
      const action = /\baction\s*=\s*["']([^"']+)["']/i.exec(formTag)?.[1] ?? '(no action attr)'
      if (sampleFormActions.length < 4) sampleFormActions.push(action)
    }
  }
  if (formsTotalPost > 0 && formsWithoutCsrf > 0) {
    findings.push({
      id: 'html-form-no-csrf',
      severity: 'warn',
      category: 'html',
      title: `${formsWithoutCsrf} of ${formsTotalPost} POST form${
        formsTotalPost === 1 ? '' : 's'
      } missing a CSRF token field`,
      description: `Forms that POST without a CSRF token can be triggered by a hostile site (Cross-Site Request Forgery). If the form changes server-side state — login, password change, money transfer, profile update — this is exploitable. We checked for the common token field names: _csrf, csrf, csrf_token, authenticity_token, _token, csrfmiddlewaretoken, __RequestVerificationToken.`,
      evidence: sampleFormActions.length > 0 ? sampleFormActions.join('\n') : '(form has no action attribute)',
      fixPrompt: `Pick a CSRF strategy: (1) double-submit cookie — issue a token in a SameSite=Lax cookie and require the same token as a hidden field, server compares. (2) framework-builtin — Django/Rails/NextAuth all ship CSRF middleware, just enable it. (3) Modern alternative: rely on SameSite=Lax cookies (default in Chrome) for browser-only CSRF defense, but verify the cookie is Lax on the auth cookie. The safest default is double-submit cookie + SameSite=Lax. Add the token as a hidden input named "_csrf" to every <form method="POST">.`,
    })
  }

  // === AUTH SIGNUP endpoint probing ===
  const signupResults = await signupP
  if (signupResults.length > 0) {
    const evidenceLines = signupResults
      .map((s) => `${s.path} → ${s.status} (${s.label})`)
      .join('\n')
    const hasSupabase = signupResults.some((s) => s.path === '/auth/v1/signup')
    findings.push({
      id: 'auth-signup-endpoint-found',
      severity: 'info',
      category: 'auth',
      title: hasSupabase
        ? 'Supabase Auth signup endpoint is live'
        : `${signupResults.length} signup endpoint${signupResults.length === 1 ? '' : 's'} reachable`,
      description: hasSupabase
        ? 'Your Supabase project exposes /auth/v1/signup. Verify that you actually want open public signup. If this is an internal/admin app, disable signup in Supabase Dashboard → Authentication → Providers → Email or whitelist allowed emails in RLS via auth.jwt() ->> "email".'
        : 'A signup-style endpoint responds. If this is an internal app or you don\'t want public registration, lock it down. We did NOT POST anything — only sent GET requests to detect existence.',
      evidence: evidenceLines,
      fixPrompt: hasSupabase
        ? `Decide whether you want open public signup. If NO — go to Supabase Dashboard → Authentication → Providers → Email and disable "Enable email signups". For internal apps, also restrict via RLS: every protected table should check auth.jwt() ->> 'email' against a whitelist (allowed_emails table) — never rely on auth.uid() IS NOT NULL alone. If YES (you want public signup) — at minimum enable Email confirmation, set rate limits in Supabase Auth settings, and consider Turnstile/hCaptcha on the signup page to block automated abuse.`
        : `Audit each detected signup endpoint and decide if open registration is intended. If yes — add CAPTCHA, email verification, and rate limiting. If no — return 404 for unauthenticated callers and only allow signup via authenticated invite flow.`,
    })
  }

  // Subdomain takeover hint
  if (dnsSnap.cname) {
    const cnameLower = dnsSnap.cname.toLowerCase()
    const match = TAKEOVER_PRONE_HOSTS.find((h) => cnameLower.endsWith(h.suffix))
    if (match) {
      findings.push({
        id: 'dns-cname-takeover-hint',
        severity: 'info',
        category: 'dns',
        title: `Domain CNAMEs to a takeover-prone host (${match.provider})`,
        description: `${url.host} has a CNAME to ${dnsSnap.cname}, which is on ${match.provider}. If the target subdomain is ever deleted (e.g. you delete the Vercel/Heroku app but forget to remove the CNAME), an attacker can claim that subdomain and serve content from your domain. We don't actively probe to confirm — that's by design.`,
        evidence: `${url.host} CNAME → ${dnsSnap.cname}`,
        fixPrompt: `Audit your DNS: list every CNAME that points to ${match.provider} (or any *.github.io, *.herokuapp.com, *.vercel.app, *.netlify.app, *.s3.amazonaws.com, *.azurewebsites.net). For each, confirm the target is still owned and active. When you delete an app/service, ALSO delete the CNAME the same day — set yourself a reminder. There are paid services (Detectify, Subjack) that monitor this continuously.`,
      })
    }
  }

  // === SUPABASE EDGE FUNCTIONS ===
  if (supabaseProjectIds.size > 0) {
    const projectId = Array.from(supabaseProjectIds)[0]
    const edgeFns = await probeEdgeFunctions(projectId).catch(
      () => [] as { name: string; status: number; cors: string | null }[],
    )
    const wildcardCors = edgeFns.filter((f) => f.cors === '*')
    if (wildcardCors.length > 0) {
      findings.push({
        id: 'auth-edge-fn-cors-wildcard',
        severity: 'warn',
        category: 'auth',
        title: `${wildcardCors.length} Supabase Edge Function${wildcardCors.length === 1 ? '' : 's'} respond with wildcard CORS`,
        description: `Functions ${wildcardCors.map((f) => f.name).join(', ')} respond to OPTIONS with Access-Control-Allow-Origin: *. Combined with cookie-based auth, this can let any other site call your function on behalf of a logged-in user.`,
        evidence: wildcardCors.map((f) => `${projectId}.supabase.co/functions/v1/${f.name} → CORS: *`).join('\n'),
        fixPrompt: `In each Edge Function (supabase/functions/<name>/index.ts), replace the "Access-Control-Allow-Origin: *" pattern with a strict allowlist. Read the Origin header from the request, check it against your known frontends (https://v-guards.com, https://yourapp.com), and only echo it back if matched — otherwise omit the header entirely. The standard pattern: "const origin = req.headers.get('origin'); const ALLOW = ['https://yourapp.com']; const allow = ALLOW.includes(origin) ? origin : ALLOW[0];".`,
      })
    } else if (edgeFns.length > 0) {
      findings.push({
        id: 'auth-edge-fn-detected',
        severity: 'info',
        category: 'auth',
        title: `${edgeFns.length} Supabase Edge Function${edgeFns.length === 1 ? '' : 's'} live on this project`,
        description: `Functions ${edgeFns.map((f) => f.name).join(', ')} are reachable on ${projectId}.supabase.co/functions/v1/. We did not invoke them — just probed via OPTIONS. Audit each one: JWT validation, rate limit, input validation.`,
        evidence: edgeFns.map((f) => `${f.name} (status ${f.status}, CORS: ${f.cors ?? 'none'})`).join('\n'),
        fixPrompt: `For each Edge Function, ensure: (1) The first lines call supabase.auth.getUser() with the Authorization header — refuse the request if not a valid JWT. (2) The function is idempotent and safe to call without harm if reached unauthenticated (so OPTIONS pre-flight without auth doesn't accidentally do work). (3) CORS is restricted to your known frontends. (4) There's a per-user / per-IP rate limit (Supabase doesn't provide this — implement in the function or in a Redis check).`,
      })
    }
  }

  // === FIREBASE STORAGE ===
  // Detect Firebase project IDs from HTML/bundles
  for (const m of html.matchAll(/https:\/\/([a-z0-9-]+)\.firebaseapp\.com/gi)) {
    firebaseIdsCollected.add(m[1])
  }
  for (const m of html.matchAll(/firebaseio\.com\/[?#]?\?ns=([a-z0-9-]+)/gi)) {
    firebaseIdsCollected.add(m[1])
  }
  for (const m of html.matchAll(/projectId\s*[:=]\s*["']([a-z0-9-]+)["']/gi)) {
    firebaseIdsCollected.add(m[1])
  }
  if (firebaseIdsCollected.size > 0) {
    const projectId = Array.from(firebaseIdsCollected)[0]
    const fbStorage = await probeFirebaseStorage(projectId).catch(() => null)
    if (fbStorage?.exposed) {
      findings.push({
        id: 'paths-firebase-storage-public',
        severity: 'critical',
        category: 'paths',
        title: 'Firebase Storage bucket allows public file listing',
        description: `Firebase Storage at ${projectId}.appspot.com responds to anonymous list-objects requests with file metadata. Anyone can enumerate every file in the bucket.`,
        evidence: `GET firebasestorage.googleapis.com/v0/b/${projectId}.appspot.com/o → ${fbStorage.sample}`,
        fixPrompt: `Open the Firebase Console → Storage → Rules and replace "allow read, write: if true;" with proper rules: "allow read: if request.auth != null && resource.metadata.uploadedBy == request.auth.uid;" (or whatever ownership rule matches your data model). Enable App Check to require valid client attestation. Then re-test: anonymous list should return 403.`,
      })
    }
  }

  // === SUPABASE STORAGE BUCKET PROBE ===
  if (supabaseProjectIds.size > 0) {
    const projectId = Array.from(supabaseProjectIds)[0]
    const buckets = await probeSupabaseStorage(projectId).catch(
      () => [] as { bucket: string; status: number }[],
    )
    const publicBuckets = buckets.filter((b) => b.status === 200)
    const existsBuckets = buckets.filter((b) => b.status === 400)
    if (publicBuckets.length > 0) {
      findings.push({
        id: 'paths-supabase-storage-public-listing',
        severity: 'critical',
        category: 'paths',
        title: `Supabase Storage bucket allows public directory listing`,
        description: `The Supabase project ${projectId}.supabase.co has ${publicBuckets.length} public bucket${publicBuckets.length === 1 ? '' : 's'} where directory listing is enabled. Anyone can enumerate every file you've uploaded.`,
        evidence: publicBuckets.map((b) => `https://${projectId}.supabase.co/storage/v1/object/public/${b.bucket}/`).join('\n'),
        fixPrompt: `Disable directory listing on these buckets. In Supabase Dashboard → Storage → ${publicBuckets.map((b) => b.bucket).join(', ')} → Configuration: turn off "Public bucket" if you don't actually need anonymous access. If you do need public access (e.g. user avatars), keep "Public" but ensure file names are unguessable (UUIDs, not user IDs). RLS policies on the storage.objects table should restrict listing operations. Re-test by GET'ing /storage/v1/object/public/<bucket>/ — should return 400 not 200.`,
      })
    } else if (existsBuckets.length > 0) {
      findings.push({
        id: 'paths-supabase-storage-info',
        severity: 'info',
        category: 'paths',
        title: `Supabase project detected: ${projectId} (${existsBuckets.length} bucket${existsBuckets.length === 1 ? '' : 's'} exist)`,
        description: `Project ${projectId}.supabase.co has buckets named ${existsBuckets.map((b) => b.bucket).join(', ')}. Listing is blocked (good) but verify each bucket's RLS rules.`,
        evidence: existsBuckets.map((b) => `${b.bucket} (HTTP 400 = bucket exists, listing blocked)`).join('\n'),
        fixPrompt: `Audit each bucket's RLS policies in Supabase Dashboard → Storage → <bucket> → Policies. Confirm: (1) only authenticated users can SELECT (read) sensitive files, (2) INSERT/UPDATE/DELETE checks ownership (auth.uid() = owner_id), (3) public buckets only contain non-sensitive content with unguessable names. Run a quick test: try downloading a file from each bucket as anon — only intended-public files should succeed.`,
      })
    }
  }

  // === S3 BUCKET PROBE ===
  if (s3BucketHosts.size > 0) {
    const s3Results = await probeS3Buckets(Array.from(s3BucketHosts)).catch(
      () => [] as { bucket: string; listAllowed: boolean }[],
    )
    const listAllowed = s3Results.filter((r) => r.listAllowed)
    if (listAllowed.length > 0) {
      findings.push({
        id: 'paths-s3-listbucket',
        severity: 'critical',
        category: 'paths',
        title: `${listAllowed.length} S3 bucket${listAllowed.length === 1 ? '' : 's'} allow public ListBucket`,
        description: `Sending GET /?list-type=2 to ${listAllowed.map((r) => r.bucket).join(', ')} returned <ListBucketResult> XML. Anyone can enumerate every object in the bucket — even if the objects themselves require auth, knowing what files exist is itself a leak.`,
        evidence: listAllowed.map((r) => `https://${r.bucket}/?list-type=2 → ListBucketResult (anon)`).join('\n'),
        fixPrompt: `Block anonymous ListBucket. In AWS Console → S3 → Bucket → Permissions → Bucket Policy: remove any "s3:ListBucket" with "Principal": "*". Also enable "Block Public Access" at the bucket level. If you need public READ on individual objects (e.g. CDN content), keep that — just don't allow listing. Test with: curl https://<bucket>.s3.amazonaws.com/?list-type=2 — should return 403 AccessDenied.`,
      })
    } else if (s3BucketHosts.size > 0) {
      // Found references but couldn't list — informational
      findings.push({
        id: 'paths-s3-references',
        severity: 'info',
        category: 'paths',
        title: `${s3BucketHosts.size} S3 bucket${s3BucketHosts.size === 1 ? '' : 's'} referenced from this site`,
        description: `Found references to ${Array.from(s3BucketHosts).slice(0, 3).join(', ')}${s3BucketHosts.size > 3 ? ` and ${s3BucketHosts.size - 3} more` : ''}. ListBucket is not allowed (good). Audit object-level permissions and ensure public READ only applies to truly public content.`,
        evidence: Array.from(s3BucketHosts).slice(0, 5).join('\n'),
        fixPrompt: `For each detected S3 bucket: confirm "Block Public Access" is enabled at the bucket level and only specific objects are public (via per-object ACL, not bucket policy). Use CloudFront in front of the bucket for cacheable public content — never expose s3.amazonaws.com URLs directly to end users.`,
      })
    }
  }

  // === NPM CVE matches ===
  for (const hit of npmCveHits) {
    findings.push({
      id: `deps-npm-${hit.cve.pkg}`,
      severity: hit.cve.severity,
      category: 'deps',
      title: `${hit.cve.pkg} version matches ${hit.cve.cve}`,
      description: `Found a version string in your bundle matching a known-vulnerable ${hit.cve.pkg} version. ${hit.cve.note}.`,
      evidence: `Bundle pattern: ${hit.sample.slice(0, 80)}\nCVE: ${hit.cve.cve}`,
      fixPrompt: `Upgrade ${hit.cve.pkg}: run "npm install ${hit.cve.pkg}@latest" (or pin to the patched version listed at https://nvd.nist.gov/vuln/detail/${hit.cve.cve}). After upgrading, run "npm audit fix" to catch any transitive vulns. Then redeploy and rescan to confirm the version string is updated. ${hit.cve.note}.`,
    })
  }

  // === AI ENDPOINT PASSIVE DETECTION (post-bundle) ===
  const aiEndpoints = detectAiEndpoints(html, bundleTextAll)
  if (aiEndpoints.length > 0) {
    findings.push({
      id: 'ai-endpoint-detected',
      severity: 'info',
      category: 'ai',
      title: `${aiEndpoints.length} AI/LLM endpoint${aiEndpoints.length === 1 ? '' : 's'} referenced`,
      description: `Found references to ${aiEndpoints.join(', ')} in the HTML or bundles. AI endpoints often accept user-supplied prompts and forward them to a model. Common gotchas: accepting "system" override from the request body, no rate limit, no auth. We did NOT actively probe these — flag is informational so you can audit them yourself.`,
      evidence: aiEndpoints.slice(0, 6).join('\n'),
      fixPrompt: `For each AI endpoint, audit: (1) Is the system prompt set ONLY server-side? Reject any "system" or "messages[0].role==system" override from the request body. (2) Is there auth? Random visitors should not be able to spend tokens on your account. (3) Is there a per-IP / per-user rate limit? (4) Is the prompt template escaped to prevent indirect injection from user data? (5) Does the response stream go through a content filter for PII / unsafe completions? See OWASP LLM Top 10 for the full checklist.`,
    })
  }

  // === JS AST ANALYSIS (S1+6) ===
  // Real parse over up to 4 bundles. Catches patterns regex misses:
  // runtime code-gen, DOM-injection sinks, hardcoded creds in object
  // literals, template-literal fetches.
  let astResult: ReturnType<typeof analyzeBundlesAst> | null = null
  if (bundleTexts.length > 0) {
    try {
      astResult = analyzeBundlesAst(bundleTexts)
    } catch {
      // parse went sideways — continue scan without AST findings
    }
  }
  if (astResult) {
    if (astResult.evalCalls > 0 || astResult.functionCtorCalls > 0) {
      const total = astResult.evalCalls + astResult.functionCtorCalls
      findings.push({
        id: 'js-ast-runtime-codegen',
        severity: 'warn',
        category: 'html',
        title: `${total} runtime code-generation call${total === 1 ? '' : 's'} in shipped JS`,
        description: `Static AST parse of your bundles found ${astResult.evalCalls} direct invocations of the runtime code evaluator and ${astResult.functionCtorCalls} uses of the Function constructor. Both let strings turn into executable code at runtime — a textbook XSS amplifier when any of those strings come from user input or DOM content. They also defeat CSP's protections (you'd need 'unsafe-eval' to allow them).`,
        evidence: `Direct evaluator calls: ${astResult.evalCalls}\nFunction-constructor uses: ${astResult.functionCtorCalls}\nParsed bundles: ${astResult.parsedBundles}, skipped: ${astResult.skippedBundles}`,
        fixPrompt: `Audit every site of runtime code generation. The two patterns above are almost always replaceable: (1) for JSON parsing, use JSON.parse; (2) for dynamic property access, use bracket notation; (3) for templating, use a real template engine that escapes by default; (4) for plugin systems, use ES modules + dynamic import(). After removing them, drop 'unsafe-eval' from your CSP — that alone closes one of the largest XSS amplification surfaces you can have.`,
      })
    }
    if (astResult.domSinkAssignments.length > 0) {
      // SPA frameworks ship vendor code that uses these sinks internally to
      // implement their own escape-hatch props. A small count on an app whose
      // framework was detected is statistically vendor-internal, not user-
      // controlled. Demote to info so the finding remains visible without
      // blocking the score; raw app misuse will trip separate JSX-prop
      // detectors aimed at framework escape hatches.
      const isSpaFramework =
        detectedFramework === 'Next.js' ||
        detectedFramework === 'Nuxt' ||
        detectedFramework === 'Vite + React' ||
        detectedFramework === 'SvelteKit' ||
        detectedFramework === 'Remix' ||
        detectedFramework === 'Astro'
      const demoteToInfo = isSpaFramework && astResult.domSinkAssignments.length <= 3
      findings.push({
        id: 'js-ast-dom-sink',
        severity: demoteToInfo ? 'info' : 'warn',
        category: 'html',
        title: `${astResult.domSinkAssignments.length} DOM-injection sink${astResult.domSinkAssignments.length === 1 ? '' : 's'} in shipped JS`,
        description: demoteToInfo
          ? `AST parse found ${astResult.domSinkAssignments.length} assignment${astResult.domSinkAssignments.length === 1 ? '' : 's'} to a DOM-sink property in the shipped JS. ${detectedFramework} ships vendor code that uses these sinks internally to implement its escape-hatch props; a small count on a framework app is usually vendor-internal, not under your control. Worth a glance — search your source for the framework's HTML-injection prop and confirm any user-controlled string is sanitized first (DOMPurify) before it reaches that prop.`
          : `AST parse found assignments to innerHTML / outerHTML, or calls to insertAdjacentHTML / write* on the document. These are DOM XSS sinks: any user-controlled string that ends up here renders as HTML, including <script> and event handlers. Safe only if the input is hard-coded or run through a sanitizer like DOMPurify before reaching the sink.`,
        evidence: astResult.domSinkAssignments
          .slice(0, 6)
          .map((s) => `${s.sink}: ${s.sample}`)
          .join('\n'),
        fixPrompt: `For every site listed above, switch to safe DOM APIs: textContent (no HTML interpretation), createElement + appendChild (structured DOM), or run the input through DOMPurify.sanitize() if HTML is genuinely needed. React: avoid setting the explicit innerHTML escape-hatch prop; if forced, sanitize first. After fixing, redeploy and rerun this scan — the count should drop.`,
      })
    }
    if (astResult.hardcodedCredentials.length > 0) {
      findings.push({
        id: 'js-ast-hardcoded-creds',
        severity: 'critical',
        category: 'secrets',
        title: `${astResult.hardcodedCredentials.length} hardcoded credential${astResult.hardcodedCredentials.length === 1 ? '' : 's'} in object literals`,
        description: `AST parse found object-literal patterns where a credential-shaped key (apiKey, secret, token, password, etc.) is bound to a credential-shaped string value in your shipped JS. Regex-based scanners miss these because the value alone may not match a known provider; the structure (key + secret-shaped value) is what gives them away. Whatever this token is, it's now public.`,
        evidence: astResult.hardcodedCredentials
          .slice(0, 6)
          .map((c) => `{ ${c.keyName}: "${c.valueSample}" }`)
          .join('\n'),
        fixPrompt: `Treat each token above as fully compromised — rotate it on the issuing service immediately. Then move the credential out of client code: read from process.env on the server, expose only what the client needs through your own /api endpoints. For tokens that MUST live client-side (like Supabase anon keys), confirm they're truly meant to be public and that RLS / equivalent gates are enforced on the data they unlock.`,
      })
    }
    if (astResult.templateUrlFetches > 0) {
      findings.push({
        id: 'js-ast-template-url-fetch',
        severity: 'info',
        category: 'meta',
        title: `${astResult.templateUrlFetches} fetch/axios call${astResult.templateUrlFetches === 1 ? '' : 's'} use template-literal URLs`,
        description: `Found ${astResult.templateUrlFetches} call site${astResult.templateUrlFetches === 1 ? '' : 's'} where the URL is built with template-string interpolation (\`fetch(\\\`/api/users/\${id}\\\`)\`). Most are fine, but template-literal URL builders are a common SSRF / open-redirect surface when the interpolated value is user-supplied without validation. Worth auditing each.`,
        evidence: `${astResult.templateUrlFetches} call sites in ${astResult.parsedBundles} parsed bundle${astResult.parsedBundles === 1 ? '' : 's'}`,
        fixPrompt: `For each fetch/axios call with a template URL: validate the interpolated values. (1) If the value is a user-controlled ID, parse it through Number / UUID validator first. (2) If it's a path segment, encodeURIComponent it. (3) If it's a full URL coming from props, allowlist the host. Block anything that resolves to private IPs (10.x, 172.16-31.x, 192.168.x, 169.254.x, localhost) before fetching to prevent SSRF.`,
      })
    }
  }

  // === API SURFACE PROBES (S1+4) ===
  // OpenAPI / Swagger / GraphQL / tRPC discovery — public spec exposure
  // is a recon goldmine for attackers; introspection on prod is even more so.
  const apiProbe = await probeApiSurface(url.origin, bundleTextAll).catch(
    (): ApiSurfaceProbeResult => ({
      openapi: { foundAt: null, endpoints: [] },
      graphql: { foundAt: null, introspection: 'unknown' },
      trpcDetected: false,
    }),
  )
  if (apiProbe.openapi.foundAt) {
    findings.push({
      id: 'paths-openapi-spec-public',
      severity: 'warn',
      category: 'paths',
      title: `OpenAPI / Swagger spec is publicly accessible (${apiProbe.openapi.endpoints.length} endpoint${
        apiProbe.openapi.endpoints.length === 1 ? '' : 's'
      })`,
      description: `Found a public OpenAPI/Swagger specification at ${apiProbe.openapi.foundAt}. This is a complete API map — every endpoint, every method, every parameter, every response shape. Attackers love public specs because they remove guesswork: they get a checklist of attack surface, sorted by likelihood of bugs. Public specs are FINE for documentation portals; problematic for internal admin/control APIs.`,
      evidence: `${apiProbe.openapi.foundAt}\n${apiProbe.openapi.endpoints
        .slice(0, 6)
        .map((e) => `  ${e.methods.join(',')} ${e.path}`)
        .join('\n')}${apiProbe.openapi.endpoints.length > 6 ? `\n  + ${apiProbe.openapi.endpoints.length - 6} more` : ''}`,
      fixPrompt: `Decide: is this spec meant to be public? If YES (public dev docs), fine — but ensure none of the listed endpoints expose admin / internal / debug actions; segregate those into a separate spec served only to authenticated developer accounts. If NO, gate the spec route behind auth (Express: \`app.use('/openapi.json', requireAuth)\`; Next.js: middleware on the matcher; FastAPI: \`app.include_router(api_router, dependencies=[Depends(get_current_user)])\`). Don't rely on obscurity — search engines have already indexed it.`,
    })
  }
  if (apiProbe.graphql.foundAt) {
    if (apiProbe.graphql.introspection === 'allowed') {
      findings.push({
        id: 'paths-graphql-introspection',
        severity: 'warn',
        category: 'paths',
        title: 'GraphQL introspection is enabled in production',
        description: `${apiProbe.graphql.foundAt} responded to a \`{__schema{queryType{name}}}\` query — introspection is on. That gives any anonymous visitor your full type system, every field, every mutation. Same problem as a public OpenAPI spec, but worse: most teams forget GraphQL introspection is even ON because it's a default in many frameworks (Apollo Server, Hot Chocolate, etc.).`,
        evidence: `${apiProbe.graphql.foundAt} accepts {__schema{queryType{name}}} → 200`,
        fixPrompt: `Disable introspection in production. Apollo Server: \`new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })\`. graphql-yoga: \`disableIntrospection()\` plugin. Hasura/Postgraphile: their docs cover the env-var. Verify after deploy: GET ${apiProbe.graphql.foundAt} should still work for known queries but \`{__schema{...}}\` should return an error like "GraphQL introspection is not allowed". Keep introspection ON in dev/staging — disable only on prod.`,
      })
    } else {
      findings.push({
        id: 'paths-graphql-detected',
        severity: 'info',
        category: 'paths',
        title: 'GraphQL endpoint detected',
        description: `${apiProbe.graphql.foundAt} responds like a GraphQL endpoint. Introspection is ${apiProbe.graphql.introspection === 'denied' ? 'correctly disabled' : 'unknown — we could not confirm either way from this scan'}. GraphQL adds an attack surface (depth/recursion attacks, field-level authorization gaps, batch-query DoS) that's worth auditing on its own.`,
        evidence: `${apiProbe.graphql.foundAt} (introspection=${apiProbe.graphql.introspection})`,
        fixPrompt: `Audit your GraphQL setup: (1) introspection OFF in prod (verified above if 'denied'), (2) max query depth + complexity limits (graphql-depth-limit, graphql-cost-analysis), (3) field-level authorization on every resolver — don't rely on top-level "is the user authenticated", check ownership per field, (4) disable batched queries if not needed (Apollo Server option), (5) rate-limit at the request level to prevent DoS.`,
      })
    }
  }
  if (apiProbe.trpcDetected) {
    findings.push({
      id: 'meta-trpc-detected',
      severity: 'info',
      category: 'meta',
      title: 'tRPC client detected in bundle',
      description: `Your bundle imports tRPC client code. tRPC procedures usually live at \`/api/trpc/<router>.<procedure>\`; they're typed end-to-end (great for DX) but each procedure needs its own auth/authorization gate — there's no shared route-level middleware like REST often has. We didn't probe individual procedures (no spec to enumerate them), so review your routers manually.`,
      evidence: 'bundle imports @trpc/client or createTRPCNext',
      fixPrompt: `For every tRPC procedure: confirm it uses \`protectedProcedure\` or your custom auth middleware before \`.input(...)\`. The default \`publicProcedure\` is callable by anyone — easy to miss. Common bug: a public procedure accidentally returns data that should be auth-gated (user list, draft posts, etc.). Run \`grep -rn 'publicProcedure' src/server/\` and audit each one.`,
    })
  }

  // === PRIVILEGE LEAK SIGNALS (S2+5) ===
  // Discover admin route paths the developer's own code references, then
  // probe each unauth. A 200 from an unauthenticated GET on a route the
  // bundle calls "admin" is a strong privilege-leak signal.
  const adminProbeResults = await discoverAndProbeAdminRoutes(
    bundleTextAll,
    html,
    url.origin,
  ).catch(() => [] as { path: string; status: number; contentLength: number | null; isSpaShell: boolean }[])
  const publicAdminRoutes = adminProbeResults.filter(
    (r) =>
      r.status === 200 &&
      // Filter out tiny responses that are clearly redirects-via-HTML or
      // generic 200 OK error pages: typically real admin pages return >1KB
      // of HTML/JSON. Anything under 200 bytes is almost always a stub.
      (r.contentLength === null || r.contentLength >= 200) &&
      // Filter out SPA shells. Vite + React, Next.js static export, Vue Router
      // history-mode fallback, and similar setups serve the SAME index.html
      // for every path — admin auth is enforced client-side after the shell
      // mounts. Reporting the shell as "admin returned 200 unauth" is a false
      // positive: no privileged data crossed the wire, just the bootstrap HTML.
      !r.isSpaShell,
  )
  if (publicAdminRoutes.length > 0) {
    findings.push({
      id: 'paths-admin-route-public',
      severity: 'critical',
      category: 'auth',
      title: `${publicAdminRoutes.length} admin route${
        publicAdminRoutes.length === 1 ? '' : 's'
      } from your bundle returned 200 without auth`,
      description: `We discovered admin/internal routes referenced in your shipped JS, then sent unauthenticated GET requests to them. Some returned HTTP 200 — meaning anyone on the internet, with no login, can reach pages your code treats as privileged. This is broken access control: the canonical OWASP A1 (#1 most exploited class in 2021).`,
      evidence: publicAdminRoutes
        .map((r) => `${r.path} → HTTP ${r.status}${r.contentLength !== null ? ` (${r.contentLength}B)` : ''}`)
        .join('\n'),
      fixPrompt: `For each route above: confirm it's actually meant to be admin-only. If yes, add a server-side auth gate at the route boundary (Next.js middleware on /admin/* / pages with getServerSession; Supabase RLS on the API the page calls; custom JWT verification). The check must run BEFORE the route handler — client-side auth (e.g. "redirect if no localStorage token") is bypassable in 5 seconds with curl. Re-run this scan after fixing — the route should now return 401/403/redirect-to-login.`,
    })
  } else if (adminProbeResults.length > 0) {
    // Discovered candidates but they're all gated correctly — emit OK marker.
    findings.push({
      id: 'paths-admin-route-clean',
      severity: 'ok',
      category: 'auth',
      title: `${adminProbeResults.length} admin route${
        adminProbeResults.length === 1 ? '' : 's'
      } discovered in bundle, all gated`,
      description: `We extracted ${adminProbeResults.length} admin/internal route path${
        adminProbeResults.length === 1 ? '' : 's'
      } from your shipped JS, then probed each without auth. None returned 200 — your access control is enforced at the route level, not just in the UI.`,
      evidence: adminProbeResults
        .map((r) => `${r.path} → HTTP ${r.status}`)
        .slice(0, 8)
        .join('\n'),
      fixPrompt: '',
    })
  }

  // === Hardcoded localhost references ===
  if (localhostHits.length > 0) {
    findings.push({
      id: 'meta-localhost-leak',
      severity: 'info',
      category: 'meta',
      title: `Hardcoded localhost URLs in production bundle`,
      description: `Found ${localhostHits.length} reference${localhostHits.length === 1 ? '' : 's'} to "http://localhost:..." in your production JS. Usually harmless but signals dev configuration leaked into the build — and sometimes carries dev-only secrets, debug endpoints, or ports.`,
      evidence: Array.from(new Set(localhostHits)).slice(0, 4).join('\n'),
      fixPrompt: `Search-and-replace your codebase for "localhost". Replace with environment-aware values: process.env.NEXT_PUBLIC_API_URL or import.meta.env.VITE_API_URL, with a production fallback. Tree-shake out test/dev branches via NODE_ENV checks. Then rebuild and confirm "localhost" is gone from the dist/ output.`,
    })
  }

  // === AUTH-FOCUSED DETECTORS (added 2026-05-06 per Royi+Oded) ===
  // Three classes: User Enumeration, Auth Weaknesses, Auth Information Disclosure.
  // Stage 1 = passive only — derive from already-fetched HTML + bundles + headers.
  // Catalog: see "Auth-focused detection classes" section in Vguard - Attack Catalog.md.

  // --- auth-enum: surface signup/login/reset endpoints as a unified enum surface ---
  {
    const authSurfaceHits: string[] = []
    const enumPatterns: { pattern: RegExp; label: string }[] = [
      { pattern: /\b(?:href|action|src)\s*=\s*["']([^"']*\/(?:login|sign[-_]?in|signin)[^"']*)["']/gi, label: 'login' },
      { pattern: /\b(?:href|action|src)\s*=\s*["']([^"']*\/(?:signup|sign[-_]?up|register)[^"']*)["']/gi, label: 'signup' },
      { pattern: /\b(?:href|action|src)\s*=\s*["']([^"']*\/(?:forgot[-_]?password|reset[-_]?password|password[-_]?reset)[^"']*)["']/gi, label: 'password-reset' },
      { pattern: /\b(?:href|action|src)\s*=\s*["']([^"']*\/api\/(?:auth|users)\/(?:exists|check[-_]?email|check[-_]?username)[^"']*)["']/gi, label: 'existence-api' },
    ]
    for (const { pattern, label } of enumPatterns) {
      for (const m of html.matchAll(pattern)) {
        authSurfaceHits.push(`${label}: ${m[1]}`)
        if (authSurfaceHits.length >= 8) break
      }
      if (authSurfaceHits.length >= 8) break
    }
    if (authSurfaceHits.length > 0) {
      const hasReset = authSurfaceHits.some((h) => h.startsWith('password-reset'))
      const hasExistsApi = authSurfaceHits.some((h) => h.startsWith('existence-api'))
      findings.push({
        id: 'auth-enum-surface',
        severity: hasExistsApi ? 'warn' : 'info',
        category: 'auth-enum',
        title: hasExistsApi
          ? 'User-existence API endpoint exposed'
          : `Auth surface present (${authSurfaceHits.length} endpoint${authSurfaceHits.length === 1 ? '' : 's'} discovered)`,
        description: hasExistsApi
          ? 'A dedicated "does this email/username exist?" endpoint was found. These endpoints are the most common source of user enumeration — anyone can iterate a wordlist of emails and learn which are registered. Combined with no rate limiting this leaks your full user base.'
          : `Login, signup, and/or password-reset flows are reachable. Stage 1 only catalogs them — confirming whether they reveal "user not found" vs "wrong password" with different responses (or different timing) requires Stage 2/3 active probing.${
              hasReset
                ? ' Note the password-reset flow: returning 200 for known emails and 404 for unknown is the most common enum leak.'
                : ''
            }`,
        evidence: authSurfaceHits.slice(0, 6).join('\n'),
        fixPrompt: `For every auth endpoint (login / signup / password-reset / forgot-password): return the SAME response body and SAME HTTP status whether the email exists or not, AND respond in roughly constant time (use a constant-time compare or add a small randomized delay before responding). Concretely for password-reset: always return 200 with "If that email is registered, we sent a reset link" — never 404. For login: same generic "Invalid credentials" for both unknown-email and wrong-password cases. Add Cloudflare Turnstile / hCaptcha + per-IP rate limit (5 attempts per 15 min) on every auth endpoint. If you have a dedicated "/api/check-email" or "/api/users/exists" endpoint — DELETE it; it's a built-in user enumeration oracle.`,
      })
    }
  }

  // --- auth-weak: JWT inspection (alg:none, weak claims, missing exp) ---
  {
    const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,200}/g
    const seenJwts = new Set<string>()
    const weakJwts: { token: string; problem: string }[] = []
    const sources = [html, bundleTextAll]
    for (const src of sources) {
      for (const m of src.matchAll(jwtRe)) {
        const token = m[0]
        if (seenJwts.has(token)) continue
        seenJwts.add(token)
        if (seenJwts.size > 20) break
        try {
          const [hRaw, pRaw] = token.split('.')
          const header = JSON.parse(
            Buffer.from(hRaw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'),
          )
          const payload = JSON.parse(
            Buffer.from(pRaw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'),
          )
          const problems: string[] = []
          if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') {
            problems.push('alg=none (signature not verified)')
          }
          if (payload && typeof payload === 'object') {
            const role = String(payload.role ?? payload.roles ?? '').toLowerCase()
            if (role.includes('admin') || role.includes('super') || role === 'service_role') {
              problems.push(`elevated role claim: ${role}`)
            }
            if (Array.isArray(payload.permissions) && payload.permissions.includes('*')) {
              problems.push('permissions: ["*"]')
            }
            if (typeof payload.exp !== 'number') {
              problems.push('no exp (token never expires)')
            }
          }
          if (problems.length > 0) {
            weakJwts.push({
              token: token.slice(0, 12) + '...' + token.slice(-4),
              problem: problems.join(', '),
            })
          }
        } catch {
          // not a real JWT — skip
        }
      }
    }
    if (weakJwts.length > 0) {
      const isCritical = weakJwts.some(
        (j) => j.problem.includes('alg=none') || j.problem.includes('admin') || j.problem.includes('service_role'),
      )
      findings.push({
        id: 'auth-weak-jwt',
        severity: isCritical ? 'critical' : 'warn',
        category: 'auth-weak',
        title: `${weakJwts.length} JWT${weakJwts.length === 1 ? '' : 's'} with weak header/claims exposed in bundle`,
        description:
          'JWT(s) found in your HTML or JS bundles have problematic headers or claims. Tokens with alg=none accept ANY signature (trivial forgery). Tokens with admin/service_role claims grant elevated access if reused. Tokens without exp never expire — long-lived persistent compromise if leaked.',
        evidence: weakJwts.slice(0, 4).map((j) => `${j.token} — ${j.problem}`).join('\n'),
        fixPrompt: `For each weak JWT: (1) If it is a service-role / admin-level token, IT MUST NEVER BE IN CLIENT CODE — move the call server-side immediately and rotate the key. (2) Set jwt.sign options to enforce alg='HS256' or 'RS256' (never 'none') and exp ≤ 1h for user sessions. (3) On the verifier, explicitly pass the allowed algorithms array — never rely on the header's alg field alone (alg:none confusion attack). For Supabase: anon keys are SAFE in client code by design (RLS enforces); service_role keys are NOT — server-only. For Auth0/Clerk/NextAuth: enforce a short access-token TTL with refresh-token rotation.`,
      })
    }
  }

  // --- auth-disclosure: session IDs in URLs, Bearer headers in HTML, stack traces ---
  {
    const disclosureHits: string[] = []
    // Session IDs in URLs (href/action/src/redirects in HTML)
    const urlParamRe = /[?&](sid|session[_-]?id|jsessionid|phpsessid|token|jwt|access[_-]?token|auth[_-]?token|api[_-]?key)=([^"'&\s<>]{8,})/gi
    for (const m of html.matchAll(urlParamRe)) {
      disclosureHits.push(`URL param: ${m[1]}=${m[2].slice(0, 8)}...`)
      if (disclosureHits.length >= 4) break
    }
    // Bearer or Authorization values inline in HTML
    const inlineAuthRe = /(authorization|bearer)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_.-]{20,}|bearer\s+[A-Za-z0-9_.-]{20,})/gi
    for (const m of html.matchAll(inlineAuthRe)) {
      disclosureHits.push(`inline ${m[1]}: ${m[2].slice(0, 12)}...`)
      if (disclosureHits.length >= 8) break
    }
    // Stack traces with auth keywords (server error pages)
    const stackTraceRe = /(at\s+\w+(?:\.[\w$]+)*\s*\([^)]+:\d+:\d+\)|Traceback\s+\(most recent call last\)|Exception\s+in\s+thread)/i
    if (stackTraceRe.test(html)) {
      const authKeyword = /(jwt|passport|nextauth|supabase\.auth|firebase\.auth|auth0|clerk|cognito)/i
      if (authKeyword.test(html)) {
        const idx = html.search(stackTraceRe)
        disclosureHits.push(
          `stack-trace + auth keyword in body @ offset ${idx}: ${html.slice(idx, idx + 120).replace(/\s+/g, ' ')}`,
        )
      }
    }

    if (disclosureHits.length > 0) {
      const hasInlineToken = disclosureHits.some(
        (h) => h.startsWith('inline') || h.startsWith('URL param: token=') || h.startsWith('URL param: jwt='),
      )
      findings.push({
        id: 'auth-disclosure-leak',
        severity: hasInlineToken ? 'critical' : 'warn',
        category: 'auth-disclosure',
        title: hasInlineToken
          ? 'Authentication token disclosed in HTML / URL'
          : `Authentication-related disclosure (${disclosureHits.length} signal${disclosureHits.length === 1 ? '' : 's'})`,
        description: hasInlineToken
          ? 'A real-looking authentication token (JWT or Bearer credential) appears directly in the page HTML or in a URL query parameter. Anyone who reads the page source — or any service that logs URLs (proxies, analytics, browser history, Referer header) — captures it.'
          : 'Found auth-related disclosure signals: session/token-named URL parameters, or stack traces that mention auth libraries. These leak implementation details and sometimes credentials to anyone who can fetch the page.',
        evidence: disclosureHits.slice(0, 5).join('\n'),
        fixPrompt: `Move every authentication token OUT of URLs and HTML attributes. Tokens belong in (a) HttpOnly+Secure+SameSite=Strict cookies set by the server, or (b) Authorization HTTP headers added by your fetch client at request time, or (c) sessionStorage with explicit XSS hardening. Never as ?token=... query params (logged everywhere) and never inlined in HTML (visible to view-source). For stack traces: in production, return a generic 500 page — log the trace server-side only. In Next.js: set output: 'standalone' + custom error.tsx; in Express: app.use((err, req, res, next) => res.status(500).json({error: 'Internal'})) AFTER your error logger. Disable any /debug, /api/debug, /__inspect routes in production.`,
      })
    }
  }

  // === CLEAN MARKERS ===
  if (url.protocol === 'https:') {
    findings.push({
      id: 'tls-https',
      severity: 'ok',
      category: 'tls',
      title: 'HTTPS with valid certificate',
      description: 'TLS handshake succeeded; the connection is encrypted.',
      evidence: `Served over ${url.protocol}//${url.host}`,
      fixPrompt: '',
    })
  } else {
    findings.unshift({
      id: 'tls-http',
      severity: 'critical',
      category: 'tls',
      title: 'Site is served over plain HTTP',
      description:
        'No TLS at all. Every request and response is in cleartext on the wire — including session cookies and any data your users submit.',
      evidence: `Served over http://${url.host}`,
      fixPrompt: `Move the deployment behind HTTPS. On Vercel/Netlify/Cloudflare Pages, HTTPS is automatic — switch the domain to one of those, or put Cloudflare in front of the existing host. Reject HTTP at the proxy with a 308 redirect to HTTPS, and add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.`,
    })
  }

  // If we found NO secrets and we successfully fetched bundles, flag clean
  const hasSecretFinding = findings.some((f) => f.category === 'secrets')
  if (!hasSecretFinding && bundlesFetched > 0) {
    findings.push({
      id: 'secrets-clean',
      severity: 'ok',
      category: 'secrets',
      title: 'No hardcoded API keys detected in JS bundles',
      description: `Scanned ${bundlesFetched} bundle${
        bundlesFetched === 1 ? '' : 's'
      } (${(bundlesSizeBytes / 1024).toFixed(0)} KB). No matches against ${SECRET_PATTERNS.length} secret patterns.`,
      evidence: `${bundlesFetched} bundle${bundlesFetched === 1 ? '' : 's'} scanned, 0 matches`,
      fixPrompt: '',
    })
  }

  const totals = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    warn: findings.filter((f) => f.severity === 'warn').length,
    info: findings.filter((f) => f.severity === 'info').length,
    ok: findings.filter((f) => f.severity === 'ok').length,
  }
  // Legacy static score kept as a debug fallback only — replaced below by
  // the dynamic engine. Don't read this for the live response.
  const _legacyVibeScore = scoreFromTotals(totals)
  void _legacyVibeScore

  const sevOrder: Record<Severity, number> = { critical: 0, warn: 1, info: 2, ok: 3 }
  findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity])

  const enriched = enrichFindings(findings, { finalUrl, detectedFramework })
  // S1+5 — content-aware risk: classify the route from the final URL path
  // and let the scorer bump risk for sensitive contexts (admin/auth/checkout).
  const routeContext = classifyRouteContext(new URL(finalUrl).pathname)
  // S1+2 — deep fingerprinting; `detectFramework` already gave us the name,
  // but we want the version too for downstream CVE matching + UI display.
  const fwAndVersion = detectFrameworkAndVersion(html, bundleTextAll)
  const detectedFrameworkVersion = fwAndVersion?.version ?? null
  const detectedReactVersion = detectReactVersion(bundleTextAll)
  // Risk scoring — first pass with the legacy CVSS-style scorer for the
  // back-compat `riskScore`/`riskBand` fields that downstream consumers rely
  // on, then the new dynamic engine for the *live* vibeScore + risk class +
  // confidence + uiGroup. The engine's output overwrites `riskScore`/`riskBand`
  // so the per-finding numbers stay consistent with what the engine penalised.
  const cspHasUnsafe = /content-security-policy/i.test(
    Array.from(mainResp.headers.keys()).join(','),
  )
    ? /'unsafe-(?:inline|eval)'/i.test(mainResp.headers.get('content-security-policy') || '')
    : false
  const engineCtx = defaultContext({
    pathname: new URL(finalUrl).pathname,
    isHttps: finalUrl.startsWith('https://'),
    cspHasUnsafe,
    stage: 1,
  })
  const legacyScored = applyRisk(enriched, routeContext)
  const engineOut = applyEngine(legacyScored, engineCtx)
  const scored = engineOut.findings
  const dynamicVibeScore = engineOut.vibeScore
  // Aggregate "risk number" still computed via legacy scorer for back-compat
  // numeric field. The user-facing band comes from the engine (which clamps
  // to `low` when no verified impact exists). We don't clamp the number — it
  // stays honest for any consumer that wants the raw value.
  const aggregateRisk = computeAggregateRisk(scored)

  const subdomains = await subdomainsP
  const attackSurface = buildAttackSurface({
    primaryDomain: url.hostname,
    baseDomain: getBaseDomain(url.hostname),
    finalUrl,
    html,
    bundleTextAll,
    responseHeaders: mainResp.headers,
    detected: {
      supabaseProjectIds: Array.from(supabaseProjectIds),
      s3BucketHosts: Array.from(s3BucketHosts),
      firebaseIds: Array.from(firebaseIdsCollected),
      aiEndpoints,
    },
    subdomains,
    waf:
      wafState.vendor && wafState.vendor !== 'unknown'
        ? {
            vendor: wafState.vendor,
            blocked: wafState.blocked,
            stealthRetryAttempted: wafState.stealthRetryAttempted,
            stealthRetrySucceeded: wafState.stealthRetrySucceeded,
          }
        : null,
  })

  // Push a synthetic `info` finding when a WAF is in front of the origin.
  // Keeping it as `info` (not `warn`) — having a WAF is a defense, not a
  // problem. The value is informational: the user knows what's there, and
  // sees whether our scan had to bypass an initial block to even reach them.
  if (wafState.vendor && wafState.vendor !== 'unknown') {
    const vendorLabel = VENDOR_LABELS[wafState.vendor]
    const evidenceLines: string[] = [`Vendor detected: ${vendorLabel}`]
    if (wafState.blocked && wafState.stealthRetrySucceeded) {
      evidenceLines.push(
        'Initial automated request was blocked, browser-like retry succeeded.',
      )
    } else if (wafState.blocked && wafState.stealthRetryAttempted && !wafState.stealthRetrySucceeded) {
      evidenceLines.push(
        'Both the initial and the stealth retry were blocked — only Stage 2 (browser-assisted) can scan past this layer.',
      )
    } else if (!wafState.blocked) {
      evidenceLines.push('Detected from response headers; the scan was not blocked.')
    }
    scored.push({
      id: 'meta-waf-detected',
      severity: 'info',
      category: 'meta',
      title: `${vendorLabel} edge protection in front of your origin`,
      description: `Your site sits behind ${vendorLabel}, which provides bot/DDoS mitigation before requests reach the origin. ${
        wafState.blocked
          ? `Vguard's initial automated request was blocked; we ${wafState.stealthRetrySucceeded ? 'completed the scan via a stealth retry that mimicked a real browser' : 'were not able to bypass the block — Stage 2 (browser-assisted) is the recommended next step'}.`
          : 'Real users are unaffected.'
      } Having edge protection is a defense, not a problem — this finding is informational.`,
      evidence: evidenceLines.join('\n'),
      fixPrompt: '',
      riskScore: 0,
      riskBand: 'low',
    })
    // Re-roll totals to reflect the new info finding so the score panel matches.
    totals.info += 1
  }

  return {
    ok: true,
    url: rawUrl,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    vibeScore: dynamicVibeScore,
    aggregateRisk,
    aggregateRiskBand: engineOut.aggregateBand,
    totals,
    findings: scored,
    attackSurface,
    stage: 1 as const,
    meta: {
      finalUrl,
      httpStatus: mainResp.status,
      contentType: mainResp.headers.get('content-type'),
      detectedFramework,
      detectedFrameworkVersion,
      detectedReactVersion,
      bundlesFetched,
      bundlesSizeBytes,
      routeContext,
    },
    detected: {
      supabaseProjectIds: Array.from(supabaseProjectIds),
      supabaseAnonKey: detectedAnonKey,
      s3BucketHosts: Array.from(s3BucketHosts),
      firebaseIds: Array.from(firebaseIdsCollected),
      aiEndpoints: aiEndpoints.map((p) => {
        try {
          return new URL(p, finalUrl).toString()
        } catch {
          return p
        }
      }),
    },
  }
}
