/**
 * Stage 2 server-side browser-assisted proxy endpoint.
 * Forwards scan requests to a Playwright worker on Railway / Fly / wherever
 * (configured via STAGE2_WORKER_URL + STAGE2_WORKER_TOKEN env vars).
 *
 * Worker returns raw browser data (cookies, localStorage, networkRequests,
 * windowGlobals). This endpoint analyzes that data into Findings, runs them
 * through the same fix-prompt composer Stage 1 uses, and returns:
 *   { ok: true, findings, durationMs, stage: 2 }
 *
 * If env vars are not set, returns 503 with a hint pointing to the bookmarklet
 * flow (which works without any worker).
 */
import type { VercelRequest, VercelResponse } from '@vercel/node'
import type { Finding } from '../src/lib/scanner-types.js'
import { enrichFindings } from './_lib/fix-prompt-composer.js'
import { applyRisk, classifyRouteContext } from './_lib/risk-scorer.js'
import { logAuditEvent, fireAndForget } from './_lib/audit-log.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 60,
}

interface BrowserScanBody {
  url?: string
  /**
   * Optional framework hint from Stage 1 — used by the fix-prompt composer
   * to produce stack-specific instructions (e.g. vercel.json vs next.config.ts).
   */
  framework?: string
}

interface WorkerCookie {
  name: string
  httpOnly: boolean
  secure: boolean
  sameSite: string | undefined
  domain: string
  // Stage 2.4 — extended cookie attributes; older workers don't return these.
  path?: string
  expiresInDays?: number
  partitioned?: boolean
  isJwt?: boolean
}

/**
 * JWT decoding result from the worker. Values never leave the worker — only
 * the analysis: alg/typ/exp window/claim names. Lets the proxy generate
 * findings about token shape (alg=none, missing exp, sensitive claims) without
 * ever seeing the credential itself.
 */
interface WorkerJwtAnalysis {
  source: 'cookie' | 'localStorage' | 'sessionStorage'
  keyName: string
  alg: string | null
  typ: string | null
  hasExp: boolean
  expSecondsFromNow: number | null
  hasIss: boolean
  hasAud: boolean
  claimNames: string[]
}

interface WorkerNetworkRequest {
  url: string
  method: string
  status: number
  resourceType: string
  // Stage 2.3 — extended capture; older workers don't return these.
  contentType?: string
  sizeBytes?: number
  durationMs?: number
  hasAuthHeader?: boolean
  hasOriginHeader?: boolean
}

/**
 * Stage 2.3 — Live API map summary returned alongside findings. Lets the UI
 * render a network table, and lets MCP/agents reason about API surface
 * without re-doing detection. Bucketed into same-origin (first-party) vs
 * third-party so audits can talk about supply chain and connect-src drift.
 */
interface ApiCallEntry {
  url: string
  method: string
  status: number
  contentType: string | null
  sizeBytes: number | null
  durationMs: number | null
  hasAuth: boolean
  origin: 'first-party' | 'third-party'
}

interface LiveApiMap {
  totalRequests: number
  apiCalls: ApiCallEntry[]
  apiHosts: { host: string; count: number; origin: 'first-party' | 'third-party' }[]
  /** First-party API endpoints that returned 200 with NO Authorization or Cookie. */
  unauthApiCalls: ApiCallEntry[]
}

interface WorkerSensitiveDataHit {
  type:
    | 'email'
    | 'phone-il'
    | 'phone-intl'
    | 'israeli-id'
    | 'credit-card'
    | 'jwt-in-body'
    | 'aws-key'
    | 'github-pat'
    | 'openai-key'
    | 'anthropic-key'
    | 'stripe-key'
    | 'internal-url'
    | 'stack-trace-abs-path'
  redactedSample: string
  sourceUrl: string
}

interface WorkerScanResult {
  ok: true
  url: string
  finalUrl: string
  networkRequests: WorkerNetworkRequest[]
  consoleErrors: string[]
  windowGlobals: Record<string, boolean>
  cookies: WorkerCookie[]
  localStorageKeys: string[]
  sessionStorageKeys: string[]
  /** Stage 2.4 — JWTs decoded by the worker (values never sent back). Optional for compat. */
  jwtAnalysis?: WorkerJwtAnalysis[]
  /** S2+4 — PII / secrets / internal URLs / stack traces in response bodies. */
  sensitiveDataFindings?: WorkerSensitiveDataHit[]
  durationMs: number
}

/**
 * Decide whether a request looks like an API call: by resourceType
 * (xhr/fetch) OR by content-type (application/*, text/event-stream) OR by
 * path pattern (/api/, /v1/, /v2/, /graphql, /trpc/).
 */
function isApiCall(r: WorkerNetworkRequest): boolean {
  if (r.resourceType === 'xhr' || r.resourceType === 'fetch') return true
  const ct = (r.contentType || '').toLowerCase()
  if (ct.startsWith('application/json')) return true
  if (ct.startsWith('application/graphql')) return true
  if (ct.startsWith('text/event-stream')) return true
  if (/\/(api|v1|v2|graphql|trpc)\//i.test(r.url)) return true
  return false
}

function buildLiveApiMap(data: WorkerScanResult): LiveApiMap {
  const finalHost = (() => {
    try {
      return new URL(data.finalUrl).hostname
    } catch {
      return ''
    }
  })()

  const apiCalls: ApiCallEntry[] = []
  const hostCounts = new Map<string, { count: number; origin: 'first-party' | 'third-party' }>()

  // Helper inlined here so it stays close to the unauth-filter that consumes it.
  // Path patterns intended to be unauth-by-design across the ecosystem; flagging
  // them as a privilege-leak produces noise the user can't act on.
  const WELL_KNOWN_PUBLIC_PATHS: RegExp[] = [
    /^\/(health|healthz|status|version|ping|ready|live)\/?$/i,
    /^\/api\/(health|healthz|status|version|ping|ready|live)\/?$/i,
    /^\/(manifest\.json|robots\.txt|sitemap\.xml|favicon\.ico)$/i,
    /^\/\.well-known\//i,
    /^\/(api\/)?(public|open)\//i,
  ]
  // eslint-disable-next-line no-inner-declarations
  function isWellKnownPublicEndpoint(rawUrl: string): boolean {
    let path = rawUrl
    try {
      path = new URL(rawUrl).pathname
    } catch {
      // already a path
    }
    return WELL_KNOWN_PUBLIC_PATHS.some((re: RegExp) => re.test(path))
  }

  for (const r of data.networkRequests) {
    if (!isApiCall(r)) continue
    let host = ''
    try {
      host = new URL(r.url).hostname
    } catch {
      // skip un-parseable
      continue
    }
    const origin: 'first-party' | 'third-party' =
      host && finalHost && (host === finalHost || host.endsWith('.' + finalHost))
        ? 'first-party'
        : 'third-party'
    const entry: ApiCallEntry = {
      url: r.url,
      method: r.method,
      status: r.status,
      contentType: r.contentType ?? null,
      sizeBytes: typeof r.sizeBytes === 'number' ? r.sizeBytes : null,
      durationMs: typeof r.durationMs === 'number' ? r.durationMs : null,
      hasAuth: r.hasAuthHeader === true,
      origin,
    }
    apiCalls.push(entry)
    const slot = hostCounts.get(host) ?? { count: 0, origin }
    slot.count += 1
    hostCounts.set(host, slot)
  }

  // Cap apiCalls in the response so a chatty SPA doesn't bloat the JSON.
  const cappedApiCalls = apiCalls.slice(0, 100)
  const apiHosts = Array.from(hostCounts.entries())
    .map(([host, v]) => ({ host, count: v.count, origin: v.origin }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 30)

  // Privilege-leak signal: first-party API call returned 200 WITHOUT Authorization
  // OR Cookie. This is what Stage 2.5 (privilege leak) will lean on, but the
  // raw signal already shows here so the UI can flag it now.
  const unauthApiCalls = apiCalls.filter(
    (e) =>
      e.origin === 'first-party' &&
      e.status >= 200 &&
      e.status < 300 &&
      !e.hasAuth &&
      // Skip GET on home / static-ish paths — only POST/PUT/PATCH/DELETE or /api/* are interesting unauth.
      (e.method !== 'GET' || /\/(api|v1|v2|graphql|trpc)\//i.test(e.url)) &&
      // Skip endpoints whose path matches conventional public-by-design names.
      // Health, status, version, manifests, and explicitly-public listings are
      // intended to be unauth — flagging them produces false positives the
      // user can't act on without breaking the contract.
      !isWellKnownPublicEndpoint(e.url),
  )

  return {
    totalRequests: data.networkRequests.length,
    apiCalls: cappedApiCalls,
    apiHosts,
    unauthApiCalls: unauthApiCalls.slice(0, 20),
  }
}

function analyzeBrowserScan(data: WorkerScanResult): Finding[] {
  const findings: Finding[] = []

  // 1. Cookies — HttpOnly missing on sensitive-named cookies
  const sensitiveCookies = data.cookies.filter((c) =>
    /sess|auth|token|jwt|sid|csrf|access/i.test(c.name),
  )
  const httpOnlyMissing = sensitiveCookies.filter((c) => !c.httpOnly)
  if (httpOnlyMissing.length > 0) {
    findings.push({
      id: 'stage2-cookie-not-httponly',
      severity: 'warn',
      category: 'cookies',
      title: `${httpOnlyMissing.length} sensitive cookie${httpOnlyMissing.length === 1 ? '' : 's'} missing HttpOnly`,
      description: `Cookies with sensitive-looking names (auth/session/token/etc.) were set WITHOUT the HttpOnly flag. That means any XSS payload on this origin can read them via document.cookie and exfiltrate session tokens. HttpOnly tells the browser "JavaScript may not read this cookie", and is the single most important defense against credential theft via XSS.`,
      evidence: httpOnlyMissing
        .map((c) => `${c.name} (domain=${c.domain}, secure=${c.secure}, sameSite=${c.sameSite ?? 'None'})`)
        .join('\n'),
      fixPrompt: `Set HttpOnly=true on every session/auth cookie. The mechanism depends on your stack — Express: res.cookie(name, value, { httpOnly: true, secure: true, sameSite: 'lax' }). NextAuth: configure cookies in [...nextauth].ts options. Supabase Auth: handled automatically (if you see this finding with Supabase, check whether you have a custom cookie set elsewhere). After fixing, rerun this scan to confirm the cookie no longer appears.`,
    })
  }

  // 2a. Cookies — SameSite=None without Secure (browser will reject anyway,
  // but flagging surfaces the misconfig).
  const sameSiteNoneInsecure = data.cookies.filter((c) => {
    const ss = (c.sameSite ?? '').toLowerCase()
    return ss === 'none' && !c.secure
  })
  if (sameSiteNoneInsecure.length > 0) {
    findings.push({
      id: 'stage2-cookie-samesite-none-insecure',
      severity: 'critical',
      category: 'cookies',
      title: `${sameSiteNoneInsecure.length} cookie${sameSiteNoneInsecure.length === 1 ? '' : 's'} use SameSite=None WITHOUT Secure`,
      description: `Browsers reject cookies with SameSite=None unless they also have Secure=true. The cookie will be silently dropped — auth flows that depend on it (cross-site OAuth callbacks, embedded iframes) WILL break in production. This is also a clear configuration bug.`,
      evidence: sameSiteNoneInsecure.map((c) => `${c.name} domain=${c.domain}`).join('\n'),
      fixPrompt: `Add Secure=true to every cookie that uses SameSite=None. Most frameworks set this with one option flag (e.g. \`{ sameSite: 'none', secure: true }\`). If you don't actually need cross-site (e.g. it's a same-origin SPA), switch to SameSite=Lax instead — that's the modern default and removes the need for Secure to even be discussed.`,
    })
  }

  // 2b. Cookie name prefix violations (__Secure- / __Host-) — RFC 6265bis.
  const prefixViolations = data.cookies.filter((c) => {
    if (c.name.startsWith('__Secure-') && !c.secure) return true
    if (c.name.startsWith('__Host-')) {
      // __Host- requires: Secure=true, Path=/, no Domain attribute
      if (!c.secure) return true
      if (c.path && c.path !== '/') return true
      // Domain attribute presence is signaled by leading-dot OR mismatch with origin host;
      // worker reports the resolved domain so a leading '.' here means Domain= was set.
      if (c.domain && c.domain.startsWith('.')) return true
    }
    return false
  })
  if (prefixViolations.length > 0) {
    findings.push({
      id: 'stage2-cookie-prefix-violations',
      severity: 'warn',
      category: 'cookies',
      title: `${prefixViolations.length} cookie${prefixViolations.length === 1 ? '' : 's'} use a security prefix without honoring its rules`,
      description: `RFC 6265bis defines two cookie-name prefixes that promise extra hardening: __Secure- guarantees Secure=true; __Host- additionally requires Path=/ and no Domain attribute. When the prefix is set but the rules aren't honored, the cookie isn't actually as locked-down as the name suggests — and worse, browsers may quietly reject it on newer engines.`,
      evidence: prefixViolations
        .map((c) => `${c.name} (secure=${c.secure}, path=${c.path ?? '?'}, domain=${c.domain})`)
        .join('\n'),
      fixPrompt: `Either rename the cookie to drop the prefix, OR fix the attributes. For __Host-: set Secure=true, Path=/, and DO NOT set a Domain attribute. For __Secure-: set Secure=true. If you don't need the strong guarantees (e.g. it's a CSRF token tied to a subpath), use a normal name like \`csrf_token\` instead.`,
    })
  }

  // 2c. Long-lived sensitive cookies — auth/session cookies with Max-Age > 30 days
  // are convenient but increase the blast radius if they leak.
  const longLivedSensitive = data.cookies.filter((c) => {
    const sensitive = /sess|auth|token|jwt|sid|csrf|access/i.test(c.name)
    return sensitive && typeof c.expiresInDays === 'number' && c.expiresInDays > 30
  })
  if (longLivedSensitive.length > 0) {
    findings.push({
      id: 'stage2-cookie-long-lived',
      severity: 'info',
      category: 'cookies',
      title: `${longLivedSensitive.length} sensitive cookie${longLivedSensitive.length === 1 ? '' : 's'} valid for >30 days`,
      description: `Auth-shaped cookies that live past 30 days expand the window where a stolen token can be replayed. Best practice is short-lived access tokens (15-60 min) with refresh tokens that rotate. If these are session cookies in name only but actually long-lived API tokens, that's the case to revisit.`,
      evidence: longLivedSensitive
        .map((c) => `${c.name} (expires in ~${c.expiresInDays} days)`)
        .join('\n'),
      fixPrompt: `For each long-lived cookie above: review whether it really needs a >30 day lifetime. If the underlying use case is "stay signed in", split into a short-lived access cookie (~30 min) + a long-lived refresh cookie that the server rotates on each use. That way a stolen access cookie has minutes to be exploited; the refresh cookie carries enough server-side state to detect replay.`,
    })
  }

  // 2. Cookies — Secure missing on HTTPS origin
  const finalIsHttps = data.finalUrl.startsWith('https://')
  if (finalIsHttps) {
    const insecureCookies = data.cookies.filter((c) => !c.secure)
    if (insecureCookies.length > 0) {
      findings.push({
        id: 'stage2-cookie-insecure',
        severity: 'warn',
        category: 'cookies',
        title: `${insecureCookies.length} cookie${insecureCookies.length === 1 ? '' : 's'} set without Secure flag on HTTPS site`,
        description: `On an HTTPS site, every cookie should have the Secure attribute. Without it, browsers will send the cookie over HTTP if any HTTP request to the same origin happens (e.g. a manual http:// link, mixed-content downgrade, or man-in-the-middle on a coffee-shop wifi). The cookie value leaks in cleartext.`,
        evidence: insecureCookies
          .slice(0, 8)
          .map((c) => `${c.name} (httpOnly=${c.httpOnly}, sameSite=${c.sameSite ?? 'None'})`)
          .join('\n'),
        fixPrompt: `Add Secure=true to every cookie set on this origin. Same mechanism as HttpOnly above — wherever you call res.cookie() / setCookie() / equivalent, add { secure: true }. Note: Secure is REQUIRED if SameSite is 'None'; browsers reject the cookie otherwise.`,
      })
    }
  }

  // 3. localStorage with auth-token-shaped keys
  const lsAuthKeys = data.localStorageKeys.filter((k) =>
    /sb-.*-auth-token|supabase\.auth\.token|firebase:authUser|access_token|refresh_token/i.test(k),
  )
  if (lsAuthKeys.length > 0) {
    findings.push({
      id: 'stage2-localstorage-auth-tokens',
      severity: 'warn',
      category: 'cookies',
      title: 'Authentication tokens stored in localStorage',
      description: `Found ${lsAuthKeys.length} key${lsAuthKeys.length === 1 ? '' : 's'} in localStorage that look like auth tokens. localStorage is fully readable by any JavaScript on this origin — any XSS immediately exfiltrates them. The recommended pattern is HttpOnly cookies for tokens, with localStorage only for non-sensitive UI state.`,
      evidence: lsAuthKeys.slice(0, 6).join('\n'),
      fixPrompt: `Move auth tokens to HttpOnly cookies. For Supabase: use the @supabase/ssr package and the "useSession with cookies" pattern. For Firebase: enable Firebase Hosting cookies or session cookies. The token will live in cookies (HttpOnly + Secure + SameSite=Lax) which JavaScript cannot read, dropping your XSS exposure for credential theft to zero.`,
    })
  }

  // 4. window.firebaseConfig exposed
  if (data.windowGlobals.hasFirebaseConfig) {
    findings.push({
      id: 'stage2-firebase-config-global',
      severity: 'info',
      category: 'meta',
      title: 'window.firebaseConfig is exposed globally',
      description: `Firebase configuration is attached to the window object. While Firebase config (apiKey, authDomain, etc.) is meant to be public, having it on a window global makes any 3rd-party script trivially dump it. Use module-scoped initialization instead.`,
      evidence: 'window.firebaseConfig is defined at runtime',
      fixPrompt: `Initialize Firebase inside an IIFE or a module — don't attach the config object to window. Also enable Firebase App Check for stronger client-side attestation; that way even if config leaks, an attacker can't make valid API calls without a verified browser.`,
    })
  }

  // 5. Network — confirm external API hits at runtime
  const apiHostsAtRuntime = Array.from(
    new Set(
      data.networkRequests
        .filter((r) =>
          /supabase\.co\/(rest|auth|storage|functions)|firebaseapp\.com|firebaseio\.com|googleapis\.com\/.*v[0-9]|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com/i.test(
            r.url,
          ),
        )
        .map((r) => {
          try {
            return new URL(r.url).host
          } catch {
            return r.url
          }
        }),
    ),
  )
  if (apiHostsAtRuntime.length > 0) {
    findings.push({
      id: 'stage2-external-apis',
      severity: 'info',
      category: 'meta',
      title: `Browser confirmed ${apiHostsAtRuntime.length} external API host${apiHostsAtRuntime.length === 1 ? '' : 's'} hit at runtime`,
      description: `Stage 1 detected references to these APIs from static HTML/bundle scanning. Stage 2 confirmed your browser actually hits them at runtime. Useful for verifying which integrations are live (vs dormant) and for auditing CSP connect-src directives.`,
      evidence: apiHostsAtRuntime.slice(0, 8).join('\n'),
      fixPrompt: `Audit your Content-Security-Policy connect-src directive against the hosts above. Every host your browser actually hits should be in connect-src; every host in connect-src should still be reachable here. Drift either way (allowed-but-unused or used-but-not-allowed) signals tech debt or stealth integrations.`,
    })
  }

  // 6. Network — non-HTTPS request from an HTTPS page
  if (finalIsHttps) {
    const httpRequests = data.networkRequests.filter((r) => r.url.startsWith('http://'))
    if (httpRequests.length > 0) {
      const hosts = Array.from(new Set(httpRequests.map((r) => {
        try { return new URL(r.url).host } catch { return r.url }
      })))
      findings.push({
        id: 'stage2-mixed-content-runtime',
        severity: 'warn',
        category: 'mixed-content',
        title: `Browser made ${httpRequests.length} HTTP request${httpRequests.length === 1 ? '' : 's'} from an HTTPS page`,
        description: `This is mixed content confirmed at runtime — Stage 1 may not see this if the request is triggered by JavaScript after page load. Modern browsers block most active mixed content, but cookies on the HTTP origin still leak.`,
        evidence: hosts.slice(0, 6).join('\n'),
        fixPrompt: `Find every fetch/XHR/img/script in your code that uses http:// and switch to https://. Run "git grep \\"http://\\"" to find them. If a third-party host doesn't support HTTPS, find an alternative. As a stop-gap, add "upgrade-insecure-requests" to your CSP so browsers auto-rewrite http to https.`,
      })
    }
  }

  // 6.5. Stage 2.4 — JWT analysis. Worker decoded JWTs locally; the analyses
  //      are privacy-safe (alg + claim NAMES only, no values).
  const jwts = data.jwtAnalysis ?? []
  if (jwts.length > 0) {
    const algNone = jwts.filter((j) => (j.alg ?? '').toLowerCase() === 'none')
    if (algNone.length > 0) {
      findings.push({
        id: 'stage2-jwt-alg-none',
        severity: 'critical',
        category: 'auth',
        title: `${algNone.length} JWT${algNone.length === 1 ? '' : 's'} use alg="none" (unsigned)`,
        description: `Stage 2 found JWT-shaped tokens with alg="none" in your cookies/storage. Unsigned tokens are forgeable — anyone can craft a payload claiming any user/role. This is one of the oldest and most exploited JWT bugs.`,
        evidence: algNone.map((j) => `${j.source}:${j.keyName} alg=none`).join('\n'),
        fixPrompt: `Configure your JWT verifier to REJECT alg="none" — most libraries (jsonwebtoken, jose, etc.) require you to pass an explicit allowlist of algorithms. Pick HS256 (symmetric, good for monolith) or RS256 (asymmetric, good when verifiers don't share the signing key). Re-sign every issued token with the new algorithm and rotate the previous secret. Never trust the alg field from the token itself for verifier selection.`,
      })
    }
    const noExp = jwts.filter((j) => !j.hasExp)
    if (noExp.length > 0) {
      findings.push({
        id: 'stage2-jwt-no-exp',
        severity: 'warn',
        category: 'auth',
        title: `${noExp.length} JWT${noExp.length === 1 ? '' : 's'} have no \`exp\` claim`,
        description: `Tokens without an exp claim are valid forever — there's no way for the server to know when to stop accepting them, and revocation requires a denylist that most setups don't have. A leaked token from 6 months ago still authenticates today.`,
        evidence: noExp.map((j) => `${j.source}:${j.keyName} (no exp)`).join('\n'),
        fixPrompt: `Issue every JWT with a near-term \`exp\` (15-60 min for access tokens, 7-30 days for refresh tokens). Most libraries take \`expiresIn\` as an option; if you're hand-crafting payloads, add \`exp: Math.floor(Date.now() / 1000) + 60 * 60\`. Reject tokens missing \`exp\` server-side — a missing expiry should never be treated as "no expiry".`,
      })
    }
    const farFutureExp = jwts.filter(
      (j) => j.hasExp && typeof j.expSecondsFromNow === 'number' && j.expSecondsFromNow > 60 * 60 * 24 * 365,
    )
    if (farFutureExp.length > 0) {
      findings.push({
        id: 'stage2-jwt-very-long-exp',
        severity: 'info',
        category: 'auth',
        title: `${farFutureExp.length} JWT${farFutureExp.length === 1 ? '' : 's'} expire more than 1 year from now`,
        description: `JWTs with a year+ lifetime function as nearly-permanent credentials. If the token leaks, the attacker has a year to abuse it. Short access tokens + refresh tokens are the standard pattern.`,
        evidence: farFutureExp
          .map(
            (j) =>
              `${j.source}:${j.keyName} expires in ${Math.round((j.expSecondsFromNow ?? 0) / 86400)} days`,
          )
          .join('\n'),
        fixPrompt: `Reduce \`exp\` to 15-60 minutes for access tokens. If you need long sessions, issue a separate refresh token (HttpOnly + Secure cookie) and rotate the access token on each refresh. The endpoints above are the ones currently issued long-lived; back through the issuer config and shorten.`,
      })
    }
    const sensitiveClaims = jwts
      .map((j) => ({
        j,
        sensitive: j.claimNames.filter((n) =>
          /^(email|email_verified|phone|name|given_name|family_name|address|role|roles|permissions)$/i.test(n),
        ),
      }))
      .filter((x) => x.sensitive.length > 0)
    if (sensitiveClaims.length > 0) {
      findings.push({
        id: 'stage2-jwt-sensitive-claims',
        severity: 'info',
        category: 'auth',
        title: `JWT payload exposes ${sensitiveClaims[0].sensitive.length} sensitive claim${
          sensitiveClaims[0].sensitive.length === 1 ? '' : 's'
        }`,
        description: `JWT payloads are base64-encoded JSON, NOT encrypted. Anyone holding the token reads every claim. Tokens stored in localStorage or non-HttpOnly cookies are exfiltrated by any XSS payload — at which point the attacker also gets every claim inside (email, role, permissions, etc.). Best practice: keep JWTs minimal (sub + scope at most) and look up the rest server-side per request.`,
        evidence: sensitiveClaims
          .slice(0, 4)
          .map((x) => `${x.j.source}:${x.j.keyName} → ${x.sensitive.join(', ')}`)
          .join('\n'),
        fixPrompt: `Audit your JWT issuance: which claims are inside? If \`role\`, \`permissions\`, \`email\`, or any PII is in the token, move them to a server-side session lookup keyed by the JWT's \`sub\` (user id). Re-issue tokens with only the minimum claims (\`sub\`, \`exp\`, \`iat\`, \`scope\` if needed). Any client code that read the claim from the JWT now needs an API call instead — that's the right tradeoff for security.`,
      })
    }
  }

  // 6.6. Stage 2.4 — Sensitive data in response bodies (S2+4). Worker
  //      scanned response bodies locally; sends back only `{type, redactedSample, sourceUrl}`.
  const sd = data.sensitiveDataFindings ?? []
  if (sd.length > 0) {
    const buckets = new Map<string, WorkerSensitiveDataHit[]>()
    for (const h of sd) {
      const key =
        h.type === 'aws-key' || h.type === 'github-pat' || h.type === 'openai-key' ||
        h.type === 'anthropic-key' || h.type === 'stripe-key' || h.type === 'jwt-in-body'
          ? 'secret'
          : h.type === 'email' || h.type === 'phone-il' || h.type === 'phone-intl' ||
            h.type === 'israeli-id' || h.type === 'credit-card'
            ? 'pii'
            : h.type === 'internal-url'
              ? 'internal'
              : 'stack'
      const arr = buckets.get(key) ?? []
      arr.push(h)
      buckets.set(key, arr)
    }

    const secrets = buckets.get('secret') ?? []
    if (secrets.length > 0) {
      findings.push({
        id: 'stage2-secret-in-response',
        severity: 'critical',
        category: 'secrets',
        title: `${secrets.length} secret${secrets.length === 1 ? '' : 's'} returned in response bod${secrets.length === 1 ? 'y' : 'ies'}`,
        description: `Stage 2 captured response bodies your browser fetched and found ${secrets.length} server-issued secret${secrets.length === 1 ? '' : 's'} in them. APIs should never return raw provider keys, JWTs, or AWS access keys to the browser. Whatever this token is, it's now in browser memory + dev-tools network panel — assume any user can read it.`,
        evidence: secrets.slice(0, 8).map((s) => `${s.type} "${s.redactedSample}" in ${s.sourceUrl}`).join('\n'),
        fixPrompt: `Audit each endpoint above and remove the leaked secret from the response body. Common patterns: (1) an admin endpoint returns a service-role config object that includes a secret instead of just the public fields — split the response. (2) An error handler dumps the full env or config — replace with a generic message and log the detail server-side. (3) A development helper endpoint was left enabled in production — gate it behind NODE_ENV !== 'production'. After fixing, treat each secret as compromised and rotate at the issuing service.`,
      })
    }

    const pii = buckets.get('pii') ?? []
    if (pii.length > 0) {
      // PII in own-data responses (logged-in user's profile) is fine; PII in
      // a public/unauth endpoint is the leak. We can't tell which here, so
      // flag as warn and let the user audit per source.
      findings.push({
        id: 'stage2-pii-in-response',
        severity: 'warn',
        category: 'meta',
        title: `${pii.length} PII match${pii.length === 1 ? '' : 'es'} in response bod${pii.length === 1 ? 'y' : 'ies'}`,
        description: `Stage 2 found PII patterns (emails, phone numbers, Israeli IDs, credit cards) in response bodies the browser fetched. Some are legitimate (the logged-in user's own profile); some are leaks (an unauthenticated endpoint that returns other users' data, or a debug endpoint that dumps a database). Audit the sources below.`,
        evidence: pii.slice(0, 8).map((p) => `${p.type} "${p.redactedSample}" in ${p.sourceUrl}`).join('\n'),
        fixPrompt: `For each endpoint above: confirm the caller is authenticated AND authorized to see this data. (1) Anonymous endpoints should never return user emails/phones unless explicitly intentional (e.g. public author byline). (2) Authenticated endpoints should filter to ONLY the requesting user's data — IDOR class bug if /api/users/123 returns user 124's data. (3) Credit cards should never round-trip — if you see one in a response, you have a major PCI violation; mask server-side before sending.`,
      })
    }

    const internal = buckets.get('internal') ?? []
    if (internal.length > 0) {
      findings.push({
        id: 'stage2-internal-url-leak',
        severity: 'warn',
        category: 'meta',
        title: `${internal.length} internal URL${internal.length === 1 ? '' : 's'} leaked in response bod${internal.length === 1 ? 'y' : 'ies'}`,
        description: `Response bodies referenced private-IP, *.internal, *.local, or localhost URLs. These are infrastructure-recon gold for attackers — they reveal internal service topology, hostname conventions, and ports that aren't supposed to be public knowledge. Often appear in error stack traces, debug responses, or accidentally-shipped dev configs.`,
        evidence: internal.slice(0, 8).map((u) => `${u.redactedSample} in ${u.sourceUrl}`).join('\n'),
        fixPrompt: `Find where each internal URL is constructed and stop returning it to the client. (1) Replace internal hostnames with public-DNS equivalents server-side. (2) Strip stack traces from error responses in production — return a correlation ID instead, and log the trace to your error tracker. (3) Don't ship dev config defaults; require env vars to be explicitly set in prod and fail loudly if missing.`,
      })
    }

    const stacks = buckets.get('stack') ?? []
    if (stacks.length > 0) {
      findings.push({
        id: 'stage2-stack-trace-in-response',
        severity: 'warn',
        category: 'meta',
        title: `${stacks.length} response${stacks.length === 1 ? '' : 's'} include absolute file paths`,
        description: `Found absolute filesystem paths (Unix /home/.../, /opt/..., /var/... or Windows C:\\...) in response bodies. Almost always a stack trace from an unhandled error. Reveals the exact code structure, OS, deployment user, and sometimes credential paths to an attacker.`,
        evidence: stacks.slice(0, 6).map((s) => `${s.redactedSample} in ${s.sourceUrl}`).join('\n'),
        fixPrompt: `Add a top-level error handler that produces a sanitized response in production. Express: \`app.use((err, req, res, next) => { logger.error(err); res.status(500).json({ error: 'Internal error', traceId }) })\`. Next.js: customize \`error.tsx\` / API \`onError\` to never include err.stack. Verify by triggering a controlled error in prod (e.g. malformed JSON body) and confirming the response has no path strings.`,
      })
    }
  }

  // 7. Live API map — surface what the browser actually hit, and call out
  //    first-party API calls that returned 2xx without Authorization OR Cookie.
  const apiMap = buildLiveApiMap(data)
  if (apiMap.unauthApiCalls.length > 0) {
    findings.push({
      id: 'stage2-unauth-api-calls',
      severity: 'warn',
      category: 'auth',
      title: `${apiMap.unauthApiCalls.length} first-party API call${
        apiMap.unauthApiCalls.length === 1 ? '' : 's'
      } returned 2xx without auth`,
      description: `During the scan, ${apiMap.unauthApiCalls.length} call${
        apiMap.unauthApiCalls.length === 1 ? '' : 's'
      } to your own API endpoints succeeded without an Authorization header AND without a Cookie. That means an unauthenticated visitor reached data or actions that may be intended for logged-in users only. Some of these are legitimate public endpoints (e.g. /api/health) — many are not. Audit each.`,
      evidence: apiMap.unauthApiCalls
        .slice(0, 8)
        .map((c) => `${c.method} ${c.url} → ${c.status} (${c.contentType ?? 'no content-type'})`)
        .join('\n'),
      fixPrompt: `For each of the endpoints above: open the route handler and confirm whether it should require auth. If yes — add an auth gate (NextAuth getServerSession, Supabase getSession on the request, custom JWT middleware). If no — that's fine, but consider rate-limiting (Vercel WAF or middleware) so it can't be abused for scraping or DoS. Re-run Stage 2 after fixing to confirm only intentionally-public endpoints remain.`,
    })
  } else if (apiMap.totalRequests > 0) {
    findings.push({
      id: 'stage2-api-map-clean',
      severity: 'ok',
      category: 'auth',
      title: `Live API map captured ${apiMap.apiCalls.length} call${
        apiMap.apiCalls.length === 1 ? '' : 's'
      } across ${apiMap.apiHosts.length} host${apiMap.apiHosts.length === 1 ? '' : 's'}`,
      description: `Browser ran the page and recorded every fetch/XHR. None of the first-party API calls succeeded without auth — a sign your gates are wired correctly at the runtime level (not just declared in code).`,
      evidence: apiMap.apiHosts
        .slice(0, 6)
        .map((h) => `${h.host} (${h.count} call${h.count === 1 ? '' : 's'}, ${h.origin})`)
        .join('\n'),
      fixPrompt: '',
    })
  }

  // 8. Console errors — informational signal of misconfiguration
  if (data.consoleErrors.length >= 3) {
    findings.push({
      id: 'stage2-console-errors',
      severity: 'info',
      category: 'meta',
      title: `${data.consoleErrors.length} console error${data.consoleErrors.length === 1 ? '' : 's'} during page load`,
      description: `The browser logged multiple errors while loading the page. Errors don't directly indicate a vulnerability, but they often expose stack traces, internal endpoints, or auth misconfig that helps an attacker recon.`,
      evidence: data.consoleErrors.slice(0, 5).join('\n---\n'),
      fixPrompt: `Open the browser DevTools console on this page and triage the errors. For each: confirm it's not leaking internal info (file paths, internal API URLs, auth endpoints). Fix or silence; uncaught errors are also a UX bug. Production builds should be clean — if these only show in dev, that's fine, but verify they don't appear on the deployed bundle.`,
    })
  }

  // Clean marker if nothing else fired
  if (findings.length === 0) {
    findings.push({
      id: 'stage2-clean',
      severity: 'ok',
      category: 'meta',
      title: 'Stage 2 browser scan added no new findings',
      description: `The headless browser ran your site, snapshotted cookies/localStorage/window globals, and recorded ${data.networkRequests.length} network request${data.networkRequests.length === 1 ? '' : 's'}. Nothing visible only at runtime came up — your runtime hygiene matches your static profile.`,
      evidence: `Stage 2 completed in ${data.durationMs}ms · ${data.cookies.length} cookies · ${data.localStorageKeys.length} localStorage keys · ${data.networkRequests.length} requests`,
      fixPrompt: '',
    })
  }

  return findings
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const workerUrl = process.env.STAGE2_WORKER_URL
  const workerToken = process.env.STAGE2_WORKER_TOKEN
  if (!workerUrl || !workerToken) {
    return res.status(503).json({
      ok: false,
      error: {
        code: 'not_configured',
        message:
          "Server-side browser-assisted scanning isn't configured on this deployment. Use the bookmarklet flow instead — it works without any worker.",
      },
    })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as BrowserScanBody
  const url = (body.url ?? '').trim()
  const framework = typeof body.framework === 'string' ? body.framework.trim() || null : null
  if (!url) {
    return res.status(400).json({ ok: false, error: { code: 'invalid_url', message: 'Missing url.' } })
  }

  fireAndForget(
    logAuditEvent(req, { event_type: 'stage2_started', scanned_url: url.slice(0, 1000) }),
  )

  const t0 = Date.now()
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 45000)
    let r: Response
    try {
      r = await fetch(`${workerUrl.replace(/\/$/, '')}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${workerToken}`,
        },
        body: JSON.stringify({ url, timeout: 15000 }),
        signal: controller.signal,
      })
    } finally {
      clearTimeout(timer)
    }
    if (!r.ok) {
      const text = (await r.text()).slice(0, 500)
      return res.status(r.status).json({
        ok: false,
        error: {
          code: 'internal',
          message: `Worker returned ${r.status}: ${text}`,
        },
      })
    }
    const workerData = (await r.json()) as WorkerScanResult
    const rawFindings = analyzeBrowserScan(workerData)
    const enriched = enrichFindings(rawFindings, {
      finalUrl: workerData.finalUrl,
      detectedFramework: framework,
    })
    // Apply the same content-aware risk scoring used in Stage 1 / Stage 3
    // so Stage 2 findings don't ship without riskScore + riskBand.
    let routeContext: 'sensitive' | 'public' | 'unknown' = 'unknown'
    try {
      routeContext = classifyRouteContext(new URL(workerData.finalUrl).pathname)
    } catch {
      // workerData.finalUrl invalid — keep 'unknown'
    }
    const scored = applyRisk(enriched, routeContext)
    const liveApiMap = buildLiveApiMap(workerData)
    fireAndForget(
      logAuditEvent(req, {
        event_type: 'stage2_completed',
        scanned_url: url.slice(0, 1000),
        scan_outcome: 'success',
        metadata: {
          finding_count: scored.length,
          network_request_count: workerData.networkRequests.length,
          cookie_count: workerData.cookies.length,
          duration_ms: Date.now() - t0,
        },
      }),
    )
    return res.status(200).json({
      ok: true,
      stage: 2,
      url: workerData.url,
      finalUrl: workerData.finalUrl,
      durationMs: Date.now() - t0,
      workerDurationMs: workerData.durationMs,
      networkRequestCount: workerData.networkRequests.length,
      cookieCount: workerData.cookies.length,
      findings: scored,
      routeContext,
      liveApiMap,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: { code: 'internal', message: msg } })
  }
}
