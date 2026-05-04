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
      (e.method !== 'GET' || /\/(api|v1|v2|graphql|trpc)\//i.test(e.url)),
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
    const liveApiMap = buildLiveApiMap(workerData)
    return res.status(200).json({
      ok: true,
      stage: 2,
      url: workerData.url,
      finalUrl: workerData.finalUrl,
      durationMs: Date.now() - t0,
      workerDurationMs: workerData.durationMs,
      networkRequestCount: workerData.networkRequests.length,
      cookieCount: workerData.cookies.length,
      findings: enriched,
      liveApiMap,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: { code: 'internal', message: msg } })
  }
}
