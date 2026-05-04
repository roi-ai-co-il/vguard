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

  // 7. Console errors — informational signal of misconfiguration
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
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: { code: 'internal', message: msg } })
  }
}
