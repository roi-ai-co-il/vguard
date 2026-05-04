/**
 * VibeSecure Stage 2 Playwright worker. Deploy to Railway / Fly / your-own-host.
 * Does NOT run on Vercel — @sparticuz/chromium cold starts are too slow for an
 * interactive UX. Better to keep a small dedicated worker on Railway that the
 * Vercel proxy endpoint hits.
 *
 * Endpoint:
 *   POST /scan  { url: string, timeout?: number }
 *   → { ok, url, finalUrl, networkRequests, consoleErrors, windowGlobals,
 *       cookies, localStorageKeys, sessionStorageKeys, durationMs }
 *
 * Auth: requires `Authorization: Bearer <STAGE2_WORKER_TOKEN>` header.
 * Set STAGE2_WORKER_TOKEN to a long random string (and add the same value
 * to the VibeSecure Vercel env vars).
 */
import express from 'express'
import { chromium, type Browser, type Request as PWRequest } from 'playwright-chromium'

const app = express()
app.use(express.json({ limit: '256kb' }))

const WORKER_TOKEN = process.env.STAGE2_WORKER_TOKEN ?? ''
const PORT = parseInt(process.env.PORT ?? '8080', 10)

let browserPromise: Promise<Browser> | null = null
function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = chromium.launch({ headless: true, args: ['--no-sandbox'] })
  }
  return browserPromise
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

/**
 * Live API mapping (Stage 2.3) — every network entry now carries the metadata
 * the proxy analyzer + UI need to spot weak APIs without re-fetching:
 *   - contentType (from response headers — JSON / HTML / image classification)
 *   - sizeBytes (from response body, undefined when streamed without length)
 *   - durationMs (request → response latency)
 *   - hasAuthHeader (Authorization OR Cookie present, name only — never value)
 *   - hasOriginHeader (CORS visibility marker, useful for cross-origin audits)
 *
 * The proxy treats every new field as optional so an older worker still works.
 */
interface NetworkRequestEntry {
  url: string
  method: string
  status: number
  resourceType: string
  contentType?: string
  sizeBytes?: number
  durationMs?: number
  hasAuthHeader?: boolean
  hasOriginHeader?: boolean
}

/**
 * JWT analysis — Stage 2.4.
 *
 * The worker scans cookie values + localStorage/sessionStorage values for
 * the JWT pattern (eyJ...eyJ...sig), decodes header + payload locally, and
 * sends back ONLY the analysis: algorithm, exp presence, claim names, etc.
 * The actual JWT value never leaves the worker — privacy by design.
 *
 * Claim names are emitted (not values) so the proxy can flag overly-private
 * data sitting in tokens any XSS payload could exfiltrate.
 */
interface JwtAnalysis {
  source: 'cookie' | 'localStorage' | 'sessionStorage'
  /** Cookie or storage key the JWT lived in (no value). */
  keyName: string
  alg: string | null
  typ: string | null
  hasExp: boolean
  /** When `exp` is present, seconds until expiry (negative = already expired). */
  expSecondsFromNow: number | null
  hasIss: boolean
  hasAud: boolean
  /** Names of payload claims (NOT values) — lets the proxy flag PII at rest. */
  claimNames: string[]
}

const JWT_RE = /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/

function base64UrlDecode(s: string): string {
  // base64url → base64
  let b = s.replace(/-/g, '+').replace(/_/g, '/')
  while (b.length % 4) b += '='
  try {
    return Buffer.from(b, 'base64').toString('utf-8')
  } catch {
    return ''
  }
}

function analyzeJwt(source: JwtAnalysis['source'], keyName: string, value: string): JwtAnalysis | null {
  if (typeof value !== 'string' || value.length < 30 || value.length > 4096) return null
  if (!JWT_RE.test(value)) return null
  const parts = value.split('.')
  if (parts.length !== 3) return null
  const headerJson = base64UrlDecode(parts[0])
  const payloadJson = base64UrlDecode(parts[1])
  let header: Record<string, unknown> = {}
  let payload: Record<string, unknown> = {}
  try {
    header = JSON.parse(headerJson) as Record<string, unknown>
    payload = JSON.parse(payloadJson) as Record<string, unknown>
  } catch {
    return null
  }
  const alg = typeof header['alg'] === 'string' ? (header['alg'] as string) : null
  const typ = typeof header['typ'] === 'string' ? (header['typ'] as string) : null
  const exp = typeof payload['exp'] === 'number' ? (payload['exp'] as number) : null
  const expSecondsFromNow = exp === null ? null : exp - Math.floor(Date.now() / 1000)
  return {
    source,
    keyName,
    alg,
    typ,
    hasExp: exp !== null,
    expSecondsFromNow,
    hasIss: typeof payload['iss'] === 'string',
    hasAud: typeof payload['aud'] === 'string' || Array.isArray(payload['aud']),
    claimNames: Object.keys(payload).slice(0, 32),
  }
}

interface CookieEntry {
  name: string
  httpOnly: boolean
  secure: boolean
  sameSite: string | undefined
  domain: string
  path?: string
  /** Days until expiry (-1 = session cookie). */
  expiresInDays?: number
  /** Did Playwright report `partitioned` (CHIPS opt-in)? */
  partitioned?: boolean
  /** True when the cookie's value matches the JWT shape. */
  isJwt?: boolean
}

interface ScanResult {
  ok: true
  url: string
  finalUrl: string
  networkRequests: NetworkRequestEntry[]
  consoleErrors: string[]
  windowGlobals: Record<string, boolean>
  cookies: CookieEntry[]
  localStorageKeys: string[]
  sessionStorageKeys: string[]
  /** JWTs detected anywhere (cookie value or storage value). Values are never sent back — only analysis. */
  jwtAnalysis: JwtAnalysis[]
  durationMs: number
}

app.post('/scan', async (req, res) => {
  const t0 = Date.now()
  if (!WORKER_TOKEN) {
    return res.status(503).json({ ok: false, error: 'Worker token not configured.' })
  }
  const auth = req.headers.authorization ?? ''
  if (auth !== `Bearer ${WORKER_TOKEN}`) {
    return res.status(401).json({ ok: false, error: 'Unauthorized.' })
  }

  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : ''
  const timeoutMs = Math.min(parseInt(req.body?.timeout ?? '15000', 10), 30000)

  let parsed: URL
  try {
    parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`)
  } catch {
    return res.status(400).json({ ok: false, error: 'Invalid URL.' })
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ ok: false, error: 'Only http/https.' })
  }
  if (isPrivateHost(parsed.hostname)) {
    return res.status(400).json({ ok: false, error: 'Private/local hosts not allowed.' })
  }

  const browser = await getBrowser()
  const context = await browser.newContext({
    userAgent: 'VibeSecure-Stage2/0.1',
    viewport: { width: 1280, height: 800 },
  })
  const page = await context.newPage()

  const networkRequests: ScanResult['networkRequests'] = []
  const consoleErrors: string[] = []
  // Track request-start timestamps so we can derive durationMs on response.
  const requestStartedAt = new WeakMap<PWRequest, number>()

  page.on('request', (req) => {
    requestStartedAt.set(req, Date.now())
  })

  page.on('response', async (resp) => {
    if (networkRequests.length >= 200) return
    const req = resp.request()
    const reqHeaders = req.headers()
    const respHeaders = resp.headers()
    const startedAt = requestStartedAt.get(req)
    const contentLengthRaw = respHeaders['content-length']
    const contentLength = contentLengthRaw ? parseInt(contentLengthRaw, 10) : undefined
    networkRequests.push({
      url: resp.url(),
      method: req.method(),
      status: resp.status(),
      resourceType: req.resourceType(),
      contentType: respHeaders['content-type'],
      sizeBytes: Number.isFinite(contentLength) ? contentLength : undefined,
      durationMs: startedAt ? Date.now() - startedAt : undefined,
      hasAuthHeader: Boolean(reqHeaders['authorization'] || reqHeaders['cookie']),
      hasOriginHeader: Boolean(reqHeaders['origin']),
    })
  })
  page.on('pageerror', (err) => {
    if (consoleErrors.length >= 50) return
    consoleErrors.push(String(err.message ?? err).slice(0, 500))
  })
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return
    if (consoleErrors.length >= 50) return
    consoleErrors.push(msg.text().slice(0, 500))
  })

  let finalUrl = parsed.toString()
  try {
    await page.goto(parsed.toString(), { waitUntil: 'networkidle', timeout: timeoutMs })
    finalUrl = page.url()
    // Give async hydration a beat
    await page.waitForTimeout(1500)
  } catch (e) {
    // Continue with what we collected so far
    consoleErrors.push(`navigation: ${e instanceof Error ? e.message : 'failed'}`)
  }

  // Stage 2.4 — JWT decoding requires VALUES (not just keys), so the page
  // pulls keys + values for storage and we scan them locally on the worker.
  // Values never leave the worker — only the privacy-safe analysis goes back.
  const collected = await page.evaluate(() => {
    type WindowSnapshot = Record<string, unknown>
    const w = window as unknown as WindowSnapshot
    const collectStorage = (storage: Storage): { key: string; value: string }[] => {
      const out: { key: string; value: string }[] = []
      for (let i = 0; i < storage.length && i < 200; i++) {
        const k = storage.key(i)
        if (k === null) continue
        const v = storage.getItem(k) ?? ''
        // Cap individual value at 8KB so a giant blob doesn't OOM the worker.
        out.push({ key: k, value: v.slice(0, 8192) })
      }
      return out
    }
    return {
      windowGlobals: {
        hasSupabase: typeof w.supabase !== 'undefined',
        hasFirebase: typeof w.firebase !== 'undefined',
        hasFirebaseConfig: typeof w.firebaseConfig !== 'undefined',
        hasAppConfig:
          typeof w.__APP_CONFIG !== 'undefined' || typeof w.__NEXT_DATA__ !== 'undefined',
        hasReactRoot: !!document.getElementById('root'),
      },
      localStorageEntries: collectStorage(localStorage),
      sessionStorageEntries: collectStorage(sessionStorage),
    }
  })

  const cookieSnapshot = await context.cookies()
  const nowSec = Math.floor(Date.now() / 1000)
  const cookies: CookieEntry[] = cookieSnapshot.map((c) => {
    const expiresInDays = typeof c.expires === 'number' && c.expires > 0
      ? Math.round((c.expires - nowSec) / 86400)
      : -1
    const partitioned = (c as unknown as { partitioned?: boolean }).partitioned ?? false
    const isJwt = typeof c.value === 'string' && JWT_RE.test(c.value)
    return {
      name: c.name,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite,
      domain: c.domain,
      path: c.path,
      expiresInDays,
      partitioned,
      isJwt,
    }
  })

  // JWT analysis from cookie values + storage values — values stay local.
  const jwtAnalysis: JwtAnalysis[] = []
  for (const c of cookieSnapshot) {
    const a = analyzeJwt('cookie', c.name, c.value)
    if (a) jwtAnalysis.push(a)
  }
  for (const e of collected.localStorageEntries) {
    const a = analyzeJwt('localStorage', e.key, e.value)
    if (a) jwtAnalysis.push(a)
  }
  for (const e of collected.sessionStorageEntries) {
    const a = analyzeJwt('sessionStorage', e.key, e.value)
    if (a) jwtAnalysis.push(a)
  }
  const localStorageKeys = collected.localStorageEntries.map((e) => e.key)
  const sessionStorageKeys = collected.sessionStorageEntries.map((e) => e.key)

  await page.close().catch(() => undefined)
  await context.close().catch(() => undefined)

  const result: ScanResult = {
    ok: true,
    url: parsed.toString(),
    finalUrl,
    networkRequests,
    consoleErrors,
    windowGlobals: collected.windowGlobals,
    cookies,
    localStorageKeys,
    sessionStorageKeys,
    jwtAnalysis,
    durationMs: Date.now() - t0,
  }
  return res.json(result)
})

app.get('/healthz', (_req, res) => {
  res.json({ ok: true, version: '0.1.0' })
})

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`vibesecure stage2 worker listening on :${PORT}`)
})
