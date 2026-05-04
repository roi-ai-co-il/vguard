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
import { chromium, type Browser } from 'playwright-chromium'

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

interface ScanResult {
  ok: true
  url: string
  finalUrl: string
  networkRequests: { url: string; method: string; status: number; resourceType: string }[]
  consoleErrors: string[]
  windowGlobals: Record<string, boolean>
  cookies: { name: string; httpOnly: boolean; secure: boolean; sameSite: string | undefined; domain: string }[]
  localStorageKeys: string[]
  sessionStorageKeys: string[]
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

  page.on('response', async (resp) => {
    if (networkRequests.length >= 200) return
    networkRequests.push({
      url: resp.url(),
      method: resp.request().method(),
      status: resp.status(),
      resourceType: resp.request().resourceType(),
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

  const collected = await page.evaluate(() => {
    type WindowSnapshot = Record<string, unknown>
    const w = window as unknown as WindowSnapshot
    return {
      windowGlobals: {
        hasSupabase: typeof w.supabase !== 'undefined',
        hasFirebase: typeof w.firebase !== 'undefined',
        hasFirebaseConfig: typeof w.firebaseConfig !== 'undefined',
        hasAppConfig:
          typeof w.__APP_CONFIG !== 'undefined' || typeof w.__NEXT_DATA__ !== 'undefined',
        hasReactRoot: !!document.getElementById('root'),
      },
      localStorageKeys: Object.keys(localStorage),
      sessionStorageKeys: Object.keys(sessionStorage),
    }
  })

  const cookieSnapshot = await context.cookies()
  const cookies = cookieSnapshot.map((c) => ({
    name: c.name,
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
    domain: c.domain,
  }))

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
    localStorageKeys: collected.localStorageKeys,
    sessionStorageKeys: collected.sessionStorageKeys,
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
