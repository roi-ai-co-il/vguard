import crypto from 'node:crypto'
import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface RateLimitBucket {
  count: number
  resetAt: number
}
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX = 30
const buckets = new Map<string, RateLimitBucket>()

function clientIp(req: VercelRequest): string {
  const xff = req.headers['x-forwarded-for']
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim()
  if (Array.isArray(xff) && xff.length > 0) return xff[0].split(',')[0].trim()
  const real = req.headers['x-real-ip']
  if (typeof real === 'string') return real
  return 'unknown'
}

function rateLimited(key: string): boolean {
  const now = Date.now()
  const b = buckets.get(key)
  if (!b || b.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    return false
  }
  b.count += 1
  return b.count > RATE_LIMIT_MAX
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return crypto.timingSafeEqual(ab, bb)
}

const SESSION_TTL_MS = 15 * 60 * 1000
const SESSION_COOKIE = 'vg_admin_session'

function signSession(expiresAt: number, adminSecret: string): string {
  const hmac = crypto.createHmac('sha256', adminSecret).update(String(expiresAt)).digest('hex')
  return `${expiresAt}.${hmac}`
}

function verifySession(cookieValue: string | undefined, adminSecret: string): boolean {
  if (!cookieValue) return false
  const idx = cookieValue.indexOf('.')
  if (idx < 0) return false
  const expiresAt = parseInt(cookieValue.slice(0, idx), 10)
  const hmac = cookieValue.slice(idx + 1)
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false
  const expected = crypto.createHmac('sha256', adminSecret).update(String(expiresAt)).digest('hex')
  if (hmac.length !== expected.length) return false
  return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expected))
}

function readCookie(req: VercelRequest, name: string): string | undefined {
  const raw = req.headers.cookie
  if (typeof raw !== 'string') return undefined
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === name) return rest.join('=')
  }
  return undefined
}

async function verifyTurnstile(token: string, ip: string | null): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY
  if (!secret) return true // Turnstile disabled — skip
  if (!token) return false
  const body = new URLSearchParams({ secret, response: token })
  if (ip && ip !== 'unknown') body.set('remoteip', ip)
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    const j = (await r.json()) as { success?: boolean }
    return j.success === true
  } catch {
    return false
  }
}

function checkAuth(req: VercelRequest): { ok: boolean; reason?: string } {
  const adminSecret = process.env.ADMIN_SECRET
  if (adminSecret) {
    const provided =
      (req.headers['x-admin-secret'] as string | undefined) ??
      (typeof req.query.secret === 'string' ? req.query.secret : '')
    if (!provided) return { ok: false, reason: 'no_secret' }
    return { ok: constantTimeEqual(provided, adminSecret) }
  }
  // No secret OR email allowlist configured → refuse rather than leak.
  return { ok: false, reason: 'not_configured' }
}

function notFound(res: VercelResponse) {
  // Hide existence of the route from non-admins.
  res.setHeader('Cache-Control', 'no-store')
  return res.status(404).json({ ok: false, error: 'not_found' })
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'GET') {
    return notFound(res)
  }

  if (rateLimited(`admin:${clientIp(req)}`)) {
    return res.status(429).json({ ok: false, error: 'rate_limited' })
  }

  const auth = checkAuth(req)
  if (!auth.ok) {
    return notFound(res)
  }

  // Turnstile gate: required unless a still-valid session cookie is present.
  // The cookie is HMAC-signed with ADMIN_SECRET so it cannot be forged.
  const adminSecret = process.env.ADMIN_SECRET as string
  const sessionCookie = readCookie(req, SESSION_COOKIE)
  const sessionValid = verifySession(sessionCookie, adminSecret)
  let issuedNewSession = false
  if (!sessionValid) {
    const tsToken = (req.headers['x-turnstile-token'] as string | undefined) ?? ''
    const tsOk = await verifyTurnstile(tsToken, clientIp(req))
    if (!tsOk) {
      return notFound(res)
    }
    const expiresAt = Date.now() + SESSION_TTL_MS
    const cookie = signSession(expiresAt, adminSecret)
    res.setHeader(
      'Set-Cookie',
      `${SESSION_COOKIE}=${cookie}; Path=/api/admin; Max-Age=${SESSION_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Strict`,
    )
    issuedNewSession = true
  }
  void issuedNewSession

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) {
    return res.status(503).json({ ok: false, error: 'storage_not_configured' })
  }

  const limit = Math.min(
    parseInt(typeof req.query.limit === 'string' ? req.query.limit : '100', 10) || 100,
    500,
  )
  const eventType = typeof req.query.event_type === 'string' ? req.query.event_type : null
  const scannedDomain = typeof req.query.domain === 'string' ? req.query.domain : null
  const scanOutcome = typeof req.query.scan_outcome === 'string' ? req.query.scan_outcome : null
  const wafVendor = typeof req.query.waf_vendor === 'string' ? req.query.waf_vendor : null
  const since = typeof req.query.since === 'string' ? req.query.since : null
  const until = typeof req.query.until === 'string' ? req.query.until : null

  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    let q = client
      .from('vs_audit_log')
      .select(
        'id, created_at, event_type, user_id, session_id, ip_hash, user_agent, path, scanned_url, scan_outcome, vibe_score, waf_vendor, metadata',
      )
      .order('created_at', { ascending: false })
      .limit(limit)

    if (eventType) q = q.eq('event_type', eventType)
    if (scanOutcome) q = q.eq('scan_outcome', scanOutcome)
    if (wafVendor) q = q.eq('waf_vendor', wafVendor)
    if (scannedDomain) q = q.ilike('scanned_url', `%${scannedDomain}%`)
    if (since) q = q.gte('created_at', since)
    if (until) q = q.lte('created_at', until)

    const { data, error } = await q
    if (error) {
      return res.status(500).json({ ok: false, error: error.message })
    }
    return res.status(200).json({ ok: true, count: data?.length ?? 0, logs: data ?? [] })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown'
    return res.status(500).json({ ok: false, error: msg })
  }
}
