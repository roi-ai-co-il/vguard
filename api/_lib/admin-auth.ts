import crypto from 'node:crypto'
import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'

/**
 * Shared admin authorization for the V-Guards admin endpoints
 * (`/api/admin/logs`, `/api/admin/dashboard`). Extracted so both routes enforce
 * the exact same gate and can't drift.
 *
 * Three layers, in order:
 *   1. Per-IP rate limit (in-memory, best-effort across warm lambdas).
 *   2. `ADMIN_SECRET` constant-time check (the `x-admin-secret` header or
 *      `?secret=` query). Failure → 404, so the route's existence stays hidden.
 *   3. Cloudflare Turnstile, UNLESS a still-valid HMAC-signed session cookie is
 *      present. A fresh Turnstile pass mints a 15-minute session cookie signed
 *      with ADMIN_SECRET, so it can't be forged.
 *
 * `authorizeAdmin` sets `Cache-Control: no-store` (+ the session cookie on a
 * fresh login) on the response and returns a verdict. The caller sends the
 * final body so it can tailor 404/429 copy and pick GET/POST handling.
 */

interface RateLimitBucket {
  count: number
  resetAt: number
}
const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX = 30
const buckets = new Map<string, RateLimitBucket>()

// 7 days — the admin is a 2-person internal tool; a long session means Royi/Oded
// pass Turnstile once a week, not every visit. The cookie is HMAC-signed with
// ADMIN_SECRET (can't be forged) and HttpOnly/Secure/SameSite=Strict.
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000
const SESSION_COOKIE = 'vg_admin_session'

export function clientIp(req: VercelRequest): string {
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

function checkSecret(req: VercelRequest): boolean {
  const adminSecret = process.env.ADMIN_SECRET
  if (!adminSecret) return false // not configured → refuse rather than leak
  const provided =
    (req.headers['x-admin-secret'] as string | undefined) ??
    (typeof req.query.secret === 'string' ? req.query.secret : '')
  if (!provided) return false
  return constantTimeEqual(provided, adminSecret)
}

/**
 * Per-user login: verify `username` + `password` against the `vs_admin_users`
 * table (scrypt-hashed). Lets Royi + Oded each have their own credential while
 * `ADMIN_SECRET` stays as a master key. Fail-closed on any error.
 */
async function verifyUserPassword(username: string, password: string): Promise<boolean> {
  if (!username || !password) return false
  const env = adminSupabaseEnv()
  if (!env) return false
  try {
    const client = createClient(env.url, env.key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const { data, error } = await client
      .from('vs_admin_users')
      .select('password_hash')
      .eq('username', username.toLowerCase())
      .maybeSingle()
    if (error || !data?.password_hash) return false
    const [scheme, salt, expected] = String(data.password_hash).split('$')
    if (scheme !== 'scrypt' || !salt || !expected) return false
    const derived = crypto.scryptSync(password, salt, 32).toString('hex')
    if (derived.length !== expected.length) return false
    const ok = crypto.timingSafeEqual(Buffer.from(derived), Buffer.from(expected))
    if (ok) {
      void client
        .from('vs_admin_users')
        .update({ last_login_at: new Date().toISOString() })
        .eq('username', username.toLowerCase())
        .then(() => {})
    }
    return ok
  } catch {
    return false
  }
}

export type AdminAuthVerdict =
  | { ok: true }
  | { ok: false; code: 404 | 429 }

/**
 * Run the full admin gate. Sets response headers (Cache-Control + Set-Cookie on
 * a fresh session). Returns a verdict; the caller sends the body.
 */
export async function authorizeAdmin(
  req: VercelRequest,
  res: VercelResponse,
): Promise<AdminAuthVerdict> {
  res.setHeader('Cache-Control', 'no-store')

  if (rateLimited(`admin:${clientIp(req)}`)) {
    return { ok: false, code: 429 }
  }

  // Auth: a username present → per-user login (vs_admin_users, password sent in
  // the x-admin-secret header); otherwise the master ADMIN_SECRET.
  const adminUser = (req.headers['x-admin-user'] as string | undefined)?.trim()
  let credOk: boolean
  if (adminUser) {
    const password =
      (req.headers['x-admin-secret'] as string | undefined) ??
      (typeof req.query.secret === 'string' ? req.query.secret : '')
    credOk = await verifyUserPassword(adminUser, password ?? '')
  } else {
    credOk = checkSecret(req)
  }
  if (!credOk) {
    return { ok: false, code: 404 }
  }

  const adminSecret = process.env.ADMIN_SECRET as string
  const sessionCookie = readCookie(req, SESSION_COOKIE)
  if (!verifySession(sessionCookie, adminSecret)) {
    const tsToken = (req.headers['x-turnstile-token'] as string | undefined) ?? ''
    const tsOk = await verifyTurnstile(tsToken, clientIp(req))
    if (!tsOk) {
      return { ok: false, code: 404 }
    }
    const expiresAt = Date.now() + SESSION_TTL_MS
    const cookie = signSession(expiresAt, adminSecret)
    res.setHeader(
      'Set-Cookie',
      `${SESSION_COOKIE}=${cookie}; Path=/api/admin; Max-Age=${SESSION_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Strict`,
    )
  }

  return { ok: true }
}

/** Service-role Supabase env, validated once. Returns null if unconfigured. */
export function adminSupabaseEnv(): { url: string; key: string } | null {
  const url = process.env.SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) return null
  return { url, key }
}
