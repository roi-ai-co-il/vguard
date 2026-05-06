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
