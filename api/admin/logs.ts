import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import { authorizeAdmin, adminSupabaseEnv } from '../_lib/admin-auth.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Hide the route's existence from non-admins / wrong methods.
  if (req.method !== 'GET') {
    res.setHeader('Cache-Control', 'no-store')
    return res.status(404).json({ ok: false, error: 'not_found' })
  }

  const gate = await authorizeAdmin(req, res)
  if (!gate.ok) {
    if (gate.code === 429) return res.status(429).json({ ok: false, error: 'rate_limited' })
    return res.status(404).json({ ok: false, error: 'not_found' })
  }

  const env = adminSupabaseEnv()
  if (!env) {
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
    const client = createClient(env.url, env.key, {
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
