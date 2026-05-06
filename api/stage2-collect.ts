import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import { logAuditEvent, fireAndForget } from './_lib/audit-log.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface CollectBody {
  uuid?: string
  url?: string
  cookieKeys?: string[]
  localStorageKeys?: string[]
  sessionStorageKeys?: string[]
  globals?: Record<string, boolean>
  performanceUrls?: string[]
  consoleErrorCount?: number
  userAgent?: string
}

function setCorsHeaders(res: VercelResponse) {
  // Bookmarklet runs on the USER's site origin; we don't know it in advance.
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  res.setHeader('Access-Control-Max-Age', '600')
}

function isValidUuid(s: string): boolean {
  return /^[a-z0-9-]{16,64}$/i.test(s)
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  setCorsHeaders(res)
  res.setHeader('Cache-Control', 'no-store')

  if (req.method === 'OPTIONS') {
    return res.status(204).end()
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as CollectBody
  const uuid = (body.uuid ?? '').trim()
  const url = (body.url ?? '').trim()

  if (!uuid || !isValidUuid(uuid)) {
    return res.status(400).json({ ok: false, error: 'Invalid uuid.' })
  }
  if (!url || url.length > 2048) {
    return res.status(400).json({ ok: false, error: 'Invalid url.' })
  }

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) {
    return res
      .status(503)
      .json({ ok: false, error: 'Stage 2 collection is not configured (missing env).' })
  }

  // Bound the payload — defensive against bookmarklet abuse
  const safeData = {
    cookieKeys: (body.cookieKeys ?? []).slice(0, 50).map((k) => String(k).slice(0, 100)),
    localStorageKeys: (body.localStorageKeys ?? []).slice(0, 50).map((k) => String(k).slice(0, 100)),
    sessionStorageKeys: (body.sessionStorageKeys ?? [])
      .slice(0, 50)
      .map((k) => String(k).slice(0, 100)),
    globals: body.globals && typeof body.globals === 'object' ? body.globals : {},
    performanceUrls: (body.performanceUrls ?? []).slice(0, 100).map((u) => String(u).slice(0, 1024)),
    consoleErrorCount:
      typeof body.consoleErrorCount === 'number' ? body.consoleErrorCount : 0,
  }
  const ua = (body.userAgent ?? req.headers['user-agent'] ?? '').toString().slice(0, 300)

  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    await client.from('vs_stage2_collections').upsert(
      {
        uuid,
        url: url.slice(0, 2048),
        data: safeData,
        collected_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        user_agent: ua,
      },
      { onConflict: 'uuid' },
    )
    fireAndForget(
      logAuditEvent(req, {
        event_type: 'stage2_completed',
        scanned_url: url.slice(0, 1000),
        session_id: uuid,
        metadata: {
          cookie_count: safeData.cookieKeys.length,
          local_storage_count: safeData.localStorageKeys.length,
          session_storage_count: safeData.sessionStorageKeys.length,
          performance_url_count: safeData.performanceUrls.length,
        },
      }),
    )
    return res.status(200).json({ ok: true })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: msg })
  }
}
