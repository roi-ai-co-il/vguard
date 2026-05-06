import crypto from 'node:crypto'
import type { VercelRequest } from '@vercel/node'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

export type AuditEventType =
  | 'page_visit'
  | 'scan_started'
  | 'scan_completed'
  | 'scan_failed'
  | 'stage2_started'
  | 'stage2_completed'
  | 'badge_requested'
  | 'terms_viewed'
  | 'privacy_viewed'

export interface AuditEvent {
  event_type: AuditEventType
  user_id?: string | null
  session_id?: string | null
  path?: string | null
  scanned_url?: string | null
  scan_outcome?: string | null
  vibe_score?: number | null
  waf_vendor?: string | null
  metadata?: Record<string, unknown>
}

const SAFE_METADATA_KEY = /^[a-z0-9_-]{1,40}$/i
const FORBIDDEN_KEY = /cookie|authorization|auth[-_]?token|password|secret|bearer|set-cookie|api[-_]?key|x-admin-secret/i
const FORBIDDEN_VALUE_PATTERN = /(?:eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)|(?:sk-[A-Za-z0-9_-]{12,})|(?:sbp_[A-Za-z0-9_]+)|(?:bearer\s+\S+)/i

export function sanitizeMetadata(input: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!input || typeof input !== 'object') return {}
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(input)) {
    if (!SAFE_METADATA_KEY.test(k)) continue
    if (FORBIDDEN_KEY.test(k)) continue
    if (typeof v === 'string') {
      if (FORBIDDEN_VALUE_PATTERN.test(v)) continue
      out[k] = v.length > 500 ? v.slice(0, 500) : v
    } else if (typeof v === 'number' || typeof v === 'boolean' || v === null) {
      out[k] = v
    } else if (Array.isArray(v)) {
      out[k] = v.slice(0, 50).filter((x) => typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean')
    } else {
      // Drop nested objects to keep the row safe-by-default.
      continue
    }
  }
  return out
}

function clientIp(req: VercelRequest): string | null {
  const xff = req.headers['x-forwarded-for']
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim()
  if (Array.isArray(xff) && xff.length > 0) return xff[0].split(',')[0].trim()
  const real = req.headers['x-real-ip']
  if (typeof real === 'string' && real.length > 0) return real
  return null
}

export function hashIp(ip: string | null): string | null {
  if (!ip) return null
  const salt = process.env.AUDIT_IP_SALT ?? ''
  if (!salt) return null
  return crypto.createHash('sha256').update(`${salt}:${ip}`).digest('hex')
}

let _client: SupabaseClient | null = null
function getClient(): SupabaseClient | null {
  if (_client) return _client
  const url = process.env.SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) return null
  _client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  })
  return _client
}

export async function logAuditEvent(req: VercelRequest | null, event: AuditEvent): Promise<void> {
  const client = getClient()
  if (!client) return

  const ua = req?.headers['user-agent']
  const ip = req ? clientIp(req) : null
  const reqPath = req?.url ? req.url.split('?')[0] : null

  const row = {
    event_type: event.event_type,
    user_id: event.user_id ?? null,
    session_id: event.session_id?.slice(0, 64) ?? null,
    ip_hash: hashIp(ip),
    user_agent: typeof ua === 'string' ? ua.slice(0, 400) : null,
    path: (event.path ?? reqPath)?.slice(0, 400) ?? null,
    scanned_url: event.scanned_url?.slice(0, 1000) ?? null,
    scan_outcome: event.scan_outcome?.slice(0, 60) ?? null,
    vibe_score: typeof event.vibe_score === 'number' ? Math.round(event.vibe_score) : null,
    waf_vendor: event.waf_vendor?.slice(0, 60) ?? null,
    metadata: sanitizeMetadata(event.metadata),
  }

  try {
    await client.from('vs_audit_log').insert(row)
  } catch {
    // fail-soft: never break business logic
  }
}

export function fireAndForget(p: Promise<unknown>): void {
  p.catch(() => {
    /* swallow */
  })
}
