import type { VercelRequest } from '@vercel/node'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { hashIp } from './audit-log.js'

/**
 * Vguard lead capture. Fail-soft insert into `vs_leads` (see migration
 * `0002_vs_leads.sql`). Two sources:
 *   - 'contact' — homepage contact form
 *   - 'verify'  — Stage-3 ownership-verification email (domain-owner intent)
 *
 * Never throws; missing env / DB errors are swallowed so it can never break the
 * business response (the contact email / verify result already went out).
 * Mirrors the fail-soft contract of `audit-log.ts` and `scan-telemetry.ts`.
 */

export type LeadSource = 'contact' | 'verify'

export interface LeadInput {
  source: LeadSource
  email: string
  name?: string | null
  message?: string | null
  domain?: string | null
  method?: string | null
  verified?: boolean | null
  metadata?: Record<string, unknown>
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

function clientIp(req: VercelRequest): string | null {
  const xff = req.headers['x-forwarded-for']
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim()
  if (Array.isArray(xff) && xff.length > 0) return xff[0].split(',')[0].trim()
  const real = req.headers['x-real-ip']
  if (typeof real === 'string' && real.length > 0) return real
  return null
}

export async function recordLead(req: VercelRequest | null, lead: LeadInput): Promise<void> {
  const client = getClient()
  if (!client) return

  const ua = req?.headers['user-agent']
  const ip = req ? clientIp(req) : null

  const row = {
    source: lead.source,
    email: lead.email.slice(0, 200),
    name: lead.name?.slice(0, 120) ?? null,
    message: lead.message?.slice(0, 4000) ?? null,
    domain: lead.domain?.slice(0, 253) ?? null,
    method: lead.method?.slice(0, 20) ?? null,
    verified: typeof lead.verified === 'boolean' ? lead.verified : null,
    ip_hash: hashIp(ip),
    user_agent: typeof ua === 'string' ? ua.slice(0, 400) : null,
    metadata: lead.metadata ?? {},
  }

  try {
    await client.from('vs_leads').insert(row)
  } catch {
    // fail-soft: never break the contact/verify response
  }
}
