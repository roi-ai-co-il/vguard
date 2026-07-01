/**
 * Verification cache backed by Supabase vs_verified_domains.
 * Fail-soft: if env vars aren't set or the DB call fails, callers fall back
 * to per-request verification.
 */
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

let cachedClient: SupabaseClient | null = null
let envChecked = false

function getClient(): SupabaseClient | null {
  if (envChecked) return cachedClient
  envChecked = true
  const url = process.env.SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) return null
  try {
    cachedClient = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
  } catch {
    cachedClient = null
  }
  return cachedClient
}

export interface CachedVerification {
  domain: string
  uuid: string
  method: 'file' | 'dns' | 'oauth'
  verifiedAt: string
  expiresAt: string
  scanCount: number
}

export async function getCachedVerification(
  domain: string,
): Promise<CachedVerification | null> {
  const client = getClient()
  if (!client) return null
  try {
    const { data, error } = await client
      .from('vs_verified_domains')
      .select('domain, uuid, method, verified_at, expires_at, scan_count')
      .eq('domain', domain)
      .maybeSingle()
    if (error || !data) return null
    if (new Date(data.expires_at as string).getTime() < Date.now()) return null
    return {
      domain: data.domain as string,
      uuid: data.uuid as string,
      method: data.method as 'file' | 'dns' | 'oauth',
      verifiedAt: data.verified_at as string,
      expiresAt: data.expires_at as string,
      scanCount: (data.scan_count as number) ?? 0,
    }
  } catch {
    return null
  }
}

export async function recordVerification(
  domain: string,
  uuid: string,
  method: 'file' | 'dns' | 'oauth',
  userAgent?: string | null,
  email?: string | null,
): Promise<void> {
  const client = getClient()
  if (!client) return
  try {
    await client.from('vs_verified_domains').upsert(
      {
        domain,
        uuid,
        method,
        verified_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
        user_agent: userAgent ?? null,
        email: email && email.trim() ? email.trim().slice(0, 200) : null,
        scan_count: 0,
      },
      { onConflict: 'domain' },
    )
  } catch {
    // ignore — fail-soft
  }
}

export async function incrementScanCount(domain: string): Promise<void> {
  const client = getClient()
  if (!client) return
  try {
    // Read-modify-write (race-y under high concurrency, acceptable for MVP)
    const { data } = await client
      .from('vs_verified_domains')
      .select('scan_count')
      .eq('domain', domain)
      .maybeSingle()
    const current = (data?.scan_count as number | undefined) ?? 0
    await client
      .from('vs_verified_domains')
      .update({ scan_count: current + 1 })
      .eq('domain', domain)
  } catch {
    // ignore — fail-soft
  }
}
