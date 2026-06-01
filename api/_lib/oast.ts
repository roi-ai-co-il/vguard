/**
 * OAST (Out-of-band Application Security Testing) collaborator — confirms SSRF.
 *
 * The scanner sends a benign URL pointing at our own `/api/oast` endpoint as the
 * value of URL-shaped parameters. If the TARGET server fetches it server-side
 * (the definition of SSRF), our endpoint records the hit, and the scanner — by
 * polling `vs_oast_hits` — gets a CONFIRMED, reproducible SSRF finding rather
 * than a static "this looks like an SSRF surface" guess.
 *
 * HTTP-OAST (not DNS): catches SSRF where the server makes an HTTP request to a
 * full URL we control (the common reflected/immediate case). Fail-soft: with no
 * Supabase creds the helpers no-op, so SSRF simply isn't confirmed — never an error.
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

export function oastEnabled(): boolean {
  return !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
}

/** Random URL-safe token. crypto.randomUUID is available in the Vercel Node runtime. */
export function makeOastToken(): string {
  try {
    return 'vs' + crypto.randomUUID().replace(/-/g, '')
  } catch {
    return 'vs' + Math.random().toString(36).slice(2) + Date.now().toString(36)
  }
}

function oastOrigin(): string {
  return process.env.VGUARD_PUBLIC_ORIGIN || 'https://v-guards.com'
}

/** The collaborator URL the scanner plants in URL-shaped params. */
export function oastUrl(token: string): string {
  return `${oastOrigin()}/api/oast?t=${token}`
}

/** Record a hit (called by the /api/oast receiver). Fail-soft. */
export async function recordOastHit(
  token: string,
  meta: { remoteAddr?: string | null; userAgent?: string | null },
): Promise<void> {
  const client = getClient()
  if (!client || !/^vs[a-z0-9]{8,}$/i.test(token)) return
  try {
    await client.from('vs_oast_hits').insert({
      token,
      hit_at: new Date().toISOString(),
      remote_addr: meta.remoteAddr ?? null,
      user_agent: meta.userAgent ?? null,
    })
  } catch {
    // ignore — fail-soft
  }
}

/**
 * Return the subset of `tokens` that were hit (i.e. the target fetched our URL).
 * Called once near the end of a scan, after the SSRF payloads have had time to
 * trigger. Fail-soft → empty set on any error (no false SSRF confirmations).
 */
export async function checkOastHits(tokens: string[]): Promise<Set<string>> {
  const hit = new Set<string>()
  const client = getClient()
  if (!client || tokens.length === 0) return hit
  try {
    const { data } = await client
      .from('vs_oast_hits')
      .select('token')
      .in('token', tokens)
    for (const row of data ?? []) hit.add((row as { token: string }).token)
  } catch {
    // ignore
  }
  return hit
}
