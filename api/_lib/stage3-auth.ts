/**
 * Stage 3 ownership authorization — the security core.
 *
 * The old model was exploitable: the DNS/file token was PUBLIC and CLIENT-chosen,
 * so anyone could read a verified domain's token and re-use it under their own
 * email. This module fixes that by separating two concerns:
 *
 *   1. Domain Proof (challenge): the SERVER issues a token bound to (domain,email).
 *      Verification passes only if the domain publicly exposes THAT token — the
 *      one the server created for THAT email. A different email gets a different
 *      token, so reading someone else's public token is useless.
 *
 *   2. Stage 3 Authorization: on success we mint a PRIVATE auth token (never in
 *      DNS, never public) and store only its hash. Stage 3 runs only when the
 *      caller presents an auth token that maps to an ACTIVE authorization for the
 *      exact domain. The server decides — client state is never trusted.
 *
 * Backed by Supabase (`vs_verification_challenges`, `vs_domain_authorizations`).
 * When no Supabase env is present (local dev / unit tests) it falls back to an
 * in-memory store — but ONLY outside production, so prod can never silently
 * fail-open to ephemeral memory.
 */
import crypto from 'node:crypto'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

export type VerifyMethod = 'dns' | 'file' | 'oauth'

const CHALLENGE_TTL_MS = 7 * 24 * 3600 * 1000

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

// ── pure helpers (unit-testable) ────────────────────────────────────────────
export function normalizeDomain(d: string): string {
  return (d ?? '').trim().toLowerCase().replace(/^www\./, '')
}
export function normalizeEmail(e: string): string {
  return (e ?? '').trim().toLowerCase()
}
export function sha256(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex')
}
export function genToken(prefix: string, bytes = 18): string {
  return `${prefix}-${crypto.randomBytes(bytes).toString('hex')}`
}
/** Does any public record value carry exactly the server-issued token? */
export function tokenPresentIn(token: string, foundValues: string[]): boolean {
  if (!token) return false
  return foundValues.some((v) => {
    const t = (v ?? '').trim()
    return t === token || t.includes(token)
  })
}

// ── in-memory fallback (non-prod / tests only) ──────────────────────────────
interface ChallengeRow {
  domain: string
  email: string
  token: string
  token_hash: string
  method: string
  status: 'pending' | 'verified' | 'revoked'
  created_at: string
  expires_at: string
  verified_at: string | null
}
interface AuthzRow {
  domain: string
  email: string
  method: string
  auth_token_hash: string
  verified_at: string
  revoked_at: string | null
}
const memChallenges = new Map<string, ChallengeRow>()
const memAuthz = new Map<string, AuthzRow>()
const memAllowed = () => process.env.NODE_ENV !== 'production'
const key2 = (d: string, e: string) => `${d}|${e}`

/** Test-only: wipe the in-memory store between cases. */
export function __resetMemoryForTests(): void {
  memChallenges.clear()
  memAuthz.clear()
}

// ── challenges ──────────────────────────────────────────────────────────────

export interface ChallengeInfo {
  token: string
  method: VerifyMethod
  expiresAt: string
}

/**
 * Get the existing pending, non-expired challenge for (domain,email), or create
 * a fresh one. Idempotent so a page refresh doesn't rotate the token out from
 * under a DNS record the user already added. Returns null only on a hard
 * storage failure in production.
 */
export async function createOrGetChallenge(
  domainRaw: string,
  emailRaw: string,
  method: VerifyMethod,
): Promise<ChallengeInfo | null> {
  const domain = normalizeDomain(domainRaw)
  const email = normalizeEmail(emailRaw)
  const nowMs = Date.now()

  const existing = await getPendingChallenge(domain, email)
  if (existing && new Date(existing.expiresAt).getTime() > nowMs) {
    return existing
  }

  const token = genToken('vs')
  const row: ChallengeRow = {
    domain,
    email,
    token,
    token_hash: sha256(token),
    method,
    status: 'pending',
    created_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + CHALLENGE_TTL_MS).toISOString(),
    verified_at: null,
  }

  const client = getClient()
  if (!client) {
    if (!memAllowed()) return null
    memChallenges.set(key2(domain, email), row)
    return { token, method, expiresAt: row.expires_at }
  }
  try {
    await client.from('vs_verification_challenges').upsert(
      {
        domain,
        email,
        token,
        token_hash: row.token_hash,
        method,
        status: 'pending',
        created_at: row.created_at,
        expires_at: row.expires_at,
        verified_at: null,
      },
      { onConflict: 'domain,email' },
    )
    return { token, method, expiresAt: row.expires_at }
  } catch {
    return null
  }
}

export async function getPendingChallenge(
  domainRaw: string,
  emailRaw: string,
): Promise<ChallengeInfo | null> {
  const domain = normalizeDomain(domainRaw)
  const email = normalizeEmail(emailRaw)
  const client = getClient()
  if (!client) {
    if (!memAllowed()) return null
    const row = memChallenges.get(key2(domain, email))
    if (!row || row.status !== 'pending') return null
    return { token: row.token, method: row.method as VerifyMethod, expiresAt: row.expires_at }
  }
  try {
    const { data } = await client
      .from('vs_verification_challenges')
      .select('token, method, status, expires_at')
      .eq('domain', domain)
      .eq('email', email)
      .maybeSingle()
    if (!data || data.status !== 'pending' || !data.token) return null
    return {
      token: data.token as string,
      method: data.method as VerifyMethod,
      expiresAt: data.expires_at as string,
    }
  } catch {
    return null
  }
}

// ── authorization ───────────────────────────────────────────────────────────

/**
 * Called after the domain publicly exposes the challenge token for (domain,email).
 * Marks the challenge verified and issues a PRIVATE auth token, returning its
 * plaintext exactly once (to store on the client + email to the owner). Only the
 * hash is persisted.
 */
export async function markVerifiedAndAuthorize(
  domainRaw: string,
  emailRaw: string,
  method: VerifyMethod,
): Promise<{ authToken: string } | null> {
  const domain = normalizeDomain(domainRaw)
  const email = normalizeEmail(emailRaw)
  const authToken = genToken('vga', 24)
  const authHash = sha256(authToken)
  const now = new Date().toISOString()

  const client = getClient()
  if (!client) {
    if (!memAllowed()) return null
    const ch = memChallenges.get(key2(domain, email))
    if (ch) {
      ch.status = 'verified'
      ch.verified_at = now
    }
    memAuthz.set(key2(domain, email), {
      domain,
      email,
      method,
      auth_token_hash: authHash,
      verified_at: now,
      revoked_at: null,
    })
    return { authToken }
  }
  try {
    await client
      .from('vs_verification_challenges')
      .update({ status: 'verified', verified_at: now })
      .eq('domain', domain)
      .eq('email', email)
    await client.from('vs_domain_authorizations').upsert(
      {
        domain,
        email,
        method,
        auth_token_hash: authHash,
        verified_at: now,
        revoked_at: null,
      },
      { onConflict: 'domain,email' },
    )
    return { authToken }
  } catch {
    return null
  }
}

/**
 * THE Stage 3 gate. Authorized only if the presented private auth token maps to
 * an ACTIVE (non-revoked) authorization whose domain exactly matches. Never
 * trusts a client-claimed email — the email is derived from the stored record.
 */
export async function isAuthorizedForStage3(
  domainRaw: string,
  authToken: string,
): Promise<{ authorized: boolean; email?: string; method?: VerifyMethod }> {
  const domain = normalizeDomain(domainRaw)
  const token = (authToken ?? '').trim()
  if (!token || !/^vga-[a-f0-9]{20,}$/.test(token)) return { authorized: false }
  const hash = sha256(token)

  const client = getClient()
  if (!client) {
    if (!memAllowed()) return { authorized: false }
    for (const row of memAuthz.values()) {
      if (row.auth_token_hash === hash && !row.revoked_at && row.domain === domain) {
        return { authorized: true, email: row.email, method: row.method as VerifyMethod }
      }
    }
    return { authorized: false }
  }
  try {
    const { data } = await client
      .from('vs_domain_authorizations')
      .select('domain, email, method, revoked_at')
      .eq('auth_token_hash', hash)
      .maybeSingle()
    if (!data || data.revoked_at) return { authorized: false }
    if (normalizeDomain(data.domain as string) !== domain) return { authorized: false }
    return { authorized: true, email: data.email as string, method: data.method as VerifyMethod }
  } catch {
    return { authorized: false }
  }
}

export async function revokeAuthorization(domainRaw: string, emailRaw: string): Promise<void> {
  const domain = normalizeDomain(domainRaw)
  const email = normalizeEmail(emailRaw)
  const now = new Date().toISOString()
  const client = getClient()
  if (!client) {
    if (!memAllowed()) return
    const row = memAuthz.get(key2(domain, email))
    if (row) row.revoked_at = now
    return
  }
  try {
    await client
      .from('vs_domain_authorizations')
      .update({ revoked_at: now })
      .eq('domain', domain)
      .eq('email', email)
  } catch {
    // fail-soft
  }
}

export interface AuthorizationRow {
  domain: string
  email: string
  method: string
  verified_at: string
  revoked_at: string | null
}

export async function listAuthorizations(): Promise<AuthorizationRow[]> {
  const client = getClient()
  if (!client) {
    if (!memAllowed()) return []
    return [...memAuthz.values()].map((r) => ({
      domain: r.domain,
      email: r.email,
      method: r.method,
      verified_at: r.verified_at,
      revoked_at: r.revoked_at,
    }))
  }
  try {
    const { data } = await client
      .from('vs_domain_authorizations')
      .select('domain, email, method, verified_at, revoked_at')
      .order('verified_at', { ascending: false })
    return (data as AuthorizationRow[] | null) ?? []
  } catch {
    return []
  }
}
