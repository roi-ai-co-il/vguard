import type { VercelRequest, VercelResponse } from '@vercel/node'
import { promises as dns } from 'node:dns'
import {
  getPendingChallenge,
  markVerifiedAndAuthorize,
  tokenPresentIn,
} from './_lib/stage3-auth.js'
import {
  sendVerificationConfirmation,
  sendVerificationFailure,
} from './_lib/verify-email.js'
import { recordLead } from './_lib/leads-store.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 15,
}

interface VerifyBody {
  domain?: string
  email?: string
  method?: 'file' | 'dns'
}

interface VerifyResponse {
  ok: boolean
  verified?: boolean
  method?: 'file' | 'dns'
  /** Private per-owner access token — returned once on success, stored by the
   *  client + emailed. Used to authorize Stage 3 (never the public DNS token). */
  authToken?: string
  error?: string
  hint?: string
}

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController()
  const t = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { signal: controller.signal, redirect: 'follow' })
  } finally {
    clearTimeout(t)
  }
}

/** Read the public values the domain currently exposes for this method. */
async function readDomainValues(domain: string, method: 'file' | 'dns'): Promise<string[]> {
  if (method === 'file') {
    try {
      const r = await fetchWithTimeout(`https://${domain}/.well-known/Vguard-verify.txt`, 5000)
      if (!r.ok) return []
      return [(await r.text()).trim()]
    } catch {
      return []
    }
  }
  try {
    const records = await dns.resolveTxt(`_Vguard-verify.${domain}`).catch(() => [] as string[][])
    return records.map((parts) => parts.join(''))
  } catch {
    return []
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' } satisfies VerifyResponse)
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as VerifyBody
  const domain = (body.domain ?? '').trim().toLowerCase()
  const email = (body.email ?? '').trim()
  const method = body.method === 'file' ? 'file' : 'dns'

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({
      ok: false,
      error: 'A valid email is required so we can bind ownership to you and email the result.',
    } satisfies VerifyResponse)
  }
  if (!domain || !DOMAIN_RE.test(domain)) {
    return res.status(400).json({ ok: false, error: 'Invalid domain.' } satisfies VerifyResponse)
  }

  // The token is whatever the SERVER issued for THIS (domain,email). If there's
  // no pending challenge, the client must request one first — we never accept a
  // client-supplied code.
  const challenge = await getPendingChallenge(domain, email)
  if (!challenge) {
    return res.status(409).json({
      ok: false,
      error: 'No active verification for this email. Request a fresh code and try again.',
    } satisfies VerifyResponse)
  }

  // Dev-only bypass: localhost can't host a real DNS record / file, so skip the
  // network read locally — but STILL require a server-issued challenge to exist
  // for this exact (domain,email), so the email-binding logic is exercised. Can
  // never fire in production (Vercel sets NODE_ENV=production).
  let present: boolean
  if (process.env.NODE_ENV !== 'production') {
    present = true
  } else {
    const values = await readDomainValues(domain, method)
    present = tokenPresentIn(challenge.token, values)
  }

  // Capture the attempt as a lead (hottest intent). Fail-soft; never blocks.
  await recordLead(req, { source: 'verify', email, domain, method, verified: present }).catch(
    () => {},
  )

  if (!present) {
    const hint =
      method === 'dns'
        ? `No matching TXT record at _Vguard-verify.${domain}. Add a TXT record with the exact code shown on the page (DNS can take a few minutes to propagate), then verify again.`
        : `The file at https://${domain}/.well-known/Vguard-verify.txt didn't contain the exact code shown on the page. Upload it and verify again.`
    try {
      await sendVerificationFailure(email, domain, method, challenge.token, hint)
    } catch {
      // ignore
    }
    return res.status(200).json({ ok: true, verified: false, method, hint } satisfies VerifyResponse)
  }

  const authz = await markVerifiedAndAuthorize(domain, email, method)
  if (!authz) {
    return res.status(503).json({
      ok: false,
      error: 'Verified, but authorization storage is unavailable. Please try again shortly.',
    } satisfies VerifyResponse)
  }

  try {
    await sendVerificationConfirmation(email, domain, method, authz.authToken)
  } catch {
    // Email failure shouldn't fail the verify response.
  }

  return res
    .status(200)
    .json({ ok: true, verified: true, method, authToken: authz.authToken } satisfies VerifyResponse)
}
