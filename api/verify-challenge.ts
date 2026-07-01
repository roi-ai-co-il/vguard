import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createOrGetChallenge } from './_lib/stage3-auth.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface Body {
  domain?: string
  email?: string
  method?: 'file' | 'dns'
}

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

/**
 * Issues the SERVER-generated ownership token for (domain, email). The client
 * displays it and the owner adds it to DNS / a file. The token is bound to this
 * exact email — reading another owner's public token is useless. The client
 * never chooses the token.
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Body
  const domain = (body.domain ?? '').trim().toLowerCase()
  const email = (body.email ?? '').trim()
  const method = body.method === 'file' ? 'file' : 'dns'

  if (!domain || !DOMAIN_RE.test(domain)) {
    return res.status(400).json({ ok: false, error: 'Invalid domain.' })
  }
  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ ok: false, error: 'A valid email is required.' })
  }

  const challenge = await createOrGetChallenge(domain, email, method)
  if (!challenge) {
    return res.status(503).json({
      ok: false,
      error: 'Verification storage is unavailable right now. Please try again shortly.',
    })
  }

  return res.status(200).json({
    ok: true,
    token: challenge.token,
    method: challenge.method,
    expiresAt: challenge.expiresAt,
  })
}
