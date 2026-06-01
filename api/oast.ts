import type { VercelRequest, VercelResponse } from '@vercel/node'
import { recordOastHit } from './_lib/oast.js'

export const config = { runtime: 'nodejs', maxDuration: 10 }

/**
 * OAST collaborator receiver. When a scanned target has SSRF and fetches the
 * URL we planted (`/api/oast?t=<token>`), the request lands here and we record
 * the token. The scanner later polls `vs_oast_hits` to confirm the SSRF.
 *
 * Always returns 200 fast (any method) — we want the target's fetch to succeed
 * so the hit is recorded; the response body is irrelevant.
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')
  const token = typeof req.query.t === 'string' ? req.query.t : ''
  if (token) {
    const fwd = req.headers['x-forwarded-for']
    const remoteAddr = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(',')[0]?.trim() ?? null
    const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null
    // Fire-and-forget so the response is instant; await briefly so the serverless
    // function isn't frozen before the insert completes.
    await recordOastHit(token, { remoteAddr, userAgent: ua }).catch(() => {})
  }
  res.status(200).json({ ok: true })
}
