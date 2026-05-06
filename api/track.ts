import type { VercelRequest, VercelResponse } from '@vercel/node'
import { logAuditEvent } from './_lib/audit-log.js'
import type { AuditEventType } from './_lib/audit-log.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 5,
}

const ALLOWED: ReadonlySet<AuditEventType> = new Set([
  'page_visit',
  'terms_viewed',
  'privacy_viewed',
  'badge_requested',
])

interface TrackBody {
  event_type?: string
  path?: string
  session_id?: string
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as TrackBody
  const ev = (body.event_type ?? '').trim()
  if (!ALLOWED.has(ev as AuditEventType)) {
    return res.status(400).json({ ok: false, error: 'invalid_event' })
  }

  const path = typeof body.path === 'string' ? body.path.slice(0, 400) : null
  const sessionId =
    typeof body.session_id === 'string' && /^[a-z0-9-]{8,64}$/i.test(body.session_id)
      ? body.session_id
      : null

  await logAuditEvent(req, {
    event_type: ev as AuditEventType,
    path,
    session_id: sessionId,
  })

  return res.status(204).end()
}
