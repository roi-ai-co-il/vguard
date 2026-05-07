import type { VercelRequest, VercelResponse } from '@vercel/node'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface RateBucket {
  count: number
  resetAt: number
}
const RATE_WINDOW_MS = 60_000
const RATE_MAX = 5
const buckets = new Map<string, RateBucket>()

function clientIp(req: VercelRequest): string {
  const xff = req.headers['x-forwarded-for']
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim()
  if (Array.isArray(xff) && xff.length > 0) return xff[0].split(',')[0].trim()
  const real = req.headers['x-real-ip']
  if (typeof real === 'string') return real
  return 'unknown'
}

function rateLimited(ip: string): boolean {
  const now = Date.now()
  const b = buckets.get(ip)
  if (!b || b.resetAt < now) {
    buckets.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS })
    return false
  }
  b.count += 1
  return b.count > RATE_MAX
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY
  if (!secret) return true
  if (!token) return false
  const body = new URLSearchParams({ secret, response: token })
  if (ip && ip !== 'unknown') body.set('remoteip', ip)
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    const j = (await r.json()) as { success?: boolean }
    return j.success === true
  } catch {
    return false
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'method_not_allowed' })
  }

  const ip = clientIp(req)
  if (rateLimited(`contact:${ip}`)) {
    return res.status(429).json({ ok: false, error: 'rate_limited' })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as {
    name?: unknown
    email?: unknown
    message?: unknown
    turnstileToken?: unknown
  }

  const name = typeof body.name === 'string' ? body.name.trim().slice(0, 100) : ''
  const email = typeof body.email === 'string' ? body.email.trim().slice(0, 200) : ''
  const message = typeof body.message === 'string' ? body.message.trim().slice(0, 4000) : ''
  const tsToken = typeof body.turnstileToken === 'string' ? body.turnstileToken : ''

  if (name.length < 2) return res.status(400).json({ ok: false, error: 'name_too_short' })
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'invalid_email' })
  if (message.length < 10) return res.status(400).json({ ok: false, error: 'message_too_short' })

  const tsOk = await verifyTurnstile(tsToken, ip)
  if (!tsOk) return res.status(403).json({ ok: false, error: 'turnstile_failed' })

  const resendToken = process.env.RESEND_TOKEN
  if (!resendToken) {
    return res.status(503).json({ ok: false, error: 'mailer_not_configured' })
  }

  const fromAddress = process.env.CONTACT_FROM ?? 'V-Guards <noreply@roiai.co.il>'
  const toAddress = process.env.CONTACT_TO ?? 'infovguards@gmail.com'

  const subject = `V-Guards contact — ${name}`
  const textBody =
    `New contact form submission on v-guards.com\n\n` +
    `Name:    ${name}\n` +
    `Email:   ${email}\n` +
    `IP:      ${ip}\n` +
    `Time:    ${new Date().toISOString()}\n\n` +
    `Message:\n${message}\n`
  const htmlBody = `
<div style="font-family:system-ui,sans-serif;color:#111;max-width:600px">
  <h2 style="margin:0 0 16px;font-size:18px">New V-Guards contact form submission</h2>
  <table style="border-collapse:collapse;font-size:14px">
    <tr><td style="padding:4px 12px 4px 0;color:#666">Name</td><td><strong>${escapeHtml(name)}</strong></td></tr>
    <tr><td style="padding:4px 12px 4px 0;color:#666">Email</td><td><a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></td></tr>
    <tr><td style="padding:4px 12px 4px 0;color:#666">IP</td><td>${escapeHtml(ip)}</td></tr>
    <tr><td style="padding:4px 12px 4px 0;color:#666">Time</td><td>${new Date().toISOString()}</td></tr>
  </table>
  <hr style="border:none;border-top:1px solid #eee;margin:16px 0">
  <div style="white-space:pre-wrap;font-size:14px;line-height:1.5">${escapeHtml(message)}</div>
</div>`.trim()

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${resendToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [toAddress],
        reply_to: email,
        subject,
        text: textBody,
        html: htmlBody,
      }),
    })
    if (!r.ok) {
      const errText = await r.text()
      return res.status(502).json({ ok: false, error: 'mailer_failed', detail: errText.slice(0, 200) })
    }
    return res.status(200).json({ ok: true })
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'unknown'
    return res.status(500).json({ ok: false, error: 'internal', detail: msg.slice(0, 200) })
  }
}
