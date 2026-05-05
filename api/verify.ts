import type { VercelRequest, VercelResponse } from '@vercel/node'
import { promises as dns } from 'node:dns'
import { recordVerification } from './_lib/verification-store.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 15,
}

interface VerifyBody {
  domain?: string
  uuid?: string
  method?: 'file' | 'dns'
}

interface VerifyResponse {
  ok: boolean
  verified?: boolean
  method?: 'file' | 'dns'
  error?: string
  hint?: string
}

async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController()
  const t = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { signal: controller.signal, redirect: 'follow' })
  } finally {
    clearTimeout(t)
  }
}

async function verifyFileChallenge(domain: string, uuid: string): Promise<VerifyResponse> {
  const challengeUrl = `https://${domain}/.well-known/Vguard-verify.txt`
  try {
    const r = await fetchWithTimeout(challengeUrl, 5000)
    if (!r.ok) {
      return {
        ok: true,
        verified: false,
        method: 'file',
        hint: `GET ${challengeUrl} returned ${r.status}. Upload the file with the UUID as its content, then click verify again.`,
      }
    }
    const body = (await r.text()).trim()
    if (body === uuid || body.includes(uuid)) {
      return { ok: true, verified: true, method: 'file' }
    }
    return {
      ok: true,
      verified: false,
      method: 'file',
      hint: `File found but content does not match. Expected UUID, got first 80 chars: "${body.slice(0, 80)}"`,
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return {
      ok: true,
      verified: false,
      method: 'file',
      hint: `Could not fetch ${challengeUrl}: ${msg}`,
    }
  }
}

async function verifyDnsChallenge(domain: string, uuid: string): Promise<VerifyResponse> {
  const txtHost = `_Vguard-verify.${domain}`
  try {
    const records = await dns.resolveTxt(txtHost).catch(() => [] as string[][])
    const flat = records.map((parts) => parts.join(''))
    if (flat.some((rec) => rec.includes(uuid))) {
      return { ok: true, verified: true, method: 'dns' }
    }
    return {
      ok: true,
      verified: false,
      method: 'dns',
      hint: `No matching TXT record at ${txtHost}. Add: ${txtHost} TXT "${uuid}" (DNS may take a few minutes to propagate).`,
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return {
      ok: true,
      verified: false,
      method: 'dns',
      hint: `DNS lookup failed: ${msg}`,
    }
  }
}

function isValidDomain(s: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(s)
}

function isValidUuid(s: string): boolean {
  return /^[a-z0-9-]{16,64}$/i.test(s)
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' } satisfies VerifyResponse)
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as VerifyBody
  const domain = (body.domain ?? '').trim().toLowerCase()
  const uuid = (body.uuid ?? '').trim()
  const method = body.method ?? 'file'

  if (!domain || !isValidDomain(domain)) {
    return res
      .status(400)
      .json({ ok: false, error: 'Invalid domain.' } satisfies VerifyResponse)
  }
  if (!uuid || !isValidUuid(uuid)) {
    return res
      .status(400)
      .json({ ok: false, error: 'Invalid UUID.' } satisfies VerifyResponse)
  }
  if (method !== 'file' && method !== 'dns') {
    return res
      .status(400)
      .json({ ok: false, error: 'Method must be "file" or "dns".' } satisfies VerifyResponse)
  }

  try {
    const result =
      method === 'file' ? await verifyFileChallenge(domain, uuid) : await verifyDnsChallenge(domain, uuid)
    if (result.verified) {
      const ua = (req.headers['user-agent'] as string | undefined) ?? null
      // Fire-and-forget; we don't gate the response on the cache write
      recordVerification(domain, uuid, method, ua).catch(() => {
        // ignore
      })
    }
    return res.status(200).json(result)
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: msg } satisfies VerifyResponse)
  }
}
