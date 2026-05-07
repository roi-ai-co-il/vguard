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
  /**
   * When DNS verification fails but a Vguard-shaped UUID (vs-...) IS present
   * in the TXT record, surface it so the UI can offer "use this code" — i.e.
   * adopt the existing record into the client's persisted UUID instead of
   * forcing the user to update DNS again. Solves the common "I added the
   * record but Vguard rotated its UUID before I clicked verify" race.
   */
  foundDnsUuid?: string
}

const VGUARD_UUID_RE = /vs-[A-Za-z0-9-]{16,64}/

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
    // Look for any Vguard-shaped UUID in the existing TXT records. If one is
    // present, the user has a stale (or freshly-added but pre-rotation) code
    // at the registrar — much faster recovery to adopt it than push a new DNS
    // update through propagation again.
    let foundDnsUuid: string | undefined
    for (const rec of flat) {
      const m = rec.match(VGUARD_UUID_RE)
      if (m && m[0] !== uuid) {
        foundDnsUuid = m[0]
        break
      }
    }
    return {
      ok: true,
      verified: false,
      method: 'dns',
      hint: foundDnsUuid
        ? `DNS at ${txtHost} has a Vguard verification code (${foundDnsUuid}) — but it doesn't match the current code on this page (${uuid}). Click "Use this DNS code" below to adopt the existing record (instant) — or update the DNS record value to "${uuid}" and wait for propagation.`
        : `No matching TXT record at ${txtHost}. Add: ${txtHost} TXT "${uuid}" (DNS may take a few minutes to propagate).`,
      foundDnsUuid,
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
      // Await the cache write so the immediately-following /api/scan-deep
      // call sees the cached entry and doesn't fall back to a live re-verify
      // (Vercel's runtime DNS resolver can be ~30s behind a fresh TXT update,
      // creating a flaky "verified then ownership-failed" UX). Fail-soft on
      // the write itself — verification still passes for this response.
      try {
        await recordVerification(domain, uuid, method, ua)
      } catch {
        // ignore — DB write is best-effort, deep scan can re-verify live
      }
    }
    return res.status(200).json(result)
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: msg } satisfies VerifyResponse)
  }
}
