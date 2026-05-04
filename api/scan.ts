import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import { runScan } from './_lib/scanner.js'
import type { Finding, ScanResult } from '../src/lib/scanner-types.js'

async function logScan(
  result: ScanResult,
  country: string | null,
): Promise<void> {
  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) return
  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const top = pickTopFinding(result.findings)
    const hostname = (() => {
      try {
        return new URL(result.meta.finalUrl).hostname
      } catch {
        return ''
      }
    })()
    if (!hostname) return
    await client.from('vs_scan_log').insert({
      hostname,
      vibe_score: result.vibeScore,
      top_finding_id: top?.id ?? null,
      top_finding_severity: top?.severity ?? null,
      top_finding_title: top?.title?.slice(0, 200) ?? null,
      country: country?.slice(0, 4) ?? null,
    })
  } catch {
    // ignore — fail-soft
  }
}

function pickTopFinding(findings: Finding[]): Finding | null {
  const order = { critical: 0, warn: 1, info: 2, ok: 3 } as const
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity])
  const first = sorted.find((f) => f.severity !== 'ok')
  return first ?? null
}

export const config = {
  runtime: 'nodejs',
  maxDuration: 30,
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method === 'GET') {
    const url = typeof req.query.url === 'string' ? req.query.url : ''
    if (!url) {
      return res
        .status(400)
        .json({ ok: false, error: { code: 'invalid_url', message: 'Missing ?url parameter.' } })
    }
    const result = await runScan(url)
    return res.status(200).json(result)
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST')
    return res.status(405).json({ ok: false, error: { code: 'internal', message: 'Method not allowed.' } })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as { url?: string }
  const targetUrl = typeof body.url === 'string' ? body.url : ''
  if (!targetUrl) {
    return res
      .status(400)
      .json({ ok: false, error: { code: 'invalid_url', message: 'Missing "url" in request body.' } })
  }

  try {
    const result = await runScan(targetUrl)
    if (result.ok) {
      // Vercel injects geo info as `x-vercel-ip-country` (ISO-3166-1 alpha-2).
      const country = (req.headers['x-vercel-ip-country'] as string | undefined) ?? null
      logScan(result, country).catch(() => {
        // ignore
      })
    }
    return res.status(200).json(result)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res
      .status(500)
      .json({ ok: false, error: { code: 'internal', message: msg } })
  }
}
