import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import { runScan } from './_lib/scanner.js'
import { logAuditEvent, fireAndForget } from './_lib/audit-log.js'
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

  fireAndForget(
    logAuditEvent(req, { event_type: 'scan_started', scanned_url: targetUrl }),
  )

  try {
    const result = await runScan(targetUrl)
    if (result.ok) {
      // Vercel injects geo info as `x-vercel-ip-country` (ISO-3166-1 alpha-2).
      const country = (req.headers['x-vercel-ip-country'] as string | undefined) ?? null
      logScan(result, country).catch(() => {
        // ignore
      })
      fireAndForget(
        logAuditEvent(req, {
          event_type: 'scan_completed',
          scanned_url: targetUrl,
          scan_outcome: 'success',
          vibe_score: result.vibeScore,
          metadata: {
            critical: result.totals.critical,
            warn: result.totals.warn,
            info: result.totals.info,
            framework: result.meta.detectedFramework ?? undefined,
            duration_ms: result.durationMs,
          },
        }),
      )
    } else {
      fireAndForget(
        logAuditEvent(req, {
          event_type: 'scan_failed',
          scanned_url: targetUrl,
          scan_outcome: result.error.code,
        }),
      )
    }
    return res.status(200).json(result)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    fireAndForget(
      logAuditEvent(req, {
        event_type: 'scan_failed',
        scanned_url: targetUrl,
        scan_outcome: 'internal_error',
        metadata: { error: msg.slice(0, 200) },
      }),
    )
    return res
      .status(500)
      .json({ ok: false, error: { code: 'internal', message: msg } })
  }
}
