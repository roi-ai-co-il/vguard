import type { VercelRequest, VercelResponse } from '@vercel/node'
import { runScan } from './_lib/scanner.js'
import { logAuditEvent, fireAndForget } from './_lib/audit-log.js'
import { logScanOutcome } from './_lib/scan-telemetry.js'

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
    const country = (req.headers['x-vercel-ip-country'] as string | undefined) ?? null
    logScanOutcome(result, url, country).catch(() => {})
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
    const country = (req.headers['x-vercel-ip-country'] as string | undefined) ?? null
    logScanOutcome(result, targetUrl, country).catch(() => {})
    if (result.ok) {
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
