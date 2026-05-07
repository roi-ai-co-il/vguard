import type { VercelRequest, VercelResponse } from '@vercel/node'
import { runScan } from './_lib/scanner.js'
import { logScanOutcome } from './_lib/scan-telemetry.js'

/**
 * POST /api/scan-stream  { url: "https://example.com" }
 *
 * NDJSON-streamed variant of /api/scan. Emits one JSON event per line as the
 * scan progresses, then a final `result` event with the full ScanResponse.
 * The frontend uses `fetch` + `response.body.getReader()` to consume; each
 * chunk is parsed and used to drive the live progress UI.
 *
 * Why NDJSON over EventSource (SSE):
 *  - EventSource is GET-only; passing arbitrary URLs as query params is fine
 *    but POST keeps the URL out of HTTP access logs / browser history.
 *  - NDJSON over a chunked POST works in any modern browser without polyfill.
 *
 * Why this exists alongside /api/scan:
 *  - /api/scan stays for `curl` users, MCP servers, and CI integrations that
 *    just want the JSON object. /api/scan-stream is for the interactive UI.
 *
 * Phase pacing: the scanner doesn't expose per-phase callbacks today, so the
 * stream emits a deterministic timeline of phases at 600ms intervals while
 * the real scan runs in parallel. When the scan resolves, any remaining
 * phases are flushed instantly and the `result` event is sent. This keeps
 * the UI honest: phases never lag behind the actual answer.
 */

export const config = {
  maxDuration: 30,
}

interface PhaseEvent {
  type: 'phase'
  step: number
  total: number
  name: string
  label: string
}

const PHASES: { name: string; label: string }[] = [
  { name: 'connect', label: 'Resolving DNS + TLS handshake' },
  { name: 'homepage', label: 'Fetching homepage HTML' },
  { name: 'headers', label: 'Auditing 9 hardening headers' },
  { name: 'bundles', label: 'Scanning JS bundles for secrets + AST sinks' },
  { name: 'paths', label: 'Probing 33 admin / dotfile paths' },
  { name: 'dns', label: 'DMARC / SPF / CAA / DNSSEC lookups' },
  { name: 'analyze', label: 'Running detectors + risk scoring' },
]

const PHASE_INTERVAL_MS = 600

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Use POST with { url }' })
    return
  }
  const url = (req.body?.url ?? '').toString()
  if (!url) {
    res.status(400).json({ error: 'Missing url' })
    return
  }

  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  const send = (event: unknown): void => {
    res.write(JSON.stringify(event) + '\n')
    // Force flush so each line lands on the wire immediately, not at end-of-handler.
    ;(res as unknown as { flush?: () => void }).flush?.()
  }

  // Kick off the actual scan in parallel with the phase timeline.
  let scanDone = false
  const scanPromise = runScan(url).finally(() => {
    scanDone = true
  })

  // Emit phase 0 immediately so the UI never sees blank dead air.
  send({
    type: 'phase',
    step: 1,
    total: PHASES.length,
    name: PHASES[0].name,
    label: PHASES[0].label,
  } satisfies PhaseEvent)

  for (let i = 1; i < PHASES.length; i++) {
    if (scanDone) break
    await new Promise<void>((r) => setTimeout(r, PHASE_INTERVAL_MS))
    if (scanDone) break
    send({
      type: 'phase',
      step: i + 1,
      total: PHASES.length,
      name: PHASES[i].name,
      label: PHASES[i].label,
    } satisfies PhaseEvent)
  }

  // Wait for the real scan to finish (if it hasn't already).
  const result = await scanPromise

  // Fire-and-forget telemetry. Same `vs_scan_log` row shape whether the scan
  // succeeded or got blocked — we want to count both for the WAF dashboard.
  const country = (req.headers['x-vercel-ip-country'] as string | undefined) ?? null
  logScanOutcome(result, url, country).catch(() => {})

  // Emit the final phase + result so the UI can clamp progress to 100%.
  send({
    type: 'phase',
    step: PHASES.length,
    total: PHASES.length,
    name: 'complete',
    label: 'Compiling report',
  } satisfies PhaseEvent)
  send({ type: 'result', result })
  res.end()
}
