import { createClient } from '@supabase/supabase-js'
import type {
  Finding,
  ScanFailure,
  ScanResponse,
  ScanResult,
} from '../../src/lib/scanner-types.js'

/**
 * Vguard scan telemetry. Fail-soft Supabase insert into `vs_scan_log`.
 *
 * Captures both success (ScanResult) and failure (ScanFailure) outcomes so we
 * can answer:
 *   - how many scans get blocked by a WAF
 *   - which vendors block the most
 *   - how often the stealth retry rescues a blocked scan
 *
 * Schema columns are defined in migration `vs_scan_log_add_waf_telemetry`.
 *
 * Imported by both `api/scan.ts` and `api/scan-stream.ts` so every scan path
 * logs identically. Never throws; missing env / DB errors are swallowed.
 */
export async function logScanOutcome(
  outcome: ScanResponse,
  rawUrl: string,
  country: string | null,
): Promise<void> {
  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) return
  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const row = outcome.ok
      ? buildSuccessRow(outcome, country)
      : buildFailureRow(outcome, rawUrl, country)
    if (!row) return
    await client.from('vs_scan_log').insert(row)
  } catch {
    // ignore — fail-soft
  }
}

function pickTopFinding(findings: Finding[]): Finding | null {
  const order = { critical: 0, warn: 1, info: 2, ok: 3 } as const
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity])
  return sorted.find((f) => f.severity !== 'ok') ?? null
}

function buildSuccessRow(result: ScanResult, country: string | null) {
  const top = pickTopFinding(result.findings)
  let hostname: string
  try {
    hostname = new URL(result.meta.finalUrl).hostname
  } catch {
    return null
  }
  if (!hostname) return null
  const surface = result.attackSurface
  return {
    hostname,
    vibe_score: result.vibeScore,
    top_finding_id: top?.id ?? null,
    top_finding_severity: top?.severity ?? null,
    top_finding_title: top?.title?.slice(0, 200) ?? null,
    country: country?.slice(0, 4) ?? null,
    waf_vendor: surface?.wafVendor ?? null,
    waf_blocked: surface?.wafBlocked ?? null,
    stealth_retry_attempted: surface?.stealthRetryAttempted ?? null,
    stealth_retry_succeeded: surface?.stealthRetrySucceeded ?? null,
    scan_outcome: 'success',
  }
}

function buildFailureRow(failure: ScanFailure, rawUrl: string, country: string | null) {
  let hostname: string
  try {
    hostname = new URL(rawUrl).hostname
  } catch {
    return null
  }
  if (!hostname) return null
  const e = failure.error
  return {
    hostname,
    vibe_score: 0,
    top_finding_id: null,
    top_finding_severity: null,
    top_finding_title: null,
    country: country?.slice(0, 4) ?? null,
    waf_vendor: e.wafVendor ?? null,
    waf_blocked: e.code === 'blocked_by_waf',
    // Stealth retry was attempted whenever blocked_by_waf came back; on this
    // failure path it definitionally failed (else the scan would be ok=true).
    stealth_retry_attempted: e.code === 'blocked_by_waf',
    stealth_retry_succeeded: false,
    scan_outcome: e.code,
  }
}
