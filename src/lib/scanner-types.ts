/**
 * Shared scanner types between server (api/scan.ts) and client (ScanForm).
 * No Node imports here — must stay browser-safe.
 */

export type Severity = 'critical' | 'warn' | 'info' | 'ok'

export type Category =
  | 'secrets'
  | 'auth'
  | 'headers'
  | 'paths'
  | 'sourcemaps'
  | 'tls'
  | 'cookies'
  | 'integrity'
  | 'mixed-content'
  | 'html'
  | 'dns'
  | 'email'
  | 'methods'
  | 'ai'
  | 'deps'
  | 'meta'

export interface Finding {
  id: string
  severity: Severity
  category: Category
  title: string
  description: string
  evidence: string
  fixPrompt: string
}

export interface ScanError {
  code:
    | 'invalid_url'
    | 'unreachable'
    | 'blocked_by_target'
    | 'timeout'
    | 'too_large'
    | 'rate_limited'
    | 'internal'
  message: string
}

export interface ScanResult {
  ok: true
  url: string
  scannedAt: string
  durationMs: number
  vibeScore: number
  totals: { critical: number; warn: number; info: number; ok: number }
  findings: Finding[]
  meta: {
    finalUrl: string
    httpStatus: number
    contentType: string | null
    detectedFramework: string | null
    bundlesFetched: number
    bundlesSizeBytes: number
  }
  /**
   * Detection metadata from the scan, used by Stage 3 deep scan to drive
   * targeted probes (e.g. RLS testing using the detected anon key).
   * Only set on Stage 1 scans; Stage 3 reuses these.
   */
  detected?: {
    supabaseProjectIds: string[]
    supabaseAnonKey: string | null
    s3BucketHosts: string[]
    firebaseIds: string[]
    aiEndpoints: string[]
  }
  /** When true, the result already includes Stage 3 findings appended. */
  stage?: 1 | 3
}

export interface ScanFailure {
  ok: false
  error: ScanError
}

export type ScanResponse = ScanResult | ScanFailure
