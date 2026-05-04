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
  /**
   * CVSS-style risk score 0.0–10.0 (10 = worst). Derived from severity +
   * category weight + per-finding overrides. Lets the UI rank "fix-first"
   * within the same severity bucket. Set by `risk-scorer.applyRisk`.
   */
  riskScore?: number
  /**
   * Human-readable risk band: `low` (0–3), `medium` (3–6), `high` (6–8),
   * `severe` (8–10). Derived from `riskScore` so the UI doesn't recompute.
   */
  riskBand?: 'low' | 'medium' | 'high' | 'severe'
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
    /** S1+2 — Specific version when extractable (e.g. "15.0.3" for Next.js). */
    detectedFrameworkVersion?: string | null
    /** S1+2 — React version when detectable from the bundle. */
    detectedReactVersion?: string | null
    bundlesFetched: number
    bundlesSizeBytes: number
    /** S1+5 — Route context classification (sensitive / public / unknown). */
    routeContext?: 'sensitive' | 'public' | 'unknown'
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
  /**
   * Composite 0–100 risk score for the whole scan (100 = worst). Independent
   * of `vibeScore`: vibeScore = "how good is this site"; aggregateRisk =
   * "how dangerous are the open issues, weighted by per-finding riskScore".
   * One critical can produce a higher aggregateRisk than ten infos.
   */
  aggregateRisk?: number
  /** Risk band for the overall scan, mirrors per-finding bands. */
  aggregateRiskBand?: 'low' | 'medium' | 'high' | 'severe'
  /**
   * Structured attack-surface map for this site. A flat machine-readable
   * picture of the asset (domains, endpoints, third-party scripts, auth
   * providers, data stores) that an MCP/agent or a security reviewer can
   * scan without re-doing detection. Always present on Stage 1+.
   */
  attackSurface?: AttackSurface
}

export type CdnProvider =
  | 'cloudflare'
  | 'aws-cloudfront'
  | 'fastly'
  | 'akamai'
  | 'vercel'
  | 'netlify'
  | 'sucuri'
  | null

export interface AttackSurface {
  primaryDomain: string
  baseDomain: string
  /** Detected CDN/edge in front of the origin, from response headers. */
  cdn: CdnProvider
  /**
   * Public endpoints the scanner saw referenced in HTML, bundles, sitemaps,
   * or platform detection. Deduped by `path`; `source` is the strongest
   * signal we had for it.
   */
  endpoints: { path: string; source: 'html' | 'bundle' | 'detected' | 'sitemap' }[]
  /** External scripts loaded into the page (cross-origin only). */
  thirdPartyScripts: string[]
  /** `<form action="..." method="...">` entries from the main HTML. */
  forms: { action: string; method: string }[]
  /** Auth/identity providers detected from bundles + globals. */
  authProviders: string[]
  /** Data backends referenced from bundles (Supabase project, S3 bucket, Firebase). */
  dataStores: { kind: 'supabase' | 's3' | 'firebase' | 'cloudfront'; ref: string }[]
  /** Subdomains resolved during the scan. Empty in v1.2 — passive CT lookup TODO. */
  subdomains: string[]
}

export interface ScanFailure {
  ok: false
  error: ScanError
}

export type ScanResponse = ScanResult | ScanFailure
