/**
 * Shared scanner types between server (api/scan.ts) and client (ScanForm).
 * No Node imports here — must stay browser-safe.
 */

export type Severity = 'critical' | 'warn' | 'info' | 'ok'

export type Category =
  | 'secrets'
  | 'auth'
  | 'auth-enum'
  | 'auth-weak'
  | 'auth-disclosure'
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
  /**
   * Dynamic-engine risk class (2026-05-08+). Five buckets, derived from
   * traits (exploitability, auth-impact, runtime-confirmed, etc.) — not
   * from a static per-id table.
   */
  riskClass?:
    | 'critical-exploit'
    | 'high-impact-misconfig'
    | 'medium-weakness'
    | 'low-hardening'
    | 'informational'
  /** Confidence the finding is real and actionable. */
  confidence?: 'confirmed' | 'likely' | 'informational'
  /**
   * Coarse UI section for grouped report rendering:
   *   security-risks | hardening-improvements | informational.
   */
  uiGroup?: 'security-risks' | 'hardening-improvements' | 'informational'
}

/**
 * Vendor signals we recognize from response headers when a target denies
 * automated access. Drives a chip on the error UI + tailored fix copy.
 */
export type WafVendor =
  | 'cloudflare'
  | 'akamai'
  | 'imperva'
  | 'fastly'
  | 'aws-cloudfront'
  | 'aws-waf'
  | 'vercel-bot-protection'
  | 'sucuri'
  | 'stackpath'
  | 'ddos-guard'
  | 'unknown'

/**
 * What Vguard thinks the user should do next when a 4xx came from a WAF.
 * The frontend renders this as a CTA button.
 */
export type SuggestedAction =
  | 'stage2-bookmarklet' // run from user's browser, bypasses WAF
  | 'stage2-server-browser' // server-side Playwright with realistic profile
  | 'stage3-verify-ownership' // owner can prove they own the domain → unlock
  | 'fix-target' // 4xx is the user's app actually broken (rare, e.g. 410)
  | 'try-canonical-host' // www vs apex / http vs https mismatch

export interface ScanError {
  code:
    | 'invalid_url'
    | 'unreachable'
    | 'blocked_by_target' // generic 4xx (e.g. 404 / 410), site reachable but rejected
    | 'blocked_by_waf' // 403/406/429/451 with WAF/CDN signals — different UX
    | 'timeout'
    | 'too_large'
    | 'rate_limited'
    | 'internal'
  message: string
  /** HTTP status from the target when the error originated from a fetch. */
  httpStatus?: number
  /** WAF/edge vendor identified from response headers (only on `blocked_by_waf`). */
  wafVendor?: WafVendor
  /** Recommended next step the frontend should surface as a CTA. */
  suggestedAction?: SuggestedAction
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
   * WAF / bot-protection vendor identified during the scan, if any. Set when
   * the target returned a 4xx with WAF signals. Distinct from `cdn` because
   * a site can sit behind a CDN without bot-protection (or vice-versa: a
   * site with no CDN can still front AWS WAF directly).
   */
  wafVendor?: WafVendor | null
  /**
   * True when the initial scanner request was blocked (4xx) and we recognized
   * a WAF. Always paired with `wafVendor`. The scan may still have succeeded
   * if the stealth retry got through — see `stealthRetrySucceeded`.
   */
  wafBlocked?: boolean
  /** True when we attempted a stealth-headers retry after the initial 4xx. */
  stealthRetryAttempted?: boolean
  /** True when the stealth retry returned a usable 2xx/3xx response. */
  stealthRetrySucceeded?: boolean
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
