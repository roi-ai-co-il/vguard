/**
 * Shared scanner types between server (api/scan.ts) and client (ScanForm).
 * No Node imports here — must stay browser-safe.
 */

export type Severity = 'critical' | 'warn' | 'info' | 'ok'

/**
 * Reconciled 5-tier severity (CVSS-aligned). This — NOT the raw detector
 * `severity` — is the single source of truth for the badge, the totals, and
 * the score. Derived from the engine's `riskClass`, so a detector that emitted
 * `critical` on a public token can no longer show "Critical" while scoring as a
 * medium. Mapping: critical-exploit→critical, high-impact-misconfig→high,
 * medium-weakness→medium, low-hardening→low, informational→info.
 */
export type EffectiveSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Letter grade shown alongside the 0–100 number (SSL Labs / Observatory style).
 * V6 scale: A 90–100 · B 80–89 · C 70–79 · D 60–69 · F 0–59. `A+` was retired
 * in V6 — the 90+ band is qualified by `ScoreTier` instead.
 */
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

/** Qualifier inside the A band: 90–94 excellent · 95–99 outstanding · 100 exceptional. */
export type ScoreTier = 'excellent' | 'outstanding' | 'exceptional'

// ---------------------------------------------------------------------------
// Professional exposure-scoring dimensions (2026-06-07 v5)
// Inspired by CVSS / EPSS / OWASP risk methodology. Deterministic "Smart
// Scoring" — NO telemetry, NO ML. Every field is derived from observable scan
// evidence in `api/_lib/finding-traits.ts`.
// ---------------------------------------------------------------------------

/** How realistically an attacker can use this finding. */
export type Exploitability = 'none' | 'theoretical' | 'plausible' | 'easy' | 'confirmed'

/** What an attacker needs before this finding is usable. */
export type AttackPrerequisite =
  | 'none'
  | 'userInteraction'
  | 'authRequired'
  | 'ownershipRequired'
  | 'unknown'

/** The kind of impact if the finding is real. */
export type ImpactType =
  | 'none'
  | 'hardening'
  | 'infoDisclosure'
  | 'credentialExposure'
  | 'authBypass'
  | 'dataExposure'
  | 'codeExecution'
  | 'transportBreak'
  | 'supplyChain'
  | 'abusePath'

/** How the evidence for this finding was obtained. */
export type EvidenceKind =
  | 'passive'
  | 'heuristic'
  | 'runtime'
  | 'activeProbe'
  | 'ownershipVerifiedDeepScan'

/** Strength of the evidence behind the finding. */
export type EvidenceStrength = 'weak' | 'moderate' | 'strong' | 'confirmed'

/**
 * V6 risk category — the four weighted buckets the score is computed over,
 * plus `recon` (visibility-only, zero score impact):
 *   data    (40%) — secret/data exposure (.env, keys, dumps, public buckets)
 *   access  (30%) — access control & authorization (IDOR, RLS, admin, rate limits)
 *   exploit (25%) — exploitable vulnerabilities (XSS, SQLi, SSRF, traversal, RCE)
 *   posture (5%)  — defense-in-depth hardening (headers, cookies, SPF, CVEs, WAF)
 *   recon   (0%)  — fingerprinting/tech-detection observations
 */
export type RiskCategory = 'data' | 'access' | 'exploit' | 'posture' | 'recon'

/**
 * Business-impact sensitivity of the asset a finding touches. Multiplies the
 * technical penalty: public 0.7× · userData 1.0× · financial 1.3× ·
 * adminInternal 1.6×. Derived from observable signals only — never a brand list.
 */
export type BusinessImpact = 'public' | 'userData' | 'financial' | 'adminInternal'

/** Observable classification of the scanned target (NOT a brand list). */
export type TargetProfile =
  | 'staticMarketingSite'
  | 'smallBusinessSite'
  | 'vibeCodedApp'
  | 'spaAppShell'
  | 'saasLoginApp'
  | 'ecommerceCheckout'
  | 'apiHeavyApp'
  | 'enterpriseProfessionalSite'
  | 'wafLimitedTarget'
  | 'unknown'

/** Separate from the security score: how much we were able to verify. */
export type ScanConfidence = 'low' | 'medium' | 'high'

/** How hard the orchestrator decided to work on this target. */
export type ScanIntensity = 'concise' | 'standard' | 'expanded' | 'deep'

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
  /**
   * Reconciled severity derived from `riskClass` by the scoring engine. This is
   * what the UI badge and the totals MUST render — keeps "what's shown" and
   * "what's scored" in lockstep. Falls back to `severity` for legacy data.
   */
  effectiveSeverity?: EffectiveSeverity
  /**
   * Confidence the finding is real and actionable (V6 vocabulary):
   * verified (exploitation/observation evidence, 100% weight) ·
   * likely (strong signal, 60%) · possible (detection only, 20%).
   */
  confidence?: 'verified' | 'likely' | 'possible'
  /**
   * Coarse UI section for grouped report rendering. New 5-bucket model
   * (2026-05-08 v2 strict-Critical-gate):
   *   confirmed-vulnerabilities | likely-risks | needs-review |
   *   hardening-recommendations | informational-observations
   */
  uiGroup?:
    | 'confirmed-vulnerabilities'
    | 'likely-risks'
    | 'needs-review'
    | 'hardening-recommendations'
    | 'informational-observations'
  // -------------------------------------------------------------------------
  // Professional scoring traits (v5). Set by `deriveFindingTraits`. Optional so
  // legacy data + detector emit-sites that don't set them still type-check; the
  // engine derives them from id/category/severity/evidence when absent.
  // -------------------------------------------------------------------------
  /** True ONLY with evidence of real impact — the strict gate. */
  verifiedImpact?: boolean
  exploitability?: Exploitability
  attackPrerequisite?: AttackPrerequisite
  /** Reachable from the public internet (vs requiring local/internal access). */
  remoteReachable?: boolean
  /** Exposed on the public internet surface (vs auth-gated). */
  publicInternetExposure?: boolean
  /** Confirmed by an active probe / runtime / deep scan (not inferred). */
  activeProbeConfirmed?: boolean
  impactType?: ImpactType
  evidenceKind?: EvidenceKind
  evidenceStrength?: EvidenceStrength
  /** V6 — which of the four weighted risk buckets this finding scores under. */
  riskCategory?: RiskCategory
  /** V6 — sensitivity of the affected asset (multiplies the penalty). */
  businessImpact?: BusinessImpact
  /** V6 — true when this is a verified Golden Finding (major security failure). */
  isGoldenFinding?: boolean
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

/** Structured error type from the URL reachability resolver (per candidate). */
export type ResolverErrorType =
  | 'dns_error'
  | 'tcp_connect_timeout'
  | 'tls_error'
  | 'http_timeout'
  | 'too_many_redirects'
  | 'unknown_network_error'

/** One candidate's reachability attempt — the debug record (resolver §10). */
export interface ResolutionAttempt {
  userInputUrl: string
  candidateUrl: string
  startedAt: number
  durationMs: number
  protocol: string
  hostname: string
  port: string
  statusCode: number | null
  errorType: ResolverErrorType | null
  errorMessage: string | null
  redirectChain: string[]
  contentType: string | null
  /** First ~200 chars of the body, secrets redacted. Never the full body. */
  responseBodySample: string
  selected: boolean
  selectionReason: string | null
}

/** Resolver outcome metadata attached to a successful scan (resolver §1). */
export interface UrlResolution {
  userInputUrl: string
  normalizedHost: string
  resolvedScanUrl: string
  /** A non-exact candidate (different protocol/host than the user typed) won. */
  usedFallback: boolean
  /** The resolved URL is http:// — HTTPS was unavailable/failed. Scored. */
  httpDowngraded: boolean
  /** scannable | http_only | reachable_but_blocked. */
  reachability: 'scannable' | 'http_only' | 'reachable_but_blocked'
  attempts: ResolutionAttempt[]
}

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
    // Resolver failure codes — every URL candidate failed (resolver §7D).
    | 'all_candidates_failed'
    | 'dns_error'
    | 'tcp_connect_timeout'
    | 'tls_error'
    | 'http_timeout'
    | 'too_many_redirects'
    | 'unknown_network_error'
  message: string
  /** HTTP status from the target when the error originated from a fetch. */
  httpStatus?: number
  /** WAF/edge vendor identified from response headers (only on `blocked_by_waf`). */
  wafVendor?: WafVendor
  /** Recommended next step the frontend should surface as a CTA. */
  suggestedAction?: SuggestedAction
  /** Every URL candidate the resolver tried, with per-attempt failure reasons. */
  resolutionAttempts?: ResolutionAttempt[]
}

/** One category's contribution to the score, for the "why this score" card. */
export interface ScoreCategoryContribution {
  category: Category
  label: string
  /** Points removed by this category (positive number). */
  penalty: number
  findingCount: number
  worstSeverity: EffectiveSeverity
  /** True when a per-category swing cap limited this category's penalty. */
  capped: boolean
}

/** One V6 risk category's contribution to the score. */
export interface RiskCategoryContribution {
  category: RiskCategory
  label: string
  /** The category's weight in the model (0.40 / 0.30 / 0.25 / 0.05 / 0). */
  weight: number
  /** Points removed by this risk category (positive number, post-decay). */
  penalty: number
  findingCount: number
  /** True when the posture total clamp limited this category's penalty. */
  capped: boolean
}

/** Full, attributable score derivation — the scorecard the UI renders. */
export interface ScoreBreakdown {
  base: 100
  categories: ScoreCategoryContribution[]
  /** V6 — the four weighted risk buckets behind the number (recon shown as 0). */
  riskCategories?: RiskCategoryContribution[]
  /** Raw score after deductions (and WAF bonus), before any cap. */
  rawScore: number
  /** Worst effective severity present (drives the per-category dot colors). */
  worstSeverity: EffectiveSeverity | null
  /** Legacy field — V6 always 100; caps are expressed via `hardCap`. */
  bandCeiling: number
  /**
   * Non-negotiable cap that overrode the subtotal, if any: no-HTTPS (49) or a
   * verified Golden Finding from the grade-cap set (max grade C → 79).
   */
  hardCap?: { reason: string; cap: number }
  /** Small bonus applied because a WAF fronts the origin (never a penalty). */
  wafBonus?: number
  /** Qualifier inside the A band (excellent/outstanding/exceptional). */
  scoreTier?: ScoreTier
  finalScore: number
  // -------------------------------------------------------------------------
  // Self-explaining score (v5). Plain-language drivers so a non-security user
  // understands WHY the number is what it is.
  // -------------------------------------------------------------------------
  /** The findings that pulled the score down, worst first. */
  riskDrivers?: string[]
  /** Concrete good things the scan observed (HTTPS, no exposed secrets, …). */
  positiveSignals?: string[]
  /** What the scan could NOT verify (passive only, WAF block, auth areas …). */
  coverageLimitations?: string[]
  /** Why the score isn't higher. */
  whyNotHigher?: string
  /** Why the score isn't lower. */
  whyNotLower?: string
  /** The single most useful next action for this result. */
  recommendedNextStep?: string
  /** How hard the orchestrator decided to work. */
  scanIntensityUsed?: ScanIntensity
  /** Observable target classification. */
  targetProfile?: TargetProfile
}

export interface ScanResult {
  ok: true
  url: string
  scannedAt: string
  durationMs: number
  vibeScore: number
  /**
   * Customer-facing score the UI renders. Display-only cosmetic of `vibeScore`:
   * a clean 96–99 (with NO critical finding) shows as a premium 100; everything
   * else is identical to `vibeScore`. The raw `vibeScore` / `scoreBreakdown` are
   * never changed — see `api/_lib/display-score.ts`.
   */
  displayScore?: number
  /** True only when `displayScore` was rounded up from a 96–99 `vibeScore`. */
  scoreAdjustedForDisplay?: boolean
  /** Letter grade derived from `vibeScore` (A … F). */
  grade?: Grade
  totals: { critical: number; warn: number; info: number; ok: number }
  /** 5-tier reconciled counts (the honest histogram behind the badges). */
  severityCounts?: { critical: number; high: number; medium: number; low: number; info: number; ok: number }
  /** Attributable per-category score derivation for the "why this score" card. */
  scoreBreakdown?: ScoreBreakdown
  // -------------------------------------------------------------------------
  // Coverage / confidence (v5) — kept SEPARATE from `vibeScore`. "How secure it
  // looks" (vibeScore) is not "how much we could verify" (coverage/confidence).
  // -------------------------------------------------------------------------
  /** Observable target classification (drives adaptive intensity + copy). */
  targetProfile?: TargetProfile
  /** How much confidence to place in this scan's coverage. */
  scanConfidence?: ScanConfidence
  /** 0–100 — how much of the relevant surface this scan type could examine. */
  coverageScore?: number
  /** How hard the orchestrator worked on this target. */
  scanIntensityUsed?: ScanIntensity
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
    /**
     * Passively-detected login/signup/password-reset endpoints. Stage 1 only
     * DETECTS them; the active rate-limit test (Stage 3, ownership-verified)
     * probes exactly these — never arbitrary pasted URLs.
     */
    authEndpoints?: string[]
  }
  /**
   * URL reachability resolution metadata — which candidate was scanned, whether
   * a fallback (www/apex/http) was used, and the full attempt log. Drives the
   * "User input vs Scanned URL" UI + the fallback note.
   */
  resolution?: UrlResolution
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
