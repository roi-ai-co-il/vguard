/**
 * Vguard — Dynamic risk-based scoring engine (2026-05-08).
 *
 * Replaces the static `scoreFromTotals` (-20/-7/-2 per finding) and the
 * per-id prefix-override table in `risk-scorer.ts`.
 *
 * Design goals (per Royi's spec):
 *   1. No hardcoded per-finding weights. Every finding is classified by the
 *      *traits* we extract from it (id, category, evidence, description,
 *      severity, route context, stage). Adding a new detector never requires
 *      touching this file.
 *   2. Risk is a function of: exploitability, auth-impact, public exposure,
 *      sensitive-data leak, browser attack surface, runtime-confirmed,
 *      defense-in-depth-only, and real-world abuse likelihood.
 *   3. Runtime-confirmed (Stage 2/3) findings outweigh passive (Stage 1)
 *      hits at the same severity.
 *   4. Advanced hardening headers (COOP/COEP/CORP/Permissions-Policy) are
 *      low-impact unless paired with an exploit.
 *   5. CSP context-aware: a CSP with `'unsafe-inline'` is materially worse
 *      than a CSP that's just "missing some directives".
 *   6. Diminishing returns: 10 minor hardening misses cannot dwarf one
 *      true critical.
 *   7. Vibe score reflects realistic risk posture. A site with no real
 *      exploitable issues but missing some hardening headers should score
 *      80–95, not 30.
 *   8. Confidence levels: confirmed (active probe hit / runtime), likely
 *      (passive evidence), informational (defense-in-depth observation).
 *
 * Pure module — no I/O, browser-safe.
 */

import type { Category, Finding, Severity } from '../../src/lib/scanner-types.js'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RiskClass =
  | 'critical-exploit'
  | 'high-impact-misconfig'
  | 'medium-weakness'
  | 'low-hardening'
  | 'informational'

export type Confidence = 'confirmed' | 'likely' | 'informational'

export type RouteContext = 'sensitive' | 'public' | 'unknown'

export interface ScoringContext {
  routeContext: RouteContext
  /** True when CSP is present but contains `'unsafe-inline'` / `'unsafe-eval'`. */
  cspHasUnsafe?: boolean
  /** True when the site is HTTPS at all (plain HTTP escalates everything). */
  httpsActive: boolean
  /** Stage of the scan that produced these findings. Stage 2/3 raise confidence. */
  stage: 1 | 2 | 3
}

export interface FindingTraits {
  /** Active probe hit OR runtime-observed (e.g. SQLi error, reflected XSS, RLS leak). */
  exploitable: boolean
  /** Leaks credentials, tokens, or sensitive data once obtained. */
  secretLeak: boolean
  /** Affects auth/authorization/RLS/admin surface. */
  authImpact: boolean
  /** Sits on a publicly reachable URL (no creds required to hit). */
  publicExposure: boolean
  /** Could leak PII, financial data, or session state. */
  sensitiveData: boolean
  /** Increases browser-side attack surface (XSS, clickjack, mixed content). */
  browserSurface: boolean
  /** Confirmed at runtime in Stage 2/3 (vs inferred from passive scan). */
  runtimeConfirmed: boolean
  /** Pure defense-in-depth — no exploit alone, only hurts when paired with one. */
  defenseInDepthOnly: boolean
  /** A CSP/header *misconfiguration* (e.g. unsafe-inline) rather than absence. */
  configurationFlaw: boolean
  /** Evidence indicates a high real-world abuse rate (env files, .git, source maps). */
  highAbuseLikelihood: boolean
}

// ---------------------------------------------------------------------------
// Trait extraction — pattern-driven, not a finding-by-finding table
// ---------------------------------------------------------------------------

const ID = (s: string, ...ps: string[]) => ps.some((p) => s.startsWith(p) || s.includes(p))

const ADVANCED_HARDENING_TOKENS = [
  'coop',
  'coep',
  'corp',
  'permissions-policy',
  'cross-origin-opener',
  'cross-origin-embedder',
  'cross-origin-resource',
  'referrer-policy',
  'origin-agent-cluster',
]

function isAdvancedHardeningHeader(id: string, evidence: string, description: string): boolean {
  const hay = `${id} ${evidence} ${description}`.toLowerCase()
  return ADVANCED_HARDENING_TOKENS.some((t) => hay.includes(t))
}

export function extractTraits(finding: Finding, ctx: ScoringContext): FindingTraits {
  const id = finding.id || ''
  const cat = finding.category
  const sev = finding.severity
  const ev = (finding.evidence || '').toLowerCase()
  const desc = (finding.description || '').toLowerCase()

  const isStage2 = id.startsWith('stage2-')
  const isStage3 = id.startsWith('stage3-') || id.startsWith('deep-')
  const runtimeConfirmed = isStage2 || isStage3 || ctx.stage > 1

  const exploitable =
    ID(id, 'paths-xss', 'paths-sqli', 'paths-open-redirect', 'paths-traversal', 'paths-ssrf') ||
    ID(id, 'auth-signup-supabase-open', 'rls-anon-select', 'auth-idor') ||
    ID(id, 'paths-firebase-rtdb-root', 'paths-supabase-storage-public', 'paths-s3-listbucket') ||
    cat === 'auth-disclosure'

  const secretLeak =
    cat === 'secrets' ||
    ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials', 'paths-database-sql', 'paths-backup', 'sourcemaps-exposed') ||
    ID(id, 'stage2-localstorage-auth-tokens')

  const authImpact =
    cat === 'auth' ||
    cat === 'auth-enum' ||
    cat === 'auth-weak' ||
    cat === 'auth-disclosure' ||
    ID(id, 'auth-', 'rls-', 'idor-', 'jwt-')

  const publicExposure =
    // anything we found on the public web by default is publicly exposed
    cat !== 'meta' && finding.severity !== 'ok'

  const sensitiveData =
    secretLeak ||
    ID(id, 'cookies-not-httponly', 'cookies-no-secure', 'cookies-no-samesite') ||
    ID(id, 'stage2-cookie-not-httponly', 'stage2-localstorage-auth-tokens') ||
    ID(id, 'paths-firebase-rtdb', 'paths-supabase-storage', 'paths-s3-list', 'paths-backup')

  const browserSurface =
    cat === 'headers' ||
    cat === 'mixed-content' ||
    cat === 'integrity' ||
    cat === 'html' ||
    ID(id, 'paths-xss', 'cookies-')

  // Defense-in-depth-only:
  //  - advanced hardening headers (COOP/COEP/CORP/Permissions-Policy/Referrer-Policy)
  //  - DNS hardening that doesn't cause exploits alone (DNSSEC, CAA)
  //  - DMARC monitor-only, SPF soft-fail
  //  - X-Content-Type-Options absent (nosniff)
  //  - HSTS missing on HTTPS site (downgrade is the exploit, not the absence)
  const defenseInDepthOnly =
    !exploitable &&
    !secretLeak &&
    sev !== 'critical' &&
    (
      isAdvancedHardeningHeader(id, ev, desc) ||
      ID(id, 'headers-no-x-content-type', 'headers-no-hsts', 'headers-no-x-frame-options') ||
      ID(id, 'dns-no-caa', 'dns-no-dnssec') ||
      ID(id, 'email-dmarc-monitor', 'email-spf-softfail') ||
      ID(id, 'integrity-no-sri', 'meta-')
    )

  const configurationFlaw =
    /unsafe-inline|unsafe-eval/.test(ev) ||
    /unsafe-inline|unsafe-eval/.test(desc) ||
    ID(id, 'headers-csp-unsafe', 'headers-csp-weak') ||
    ID(id, 'cors-wildcard', 'cors-credentials-wildcard')

  const highAbuseLikelihood =
    ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials', 'sourcemaps-exposed') ||
    ID(id, 'secrets-stripe', 'secrets-aws', 'secrets-supabase-service-role', 'secrets-anthropic', 'secrets-openai') ||
    ID(id, 'paths-xss', 'paths-sqli')

  return {
    exploitable,
    secretLeak,
    authImpact,
    publicExposure,
    sensitiveData,
    browserSurface,
    runtimeConfirmed,
    defenseInDepthOnly,
    configurationFlaw,
    highAbuseLikelihood,
  }
}

// ---------------------------------------------------------------------------
// Classification → risk class + confidence
// ---------------------------------------------------------------------------

export function classifyRiskClass(
  finding: Finding,
  traits: FindingTraits,
  ctx: ScoringContext,
): RiskClass {
  if (finding.severity === 'ok') return 'informational'

  // Critical-exploit: confirmed exploit OR live secret OR plain-HTTP traffic.
  if (
    (traits.exploitable && (traits.runtimeConfirmed || traits.highAbuseLikelihood)) ||
    (traits.secretLeak && traits.highAbuseLikelihood) ||
    (!ctx.httpsActive && traits.publicExposure && finding.category === 'tls')
  ) {
    return 'critical-exploit'
  }

  // High-impact-misconfig: auth/RLS/secrets/sensitive-data leaks discovered
  // passively, plus serious config flaws like CSP with unsafe-inline.
  if (
    traits.secretLeak ||
    (traits.authImpact && finding.severity !== 'info') ||
    (traits.configurationFlaw && traits.browserSurface) ||
    traits.exploitable
  ) {
    return 'high-impact-misconfig'
  }

  // Defense-in-depth-only → low-hardening regardless of declared severity.
  if (traits.defenseInDepthOnly) {
    return ctx.routeContext === 'sensitive' ? 'medium-weakness' : 'low-hardening'
  }

  // Medium: real weaknesses (missing headers on auth surface, weak TLS, etc.)
  if (finding.severity === 'critical' || finding.severity === 'warn') {
    return 'medium-weakness'
  }

  return 'informational'
}

export function classifyConfidence(
  finding: Finding,
  traits: FindingTraits,
): Confidence {
  if (finding.severity === 'ok') return 'informational'
  if (traits.runtimeConfirmed) return 'confirmed'
  if (traits.exploitable && traits.highAbuseLikelihood) return 'confirmed'
  if (traits.defenseInDepthOnly) return 'informational'
  if (finding.severity === 'info') return 'informational'
  return 'likely'
}

// ---------------------------------------------------------------------------
// Per-finding 0–10 risk
// ---------------------------------------------------------------------------

const CLASS_BASE: Record<RiskClass, number> = {
  'critical-exploit': 9.0,
  'high-impact-misconfig': 7.0,
  'medium-weakness': 4.5,
  'low-hardening': 1.5,
  informational: 0.5,
}

const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  confirmed: 1.0,
  likely: 0.85,
  informational: 0.6,
}

export function computeFindingRisk(
  finding: Finding,
  traits: FindingTraits,
  riskClass: RiskClass,
  confidence: Confidence,
  ctx: ScoringContext,
): number {
  if (finding.severity === 'ok') return 0
  let raw = CLASS_BASE[riskClass] * CONFIDENCE_MULTIPLIER[confidence]

  // Trait amplifiers (each small; large effects come from class, not stacking)
  if (traits.runtimeConfirmed) raw += 0.6
  if (traits.highAbuseLikelihood) raw += 0.4
  if (traits.configurationFlaw && traits.browserSurface) raw += 0.5
  if (traits.authImpact && ctx.routeContext === 'sensitive') raw += 0.5
  if (traits.sensitiveData && ctx.routeContext === 'sensitive') raw += 0.3
  // Damping: pure defense-in-depth on a marketing page is genuinely low-impact
  if (traits.defenseInDepthOnly && ctx.routeContext === 'public') raw -= 0.5

  return Math.round(Math.max(0, Math.min(10, raw)) * 10) / 10
}

// ---------------------------------------------------------------------------
// Aggregate vibe score (0–100, higher is better) — diminishing returns
// ---------------------------------------------------------------------------

const CLASS_DAMAGE: Record<RiskClass, number> = {
  'critical-exploit': 35,
  'high-impact-misconfig': 18,
  'medium-weakness': 6,
  'low-hardening': 1.5,
  informational: 0.2,
}

/**
 * Diminishing-returns aggregator. Sort penalties descending, apply each at
 * a decaying weight (1.0, 0.55, 0.35, 0.22, 0.14, …). The first hit lands
 * full-strength; each subsequent finding contributes less.
 *
 * Why: 10 missing-COOP findings shouldn't drown out 1 leaked Stripe key.
 * The decay also means a wall of low-hardening misses tops out around
 * ~5 points off the score — realistic for "site is fine, just not hardened".
 */
function diminishingSum(penalties: number[]): number {
  const sorted = [...penalties].sort((a, b) => b - a)
  let total = 0
  let factor = 1.0
  for (const p of sorted) {
    total += p * factor
    factor *= 0.6
  }
  return total
}

export interface ScoredFinding {
  finding: Finding
  traits: FindingTraits
  riskClass: RiskClass
  confidence: Confidence
  riskScore: number
  /** The damage this finding contributed to the vibe-score subtraction. */
  scoreImpact: number
}

export interface EngineOutput {
  vibeScore: number
  scored: ScoredFinding[]
  /** Counts grouped by the new risk classes (not by old severity). */
  groupCounts: Record<RiskClass, number>
}

export function runScoringEngine(findings: Finding[], ctx: ScoringContext): EngineOutput {
  const scored: ScoredFinding[] = findings.map((f) => {
    const traits = extractTraits(f, ctx)
    const riskClass = classifyRiskClass(f, traits, ctx)
    const confidence = classifyConfidence(f, traits)
    const riskScore = computeFindingRisk(f, traits, riskClass, confidence, ctx)
    // Score impact uses class-damage scaled by confidence and risk.
    const baseDamage = CLASS_DAMAGE[riskClass]
    const impact =
      f.severity === 'ok'
        ? 0
        : baseDamage * CONFIDENCE_MULTIPLIER[confidence] * (riskScore / 10 + 0.4)
    return { finding: f, traits, riskClass, confidence, riskScore, scoreImpact: impact }
  })

  // Per-class diminishing returns: each class deducts independently so a
  // single critical-exploit always outweighs a swarm of low-hardening misses.
  const byClass: Record<RiskClass, number[]> = {
    'critical-exploit': [],
    'high-impact-misconfig': [],
    'medium-weakness': [],
    'low-hardening': [],
    informational: [],
  }
  for (const s of scored) {
    if (s.finding.severity !== 'ok') byClass[s.riskClass].push(s.scoreImpact)
  }

  const totalPenalty =
    diminishingSum(byClass['critical-exploit']) +
    diminishingSum(byClass['high-impact-misconfig']) +
    diminishingSum(byClass['medium-weakness']) +
    diminishingSum(byClass['low-hardening']) +
    diminishingSum(byClass.informational)

  const vibeScore = Math.max(0, Math.min(100, Math.round(100 - totalPenalty)))

  const groupCounts: Record<RiskClass, number> = {
    'critical-exploit': byClass['critical-exploit'].length,
    'high-impact-misconfig': byClass['high-impact-misconfig'].length,
    'medium-weakness': byClass['medium-weakness'].length,
    'low-hardening': byClass['low-hardening'].length,
    informational: byClass.informational.length,
  }

  return { vibeScore, scored, groupCounts }
}

// ---------------------------------------------------------------------------
// Severity → riskBand mapping (kept stable for existing UI)
// ---------------------------------------------------------------------------

export function bandForRiskScore(score: number): NonNullable<Finding['riskBand']> {
  if (score >= 8) return 'severe'
  if (score >= 6) return 'high'
  if (score >= 3) return 'medium'
  return 'low'
}

/**
 * Apply engine results onto the original findings array (returns a fresh
 * array). Sets `riskScore` + `riskBand` and adds the new fields if the
 * Finding interface gains them later. Also returns a high-level group
 * for UI grouping (Security Risks / Hardening Improvements / Informational).
 */
export type UiGroup = 'security-risks' | 'hardening-improvements' | 'informational'

export function uiGroupFor(rc: RiskClass, sev: Severity): UiGroup {
  if (sev === 'ok') return 'informational'
  if (rc === 'critical-exploit' || rc === 'high-impact-misconfig') return 'security-risks'
  if (rc === 'medium-weakness' || rc === 'low-hardening') return 'hardening-improvements'
  return 'informational'
}

export interface EnrichedFinding extends Finding {
  riskClass?: RiskClass
  confidence?: Confidence
  uiGroup?: UiGroup
}

export function applyEngine(
  findings: Finding[],
  ctx: ScoringContext,
): { vibeScore: number; findings: EnrichedFinding[]; groupCounts: Record<RiskClass, number> } {
  const { vibeScore, scored, groupCounts } = runScoringEngine(findings, ctx)
  const enriched: EnrichedFinding[] = scored.map((s) => ({
    ...s.finding,
    riskScore: s.riskScore,
    riskBand: bandForRiskScore(s.riskScore),
    riskClass: s.riskClass,
    confidence: s.confidence,
    uiGroup: uiGroupFor(s.riskClass, s.finding.severity),
  }))
  return { vibeScore, findings: enriched, groupCounts }
}

// Helper for callers that don't want to touch ScoringContext directly.
export function defaultContext(opts: {
  pathname: string
  isHttps: boolean
  cspHasUnsafe?: boolean
  stage?: 1 | 2 | 3
}): ScoringContext {
  // Lightweight route classifier (kept here so engine has zero runtime deps).
  const p = (opts.pathname || '/').toLowerCase()
  const sensitive =
    /\/(?:admin|login|signin|sign-in|signup|register|account|profile|settings|billing|payments?|checkout|cart|order|invoice|subscription|pay|wallet|kyc|verify|verification|onboarding|reset|forgot|password|2fa|mfa|otp|auth|oauth|sso|api\/auth|api\/admin|api\/internal|dashboard|backoffice|cms|wp-admin)\b/i.test(p)
  const publicMarketing =
    /^\/?(?:|index\.html?|home|about|blog|news|press|legal|terms|privacy|cookies|contact|help|faq|features|pricing|docs|documentation|case-studies?|customers|stories|team|company|jobs|careers)(?:\/|$)/i.test(p)
  const routeContext: RouteContext = sensitive ? 'sensitive' : publicMarketing ? 'public' : 'unknown'
  return {
    routeContext,
    httpsActive: opts.isHttps,
    cspHasUnsafe: opts.cspHasUnsafe ?? false,
    stage: opts.stage ?? 1,
  }
}
