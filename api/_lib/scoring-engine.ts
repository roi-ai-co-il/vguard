/**
 * Vguard — Dynamic risk-based scoring engine.
 *
 * 2026-05-09 v3 — extracted policy constants/predicates into
 * `scoring-policy.ts` (single source of truth). Engine logic kept here:
 * trait extraction, classification, per-finding score, aggregate score,
 * caps, UI grouping.
 *
 * Core principle: PASSIVE SIGNALS ARE NOT VERIFIED VULNERABILITIES.
 *
 * Pure module — no I/O, browser-safe.
 */

import type { EffectiveSeverity, Finding, Grade, ScoreBreakdown, ScoreCategoryContribution } from '../../src/lib/scanner-types.js'
import {
  CLASS_BASE,
  CONFIDENCE_MULT,
  DECAY_FACTOR,
  RISKCLASS_TO_EFFECTIVE,
  SEVERITY_PENALTY,
  BAND_CEILING,
  CATEGORY_CAP,
  DEFAULT_CATEGORY_CAP,
  CATEGORY_LABELS,
  gradeForScore,
  isAdvancedHardeningHeader,
  isPublicClientIdentifier,
  verifiedImpactPredicate,
  type RiskClass,
  type Confidence,
  type UiGroup,
  type RouteContext,
  type ScoringContext,
  type FindingTraits,
} from './scoring-policy.js'

// Re-export so existing consumers don't break.
export type { RiskClass, Confidence, UiGroup, RouteContext, ScoringContext, FindingTraits }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ID = (s: string, ...ps: string[]) => ps.some((p) => s.startsWith(p) || s.includes(p))

// ---------------------------------------------------------------------------
// Trait extraction — pattern-driven
// ---------------------------------------------------------------------------

export function extractTraits(finding: Finding, ctx: ScoringContext): FindingTraits {
  const id = finding.id || ''
  const cat = finding.category
  const sev = finding.severity
  const ev = (finding.evidence || '').toLowerCase()
  const desc = (finding.description || '').toLowerCase()

  const isStage2 = id.startsWith('stage2-')
  const isStage3 = id.startsWith('stage3-') || id.startsWith('deep-')
  const runtimeConfirmed = isStage2 || isStage3 || ctx.stage > 1

  const activeProbeHit = ID(
    id,
    'paths-xss-reflected',
    'paths-sqli',
    'paths-open-redirect',
    'paths-traversal',
    'paths-ssrf',
  )
  const exploitable =
    activeProbeHit ||
    (runtimeConfirmed && (cat === 'auth-disclosure' || ID(id, 'rls-anon-select', 'auth-idor')))

  const secretPattern =
    cat === 'secrets' ||
    ID(
      id,
      'paths-env',
      'paths-git',
      'paths-aws-credentials',
      'paths-database-sql',
      'paths-backup',
      'sourcemaps-exposed',
    ) ||
    ID(id, 'stage2-localstorage-auth-tokens')

  const knownPublicClientId = isPublicClientIdentifier(id, finding.evidence || '', finding.description || '')

  // AST-heuristic credentials — NOT a real leak. Force them out of the
  // "verified secret" lane so they can never be `verifiedImpact`. The
  // detector now emits `warn` severity + clearer copy, but legacy data may
  // still arrive flagged `critical`; treat the id as a known-public class.
  const isAstHeuristic = id === 'js-ast-hardcoded-creds'

  const knownPublicAsset =
    knownPublicClientId ||
    isAstHeuristic ||
    ID(
      id,
      'paths-robots',
      'paths-sitemap',
      'paths-swagger',
      'paths-openapi',
      'paths-api-docs',
      'paths-graphql',
      'paths-status',
      'paths-well-known',
    ) ||
    ID(id, 'paths-admin-login-visible', 'paths-admin-protected') ||
    ID(id, 'stage2-public-api-2xx', 'paths-api-public-2xx') ||
    // SPA-shell / empty-body path probes — suppressed as info by detector
    // but they may still arrive here as `warn`; classify as known-public.
    ID(id, '-spa-shell-200', '-empty-200', 'paths-admin-route-clean')

  const authImpact =
    cat === 'auth' ||
    cat === 'auth-enum' ||
    cat === 'auth-weak' ||
    cat === 'auth-disclosure' ||
    ID(id, 'auth-', 'rls-', 'idor-', 'jwt-')

  const publicExposure = cat !== 'meta' && finding.severity !== 'ok'

  const authCookie =
    /(\b|_)(sess|session|auth|token|jwt|sid|csrf|xsrf|access_token|refresh_token)\b/i.test(ev) ||
    /(\b|_)(sess|session|auth|token|jwt|sid|csrf|xsrf|access_token|refresh_token)\b/i.test(desc)

  const sensitiveData =
    (secretPattern && !knownPublicClientId && !isAstHeuristic) ||
    (cat === 'cookies' && authCookie) ||
    ID(id, 'paths-firebase-rtdb-root') ||
    ID(id, 'paths-supabase-storage-public-list', 'paths-s3-list')

  const browserSurface =
    cat === 'headers' ||
    cat === 'mixed-content' ||
    cat === 'integrity' ||
    cat === 'html' ||
    ID(id, 'paths-xss', 'cookies-')

  const defenseInDepthOnly =
    !exploitable &&
    !sensitiveData &&
    sev !== 'critical' &&
    (isAdvancedHardeningHeader(id, finding.evidence || '', finding.description || '') ||
      ID(
        id,
        'headers-no-x-content-type',
        'headers-no-hsts',
        'headers-no-x-frame-options',
        'headers-csp-missing',
        'headers-csp-weak',
        'headers-csp-unsafe-inline',
        'headers-csp-unsafe-eval',
        'headers-csp-wildcard',
        'headers-csp-no-base-uri',
        'headers-csp-no-frame-ancestors',
        'headers-csp-no-form-action',
      ) ||
      ID(id, 'cookies-no-secure', 'cookies-no-samesite') ||
      ID(id, 'dom-sink-innerhtml', 'dom-sink-outerhtml', 'dom-sink-insertadjacent', 'dom-sink-document-write', 'js-ast-dom-sink') ||
      ID(id, 'dns-no-caa', 'dns-no-dnssec') ||
      ID(id, 'email-dmarc-monitor', 'email-spf-softfail') ||
      ID(id, 'integrity-no-sri') ||
      ID(id, 'meta-'))

  const configurationFlaw =
    /unsafe-inline|unsafe-eval/.test(ev) ||
    /unsafe-inline|unsafe-eval/.test(desc) ||
    ID(id, 'headers-csp-unsafe', 'headers-csp-weak') ||
    ID(id, 'cors-wildcard', 'cors-credentials-wildcard')

  const highAbuseLikelihood =
    ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials', 'sourcemaps-exposed-with-secrets') ||
    ID(
      id,
      'secrets-stripe-secret',
      'secrets-aws',
      'secrets-supabase-service-role',
      'secrets-anthropic',
      'secrets-openai',
    ) ||
    ID(id, 'paths-xss-reflected', 'paths-sqli')

  // -------------------------------------------------------------------------
  // STRICT VERIFIED-IMPACT GATE — single source of truth in scoring-policy.
  // -------------------------------------------------------------------------
  const verifiedImpact = verifiedImpactPredicate(
    finding,
    { authImpact, runtimeConfirmed, knownPublicAsset },
    ctx,
  )

  return {
    exploitable,
    secretPattern,
    authImpact,
    publicExposure,
    sensitiveData,
    browserSurface,
    runtimeConfirmed,
    defenseInDepthOnly,
    configurationFlaw,
    highAbuseLikelihood,
    verifiedImpact,
    knownPublicAsset,
    authCookie,
  }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export function classifyRiskClass(
  finding: Finding,
  traits: FindingTraits,
  ctx: ScoringContext,
): RiskClass {
  if (finding.severity === 'ok') return 'informational'

  // `meta` is the informational-observations category (WAF present, localhost
  // reference, etc.) — never a weakness. It must never set a band ceiling or it
  // produces the nonsense "1 Medium (capped) · −0 · score capped at 79".
  if (finding.category === 'meta') return 'informational'

  if (traits.knownPublicAsset && !traits.verifiedImpact) {
    return 'informational'
  }

  if (traits.verifiedImpact) return 'critical-exploit'

  // High-impact misconfig for non-verified-but-impactful cases.
  if (
    traits.runtimeConfirmed &&
    (traits.exploitable ||
      traits.sensitiveData ||
      (traits.authImpact && finding.severity !== 'info'))
  ) {
    return 'high-impact-misconfig'
  }

  // CORS open + creds:true — high-impact even when flagged as warn (without
  // verified impact from detector). Spec test 16.
  if (
    finding.id.startsWith('cors-credentials-wildcard') ||
    finding.id.startsWith('cors-creds-wildcard')
  ) {
    return 'high-impact-misconfig'
  }

  // Auth/session cookies missing hardening — session-theft surface.
  if (finding.category === 'cookies' && traits.authCookie && finding.severity !== 'info') {
    return 'high-impact-misconfig'
  }

  // Source maps without secrets — distinct grading:
  //   bare 'sourcemaps-exposed' → low-hardening (info-ish) on public route,
  //                              → medium-weakness on sensitive route
  //   'sourcemaps-exposed-with-internal-paths' → medium-weakness
  // Source maps WITHOUT secrets are transparency, not a vulnerability — top-tier
  // sites (GitHub, Apple, …) ship them intentionally. Grade as a hardening
  // suggestion on public routes; a weakness only on sensitive routes or when
  // internal paths leak. The with-secrets variant is caught by the verified-
  // impact gate (→ critical). This covers both the bare `sourcemaps-exposed`
  // id and the per-file `sourcemap-<file>` ids the detector actually emits.
  if (finding.category === 'sourcemaps' && !finding.id.includes('with-secrets')) {
    if (finding.id.includes('with-internal-paths')) return 'medium-weakness'
    return ctx.routeContext === 'sensitive' ? 'medium-weakness' : 'low-hardening'
  }

  if (traits.defenseInDepthOnly) {
    if (ctx.routeContext === 'sensitive' && traits.browserSurface) return 'medium-weakness'
    if (finding.category === 'cookies' && traits.authCookie) return 'medium-weakness'
    return 'low-hardening'
  }

  if (traits.authImpact && finding.severity !== 'info') {
    return 'medium-weakness'
  }

  if (traits.configurationFlaw && traits.browserSurface) {
    return 'low-hardening'
  }

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
  if (traits.verifiedImpact) return 'confirmed'
  if (traits.runtimeConfirmed) return 'confirmed'
  if (traits.knownPublicAsset) return 'informational'
  if (traits.defenseInDepthOnly) return 'informational'
  if (finding.severity === 'info') return 'informational'
  return 'likely'
}

export function uiGroupFor(finding: Finding, riskClass: RiskClass, traits: FindingTraits): UiGroup {
  if (finding.severity === 'ok') return 'informational-observations'
  if (traits.verifiedImpact) return 'confirmed-vulnerabilities'
  if (riskClass === 'critical-exploit') return 'confirmed-vulnerabilities'
  if (riskClass === 'high-impact-misconfig') return 'likely-risks'
  if (riskClass === 'medium-weakness') return 'needs-review'
  if (riskClass === 'low-hardening') return 'hardening-recommendations'
  return 'informational-observations'
}

// ---------------------------------------------------------------------------
// Per-finding 0–10 risk
// ---------------------------------------------------------------------------

export function computeFindingRisk(
  finding: Finding,
  traits: FindingTraits,
  riskClass: RiskClass,
  confidence: Confidence,
  ctx: ScoringContext,
): number {
  if (finding.severity === 'ok') return 0
  let raw = CLASS_BASE[riskClass] * CONFIDENCE_MULT[confidence]

  if (traits.runtimeConfirmed && traits.verifiedImpact) raw += 0.6
  if (traits.highAbuseLikelihood && traits.verifiedImpact) raw += 0.4
  if (traits.authImpact && ctx.routeContext === 'sensitive') raw += 0.3
  if (traits.sensitiveData && ctx.routeContext === 'sensitive') raw += 0.2
  if (traits.defenseInDepthOnly && ctx.routeContext === 'public') raw -= 0.5

  return Math.round(Math.max(0, Math.min(10, raw)) * 10) / 10
}

// ---------------------------------------------------------------------------
// Aggregate vibe score — diminishing returns + STRICT CAPS
// ---------------------------------------------------------------------------

function diminishingSum(penalties: number[]): number {
  const sorted = [...penalties].sort((a, b) => b - a)
  let total = 0
  let factor = 1.0
  for (const p of sorted) {
    total += p * factor
    factor *= DECAY_FACTOR
  }
  return total
}

export function bandForRiskScore(score: number): NonNullable<Finding['riskBand']> {
  if (score >= 8) return 'severe'
  if (score >= 6) return 'high'
  if (score >= 3) return 'medium'
  return 'low'
}

export interface ScoredFinding {
  finding: Finding
  traits: FindingTraits
  riskClass: RiskClass
  effectiveSeverity: EffectiveSeverity
  confidence: Confidence
  riskScore: number
  /** Point penalty this finding contributes (severity × confidence, pre cap/decay). */
  scoreImpact: number
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  ok: number
}

export interface EngineOutput {
  vibeScore: number
  grade: Grade
  scored: ScoredFinding[]
  groupCounts: Record<RiskClass, number>
  severityCounts: SeverityCounts
  hasVerifiedImpact: boolean
  breakdown: ScoreBreakdown
}

const SEV_RANK: Record<EffectiveSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

/**
 * Categories whose findings are DETERMINISTIC across scans — derived from the
 * fetched response headers, TLS handshake, DNS records, and downloaded bundles,
 * which are identical every run. These may set the band ceiling. The omitted
 * categories (`paths`, `auth*`, `ai`) are active-probe-driven and flaky, so they
 * only set the ceiling when the finding is a verified/confirmed exploit (handled
 * separately) — otherwise they just deduct. This keeps the same site at the same
 * grade run-to-run.
 */
const STABLE_CEILING_CATS = new Set<string>([
  'headers',
  'cookies',
  'tls',
  'mixed-content',
  'integrity',
  'html',
  'dns',
  'email',
  'secrets',
  'sourcemaps',
  'deps',
  'methods',
  'meta',
])

/**
 * Aggregate the per-finding penalties into the 0–100 vibe score using the
 * band-anchored hybrid model (see scoring-policy.ts header):
 *   1. penalty = SEVERITY_PENALTY[effective] × CONFIDENCE_MULT[confidence]
 *   2. accumulate per category with diminishing returns, then cap the swing
 *      (unless the category carries a real critical/high)
 *   3. rawScore = 100 − Σ category penalties
 *   4. the worst severity present CAPS the score (band ceiling)
 *   5. hard caps for non-negotiables (no HTTPS, …) override everything
 */
export function runScoringEngine(findings: Finding[], ctx: ScoringContext): EngineOutput {
  const scored: ScoredFinding[] = findings.map((f) => {
    const traits = extractTraits(f, ctx)
    const riskClass = classifyRiskClass(f, traits, ctx)
    const confidence = classifyConfidence(f, traits)
    const riskScore = computeFindingRisk(f, traits, riskClass, confidence, ctx)
    const effectiveSeverity: EffectiveSeverity =
      f.severity === 'ok' ? 'info' : RISKCLASS_TO_EFFECTIVE[riskClass]
    const scoreImpact =
      f.severity === 'ok' ? 0 : SEVERITY_PENALTY[effectiveSeverity] * CONFIDENCE_MULT[confidence]
    return { finding: f, traits, riskClass, effectiveSeverity, confidence, riskScore, scoreImpact }
  })

  // Reconciled severity histogram — the honest counts behind the badges.
  const severityCounts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ok: 0 }
  for (const s of scored) {
    if (s.finding.severity === 'ok') severityCounts.ok++
    else severityCounts[s.effectiveSeverity]++
  }

  // Group penalties by category → diminish within → cap the swing.
  const byCat = new Map<
    string,
    { penalties: number[]; worst: EffectiveSeverity; count: number; hasRealRisk: boolean }
  >()
  for (const s of scored) {
    if (s.finding.severity === 'ok' || s.scoreImpact <= 0) continue
    const cat = s.finding.category
    const e =
      byCat.get(cat) ?? { penalties: [], worst: 'info' as EffectiveSeverity, count: 0, hasRealRisk: false }
    e.penalties.push(s.scoreImpact)
    e.count++
    if (SEV_RANK[s.effectiveSeverity] > SEV_RANK[e.worst]) e.worst = s.effectiveSeverity
    // Only a CONFIRMED critical lifts the per-category swing cap — we never mute
    // a real exploit, but unconfirmed high-impact misconfigs (e.g. several auth
    // cookies missing HttpOnly) stay bounded so one category can't dominate.
    if (s.effectiveSeverity === 'critical') e.hasRealRisk = true
    byCat.set(cat, e)
  }

  const categories: ScoreCategoryContribution[] = []
  let totalPenalty = 0
  for (const [cat, e] of byCat) {
    const raw = diminishingSum(e.penalties)
    // Cap only when the category's worst issue is medium-or-below — a confirmed
    // critical/high is never muted.
    const cap = e.hasRealRisk
      ? Infinity
      : CATEGORY_CAP[cat as keyof typeof CATEGORY_CAP] ?? DEFAULT_CATEGORY_CAP
    const penalty = Math.min(raw, cap)
    totalPenalty += penalty
    categories.push({
      category: cat as ScoreCategoryContribution['category'],
      label: CATEGORY_LABELS[cat as keyof typeof CATEGORY_LABELS] ?? cat,
      penalty: Math.round(penalty * 10) / 10,
      findingCount: e.count,
      worstSeverity: e.worst,
      capped: raw > cap,
    })
  }
  categories.sort((a, b) => b.penalty - a.penalty)

  const rawScore = Math.max(0, 100 - totalPenalty)

  // Worst severity present → band ceiling (SSL Labs mechanic). Info doesn't cap.
  //
  // STABILITY (root fix 2026-06-01): the ceiling has outsized impact (it can
  // swing a whole grade), so ONLY deterministic / confirmed findings may set
  // it. Findings derived from the fetched response, headers and bundles are the
  // same on every scan; active network probes (paths, auth, AI endpoints) can
  // 200 once and time-out / get WAF-blocked the next run — letting one of those
  // set the ceiling made the same site score 89 then 79. A flaky probe finding
  // still DEDUCTS (smooth, small), it just can't move the band unless it's a
  // confirmed/verified exploit (a real .env leak or reflected XSS IS stable).
  let worstSeverity: EffectiveSeverity | null = null
  for (const s of scored) {
    if (s.finding.severity === 'ok' || s.effectiveSeverity === 'info') continue
    const ceilingEligible =
      STABLE_CEILING_CATS.has(s.finding.category) ||
      s.traits.verifiedImpact ||
      s.confidence === 'confirmed'
    if (!ceilingEligible) continue
    if (!worstSeverity || SEV_RANK[s.effectiveSeverity] > SEV_RANK[worstSeverity]) {
      worstSeverity = s.effectiveSeverity
    }
  }
  const bandCeiling = worstSeverity ? BAND_CEILING[worstSeverity] : 100

  // Hard caps — non-negotiables override everything.
  let hardCap: ScoreBreakdown['hardCap'] | undefined
  if (!ctx.httpsActive) hardCap = { reason: 'Served without HTTPS', cap: 49 }

  let finalScore = Math.min(rawScore, bandCeiling)
  if (hardCap) finalScore = Math.min(finalScore, hardCap.cap)
  finalScore = Math.max(0, Math.round(finalScore))

  const hasVerifiedImpact = scored.some((s) => s.traits.verifiedImpact)
  const isClean =
    worstSeverity === null &&
    scored.every((s) => s.finding.severity === 'ok' || s.effectiveSeverity === 'info')
  const grade = gradeForScore(finalScore, isClean)

  const groupCounts: Record<RiskClass, number> = {
    'critical-exploit': 0,
    'high-impact-misconfig': 0,
    'medium-weakness': 0,
    'low-hardening': 0,
    informational: 0,
  }
  for (const s of scored) if (s.finding.severity !== 'ok') groupCounts[s.riskClass]++

  const breakdown: ScoreBreakdown = {
    base: 100,
    categories,
    rawScore: Math.round(rawScore),
    worstSeverity,
    bandCeiling,
    hardCap,
    finalScore,
  }

  return { vibeScore: finalScore, grade, scored, groupCounts, severityCounts, hasVerifiedImpact, breakdown }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

export interface EnrichedFinding extends Finding {
  riskClass?: RiskClass
  effectiveSeverity?: EffectiveSeverity
  confidence?: Confidence
  uiGroup?: UiGroup
}

export interface ApplyResult {
  vibeScore: number
  grade: Grade
  findings: EnrichedFinding[]
  groupCounts: Record<RiskClass, number>
  severityCounts: SeverityCounts
  scoreBreakdown: ScoreBreakdown
  hasVerifiedImpact: boolean
  /** Aggregate band derived directly from the final score (no clamping). */
  aggregateBand: 'low' | 'medium' | 'high' | 'severe'
}

export function applyEngine(findings: Finding[], ctx: ScoringContext): ApplyResult {
  const { vibeScore, grade, scored, groupCounts, severityCounts, hasVerifiedImpact, breakdown } =
    runScoringEngine(findings, ctx)

  const enriched: EnrichedFinding[] = scored.map((s) => ({
    ...s.finding,
    riskScore: s.riskScore,
    riskBand: bandForRiskScore(s.riskScore),
    riskClass: s.riskClass,
    effectiveSeverity: s.effectiveSeverity,
    confidence: s.confidence,
    uiGroup: uiGroupFor(s.finding, s.riskClass, s.traits),
  }))

  // Band derives straight from the final score — the band ceiling already did
  // the "don't over-alarm" work, so no separate clamp. Honest weak posture is
  // allowed to land in medium/high without a confirmed exploit (the whole point
  // of the v4 redesign).
  let aggregateBand: ApplyResult['aggregateBand']
  if (vibeScore < 50) aggregateBand = 'severe'
  else if (vibeScore < 70) aggregateBand = 'high'
  else if (vibeScore < 85) aggregateBand = 'medium'
  else aggregateBand = 'low'

  return {
    vibeScore,
    grade,
    findings: enriched,
    groupCounts,
    severityCounts,
    scoreBreakdown: breakdown,
    hasVerifiedImpact,
    aggregateBand,
  }
}

export function defaultContext(opts: {
  pathname: string
  isHttps: boolean
  cspHasUnsafe?: boolean
  stage?: 1 | 2 | 3
}): ScoringContext {
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
