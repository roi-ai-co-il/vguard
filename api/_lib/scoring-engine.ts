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

import type { Finding } from '../../src/lib/scanner-types.js'
import {
  CAPS,
  CLASS_BASE,
  CLASS_DAMAGE,
  CONFIDENCE_MULT,
  DECAY_FACTOR,
  BAND_THRESHOLDS,
  isAdvancedHardeningHeader,
  isPublicClientIdentifier,
  verifiedImpactPredicate,
  type RiskClass,
  type Confidence,
  type UiGroup,
  type RouteContext,
  type ScoringContext,
  type FindingTraits,
} from './scoring-policy.ts'

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
      ID(id, 'dom-sink-innerhtml', 'dom-sink-outerhtml', 'dom-sink-insertadjacent', 'dom-sink-document-write') ||
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
  if (finding.id === 'sourcemaps-exposed') {
    return ctx.routeContext === 'sensitive' ? 'medium-weakness' : 'low-hardening'
  }
  if (finding.id === 'sourcemaps-exposed-with-internal-paths') {
    return 'medium-weakness'
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
  confidence: Confidence
  riskScore: number
  scoreImpact: number
}

export interface EngineOutput {
  vibeScore: number
  scored: ScoredFinding[]
  groupCounts: Record<RiskClass, number>
  hasVerifiedImpact: boolean
}

export function runScoringEngine(findings: Finding[], ctx: ScoringContext): EngineOutput {
  const scored: ScoredFinding[] = findings.map((f) => {
    const traits = extractTraits(f, ctx)
    const riskClass = classifyRiskClass(f, traits, ctx)
    const confidence = classifyConfidence(f, traits)
    const riskScore = computeFindingRisk(f, traits, riskClass, confidence, ctx)
    const baseDamage = CLASS_DAMAGE[riskClass]
    const impact =
      f.severity === 'ok'
        ? 0
        : baseDamage * CONFIDENCE_MULT[confidence] * (riskScore / 10 + 0.4)
    return { finding: f, traits, riskClass, confidence, riskScore, scoreImpact: impact }
  })

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

  const criticalSum = diminishingSum(byClass['critical-exploit'])
  const highSum = diminishingSum(byClass['high-impact-misconfig'])
  const mediumSum = diminishingSum(byClass['medium-weakness'])
  const hardeningSumRaw = diminishingSum(byClass['low-hardening'])
  const informationalSumRaw = diminishingSum(byClass.informational)

  const hasVerifiedImpact = scored.some((s) => s.traits.verifiedImpact)
  // Caps only apply when there is NO verified impact.
  const hardeningSum = hasVerifiedImpact
    ? hardeningSumRaw
    : Math.min(hardeningSumRaw, CAPS.hardeningTotal)
  const informationalSum = hasVerifiedImpact
    ? informationalSumRaw
    : Math.min(informationalSumRaw, CAPS.informationalTotal)

  const HARDENING_CATS = new Set(['headers', 'cookies', 'html'])
  const allHardeningOnlyCats = scored
    .filter((s) => s.finding.severity !== 'ok')
    .every((s) => HARDENING_CATS.has(s.finding.category as string))

  let mediumLowInfo = mediumSum + hardeningSum + informationalSum
  if (!hasVerifiedImpact && allHardeningOnlyCats) {
    mediumLowInfo = Math.min(mediumLowInfo, CAPS.headerCspOnlyCombined)
  }

  const totalPenaltyRaw = criticalSum + highSum + mediumLowInfo
  const vibeScore = Math.max(0, Math.min(100, Math.round(100 - totalPenaltyRaw)))

  const groupCounts: Record<RiskClass, number> = {
    'critical-exploit': byClass['critical-exploit'].length,
    'high-impact-misconfig': byClass['high-impact-misconfig'].length,
    'medium-weakness': byClass['medium-weakness'].length,
    'low-hardening': byClass['low-hardening'].length,
    informational: byClass.informational.length,
  }

  return { vibeScore, scored, groupCounts, hasVerifiedImpact }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

export interface EnrichedFinding extends Finding {
  riskClass?: RiskClass
  confidence?: Confidence
  uiGroup?: UiGroup
}

export interface ApplyResult {
  vibeScore: number
  findings: EnrichedFinding[]
  groupCounts: Record<RiskClass, number>
  hasVerifiedImpact: boolean
  /** Aggregate band, clamped to <= medium when no verified impact. */
  aggregateBand: 'low' | 'medium' | 'high' | 'severe'
}

export function applyEngine(findings: Finding[], ctx: ScoringContext): ApplyResult {
  const { vibeScore, scored, groupCounts, hasVerifiedImpact } = runScoringEngine(findings, ctx)

  const enriched: EnrichedFinding[] = scored.map((s) => ({
    ...s.finding,
    riskScore: s.riskScore,
    riskBand: bandForRiskScore(s.riskScore),
    riskClass: s.riskClass,
    confidence: s.confidence,
    uiGroup: uiGroupFor(s.finding, s.riskClass, s.traits),
  }))

  const inverted = 100 - vibeScore
  let aggregateBand: ApplyResult['aggregateBand']
  if (inverted >= BAND_THRESHOLDS.severe) aggregateBand = 'severe'
  else if (inverted >= BAND_THRESHOLDS.high) aggregateBand = 'high'
  else if (inverted >= BAND_THRESHOLDS.medium) aggregateBand = 'medium'
  else aggregateBand = 'low'

  if (!hasVerifiedImpact && (aggregateBand === 'severe' || aggregateBand === 'high')) {
    aggregateBand = 'medium'
  }

  return { vibeScore, findings: enriched, groupCounts, hasVerifiedImpact, aggregateBand }
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
