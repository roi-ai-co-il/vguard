/**
 * Vguard — V6 risk-based scoring engine (2026-06-13).
 *
 * The score measures REAL-WORLD RISK (data exposure, unauthorized access,
 * account/system compromise, business impact) — NOT checklist completeness.
 * Recon/fingerprinting findings have zero score impact; hardening gaps are
 * clamped to the posture category's literal 5% weight.
 *
 *   per-finding penalty = base(riskCategory, golden?, tier)
 *                         × confidence (verified 1.0 / likely 0.6 / possible 0.2)
 *                         × businessImpact (public 0.7 … adminInternal 1.6)
 *   score = 100 − Σ decayed penalties (+ WAF bonus)
 *           → grade-cap rule (verified golden cap-set ⇒ max C / 79)
 *           → perfect-score gate (100 needs literally zero deductions)
 *
 * Core principle unchanged since v3: PASSIVE SIGNALS ARE NOT VERIFIED
 * VULNERABILITIES. V6 tightens it further: a reflected canary is Possible XSS
 * and an SQL error signature is suspected SQLi — neither is verified.
 *
 * Policy constants/predicates live in `scoring-policy.ts` (single source of
 * truth). Pure module — no I/O, browser-safe.
 */

import type {
  BusinessImpact,
  EffectiveSeverity,
  Finding,
  Grade,
  RiskCategory,
  RiskCategoryContribution,
  ScoreBreakdown,
  ScoreCategoryContribution,
} from '../../src/lib/scanner-types.js'
import {
  isActiveProbeHitId,
  isBaselineHardeningHeaderId,
  isCookieHardeningId,
  isHardeningHeaderId,
  isReflectedXssId,
  isWafPresentId,
} from './finding-ids.js'
import { deriveFindingTraits } from './finding-traits.js'
import {
  BUSINESS_IMPACT_MULT,
  CATEGORY_LABELS,
  CONFIDENCE_MULT,
  DECAY_FACTOR,
  GOLDEN_CAP_SCORE,
  GOLDEN_PENALTY,
  POSTURE_TOTAL_CAP,
  REGULAR_PENALTY,
  RISKCLASS_TO_EFFECTIVE,
  RISK_CATEGORY_LABELS,
  RISK_CATEGORY_WEIGHT,
  WAF_BONUS,
  gradeCapApplies,
  gradeForScore,
  isGoldenFinding,
  isGoldenKindFinding,
  isPublicClientIdentifier,
  mapToRiskCategory,
  scoreTierForScore,
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
  // 2026-06-07 v5.7 — `runtimeConfirmed` is a property of the FINDING, not of the
  // scan's stage. The old `|| ctx.stage > 1` meant that when Stage 2 results were
  // MERGED (ctx.stage=2), every passive Stage-1 finding was falsely marked
  // runtime-confirmed → confidence "confirmed" → ceiling-eligible → it could cap
  // the grade. That's exactly what dropped Palo Alto's merged score to 79 on an
  // `auth-enum-surface` that Stage 1 alone scored 86. A passive finding stays
  // passive even inside a Stage-2/3 report.
  const runtimeConfirmed = isStage2 || isStage3

  // Via the shared contract so the REAL emitted ids (`paths-reflected-xss`,
  // word order and all) match — raw token lists drift (the 2026-06-07 audit bug).
  const activeProbeHit = isActiveProbeHitId(id)
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

  // 2026-06-07 v5.4 — match the cookie NAME/value in `evidence` only, NOT the
  // finding's own description prose. Testing `desc` made analytics cookies match
  // because our copy literally says "Auth-shaped cookies…" → e.g. Apple's
  // `dssid2` (a tracking cookie) was misread as a session cookie and scored as a
  // High session-theft risk. Evidence holds the real cookie name, so it still
  // catches a genuine `session=`/`auth_token=` cookie.
  const authCookie =
    /(\b|_)(sess|session|auth|token|jwt|sid|csrf|xsrf|access_token|refresh_token)\b/i.test(ev)

  // NOTE: a cookie missing a flag is NOT "sensitive data exposure" — the cookie
  // existing doesn't expose data; it's defense-in-depth. Keeping it out of
  // `sensitiveData` is what stops auth-named cookies from being scored as a
  // High data-exposure risk (the Apple/Palo-Alto downgrade). Real data exposure
  // is a leaked secret or a public bucket/RTDB. (2026-06-07 v5.5)
  const sensitiveData =
    (secretPattern && !knownPublicClientId && !isAstHeuristic) ||
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
    // Hardening-header detection goes through the shared finding-ids contract,
    // so the REAL emitted ids (`headers-content-security-policy`, …) are
    // correctly recognised as defense-in-depth.
    (isHardeningHeaderId(id) ||
      isBaselineHardeningHeaderId(id) ||
      isCookieHardeningId(id) ||
      ID(id, 'dom-sink-innerhtml', 'dom-sink-outerhtml', 'dom-sink-insertadjacent', 'dom-sink-document-write', 'js-ast-dom-sink') ||
      ID(id, 'dns-no-caa', 'dns-no-dnssec') ||
      ID(id, 'email-dmarc-monitor', 'email-spf-softfail', 'email-spf-soft-fail') ||
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

/**
 * EXPLICIT allowlist of genuine unconfirmed weaknesses that classify as
 * medium-weakness (shown in "needs review"). Everything not verified, not a
 * real runtime exposure, and not on this list defaults to hardening — so a
 * new/unanticipated detector can never surprise-tank a clean site.
 */
function isGenuineUnconfirmedWeakness(
  finding: Finding,
  ctx: ScoringContext,
): boolean {
  const id = finding.id || ''
  const cat = finding.category

  // NOTE: weak CSP / missing headers / cookie flags are deliberately NOT here.
  // They are defense-in-depth — like a cookie missing HttpOnly, a weak CSP only
  // matters in combination with an injection. Consistent rule: anything that
  // needs ANOTHER vulnerability to be exploitable is hardening, not a weakness.
  // The allowlist below is for findings that are DIRECTLY a problem on their own.

  // NOTE: `auth-enum-surface` is NOT here. The detector only finds that a login/
  // signup page EXISTS — a surface, not confirmed account enumeration (which
  // requires the response to reveal whether an account exists). Merely having a
  // login page is normal, so it is hardening/observation, not a capping weakness.

  // SameSite=None cookie sent cross-site WITHOUT Secure — actively insecure.
  if (id.includes('samesite-none')) return true
  // A dependency pinned to a known-vulnerable (CVE-matched) version.
  if (/deps-(npm|server-cve)/.test(id)) return true
  // Mixed content — an active downgrade surface on an HTTPS page.
  if (cat === 'mixed-content') return true
  // Source maps leaking internal paths, or any source map on a sensitive route.
  if (cat === 'sourcemaps' && !id.includes('with-secrets')) {
    if (id.includes('with-internal-paths')) return true
    if (ctx.routeContext === 'sensitive') return true
    return false
  }
  // A sensitive path returned 200 with a non-shell body but we couldn't confirm
  // a secret — worth a human look (the verified-secret variant is critical).
  if (id.includes('-exposed-needs-review')) return true
  return false
}

export function classifyRiskClass(
  finding: Finding,
  traits: FindingTraits,
  ctx: ScoringContext,
): RiskClass {
  const sev = finding.severity

  // ---- Non-weaknesses ----
  if (sev === 'ok') return 'informational'
  // `meta` is informational-observations (WAF present, localhost ref, …).
  if (finding.category === 'meta') return 'informational'
  // Publishable client identifiers (anon keys, pk_live_, GA ids) are not secrets.
  if (traits.knownPublicAsset && !traits.verifiedImpact) return 'informational'

  // =========================================================================
  // ROOT PRINCIPLE (v5.6, kept in V6) — only these escalate; EVERYTHING ELSE
  // defaults to hardening, which deducts a clamped, minimal amount.
  //   (1) verified impact              → critical-exploit
  //   (2) real runtime/active exposure → high-impact-misconfig
  //   (3) explicit weakness allowlist  → medium-weakness
  //   (4) everything else              → low-hardening / informational
  // =========================================================================

  // (1) Verified impact — the only path to Critical.
  if (traits.verifiedImpact) return 'critical-exploit'

  // (2) Real exposure short of the verified bar: an active-probe detection
  //     (Possible XSS / suspected SQLi), or real sensitive data/token/bucket
  //     actually OBSERVED at runtime (e.g. an auth token in localStorage).
  if (traits.exploitable) return 'high-impact-misconfig'
  if (traits.runtimeConfirmed && traits.sensitiveData) return 'high-impact-misconfig'

  // (3) Explicit allowlist of genuine unconfirmed weaknesses.
  if (isGenuineUnconfirmedWeakness(finding, ctx)) return 'medium-weakness'

  // (4) Default = hardening / informational. Hardening headers + cookie flags
  //     map to low-hardening at ANY severity. A detector-`critical` we could
  //     neither verify nor allowlist becomes "needs review" (medium) rather
  //     than a critical.
  if (
    traits.defenseInDepthOnly ||
    isHardeningHeaderId(finding.id) ||
    isCookieHardeningId(finding.id)
  ) {
    return 'low-hardening'
  }
  if (sev === 'critical') return 'medium-weakness'
  if (sev === 'warn') return 'low-hardening'
  return 'informational'
}

/**
 * V6 confidence — drives the 1.0 / 0.6 / 0.2 multiplier:
 *   verified — exploitation / direct-observation evidence
 *   likely   — strong signal (runtime observation, SQL error signature,
 *              unverified detector-critical)
 *   possible — detection only (reflected canary, pattern match, heuristic,
 *              hardening observations)
 */
export function classifyConfidence(
  finding: Finding,
  traits: FindingTraits,
): Confidence {
  const id = finding.id || ''
  if (finding.severity === 'ok') return 'possible'
  if (traits.verifiedImpact) return 'verified'
  // Reflected canary = Possible XSS (browser execution required to verify).
  if (isReflectedXssId(id)) return 'possible'
  // Sensitive-path 200 whose body we could NOT confirm — detection only.
  if (id.includes('-exposed-needs-review')) return 'possible'
  if (traits.knownPublicAsset) return 'possible'
  if (traits.runtimeConfirmed) return 'likely'
  if (traits.defenseInDepthOnly) return 'possible'
  if (finding.severity === 'info') return 'possible'
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
// Per-finding 0–10 risk (display/ranking only — NOT the score input)
// ---------------------------------------------------------------------------

const RISK_SCORE_BASE: Record<RiskClass, number> = {
  'critical-exploit': 9.0,
  'high-impact-misconfig': 6.0,
  'medium-weakness': 3.5,
  'low-hardening': 1.2,
  informational: 0.4,
}

export function computeFindingRisk(
  finding: Finding,
  traits: FindingTraits,
  riskClass: RiskClass,
  confidence: Confidence,
  ctx: ScoringContext,
): number {
  if (finding.severity === 'ok') return 0
  let raw = RISK_SCORE_BASE[riskClass] * CONFIDENCE_MULT[confidence]

  if (traits.runtimeConfirmed && traits.verifiedImpact) raw += 0.6
  if (traits.highAbuseLikelihood && traits.verifiedImpact) raw += 0.4
  if (traits.authImpact && ctx.routeContext === 'sensitive') raw += 0.3
  if (traits.sensitiveData && ctx.routeContext === 'sensitive') raw += 0.2
  if (traits.defenseInDepthOnly && ctx.routeContext === 'public') raw -= 0.5

  return Math.round(Math.max(0, Math.min(10, raw)) * 10) / 10
}

// ---------------------------------------------------------------------------
// V6 per-finding penalty
// ---------------------------------------------------------------------------

/** riskClass → the tier used to look up the non-golden penalty base. */
const RISKCLASS_TO_TIER: Record<RiskClass, 'critical' | 'high' | 'medium' | 'low' | null> = {
  'critical-exploit': 'critical',
  'high-impact-misconfig': 'high',
  'medium-weakness': 'medium',
  'low-hardening': 'low',
  informational: null,
}

export function computeFindingPenalty(opts: {
  finding: Finding
  traits: FindingTraits
  riskClass: RiskClass
  riskCategory: RiskCategory
  confidence: Confidence
  businessImpact: BusinessImpact
}): number {
  const { finding, traits, riskClass, riskCategory, confidence, businessImpact } = opts
  if (finding.severity === 'ok') return 0
  if (riskCategory === 'recon') return 0
  const tier = RISKCLASS_TO_TIER[riskClass]
  if (!tier) return 0

  const goldenKind = isGoldenKindFinding(finding, { knownPublicAsset: traits.knownPublicAsset })
  const base = goldenKind ? GOLDEN_PENALTY[riskCategory] : REGULAR_PENALTY[riskCategory][tier]
  if (base <= 0) return 0

  // Business context can scale a finding up or down — but never rescue a
  // VERIFIED golden finding below its full base.
  let biMult = BUSINESS_IMPACT_MULT[businessImpact]
  if (goldenKind && traits.verifiedImpact) biMult = Math.max(1, biMult)

  return base * CONFIDENCE_MULT[confidence] * biMult
}

// ---------------------------------------------------------------------------
// Aggregate vibe score
// ---------------------------------------------------------------------------

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
  riskCategory: RiskCategory
  businessImpact: BusinessImpact
  isGolden: boolean
  riskScore: number
  /** Point penalty this finding contributes (pre decay/clamp). */
  scoreImpact: number
  /** Point penalty after in-category diminishing returns + posture clamp. */
  effectivePenalty: number
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

/** Sort desc and apply 1, 0.6, 0.36, … decay; returns per-item effective values. */
function decayPenalties(items: { penalty: number }[]): Map<{ penalty: number }, number> {
  const sorted = [...items].sort((a, b) => b.penalty - a.penalty)
  const out = new Map<{ penalty: number }, number>()
  let factor = 1.0
  for (const it of sorted) {
    out.set(it, it.penalty * factor)
    factor *= DECAY_FACTOR
  }
  return out
}

/**
 * Aggregate per-finding penalties into the 0–100 vibe score (V6):
 *   1. group penalties by RISK CATEGORY (data / access / exploit / posture)
 *   2. diminishing returns within each category
 *   3. clamp the UNVERIFIED posture total to its literal 5% weight
 *   4. rawScore = 100 − Σ; small WAF bonus when no verified impact exists
 *   5. caps: no-HTTPS → 49; verified grade-cap golden → 79 (max C)
 *   6. perfect-score gate: any deduction at all ⇒ ≤ 99
 */
export function runScoringEngine(findings: Finding[], ctx: ScoringContext): EngineOutput {
  const scored: ScoredFinding[] = findings.map((f) => {
    const traits = extractTraits(f, ctx)
    const riskClass = classifyRiskClass(f, traits, ctx)
    const confidence = classifyConfidence(f, traits)
    const riskScore = computeFindingRisk(f, traits, riskClass, confidence, ctx)
    const effectiveSeverity: EffectiveSeverity =
      f.severity === 'ok' ? 'info' : RISKCLASS_TO_EFFECTIVE[riskClass]
    const pro = deriveFindingTraits(f, ctx)
    const riskCategory = mapToRiskCategory(f, { knownPublicAsset: traits.knownPublicAsset })
    const businessImpact = pro.businessImpact
    const isGolden = isGoldenFinding(f, {
      knownPublicAsset: traits.knownPublicAsset,
      verifiedImpact: traits.verifiedImpact,
    })
    const scoreImpact = computeFindingPenalty({
      finding: f,
      traits,
      riskClass,
      riskCategory,
      confidence,
      businessImpact,
    })
    return {
      finding: f,
      traits,
      riskClass,
      effectiveSeverity,
      confidence,
      riskCategory,
      businessImpact,
      isGolden,
      riskScore,
      scoreImpact,
      effectivePenalty: 0,
    }
  })

  // Reconciled severity histogram — the honest counts behind the badges.
  const severityCounts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ok: 0 }
  for (const s of scored) {
    if (s.finding.severity === 'ok') severityCounts.ok++
    else severityCounts[s.effectiveSeverity]++
  }

  // ---- Risk-category aggregation with diminishing returns ----
  const SCORED_CATEGORIES: RiskCategory[] = ['data', 'access', 'exploit', 'posture']
  let postureClamped = false
  for (const rc of SCORED_CATEGORIES) {
    const members = scored.filter((s) => s.riskCategory === rc && s.scoreImpact > 0)
    if (members.length === 0) continue

    if (rc === 'posture') {
      // Verified posture findings (e.g. a critical CVE match) are never muted;
      // everything unverified shares the literal 5-point posture budget.
      const verified = members.filter((s) => s.traits.verifiedImpact)
      const unverified = members.filter((s) => !s.traits.verifiedImpact)
      for (const grp of [verified, unverified]) {
        const items = grp.map((s) => ({ penalty: s.scoreImpact, s }))
        const eff = decayPenalties(items)
        for (const it of items) it.s.effectivePenalty = eff.get(it) ?? 0
      }
      const unverifiedSum = unverified.reduce((a, s) => a + s.effectivePenalty, 0)
      if (unverifiedSum > POSTURE_TOTAL_CAP) {
        const scale = POSTURE_TOTAL_CAP / unverifiedSum
        for (const s of unverified) s.effectivePenalty *= scale
        postureClamped = true
      }
    } else {
      const items = members.map((s) => ({ penalty: s.scoreImpact, s }))
      const eff = decayPenalties(items)
      for (const it of items) it.s.effectivePenalty = eff.get(it) ?? 0
    }
  }

  const totalPenalty = scored.reduce((a, s) => a + s.effectivePenalty, 0)

  // ---- WAF bonus (bonus only — absence is never penalized) ----
  const wafPresent = ctx.wafPresent === true || scored.some((s) => isWafPresentId(s.finding.id || ''))
  const hasVerifiedImpact = scored.some((s) => s.traits.verifiedImpact)
  const wafBonus = wafPresent && !hasVerifiedImpact ? WAF_BONUS : 0

  let rawScore = Math.max(0, Math.min(100, 100 - totalPenalty + wafBonus))

  // ---- Caps (the binding one is surfaced in the breakdown) ----
  let hardCap: ScoreBreakdown['hardCap'] | undefined
  if (!ctx.httpsActive) hardCap = { reason: 'Served without HTTPS', cap: 49 }
  const goldenCapBinds = scored.some((s) =>
    gradeCapApplies(s.finding, {
      knownPublicAsset: s.traits.knownPublicAsset,
      verifiedImpact: s.traits.verifiedImpact,
    }),
  )
  if (goldenCapBinds && (!hardCap || hardCap.cap > GOLDEN_CAP_SCORE)) {
    hardCap = hardCap ?? {
      reason: 'Verified critical exposure — grade capped at C until fixed',
      cap: GOLDEN_CAP_SCORE,
    }
  }

  let finalScore = Math.min(rawScore, hardCap?.cap ?? 100)
  finalScore = Math.max(0, Math.round(finalScore))
  // Perfect-score gate: 100 is reserved for literally zero deductions.
  if (totalPenalty > 0 && finalScore >= 100) finalScore = 99

  const grade = gradeForScore(finalScore)
  const scoreTier = scoreTierForScore(finalScore)

  // ---- Breakdown: V6 risk-category view ----
  const riskCategories: RiskCategoryContribution[] = (
    ['data', 'access', 'exploit', 'posture', 'recon'] as RiskCategory[]
  )
    .map((rc) => {
      const members = scored.filter(
        (s) => s.riskCategory === rc && s.finding.severity !== 'ok',
      )
      const penalty = members.reduce((a, s) => a + s.effectivePenalty, 0)
      return {
        category: rc,
        label: RISK_CATEGORY_LABELS[rc],
        weight: RISK_CATEGORY_WEIGHT[rc],
        penalty: Math.round(penalty * 10) / 10,
        findingCount: members.length,
        capped: rc === 'posture' && postureClamped,
      }
    })
    .filter((c) => c.findingCount > 0 || c.penalty > 0)

  // ---- Breakdown: legacy 19-finding-category view (per-category dots) ----
  const byCat = new Map<string, { penalty: number; worst: EffectiveSeverity; count: number; capped: boolean }>()
  for (const s of scored) {
    if (s.finding.severity === 'ok' || s.effectivePenalty <= 0) continue
    const cat = s.finding.category
    const e = byCat.get(cat) ?? { penalty: 0, worst: 'info' as EffectiveSeverity, count: 0, capped: false }
    e.penalty += s.effectivePenalty
    e.count++
    if (SEV_RANK[s.effectiveSeverity] > SEV_RANK[e.worst]) e.worst = s.effectiveSeverity
    if (s.riskCategory === 'posture' && postureClamped && !s.traits.verifiedImpact) e.capped = true
    byCat.set(cat, e)
  }
  const categories: ScoreCategoryContribution[] = Array.from(byCat, ([cat, e]) => ({
    category: cat as ScoreCategoryContribution['category'],
    label: CATEGORY_LABELS[cat as keyof typeof CATEGORY_LABELS] ?? cat,
    penalty: Math.round(e.penalty * 10) / 10,
    findingCount: e.count,
    worstSeverity: e.worst,
    capped: e.capped,
  }))
  categories.sort((a, b) => b.penalty - a.penalty)

  let worstSeverity: EffectiveSeverity | null = null
  for (const s of scored) {
    if (s.finding.severity === 'ok' || s.effectiveSeverity === 'info') continue
    if (s.effectivePenalty <= 0) continue
    if (!worstSeverity || SEV_RANK[s.effectiveSeverity] > SEV_RANK[worstSeverity]) {
      worstSeverity = s.effectiveSeverity
    }
  }

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
    riskCategories,
    rawScore: Math.round(rawScore),
    worstSeverity,
    // V6 has no severity band ceiling; caps surface via `hardCap`.
    bandCeiling: 100,
    hardCap,
    wafBonus: wafBonus > 0 ? wafBonus : undefined,
    scoreTier,
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

  const enriched: EnrichedFinding[] = scored.map((s) => {
    // Attach the professional, evidence-based trait set so every shipped
    // finding self-describes its exploitability / impact / evidence strength.
    const pro = deriveFindingTraits(s.finding, ctx)
    return {
      ...s.finding,
      riskScore: s.riskScore,
      riskBand: bandForRiskScore(s.riskScore),
      riskClass: s.riskClass,
      effectiveSeverity: s.effectiveSeverity,
      confidence: s.confidence,
      uiGroup: uiGroupFor(s.finding, s.riskClass, s.traits),
      verifiedImpact: pro.verifiedImpact,
      exploitability: pro.exploitability,
      attackPrerequisite: pro.attackPrerequisite,
      remoteReachable: pro.remoteReachable,
      publicInternetExposure: pro.publicInternetExposure,
      activeProbeConfirmed: pro.activeProbeConfirmed,
      impactType: pro.impactType,
      evidenceKind: pro.evidenceKind,
      evidenceStrength: pro.evidenceStrength,
      riskCategory: s.riskCategory,
      businessImpact: s.businessImpact,
      isGoldenFinding: s.isGolden,
    }
  })

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
  wafPresent?: boolean
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
    wafPresent: opts.wafPresent ?? false,
  }
}
