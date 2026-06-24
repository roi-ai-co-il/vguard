/**
 * Vguard — Adaptive scan-orchestration policy + self-explaining score (v5).
 *
 * Two pure, deterministic decisions surfaced to the caller:
 *
 *   1. decideScanIntensity() — given the preliminary score, the target signals,
 *      and whether real impact was confirmed, decide how hard to work and what
 *      to recommend next (Stage 2 / Stage 3 / nothing). The Stage-1 detector set
 *      already runs to completion every time (bundles/paths are bounded); this
 *      policy governs the *recommendation* and report tone, and is the hook the
 *      product uses to escalate to browser-assisted / deep scans.
 *
 *   2. buildScoreExplanation() — turn the scored findings + breakdown + profile
 *      + coverage into plain-language drivers a non-security user understands.
 *
 * Pure module — no I/O, browser-safe.
 */

import type {
  Coverage,
} from './target-profile.js'
import type {
  Finding,
  ScanConfidence,
  ScanIntensity,
  ScoreBreakdown,
  TargetProfile,
} from '../../src/lib/scanner-types.js'

export interface IntensityDecision {
  scanIntensityUsed: ScanIntensity
  recommendedNextStep: string
}

/**
 * Early, cheap signals computed mid-scan (after the homepage + bundles are
 * fetched, before path probing) used to decide whether the scanner should WORK
 * HARDER on this target — i.e. run the additive extended probe set on top of the
 * always-run baseline.
 */
export interface EarlyRiskSignals {
  /** A real secret was already found in the bundles. */
  secretAlreadyFound: boolean
  /** Supabase / Firebase / S3 backend referenced. */
  hasBackend: boolean
  /** A login/signup surface is present. */
  hasLoginSurface: boolean
  /** An SPA/app shell (framework, hydration root) is present. */
  hasAppShell: boolean
}

/**
 * Adaptive Stage-1 depth (2026-06-07 v5.3). The baseline probe set ALWAYS runs
 * (consistent detection for everyone — a clean-looking site is never under-
 * scanned). We only ADD the extended probe set when the target shows risk
 * signals, so the brain genuinely works harder the less safe a target looks,
 * while a plain static marketing site stays fast and concise.
 *
 * Pure + deterministic → unit-testable without the network.
 */
export function decideProbeExpansion(s: EarlyRiskSignals): boolean {
  return s.secretAlreadyFound || s.hasBackend || s.hasLoginSurface || s.hasAppShell
}

const APP_PROFILES: TargetProfile[] = [
  'vibeCodedApp',
  'saasLoginApp',
  'ecommerceCheckout',
  'apiHeavyApp',
  'spaAppShell',
]

/**
 * Decide scan intensity + the single most useful next step.
 *
 * - verified impact OR score < 65 → work hardest; verify/escalate.
 * - 65–79 → expand evidence collection.
 * - 80–89 → standard; practical fixes, don't over-penalise hardening.
 * - 90–100 with no suspicious app surface → concise; don't invent noise.
 * - WAF-limited → honest "coverage limited", recommend Stage 2 (runs on the
 *   user's own origin, bypasses the edge block). Never inflate to look secure.
 */
export function decideScanIntensity(
  score: number,
  profile: TargetProfile,
  hasVerifiedImpact: boolean,
  ownershipVerified: boolean,
): IntensityDecision {
  if (profile === 'wafLimitedTarget') {
    return {
      scanIntensityUsed: 'standard',
      recommendedNextStep:
        'Edge protection limited passive coverage. Run a Stage 2 browser-assisted scan (it runs from your own browser/origin, so the WAF can’t block it) for higher confidence.',
    }
  }

  const isApp = APP_PROFILES.includes(profile)

  if (hasVerifiedImpact || score < 65) {
    return {
      scanIntensityUsed: 'deep',
      recommendedNextStep: ownershipVerified
        ? 'Real risk signals found. A Stage 3 verified deep scan is unlocked for this domain — run it to confirm impact (RLS/storage/auth) before you ship.'
        : 'Real risk signals found. Verify domain ownership to unlock the Stage 3 deep scan and confirm exploitability, then prioritise the confirmed findings first.',
    }
  }

  if (score < 80) {
    return {
      scanIntensityUsed: 'expanded',
      recommendedNextStep: isApp
        ? 'At least one real weakness. Review the flagged items; for app/auth/data-store surfaces consider Stage 2 (browser-assisted) to confirm runtime behaviour.'
        : 'At least one real weakness — fix the flagged items and re-scan.',
    }
  }

  if (score < 90) {
    return {
      scanIntensityUsed: 'standard',
      recommendedNextStep:
        'Good posture with minor, fixable hardening gaps. Apply the suggested fixes and re-scan to reach the top band.',
    }
  }

  // 90–100
  if (isApp) {
    return {
      scanIntensityUsed: 'standard',
      recommendedNextStep:
        'Strong passive posture. Because this is an app with login/data-store surface, a Stage 2/3 scan would raise confidence that the backend (auth, RLS, storage) is as solid as the front end.',
    }
  }
  return {
    scanIntensityUsed: 'concise',
    recommendedNextStep:
      'Strong posture and no meaningful weaknesses within passive coverage. No deeper scan needed unless the site changes.',
  }
}

// ---------------------------------------------------------------------------
// Self-explaining score
// ---------------------------------------------------------------------------

const PROFILE_LABEL: Record<TargetProfile, string> = {
  staticMarketingSite: 'static marketing site',
  smallBusinessSite: 'small business website',
  vibeCodedApp: 'vibe-coded app',
  spaAppShell: 'single-page app',
  saasLoginApp: 'SaaS / login app',
  ecommerceCheckout: 'e-commerce / checkout',
  apiHeavyApp: 'API-heavy app',
  enterpriseProfessionalSite: 'enterprise / professional site',
  wafLimitedTarget: 'WAF-protected target (limited coverage)',
  unknown: 'unclassified target',
}

export interface ScoreExplanation {
  riskDrivers: string[]
  positiveSignals: string[]
  coverageLimitations: string[]
  whyNotHigher: string
  whyNotLower: string
}

/** Build the plain-language "why this score" object. */
export function buildScoreExplanation(opts: {
  findings: Finding[]
  breakdown: ScoreBreakdown
  profile: TargetProfile
  coverage: Coverage
  hasVerifiedImpact: boolean
  httpsActive: boolean
  hasExposedSecrets: boolean
}): ScoreExplanation {
  const { findings, breakdown, profile, coverage, hasVerifiedImpact, httpsActive, hasExposedSecrets } =
    opts
  const score = breakdown.finalScore

  // Risk drivers — worst effective severities first, deduped by title.
  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const drivers = findings
    .filter((f) => f.severity !== 'ok' && (f.effectiveSeverity ?? 'info') !== 'info')
    .sort(
      (a, b) =>
        (sevRank[a.effectiveSeverity ?? 'info'] ?? 9) - (sevRank[b.effectiveSeverity ?? 'info'] ?? 9),
    )
    .slice(0, 6)
    .map((f) => {
      const sev = (f.effectiveSeverity ?? 'info').toUpperCase()
      const vi = f.verifiedImpact ? ' (verified impact)' : ''
      return `${sev}: ${f.title}${vi}`
    })

  // Positive signals — concrete good things observed.
  const positiveSignals: string[] = []
  if (httpsActive) positiveSignals.push('Served over HTTPS')
  if (!hasExposedSecrets) positiveSignals.push('No real secrets/keys exposed in client bundles')
  if (!findings.some((f) => f.category === 'paths' && f.severity === 'critical')) {
    positiveSignals.push('No sensitive files (.env/.git/backups) exposed')
  }
  if (!hasVerifiedImpact) positiveSignals.push('No confirmed exploit within scan coverage')
  if (findings.some((f) => f.category === 'tls' && f.severity === 'ok')) {
    positiveSignals.push('Valid TLS certificate')
  }

  // Coverage limitations — honest about what passive scanning can't see.
  const coverageLimitations: string[] = []
  coverageLimitations.push(`Profile: ${PROFILE_LABEL[profile]} · passive Stage-1 scan`)
  if (coverage.coverageScore < 100) {
    coverageLimitations.push(
      `Coverage ${coverage.coverageScore}/100 (confidence: ${coverage.scanConfidence}) — authenticated areas, backend authorization, and runtime behaviour are not exercised by a passive scan.`,
    )
  }
  if (profile === 'wafLimitedTarget') {
    coverageLimitations.push('Edge/WAF protection limited what the scanner could reach.')
  }
  if (profile === 'vibeCodedApp' || profile === 'saasLoginApp') {
    coverageLimitations.push('Backend rules (Supabase RLS / Firebase rules / auth) require a Stage 3 verified scan to confirm.')
  }

  // Why not higher / lower.
  let whyNotHigher: string
  if (score >= 95) whyNotHigher = 'Nothing meaningful found; this is already a top-band result for the available coverage.'
  else if (hasVerifiedImpact) whyNotHigher = 'A verified, exploitable issue is present — confirmed impact caps the score in the critical band until it is fixed.'
  else if (drivers.length > 0) whyNotHigher = `Held back by: ${drivers[0]}.`
  else whyNotHigher = 'Minor hardening gaps prevent the top band.'

  let whyNotLower: string
  if (hasVerifiedImpact) whyNotLower = 'Score reflects confirmed impact; other findings are de-weighted so one real issue dominates honestly.'
  else if (!findings.some((f) => (f.effectiveSeverity ?? 'info') === 'critical' || (f.effectiveSeverity ?? 'info') === 'high'))
    whyNotLower = 'No confirmed exploit or high-impact issue was found — remaining items are hardening/best-practice, which are capped so they can’t collapse the score.'
  else whyNotLower = 'Findings are unconfirmed misconfigurations rather than verified exploits, so confidence weighting keeps the score out of the critical band.'

  return { riskDrivers: drivers, positiveSignals, coverageLimitations, whyNotHigher, whyNotLower }
}
