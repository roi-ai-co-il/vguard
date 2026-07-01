/**
 * Vguard — display-score normalization (2026-06-22).
 *
 * A PURELY COSMETIC layer on top of the real score. The raw scoring engine is
 * never touched: `vibeScore`, `scoreBreakdown.rawScore`/`finalScore`, severities,
 * finding order, risk classification, and recommendations all stay exactly as
 * the engine produced them. This module only derives two extra, display-only
 * fields the UI renders instead of the raw number.
 *
 * Rule: a clean site that lands at an awkward 96–99 is shown as a premium
 * **100** — but ONLY when there is no critical finding. Anything ≤95 is shown
 * verbatim; a critical finding always blocks the bump (so we never paint over a
 * real vulnerability with a perfect score).
 *
 * Pure module — no I/O, browser-safe. Imported by the server (to populate the
 * API fields) AND by the UI (to normalize the post-Stage-2 merged score).
 */

import type { Finding, ScanResult } from '../../src/lib/scanner-types.js'
import { gradeForScore } from './scoring-policy.js'

/** Lower bound of the cosmetic bump window (inclusive). */
export const DISPLAY_BUMP_MIN = 96
/** Upper bound of the cosmetic bump window (inclusive). */
export const DISPLAY_BUMP_MAX = 99

/**
 * True when any finding is critical by its RECONCILED severity (the engine's
 * `effectiveSeverity`, falling back to the raw `severity`). A single critical
 * blocks the 100 display, no matter what the number says.
 */
export function findingsHaveCritical(
  findings: Pick<Finding, 'severity' | 'effectiveSeverity'>[],
): boolean {
  return findings.some((f) => (f.effectiveSeverity ?? f.severity) === 'critical')
}

/**
 * True when any finding must block a "perfect" display — a critical, OR any
 * finding the scoring engine flagged `blocksPerfectScore` (its reconciled
 * severity is high/critical). Low/medium hardening findings never block the
 * bump, so a strong site with only hardening notes still displays cleanly.
 * (2026-07-01)
 */
export function findingsBlockPerfect(
  findings: Pick<Finding, 'severity' | 'effectiveSeverity' | 'blocksPerfectScore'>[],
): boolean {
  return findings.some(
    (f) =>
      f.blocksPerfectScore === true ||
      (f.effectiveSeverity ?? f.severity) === 'critical' ||
      f.effectiveSeverity === 'high',
  )
}

export interface DisplayScore {
  /** The number the UI renders. Equals rawScore except for the 96–99→100 bump. */
  displayScore: number
  /** True only when displayScore was rounded UP from a 96–99 rawScore. */
  scoreAdjustedForDisplay: boolean
}

/**
 * The single rule. Never mutates anything; takes the raw score + whether any
 * perfect-score blocker exists, and returns the display pair.
 *
 *   raw ≤ 95              → display raw           (adjusted: false)
 *   raw 96–99, unblocked  → display 100           (adjusted: true)
 *   raw 96–99, blocked    → display raw           (adjusted: false)
 *   raw 100               → display 100           (adjusted: false)  ← already perfect
 *
 * `blocked` is the STRICT gate (see `withDisplayScore`): any critical, any high,
 * any verified impact, or any `blocksPerfectScore:true` finding. Low/medium
 * hardening/contextual notes never block it.
 */
export function computeDisplayScore(rawScore: number, opts: { blocked: boolean }): DisplayScore {
  // Cosmetic 96–99 → 100 bump — DISABLED 2026-06-25 (a perfect 100 on ordinary
  // marketing sites read as "the tool didn't check anything"), RE-ENABLED
  // 2026-07-01 behind the strict blocker gate above. This separates raw
  // technical posture (`vibeScore`, always honest) from the user-facing display
  // number — it never hides findings: the raw score, breakdown, severities, and
  // reasonCodes are all untouched, and any real risk (high/critical/verified/
  // blocksPerfectScore) keeps the honest 96–99.
  if (!opts.blocked && rawScore >= DISPLAY_BUMP_MIN && rawScore <= DISPLAY_BUMP_MAX) {
    return { displayScore: 100, scoreAdjustedForDisplay: true }
  }
  return { displayScore: rawScore, scoreAdjustedForDisplay: false }
}

/**
 * Attach the display-only fields to a finished ScanResult WITHOUT touching the
 * raw `vibeScore` / `scoreBreakdown`. Critical detection prefers the reconciled
 * `severityCounts.critical`, falling back to per-finding reconciled severity.
 */
export function withDisplayScore<T extends ScanResult>(result: T): T {
  // A high/critical reconciled severity (incl. contextually-escalated cookie/
  // transport findings via `blocksPerfectScore`) blocks the perfect display —
  // not just an explicit `critical`. Low/medium hardening never blocks it.
  const blocked =
    (result.severityCounts?.critical ?? 0) > 0 ||
    (result.severityCounts?.high ?? 0) > 0 ||
    findingsBlockPerfect(result.findings)
  const { displayScore, scoreAdjustedForDisplay } = computeDisplayScore(result.vibeScore, {
    blocked,
  })
  // Grade follows the number it's shown next to: `displayGrade` off displayScore
  // (user-facing), `rawGrade` off the untouched vibeScore (debug/admin). `grade`
  // stays the raw technical grade for back-compat.
  const rawGrade = result.grade ?? gradeForScore(result.vibeScore)
  const displayGrade = gradeForScore(displayScore)
  return { ...result, displayScore, scoreAdjustedForDisplay, rawGrade, displayGrade }
}
