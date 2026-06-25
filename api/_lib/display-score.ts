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

export interface DisplayScore {
  /** The number the UI renders. Equals rawScore except for the 96–99→100 bump. */
  displayScore: number
  /** True only when displayScore was rounded UP from a 96–99 rawScore. */
  scoreAdjustedForDisplay: boolean
}

/**
 * The single rule. Never mutates anything; takes the raw score + whether a
 * critical exists and returns the display pair.
 *
 *   raw ≤ 95           → display raw            (adjusted: false)
 *   raw 96–99, no crit → display 100            (adjusted: true)
 *   raw 96–99, crit    → display raw            (adjusted: false)  ← rule 11
 *   raw 100            → display 100            (adjusted: false)  ← already perfect
 */
export function computeDisplayScore(rawScore: number, _opts: { hasCritical: boolean }): DisplayScore {
  // Cosmetic 96–99→100 bump DISABLED (2026-06-25). User testing showed that a
  // perfect 100 on ordinary marketing sites read as "the tool didn't check
  // anything." Showing the honest score (97/98/99) — and letting different
  // sites land on different numbers — makes the scan feel like it actually
  // measured something. Aligns with scoring-v6 ("100 requires zero deductions").
  // The DISPLAY_BUMP_* constants + scoreAdjustedForDisplay field are kept so the
  // bump can be re-enabled by restoring the window check here.
  return { displayScore: rawScore, scoreAdjustedForDisplay: false }
}

/**
 * Attach the display-only fields to a finished ScanResult WITHOUT touching the
 * raw `vibeScore` / `scoreBreakdown`. Critical detection prefers the reconciled
 * `severityCounts.critical`, falling back to per-finding reconciled severity.
 */
export function withDisplayScore<T extends ScanResult>(result: T): T {
  const hasCritical =
    (result.severityCounts?.critical ?? 0) > 0 || findingsHaveCritical(result.findings)
  const { displayScore, scoreAdjustedForDisplay } = computeDisplayScore(result.vibeScore, {
    hasCritical,
  })
  return { ...result, displayScore, scoreAdjustedForDisplay }
}
