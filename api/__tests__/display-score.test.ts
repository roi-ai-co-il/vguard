import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeDisplayScore,
  findingsHaveCritical,
  findingsBlockPerfect,
  withDisplayScore,
} from '../_lib/display-score.ts'
import type { Finding, ScanResult } from '../../src/lib/scanner-types.ts'

function critical(): Pick<Finding, 'severity' | 'effectiveSeverity'> {
  return { severity: 'critical', effectiveSeverity: 'critical' }
}
function high(): Pick<Finding, 'severity' | 'effectiveSeverity' | 'blocksPerfectScore'> {
  return { severity: 'warn', effectiveSeverity: 'high', blocksPerfectScore: true }
}
/** A low/medium hardening note — never a perfect-score blocker. */
function hardening(): Pick<Finding, 'severity' | 'effectiveSeverity' | 'blocksPerfectScore'> {
  return { severity: 'warn', effectiveSeverity: 'low', blocksPerfectScore: false }
}
function medium(): Pick<Finding, 'severity' | 'effectiveSeverity' | 'blocksPerfectScore'> {
  return { severity: 'warn', effectiveSeverity: 'medium', blocksPerfectScore: false }
}

// Minimal ScanResult for withDisplayScore — it reads vibeScore, severityCounts,
// and findings. Cast keeps the test focused.
function result(vibeScore: number, findings: Partial<Finding>[] = []): ScanResult {
  const sev = {
    critical: findings.filter((f) => (f.effectiveSeverity ?? f.severity) === 'critical').length,
    high: findings.filter((f) => f.effectiveSeverity === 'high').length,
    medium: findings.filter((f) => f.effectiveSeverity === 'medium').length,
    low: findings.filter((f) => f.effectiveSeverity === 'low').length,
    info: 0,
    ok: 0,
  }
  return {
    ok: true,
    url: 'https://example.com',
    vibeScore,
    findings: findings as Finding[],
    severityCounts: sev,
    totals: { critical: sev.critical, warn: 0, info: 0, ok: 0 },
  } as unknown as ScanResult
}

describe('computeDisplayScore — 96–99→100 bump behind the strict blocker gate (2026-07-01)', () => {
  it('rawScore 95 stays 95 (below the bump window)', () => {
    assert.deepEqual(computeDisplayScore(95, { blocked: false }), {
      displayScore: 95,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 96 unblocked → 100 (adjusted)', () => {
    assert.deepEqual(computeDisplayScore(96, { blocked: false }), {
      displayScore: 100,
      scoreAdjustedForDisplay: true,
    })
  })
  it('rawScore 99 unblocked → 100 (adjusted)', () => {
    assert.deepEqual(computeDisplayScore(99, { blocked: false }), {
      displayScore: 100,
      scoreAdjustedForDisplay: true,
    })
  })
  it('rawScore 96 BLOCKED → stays 96', () => {
    assert.deepEqual(computeDisplayScore(96, { blocked: true }), {
      displayScore: 96,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 99 BLOCKED → stays 99', () => {
    assert.deepEqual(computeDisplayScore(99, { blocked: true }), {
      displayScore: 99,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 100 displays 100 (already perfect, not "adjusted")', () => {
    assert.deepEqual(computeDisplayScore(100, { blocked: false }), {
      displayScore: 100,
      scoreAdjustedForDisplay: false,
    })
  })
  it('scores outside 96–99 are never bumped, blocked or not', () => {
    for (const s of [0, 49, 79, 89, 90, 95, 100]) {
      assert.equal(computeDisplayScore(s, { blocked: false }).displayScore, s)
      assert.equal(computeDisplayScore(s, { blocked: true }).displayScore, s)
    }
  })
  it('a blocked 96–99 is never bumped', () => {
    for (const s of [96, 97, 98, 99]) {
      assert.equal(computeDisplayScore(s, { blocked: true }).displayScore, s)
      assert.equal(computeDisplayScore(s, { blocked: true }).scoreAdjustedForDisplay, false)
    }
  })
})

describe('findingsHaveCritical', () => {
  it('uses reconciled effectiveSeverity (falls back to severity)', () => {
    assert.equal(findingsHaveCritical([hardening(), hardening()]), false)
    assert.equal(findingsHaveCritical([hardening(), critical()]), true)
    assert.equal(
      findingsHaveCritical([{ severity: 'critical', effectiveSeverity: 'medium' }]),
      false,
    )
  })
})

describe('findingsBlockPerfect — critical / high / blocksPerfectScore all block', () => {
  it('low/medium hardening notes do NOT block', () => {
    assert.equal(findingsBlockPerfect([hardening(), medium()]), false)
  })
  it('a high finding blocks', () => {
    assert.equal(findingsBlockPerfect([hardening(), high()]), true)
  })
  it('a critical finding blocks', () => {
    assert.equal(findingsBlockPerfect([hardening(), critical()]), true)
  })
  it('an explicit blocksPerfectScore flag blocks even without high/critical severity', () => {
    assert.equal(
      findingsBlockPerfect([{ severity: 'warn', effectiveSeverity: 'medium', blocksPerfectScore: true }]),
      true,
    )
  })
})

describe('withDisplayScore — gated bump, raw never touched', () => {
  it('98 with only low/medium hardening → displayScore 100, adjusted true, raw preserved', () => {
    const r = withDisplayScore(result(98, [hardening(), medium()]))
    assert.equal(r.vibeScore, 98, 'rawScore is never overwritten')
    assert.equal(r.displayScore, 100)
    assert.equal(r.scoreAdjustedForDisplay, true)
  })
  it('98 WITH a high finding → stays 98 (blocked)', () => {
    const r = withDisplayScore(result(98, [high()]))
    assert.equal(r.displayScore, 98)
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('96 WITH a critical finding → stays 96 (blocked)', () => {
    const r = withDisplayScore(result(96, [critical()]))
    assert.equal(r.vibeScore, 96)
    assert.equal(r.displayScore, 96)
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('95 → 95 (below window)', () => {
    const r = withDisplayScore(result(95, [hardening()]))
    assert.equal(r.displayScore, 95)
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('detects a blocker via severityCounts.high even if findings lack the flag', () => {
    const r = result(98)
    ;(r.severityCounts as { high: number }).high = 1
    const out = withDisplayScore(r)
    assert.equal(out.displayScore, 98, 'high (via counts) blocks the bump')
    assert.equal(out.scoreAdjustedForDisplay, false)
  })
  it('detects critical via severityCounts even if findings array is empty', () => {
    const r = result(98)
    ;(r.severityCounts as { critical: number }).critical = 1
    const out = withDisplayScore(r)
    assert.equal(out.displayScore, 98)
    assert.equal(out.scoreAdjustedForDisplay, false)
  })
  it('does not mutate any other field (findings / totals / raw stay)', () => {
    const base = result(97, [hardening()])
    const out = withDisplayScore(base)
    assert.equal(out.findings.length, base.findings.length)
    assert.equal(out.totals.warn, base.totals.warn)
    assert.equal(out.vibeScore, 97)
    assert.equal(out.displayScore, 100)
    assert.equal(out.scoreAdjustedForDisplay, true)
  })
})

describe('withDisplayScore — grade follows the number it sits next to (Option A)', () => {
  function resultWithGrade(vibeScore: number, grade: 'A' | 'B' | 'C' | 'D' | 'F', findings: Partial<Finding>[] = []) {
    return { ...result(vibeScore, findings), grade } as ScanResult
  }
  it('bumped 98→100: displayGrade A (off 100), rawGrade A (off 98)', () => {
    const out = withDisplayScore(resultWithGrade(98, 'A', [hardening()]))
    assert.equal(out.displayScore, 100)
    assert.equal(out.displayGrade, 'A')
    assert.equal(out.rawGrade, 'A')
    assert.equal(out.grade, 'A', 'raw technical grade field is untouched')
  })
  it('blocked 96 with a critical: displayGrade + rawGrade both follow 96 (A)', () => {
    const out = withDisplayScore(resultWithGrade(96, 'A', [critical()]))
    assert.equal(out.displayScore, 96)
    assert.equal(out.displayGrade, 'A')
    assert.equal(out.rawGrade, 'A')
  })
  it('a capped 49/F stays F on both grades (no bump)', () => {
    const out = withDisplayScore(resultWithGrade(49, 'F', [critical()]))
    assert.equal(out.displayScore, 49)
    assert.equal(out.displayGrade, 'F')
    assert.equal(out.rawGrade, 'F')
  })
  it('rawGrade falls back to gradeForScore(vibeScore) when grade is absent', () => {
    const r = result(85, [medium()]) // no `grade` field set
    const out = withDisplayScore(r)
    assert.equal(out.rawGrade, 'B')
    assert.equal(out.displayGrade, 'B')
  })
})
