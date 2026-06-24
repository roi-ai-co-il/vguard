import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeDisplayScore,
  findingsHaveCritical,
  withDisplayScore,
} from '../_lib/display-score.ts'
import type { Finding, ScanResult } from '../../src/lib/scanner-types.ts'

function critical(): Pick<Finding, 'severity' | 'effectiveSeverity'> {
  return { severity: 'critical', effectiveSeverity: 'critical' }
}
function warn(): Pick<Finding, 'severity' | 'effectiveSeverity'> {
  return { severity: 'warn', effectiveSeverity: 'medium' }
}

// Minimal ScanResult for withDisplayScore — it only reads vibeScore,
// severityCounts.critical, and findings. Cast keeps the test focused.
function result(vibeScore: number, findings: Partial<Finding>[] = []): ScanResult {
  const sev = {
    critical: findings.filter((f) => (f.effectiveSeverity ?? f.severity) === 'critical').length,
    high: 0,
    medium: 0,
    low: 0,
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

describe('computeDisplayScore — honest score, no cosmetic bump (2026-06-25)', () => {
  it('rawScore 95 stays 95', () => {
    assert.deepEqual(computeDisplayScore(95, { hasCritical: false }), {
      displayScore: 95,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 96 stays 96 (bump disabled)', () => {
    assert.deepEqual(computeDisplayScore(96, { hasCritical: false }), {
      displayScore: 96,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 97 stays 97 (bump disabled)', () => {
    assert.deepEqual(computeDisplayScore(97, { hasCritical: false }), {
      displayScore: 97,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 99 stays 99 (bump disabled)', () => {
    assert.deepEqual(computeDisplayScore(99, { hasCritical: false }), {
      displayScore: 99,
      scoreAdjustedForDisplay: false,
    })
  })
  it('rawScore 100 displays 100', () => {
    assert.deepEqual(computeDisplayScore(100, { hasCritical: false }), {
      displayScore: 100,
      scoreAdjustedForDisplay: false,
    })
  })
  it('never changes the score regardless of critical flag', () => {
    for (const s of [0, 49, 79, 89, 90, 95, 96, 97, 99, 100]) {
      assert.equal(computeDisplayScore(s, { hasCritical: false }).displayScore, s)
      assert.equal(computeDisplayScore(s, { hasCritical: true }).displayScore, s)
    }
  })
})

describe('findingsHaveCritical', () => {
  it('uses reconciled effectiveSeverity (falls back to severity)', () => {
    assert.equal(findingsHaveCritical([warn(), warn()]), false)
    assert.equal(findingsHaveCritical([warn(), critical()]), true)
    // raw severity critical but engine reconciled to medium → NOT critical
    assert.equal(
      findingsHaveCritical([{ severity: 'critical', effectiveSeverity: 'medium' }]),
      false,
    )
  })
})

describe('withDisplayScore — attaches display fields without touching raw', () => {
  it('96 with no critical → displayScore 96 (bump disabled), rawScore untouched', () => {
    const r = withDisplayScore(result(96, [warn()]))
    assert.equal(r.vibeScore, 96, 'rawScore is never overwritten')
    assert.equal(r.displayScore, 96, 'displayScore equals the honest raw score')
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('96 WITH a critical finding → displayScore stays 96', () => {
    const r = withDisplayScore(result(96, [critical()]))
    assert.equal(r.vibeScore, 96)
    assert.equal(r.displayScore, 96)
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('95 → displayScore 95 (no change), rawScore preserved', () => {
    const r = withDisplayScore(result(95, [warn()]))
    assert.equal(r.vibeScore, 95)
    assert.equal(r.displayScore, 95)
    assert.equal(r.scoreAdjustedForDisplay, false)
  })
  it('detects critical via severityCounts even if findings array is empty', () => {
    const r = result(98)
    ;(r.severityCounts as { critical: number }).critical = 1
    const out = withDisplayScore(r)
    assert.equal(out.displayScore, 98, 'critical (via counts) blocks the bump')
    assert.equal(out.scoreAdjustedForDisplay, false)
  })
  it('does not mutate any other field (severity / findings / breakdown stay)', () => {
    const base = result(97, [warn()])
    const out = withDisplayScore(base)
    assert.equal(out.findings.length, base.findings.length)
    assert.equal(out.totals.warn, base.totals.warn)
    assert.equal(out.vibeScore, 97)
  })
})
