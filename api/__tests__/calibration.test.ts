/**
 * CALIBRATION REGRESSION TEST (2026-06-07 v5.7).
 *
 * THE fix for the per-site whack-a-mole. The other tests use synthetic findings
 * that match our assumptions; this one replays the REAL finding-sets captured
 * from a panel of professional sites (apple, paloaltonetworks, nvidia, dell,
 * microsoft, cloudflare, stripe, vercel — see `calibration-fixtures.json`,
 * regenerate with `node scripts/capture-calibration.mjs`) through the engine and
 * asserts each lands in the band it must.
 *
 * Invariants locked here (so a future engine change that would tank a real
 * professional site fails BEFORE deploy, not after a user reports it):
 *   1. Every professional site with no verified exploit scores ≥ 80 (A/B) —
 *      under BOTH the Stage-1 context AND the Stage-2 merge context (the merge
 *      context is what silently capped Palo Alto at 79).
 *   2. None of them produce a critical-exploit / verifiedImpact from passive
 *      hardening findings.
 *   3. Genuine danger (real secret / .env / confirmed RLS) still scores ≤ 49 (F)
 *      — so the leniency above never weakens danger detection.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { applyEngine, defaultContext } from '../_lib/scoring-engine.ts'
import type { Finding } from '../../src/lib/scanner-types.ts'

interface Fixture {
  url: string
  kind: string
  liveScore: number
  findings: { id: string; severity: Finding['severity']; category: Finding['category']; evidence: string }[]
}

const fixtures: Fixture[] = JSON.parse(
  readFileSync(new URL('./calibration-fixtures.json', import.meta.url), 'utf8'),
)

const mk = (x: Fixture['findings'][number]): Finding => ({
  id: x.id,
  severity: x.severity,
  category: x.category,
  title: x.id,
  description: '',
  evidence: x.evidence,
  fixPrompt: '',
})

// Representative Stage-2 findings that real professional sites add at runtime
// (analytics cookies missing flags, public unauth GETs, JWT hygiene). Appending
// these exercises the Stage-1+Stage-2 MERGE path — the one that capped Palo Alto.
const STAGE2_NOISE: Finding[] = [
  mk({ id: 'stage2-cookie-not-httponly', severity: 'warn', category: 'cookies', evidence: 'geo=us; path=/' }),
  mk({ id: 'stage2-cookie-insecure', severity: 'warn', category: 'cookies', evidence: 'at_check (httpOnly=false)' }),
  mk({ id: 'stage2-cookie-long-lived', severity: 'warn', category: 'cookies', evidence: 'dssid2 (expires ~365d)' }),
  mk({ id: 'stage2-unauth-api-calls', severity: 'warn', category: 'auth', evidence: 'GET /api-www/.../flyouts → 200' }),
]

describe('CALIBRATION — real professional sites must not be punished for hardening', () => {
  const stage1 = defaultContext({ pathname: '/', isHttps: true, stage: 1 })
  const stage2 = defaultContext({ pathname: '/', isHttps: true, stage: 2 })

  for (const fx of fixtures) {
    it(`${fx.url} (Stage 1) → A/B (≥80), no fake criticals`, () => {
      const out = applyEngine(fx.findings.map(mk), stage1)
      assert.ok(out.vibeScore >= 80, `${fx.url} dropped to ${out.vibeScore} — a professional site with only hardening must stay ≥80`)
      assert.equal(out.hasVerifiedImpact, false, `${fx.url} should have no verified impact from passive findings`)
      assert.ok(out.findings.every((f) => f.riskClass !== 'critical-exploit'))
    })

    it(`${fx.url} (Stage 1 + Stage 2 merge) → still ≥80 (no context-bleed cap)`, () => {
      const out = applyEngine([...fx.findings.map(mk), ...STAGE2_NOISE], stage2)
      assert.ok(out.vibeScore >= 80, `${fx.url} merged dropped to ${out.vibeScore} — Stage-2 merge must not cap a clean pro site`)
    })
  }
})

describe('CALIBRATION — danger detection is NOT weakened by the above', () => {
  const ctx1 = defaultContext({ pathname: '/', isHttps: true, stage: 1 })
  const ctx3 = defaultContext({ pathname: '/', isHttps: true, stage: 3 })
  const f = (id: string, sev: Finding['severity'], cat: Finding['category'], ev = '', vi?: boolean): Finding => ({
    id, severity: sev, category: cat, title: id, description: '', evidence: ev, fixPrompt: '', ...(vi ? { verifiedImpact: true } : {}),
  })

  // [label, findings, ctx, max score]. Golden findings (secrets/.env/RLS) → F;
  // dangerous CORS is a verified access-control failure → C territory (V6).
  const cases: [string, Finding[], typeof ctx1, number][] = [
    ['real Stripe key', [f('secret-stripe-app-js', 'critical', 'secrets', 'sk_live_…', true)], ctx1, 49],
    ['exposed .env w/ secret', [f('path--env', 'critical', 'paths', 'DB_PASSWORD=…', true)], ctx1, 49],
    ['confirmed Stage-3 RLS', [f('auth-rls-leak', 'critical', 'auth', '1200 rows', true)], ctx3, 49],
    ['dangerous CORS + creds', [f('headers-cors-wildcard', 'critical', 'headers', 'ACAO:* creds:true')], ctx1, 79],
  ]
  for (const [label, findings, ctx, maxScore] of cases) {
    it(`${label} → ≤${maxScore}`, () => {
      const out = applyEngine(findings, ctx)
      assert.ok(out.vibeScore <= maxScore, `${label} must be ≤${maxScore}, got ${out.vibeScore}`)
    })
  }
  it('WAF cannot rescue a verified .env (Cloudflare + .env still F)', () => {
    const out = applyEngine(
      [f('path--env', 'critical', 'paths', 'DB_PASSWORD=…', true)],
      defaultContext({ pathname: '/', isHttps: true, stage: 1, wafPresent: true }),
    )
    assert.ok(out.vibeScore <= 49, `got ${out.vibeScore}`)
    assert.equal(out.grade, 'F')
    assert.equal(out.scoreBreakdown.wafBonus, undefined, 'no WAF bonus with verified impact')
  })
})
