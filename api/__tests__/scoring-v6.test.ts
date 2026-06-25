/**
 * V6 regression tests (2026-06-13) — risk-based scoring redesign.
 *
 * Locks the V6 spec: four weighted risk categories, Verified/Likely/Possible
 * confidence (100/60/20%), business-impact context, Golden Findings, the
 * grade-cap rule (verified cap-set kind ⇒ max C), recon zero-impact, WAF as
 * bonus-only, the new grade scale (D 60–69, F 0–59, no A+), and the
 * perfect-score gate.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { applyEngine, defaultContext } from '../_lib/scoring-engine.ts'
import {
  CONFIDENCE_MULT,
  gradeForScore,
  normalizeConfidence,
  scoreTierForScore,
} from '../_lib/scoring-policy.ts'
import type { Finding } from '../../src/lib/scanner-types.ts'

const ctx1 = defaultContext({ pathname: '/', isHttps: true, stage: 1 })
const ctx3 = defaultContext({ pathname: '/', isHttps: true, stage: 3 })

function f(p: Partial<Finding> & { id: string; severity: Finding['severity']; category: Finding['category'] }): Finding {
  return {
    title: p.title ?? p.id,
    description: p.description ?? '',
    evidence: p.evidence ?? '',
    fixPrompt: p.fixPrompt ?? '',
    ...p,
  } as Finding
}

// ---------------------------------------------------------------------------
// Grade scale + tiers
// ---------------------------------------------------------------------------
describe('V6 — grade scale (A 90+ · B 80 · C 70 · D 60 · F <60, no A+)', () => {
  it('boundaries map exactly', () => {
    assert.equal(gradeForScore(100), 'A')
    assert.equal(gradeForScore(90), 'A')
    assert.equal(gradeForScore(89), 'B')
    assert.equal(gradeForScore(80), 'B')
    assert.equal(gradeForScore(79), 'C')
    assert.equal(gradeForScore(70), 'C')
    assert.equal(gradeForScore(69), 'D')
    assert.equal(gradeForScore(60), 'D')
    assert.equal(gradeForScore(59), 'F')
    assert.equal(gradeForScore(0), 'F')
  })
  it('score tiers: 90-94 excellent · 95-99 outstanding · 100 exceptional', () => {
    assert.equal(scoreTierForScore(92), 'excellent')
    assert.equal(scoreTierForScore(97), 'outstanding')
    assert.equal(scoreTierForScore(100), 'exceptional')
    assert.equal(scoreTierForScore(89), undefined)
  })
  it('legacy confidence spellings normalize', () => {
    assert.equal(normalizeConfidence('confirmed'), 'verified')
    assert.equal(normalizeConfidence('likely'), 'likely')
    assert.equal(normalizeConfidence('informational'), 'possible')
    assert.equal(normalizeConfidence(undefined), 'possible')
  })
})

// ---------------------------------------------------------------------------
// SCORE-CAP RULE — every verified cap-set kind ⇒ max grade C (≤79)
// ---------------------------------------------------------------------------
describe('V6 — grade-cap rule: verified {IDOR, RLS, SQLi, .env, DB dump, service-role, RCE} ⇒ ≤ C', () => {
  const cases: [string, Finding, typeof ctx1][] = [
    ['IDOR', f({ id: 'auth-idor-rls', severity: 'critical', category: 'auth', evidence: 'row 17 of another user returned' }), ctx3],
    ['RLS bypass', f({ id: 'auth-rls-leak', severity: 'critical', category: 'auth', evidence: 'anon SELECT 1200 rows' }), ctx3],
    ['SQLi (verified, Stage 3)', f({ id: 'stage3-sqli', severity: 'critical', category: 'paths', evidence: 'extracted version() via UNION' }), ctx3],
    ['.env exposed', f({ id: 'paths-env', severity: 'critical', category: 'paths', evidence: 'DB_PASSWORD=secret' }), ctx1],
    ['DB dump exposed', f({ id: 'path--database-sql', severity: 'critical', category: 'paths', evidence: 'CREATE TABLE users…' }), ctx1],
    ['service-role key', f({ id: 'secret-supabase-service-role-app-js', severity: 'critical', category: 'secrets', evidence: 'role=service_role eyJ…' }), ctx1],
    ['RCE', f({ id: 'stage3-rce', severity: 'critical', category: 'paths', evidence: 'id command output returned' }), ctx3],
  ]
  for (const [label, finding, ctx] of cases) {
    it(`${label} → score ≤ 79, golden, cap surfaced`, () => {
      const out = applyEngine([finding], ctx)
      assert.ok(out.vibeScore <= 79, `${label}: got ${out.vibeScore}`)
      assert.ok(['C', 'D', 'F'].includes(out.grade), `${label}: got ${out.grade}`)
      assert.equal(out.findings[0].isGoldenFinding, true, `${label} must be a Golden Finding`)
      assert.ok(out.scoreBreakdown.hardCap, `${label}: cap must surface in breakdown`)
    })
  }

  it('the cap is an upper bound — penalties still drive verified .env to F', () => {
    const out = applyEngine(
      [f({ id: 'paths-env', severity: 'critical', category: 'paths', evidence: 'DB_PASSWORD=secret' })],
      ctx1,
    )
    assert.ok(out.vibeScore <= 49, `got ${out.vibeScore}`)
    assert.equal(out.grade, 'F')
  })

  it('UNVERIFIED cap-set kind does not trigger the cap (likely SQLi → D by penalty only)', () => {
    const out = applyEngine(
      [f({ id: 'paths-sqli', severity: 'critical', category: 'paths', evidence: 'syntax error near' })],
      ctx1,
    )
    // No hardCap from the golden rule (the finding is likely, not verified).
    assert.equal(out.scoreBreakdown.hardCap, undefined)
    assert.ok(out.vibeScore >= 50 && out.vibeScore <= 69, `got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// Confidence multipliers — verified 1.0 / likely 0.6 / possible 0.2
// ---------------------------------------------------------------------------
describe('V6 — confidence system', () => {
  it('multipliers are exactly 1.0 / 0.6 / 0.2', () => {
    assert.equal(CONFIDENCE_MULT.verified, 1.0)
    assert.equal(CONFIDENCE_MULT.likely, 0.6)
    assert.equal(CONFIDENCE_MULT.possible, 0.2)
  })

  it('same kind, three evidence levels → three distinct score tiers', () => {
    // Verified SQLi (Stage 3 exploitation) — golden at full weight.
    const verified = applyEngine(
      [f({ id: 'stage3-sqli', severity: 'critical', category: 'paths', evidence: 'UNION extraction' })], ctx3)
    // Likely SQLi (error signature) — golden base × 0.6.
    const likely = applyEngine(
      [f({ id: 'paths-sqli', severity: 'critical', category: 'paths', evidence: 'syntax error near' })], ctx1)
    // Possible XSS (reflected canary) — non-golden exploit × 0.2.
    const possible = applyEngine(
      [f({ id: 'paths-xss-reflected', severity: 'critical', category: 'paths', evidence: 'canary reflected' })], ctx1)
    assert.ok(verified.vibeScore < likely.vibeScore, `${verified.vibeScore} < ${likely.vibeScore}`)
    assert.ok(likely.vibeScore < possible.vibeScore, `${likely.vibeScore} < ${possible.vibeScore}`)
    assert.ok(verified.vibeScore <= 49, 'verified exploitation is F territory')
    assert.ok(possible.vibeScore >= 90, 'a possible finding alone must not tank the site')
  })

  it('secret PATTERN without detector confirmation is not verified (AST heuristic)', () => {
    const out = applyEngine(
      [f({ id: 'js-ast-hardcoded-creds', severity: 'critical', category: 'secrets', evidence: '{ apiKey: "…" }' })],
      ctx1,
    )
    assert.notEqual(out.findings[0].confidence, 'verified')
    assert.equal(out.findings[0].verifiedImpact, false)
  })
})

// ---------------------------------------------------------------------------
// Business-impact context
// ---------------------------------------------------------------------------
describe('V6 — business impact scales the penalty', () => {
  it('the same runtime data exposure is worse on an admin route than the homepage', () => {
    const finding = () => f({ id: 'stage2-sensitive-data-exposure', severity: 'critical', category: 'auth-disclosure',
      evidence: 'response leaked records' })
    const onAdmin = applyEngine([finding()], defaultContext({ pathname: '/admin', isHttps: true, stage: 2 }))
    const onHome = applyEngine([finding()], defaultContext({ pathname: '/', isHttps: true, stage: 2 }))
    assert.ok(onAdmin.vibeScore < onHome.vibeScore,
      `admin ${onAdmin.vibeScore} must be worse than home ${onHome.vibeScore}`)
    assert.equal(onAdmin.findings[0].businessImpact, 'adminInternal')
  })

  it('business context never rescues a verified golden finding (floor at 1.0×)', () => {
    const out = applyEngine(
      [f({ id: 'paths-env', severity: 'critical', category: 'paths', evidence: 'DB_PASSWORD=secret' })],
      defaultContext({ pathname: '/about', isHttps: true, stage: 1 }),
    )
    assert.ok(out.vibeScore <= 49, `verified .env on a public route is still F, got ${out.vibeScore}`)
  })

  it('payment-grade secret (sk_live_) classifies financial and scores worse than a generic one', () => {
    const stripe = applyEngine(
      [f({ id: 'secret-stripe-app-js', severity: 'critical', category: 'secrets', evidence: 'sk_live_a1b2…' })], ctx1)
    assert.equal(stripe.findings[0].businessImpact, 'financial')
    assert.ok(stripe.vibeScore <= 30, `got ${stripe.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// Recon — zero score impact
// ---------------------------------------------------------------------------
describe('V6 — recon findings have zero score impact', () => {
  it('robots/sitemap/swagger/graphql/framework/WAF/health/anon-key → 100 (exceptional)', () => {
    const out = applyEngine([
      f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
      f({ id: 'paths-sitemap', severity: 'info', category: 'paths' }),
      f({ id: 'paths-swagger', severity: 'warn', category: 'paths' }),
      f({ id: 'paths-graphql', severity: 'info', category: 'paths' }),
      f({ id: 'meta-framework', severity: 'info', category: 'meta', evidence: 'Next.js 15' }),
      f({ id: 'meta-waf-detected', severity: 'info', category: 'meta', evidence: 'Cloudflare' }),
      f({ id: 'paths-status', severity: 'info', category: 'paths', evidence: 'GET /api/health 200' }),
      f({ id: 'secrets-supabase-anon-key', severity: 'critical', category: 'secrets', evidence: 'supabase_anon_key=eyJ…' }),
    ], ctx1)
    assert.equal(out.vibeScore, 100, `recon must not deduct, got ${out.vibeScore}`)
    assert.equal(out.grade, 'A')
    assert.equal(out.scoreBreakdown.scoreTier, 'exceptional')
    for (const x of out.findings) {
      assert.equal(x.riskCategory, 'recon', `${x.id} should be recon, got ${x.riskCategory}`)
    }
  })
})

// ---------------------------------------------------------------------------
// Posture clamp — the literal 5% weight
// ---------------------------------------------------------------------------
describe('V6 — posture clamp', () => {
  it('30 hardening findings together deduct at most 5 points', () => {
    const findings = [
      ...Array.from({ length: 10 }, (_, i) => f({ id: `headers-csp-weak-${i}`, severity: 'warn', category: 'headers' })),
      ...Array.from({ length: 10 }, (_, i) => f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies', evidence: `c${i}=1` })),
      ...Array.from({ length: 10 }, (_, i) => f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers', evidence: `h${i}` })),
    ]
    const out = applyEngine(findings, ctx1)
    assert.ok(out.vibeScore >= 95, `posture clamp must hold, got ${out.vibeScore}`)
    assert.ok(out.vibeScore <= 99, 'but deductions exist, so no perfect 100')
    const posture = out.scoreBreakdown.riskCategories?.find((c) => c.category === 'posture')
    assert.ok(posture, 'posture bucket must appear in the breakdown')
    assert.ok(posture!.penalty <= 5.05, `posture penalty ${posture!.penalty} must respect the 5-point budget`)
  })

  it('a VERIFIED posture finding (critical CVE match) is not muted by the clamp', () => {
    const out = applyEngine([
      f({ id: 'deps-server-cve-CVE-2024-1234', severity: 'critical', category: 'deps',
          evidence: 'Server: nginx/1.14.0 — CVE-2024-1234' }),
      ...Array.from({ length: 8 }, (_, i) => f({ id: `headers-csp-weak-${i}`, severity: 'warn', category: 'headers' })),
    ], ctx1)
    const posture = out.scoreBreakdown.riskCategories?.find((c) => c.category === 'posture')
    assert.ok(posture!.penalty > 5, `verified CVE must exceed the hardening budget, got ${posture!.penalty}`)
    assert.ok(out.vibeScore < 95, `got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// WAF policy — bonus only
// ---------------------------------------------------------------------------
describe('V6 — WAF policy', () => {
  const hardening = () => [
    f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
    f({ id: 'headers-no-hsts', severity: 'warn', category: 'headers' }),
    f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies' }),
    f({ id: 'integrity-no-sri', severity: 'warn', category: 'integrity' }),
    f({ id: 'dns-no-dnssec', severity: 'info', category: 'dns' }),
    f({ id: 'email-spf-soft-fail', severity: 'info', category: 'email' }),
    f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
    f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
  ]

  it('WAF present → small bonus (visible on a site with an unverified risk)', () => {
    const findings = () => [
      ...hardening(),
      f({ id: 'stage2-localstorage-auth-tokens', severity: 'warn', category: 'cookies',
          evidence: 'sb-x-auth-token in localStorage' }),
    ]
    const without = applyEngine(findings(), ctx1)
    const withWaf = applyEngine(findings(), defaultContext({ pathname: '/', isHttps: true, stage: 1, wafPresent: true }))
    assert.ok(withWaf.vibeScore > without.vibeScore,
      `WAF should add a bonus: ${withWaf.vibeScore} vs ${without.vibeScore}`)
    assert.equal(withWaf.scoreBreakdown.wafBonus, 2)
  })

  it('the synthetic meta-waf-detected finding also triggers the bonus', () => {
    const out = applyEngine(
      [...hardening(), f({ id: 'meta-waf-detected', severity: 'info', category: 'meta', evidence: 'Cloudflare' })],
      ctx1,
    )
    assert.equal(out.scoreBreakdown.wafBonus, 2)
  })

  it('Cloudflare + exposed .env still scores F — no bonus with verified impact', () => {
    const out = applyEngine(
      [f({ id: 'paths-env', severity: 'critical', category: 'paths', evidence: 'DB_PASSWORD=secret' })],
      defaultContext({ pathname: '/', isHttps: true, stage: 1, wafPresent: true }),
    )
    assert.ok(out.vibeScore <= 49, `got ${out.vibeScore}`)
    assert.equal(out.grade, 'F')
    assert.equal(out.scoreBreakdown.wafBonus, undefined)
  })

  it('no WAF → no penalty (a clean site without WAF can still hit 100)', () => {
    const out = applyEngine(
      [f({ id: 'secrets-clean', severity: 'ok', category: 'secrets' })],
      ctx1,
    )
    assert.equal(out.vibeScore, 100)
  })
})

// ---------------------------------------------------------------------------
// Breakdown shape — the 4-category scorecard
// ---------------------------------------------------------------------------
describe('V6 — risk-category breakdown', () => {
  it('riskCategories carries weights and per-bucket penalties that explain the score', () => {
    const out = applyEngine([
      f({ id: 'paths-env', severity: 'critical', category: 'paths', evidence: 'DB_PASSWORD=secret' }),
      f({ id: 'paths-sqli', severity: 'critical', category: 'paths', evidence: 'syntax error' }),
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
      f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
    ], ctx1)
    const rcs = out.scoreBreakdown.riskCategories!
    const byCat = Object.fromEntries(rcs.map((c) => [c.category, c]))
    assert.equal(byCat.data.weight, 0.4)
    assert.ok(byCat.data.penalty >= 60, 'verified .env dominates the data bucket')
    assert.equal(byCat.exploit.weight, 0.25)
    assert.ok(byCat.exploit.penalty > 30, 'likely SQLi lands in exploit')
    assert.ok(byCat.posture.penalty <= 5.05)
    assert.equal(byCat.recon.penalty, 0)
    const sum = rcs.reduce((a, c) => a + c.penalty, 0)
    assert.ok(Math.abs(Math.max(0, 100 - sum) - out.scoreBreakdown.rawScore) <= 1.5,
      `scorecard must reconcile: max(0, 100 − ${sum}) ≈ ${out.scoreBreakdown.rawScore}`)
  })
})
