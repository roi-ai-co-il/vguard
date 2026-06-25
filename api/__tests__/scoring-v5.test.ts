/**
 * v5 regression tests (2026-06-07) — exposure-scoring brain.
 *
 * These use the REAL ids the detectors emit (`secret-stripe-<file>`,
 * `path--env`, `paths-reflected-xss`, `headers-cors-wildcard`,
 * `headers-content-security-policy`, `auth-rls-leak`, …), NOT the policy-shaped
 * ids the old tests used. They lock the audit's root bugs as fixed: before this
 * work the gate matched the wrong strings, so real leaks scored ~79/C and
 * missing baseline headers scored medium instead of low.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { applyEngine, defaultContext } from '../_lib/scoring-engine.ts'
import { deriveFindingTraits } from '../_lib/finding-traits.ts'
import { deriveTargetProfile, computeCoverage, type TargetSignals } from '../_lib/target-profile.ts'
import { decideScanIntensity, decideProbeExpansion } from '../_lib/scan-orchestrator-policy.ts'
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

const cls = (out: ReturnType<typeof applyEngine>, i = 0) => out.findings[i].riskClass

// ---------------------------------------------------------------------------
// A/B/C — professional / enterprise site, only hardening gaps → not punished,
// not auto-90, no fake criticals.
// ---------------------------------------------------------------------------
describe('A/B/C — professional site with only hardening gaps', () => {
  it('advanced headers missing → low/info, lands in B/A band, no critical', () => {
    const out = applyEngine(
      [
        f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-referrer-policy', severity: 'info', category: 'headers' }),
        f({ id: 'tls-https', severity: 'ok', category: 'tls' }),
      ],
      ctx1,
    )
    assert.ok(out.vibeScore >= 85, `score ${out.vibeScore} should stay >= 85`)
    assert.equal(out.hasVerifiedImpact, false)
    assert.ok(out.findings.every((x) => x.riskClass !== 'critical-exploit'))
  })

  it('one real weakness drops the score normally (no brand protection exists)', () => {
    // V6: an SQL error signature is LIKELY SQLi (suspected ≠ verified) — it
    // drops the site to D territory; verified exploitation would be F.
    const out = applyEngine(
      [f({ id: 'paths-sqli-error', severity: 'critical', category: 'paths', evidence: 'SQL syntax error near' })],
      ctx1,
    )
    assert.ok(out.vibeScore <= 65, `likely SQLi must drop hard, got ${out.vibeScore}`)
    assert.ok(['D', 'F'].includes(out.grade), `got ${out.grade}`)
  })
})

// ---------------------------------------------------------------------------
// D — small business missing CSP/HSTS/XFO ONLY (the headline mis-calibration).
// ---------------------------------------------------------------------------
describe('D — missing CSP/HSTS/X-Frame-Options only', () => {
  it('REAL ids classify as low-hardening, land in B (~80s), never critical', () => {
    const out = applyEngine(
      [
        f({ id: 'headers-content-security-policy', severity: 'warn', category: 'headers' }),
        f({ id: 'headers-strict-transport-security', severity: 'warn', category: 'headers' }),
        f({ id: 'headers-x-frame-options', severity: 'warn', category: 'headers' }),
      ],
      ctx1,
    )
    assert.ok(out.findings.every((x) => x.riskClass === 'low-hardening'), 'all three must be low-hardening')
    assert.ok(out.vibeScore >= 80, `should be high-80s/B, got ${out.vibeScore}`)
    assert.ok(['A', 'B'].includes(out.grade), `grade ${out.grade} should be A/B`)
    assert.equal(out.hasVerifiedImpact, false)
  })
})

// ---------------------------------------------------------------------------
// E — public anon key only → not a real secret.
// ---------------------------------------------------------------------------
describe('E — public anon/client key only', () => {
  it('public client identifier is informational, no score damage', () => {
    const out = applyEngine(
      [f({ id: 'secret-supabase-anon-app-js', severity: 'critical', category: 'secrets', evidence: 'VITE_SUPABASE_ANON_KEY=eyJhbGc…' })],
      ctx1,
    )
    assert.equal(cls(out), 'informational')
    assert.equal(out.findings[0].verifiedImpact, false)
    assert.ok(out.vibeScore >= 85, `anon key alone must not damage score, got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// F — real provider secret leaks → critical-exploit, ≤49/F.
// ---------------------------------------------------------------------------
describe('F — real provider secret leak (was 79/C before the fix)', () => {
  for (const id of [
    'secret-stripe-app-bundle-js',
    'secret-openai-main-js',
    'secret-aws-vendor-js',
    'secret-anthropic-chunk-js',
    'secret-supabase-service-role-app-js',
  ]) {
    it(`${id} → critical-exploit, verified impact, ≤49`, () => {
      const out = applyEngine(
        [f({ id, severity: 'critical', category: 'secrets', evidence: 'app.js → "sk_live_a…b12"' })],
        ctx1,
      )
      assert.equal(cls(out), 'critical-exploit', `${id} must be critical-exploit`)
      assert.equal(out.findings[0].verifiedImpact, true)
      assert.equal(out.findings[0].impactType, 'credentialExposure')
      assert.ok(out.vibeScore <= 49, `${id} must be ≤49, got ${out.vibeScore}`)
      assert.equal(out.grade, 'F')
    })
  }
})

// ---------------------------------------------------------------------------
// G/H — exposed .env: real secret → F; SPA-shell / needs-review → not F.
// ---------------------------------------------------------------------------
describe('G/H — exposed .env real vs false-positive', () => {
  it('G: path--env critical (real secret in body) → critical-exploit, ≤49', () => {
    const out = applyEngine(
      [f({ id: 'path--env', severity: 'critical', category: 'paths', evidence: 'GET /.env → 200\nMatched redacted: DB_PASSW…x9z2' })],
      ctx1,
    )
    assert.equal(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore <= 49)
  })

  it('H1: path--env-spa-shell-200 (info) → informational, no fake F', () => {
    const out = applyEngine(
      [f({ id: 'path--env-spa-shell-200', severity: 'info', category: 'paths' })],
      ctx1,
    )
    assert.notEqual(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore >= 85)
  })

  it('H2: path--env-exposed-needs-review (warn) → not critical, not F', () => {
    const out = applyEngine(
      [f({ id: 'path--env-exposed-needs-review', severity: 'warn', category: 'paths' })],
      ctx1,
    )
    assert.notEqual(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore >= 70, `needs-review should not be F, got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// I — XSS classification (V6): reflected canary = Possible XSS; browser
// execution = Verified XSS (golden).
// ---------------------------------------------------------------------------
describe('I — XSS classification', () => {
  it('paths-reflected-xss → Possible XSS: likely-risks, dents without tanking', () => {
    const out = applyEngine(
      [f({ id: 'paths-reflected-xss', severity: 'critical', category: 'paths', evidence: 'canary reflected unescaped in ?q=' })],
      ctx1,
    )
    assert.equal(out.findings[0].verifiedImpact, false)
    assert.equal(out.findings[0].confidence, 'possible')
    assert.equal(cls(out), 'high-impact-misconfig')
    assert.ok(out.vibeScore >= 80, `got ${out.vibeScore}`)
  })

  it('paths-aggressive-xss (browser-executed) → Verified XSS: golden, F', () => {
    const out = applyEngine(
      [f({ id: 'paths-aggressive-xss', severity: 'critical', category: 'paths', evidence: 'payload executed in browser' })],
      ctx3,
    )
    assert.equal(out.findings[0].verifiedImpact, true)
    assert.equal(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore <= 49)
  })
})

// ---------------------------------------------------------------------------
// J — Stage 3 confirmed RLS public data exposure (was 80/B before).
// ---------------------------------------------------------------------------
describe('J — Stage 3 confirmed RLS public data exposure', () => {
  it('auth-rls-leak (stage 3) → critical-exploit, ≤49/F, not 80/B', () => {
    const out = applyEngine(
      [f({ id: 'auth-rls-leak', severity: 'critical', category: 'auth', evidence: 'anon SELECT * FROM users → 1,240 rows' })],
      ctx3,
    )
    assert.equal(out.findings[0].verifiedImpact, true)
    assert.equal(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore <= 49, `confirmed RLS breach must be F, got ${out.vibeScore}`)
    assert.equal(out.grade, 'F')
  })
})

// ---------------------------------------------------------------------------
// K — dangerous CORS: wildcard-only ≠ critical; wildcard + creds = critical.
// ---------------------------------------------------------------------------
describe('K — CORS', () => {
  it('headers-cors-wildcard info (no credentials) → informational, no damage', () => {
    const out = applyEngine(
      [f({ id: 'headers-cors-wildcard', severity: 'info', category: 'headers', evidence: 'Access-Control-Allow-Origin: *' })],
      ctx1,
    )
    assert.notEqual(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore >= 85)
  })

  it('headers-cors-wildcard critical (+credentials) → verified access-control failure, ≤ C', () => {
    // V6: dangerous CORS is a verified access-control misconfig (not a golden
    // finding) — it lands the site in C territory, not auto-F.
    const out = applyEngine(
      [f({ id: 'headers-cors-wildcard', severity: 'critical', category: 'headers', evidence: 'ACAO:* + Allow-Credentials:true' })],
      ctx1,
    )
    assert.equal(out.findings[0].verifiedImpact, true)
    assert.equal(cls(out), 'critical-exploit')
    assert.ok(out.vibeScore <= 79, `got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// L — many low hardening issues: decay/caps prevent collapse; a real medium
// prevents 90+; never F without verified impact.
// ---------------------------------------------------------------------------
describe('L — many low hardening issues', () => {
  it('8 hardening gaps → capped, stays ≥ 80, never F, no critical', () => {
    const out = applyEngine(
      [
        f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-cross-origin-embedder-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-cross-origin-resource-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
        f({ id: 'integrity-no-sri', severity: 'warn', category: 'integrity' }),
        f({ id: 'dns-no-dnssec', severity: 'info', category: 'dns' }),
        f({ id: 'dns-no-caa', severity: 'info', category: 'dns' }),
        f({ id: 'email-spf-soft-fail', severity: 'info', category: 'email' }),
      ],
      ctx1,
    )
    assert.ok(out.vibeScore >= 80, `lows must not collapse the score, got ${out.vibeScore}`)
    assert.notEqual(out.grade, 'F')
    assert.ok(out.findings.every((x) => x.riskClass !== 'critical-exploit'))
  })

  it('mixed content classifies medium-weakness but scores as posture (V6: minimal influence)', () => {
    // V6: mixed content surfaces in needs-review, but as a posture finding it
    // shares the literal 5-point hardening budget — never below the A band on
    // its own, and never a perfect 100 either.
    const out = applyEngine(
      [
        f({ id: 'mixed-content', severity: 'warn', category: 'mixed-content', evidence: 'http://cdn/app.js on https page' }),
        f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
      ],
      ctx1,
    )
    assert.equal(out.findings[0].riskClass, 'medium-weakness')
    assert.ok(out.vibeScore >= 90 && out.vibeScore <= 99, `got ${out.vibeScore}`)
  })
})

// ---------------------------------------------------------------------------
// M/N — adaptive orchestration policy.
// ---------------------------------------------------------------------------
describe('M/N — adaptive scan intensity', () => {
  it('M: verified impact → deep + escalation recommendation', () => {
    const d = decideScanIntensity(40, 'vibeCodedApp', true, false)
    assert.equal(d.scanIntensityUsed, 'deep')
    assert.match(d.recommendedNextStep, /Stage 3|verify/i)
  })

  it('N: high score, static site → concise, no over-scan', () => {
    const d = decideScanIntensity(96, 'staticMarketingSite', false, false)
    assert.equal(d.scanIntensityUsed, 'concise')
  })

  it('WAF-limited → standard + Stage 2 recommendation (never inflate)', () => {
    const d = decideScanIntensity(85, 'wafLimitedTarget', false, false)
    assert.match(d.recommendedNextStep, /Stage 2/i)
  })
})

describe('v5.4 — professional sites not punished by Stage-2 noise (the "Apple got 43" fix)', () => {
  // The word "auth" in our OWN description must not make an analytics cookie High.
  it('analytics cookie (auth only in description prose) → low-hardening, not High', () => {
    const out = applyEngine(
      [f({ id: 'stage2-cookie-long-lived', severity: 'warn', category: 'cookies',
           evidence: 'dssid2 (expires in ~365 days)',
           description: 'Auth-shaped cookies that live past 30 days expand the replay window.' })],
      ctx1,
    )
    assert.equal(out.findings[0].riskClass, 'low-hardening')
    assert.ok(out.vibeScore >= 90, `analytics cookie must not tank score, got ${out.vibeScore}`)
  })

  // v5.5: cookie flags (even on a real session cookie) are DEFENSE-IN-DEPTH —
  // a missing HttpOnly is only exploitable WITH another vuln (XSS). It deducts
  // as hardening and is shown with a fix prompt, but never caps the grade. This
  // is the deliberate call after Apple AND Palo Alto were graded C for cookies.
  it('real session cookie missing HttpOnly → hardening, never caps the grade', () => {
    const out = applyEngine(
      [f({ id: 'stage2-cookie-not-httponly', severity: 'warn', category: 'cookies',
           evidence: 'session=eyJhbGc...; auth_token=eyJ...' })],
      ctx1,
    )
    assert.equal(out.findings[0].riskClass, 'low-hardening')
    assert.ok(out.vibeScore >= 90, `cookie flag must not cap, got ${out.vibeScore}`)
  })

  it('stage2-unauth-api-calls → low-hardening (audit item), never caps the grade', () => {
    const out = applyEngine(
      [f({ id: 'stage2-unauth-api-calls', severity: 'warn', category: 'auth',
           evidence: 'GET /api-www/.../flyouts → 200' })],
      ctx1,
    )
    assert.equal(out.findings[0].riskClass, 'low-hardening')
    assert.ok(out.vibeScore >= 90, `unauth GET of public data must not cap, got ${out.vibeScore}`)
  })

  it('Apple-like: many hardening gaps across categories, no real weakness → A band (≥88)', () => {
    const F = (id: string, sev: Finding['severity'], cat: Finding['category'], ev = '') =>
      f({ id, severity: sev, category: cat, evidence: ev })
    const out = applyEngine([
      F('headers-csp-weak', 'warn', 'headers', "unsafe-inline"),
      F('headers-permissions-policy', 'info', 'headers'),
      F('headers-cross-origin-opener-policy', 'info', 'headers'),
      F('integrity-no-sri', 'warn', 'integrity'),
      F('html-inline-xss-surface', 'warn', 'html'),
      F('js-ast-dom-sink', 'info', 'html'),
      F('dns-no-dnssec', 'info', 'dns'),
      F('email-spf-soft-fail', 'info', 'email'),
      F('stage2-unauth-api-calls', 'warn', 'auth', 'GET /.../flyouts → 200'),
      F('stage2-cookie-long-lived', 'warn', 'cookies', 'dssid2 (expires ~365d)'),
      F('stage2-cookie-insecure', 'warn', 'cookies', 'geo (httpOnly=false)'),
    ], defaultContext({ pathname: '/', isHttps: true, stage: 2 }))
    assert.ok(out.vibeScore >= 88, `professional site w/ only hardening must be A-band, got ${out.vibeScore}`)
    assert.equal(out.hasVerifiedImpact, false)
    assert.ok(out.findings.every((x) => x.riskClass !== 'critical-exploit' && x.riskClass !== 'high-impact-misconfig'))
  })
})

describe('v5.3 — adaptive probe depth (work harder on risky targets)', () => {
  const base = { secretAlreadyFound: false, hasBackend: false, hasLoginSurface: false, hasAppShell: false }
  it('plain static site → baseline only (concise, fast)', () => {
    assert.equal(decideProbeExpansion(base), false)
  })
  it('any risk signal → expand the probe set', () => {
    assert.equal(decideProbeExpansion({ ...base, hasBackend: true }), true)
    assert.equal(decideProbeExpansion({ ...base, hasLoginSurface: true }), true)
    assert.equal(decideProbeExpansion({ ...base, hasAppShell: true }), true)
    assert.equal(decideProbeExpansion({ ...base, secretAlreadyFound: true }), true)
  })
})

// ---------------------------------------------------------------------------
// Target profile + coverage — observable only, no brand list, honest coverage.
// ---------------------------------------------------------------------------
describe('target profile + coverage (no brand whitelist)', () => {
  const base: TargetSignals = {
    framework: null,
    hasAppShell: false,
    hasLoginSurface: false,
    hasApiSurface: false,
    hasCheckout: false,
    hasAdminRoute: false,
    usesSupabase: false,
    usesFirebase: false,
    usesS3: false,
    vibeStackTrace: false,
    thirdPartyScriptCount: 0,
    bundleCount: 0,
    isSharedPlatform: false,
    hasProfessionalEdge: false,
    coverageBlocked: false,
    subdomainCount: 0,
  }

  it('Supabase app shell → vibeCodedApp; coverage lowered by untested backend', () => {
    const s = { ...base, hasAppShell: true, hasLoginSurface: true, usesSupabase: true, bundleCount: 3 }
    assert.equal(deriveTargetProfile(s), 'vibeCodedApp')
    const cov = computeCoverage(s, false)
    assert.ok(cov.coverageScore < 80, 'app w/ login+backend must not claim full coverage')
  })

  it('static site → high coverage/confidence for its context', () => {
    const cov = computeCoverage(base, false)
    assert.equal(cov.coverageScore, 100)
    assert.equal(cov.scanConfidence, 'high')
    assert.equal(deriveTargetProfile(base), 'staticMarketingSite')
  })

  it('WAF block lowers confidence, not the score', () => {
    const cov = computeCoverage({ ...base, coverageBlocked: true }, false)
    assert.equal(cov.scanConfidence, 'low')
    assert.equal(deriveTargetProfile({ ...base, coverageBlocked: true }), 'wafLimitedTarget')
  })
})

// ---------------------------------------------------------------------------
// Direct gate check — finding-traits verifiedImpact on real ids.
// ---------------------------------------------------------------------------
describe('verified-impact gate fires on REAL emitted ids', () => {
  const cases: [string, Finding['severity'], Finding['category'], boolean][] = [
    ['secret-stripe-app-js', 'critical', 'secrets', true],
    ['secret-supabase-service-role-x', 'critical', 'secrets', true],
    ['path--env', 'critical', 'paths', true],
    ['paths-reflected-xss', 'critical', 'paths', false], // V6: reflection ≠ execution
    ['paths-aggressive-xss', 'critical', 'paths', true], // browser-executed
    ['paths-ssrf-confirmed', 'critical', 'paths', true],
    ['auth-rls-leak', 'critical', 'auth', true],
    ['headers-cors-wildcard', 'critical', 'headers', true],
    ['headers-content-security-policy', 'warn', 'headers', false],
    ['headers-x-frame-options', 'warn', 'headers', false],
    ['secret-supabase-anon-js', 'critical', 'secrets', false], // public client id
  ]
  for (const [id, severity, category, expected] of cases) {
    it(`${id} verifiedImpact === ${expected}`, () => {
      const evidence = id.includes('anon') ? 'VITE_SUPABASE_ANON_KEY=eyJ…' : 'redacted'
      const t = deriveFindingTraits(f({ id, severity, category, evidence }), id.startsWith('auth-rls') ? ctx3 : ctx1)
      assert.equal(t.verifiedImpact, expected)
    })
  }

  it('v5.2: a detector-declared verifiedImpact is honoured even on an UNKNOWN id', () => {
    // Architecture hardening: the gate no longer depends only on id matching.
    // A future/renamed detector that self-declares impact is trusted.
    const out = applyEngine(
      [f({ id: 'some-brand-new-detector-2027', severity: 'critical', category: 'secrets', evidence: 'redacted', verifiedImpact: true })],
      ctx1,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore <= 49)
  })
})
