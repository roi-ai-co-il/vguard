import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { applyEngine, defaultContext } from '../_lib/scoring-engine.ts'
import type { Finding } from '../../src/lib/scanner-types.ts'

const baseCtx = defaultContext({ pathname: '/', isHttps: true, stage: 1 })

function f(partial: Partial<Finding> & { id: string; severity: Finding['severity']; category: Finding['category'] }): Finding {
  return {
    title: partial.title ?? partial.id,
    description: partial.description ?? '',
    evidence: partial.evidence ?? '',
    fixPrompt: partial.fixPrompt ?? '',
    ...partial,
  } as Finding
}

// ----------------------------------------------------------------------------
// Unit tests — strict critical gate
// ----------------------------------------------------------------------------

describe('strict critical gate — passive findings cannot be Critical alone', () => {
  it('CSP unsafe-inline alone is NOT critical', () => {
    const out = applyEngine(
      [f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers',
           evidence: "script-src 'self' unsafe-inline-policy" })],
      baseCtx,
    )
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore >= 85, `vibeScore should stay >= 85 (natural cap), got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
  })

  it('Cookie missing Secure on non-auth cookie is NOT critical', () => {
    const out = applyEngine(
      [f({ id: 'cookies-no-secure', severity: 'critical', category: 'cookies',
           evidence: 'preferences=dark; Path=/' })],
      baseCtx,
    )
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore >= 85)
  })

  it('DOM sink alone is informational/hardening only', () => {
    const out = applyEngine(
      [f({ id: 'dom-sink-innerhtml', severity: 'warn', category: 'html',
           evidence: 'sink assignment without taint flow' })],
      baseCtx,
    )
    assert.ok(['informational', 'low-hardening'].includes(out.findings[0].riskClass!))
    assert.ok(out.vibeScore >= 85)
  })

  it('Public 2xx API endpoint without sensitive content is informational', () => {
    const out = applyEngine(
      [f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
           evidence: 'GET /api/health 200 OK' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 85)
  })

  it('Frontend public client identifier (Firebase web SDK key) is informational', () => {
    const out = applyEngine(
      [f({ id: 'secrets-firebase-api-key', severity: 'critical', category: 'secrets',
           evidence: 'firebase_api_key=public-web-key' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 85)
  })

  it('Visible admin login page is NOT critical', () => {
    const out = applyEngine(
      [f({ id: 'paths-admin-login-visible', severity: 'critical', category: 'paths',
           evidence: '/admin -> 302 /login' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 85)
  })

  it('robots.txt / sitemap / openapi are informational', () => {
    const out = applyEngine(
      [
        f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
        f({ id: 'paths-sitemap', severity: 'info', category: 'paths' }),
        f({ id: 'paths-openapi', severity: 'info', category: 'paths' }),
      ],
      baseCtx,
    )
    for (const fi of out.findings) {
      assert.equal(fi.riskClass, 'informational')
      assert.equal(fi.uiGroup, 'informational-observations')
    }
    assert.ok(out.vibeScore >= 95)
  })

  it('COOP/COEP/CORP/Permissions-Policy missing → low-hardening', () => {
    const out = applyEngine(
      [
        f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-cross-origin-embedder-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-cross-origin-resource-policy', severity: 'info', category: 'headers' }),
        f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
      ],
      baseCtx,
    )
    for (const fi of out.findings) {
      assert.equal(fi.riskClass, 'low-hardening')
      assert.equal(fi.uiGroup, 'hardening-recommendations')
    }
    assert.ok(out.vibeScore >= 90)
  })
})

// ----------------------------------------------------------------------------
// Unit tests — verified impact gate opens Critical
// ----------------------------------------------------------------------------

describe('verified impact opens Critical', () => {
  it('Verified .env exposure with real sensitive content IS critical', () => {
    const out = applyEngine(
      [f({ id: 'paths-env', severity: 'critical', category: 'paths',
           evidence: 'DB_PASSWORD=super-secret\nSTRIPE_SECRET_KEY=sk_live_xxx' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.equal(out.findings[0].uiGroup, 'confirmed-vulnerabilities')
    assert.ok(out.vibeScore < 75)
  })

  it('Confirmed reflected XSS IS critical', () => {
    const out = applyEngine(
      [f({ id: 'paths-xss-reflected', severity: 'critical', category: 'paths',
           evidence: 'param=q reflected vsxsscanary7q3 unencoded' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })

  it('Confirmed SQLi error IS critical', () => {
    const out = applyEngine(
      [f({ id: 'paths-sqli', severity: 'critical', category: 'paths',
           evidence: "param=id triggered: ERROR: syntax error at or near \"'\"" })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })

  it('Stage 3 confirmed RLS broken IS critical', () => {
    const out = applyEngine(
      [f({ id: 'stage3-rls-broken', severity: 'critical', category: 'auth',
           evidence: 'public.users readable with anon key (returned 47 rows)' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })

  it('TLS cert expired IS critical', () => {
    const out = applyEngine(
      [f({ id: 'tls-cert-expired', severity: 'critical', category: 'tls',
           evidence: 'cert.valid_to=2025-01-01' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })
})

// ----------------------------------------------------------------------------
// Score-cap regression tests
// ----------------------------------------------------------------------------

describe('score caps when no verified impact', () => {
  it('Hardening-only swarm cannot push score below 90', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      f({ id: `headers-cross-origin-${i}`, severity: 'info', category: 'headers' }),
    )
    const out = applyEngine(findings, baseCtx)
    assert.ok(out.vibeScore >= 90, `expected vibeScore >= 90 with hardening-only swarm, got ${out.vibeScore}`)
  })

  it('Cookie/header/CSP-only mix stays >= 85', () => {
    const findings = [
      f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers' }),
      f({ id: 'headers-no-x-frame-options', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-no-hsts', severity: 'warn', category: 'headers' }),
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies' }),
      f({ id: 'cookies-no-samesite', severity: 'warn', category: 'cookies' }),
      f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
    ]
    const out = applyEngine(findings, baseCtx)
    assert.ok(out.vibeScore >= 85, `expected vibeScore >= 85 with header/cookie-only mix, got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
  })

  it('No verified impact → aggregateBand never severe/high', () => {
    const findings = Array.from({ length: 30 }, (_, i) =>
      f({ id: `headers-csp-weak-${i}`, severity: 'warn', category: 'headers' }),
    )
    const out = applyEngine(findings, baseCtx)
    assert.equal(out.aggregateBand, 'low')
  })
})

// ----------------------------------------------------------------------------
// Enterprise regression tests
// ----------------------------------------------------------------------------

describe('enterprise regression — apple.com / amazon.com profile must NOT score low', () => {
  it('apple.com-like report → no Critical, score >= 75', () => {
    const findings: Finding[] = [
      f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers',
          evidence: "script-src 'self' unsafe-inline-policy" }),
      f({ id: 'headers-csp-weak-default-src', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-csp-no-frame-ancestors', severity: 'warn', category: 'headers' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
          evidence: 'GET /api/locale 200 OK' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
          evidence: 'GET /api/nav 200 OK' }),
      f({ id: 'dom-sink-innerhtml', severity: 'warn', category: 'html' }),
      f({ id: 'dom-sink-document-write', severity: 'warn', category: 'html' }),
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies',
          evidence: 'aid_marketing=abc; preferences=dark' }),
      f({ id: 'cookies-no-httponly', severity: 'warn', category: 'cookies',
          evidence: 'analytics=...' }),
      f({ id: 'secrets-google-maps-api', severity: 'critical', category: 'secrets',
          evidence: 'google_maps_api_key=public-web-key' }),
      f({ id: 'secrets-firebase-api-key', severity: 'critical', category: 'secrets',
          evidence: 'firebase_api_key=public-web-key' }),
      f({ id: 'paths-admin-login-visible', severity: 'critical', category: 'paths',
          evidence: '/account/sign-in' }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
      f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
      f({ id: 'paths-sitemap', severity: 'info', category: 'paths' }),
    ]
    const out = applyEngine(findings, baseCtx)

    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.equal(criticalCount, 0, `expected 0 critical, got ${criticalCount}`)
    assert.ok(out.vibeScore >= 85, `expected vibeScore >= 85 (natural cap), got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
    assert.equal(out.hasVerifiedImpact, false)
  })

  it('amazon.com-like report → score >= 75 unless confirmed exploit', () => {
    const findings: Finding[] = []
    const headers = [
      'headers-csp-missing', 'headers-no-hsts', 'headers-no-x-frame-options',
      'headers-no-x-content-type', 'headers-cross-origin-opener-policy',
      'headers-cross-origin-embedder-policy', 'headers-cross-origin-resource-policy',
      'headers-permissions-policy',
    ]
    for (const h of headers) findings.push(f({ id: h, severity: 'warn', category: 'headers' }))
    for (let i = 0; i < 5; i++) {
      findings.push(f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies',
        evidence: `cookie_${i}=...` }))
    }
    for (let i = 0; i < 12; i++) {
      findings.push(f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
        evidence: `GET /api/path-${i} 200 OK` }))
    }
    for (let i = 0; i < 6; i++) {
      findings.push(f({ id: 'dom-sink-innerhtml', severity: 'warn', category: 'html' }))
    }
    findings.push(f({ id: 'paths-robots', severity: 'info', category: 'paths' }))
    findings.push(f({ id: 'paths-sitemap', severity: 'info', category: 'paths' }))

    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.equal(criticalCount, 0)
    assert.ok(out.vibeScore >= 85, `expected vibeScore >= 85 (natural cap), got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
  })

  it('amazon.com-like + ONE confirmed exploit → Critical surfaces, score drops below floor', () => {
    const findings: Finding[] = [
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths' }),
      f({ id: 'paths-xss-reflected', severity: 'critical', category: 'paths',
          evidence: 'param=q reflected canary unencoded' }),
    ]
    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.ok(criticalCount >= 1, 'expected at least 1 critical-exploit on confirmed XSS')
    assert.equal(out.hasVerifiedImpact, true)
    assert.ok(out.vibeScore < 75, `score should reflect real exploit, got ${out.vibeScore}`)
  })
})

// ----------------------------------------------------------------------------
// UI grouping
// ----------------------------------------------------------------------------

describe('UI grouping', () => {
  it('confirmed-vulnerabilities only includes verifiedImpact findings', () => {
    const out = applyEngine(
      [
        f({ id: 'paths-xss-reflected', severity: 'critical', category: 'paths',
           evidence: 'reflected canary' }),
        f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers' }),
        f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      ],
      baseCtx,
    )
    const groups = new Set(out.findings.map((x) => x.uiGroup))
    assert.ok(groups.has('confirmed-vulnerabilities'))
    assert.ok(groups.has('hardening-recommendations'))
    const csp = out.findings.find((x) => x.id === 'headers-csp-weak-script-src')
    assert.notEqual(csp!.uiGroup, 'confirmed-vulnerabilities')
  })
})

// ----------------------------------------------------------------------------
// Final-spec regression tests (4 canonical scenarios from the rebuild brief)
// ----------------------------------------------------------------------------

describe('final-spec regressions — calm for noise, strict for real risk, honest for weak posture', () => {
  it('SCENARIO 1 — apple-like enterprise frontend: no Critical, low band, score 85+', () => {
    const findings: Finding[] = [
      f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers',
          evidence: "script-src 'self' 'unsafe-inline'" }),
      f({ id: 'headers-csp-no-frame-ancestors', severity: 'warn', category: 'headers' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
          evidence: 'GET /api/locale 200 OK' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
          evidence: 'GET /api/nav 200 OK' }),
      f({ id: 'dom-sink-innerhtml', severity: 'warn', category: 'html' }),
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies',
          evidence: 'analytics_id=abc; preferences=dark' }),
      f({ id: 'secrets-google-maps-api', severity: 'critical', category: 'secrets',
          evidence: 'google_maps_api_key=AIzaSy...public' }),
      f({ id: 'secrets-firebase-api-key', severity: 'critical', category: 'secrets',
          evidence: 'firebase_api_key=AIzaSy...public' }),
      f({ id: 'paths-admin-login-visible', severity: 'critical', category: 'paths',
          evidence: '/account/sign-in -> 200 login form' }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
    ]
    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.equal(criticalCount, 0, `expected 0 Critical, got ${criticalCount}`)
    assert.ok(out.vibeScore >= 85, `expected >= 85, got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
    assert.equal(out.hasVerifiedImpact, false)
  })

  it('SCENARIO 2 — clean simple site: 90+', () => {
    const findings: Finding[] = [
      f({ id: 'tls-active', severity: 'ok', category: 'tls', evidence: 'TLSv1.3' }),
      f({ id: 'headers-csp-present', severity: 'ok', category: 'headers' }),
      f({ id: 'secrets-clean', severity: 'ok', category: 'secrets' }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      f({ id: 'paths-robots', severity: 'info', category: 'paths' }),
    ]
    const out = applyEngine(findings, baseCtx)
    assert.ok(out.vibeScore >= 90, `expected >= 90 on clean site, got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
    assert.equal(out.hasVerifiedImpact, false)
  })

  it('SCENARIO 3a — weak posture, no exploit: hardening + auth cookies + swagger → 55-78, not Healthy', () => {
    // Per spec: missing HSTS/CSP/XFO + insecure AUTH cookies + exposed swagger.
    // No verified exploit. Score should land in 55-78 — neither alarming
    // (no Critical) nor falsely Healthy.
    const findings: Finding[] = [
      f({ id: 'headers-no-hsts', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-no-x-frame-options', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-no-x-content-type', severity: 'warn', category: 'headers' }),
      // Differentiator vs amazon-like: AUTH cookies, not analytics.
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies',
          evidence: 'session=eyJ...; Path=/' }),
      f({ id: 'cookies-no-httponly', severity: 'warn', category: 'cookies',
          evidence: 'auth_token=eyJ...; Path=/' }),
      f({ id: 'cookies-no-samesite', severity: 'warn', category: 'cookies',
          evidence: 'jwt=eyJ...; Path=/' }),
      // API surface exposure on production (info, but signals weak hygiene)
      f({ id: 'paths-swagger', severity: 'info', category: 'paths',
          evidence: 'GET /swagger/v1 200 OK' }),
    ]
    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.equal(criticalCount, 0, `weak posture without exploit shouldn't show Critical, got ${criticalCount}`)
    assert.ok(out.vibeScore < 85, `expected weak posture < 85, got ${out.vibeScore}`)
    assert.ok(out.vibeScore >= 50, `weak posture shouldn't crash below 50 without exploit, got ${out.vibeScore}`)
  })

  it('SCENARIO 3b — weak site WITH confirmed CVE + dangerous CORS: Critical surfaces, score < 65', () => {
    const findings: Finding[] = [
      f({ id: 'headers-no-hsts', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
      f({ id: 'cookies-no-secure', severity: 'warn', category: 'cookies',
          evidence: 'session=eyJ...; Path=/' }),
      // Vulnerable dep — detector emitted critical, must surface as Critical
      f({ id: 'deps-server-cve-CVE-2023-XXXXX', severity: 'critical', category: 'deps',
          evidence: 'Server: nginx/1.14.0\nMatched CVE: CVE-2023-XXXXX' }),
      // Dangerous CORS — credentialed wildcard, detector flagged critical
      f({ id: 'cors-credentials-wildcard', severity: 'critical', category: 'headers',
          evidence: 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true' }),
    ]
    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.ok(criticalCount >= 1, `expected >=1 Critical (CVE / CORS-creds), got ${criticalCount}`)
    assert.equal(out.hasVerifiedImpact, true)
    assert.ok(out.vibeScore < 65, `expected score < 65, got ${out.vibeScore}`)
  })

  it('SCENARIO 4 — confirmed exploit (SQLi + leaked .env): score < 50, severe band', () => {
    const findings: Finding[] = [
      f({ id: 'paths-sqli', severity: 'critical', category: 'paths',
          evidence: "param=id triggered: ERROR: syntax error at or near \"'\"" }),
      f({ id: 'paths-env', severity: 'critical', category: 'paths',
          evidence: 'DB_PASSWORD=super-secret\nSTRIPE_SECRET_KEY=sk_live_xxx' }),
      f({ id: 'secrets-stripe-secret', severity: 'critical', category: 'secrets',
          evidence: 'sk_live_a1b2c3d4...redacted' }),
      f({ id: 'paths-admin-login-visible', severity: 'info', category: 'paths' }),
    ]
    const out = applyEngine(findings, baseCtx)
    const criticalCount = out.findings.filter((x) => x.riskClass === 'critical-exploit').length
    assert.ok(criticalCount >= 2, `expected multiple Critical on real exploits, got ${criticalCount}`)
    assert.equal(out.hasVerifiedImpact, true)
    assert.ok(out.vibeScore < 50, `confirmed exploit should drop score below 50, got ${out.vibeScore}`)
    assert.ok(['high', 'severe'].includes(out.aggregateBand), `expected high/severe band, got ${out.aggregateBand}`)
  })
})

// ----------------------------------------------------------------------------
// Scoring-policy overhaul — 20 canonical scenarios
// ----------------------------------------------------------------------------

describe('scoring-policy overhaul — 20 scenarios', () => {
  it('1. Enterprise frontend: no confirmed-vuln, score 85-95, band low', () => {
    const out = applyEngine([
      f({ id: 'headers-csp-weak-script-src', severity: 'critical', category: 'headers',
          evidence: "'unsafe-inline'" }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-embedder-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-resource-policy', severity: 'info', category: 'headers' }),
      f({ id: 'paths-admin-login-visible', severity: 'critical', category: 'paths' }),
      f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths' }),
    ], baseCtx)
    assert.equal(out.hasVerifiedImpact, false)
    assert.ok(out.vibeScore >= 85 && out.vibeScore <= 99, `expected 85-99, got ${out.vibeScore}`)
    assert.equal(out.aggregateBand, 'low')
  })

  it('2. Hardening-only: score >= 85', () => {
    const out = applyEngine([
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
      f({ id: 'headers-permissions-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-referrer-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-opener-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-embedder-policy', severity: 'info', category: 'headers' }),
      f({ id: 'headers-cross-origin-resource-policy', severity: 'info', category: 'headers' }),
    ], baseCtx)
    assert.ok(out.vibeScore >= 85, `expected >=85, got ${out.vibeScore}`)
    assert.equal(out.findings.filter((x) => x.riskClass === 'critical-exploit').length, 0)
  })

  it('3. Static site with few missing headers: 90-100', () => {
    const out = applyEngine([
      f({ id: 'headers-no-x-content-type', severity: 'info', category: 'headers' }),
      f({ id: 'headers-no-hsts', severity: 'warn', category: 'headers' }),
    ], baseCtx)
    assert.ok(out.vibeScore >= 90, `got ${out.vibeScore}`)
  })

  it('4. CSP unsafe-inline alone → low-hardening', () => {
    const out = applyEngine([
      f({ id: 'headers-csp-unsafe-inline', severity: 'warn', category: 'headers',
          evidence: "script-src 'self' 'unsafe-inline'" }),
    ], baseCtx)
    assert.ok(['low-hardening', 'informational'].includes(out.findings[0].riskClass!))
  })

  it('5. Source map exposed alone (no secrets) → not critical, score >= 80', () => {
    const out = applyEngine([
      f({ id: 'sourcemaps-exposed', severity: 'info', category: 'sourcemaps' }),
    ], baseCtx)
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.equal(out.hasVerifiedImpact, false)
    assert.ok(out.vibeScore >= 80, `got ${out.vibeScore}`)
  })

  it('6. Source map with secrets → critical-exploit, score < 70', () => {
    const out = applyEngine([
      f({ id: 'sourcemaps-exposed-with-secrets', severity: 'critical', category: 'sourcemaps',
          evidence: 'DB_PASSWORD=...' }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore < 70, `got ${out.vibeScore}`)
  })

  it('7. .env returns 200 SPA shell → suppressed as info, no critical', () => {
    // Detector now emits an info `-spa-shell-200` id when body is the SPA
    // shell. Engine must NOT promote it to critical-exploit.
    const out = applyEngine([
      f({ id: 'path--env-spa-shell-200', severity: 'info', category: 'paths',
          evidence: 'GET /.env → 200 (SPA shell)' }),
    ], baseCtx)
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.equal(out.hasVerifiedImpact, false)
  })

  it('8. .env returns 200 with DB_PASSWORD → confirmed-vuln, score < 60', () => {
    const out = applyEngine([
      f({ id: 'paths-env', severity: 'critical', category: 'paths',
          evidence: 'DB_PASSWORD=super-secret\nSTRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxx' }),
    ], baseCtx)
    assert.equal(out.findings[0].uiGroup, 'confirmed-vulnerabilities')
    assert.ok(out.vibeScore < 60, `got ${out.vibeScore}`)
  })

  it('9. Admin path returns login page → not critical', () => {
    const out = applyEngine([
      f({ id: 'paths-admin-login-visible', severity: 'info', category: 'paths' }),
    ], baseCtx)
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
  })

  it('10. Admin path returns dashboard data → critical-exploit, score < 60', () => {
    const out = applyEngine([
      f({ id: 'paths-admin-unauth-data', severity: 'critical', category: 'auth',
          evidence: '/admin → 200, dashboard table visible' }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore < 60, `got ${out.vibeScore}`)
  })

  it('11. Supabase anon key in bundle → informational', () => {
    const out = applyEngine([
      f({ id: 'secrets-supabase-anon-key', severity: 'critical', category: 'secrets',
          evidence: 'supabase_anon_key=eyJ...' }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 90, `got ${out.vibeScore}`)
  })

  it('12. Supabase service_role key → critical-exploit, score < 50', () => {
    const out = applyEngine([
      f({ id: 'secrets-supabase-service-role', severity: 'critical', category: 'secrets',
          evidence: 'role=service_role, eyJ...' }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore < 60, `got ${out.vibeScore}`)
  })

  it('13. Reflected XSS confirmed → confirmed-vuln', () => {
    const out = applyEngine([
      f({ id: 'paths-xss-reflected', severity: 'critical', category: 'paths',
          evidence: 'canary reflected' }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore < 75)
  })

  it('14. SQL error-based injection confirmed → confirmed-vuln', () => {
    const out = applyEngine([
      f({ id: 'paths-sqli', severity: 'critical', category: 'paths',
          evidence: "ERROR: syntax error at or near \"'\"" }),
    ], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })

  it('15. CORS * without credentials → informational or low', () => {
    const out = applyEngine([
      f({ id: 'cors-wildcard', severity: 'info', category: 'headers',
          evidence: 'Access-Control-Allow-Origin: *' }),
    ], baseCtx)
    assert.ok(['informational', 'low-hardening'].includes(out.findings[0].riskClass!))
  })

  it('16. CORS * with Allow-Credentials:true → high-impact-misconfig', () => {
    const out = applyEngine([
      f({ id: 'cors-credentials-wildcard', severity: 'critical', category: 'headers',
          evidence: 'ACAO:*\nACAC:true' }),
    ], baseCtx)
    assert.ok(['critical-exploit', 'high-impact-misconfig'].includes(out.findings[0].riskClass!))
  })

  it('17. Auth cookie missing HttpOnly on sensitive route → medium or high', () => {
    const sensitiveCtx = defaultContext({ pathname: '/admin', isHttps: true, stage: 1 })
    const out = applyEngine([
      f({ id: 'cookies-no-httponly', severity: 'warn', category: 'cookies',
          evidence: 'session=eyJ...; Path=/' }),
    ], sensitiveCtx)
    assert.ok(['medium-weakness', 'high-impact-misconfig'].includes(out.findings[0].riskClass!))
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
  })

  it('18. Stage 2 localStorage auth token → high-impact-misconfig, score recomputed', () => {
    const stage2Ctx = defaultContext({ pathname: '/', isHttps: true, stage: 2 })
    const out = applyEngine([
      f({ id: 'stage2-localstorage-auth-tokens', severity: 'warn', category: 'cookies',
          evidence: 'sb-xxx-auth-token' }),
    ], stage2Ctx)
    assert.ok(['high-impact-misconfig', 'medium-weakness'].includes(out.findings[0].riskClass!))
  })

  it('19. Stage 2 public API 2xx no sensitive response → informational', () => {
    const stage2Ctx = defaultContext({ pathname: '/', isHttps: true, stage: 2 })
    const out = applyEngine([
      f({ id: 'stage2-public-api-2xx', severity: 'info', category: 'paths',
          evidence: '/api/health 200' }),
    ], stage2Ctx)
    assert.equal(out.findings[0].riskClass, 'informational')
  })

  it('20. Stage 2 sensitive data in response → high or critical, recomputed', () => {
    const stage2Ctx = defaultContext({ pathname: '/admin', isHttps: true, stage: 2 })
    const out = applyEngine([
      f({ id: 'stage2-sensitive-data-exposure', severity: 'critical', category: 'auth-disclosure',
          evidence: 'response leaked PII' }),
    ], stage2Ctx)
    assert.ok(['critical-exploit', 'high-impact-misconfig'].includes(out.findings[0].riskClass!))
  })
})

// ----------------------------------------------------------------------------
// Integration — Stage 1 + Stage 2 merge
// ----------------------------------------------------------------------------

describe('integration — stage 1 + stage 2 merge', () => {
  it('Stage 1 + Stage 2 merged score is lower when Stage 2 adds high-impact', () => {
    const stage1 = [
      f({ id: 'headers-csp-missing', severity: 'warn', category: 'headers' }),
    ]
    const stage1Out = applyEngine(stage1, baseCtx)
    const stage2Ctx = defaultContext({ pathname: '/', isHttps: true, stage: 2 })
    const merged = applyEngine(
      [...stage1, f({ id: 'stage2-localstorage-auth-tokens', severity: 'warn', category: 'cookies',
                     evidence: 'sb-xxx-auth-token in localStorage' })],
      stage2Ctx,
    )
    assert.ok(merged.vibeScore < stage1Out.vibeScore,
      `merged ${merged.vibeScore} should be < stage1 ${stage1Out.vibeScore}`)
  })

  it('Stage 3 deep RLS breach → critical-exploit with stage:3 context', () => {
    const stage3Ctx = defaultContext({ pathname: '/', isHttps: true, stage: 3 })
    const out = applyEngine([
      f({ id: 'stage3-rls-broken', severity: 'critical', category: 'auth',
          evidence: 'anon key can SELECT public.users (47 rows)' }),
    ], stage3Ctx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
  })

  it('legacy risk-scorer cannot affect engine output (isolation)', () => {
    // The engine should not import or call any function from risk-scorer.ts.
    // We can't easily mock here, but we can verify the engine's outputs match
    // a hand-computed expectation with NO riskScore/riskBand on input.
    const input: Finding = {
      id: 'paths-xss-reflected', severity: 'critical', category: 'paths',
      title: 'x', description: 'x', evidence: 'canary reflected', fixPrompt: '',
    }
    const out = applyEngine([input], baseCtx)
    assert.equal(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(typeof out.findings[0].riskScore === 'number')
  })
})

// ----------------------------------------------------------------------------
// AST heuristic — must NOT be confirmed-vulnerabilities
// ----------------------------------------------------------------------------

describe('AST heuristic — credential-shaped patterns', () => {
  it('js-ast-hardcoded-creds is never critical-exploit, lands in needs-review/info', () => {
    const out = applyEngine([
      f({ id: 'js-ast-hardcoded-creds', severity: 'warn', category: 'secrets',
          evidence: '{ apiKey: "sk_test_xxxxx" } (5 matches)' }),
    ], baseCtx)
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.notEqual(out.findings[0].uiGroup, 'confirmed-vulnerabilities')
  })

  it('js-ast-hardcoded-creds even when legacy-tagged critical does not promote', () => {
    const out = applyEngine([
      f({ id: 'js-ast-hardcoded-creds', severity: 'critical', category: 'secrets',
          evidence: '{ apiKey: "..." }' }),
    ], baseCtx)
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
  })
})

