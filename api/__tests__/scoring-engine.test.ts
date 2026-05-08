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
    assert.ok(out.vibeScore >= 75, `vibeScore should stay >= 75, got ${out.vibeScore}`)
    assert.notEqual(out.aggregateBand, 'severe')
    assert.notEqual(out.aggregateBand, 'high')
  })

  it('Cookie missing Secure on non-auth cookie is NOT critical', () => {
    const out = applyEngine(
      [f({ id: 'cookies-no-secure', severity: 'critical', category: 'cookies',
           evidence: 'preferences=dark; Path=/' })],
      baseCtx,
    )
    assert.notEqual(out.findings[0].riskClass, 'critical-exploit')
    assert.ok(out.vibeScore >= 75)
  })

  it('DOM sink alone is informational/hardening only', () => {
    const out = applyEngine(
      [f({ id: 'dom-sink-innerhtml', severity: 'warn', category: 'html',
           evidence: 'sink assignment without taint flow' })],
      baseCtx,
    )
    assert.ok(['informational', 'low-hardening'].includes(out.findings[0].riskClass!))
    assert.ok(out.vibeScore >= 75)
  })

  it('Public 2xx API endpoint without sensitive content is informational', () => {
    const out = applyEngine(
      [f({ id: 'paths-api-public-2xx', severity: 'warn', category: 'paths',
           evidence: 'GET /api/health 200 OK' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 75)
  })

  it('Frontend public client identifier (Firebase web SDK key) is informational', () => {
    const out = applyEngine(
      [f({ id: 'secrets-firebase-api-key', severity: 'critical', category: 'secrets',
           evidence: 'firebase_api_key=public-web-key' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 75)
  })

  it('Visible admin login page is NOT critical', () => {
    const out = applyEngine(
      [f({ id: 'paths-admin-login-visible', severity: 'critical', category: 'paths',
           evidence: '/admin -> 302 /login' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 75)
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
    assert.notEqual(out.aggregateBand, 'severe')
    assert.notEqual(out.aggregateBand, 'high')
  })

  it('No verified impact → aggregateBand never severe/high', () => {
    const findings = Array.from({ length: 30 }, (_, i) =>
      f({ id: `headers-csp-weak-${i}`, severity: 'warn', category: 'headers' }),
    )
    const out = applyEngine(findings, baseCtx)
    assert.notEqual(out.aggregateBand, 'severe')
    assert.notEqual(out.aggregateBand, 'high')
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
    assert.ok(out.vibeScore >= 75, `expected vibeScore >= 75, got ${out.vibeScore}`)
    assert.notEqual(out.aggregateBand, 'severe')
    assert.notEqual(out.aggregateBand, 'high')
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
    assert.ok(out.vibeScore >= 75, `expected vibeScore >= 75, got ${out.vibeScore}`)
    assert.notEqual(out.aggregateBand, 'severe')
    assert.notEqual(out.aggregateBand, 'high')
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
