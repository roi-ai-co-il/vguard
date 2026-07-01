import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  decideCsrf,
  classifyEndpointSensitivity,
  type CsrfEvidence,
} from '../_lib/csrf-decision-engine.ts'
import { applyEngine, defaultContext } from '../_lib/scoring-engine.ts'
import type { Finding } from '../../src/lib/scanner-types.ts'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build passive evidence with NO protection by default; override per test. */
function ev(partial: Partial<CsrfEvidence> & { action: string }): CsrfEvidence {
  const { action, target, ...rest } = partial
  return {
    target: {
      method: 'POST',
      action,
      sameOrigin: true,
      kind: 'form',
      ...target,
    },
    hasVisibleToken: false,
    hasTokenMetaTag: false,
    metaTokenUsedByJs: false,
    hasCsrfHeaderEvidence: false,
    doubleSubmitCookiePattern: false,
    authCookieSameSite: null,
    hasAuthSessionCookie: false,
    framework: null,
    mode: 'passive',
    ...rest,
  }
}

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

// ---------------------------------------------------------------------------
// Decision engine — pure unit tests (the required scenarios 1–7)
// ---------------------------------------------------------------------------

describe('CSRF decision engine — passive decisions', () => {
  // 1. Contact form, POST, no token, no cookies → info, no penalty
  it('contact form, no token, no cookies → info', () => {
    const d = decideCsrf(ev({ action: '/contact' }))
    assert.equal(d.decision, 'info')
    assert.equal(d.findingId, 'csrf-protection-not-visible-info')
    assert.equal(d.severity, 'info')
    assert.equal(d.sensitivity, 'public')
  })

  // 2. Contact form + SameSite=Lax session cookie → no_issue (or info), no penalty
  it('contact form + SameSite=Lax session cookie → no_issue', () => {
    const d = decideCsrf(
      ev({ action: '/contact', hasAuthSessionCookie: true, authCookieSameSite: 'lax' }),
    )
    assert.ok(['no_issue', 'info'].includes(d.decision), `got ${d.decision}`)
    assert.notEqual(d.decision, 'low')
  })

  // 3. Form with hidden csrf_token → no_issue
  it('hidden csrf_token present → no_issue', () => {
    const d = decideCsrf(ev({ action: '/account/update', hasVisibleToken: true }))
    assert.equal(d.decision, 'no_issue')
    assert.equal(d.findingId, null)
  })

  // 4. Rails/Django/Laravel/ASP.NET token patterns (visible field) → no_issue
  it('framework token patterns (visible field) → no_issue', () => {
    for (const fw of ['rails', 'django', 'laravel', 'aspnet'] as const) {
      const d = decideCsrf(
        ev({ action: '/settings', hasVisibleToken: true, framework: fw }),
      )
      assert.equal(d.decision, 'no_issue', `${fw} visible token should be no_issue`)
    }
  })

  // 5. Angular XSRF-TOKEN cookie + X-XSRF-Token signal (double-submit) → no_issue
  it('Angular double-submit (XSRF-TOKEN cookie + X-XSRF-Token) → no_issue', () => {
    const d = decideCsrf(
      ev({
        action: '/account/email',
        framework: 'angular',
        doubleSubmitCookiePattern: true,
        hasCsrfHeaderEvidence: true,
      }),
    )
    assert.equal(d.decision, 'no_issue')
  })

  // 6. Profile/settings/password endpoint, no token, no header, no SameSite → low, possible
  it('sensitive account endpoint, no protection → low / possible', () => {
    for (const path of ['/profile', '/settings', '/account/password', '/user/update']) {
      const d = decideCsrf(ev({ action: path }))
      assert.equal(d.decision, 'low', `${path} should be low`)
      assert.equal(d.findingId, 'csrf-sensitive-action-no-passive-protection-low')
      assert.equal(d.confidence, 'possible')
      assert.equal(d.severity, 'warn')
    }
  })

  // 7. Payment/admin/delete endpoint, passive only, no protection → low AT MOST
  it('financial/admin/destructive endpoint, passive → low at most (never medium+)', () => {
    for (const path of ['/payment', '/admin/users', '/account/delete', '/billing/transfer']) {
      const d = decideCsrf(ev({ action: path }))
      assert.equal(d.decision, 'low', `${path} passive should cap at low, got ${d.decision}`)
      assert.ok(!['medium', 'high', 'critical'].includes(d.decision))
    }
  })

  // Hard clamp: passive can never exceed low even with a worst-case sensitive target
  it('passive mode is hard-capped at low regardless of sensitivity', () => {
    const worst = ev({ action: '/admin/payment/transfer/delete' })
    const d = decideCsrf(worst)
    assert.ok(['no_issue', 'info', 'low'].includes(d.decision))
    assert.notEqual(d.decision, 'medium')
    assert.notEqual(d.decision, 'high')
    assert.notEqual(d.decision, 'critical')
  })

  // Framework hint alone does NOT suppress a low on a sensitive, otherwise-unprotected endpoint
  it('framework hint alone does not suppress low on a sensitive endpoint', () => {
    const d = decideCsrf(ev({ action: '/account/password', framework: 'laravel' }))
    // framework is weak alt-evidence → info (not suppressed to no_issue); never no_issue
    assert.notEqual(d.decision, 'no_issue')
  })

  // Header evidence on a form without a hidden field is NOT suspicious
  it('custom CSRF header evidence → no_issue even without a hidden field', () => {
    const d = decideCsrf(ev({ action: '/account/settings', hasCsrfHeaderEvidence: true }))
    assert.equal(d.decision, 'no_issue')
  })

  // Active-mode confirmed high-impact state change → critical (verified/deep scan only)
  it('active verified confirmed high-impact state change → critical', () => {
    const d = decideCsrf(
      ev({
        action: '/account/password',
        mode: 'active',
        activeVerification: { confirmedStateChange: true },
      }),
    )
    assert.equal(d.decision, 'critical')
    assert.equal(d.findingId, 'csrf-critical-state-change-confirmed')
  })
})

describe('classifyEndpointSensitivity', () => {
  it('buckets public / auth / account / financial / unknown', () => {
    assert.equal(classifyEndpointSensitivity('/contact'), 'public')
    assert.equal(classifyEndpointSensitivity('/login'), 'auth')
    assert.equal(classifyEndpointSensitivity('/profile'), 'account')
    assert.equal(classifyEndpointSensitivity('/payment'), 'financial')
    assert.equal(classifyEndpointSensitivity('/admin'), 'financial')
    assert.equal(classifyEndpointSensitivity('/x9q7z'), 'unknown')
  })

  it('signin aliases classify as auth (not unknown)', () => {
    assert.equal(classifyEndpointSensitivity('/signin.html'), 'auth')
    assert.equal(classifyEndpointSensitivity('/sign-in'), 'auth')
    assert.equal(classifyEndpointSensitivity('/users/sign_in'), 'auth')
  })
})

describe('CSRF decision engine — signin aliases drive the Low path', () => {
  it('POST to /signin.html with no protection → low', () => {
    const d = decideCsrf(ev({ action: '/signin.html' }))
    assert.equal(d.decision, 'low')
    assert.equal(d.sensitivity, 'auth')
    assert.equal(d.confidence, 'possible')
  })
})

// ---------------------------------------------------------------------------
// Scoring-engine regressions (scenarios 8–10 + the Low routing)
// ---------------------------------------------------------------------------

describe('CSRF scoring — visibility-only heuristic stays recon/info/zero', () => {
  // 8. Existing visibility-only CSRF heuristic → info/recon/no score impact
  it('html-form-no-csrf → recon, informational, zero score impact', () => {
    const out = applyEngine(
      [f({ id: 'html-form-no-csrf', severity: 'info', category: 'html', evidence: '1 of 1 POST forms had no visible HTML CSRF token field.' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskCategory, 'recon')
    assert.equal(out.findings[0].riskClass, 'informational')
    assert.ok(out.vibeScore >= 95, `zero-impact heuristic; score should stay high, got ${out.vibeScore}`)
  })

  // New info id is also recon/zero
  it('csrf-protection-not-visible-info → recon, zero score impact', () => {
    const out = applyEngine(
      [f({ id: 'csrf-protection-not-visible-info', severity: 'info', category: 'html', evidence: 'Endpoint appears public/non-sensitive.' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskCategory, 'recon')
    assert.ok(out.vibeScore >= 95, `got ${out.vibeScore}`)
  })

  // 9. CSRF info findings must not increase the warning count
  it('CSRF info findings do not increase the warning count', () => {
    const out = applyEngine(
      [
        f({ id: 'html-form-no-csrf', severity: 'info', category: 'html' }),
        f({ id: 'csrf-protection-not-visible-info', severity: 'info', category: 'html' }),
      ],
      baseCtx,
    )
    // warn bucket = high + medium (see scanner reconciliation)
    assert.equal(out.severityCounts.high, 0)
    assert.equal(out.severityCounts.medium, 0)
    assert.equal(out.severityCounts.critical, 0)
  })

  // 10. CSRF info findings must not reduce score or letter grade
  it('CSRF info findings do not reduce score or grade', () => {
    const clean = applyEngine([], baseCtx)
    const withInfo = applyEngine(
      [
        f({ id: 'html-form-no-csrf', severity: 'info', category: 'html' }),
        f({ id: 'csrf-protection-not-visible-info', severity: 'info', category: 'html' }),
      ],
      baseCtx,
    )
    assert.equal(withInfo.vibeScore, clean.vibeScore)
    assert.equal(withInfo.grade, clean.grade)
  })

  // Low passive risk finding → posture, small capped, NOT in the warn bucket
  it('csrf-sensitive-action-no-passive-protection-low → posture, small capped, not a warning', () => {
    const out = applyEngine(
      [f({ id: 'csrf-sensitive-action-no-passive-protection-low', severity: 'warn', category: 'html', confidence: 'possible', evidence: 'account endpoint, no passive protection' })],
      baseCtx,
    )
    assert.equal(out.findings[0].riskCategory, 'posture')
    // reconciles down to low/info — never high/medium/critical
    assert.ok(['low', 'info'].includes(out.findings[0].effectiveSeverity!), `got ${out.findings[0].effectiveSeverity}`)
    // display confidence is pinned to possible/unverified (never 'likely')
    assert.equal(out.findings[0].confidence, 'possible')
    assert.equal(out.severityCounts.high, 0)
    assert.equal(out.severityCounts.medium, 0)
    assert.equal(out.severityCounts.critical, 0)
    // small, capped: a lone passive posture item barely moves the score
    assert.ok(out.vibeScore >= 90, `passive CSRF penalty must be small, got ${out.vibeScore}`)
  })
})
