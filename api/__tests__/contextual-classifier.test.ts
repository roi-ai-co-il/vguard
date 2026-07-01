/**
 * Contextual risk classifier — regression matrix (2026-07-01).
 *
 * Covers the 12 required cases from the spec plus the cookie-sensitivity banks
 * and false-positive / false-negative guards. Two layers are tested:
 *
 *   1. the pure classifier (`classifyContextualFinding`) against a hand-built
 *      SiteSecurityContext — this is where every branch is exercised;
 *   2. end-to-end through `applyEngine` with a `siteContext`, proving the
 *      engine wires effectiveSeverity / blocksPerfectScore / reasonCodes /
 *      penalty correctly, and that OMITTING siteContext changes nothing.
 *
 * CI-critical: if the expected classification behavior changes unexpectedly,
 * these assertions fail.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  classifyContextualFinding,
  classifyCookieSensitivity,
  buildSiteSecurityContext,
  type SiteSecurityContext,
  type CookieObservation,
} from '../_lib/contextual-risk-classifier.ts'
import { applyEngine } from '../_lib/scoring-engine.ts'
import type { Finding } from '../../src/lib/scanner-types.ts'
import type { ScoringContext } from '../_lib/scoring-policy.ts'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function cookie(p: Partial<CookieObservation> & { name: string }): CookieObservation {
  return {
    hasSecure: false,
    hasHttpOnly: false,
    sameSite: null,
    setOverHttp: false,
    sensitivity: classifyCookieSensitivity(p.name),
    ...p,
  }
}

function ctx(p: Partial<SiteSecurityContext> = {}): SiteSecurityContext {
  return {
    httpsActive: true,
    httpReachableWithoutRedirect: false,
    httpsReachable: true,
    hstsPresent: false,
    hasLoginForm: false,
    hasPasswordInput: false,
    hasAdminIndicator: false,
    hasPaymentIndicator: false,
    hasPrivateUserData: false,
    hasAnyForm: false,
    hasStateChangingForm: false,
    hasCsrfSignal: false,
    servesPrivateDataOverHttp: false,
    loginFormOverHttp: false,
    cookies: [],
    ...p,
  }
}

const cookieFinding = (name: string): Pick<Finding, 'id' | 'category'> => ({
  id: `cookie-${name}`,
  category: 'cookies',
})

const httpRedirectFinding: Pick<Finding, 'id' | 'category'> = {
  id: 'tls-no-http-redirect',
  category: 'tls',
}

// Full Finding builder for the engine-level assertions.
function f(p: Partial<Finding> & { id: string; severity: Finding['severity']; category: Finding['category'] }): Finding {
  return {
    title: p.title ?? p.id,
    description: p.description ?? '',
    evidence: p.evidence ?? '',
    fixPrompt: p.fixPrompt ?? '',
    ...p,
  } as Finding
}

const baseEngineCtx: ScoringContext = { routeContext: 'unknown', httpsActive: true, stage: 1 }

// ===========================================================================
// Cookie-sensitivity banks
// ===========================================================================

test('cookie sensitivity — sensitive session/auth names', () => {
  for (const n of [
    'session', 'sessionid', 'sess', 'sid', 'auth', 'auth_token', 'access_token',
    'refresh_token', 'jwt', 'id_token', 'connect.sid', 'PHPSESSID', 'JSESSIONID',
    'ASP.NET_SessionId', 'laravel_session', 'next-auth.session-token',
    'supabase-auth-token', 'sb-abcdef-auth-token', 'remember_me', 'firebaseLocalStorage',
  ]) {
    assert.equal(classifyCookieSensitivity(n), 'sensitive', `${n} should be sensitive`)
  }
})

test('cookie sensitivity — semi-sensitive', () => {
  for (const n of ['csrf', 'xsrf-token', 'nonce', 'state', 'device_id', 'visitor_id', 'client_id']) {
    assert.equal(classifyCookieSensitivity(n), 'semiSensitive', `${n} should be semi`)
  }
})

test('cookie sensitivity — non-sensitive analytics/preference (incl. Google infra)', () => {
  for (const n of ['_ga', '_ga_ABC123', '_gid', '_gat', 'utm_source', 'gclid', '_fbp',
    'consent', 'locale', 'lang', 'theme', 'prefs', 'bucket', 'ab_test', 'variant',
    'NID', 'AEC', 'DV', 'SOCS']) {
    assert.equal(classifyCookieSensitivity(n), 'nonSensitive', `${n} should be non-sensitive`)
  }
})

// ===========================================================================
// SPEC REGRESSION CASES 1–12
// ===========================================================================

test('CASE 1 — HTTP reachable, public page only, no forms/cookies → LOW, does not block perfect', () => {
  const c = classifyContextualFinding(httpRedirectFinding, ctx({ httpReachableWithoutRedirect: true }))!
  assert.equal(c.severity, 'low')
  assert.equal(c.blocksPerfectScore, false)
  assert.ok(c.reasonCodes.includes('PUBLIC_STATIC_ONLY'))
})

test('CASE 2 — HTTP reachable with login/password form → HIGH (unverified), blocks perfect', () => {
  const c = classifyContextualFinding(
    httpRedirectFinding,
    ctx({ httpReachableWithoutRedirect: true, hasLoginForm: true, hasPasswordInput: true }),
  )!
  assert.equal(c.severity, 'high')
  assert.equal(c.confidence, 'likely')
  assert.equal(c.blocksPerfectScore, true)
})

test('CASE 2b — login form served over HTTP (verified) → CRITICAL', () => {
  const c = classifyContextualFinding(
    httpRedirectFinding,
    ctx({ httpReachableWithoutRedirect: true, hasLoginForm: true, loginFormOverHttp: true }),
  )!
  assert.equal(c.severity, 'critical')
  assert.equal(c.confidence, 'verified')
  assert.equal(c.blocksPerfectScore, true)
})

test('CASE 3 — HTTP serves private/user data → CRITICAL, blocks perfect', () => {
  const c = classifyContextualFinding(
    httpRedirectFinding,
    ctx({ httpReachableWithoutRedirect: true, servesPrivateDataOverHttp: true }),
  )!
  assert.equal(c.severity, 'critical')
  assert.equal(c.confidence, 'verified')
  assert.equal(c.blocksPerfectScore, true)
  assert.ok(c.reasonCodes.includes('PRIVATE_DATA_OVER_HTTP'))
})

test('CASE 4 — cookie "bucket" missing SameSite → LOW, does not block perfect', () => {
  const c = classifyContextualFinding(cookieFinding('bucket'), ctx({ cookies: [cookie({ name: 'bucket' })] }))!
  assert.equal(c.severity, 'low')
  assert.equal(c.blocksPerfectScore, false)
  assert.ok(c.reasonCodes.includes('COOKIE_NONSENSITIVE'))
})

test('CASE 5 — cookie "_ga" missing Secure → LOW, does not block perfect', () => {
  const c = classifyContextualFinding(
    cookieFinding('_ga'),
    ctx({ httpReachableWithoutRedirect: true, cookies: [cookie({ name: '_ga' })] }),
  )!
  assert.equal(c.severity, 'low')
  assert.equal(c.blocksPerfectScore, false)
})

test('CASE 6 — cookie "session" missing SameSite, no CSRF surface → MEDIUM (not critical)', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    // Secure IS present so the Secure dimension can't drive it; only SameSite is missing.
    ctx({ cookies: [cookie({ name: 'session', hasSecure: true, hasHttpOnly: true, sameSite: null })] }),
  )!
  assert.equal(c.severity, 'medium')
  assert.notEqual(c.severity, 'critical')
  assert.equal(c.blocksPerfectScore, false)
})

test('CASE 7 — cookie "session" missing SameSite + state-changing form + no CSRF signal → HIGH', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({
      hasStateChangingForm: true,
      hasCsrfSignal: false,
      cookies: [cookie({ name: 'session', hasSecure: true, hasHttpOnly: true, sameSite: null })],
    }),
  )!
  assert.equal(c.severity, 'high')
  assert.equal(c.contextClass, 'csrf')
  assert.equal(c.blocksPerfectScore, true)
  assert.ok(c.reasonCodes.includes('NO_CSRF_SIGNAL'))
})

test('CASE 7b — same but a visible CSRF defense exists → stays MEDIUM', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({
      hasStateChangingForm: true,
      hasCsrfSignal: true,
      cookies: [cookie({ name: 'session', hasSecure: true, hasHttpOnly: true, sameSite: null })],
    }),
  )!
  assert.equal(c.severity, 'medium')
})

test('CASE 8 — cookie "NID" (analytics-like) without Secure → LOW unless sensitive evidence', () => {
  const c = classifyContextualFinding(
    cookieFinding('NID'),
    ctx({ httpReachableWithoutRedirect: true, cookies: [cookie({ name: 'NID' })] }),
  )!
  assert.equal(c.severity, 'low')
  assert.equal(c.blocksPerfectScore, false)
})

test('CASE 9 — cookie "session" without Secure + HTTP reachable → HIGH, blocks perfect', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({ httpReachableWithoutRedirect: true, cookies: [cookie({ name: 'session' })] }),
  )!
  assert.equal(c.severity, 'high')
  assert.equal(c.contextClass, 'transport')
  assert.equal(c.blocksPerfectScore, true)
  assert.ok(c.reasonCodes.includes('COULD_SEND_OVER_HTTP'))
})

test('CASE 10 — cookie "session" set over HTTP → CRITICAL, blocks perfect', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({ httpsActive: false, cookies: [cookie({ name: 'session', setOverHttp: true })] }),
  )!
  assert.equal(c.severity, 'critical')
  assert.equal(c.confidence, 'verified')
  assert.equal(c.blocksPerfectScore, true)
  assert.ok(c.reasonCodes.includes('SET_OVER_HTTP'))
})

test('CASE 11 — Google-like hardening-only: HTTP reachable + cookie observations, no sensitive impact → no HIGH/CRITICAL', () => {
  const siteCtx = ctx({
    httpReachableWithoutRedirect: true,
    cookies: [cookie({ name: 'NID' }), cookie({ name: 'AEC' }), cookie({ name: 'SOCS' })],
  })
  const transport = classifyContextualFinding(httpRedirectFinding, siteCtx)!
  assert.equal(transport.severity, 'low')
  for (const n of ['NID', 'AEC', 'SOCS']) {
    const c = classifyContextualFinding(cookieFinding(n), siteCtx)!
    assert.ok(['info', 'low'].includes(c.severity), `${n} → ${c.severity}`)
    assert.equal(c.blocksPerfectScore, false)
  }
})

test('CASE 12 — dangerous weak site: HTTP reachable + login + session cookie → HIGH/CRITICAL', () => {
  const siteCtx = ctx({
    httpReachableWithoutRedirect: true,
    hasLoginForm: true,
    hasPasswordInput: true,
    cookies: [cookie({ name: 'session' })],
  })
  const transport = classifyContextualFinding(httpRedirectFinding, siteCtx)!
  assert.ok(['high', 'critical'].includes(transport.severity))
  const cookieC = classifyContextualFinding(cookieFinding('session'), siteCtx)!
  assert.ok(['high', 'critical'].includes(cookieC.severity))
  assert.equal(cookieC.blocksPerfectScore, true)
})

// ===========================================================================
// SameSite=None without Secure (existing engine allowlist parity)
// ===========================================================================

test('SameSite=None without Secure on a sensitive cookie → HIGH', () => {
  const c = classifyContextualFinding(
    cookieFinding('auth_token'),
    ctx({ cookies: [cookie({ name: 'auth_token', sameSite: 'none', hasSecure: false })] }),
  )!
  assert.equal(c.severity, 'high')
  assert.ok(c.reasonCodes.includes('SAMESITE_NONE_NO_SECURE'))
})

// ===========================================================================
// HSTS mitigation nuance
// ===========================================================================

test('sensitive cookie missing Secure, HTTPS-only WITH HSTS → LOW (residual)', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({ httpReachableWithoutRedirect: false, hstsPresent: true, cookies: [cookie({ name: 'session', hasSecure: false, sameSite: 'lax' })] }),
  )!
  assert.equal(c.severity, 'low')
  assert.equal(c.blocksPerfectScore, false)
})

test('sensitive cookie missing Secure, HTTPS-only NO HSTS → MEDIUM (first-request TOFU)', () => {
  const c = classifyContextualFinding(
    cookieFinding('session'),
    ctx({ httpReachableWithoutRedirect: false, hstsPresent: false, cookies: [cookie({ name: 'session', hasSecure: false, sameSite: 'lax' })] }),
  )!
  assert.equal(c.severity, 'medium')
})

// ===========================================================================
// Non-owned findings pass through untouched
// ===========================================================================

test('classifier returns null for findings it does not own', () => {
  assert.equal(classifyContextualFinding({ id: 'paths-env', category: 'paths' }, ctx()), null)
  assert.equal(classifyContextualFinding({ id: 'headers-hsts-weak', category: 'headers' }, ctx()), null)
  assert.equal(classifyContextualFinding({ id: 'tls-http', category: 'tls' }, ctx()), null)
})

// ===========================================================================
// ENGINE-LEVEL: siteContext changes the classification; omitting it does not
// ===========================================================================

test('engine — WITHOUT siteContext, a session cookie stays low-hardening (unchanged behavior)', () => {
  const out = applyEngine(
    [f({ id: 'cookie-session', severity: 'warn', category: 'cookies', evidence: 'session=x; path=/' })],
    baseEngineCtx,
  )
  assert.equal(out.findings[0].effectiveSeverity, 'low')
  assert.equal(out.findings[0].riskClass, 'low-hardening')
  assert.equal(out.findings[0].reasonCodes, undefined)
})

test('engine — WITH siteContext (session no Secure + HTTP reachable) → escalated to HIGH + reasonCodes + real penalty', () => {
  const siteContext = ctx({
    httpReachableWithoutRedirect: true,
    cookies: [cookie({ name: 'session', hasSecure: false })],
  })
  const clean = applyEngine([f({ id: 'tls-https', severity: 'ok', category: 'tls' })], baseEngineCtx)
  const out = applyEngine(
    [f({ id: 'cookie-session', severity: 'warn', category: 'cookies', evidence: 'session=x; path=/' })],
    { ...baseEngineCtx, siteContext },
  )
  const finding = out.findings[0]
  assert.equal(finding.effectiveSeverity, 'high')
  assert.equal(finding.riskClass, 'high-impact-misconfig')
  assert.equal(finding.blocksPerfectScore, true)
  assert.ok((finding.reasonCodes ?? []).includes('COULD_SEND_OVER_HTTP'))
  assert.equal(finding.contextClass, 'transport')
  // High escapes the posture clamp → the score actually drops below a clean 100.
  assert.ok(out.vibeScore < clean.vibeScore, `escalated score ${out.vibeScore} should be < clean ${clean.vibeScore}`)
  assert.ok(out.severityCounts.high >= 1)
})

test('engine — WITH siteContext, an analytics cookie stays LOW and does not tank the score', () => {
  const siteContext = ctx({
    httpReachableWithoutRedirect: true,
    cookies: [cookie({ name: '_ga' })],
  })
  const out = applyEngine(
    [f({ id: 'cookie-_ga', severity: 'info', category: 'cookies', evidence: '_ga=x; path=/' })],
    { ...baseEngineCtx, siteContext },
  )
  assert.equal(out.findings[0].effectiveSeverity, 'low')
  assert.equal(out.findings[0].blocksPerfectScore, false)
  assert.ok(out.vibeScore >= 95, `hardening-only should stay high, got ${out.vibeScore}`)
})

test('engine — session cookie set over HTTP → CRITICAL + verifiedImpact true', () => {
  const siteContext = ctx({
    httpsActive: false,
    cookies: [cookie({ name: 'session', setOverHttp: true })],
  })
  const out = applyEngine(
    [f({ id: 'cookie-session', severity: 'warn', category: 'cookies', evidence: 'session=x' })],
    { ...baseEngineCtx, httpsActive: false, siteContext },
  )
  assert.equal(out.findings[0].effectiveSeverity, 'critical')
  assert.equal(out.findings[0].verifiedImpact, true)
  assert.equal(out.findings[0].blocksPerfectScore, true)
})

// ===========================================================================
// buildSiteSecurityContext — parsing + surface detection
// ===========================================================================

test('buildSiteSecurityContext — parses cookies, login form, HSTS, state-changing form', () => {
  const built = buildSiteSecurityContext({
    finalUrl: 'https://example.com/login',
    httpsActive: true,
    httpReachableWithoutRedirect: true,
    hstsHeaderPresent: true,
    html: `<form method="post" action="/login"><input type="password" name="pw"></form>`,
    setCookies: ['session=abc; Path=/; HttpOnly', '_ga=1; Path=/'],
  })
  assert.equal(built.hasPasswordInput, true)
  assert.equal(built.hasLoginForm, true)
  assert.equal(built.hasStateChangingForm, true)
  assert.equal(built.hstsPresent, true)
  const session = built.cookies.find((c) => c.name === 'session')!
  assert.equal(session.sensitivity, 'sensitive')
  assert.equal(session.hasSecure, false)
  assert.equal(session.hasHttpOnly, true)
  const ga = built.cookies.find((c) => c.name === '_ga')!
  assert.equal(ga.sensitivity, 'nonSensitive')
})

test('buildSiteSecurityContext — cookies set over HTTP are flagged setOverHttp', () => {
  const built = buildSiteSecurityContext({
    finalUrl: 'http://insecure.example/',
    httpsActive: false,
    httpReachableWithoutRedirect: true,
    hstsHeaderPresent: false,
    html: '<h1>hello</h1>',
    setCookies: ['session=abc; Path=/'],
  })
  assert.equal(built.cookies[0].setOverHttp, true)
})
