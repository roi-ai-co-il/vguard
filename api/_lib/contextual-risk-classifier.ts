/**
 * Vguard — contextual risk classifier (2026-07-01).
 *
 * NOT A SCAN STAGE. This module runs AFTER Stage-1/2/3 detectors have already
 * produced their findings, inside the existing scoring-engine decision flow. It
 * takes two specific families of hardening findings that the generic engine
 * treats too coarsely —
 *
 *   • `cookie-<name>`        (a Set-Cookie missing Secure / SameSite / HttpOnly)
 *   • `tls-no-http-redirect` (http:// reachable on an otherwise-HTTPS host)
 *
 * — and re-classifies them from *observable context* (cookie sensitivity, the
 * flags actually present, whether the cookie was set over HTTP or could be sent
 * over HTTP, whether a login/admin/payment/private-data surface exists, whether
 * a state-changing form lacks a visible CSRF defense, HSTS presence).
 *
 * The generic engine collapses BOTH families to `low-hardening` unconditionally.
 * That is safe against false positives but blind to context: a `session` cookie
 * with no Secure flag on a host that also answers plain HTTP is a real
 * session-theft risk, not a hardening note. Conversely an `_ga` analytics cookie
 * without SameSite is genuinely a hardening note and must NOT tank a clean site.
 *
 * PRINCIPLE (unchanged from the engine): a technical finding alone is never
 * High/Critical. High requires sensitive context + strong evidence; Critical
 * requires verified impact (a sensitive cookie actually set over HTTP, or
 * private data / a login form demonstrably served over HTTP).
 *
 * Pure module — no I/O, browser-safe. Exercised directly by
 * `api/__tests__/contextual-classifier.test.ts` and consumed by
 * `scoring-engine.runScoringEngine` when `ScoringContext.siteContext` is set.
 */

import type { RiskCategory } from '../../src/lib/scanner-types.js'
import type { RiskClass, Confidence } from './scoring-policy.js'

// ---------------------------------------------------------------------------
// Public taxonomy (task-facing shape). Mapped onto the engine's existing
// RiskClass/Confidence/RiskCategory so scoring stays in lockstep.
// ---------------------------------------------------------------------------

/** The 5-tier severity the UI badge + totals render (engine `effectiveSeverity`). */
export type ContextualSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

/** The "why this matters" domain of a contextual decision. */
export type ContextClass =
  | 'hardening'
  | 'transport'
  | 'cookie'
  | 'auth'
  | 'csrf'
  | 'data-exposure'

/** Cookie sensitivity from the name banks below (best evidence still wins). */
export type CookieSensitivity = 'sensitive' | 'semiSensitive' | 'nonSensitive' | 'unknown'

/** One observed Set-Cookie, already parsed into flags + sensitivity. */
export interface CookieObservation {
  name: string
  hasSecure: boolean
  hasHttpOnly: boolean
  sameSite: 'strict' | 'lax' | 'none' | null
  /** The Set-Cookie response was received over http:// (verified exposure). */
  setOverHttp: boolean
  sensitivity: CookieSensitivity
}

/**
 * Everything the classifier needs, all from passive/observable evidence. Built
 * by `buildSiteSecurityContext` in production; constructed directly by tests.
 */
export interface SiteSecurityContext {
  /** The scanned page was served over https://. */
  httpsActive: boolean
  /** http://<host> answered 2xx WITHOUT a 30x redirect to https (the
   * `tls-no-http-redirect` condition). Means a sensitive non-Secure cookie
   * could ride the first plain-HTTP request. */
  httpReachableWithoutRedirect: boolean
  /** https:// is reachable at all (almost always true for a scanned page). */
  httpsReachable: boolean
  /** A valid Strict-Transport-Security header was present on the response. */
  hstsPresent: boolean

  // --- sensitive-context signals (observable, never a brand list) ---
  /** A login/sign-in/auth form or a password input was seen. */
  hasLoginForm: boolean
  hasPasswordInput: boolean
  /** admin / dashboard / backoffice surface (path or explicit markers). */
  hasAdminIndicator: boolean
  /** checkout / cart / payment / billing surface. */
  hasPaymentIndicator: boolean
  /** authenticated user-data surface (account nav / "sign out" / profile). */
  hasPrivateUserData: boolean
  /** Any interactive `<form>` at all (GET or state-changing). */
  hasAnyForm: boolean
  /** A state-changing form (POST/PUT/PATCH/DELETE) is present. */
  hasStateChangingForm: boolean
  /** A CSRF defense is visible (token / meta / custom header / double-submit /
   * strong SameSite on an auth cookie). */
  hasCsrfSignal: boolean

  // --- VERIFIED transport-exposure signals (only set from real evidence) ---
  /** Private/user data was actually observed being served over http://. */
  servesPrivateDataOverHttp: boolean
  /** A login/credential form's action targets http:// (cleartext submit). */
  loginFormOverHttp: boolean

  /** Every Set-Cookie observed on the scan, parsed. */
  cookies: CookieObservation[]
}

/** The classifier's verdict for one finding. `null` = "not my concern". */
export interface ContextualClassification {
  severity: ContextualSeverity
  confidence: Confidence
  blocksPerfectScore: boolean
  contextClass: ContextClass
  reasonCodes: string[]
  explanation: string
  // ---- engine-facing mappings (kept in lockstep with `severity`) ----
  /** Engine risk class that drives effectiveSeverity + penalty tier. */
  riskClass: RiskClass
  /** When escalated to high/critical, re-route out of the clamped posture
   * bucket so the score actually moves; undefined leaves the engine mapping. */
  riskCategoryOverride?: RiskCategory
}

// ---------------------------------------------------------------------------
// Cookie sensitivity banks (from the product spec). Matched case-insensitively
// against the cookie NAME. Order: sensitive → semi → non-sensitive.
// ---------------------------------------------------------------------------

/** Usually carries a session / auth / identity. */
const SENSITIVE_COOKIE_PATTERNS: RegExp[] = [
  /^(?:.*[_.-])?sess(?:ion)?(?:id|_id)?$/i,
  /^sid$/i,
  /(?:^|[_.-])auth(?:[_.-]|$)/i,
  /(?:^|[_.-])(?:access|refresh|id)_token(?:[_.-]|$)/i,
  /(?:^|[_.-])token(?:[_.-]|$)/i,
  /(?:^|[_.-])jwt(?:[_.-]|$)/i,
  /(?:^|[_.-])login(?:[_.-]|$)/i,
  /(?:^|[_.-])remember[_.-]?me(?:[_.-]|$)/i,
  /^user(?:[_.-]|$)/i,
  /^account(?:[_.-]|$)/i,
  /^admin(?:[_.-]|$)/i,
  // framework / provider session cookie names
  /^connect\.sid$/i,
  /^phpsessid$/i,
  /^jsessionid$/i,
  /^asp\.net_sessionid$/i,
  /^laravel_session$/i,
  /^next-auth\.session-token$/i,
  /^__secure-next-auth\.session-token$/i,
  /^supabase-auth-token$/i,
  /^sb-[a-z0-9-]+-auth-token$/i,
  /firebase/i,
]

/** CSRF/state/device correlation — worth protecting, not a session by itself. */
const SEMI_SENSITIVE_COOKIE_PATTERNS: RegExp[] = [
  /(?:^|[_.-])x?csrf(?:[_.-]|$)/i,
  /(?:^|[_.-])x?xsrf(?:[_.-]|$)/i,
  /(?:^|[_.-])nonce(?:[_.-]|$)/i,
  /^state$/i,
  /(?:^|[_.-])device(?:[_.-]|$)/i,
  /(?:^|[_.-])visitor[_.-]?id(?:[_.-]|$)/i,
  /(?:^|[_.-])client[_.-]?id(?:[_.-]|$)/i,
]

/** Analytics / preference / consent — hardening-only. */
const NON_SENSITIVE_COOKIE_PATTERNS: RegExp[] = [
  /analytics/i,
  /^_ga(?:_[a-z0-9]+)?$/i,
  /^_gid$/i,
  /^_gat/i,
  /^utm/i,
  /^gclid$/i,
  /^_fbp$/i,
  /consent/i,
  /^locale$/i,
  /^lang$/i,
  /^theme$/i,
  /^prefs?$/i,
  /^preferences$/i,
  /^bucket$/i,
  /experiment/i,
  /^ab[_.-]?test$/i,
  /^variant$/i,
  /personalization/i,
  // Google infra cookies that are NOT sessions.
  /^nid$/i,
  /^aec$/i,
  /^dv$/i,
  /^socs$/i,
  /^1?p_jar$/i,
]

/**
 * Classify a cookie name. Non-sensitive is checked BEFORE sensitive so that a
 * clearly-analytics name (e.g. `NID`, `_ga`) can never be dragged into the
 * sensitive bucket by a loose substring. Unknown when nothing matches.
 */
export function classifyCookieSensitivity(name: string): CookieSensitivity {
  const n = (name || '').trim()
  if (!n || n === '(unknown)') return 'unknown'
  // Order matters. Non-sensitive first so a clearly-analytics name (`NID`,
  // `_ga`) can't be dragged into a higher bucket. Semi BEFORE sensitive so a
  // CSRF-token cookie (`xsrf-token`, `csrf`) isn't captured by the broad
  // `…token…` sensitive pattern — no genuinely-sensitive name matches the semi
  // bank, so this reorder only affects CSRF/state/device correlation cookies.
  if (NON_SENSITIVE_COOKIE_PATTERNS.some((re) => re.test(n))) return 'nonSensitive'
  if (SEMI_SENSITIVE_COOKIE_PATTERNS.some((re) => re.test(n))) return 'semiSensitive'
  if (SENSITIVE_COOKIE_PATTERNS.some((re) => re.test(n))) return 'sensitive'
  return 'unknown'
}

// ---------------------------------------------------------------------------
// Severity → engine mappings
// ---------------------------------------------------------------------------

const SEVERITY_TO_RISKCLASS: Record<ContextualSeverity, RiskClass> = {
  critical: 'critical-exploit',
  high: 'high-impact-misconfig',
  medium: 'medium-weakness',
  low: 'low-hardening',
  info: 'informational',
}

const SEV_RANK: Record<ContextualSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

function maxSeverity(a: ContextualSeverity, b: ContextualSeverity): ContextualSeverity {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b
}

// ---------------------------------------------------------------------------
// Cookie classification
// ---------------------------------------------------------------------------

/** Extract the cookie name from a `cookie-<name>` finding id. */
function cookieNameFromId(id: string): string {
  return id.startsWith('cookie-') ? id.slice('cookie-'.length) : ''
}

function classifyCookieFinding(
  cookie: CookieObservation,
  ctx: SiteSecurityContext,
): ContextualClassification {
  const reasonCodes: string[] = []
  const sens = cookie.sensitivity
  const isSensitive = sens === 'sensitive'
  const missingSecure = !cookie.hasSecure
  const missingSameSite = cookie.sameSite === null
  const sameSiteNoneNoSecure = cookie.sameSite === 'none' && !cookie.hasSecure
  const missingHttpOnly = !cookie.hasHttpOnly

  reasonCodes.push(
    sens === 'sensitive'
      ? 'COOKIE_SENSITIVE'
      : sens === 'semiSensitive'
        ? 'COOKIE_SEMISENSITIVE'
        : sens === 'nonSensitive'
          ? 'COOKIE_NONSENSITIVE'
          : 'COOKIE_UNKNOWN_NAME',
  )

  let severity: ContextualSeverity = 'info'
  let confidence: Confidence = 'possible'
  let contextClass: ContextClass = 'cookie'
  let riskCategoryOverride: RiskCategory | undefined

  // ---- Missing Secure ----
  if (missingSecure) {
    reasonCodes.push('MISSING_SECURE')
    if (isSensitive) {
      if (cookie.setOverHttp) {
        // Verified: a sensitive cookie was actually written over plain HTTP.
        severity = maxSeverity(severity, 'critical')
        confidence = 'verified'
        contextClass = 'transport'
        riskCategoryOverride = 'exploit'
        reasonCodes.push('SET_OVER_HTTP', 'VERIFIED_IMPACT')
      } else if (ctx.httpReachableWithoutRedirect) {
        // The host answers plain HTTP → the browser WILL attach this cookie to
        // the first http request. Strong, but short of "observed exfiltrated".
        severity = maxSeverity(severity, 'high')
        confidence = 'likely'
        contextClass = 'transport'
        riskCategoryOverride = riskCategoryOverride ?? 'exploit'
        reasonCodes.push('COULD_SEND_OVER_HTTP', 'HTTP_REACHABLE')
      } else if (!ctx.hstsPresent) {
        // HTTPS-only but no HSTS: a first-visit TOFU downgrade could still leak
        // it once. Real, but not high.
        severity = maxSeverity(severity, 'medium')
        if (confidence === 'possible') confidence = 'likely'
        reasonCodes.push('NO_HSTS', 'FIRST_REQUEST_RISK')
      } else {
        severity = maxSeverity(severity, 'low')
        reasonCodes.push('HSTS_PRESENT', 'RESIDUAL_HARDENING')
      }
    } else if (sens === 'semiSensitive' || sens === 'unknown') {
      if (ctx.httpReachableWithoutRedirect || cookie.setOverHttp) {
        severity = maxSeverity(severity, 'medium')
        reasonCodes.push(cookie.setOverHttp ? 'SET_OVER_HTTP' : 'HTTP_REACHABLE')
      } else {
        severity = maxSeverity(severity, 'low')
      }
    } else {
      // Non-sensitive (analytics/preference): always a hardening note.
      severity = maxSeverity(severity, 'low')
      reasonCodes.push('HARDENING_ONLY')
    }
  }

  // ---- SameSite ----
  if (sameSiteNoneNoSecure) {
    // SameSite=None without Secure is actively broken (browsers reject it AND
    // it is cross-site by declaration). Medium baseline; high if sensitive.
    reasonCodes.push('SAMESITE_NONE_NO_SECURE')
    severity = maxSeverity(severity, isSensitive ? 'high' : 'medium')
    if (isSensitive) {
      contextClass = 'cookie'
      riskCategoryOverride = riskCategoryOverride ?? 'access'
      if (confidence === 'possible') confidence = 'likely'
    }
  } else if (missingSameSite) {
    reasonCodes.push('MISSING_SAMESITE')
    if (!isSensitive) {
      severity = maxSeverity(severity, 'low')
    } else if (ctx.hasStateChangingForm && !ctx.hasCsrfSignal) {
      // Sensitive session cookie + a state-changing form + no visible CSRF
      // defense → real CSRF exposure. NOT verified (browsers default omitted
      // SameSite to Lax, and other defenses may exist unseen) → stays possible.
      severity = maxSeverity(severity, 'high')
      contextClass = 'csrf'
      riskCategoryOverride = riskCategoryOverride ?? 'access'
      reasonCodes.push('STATE_CHANGING_FORM', 'NO_CSRF_SIGNAL')
    } else {
      // Sensitive but no CSRF surface (or CSRF defense present) → medium at
      // most. Modern browsers default omitted SameSite to Lax.
      severity = maxSeverity(severity, 'medium')
      reasonCodes.push(ctx.hasCsrfSignal ? 'CSRF_SIGNAL_PRESENT' : 'DEFAULTS_TO_LAX')
    }
  }

  // ---- Missing HttpOnly (never escalates on its own; XSS-conditional) ----
  if (missingHttpOnly && isSensitive) {
    reasonCodes.push('MISSING_HTTPONLY')
    severity = maxSeverity(severity, 'low')
  }

  // Sensitive-context annotations (do not themselves escalate a cookie finding,
  // but explain WHY the reader should care).
  if (ctx.hasLoginForm || ctx.hasPasswordInput) reasonCodes.push('LOGIN_CONTEXT')
  if (ctx.hasAdminIndicator) reasonCodes.push('ADMIN_CONTEXT')
  if (ctx.hasPaymentIndicator) reasonCodes.push('PAYMENT_CONTEXT')

  if (SEV_RANK[severity] <= SEV_RANK.low) reasonCodes.push('DOWNGRADE_HARDENING_ONLY')
  else if (SEV_RANK[severity] >= SEV_RANK.high) reasonCodes.push('ESCALATED_SENSITIVE_CONTEXT')

  const blocksPerfectScore = SEV_RANK[severity] >= SEV_RANK.high

  return {
    severity,
    confidence,
    blocksPerfectScore,
    contextClass,
    reasonCodes,
    explanation: explainCookie(cookie, severity, reasonCodes),
    riskClass: SEVERITY_TO_RISKCLASS[severity],
    riskCategoryOverride,
  }
}

function explainCookie(
  cookie: CookieObservation,
  severity: ContextualSeverity,
  reasonCodes: string[],
): string {
  const sensLabel =
    cookie.sensitivity === 'sensitive'
      ? 'a session/auth cookie'
      : cookie.sensitivity === 'semiSensitive'
        ? 'a semi-sensitive (CSRF/state/device) cookie'
        : cookie.sensitivity === 'nonSensitive'
          ? 'a non-sensitive (analytics/preference) cookie'
          : 'a cookie of unknown sensitivity'
  const has = (c: string) => reasonCodes.includes(c)
  if (severity === 'critical') {
    return `"${cookie.name}" is ${sensLabel} and was set over plain HTTP without Secure — it is demonstrably exposed to any network attacker. Verified critical.`
  }
  if (severity === 'high') {
    if (has('COULD_SEND_OVER_HTTP')) {
      return `"${cookie.name}" is ${sensLabel} with no Secure flag, and the host also answers plain HTTP — the browser will attach it to the first cleartext request, enabling session theft. Escalated to High on evidence.`
    }
    if (has('NO_CSRF_SIGNAL')) {
      return `"${cookie.name}" is ${sensLabel} with no SameSite, and a state-changing form exists with no visible CSRF defense — a real cross-site-request-forgery surface. Escalated to High.`
    }
    if (has('SAMESITE_NONE_NO_SECURE')) {
      return `"${cookie.name}" is ${sensLabel} declared SameSite=None without Secure — cross-site by design and rejected by browsers. Escalated to High.`
    }
    return `"${cookie.name}" is ${sensLabel} with a sensitive-context weakness. Escalated to High.`
  }
  if (severity === 'medium') {
    return `"${cookie.name}" is ${sensLabel} missing a hardening flag; the residual risk is real but unverified (browsers default omitted SameSite to Lax, HTTPS mostly holds). Kept at Medium.`
  }
  if (severity === 'low') {
    return `"${cookie.name}" is ${sensLabel} missing a hardening flag. No sensitive/transport impact observed — a hardening note that stays visible but does not block a perfect score.`
  }
  return `"${cookie.name}" — informational cookie observation.`
}

// ---------------------------------------------------------------------------
// Transport classification (tls-no-http-redirect)
// ---------------------------------------------------------------------------

function classifyTransportFinding(ctx: SiteSecurityContext): ContextualClassification {
  const reasonCodes: string[] = ['HTTP_REACHABLE']
  const sensitiveCookieSetOverHttp = ctx.cookies.some(
    (c) => c.sensitivity === 'sensitive' && c.setOverHttp,
  )
  const sensitiveCookieExposable = ctx.cookies.some(
    (c) => c.sensitivity === 'sensitive' && !c.hasSecure,
  )
  const loginCtx = ctx.hasLoginForm || ctx.hasPasswordInput
  const adminPayCtx = ctx.hasAdminIndicator || ctx.hasPaymentIndicator

  let severity: ContextualSeverity
  let confidence: Confidence
  let riskCategoryOverride: RiskCategory | undefined

  if (ctx.servesPrivateDataOverHttp || sensitiveCookieSetOverHttp || ctx.loginFormOverHttp) {
    // Verified impact actually served/observed over HTTP.
    severity = 'critical'
    confidence = 'verified'
    riskCategoryOverride = 'exploit'
    if (ctx.servesPrivateDataOverHttp) reasonCodes.push('PRIVATE_DATA_OVER_HTTP')
    if (sensitiveCookieSetOverHttp) reasonCodes.push('SESSION_COOKIE_SET_OVER_HTTP')
    if (ctx.loginFormOverHttp) reasonCodes.push('LOGIN_FORM_OVER_HTTP')
    reasonCodes.push('VERIFIED_IMPACT')
  } else if (loginCtx || adminPayCtx || sensitiveCookieExposable || ctx.hasPrivateUserData) {
    // Sensitive surface exists on a host that also answers cleartext HTTP.
    severity = 'high'
    confidence = 'likely'
    riskCategoryOverride = 'exploit'
    if (loginCtx) reasonCodes.push('LOGIN_CONTEXT')
    if (ctx.hasAdminIndicator) reasonCodes.push('ADMIN_CONTEXT')
    if (ctx.hasPaymentIndicator) reasonCodes.push('PAYMENT_CONTEXT')
    if (sensitiveCookieExposable) reasonCodes.push('SENSITIVE_COOKIE_EXPOSABLE')
    if (ctx.hasPrivateUserData) reasonCodes.push('PRIVATE_DATA_CONTEXT')
    reasonCodes.push('ESCALATED_SENSITIVE_CONTEXT')
  } else if (ctx.hasAnyForm || ctx.hasStateChangingForm) {
    // Normal interactive site, but no observed auth/session/payment/admin
    // impact. Cleartext still matters for form data in transit → Medium.
    severity = 'medium'
    confidence = 'likely'
    reasonCodes.push('INTERACTIVE_FORMS_NO_SENSITIVE_IMPACT')
  } else {
    // Public/static content only. Hardening note; must not tank a clean site.
    severity = 'low'
    confidence = 'possible'
    reasonCodes.push('PUBLIC_STATIC_ONLY', 'DOWNGRADE_HARDENING_ONLY')
  }

  if (ctx.hstsPresent) reasonCodes.push('HSTS_PRESENT')

  return {
    severity,
    confidence,
    blocksPerfectScore: SEV_RANK[severity] >= SEV_RANK.high,
    contextClass: 'transport',
    reasonCodes,
    explanation: explainTransport(severity, reasonCodes),
    riskClass: SEVERITY_TO_RISKCLASS[severity],
    riskCategoryOverride,
  }
}

function explainTransport(severity: ContextualSeverity, reasonCodes: string[]): string {
  const has = (c: string) => reasonCodes.includes(c)
  if (severity === 'critical') {
    if (has('PRIVATE_DATA_OVER_HTTP')) {
      return 'Private/user data is served over plain HTTP on this host — cleartext exposure verified. Critical.'
    }
    if (has('SESSION_COOKIE_SET_OVER_HTTP')) {
      return 'A session/auth cookie is set over plain HTTP on this host — the session token travels in cleartext. Critical.'
    }
    return 'A login/credential form is served/submitted over plain HTTP — credentials travel in cleartext. Critical.'
  }
  if (severity === 'high') {
    return 'http:// is reachable without redirect AND this host exposes a login/admin/payment/private-data or a sensitive non-Secure cookie — a real session/credential-theft path over the cleartext channel. High.'
  }
  if (severity === 'medium') {
    return 'http:// is reachable without redirect on an interactive site (forms present) but with no observed auth/session/payment/admin/private-data impact. Data submitted before the upgrade travels in cleartext. Medium.'
  }
  return 'http:// is reachable without redirect, but the host serves only public/static content with no forms, sensitive cookies, or private data observed. A hardening note — does not block a perfect score.'
}

// ---------------------------------------------------------------------------
// Entry point used by the scoring engine
// ---------------------------------------------------------------------------

/**
 * Contextually re-classify a single finding. Returns `null` for anything that
 * is NOT one of the two families this module owns — those flow through the
 * generic engine unchanged.
 */
export function classifyContextualFinding(
  finding: { id: string; category: string },
  ctx: SiteSecurityContext,
): ContextualClassification | null {
  const id = finding.id || ''
  if (id === 'tls-no-http-redirect') {
    return classifyTransportFinding(ctx)
  }
  if (id.startsWith('cookie-') && finding.category === 'cookies') {
    const name = cookieNameFromId(id)
    const cookie =
      ctx.cookies.find((c) => c.name === name) ??
      // Fall back to name-only classification if the observation list didn't
      // carry this cookie (defensive — should not happen in production).
      ({
        name,
        hasSecure: false,
        hasHttpOnly: false,
        sameSite: null,
        setOverHttp: !ctx.httpsActive,
        sensitivity: classifyCookieSensitivity(name),
      } satisfies CookieObservation)
    return classifyCookieFinding(cookie, ctx)
  }
  return null
}

// ---------------------------------------------------------------------------
// Builder — turns raw passive scan evidence into a SiteSecurityContext.
// ---------------------------------------------------------------------------

export interface SiteContextInput {
  finalUrl: string
  httpsActive: boolean
  httpReachableWithoutRedirect: boolean
  hstsHeaderPresent: boolean
  /** Main page HTML (already fetched). */
  html: string
  /** Raw Set-Cookie strings from the main response. */
  setCookies: string[]
  /** VERIFIED only: the http:// probe body actually contained private data. */
  httpBodyPrivateData?: boolean
}

/** Parse one Set-Cookie string into a CookieObservation. */
export function parseCookie(cookieStr: string, setOverHttp: boolean): CookieObservation {
  const name = (cookieStr.split(';')[0]?.split('=')[0] ?? '').trim() || '(unknown)'
  const lower = ';' + cookieStr.toLowerCase()
  const hasSecure = /;\s*secure(\s|;|$)/i.test(lower)
  const hasHttpOnly = /;\s*httponly(\s|;|$)/i.test(lower)
  const ssMatch = /samesite=([a-z]+)/i.exec(cookieStr)
  const ssRaw = ssMatch?.[1]?.toLowerCase() ?? null
  const sameSite: CookieObservation['sameSite'] =
    ssRaw === 'strict' || ssRaw === 'lax' || ssRaw === 'none' ? ssRaw : null
  return {
    name,
    hasSecure,
    hasHttpOnly,
    sameSite,
    setOverHttp,
    sensitivity: classifyCookieSensitivity(name),
  }
}

export function buildSiteSecurityContext(input: SiteContextInput): SiteSecurityContext {
  const html = input.html || ''
  const path = (() => {
    try {
      return new URL(input.finalUrl).pathname.toLowerCase()
    } catch {
      return '/'
    }
  })()

  const cookies = input.setCookies.map((c) => parseCookie(c, !input.httpsActive))

  const hasPasswordInput = /<input[^>]*type\s*=\s*["']password["']/i.test(html)
  const hasLoginAction =
    /<form[^>]*action\s*=\s*["'][^"']*\b(?:login|signin|sign[-_]in|auth|session)\b/i.test(html)
  const hasLoginForm = hasPasswordInput || hasLoginAction

  const hasAdminIndicator =
    /\/(?:admin|backoffice|wp-admin|dashboard|cms)\b/i.test(path) ||
    /<[^>]+\b(?:id|class)\s*=\s*["'][^"']*\badmin(?:-nav|-panel|-menu)?\b/i.test(html)

  const hasPaymentIndicator =
    /\/(?:checkout|cart|payment|payments|billing|order|subscribe|subscription|pay)\b/i.test(path) ||
    /js\.stripe\.com|checkout\.stripe|paypal\.com\/sdk|\bpk_live_/i.test(html)

  const hasPrivateUserData =
    /\/(?:account|profile|settings|dashboard|inbox|orders|wallet)\b/i.test(path) ||
    /\b(?:sign out|log ?out|my account|your account|logged in as)\b/i.test(html)

  // Forms: any <form>, and whether a state-changing method is present.
  const formTags = Array.from(html.matchAll(/<form\b[^>]*>/gi)).map((m) => m[0])
  const hasAnyForm = formTags.length > 0
  const hasStateChangingForm = formTags.some((t) =>
    /\bmethod\s*=\s*["']?(?:post|put|patch|delete)["']?/i.test(t),
  )

  // CSRF defenses visible to a passive scan.
  const hasVisibleToken =
    /name\s*=\s*["'](?:_csrf|csrf|csrf_token|authenticity_token|_token|csrfmiddlewaretoken|__RequestVerificationToken|xsrf|xsrf_token|anti-?forgery)["']/i.test(
      html,
    )
  const hasMetaToken =
    /<meta\b[^>]*\bname\s*=\s*["'](?:csrf-token|csrf-param|_csrf)["']/i.test(html)
  const hasCsrfHeader = /X-CSRF-?Token|X-XSRF-?Token|X-Requested-With/i.test(html)
  const strongSameSiteAuthCookie = cookies.some(
    (c) => c.sensitivity === 'sensitive' && (c.sameSite === 'lax' || c.sameSite === 'strict'),
  )
  const hasCsrfSignal =
    hasVisibleToken || hasMetaToken || hasCsrfHeader || strongSameSiteAuthCookie

  // Verified transport signals — only from real evidence.
  const loginFormOverHttp =
    hasLoginForm &&
    /<form\b[^>]*\baction\s*=\s*["']http:\/\/[^"']+["']/i.test(html)

  return {
    httpsActive: input.httpsActive,
    httpReachableWithoutRedirect: input.httpReachableWithoutRedirect,
    httpsReachable: input.httpsActive,
    hstsPresent: input.hstsHeaderPresent,
    hasLoginForm,
    hasPasswordInput,
    hasAdminIndicator,
    hasPaymentIndicator,
    hasPrivateUserData,
    hasAnyForm,
    hasStateChangingForm,
    hasCsrfSignal,
    servesPrivateDataOverHttp:
      // Only "verified" when the site itself is served over HTTP (so this page's
      // private-data indicators ARE the http response) or the http probe body
      // was confirmed to carry private data.
      (input.httpBodyPrivateData ?? false) || (!input.httpsActive && hasPrivateUserData),
    loginFormOverHttp,
    cookies,
  }
}
