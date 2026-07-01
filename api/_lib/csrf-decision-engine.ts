/**
 * CSRF Decision Engine (V-Guards)
 * ================================
 * A small, professional decision layer that decides WHEN a missing/invisible
 * CSRF protection is merely informational, when it is a small unverified signal,
 * and when it is a real security finding.
 *
 * CORE PRINCIPLE: the absence of a *visible* HTML CSRF token is NOT proof of a
 * vulnerability. Modern apps defend with SameSite cookies, Origin/Referer
 * validation, framework middleware, custom CSRF headers, SPA/API auth, or the
 * double-submit-cookie pattern — none of which a passive HTML scan can see.
 *
 * THEREFORE, in passive mode this engine is HARD-CAPPED at `low`. Medium / High /
 * Critical are reserved for a future active/deep-scan mode that actively proves
 * protection is missing (a forged cross-site request is accepted). Passive
 * evidence alone can never produce Medium+.
 *
 * This module is PURE and network-free so it is fully unit-testable. It takes
 * evidence the scanner collected passively and returns a normalized decision.
 * No brand/domain whitelists — decisions are evidence-based only.
 */

export type CsrfDecision = 'no_issue' | 'info' | 'low' | 'medium' | 'high' | 'critical'

/** Apparent business impact of the target endpoint/form. Unclear → `unknown`. */
export type EndpointSensitivity = 'public' | 'auth' | 'account' | 'financial' | 'unknown'

export type CsrfFramework =
  | 'django'
  | 'laravel'
  | 'rails'
  | 'aspnet'
  | 'angular'
  | 'spring'
  | 'express'
  | null

/** Detector-emit severity (matches the scanner Finding `severity` union). */
export type CsrfEmitSeverity = 'info' | 'warn' | 'critical'
export type CsrfConfidence = 'possible' | 'likely' | 'verified'

export interface CsrfTarget {
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** action URL / endpoint path. */
  action: string
  /** whether the action appears same-origin as the scanned page. */
  sameOrigin: boolean
  /** form-based vs JavaScript/API-based. */
  kind: 'form' | 'api'
}

export interface CsrfEvidence {
  target: CsrfTarget

  // --- (2) visible CSRF token evidence ---
  /** hidden input / form field / obvious inline config carrying a token. */
  hasVisibleToken: boolean
  /** a <meta name="csrf-token"> (or csrf-param / _csrf) tag is present. */
  hasTokenMetaTag: boolean
  /** JavaScript appears to read the meta token (e.g. to send it as a header). */
  metaTokenUsedByJs: boolean

  // --- (3) header-based evidence ---
  /** JS/config sends a custom CSRF header (X-CSRF-Token / X-XSRF-Token / X-Requested-With / …). */
  hasCsrfHeaderEvidence: boolean

  // --- (5) double-submit cookie evidence ---
  /** a likely double-submit pattern (XSRF-TOKEN cookie + X-XSRF-Token header, csrftoken + X-CSRFToken, …). */
  doubleSubmitCookiePattern: boolean

  // --- (4) cookie evidence ---
  /** strongest SameSite seen on an auth/session-like cookie (null = missing/none-of-those). */
  authCookieSameSite: 'strict' | 'lax' | 'none' | null
  /** an auth/session-like cookie was observed at all. */
  hasAuthSessionCookie: boolean

  // --- (6) framework hint (reduces suspicion, never sole proof) ---
  framework: CsrfFramework

  /** scan mode. `passive` is hard-capped at `low`. */
  mode: 'passive' | 'active'
  /** (D) active-verification outcomes — only populated in a verified/deep scan. */
  activeVerification?: {
    /** a request with a missing/bogus token was accepted. */
    missingTokenAccepted?: boolean
    /** Origin/Referer protection appears absent or ignored. */
    originRefererIgnored?: boolean
    /** a forged cross-site request successfully performed a state change. */
    confirmedStateChange?: boolean
  }
}

export interface CsrfDecisionResult {
  decision: CsrfDecision
  /** null when `no_issue` (no finding is emitted). */
  findingId: string | null
  severity: CsrfEmitSeverity
  confidence: CsrfConfidence
  sensitivity: EndpointSensitivity
  /** human-readable "why", for evidence strings and the UI. */
  reasons: string[]
}

/** Stable finding IDs per decision tier. The old visibility-only id
 *  (`html-form-no-csrf`) is intentionally NOT one of these — it stays recon. */
export const CSRF_FINDING_IDS = {
  info: 'csrf-protection-not-visible-info',
  low: 'csrf-sensitive-action-no-passive-protection-low',
  medium: 'csrf-active-bypass-accepted-medium',
  high: 'csrf-state-change-confirmed-high',
  critical: 'csrf-critical-state-change-confirmed',
} as const

/** Ordering so callers can pick the most severe decision across many forms. */
export const DECISION_RANK: Record<CsrfDecision, number> = {
  no_issue: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
}

export function maxDecision(
  a: CsrfDecisionResult | null,
  b: CsrfDecisionResult | null,
): CsrfDecisionResult | null {
  if (!a) return b
  if (!b) return a
  return DECISION_RANK[b.decision] > DECISION_RANK[a.decision] ? b : a
}

// --- (7) endpoint sensitivity keyword buckets (conservative) -----------------
const SENSITIVITY_KEYWORDS: { bucket: EndpointSensitivity; words: string[] }[] = [
  // financial / destructive / admin (checked first — highest impact wins)
  {
    bucket: 'financial',
    words: [
      'payment', 'checkout', 'order', 'transfer', 'billing', 'invoice',
      'delete', 'remove', 'admin', 'role', 'permission', 'invite',
      'upload', 'publish',
    ],
  },
  // account mutation
  {
    bucket: 'account',
    words: [
      'profile', 'account', 'settings', 'email', 'password', 'address',
      'user/update', 'user-update', 'preferences',
    ],
  },
  // auth lifecycle
  {
    bucket: 'auth',
    words: [
      'login', 'logout', 'register', 'signup', 'sign-up',
      'forgot-password', 'forgot_password', 'reset-password', 'reset_password',
    ],
  },
  // public / non-sensitive
  {
    bucket: 'public',
    words: [
      'contact', 'search', 'newsletter', 'subscribe', 'feedback',
      'message', 'quote', 'lead',
    ],
  },
]

/**
 * Classify an endpoint/form by apparent business impact from its action path
 * (and optional input field names). Conservative: unclear → `unknown`.
 */
export function classifyEndpointSensitivity(
  action: string,
  inputs: string[] = [],
): EndpointSensitivity {
  const hay = `${action} ${inputs.join(' ')}`.toLowerCase()
  for (const { bucket, words } of SENSITIVITY_KEYWORDS) {
    if (words.some((w) => hay.includes(w))) return bucket
  }
  return 'unknown'
}

const SENSITIVE_BUCKETS: ReadonlySet<EndpointSensitivity> = new Set([
  'auth',
  'account',
  'financial',
])

function result(
  decision: CsrfDecision,
  sensitivity: EndpointSensitivity,
  reasons: string[],
): CsrfDecisionResult {
  const map: Record<CsrfDecision, { id: string | null; sev: CsrfEmitSeverity; conf: CsrfConfidence }> = {
    no_issue: { id: null, sev: 'info', conf: 'possible' },
    info: { id: CSRF_FINDING_IDS.info, sev: 'info', conf: 'possible' },
    low: { id: CSRF_FINDING_IDS.low, sev: 'warn', conf: 'possible' },
    medium: { id: CSRF_FINDING_IDS.medium, sev: 'warn', conf: 'likely' },
    high: { id: CSRF_FINDING_IDS.high, sev: 'critical', conf: 'likely' },
    critical: { id: CSRF_FINDING_IDS.critical, sev: 'critical', conf: 'verified' },
  }
  const m = map[decision]
  return { decision, findingId: m.id, severity: m.sev, confidence: m.conf, sensitivity, reasons }
}

/**
 * The decision matrix. See DECISION.md / docs/CSRF-DECISION-ENGINE.md.
 */
export function decideCsrf(ev: CsrfEvidence): CsrfDecisionResult {
  const sensitivity = classifyEndpointSensitivity(ev.target.action)
  const sensitive = SENSITIVE_BUCKETS.has(sensitivity)

  // Strong, direct protection evidence.
  const strongProtection =
    ev.hasVisibleToken ||
    (ev.hasTokenMetaTag && ev.metaTokenUsedByJs) ||
    ev.hasCsrfHeaderEvidence ||
    ev.doubleSubmitCookiePattern

  // Strong SameSite mitigation on an auth/session cookie.
  const strongSameSite =
    ev.hasAuthSessionCookie &&
    (ev.authCookieSameSite === 'strict' || ev.authCookieSameSite === 'lax')

  // Any weaker "alternative protection is plausible" signal (→ at most info).
  const someAltEvidence =
    strongSameSite || ev.hasTokenMetaTag || ev.framework !== null

  // ---- D. Active verification (deep/verified scan only) --------------------
  // Only here can Medium/High/Critical arise. Passive mode can never enter this.
  if (ev.mode === 'active' && ev.activeVerification) {
    const av = ev.activeVerification
    const highImpact =
      sensitivity === 'financial' || sensitivity === 'account' || sensitivity === 'auth'
    if (av.confirmedStateChange) {
      return highImpact
        ? result('critical', sensitivity, [
            'Active verification: a forged cross-site request successfully performed a high-impact state-changing action.',
          ])
        : result('high', sensitivity, [
            'Active verification: a forged cross-site request performed a state-changing action.',
          ])
    }
    if (av.missingTokenAccepted || av.originRefererIgnored) {
      return highImpact
        ? result('high', sensitivity, [
            'Active verification: a sensitive state-changing action was accepted without CSRF protection.',
          ])
        : result('medium', sensitivity, [
            'Active verification: a missing/bogus token was accepted and Origin/Referer was not enforced; impact not fully confirmed.',
          ])
    }
    // Active scan ran but proved protection present → fall through to passive logic.
  }

  // ---- A. No issue — strong protection evidence exists ---------------------
  if (strongProtection) {
    const why =
      ev.hasVisibleToken
        ? 'A visible CSRF token was found.'
        : ev.hasCsrfHeaderEvidence
          ? 'The app sends a custom CSRF header (X-CSRF-Token / X-XSRF-Token / …).'
          : ev.doubleSubmitCookiePattern
            ? 'A double-submit cookie pattern was detected.'
            : 'A CSRF meta token is present and appears to be used by JavaScript.'
    return result('no_issue', sensitivity, [why])
  }
  // A (cont.) — strong SameSite on auth cookie AND the endpoint is public/non-sensitive.
  if (strongSameSite && sensitivity === 'public') {
    return result('no_issue', sensitivity, [
      `Auth/session cookie uses SameSite=${ev.authCookieSameSite} and the endpoint is public/non-sensitive.`,
    ])
  }

  // ---- C. Low — sensitive action, no passive protection evidence at all ----
  // Passive & unverified. Framework hints DO NOT suppress this (they are not
  // proof); only real token/header/double-submit/SameSite evidence would.
  if (
    sensitive &&
    !ev.hasVisibleToken &&
    !ev.hasTokenMetaTag &&
    !ev.hasCsrfHeaderEvidence &&
    !ev.doubleSubmitCookiePattern &&
    !strongSameSite
  ) {
    return result('low', sensitivity, [
      `A ${sensitivity} state-changing endpoint has no visible CSRF token, no CSRF header, no double-submit cookie, and no strong SameSite mitigation on an auth/session cookie. Unverified — review recommended.`,
    ])
  }

  // ---- B. Info — everything else (default) ---------------------------------
  const reasons: string[] = []
  if (someAltEvidence) {
    if (strongSameSite) reasons.push(`Auth/session cookie uses SameSite=${ev.authCookieSameSite}.`)
    if (ev.hasTokenMetaTag) reasons.push('A CSRF meta token tag is present (JS usage not confirmed).')
    if (ev.framework) reasons.push(`Framework hint (${ev.framework}) suggests built-in CSRF protection, but direct evidence is incomplete.`)
  } else if (sensitivity === 'public') {
    reasons.push('Endpoint appears public/non-sensitive.')
  } else if (sensitivity === 'unknown') {
    reasons.push('Endpoint sensitivity is unknown and no exploit was verified.')
  } else {
    reasons.push('No visible CSRF token, but protection status could not be determined from a passive scan.')
  }
  return result('info', sensitivity, reasons)
}
