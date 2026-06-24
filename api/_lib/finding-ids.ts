/**
 * Vguard — Finding-ID contract (single source of truth).
 *
 * THE bug the 2026-06-07 audit found: detectors in `scanner.ts` emit ids like
 * `secret-stripe-<file>`, `path--env`, `paths-reflected-xss`,
 * `headers-cors-wildcard`, while the scoring policy gated on *different* strings
 * (`secrets-stripe-secret`, `paths-env`, `paths-xss-reflected`,
 * `cors-credentials-wildcard`). The verified-impact gate therefore almost never
 * fired for Stage-1 findings, so real secret leaks / `.env` exposures / reflected
 * XSS collapsed to "medium" and the site could still score 79/C.
 *
 * This module is the ONE place that maps an emitted finding `id` (+ category)
 * to its security meaning. Both the detectors and the scoring engine import from
 * here, so the two layers can never drift again. Every predicate recognises the
 * REAL emitted ids AND the legacy/policy spellings, so historical data and the
 * existing test fixtures keep classifying correctly.
 *
 * Pure module — no I/O, browser-safe.
 */

import type { Category, Finding } from '../../src/lib/scanner-types.js'

const has = (s: string, ...needles: string[]) =>
  needles.some((n) => s.includes(n))

const lc = (s: string | undefined | null) => (s || '').toLowerCase()

// ---------------------------------------------------------------------------
// Secrets — real provider keys shipped to the client
// ---------------------------------------------------------------------------

/**
 * A real provider/credential secret leak. Matches the detector ids
 * `secret-<provider>-<file>` and `secret-supabase-service-role-<file>` AND the
 * legacy policy ids `secrets-<provider>`. Excludes the AST heuristic
 * (`js-ast-hardcoded-creds`) and known-public client identifiers — those are
 * handled separately and must never reach the "verified secret" lane.
 */
export function isRealProviderSecretId(id: string): boolean {
  const s = lc(id)
  if (s.startsWith('js-ast-')) return false
  // service-role JWT is the worst case — bypasses all RLS.
  if (has(s, 'supabase-service-role', 'service-role')) return true
  // `secret-<provider>-<file>` (real emit) or `secrets-<provider>` (policy).
  return s.startsWith('secret-') || s.startsWith('secrets-')
}

// ---------------------------------------------------------------------------
// Path probes — sensitive files reachable on the origin
// ---------------------------------------------------------------------------

/**
 * Path-probe ids are emitted as `path-<slugified-path>` (real) where the path's
 * `/` and `.` are replaced with `-`, plus `-exposed-needs-review` /
 * `-spa-shell-200` / `-empty-200` variants. Legacy/policy spelling is `paths-*`.
 */
export function isPathProbeId(id: string): boolean {
  const s = lc(id)
  return s.startsWith('path-') || s.startsWith('paths-')
}

/** A sensitive-file exposure (`.env`, `.git`, db dump, backup, AWS creds, …). */
export function isSensitiveFileId(id: string): boolean {
  if (!isPathProbeId(id)) return false
  const s = lc(id)
  return has(
    s,
    'env', // .env / .env.local / .env.production
    'git', // .git/HEAD / .git/config
    'aws-credential',
    'database-sql',
    'database',
    'dump-sql',
    'dump',
    'backup',
    'svn',
    'hg-hgrc',
    'phpinfo',
    'web-config',
  )
}

/** A publicly-listable cloud bucket / database root (observation = real impact). */
export function isPublicDataStoreId(id: string): boolean {
  const s = lc(id)
  return has(
    s,
    'firebase-rtdb',
    'supabase-storage-public',
    'firebase-storage-public',
    's3-listbucket',
    's3-list',
    'directory-listing',
    'dir-listing',
  )
}

/** An admin route that returned real data without auth. */
export function isAdminUnauthDataId(id: string): boolean {
  const s = lc(id)
  return has(s, 'admin-unauth-data', 'admin-route-public', 'admin-route-unauth')
}

// ---------------------------------------------------------------------------
// Active probes — network-confirmed exploits
// ---------------------------------------------------------------------------

/**
 * Reflected XSS detected by a reflected canary. V6: a reflected canary is
 * "Possible XSS" — reflection is DETECTION, not browser-confirmed execution.
 * Only `isVerifiedXssId` counts as Verified XSS (a Golden Finding).
 */
export function isReflectedXssId(id: string): boolean {
  return has(lc(id), 'reflected-xss', 'xss-reflected')
}

/**
 * Verified XSS — payload execution confirmed (browser-executed via Stage 2/3
 * aggressive probing). The only XSS variant that qualifies as a Golden Finding.
 */
export function isVerifiedXssId(id: string): boolean {
  const s = lc(id)
  return has(s, 'aggressive-xss', 'xss-executed', 'xss-verified', 'xss-confirmed')
}

/** SQL injection confirmed by an error signature. */
export function isSqliId(id: string): boolean {
  return has(lc(id), 'sqli')
}

/** Open redirect confirmed by a Location canary. */
export function isOpenRedirectId(id: string): boolean {
  return has(lc(id), 'open-redirect')
}

/** Path traversal confirmed by a system-file marker. */
export function isPathTraversalId(id: string): boolean {
  return has(lc(id), 'traversal')
}

/** SSRF confirmed out-of-band (OAST). */
export function isSsrfId(id: string): boolean {
  return has(lc(id), 'ssrf')
}

/**
 * Any active-probe hit. These are the only Stage-1 findings carrying true
 * network confirmation. Open redirect is included for confirmation but is
 * graded as high (not critical) by the trait layer — see finding-traits.ts.
 */
export function isActiveProbeHitId(id: string): boolean {
  return (
    isReflectedXssId(id) ||
    isVerifiedXssId(id) ||
    isSqliId(id) ||
    isOpenRedirectId(id) ||
    isPathTraversalId(id) ||
    isSsrfId(id)
  )
}

// ---------------------------------------------------------------------------
// Forward-compat predicates — the V6 engine scores these kinds; detectors for
// some of them don't exist yet (rate limiting, CSRF, RCE). Registering the ids
// here first keeps the contract rule: new finding type → new predicate → THEN
// a detector may emit it.
// ---------------------------------------------------------------------------

/** Remote code execution confirmed (no Stage-1 detector yet — Stage 3 future). */
export function isRceId(id: string): boolean {
  const s = lc(id)
  // 'rce' must be token-anchored — a bare substring would match 'sou*rce*maps'.
  return (
    /(?:^|-)rce(?:-|$)/.test(s) ||
    has(s, 'remote-code-execution', 'command-injection', 'cmd-injection')
  )
}

/** CSRF weakness (no dedicated detector yet — form-token analysis is partial). */
export function isCsrfId(id: string): boolean {
  return has(lc(id), 'csrf')
}

/**
 * Missing rate limiting on auth surfaces (login / password reset / OTP / MFA),
 * credential-stuffing exposure, weak account lockout. No detector emits these
 * yet — scoring support only.
 */
export function isRateLimitId(id: string): boolean {
  const s = lc(id)
  return has(s, 'rate-limit', 'rate-limiting', 'credential-stuffing', 'account-lockout', 'brute-force')
}

/** Prompt injection against an AI endpoint (Stage-3 probe). */
export function isPromptInjectionId(id: string): boolean {
  return has(lc(id), 'prompt-injection', 'mcp-rag-leak')
}

/** The synthetic "a WAF fronts this origin" observation (bonus-only signal). */
export function isWafPresentId(id: string): boolean {
  return has(lc(id), 'waf-detected', 'waf-present')
}

// ---------------------------------------------------------------------------
// Stage 3 — ownership-verified deep-scan confirmations
// ---------------------------------------------------------------------------

/**
 * A confirmed Stage-3 exploit. Matches the REAL deep-scanner ids
 * (`auth-rls-leak`, `auth-idor-rls`, `paths-supabase-storage-anon-write`,
 * `paths-aggressive-xss`, `paths-traversal`, `ai-mcp-rag-leak`,
 * `ai-prompt-injection`) AND the legacy `stage3-*` / `deep-*` spellings.
 */
export function isStage3ConfirmationId(id: string): boolean {
  const s = lc(id)
  if (s.startsWith('stage3-') || s.startsWith('deep-')) return true
  return has(
    s,
    'rls-leak',
    'rls-broken',
    'rls-anon-select',
    'idor-rls',
    'idor',
    'storage-anon-write',
    'storage-public-write',
    'mass-assignment',
    'mcp-rag-leak',
    'prompt-injection',
    'admin-unauth-data',
  )
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/**
 * Dangerous CORS — wildcard origin combined with credentials (or an
 * edge-function wildcard). Matches the real `headers-cors-wildcard` emit AND
 * the legacy `cors-credentials-wildcard` / `cors-creds-wildcard` spellings.
 * NOTE: this only tells you the id is a CORS finding; whether it is *dangerous*
 * also depends on severity/evidence (credentials present) — see finding-traits.
 */
export function isCorsId(id: string): boolean {
  return has(lc(id), 'cors-wildcard', 'cors-credentials', 'cors-creds', 'cors-open')
}

// ---------------------------------------------------------------------------
// TLS / transport
// ---------------------------------------------------------------------------

/**
 * Broken transport that allows a real downgrade/MITM. NOTE: must NOT match the
 * healthy `tls-https` ok-marker — `'tls-https'.includes('tls-http')` is true, so
 * the plain-HTTP marker is matched exactly, not as a substring.
 */
export function isBrokenTlsId(id: string): boolean {
  const s = lc(id)
  if (s === 'tls-http' || s.startsWith('tls-http-')) return true // served plain http
  return has(s, 'tls-old-version', 'tls-weak-version', 'tls-weak-cipher', 'tls-cert-expired')
}

// ---------------------------------------------------------------------------
// Source maps
// ---------------------------------------------------------------------------

export function isSourceMapWithSecretsId(id: string): boolean {
  return has(lc(id), 'sourcemaps-exposed-with-secrets', 'sourcemap-with-secrets')
}

export function isSourceMapId(id: string): boolean {
  return has(lc(id), 'sourcemap')
}

// ---------------------------------------------------------------------------
// Dependencies / takeover
// ---------------------------------------------------------------------------

export function isCriticalDepId(id: string): boolean {
  return has(lc(id), 'deps-server-cve', 'deps-npm')
}

export function isSubdomainTakeoverId(id: string): boolean {
  return has(lc(id), 'subdomain-takeover')
}

// ---------------------------------------------------------------------------
// Hardening headers — baseline vs advanced
// ---------------------------------------------------------------------------

const ADVANCED_HEADER_TOKENS = [
  'coop',
  'coep',
  'corp',
  'permissions-policy',
  'cross-origin-opener',
  'cross-origin-embedder',
  'cross-origin-resource',
  'referrer-policy',
  'origin-agent-cluster',
]

/** Advanced, defense-in-depth-only header (COOP/COEP/CORP/Referrer/Permissions). */
export function isAdvancedHardeningHeaderId(
  id: string,
  evidence = '',
  description = '',
): boolean {
  const hay = `${lc(id)} ${lc(evidence)} ${lc(description)}`
  return ADVANCED_HEADER_TOKENS.some((t) => hay.includes(t))
}

/**
 * Baseline hardening headers (CSP / HSTS / X-Frame-Options / X-Content-Type) —
 * missing or weak. THE bug: these are emitted as `headers-content-security-policy`
 * / `headers-strict-transport-security` / `headers-x-frame-options` /
 * `headers-x-content-type-options` (the literal header name), which never matched
 * the policy's `headers-csp-missing` / `headers-no-hsts` list, so they were
 * mis-scored as medium instead of low-hardening. We recognise both spellings.
 */
export function isBaselineHardeningHeaderId(id: string): boolean {
  const s = lc(id)
  if (!s.startsWith('headers-')) return false
  if (isAdvancedHardeningHeaderId(id)) return false
  return has(
    s,
    'content-security-policy',
    'csp-missing',
    'csp-weak',
    'csp-unsafe',
    'csp-wildcard',
    'csp-no-',
    'strict-transport-security',
    'hsts',
    'x-frame-options',
    'x-content-type',
    'no-x-content-type',
  )
}

/** Any hardening header (baseline or advanced). */
export function isHardeningHeaderId(id: string): boolean {
  return isBaselineHardeningHeaderId(id) || isAdvancedHardeningHeaderId(id)
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/** A cookie-hardening finding (`cookie-<name>` real, `cookies-no-*` policy). */
export function isCookieHardeningId(id: string): boolean {
  const s = lc(id)
  return s.startsWith('cookie-') || s.startsWith('cookies-')
}

// ---------------------------------------------------------------------------
// Public client identifiers — NOT secrets
// ---------------------------------------------------------------------------

const PUBLIC_CLIENT_ID_TOKENS = [
  'next_public_',
  'vite_',
  'react_app_',
  'expo_public_',
  'firebase_api_key',
  'supabase_anon_key',
  'pk_live_',
  'pk_test_',
  'mapbox',
  'sentry_dsn',
  'ga_id',
  'gtm-',
  'gtag',
  'recaptcha_site_key',
  'turnstile_site_key',
  'hcaptcha_site_key',
  'googletagmanager',
  'google-analytics',
  'google_maps_api',
  'publishable_key',
]

/** True when the id/evidence/description points at a publishable client ID. */
export function isPublicClientIdentifier(
  id: string,
  evidence = '',
  description = '',
): boolean {
  const hay = `${lc(id)} ${lc(evidence)} ${lc(description)}`
  return PUBLIC_CLIENT_ID_TOKENS.some((t) => hay.includes(t))
}

// ---------------------------------------------------------------------------
// V6 — Golden Findings, grade-cap set, recon set
// ---------------------------------------------------------------------------

/** RLS bypass / broken RLS (anon key can read protected rows). */
export function isRlsBypassId(id: string): boolean {
  const s = lc(id)
  return has(s, 'rls-leak', 'rls-broken', 'rls-anon-select', 'rls-bypass')
}

/** IDOR (direct object reference across users). */
export function isIdorId(id: string): boolean {
  return has(lc(id), 'idor')
}

/** Anonymous write to a storage bucket / table. */
export function isAnonymousWriteId(id: string): boolean {
  const s = lc(id)
  return has(s, 'storage-anon-write', 'storage-public-write', 'anon-write', 'anonymous-write')
}

/** Supabase service-role key shipped to the client (bypasses all RLS). */
export function isServiceRoleKeyId(id: string): boolean {
  return has(lc(id), 'service-role')
}

/** AWS credentials exposed (key file or secret in bundle). */
export function isAwsCredentialsId(id: string): boolean {
  const s = lc(id)
  return has(s, 'aws-credential', 'secrets-aws', 'secret-aws')
}

/** A database dump / sqlite / backup archive reachable on the origin. */
export function isDatabaseDumpId(id: string): boolean {
  if (!isPathProbeId(id)) return false
  const s = lc(id)
  return has(s, 'database', 'dump', 'sqlite', 'backup')
}

/** An exposed `.env` file (any variant). */
export function isEnvFileId(id: string): boolean {
  if (!isPathProbeId(id)) return false
  return has(lc(id), 'env')
}

/**
 * Golden Finding KIND — the id belongs to one of the major-security-failure
 * kinds from the V6 spec. Kind alone is not enough to BE a Golden Finding:
 * the policy layer additionally requires `verifiedImpact` and excludes public
 * client identifiers (see `isGoldenFinding` in scoring-policy.ts). The kind
 * does drive the penalty BASE even when unverified (confidence then scales it
 * down: likely ×0.6, possible ×0.2).
 */
export function isGoldenKindId(id: string): boolean {
  return (
    isRlsBypassId(id) ||
    isIdorId(id) ||
    isSqliId(id) ||
    isEnvFileId(id) ||
    isDatabaseDumpId(id) ||
    isServiceRoleKeyId(id) ||
    isAwsCredentialsId(id) ||
    isVerifiedXssId(id) ||
    isSsrfId(id) ||
    isPathTraversalId(id) ||
    isRealProviderSecretId(id) || // "secrets in responses"
    isAnonymousWriteId(id) ||
    isPublicDataStoreId(id) || // public S3 / Firebase / Supabase storage
    isSourceMapWithSecretsId(id) ||
    isRceId(id)
  )
}

/**
 * The SCORE-CAP subset of Golden Findings. Any VERIFIED finding of these kinds
 * caps the grade at C (79) until fixed — overriding all other calculations:
 * IDOR · RLS bypass · SQLi · .env exposed · DB dump exposed · service-role
 * key exposed · RCE.
 */
export function isGradeCapGoldenId(id: string): boolean {
  return (
    isIdorId(id) ||
    isRlsBypassId(id) ||
    isSqliId(id) ||
    isEnvFileId(id) ||
    isDatabaseDumpId(id) ||
    isServiceRoleKeyId(id) ||
    isRceId(id)
  )
}

/**
 * Recon / fingerprinting observation — useful for visibility, ZERO score
 * impact: robots/sitemap, framework detection, WAF detection, GraphQL/Swagger
 * presence, package manifests, server headers, AI/tRPC/health endpoints,
 * console errors. (`meta` category findings are recon by definition — checked
 * at the policy layer, which sees the category.)
 */
export function isReconFindingId(id: string): boolean {
  const s = lc(id)
  return (
    isWafPresentId(id) ||
    has(
      s,
      'robots',
      'sitemap',
      'framework-detect',
      'react-detect',
      'nextjs-detect',
      'graphql',
      'swagger',
      'openapi',
      'api-docs',
      'package-json',
      'composer-json',
      'server-header',
      'x-powered-by',
      'powered-by',
      'ai-endpoint',
      'trpc',
      'health-endpoint',
      'console-error',
      'well-known',
      'status',
      'manifest',
      'humans-txt',
      'security-txt',
    )
  )
}

// ---------------------------------------------------------------------------
// Convenience: stage / runtime markers
// ---------------------------------------------------------------------------

export function isStage2Id(id: string): boolean {
  return lc(id).startsWith('stage2-')
}

/** The `meta` category is always informational (WAF present, localhost ref, …). */
export function isInformationalMeta(finding: Pick<Finding, 'category'>): boolean {
  return finding.category === ('meta' as Category)
}
