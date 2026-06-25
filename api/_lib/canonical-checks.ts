/**
 * Vguard — Canonical customer-facing check list (single source of truth).
 *
 * 2026-06-22 product decision: the main URL-scan report and the Vibe Score are
 * based on EXACTLY these 23 checks. Every other detector in `scanner.ts` still
 * runs — several are needed internally (the SSRF/private-host guard, framework
 * detection that drives content-aware severity, Supabase/edge discovery that
 * feeds the rate-limit + service-role checks) — but their findings are
 * partitioned OUT of the customer report and OUT of scoring at the scanner
 * pipeline boundary (`isCustomerFacingFinding`). They are NEVER shown as
 * website vulnerabilities.
 *
 * This keeps the scoring engine a pure, general-purpose scorer (Stage 2/3 still
 * use it for deeper, consent-gated findings) while the Stage-1 main report is
 * filtered to the canonical 23. The contract: a finding is customer-facing iff
 * `canonicalCheckForFinding()` maps its id to one of the 23 keys (or to a
 * canonical "clean"/positive marker for one of those checks).
 *
 * Pure module — no I/O, browser-safe. Imported by the scanner (partition) and
 * usable by the UI/marketing (the `CANONICAL_CHECKS` list).
 */

import type { Finding } from '../../src/lib/scanner-types.js'

export type CanonicalCheckKey =
  | 'https-tls-reachability'
  | 'secrets-in-js'
  | 'supabase-service-role-key'
  | 'tls-version'
  | 'weak-ciphers'
  | 'certificate-expiry'
  | 'mixed-content'
  | 'http-to-https-redirect'
  | 'cookie-session-hardening'
  | 'csrf-post-forms'
  | 'sensitive-path-exposure'
  | 'robots-sensitive-paths'
  | 'sitemap-internal-leak'
  | 'trace-method'
  | 'supabase-storage-exposure'
  | 'firebase-rtdb-exposure'
  | 'firebase-storage-exposure'
  | 's3-listbucket-exposure'
  | 'login-rate-limit'
  | 'open-redirect'
  | 'reflected-xss'
  | 'sql-injection'
  | 'subdomain-takeover'

export interface CanonicalCheck {
  /** Stable 1-based number matching the product spec ordering. */
  n: number
  key: CanonicalCheckKey
  /** Short customer-facing title. */
  title: string
  /** One-line "what we scan" blurb (marketing + docs). */
  blurb: string
  /**
   * Coarse marketing family — used to group the 23 checks into the 8 signal
   * streams shown on the homepage ("Eight signal streams. One verdict.").
   */
  family:
    | 'transport'
    | 'secrets'
    | 'cookies'
    | 'exposed-paths'
    | 'cloud-storage'
    | 'injection'
    | 'access-control'
    | 'recon-leak'
}

/**
 * THE list. Order = product spec order. This is the only place the 23 checks
 * are enumerated; the UI/docs/marketing read from here (or mirror it) so a
 * change here is the single edit that keeps the product consistent.
 */
export const CANONICAL_CHECKS: readonly CanonicalCheck[] = [
  {
    n: 1,
    key: 'https-tls-reachability',
    title: 'HTTPS/TLS reachability',
    blurb: 'Site loads securely over HTTPS — flags HTTP downgrade or HTTPS failure.',
    family: 'transport',
  },
  {
    n: 2,
    key: 'secrets-in-js',
    title: 'Exposed secrets in JS',
    blurb: 'API keys/secrets baked into public JavaScript bundles.',
    family: 'secrets',
  },
  {
    n: 3,
    key: 'supabase-service-role-key',
    title: 'Supabase service-role key exposure',
    blurb: 'service_role JWT/key shipped to the client — critical, bypasses all RLS.',
    family: 'secrets',
  },
  {
    n: 4,
    key: 'tls-version',
    title: 'TLS version',
    blurb: 'Deprecated TLS versions such as TLS 1.0/1.1.',
    family: 'transport',
  },
  {
    n: 5,
    key: 'weak-ciphers',
    title: 'Weak ciphers',
    blurb: 'Weak TLS ciphers (RC4, 3DES, NULL, EXPORT, MD5).',
    family: 'transport',
  },
  {
    n: 6,
    key: 'certificate-expiry',
    title: 'Certificate expiry',
    blurb: 'TLS certificate expired or near expiry.',
    family: 'transport',
  },
  {
    n: 7,
    key: 'mixed-content',
    title: 'Mixed content',
    blurb: 'HTTPS pages loading HTTP resources or submitting forms over HTTP.',
    family: 'transport',
  },
  {
    n: 8,
    key: 'http-to-https-redirect',
    title: 'HTTP to HTTPS redirect',
    blurb: 'HTTP requests are redirected to HTTPS.',
    family: 'transport',
  },
  {
    n: 9,
    key: 'cookie-session-hardening',
    title: 'Cookie/session hardening',
    blurb: 'Set-Cookie Secure / HttpOnly / SameSite — stricter for session/auth cookies.',
    family: 'cookies',
  },
  {
    n: 10,
    key: 'csrf-post-forms',
    title: 'CSRF token on POST forms',
    blurb: 'POST forms missing a CSRF-token field (severity scales with sensitivity).',
    family: 'access-control',
  },
  {
    n: 11,
    key: 'sensitive-path-exposure',
    title: 'Sensitive path exposure',
    blurb:
      'Exposed .env, .git, .aws/credentials, backups, DB dumps, admin panels, debug endpoints, swagger/openapi/graphql, server-status, Docker/config files.',
    family: 'exposed-paths',
  },
  {
    n: 12,
    key: 'robots-sensitive-paths',
    title: 'robots.txt sensitive-path analysis',
    blurb: 'robots.txt advertising sensitive paths (/admin, /api, /internal, …).',
    family: 'recon-leak',
  },
  {
    n: 13,
    key: 'sitemap-internal-leak',
    title: 'sitemap.xml internal URL leak',
    blurb: 'sitemap.xml exposing internal/sensitive URLs (/admin, /staging, /draft, …).',
    family: 'recon-leak',
  },
  {
    n: 14,
    key: 'trace-method',
    title: 'TRACE method enabled',
    blurb: 'HTTP TRACE enabled (Cross-Site Tracing risk).',
    family: 'access-control',
  },
  {
    n: 15,
    key: 'supabase-storage-exposure',
    title: 'Supabase Storage exposure',
    blurb: 'Public Supabase buckets / storage listing.',
    family: 'cloud-storage',
  },
  {
    n: 16,
    key: 'firebase-rtdb-exposure',
    title: 'Firebase Realtime DB exposure',
    blurb: 'Public Firebase Realtime Database (.json returns real content).',
    family: 'cloud-storage',
  },
  {
    n: 17,
    key: 'firebase-storage-exposure',
    title: 'Firebase Storage exposure',
    blurb: 'Firebase Storage listing / public access.',
    family: 'cloud-storage',
  },
  {
    n: 18,
    key: 's3-listbucket-exposure',
    title: 'S3 ListBucket exposure',
    blurb: 'Public S3 bucket listing / ListBucket.',
    family: 'cloud-storage',
  },
  {
    n: 19,
    key: 'login-rate-limit',
    title: 'Brute Force / Login Rate-Limit Check',
    blurb:
      'Login/signup/reset endpoints protected by rate limiting, lockout, CAPTCHA, or 429 throttling. Safe, minimal, defensive — never credential cracking.',
    family: 'access-control',
  },
  {
    n: 20,
    key: 'open-redirect',
    title: 'Open Redirect',
    blurb: 'Redirect parameters that can send users to an external domain (benign canary).',
    family: 'injection',
  },
  {
    n: 21,
    key: 'reflected-xss',
    title: 'Reflected XSS',
    blurb: 'Input reflected unescaped in HTML (safe canary).',
    family: 'injection',
  },
  {
    n: 22,
    key: 'sql-injection',
    title: 'SQL Injection',
    blurb: 'Input that triggers SQL error signatures (safe error-based detection).',
    family: 'injection',
  },
  {
    n: 23,
    key: 'subdomain-takeover',
    title: 'Subdomain takeover risk',
    blurb: 'Subdomains pointing to unclaimed/takeover-prone external hosting.',
    family: 'recon-leak',
  },
] as const

/** The 8 marketing "signal streams" — the families, in display order. */
export const SIGNAL_STREAMS: { family: CanonicalCheck['family']; label: string }[] = [
  { family: 'transport', label: 'Transport & TLS' },
  { family: 'secrets', label: 'Secrets & keys' },
  { family: 'cookies', label: 'Cookies & sessions' },
  { family: 'exposed-paths', label: 'Exposed paths & files' },
  { family: 'cloud-storage', label: 'Cloud storage (Supabase / Firebase / S3)' },
  { family: 'injection', label: 'Injection (XSS / SQLi / redirect)' },
  { family: 'access-control', label: 'Access control & rate-limiting' },
  { family: 'recon-leak', label: 'Recon leaks & takeover' },
]

const lc = (s: string | undefined | null) => (s || '').toLowerCase()
const has = (s: string, ...needles: string[]) => needles.some((n) => s.includes(n))

/**
 * Map an emitted Finding to the canonical check it belongs to, or `null` if the
 * finding is NOT one of the 23 customer-facing checks (an excluded/internal
 * detector: CORS, security headers, source maps, SRI, DNS/email records, dep
 * CVEs, framework/server fingerprinting, SSRF, AI/edge/signup discovery, JS-AST
 * heuristics, WAF/recon markers, …).
 *
 * Maps both real-impact findings AND their positive "clean"/"ok" markers so the
 * report keeps the reassuring green signals for the canonical checks.
 */
export function canonicalCheckForFinding(
  finding: Pick<Finding, 'id' | 'category'>,
): CanonicalCheckKey | null {
  const id = lc(finding.id)
  if (!id) return null

  // --- #3 service-role first (it is also a `secret-*` id) ------------------
  if (has(id, 'service-role')) return 'supabase-service-role-key'

  // --- #2 exposed secrets in JS (real provider patterns + clean marker) ----
  // The JS-AST hardcoded-creds heuristic is intentionally NOT customer-facing.
  if (id.startsWith('js-ast-')) return null
  if (id.startsWith('secret-') || id === 'secrets-clean') return 'secrets-in-js'

  // --- #1, #4, #5, #6, #8 transport / TLS ----------------------------------
  if (id === 'tls-https' || id === 'tls-http' || id.startsWith('tls-http-'))
    return 'https-tls-reachability'
  if (has(id, 'tls-old-version', 'tls-weak-version')) return 'tls-version'
  if (has(id, 'tls-weak-cipher')) return 'weak-ciphers'
  if (has(id, 'tls-cert-expired', 'tls-cert-near-expiry', 'tls-cert-expiry'))
    return 'certificate-expiry'
  if (id === 'tls-no-http-redirect') return 'http-to-https-redirect'

  // --- #7 mixed content ----------------------------------------------------
  if (finding.category === 'mixed-content' || id === 'mixed-content') return 'mixed-content'

  // --- #9 cookie/session hardening -----------------------------------------
  if (id.startsWith('cookie-') || id.startsWith('cookies-')) return 'cookie-session-hardening'

  // --- #10 CSRF on POST forms ----------------------------------------------
  if (id === 'html-form-no-csrf' || has(id, 'csrf')) return 'csrf-post-forms'

  // --- #12 robots / #13 sitemap (before generic path rules) ----------------
  if (has(id, 'robots')) return 'robots-sensitive-paths'
  if (has(id, 'sitemap')) return 'sitemap-internal-leak'

  // --- #14 TRACE -----------------------------------------------------------
  if (has(id, 'trace')) return 'trace-method'

  // --- #15-#18 cloud storage exposure --------------------------------------
  if (has(id, 'supabase-storage')) return 'supabase-storage-exposure'
  if (has(id, 'firebase-rtdb')) return 'firebase-rtdb-exposure'
  if (has(id, 'firebase-storage')) return 'firebase-storage-exposure'
  if (has(id, 's3-listbucket')) return 's3-listbucket-exposure'

  // --- #19 login rate-limit ------------------------------------------------
  if (has(id, 'rate-limit', 'brute-force')) return 'login-rate-limit'

  // --- #20-#22 active injection probes --------------------------------------
  if (has(id, 'open-redirect')) return 'open-redirect'
  if (has(id, 'reflected-xss', 'xss-reflected')) return 'reflected-xss'
  if (has(id, 'sqli')) return 'sql-injection'

  // --- #23 subdomain takeover ----------------------------------------------
  if (has(id, 'takeover')) return 'subdomain-takeover'

  // --- #11 sensitive path exposure -----------------------------------------
  // Singular `path-<slug>` = PATHS_TO_PROBE sensitive files. Plus admin routes
  // and openapi/graphql-introspection EXPOSURES (not mere presence detection).
  if (id.startsWith('path-')) return 'sensitive-path-exposure'
  if (id.startsWith('paths-admin')) return 'sensitive-path-exposure'
  if (has(id, 'openapi-spec-public', 'graphql-introspection'))
    return 'sensitive-path-exposure'

  return null
}

/**
 * True when a finding belongs to the customer-facing 23-check report. The
 * scanner partitions on this before scoring + returning, so excluded/internal
 * detectors never reach the report or the score.
 */
export function isCustomerFacingFinding(finding: Pick<Finding, 'id' | 'category'>): boolean {
  return canonicalCheckForFinding(finding) !== null
}
