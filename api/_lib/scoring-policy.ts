/**
 * Vguard — scoring policy (single source of truth).
 *
 * Pure constants + predicates used by `scoring-engine.ts` and `scanner.ts`.
 * No I/O, browser-safe. The engine module owns the *application* of these
 * constants; this module owns the *values*. Detectors in `scanner.ts` use
 * the body-content predicates (`evidenceContainsRealSecret`, `isSpaShellBody`,
 * `isPublicClientIdentifier`) before emitting a `critical` severity.
 *
 * Refactor 2026-05-09 — pulled out of `scoring-engine.ts` so detector code
 * can validate findings against the same gate the engine will apply, rather
 * than emitting `critical` and relying on the engine to demote.
 */

import type { Category, Finding, Severity } from '../../src/lib/scanner-types.js'

// ---------------------------------------------------------------------------
// Enums (kept here for SSOT; engine re-exports for back-compat)
// ---------------------------------------------------------------------------

export type RiskClass =
  | 'critical-exploit'
  | 'high-impact-misconfig'
  | 'medium-weakness'
  | 'low-hardening'
  | 'informational'

export type Confidence = 'confirmed' | 'likely' | 'informational'

export type UiGroup =
  | 'confirmed-vulnerabilities'
  | 'likely-risks'
  | 'needs-review'
  | 'hardening-recommendations'
  | 'informational-observations'

export type RouteContext = 'sensitive' | 'public' | 'unknown'

// ---------------------------------------------------------------------------
// Numeric constants
// ---------------------------------------------------------------------------

/** Per-finding 0–10 base score by risk class. */
export const CLASS_BASE: Record<RiskClass, number> = {
  'critical-exploit': 9.0,
  'high-impact-misconfig': 6.0,
  'medium-weakness': 3.5,
  'low-hardening': 1.2,
  informational: 0.4,
}

/** Aggregate score-penalty per first-hit per risk class. */
export const CLASS_DAMAGE: Record<RiskClass, number> = {
  // 35 (not 30) so a single confirmed critical lands the score below 60
  // per Royi's spec. With CONFIDENCE_MULT.confirmed=1.0 and an avg
  // riskScore→penalty multiplier of ~1.3, one critical ≈ 45 pts off → ~55.
  'critical-exploit': 35,
  'high-impact-misconfig': 15,
  'medium-weakness': 6,
  'low-hardening': 1.5,
  informational: 0.2,
}

export const CONFIDENCE_MULT: Record<Confidence, number> = {
  confirmed: 1.0,
  likely: 0.85,
  informational: 0.6,
}

/** Diminishing-returns factor applied per additional finding in a class. */
export const DECAY_FACTOR = 0.6

/** Caps when `hasVerifiedImpact === false`. */
export const CAPS = {
  hardeningTotal: 10,
  informationalTotal: 1,
  /** Cookie/header/CSP-only combined cap (medium + hardening + info). */
  headerCspOnlyCombined: 15,
}

/** Aggregate band thresholds (read off 100 - vibeScore). */
export const BAND_THRESHOLDS = {
  medium: 15,
  high: 36,
  severe: 61,
}

// ---------------------------------------------------------------------------
// Token banks
// ---------------------------------------------------------------------------

/** Substrings (lowercase) that mark a value as a publishable client identifier. */
export const PUBLIC_CLIENT_ID_TOKENS = [
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
  'public_key',
  'publishable_key',
  'client_id',
  'clientid',
  'analytics',
]

/** Header tokens that mark a finding as advanced-only hardening. */
export const ADVANCED_HARDENING_TOKENS = [
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

/**
 * Provider-specific secret-detector IDs. Only these qualify for verifiedImpact
 * on the `secrets` category — the AST heuristic is excluded.
 */
export const PROVIDER_SPECIFIC_SECRET_IDS = [
  'secrets-anthropic',
  'secrets-openai',
  'secrets-stripe-secret',
  'secrets-stripe-live',
  'secrets-aws',
  'secrets-google-api-key',
  'secrets-github-pat',
  'secrets-github-fine-grained',
  'secrets-supabase-service-role',
  'secrets-resend-api-key',
  'secrets-slack-bot-token',
]

/**
 * Body-content patterns that indicate REAL sensitive data (not the SPA shell,
 * not a marketing page that happens to mention "password"). Used by:
 *  - the path-probe detector to gate `critical` severity on body content,
 *  - the source-map detector to pick the `with-secrets` variant,
 *  - the engine to validate `verifiedImpact` on sensitive-file findings.
 */
export const SENSITIVE_BODY_PATTERNS: RegExp[] = [
  // PEM blocks (RSA, EC, DSA, OpenSSH, PGP, etc.)
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/i,
  // .env-shape secrets — key=value where the key looks dangerous
  /\b(?:DB_PASSWORD|DATABASE_URL|DATABASE_PASSWORD|MYSQL_(?:PASSWORD|ROOT_PASSWORD)|POSTGRES_PASSWORD|REDIS_PASSWORD|SECRET_KEY|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|MASTER_KEY|PRIVATE_KEY)\s*=/i,
  // Authorization headers carrying a token
  /\bauthorization\s*:\s*bearer\s+[a-z0-9._-]{16,}/i,
  // Stripe live secret keys (NOT pk_live_, NOT sk_test_ — only sk_live_).
  /\bsk_live_[a-zA-Z0-9]{16,}\b/,
  // AWS access-key IDs.
  /\bAKIA[0-9A-Z]{16}\b/,
  // GitHub fine-grained / classic PATs.
  /\bgithub_pat_[A-Za-z0-9_]{50,}\b|\bghp_[A-Za-z0-9]{36,}\b/,
  // Supabase service_role JWT (eyJ-prefixed, with role:service_role inside —
  // we can't decode here, so use a coarse proxy: very long JWT + the literal
  // word "service_role" anywhere nearby).
  /service_role/i,
  // Slack bot tokens.
  /\bxox[abp]-[A-Za-z0-9-]{10,}\b/,
  // Resend live keys.
  /\bre_[A-Za-z0-9]{20,}\b/,
  // Anthropic.
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  // OpenAI.
  /\bsk-[A-Za-z0-9]{20,}\b/,
]

/**
 * Well-known PUBLIC paths that should never trigger an exposure finding.
 * Used by Stage-2 unauth-API detector and Stage-1 path-probe filter.
 */
export const WELL_KNOWN_PUBLIC_PATHS: RegExp[] = [
  /^\/robots\.txt$/i,
  /^\/sitemap(?:_index)?\.xml$/i,
  /^\/manifest\.(?:json|webmanifest)$/i,
  /^\/favicon\.ico$/i,
  /^\/\.well-known\//i,
  /^\/api\/(?:health|healthz|status|version|ping)\b/i,
  /^\/_next\/static\//i,
  /^\/_vercel\//i,
]

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

const ID = (s: string, ...ps: string[]) =>
  ps.some((p) => s.startsWith(p) || s.includes(p))

/** True if the id/evidence/description looks like a publishable client ID. */
export function isPublicClientIdentifier(
  id: string,
  evidence: string,
  description: string,
): boolean {
  const hay = `${id} ${evidence} ${description}`.toLowerCase()
  return PUBLIC_CLIENT_ID_TOKENS.some((t) => hay.includes(t))
}

export function isAdvancedHardeningHeader(
  id: string,
  evidence: string,
  description: string,
): boolean {
  const hay = `${id} ${evidence} ${description}`.toLowerCase()
  return ADVANCED_HARDENING_TOKENS.some((t) => hay.includes(t))
}

/**
 * True iff `body` contains a real sensitive-secret pattern (not just the
 * literal word "password" in marketing copy). Use this to validate evidence
 * for `paths-env` / `sourcemaps-exposed-with-secrets` / etc. before emitting
 * `critical` severity.
 */
export function evidenceContainsRealSecret(body: string): boolean {
  if (!body) return false
  return SENSITIVE_BODY_PATTERNS.some((re) => re.test(body))
}

/**
 * Heuristic: is `body` essentially the same SPA shell as `mainHtml`?
 * Compares title + length within 5% + presence of the same root mount.
 * Used by path probes to suppress false positives where every unknown path
 * returns the SPA's index.html with 200.
 */
export function isSpaShellBody(body: string, mainHtml: string | null | undefined): boolean {
  if (!body || !mainHtml) return false
  const a = body.slice(0, 4096)
  const b = mainHtml.slice(0, 4096)
  // Cheap quick-out: both start with the same doctype + first tag.
  const aHead = a.replace(/\s+/g, ' ').slice(0, 64).toLowerCase()
  const bHead = b.replace(/\s+/g, ' ').slice(0, 64).toLowerCase()
  if (!aHead.includes('<html') && !aHead.includes('<!doctype')) return false
  if (aHead !== bHead) {
    // Fall through to deeper checks — frameworks sometimes vary the head.
  }
  const titleA = (a.match(/<title[^>]*>([^<]{0,128})/i) ?? [, ''])[1].trim()
  const titleB = (b.match(/<title[^>]*>([^<]{0,128})/i) ?? [, ''])[1].trim()
  const titlesMatch = titleA !== '' && titleA === titleB
  const lenA = body.length
  const lenB = mainHtml.length
  const lenRatio = lenA === 0 || lenB === 0 ? 0 : Math.min(lenA, lenB) / Math.max(lenA, lenB)
  // Same root mount element id is a strong SPA-shell signal.
  const rootA = (a.match(/<div[^>]+\bid\s*=\s*["']([^"']+)["'][^>]*>\s*<\/div>/i) ?? [, ''])[1]
  const rootB = (b.match(/<div[^>]+\bid\s*=\s*["']([^"']+)["'][^>]*>\s*<\/div>/i) ?? [, ''])[1]
  const rootsMatch = rootA !== '' && rootA === rootB
  // Decision: any two of (titlesMatch, lenRatio>0.95, rootsMatch) ⇒ shell.
  let votes = 0
  if (titlesMatch) votes++
  if (lenRatio >= 0.95) votes++
  if (rootsMatch) votes++
  return votes >= 2
}

// ---------------------------------------------------------------------------
// Finding traits + verifiedImpact predicate
// ---------------------------------------------------------------------------

export interface ScoringContext {
  routeContext: RouteContext
  cspHasUnsafe?: boolean
  httpsActive: boolean
  stage: 1 | 2 | 3
}

export interface FindingTraits {
  exploitable: boolean
  secretPattern: boolean
  authImpact: boolean
  publicExposure: boolean
  sensitiveData: boolean
  browserSurface: boolean
  runtimeConfirmed: boolean
  defenseInDepthOnly: boolean
  configurationFlaw: boolean
  highAbuseLikelihood: boolean
  verifiedImpact: boolean
  knownPublicAsset: boolean
  authCookie: boolean
}

/**
 * The strict verified-impact gate. Returns true ONLY when the finding has
 * evidence of real impact (active probe hit, real secret pattern in body,
 * confirmed broken TLS, etc.). Source maps alone do NOT pass this gate;
 * only `sourcemaps-exposed-with-secrets` does.
 */
export function verifiedImpactPredicate(
  finding: Finding,
  traits: Pick<
    FindingTraits,
    'authImpact' | 'runtimeConfirmed' | 'knownPublicAsset'
  >,
  ctx: ScoringContext,
): boolean {
  const id = finding.id || ''
  const cat = finding.category
  const sev = finding.severity
  const ev = finding.evidence || ''
  const detectorFlaggedCritical = sev === 'critical'

  // Active-probe hits — these are confirmed exploits at the network level.
  const activeProbeHit = ID(
    id,
    'paths-xss-reflected',
    'paths-sqli',
    'paths-open-redirect',
    'paths-traversal',
    'paths-ssrf',
  )
  if (activeProbeHit) return true

  // Provider-specific secret detectors that committed to `critical`.
  // The AST heuristic (`js-ast-hardcoded-creds`) is excluded by NOT being
  // in PROVIDER_SPECIFIC_SECRET_IDS — it stays as `warn` per the new spec.
  const isProviderSpecificSecret = PROVIDER_SPECIFIC_SECRET_IDS.some((p) => id.startsWith(p))
  if (isProviderSpecificSecret && detectorFlaggedCritical && !traits.knownPublicAsset) {
    return true
  }

  // Sensitive-file exposures. Detector must have flagged critical AND the
  // evidence must contain a real secret pattern. The detector is responsible
  // for putting the matching content in `evidence`; if it didn't, we don't
  // pass the gate (no body, no proof).
  const isSensitiveFile = ID(
    id,
    'paths-env',
    'paths-git',
    'paths-aws-credentials',
    'paths-database-sql',
    'paths-backup',
    'paths-firebase-rtdb-root',
    'paths-s3-list',
    'paths-supabase-storage-public',
    'paths-firebase-storage-public',
    'paths-phpinfo',
  )
  if (isSensitiveFile && detectorFlaggedCritical) {
    if (cat === 'paths' && (id.startsWith('paths-env') || id.startsWith('paths-git') || id.startsWith('paths-database-sql') || id.startsWith('paths-backup') || id.startsWith('paths-aws-credentials'))) {
      // For env/git/db/backup — REQUIRE a real-secret pattern in evidence.
      // The detector is supposed to embed the matched line.
      return evidenceContainsRealSecret(ev)
    }
    // Public buckets / RTDB-root / phpinfo — the detector observation alone
    // (200 + listing/dump shape) is the verified impact.
    return true
  }

  // Source maps — REMOVED from the bare `sourcemaps-exposed` id; only the
  // `-with-secrets` variant verifies.
  if (id === 'sourcemaps-exposed-with-secrets' && detectorFlaggedCritical) return true

  // Plain HTTP serving credentials form / mixed-content credentialed form.
  if (cat === 'mixed-content' && (ID(id, 'mixed-content-form-credentials') || ID(id, 'mixed-content-form'))) {
    return true
  }
  if (!ctx.httpsActive && cat === 'tls' && sev !== 'ok') return true

  // TLS broken in a way that allows real downgrade.
  if (ID(id, 'tls-cert-expired', 'tls-old-version', 'tls-weak-cipher', 'tls-weak-cipher-real')) {
    return true
  }

  // Stage 3 confirmations.
  if (
    ID(
      id,
      'stage3-rls-broken',
      'stage3-storage-public-write',
      'stage3-admin-unauth-data',
      'stage3-mass-assignment',
      'stage3-idor',
      'stage3-path-traversal',
    )
  ) {
    return true
  }

  // Admin unauth-data observation from Stage 1 detector.
  if (id === 'paths-admin-unauth-data' && detectorFlaggedCritical) return true
  // Existing admin detector ID — bundle-discovered admin route 200 unauth.
  if (id === 'paths-admin-route-public' && detectorFlaggedCritical) return true

  // Auth bypass confirmed at runtime.
  if (
    traits.authImpact &&
    traits.runtimeConfirmed &&
    ID(id, 'auth-bypass-confirmed', 'rls-anon-select')
  ) {
    return true
  }

  // Subdomain takeover.
  if (ID(id, 'dns-subdomain-takeover-ready')) return true

  // Vulnerable dependency with CVE match.
  if (detectorFlaggedCritical && ID(id, 'deps-server-cve-', 'deps-npm-')) return true

  // Dangerous CORS — `*` + Allow-Credentials: true.
  if (
    detectorFlaggedCritical &&
    ID(id, 'cors-credentials-wildcard', 'cors-creds-wildcard')
  ) {
    return true
  }

  // Directory listing exposed.
  if (detectorFlaggedCritical && ID(id, 'paths-directory-listing', 'paths-dir-listing')) {
    return true
  }

  // Public write/delete confirmed.
  if (
    detectorFlaggedCritical &&
    ID(id, 'paths-supabase-storage-public-write', 'paths-s3-public-write')
  ) {
    return true
  }

  return false
}

// ---------------------------------------------------------------------------
// UI grouping order (used by ScanForm.tsx)
// ---------------------------------------------------------------------------

export const UI_GROUP_ORDER: Record<UiGroup, number> = {
  'confirmed-vulnerabilities': 0,
  'likely-risks': 1,
  'needs-review': 2,
  'hardening-recommendations': 3,
  'informational-observations': 4,
}

// Re-exports for downstream type-checking convenience.
export type { Finding, Category, Severity }
