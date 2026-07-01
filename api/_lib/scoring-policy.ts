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

import type {
  BusinessImpact,
  Category,
  EffectiveSeverity,
  Finding,
  Grade,
  RiskCategory,
  ScoreTier,
  Severity,
} from '../../src/lib/scanner-types.js'
import {
  isRealProviderSecretId,
  isSensitiveFileId,
  isPublicDataStoreId,
  isAdminUnauthDataId,
  isOpenRedirectId,
  isStage3ConfirmationId,
  isCorsId,
  isBrokenTlsId,
  isSourceMapWithSecretsId,
  isCriticalDepId,
  isSubdomainTakeoverId,
  isPublicClientIdentifier as isPublicClientIdentifierById,
  isAdvancedHardeningHeaderId,
  isAnonymousWriteId,
  isCsrfId,
  isCsrfPassiveRiskId,
  isCsrfVerifiedRiskId,
  isGoldenKindId,
  isGradeCapGoldenId,
  isIdorId,
  isPathTraversalId,
  isPromptInjectionId,
  isRateLimitId,
  isRceId,
  isReconFindingId,
  isReflectedXssId,
  isRlsBypassId,
  isSourceMapId,
  isSqliId,
  isSsrfId,
  isVerifiedXssId,
} from './finding-ids.js'

// ---------------------------------------------------------------------------
// Enums (kept here for SSOT; engine re-exports for back-compat)
// ---------------------------------------------------------------------------

export type RiskClass =
  | 'critical-exploit'
  | 'high-impact-misconfig'
  | 'medium-weakness'
  | 'low-hardening'
  | 'informational'

/**
 * V6 confidence vocabulary. Every finding gets exactly one:
 *   verified — exploitation / direct-observation evidence (browser-executed
 *              XSS, file content returned, Stage-3 confirmation, real secret
 *              the detector saw unredacted)
 *   likely   — strong signal short of exploitation (runtime observation,
 *              SQL error signature, critical detector finding unverified)
 *   possible — detection only (reflected canary, pattern match, heuristic)
 */
export type Confidence = 'verified' | 'likely' | 'possible'

/** Accept legacy spellings from persisted data / older callers. */
export function normalizeConfidence(c: string | undefined | null): Confidence {
  switch (c) {
    case 'verified':
    case 'confirmed':
      return 'verified'
    case 'likely':
      return 'likely'
    default:
      return 'possible'
  }
}

export type UiGroup =
  | 'confirmed-vulnerabilities'
  | 'likely-risks'
  | 'needs-review'
  | 'hardening-recommendations'
  | 'informational-observations'

export type RouteContext = 'sensitive' | 'public' | 'unknown'

// ---------------------------------------------------------------------------
// V6 — risk-based scoring model (2026-06-13)
//
// The score measures REAL-WORLD RISK: data exposure, unauthorized access,
// account/system compromise, business impact. It does NOT measure checklist
// completeness — fingerprinting, tech detection, and header presence have
// little or no influence.
//
//   Score = 100 − Σ penalties (+ WAF bonus) → grade-cap rule → grade
//
// Four weighted risk categories (weights express through penalty magnitudes
// and the literal posture clamp — NOT through divided budgets, because a
// single verified .env must be able to reach F on its own):
//   data    40% — secret & data exposure
//   access  30% — access control & authorization
//   exploit 25% — exploitable vulnerabilities
//   posture  5% — defense-in-depth hardening (clamped to 5 points total)
//   recon    0% — visibility only
// ---------------------------------------------------------------------------

/** riskClass → the single reconciled severity shown AND scored. */
export const RISKCLASS_TO_EFFECTIVE: Record<RiskClass, EffectiveSeverity> = {
  'critical-exploit': 'critical',
  'high-impact-misconfig': 'high',
  'medium-weakness': 'medium',
  'low-hardening': 'low',
  informational: 'info',
}

/** The model weights (documentation + breakdown display). */
export const RISK_CATEGORY_WEIGHT: Record<RiskCategory, number> = {
  data: 0.4,
  access: 0.3,
  exploit: 0.25,
  posture: 0.05,
  recon: 0,
}

export const RISK_CATEGORY_LABELS: Record<RiskCategory, string> = {
  data: 'Data & secret exposure',
  access: 'Access control & authorization',
  exploit: 'Exploitable vulnerabilities',
  posture: 'Security posture & hardening',
  recon: 'Recon & visibility',
}

/**
 * Penalty BASE for a Golden-Finding kind (major security failure) at verified
 * confidence and baseline business impact. Confidence scales it down for
 * likely (×0.6) / possible (×0.2) detections of the same kind.
 */
export const GOLDEN_PENALTY: Record<RiskCategory, number> = {
  data: 70, // verified .env / service-role / AWS creds / DB dump → F on its own
  access: 60, // verified IDOR / RLS bypass / anonymous write
  exploit: 65, // verified XSS / SQLi / SSRF / traversal / RCE
  posture: 0, // no golden posture kinds exist
  recon: 0,
}

/**
 * Penalty BASE for non-golden findings, by risk category × tier. Tier comes
 * from the riskClass: critical-exploit→critical, high-impact-misconfig→high,
 * medium-weakness→medium, low-hardening→low.
 */
export const REGULAR_PENALTY: Record<
  RiskCategory,
  { critical: number; high: number; medium: number; low: number }
> = {
  data: { critical: 32, high: 24, medium: 12, low: 5 },
  access: { critical: 28, high: 20, medium: 10, low: 4 },
  exploit: { critical: 26, high: 18, medium: 9, low: 4 },
  posture: { critical: 12, high: 4, medium: 2.5, low: 1.5 },
  recon: { critical: 0, high: 0, medium: 0, low: 0 },
}

/**
 * V6 confidence multipliers (the spec's 100% / 60% / 20%). Detection alone is
 * never verification — this is the single biggest lever against both
 * false-positive complaints and detection-inflated scores.
 */
export const CONFIDENCE_MULT: Record<Confidence, number> = {
  verified: 1.0,
  likely: 0.6,
  possible: 0.2,
}

/**
 * Business-impact multipliers — the same technical finding is worth more on a
 * sensitive asset. For VERIFIED golden findings the multiplier is floored at
 * 1.0 (business context can never rescue a verified critical).
 */
export const BUSINESS_IMPACT_MULT: Record<BusinessImpact, number> = {
  public: 0.7,
  userData: 1.0,
  financial: 1.3,
  adminInternal: 1.6,
}

/** Diminishing-returns factor applied per additional finding in a risk category. */
export const DECAY_FACTOR = 0.6

/**
 * The posture category's 5% weight, enforced literally: all unverified
 * defense-in-depth gaps together can never remove more than 5 points.
 * (A VERIFIED posture finding — e.g. a critical CVE match — penalizes via the
 * table outside this clamp; we never mute confirmed risk.)
 */
export const POSTURE_TOTAL_CAP = 5

/** WAF present → small bonus. WAF absent → no penalty, ever. */
export const WAF_BONUS = 2

/**
 * SCORE-CAP RULE: any VERIFIED finding in the grade-cap golden subset (IDOR,
 * RLS bypass, SQLi, .env, DB dump, service-role key, RCE) caps the score at 79
 * (max grade C) until fixed. Overrides all other calculations.
 */
export const GOLDEN_CAP_SCORE = 79

/** Human labels for the breakdown card. */
export const CATEGORY_LABELS: Record<Category, string> = {
  secrets: 'Secrets & keys',
  auth: 'Authentication',
  'auth-enum': 'Account enumeration',
  'auth-weak': 'Weak authentication',
  'auth-disclosure': 'Auth disclosure',
  headers: 'Security headers',
  paths: 'Exposed paths',
  sourcemaps: 'Source maps',
  tls: 'TLS / certificate',
  cookies: 'Cookies',
  integrity: 'Subresource integrity',
  'mixed-content': 'Mixed content',
  html: 'HTML / DOM safety',
  dns: 'DNS',
  email: 'Email auth (SPF/DKIM/DMARC)',
  methods: 'HTTP methods',
  ai: 'AI endpoints',
  deps: 'Dependencies',
  meta: 'Informational',
}

/**
 * finalScore → letter grade. V6 scale:
 * A 90–100 · B 80–89 · C 70–79 · D 60–69 · F 0–59.
 */
export function gradeForScore(score: number): Grade {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

/**
 * Qualifier inside the A band. 100 is reserved for exceptional cases — it is
 * only reachable with literally zero deductions (see the perfect-score gate in
 * the engine).
 */
export function scoreTierForScore(score: number): ScoreTier | undefined {
  if (score >= 100) return 'exceptional'
  if (score >= 95) return 'outstanding'
  if (score >= 90) return 'excellent'
  return undefined
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

/**
 * True if the id/evidence/description looks like a publishable client ID.
 * Delegates to the shared finding-ids contract (single source of truth) so the
 * detectors and the engine can never disagree on what counts as "public".
 */
export function isPublicClientIdentifier(
  id: string,
  evidence: string,
  description: string,
): boolean {
  return isPublicClientIdentifierById(id, evidence, description)
}

export function isAdvancedHardeningHeader(
  id: string,
  evidence: string,
  description: string,
): boolean {
  return isAdvancedHardeningHeaderId(id, evidence, description)
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
  /**
   * V6 — a WAF/edge protection fronts the origin. Grants a small score bonus
   * (never a penalty when absent). Passed by the scanner because the synthetic
   * `meta-waf-detected` finding is appended AFTER the engine runs.
   */
  wafPresent?: boolean
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
  const critical = sev === 'critical'

  // v5.2 — a detector that saw the unredacted evidence can SELF-DECLARE verified
  // impact. Honoured first so the security decision no longer depends solely on
  // id-string matching (closes the architecture gap from the audit). Detectors
  // only set this when they are certain (real secret / confirmed probe / Stage-3
  // hit), never for public client identifiers.
  if (finding.verifiedImpact === true) return true

  // -------------------------------------------------------------------------
  // 2026-06-07 v5 REWRITE — all matching now goes through the shared
  // finding-ids contract, so the gate fires on the REAL emitted ids
  // (`secret-stripe-<file>`, `path--env`, `paths-reflected-xss`,
  // `headers-cors-wildcard`, `auth-rls-leak`, …) and the legacy spellings.
  //
  // Detector severity is trusted here: the detector saw the UNREDACTED body and
  // only committed to `critical` after confirming a real secret/listing. The
  // `evidence` field is redacted (first 8 + last 4), so re-running
  // `evidenceContainsRealSecret` on it would FALSE-negative every real leak —
  // that double-bug is exactly what kept .env/secret leaks at "medium".
  // -------------------------------------------------------------------------

  // Stage-3 ownership-verified confirmations — always real impact.
  if (isStage3ConfirmationId(id)) return true

  // V6 — detection is NOT verification. A reflected canary is Possible XSS
  // (browser execution required for Verified XSS) and an SQL error signature
  // is suspected SQLi — neither verifies here; they score via likely/possible
  // confidence instead. Traversal (actual file content returned), SSRF
  // (out-of-band confirmation), browser-executed XSS, and RCE ARE exploitation
  // evidence. Open redirect never verifies (graded high, not critical).
  if (isVerifiedXssId(id)) return true
  if (isPathTraversalId(id) && !isOpenRedirectId(id)) return true
  if (isSsrfId(id)) return true
  if (isRceId(id)) return true

  // Real provider/credential secret shipped to the client, detector-confirmed.
  if (isRealProviderSecretId(id) && critical && !traits.knownPublicAsset) return true

  // Sensitive file reachable with a confirmed real secret in the body.
  if (isSensitiveFileId(id) && critical) return true

  // Public, listable cloud bucket / DB root — observation IS the impact.
  if (isPublicDataStoreId(id) && critical) return true

  // Admin route returning real data without auth.
  if (isAdminUnauthDataId(id) && critical) return true

  // Source map shipping real secret material.
  if (isSourceMapWithSecretsId(id) && critical) return true

  // Broken transport (no HTTPS / expired cert / TLS 1.0-1.1 / weak cipher).
  if (isBrokenTlsId(id)) return true
  if (!ctx.httpsActive && cat === 'tls' && sev !== 'ok') return true

  // Plain-HTTP / mixed-content credential form.
  if (cat === 'mixed-content' && ID(id, 'mixed-content-form-credentials', 'mixed-content-form')) {
    return true
  }

  // Dangerous CORS — wildcard + credentials makes the detector emit `critical`.
  if (isCorsId(id) && critical) return true

  // Subdomain takeover ready.
  if (isSubdomainTakeoverId(id)) return true

  // Vulnerable dependency with a critical CVE match.
  if (isCriticalDepId(id) && critical) return true

  // Runtime-confirmed auth bypass / anon RLS select.
  if (traits.authImpact && traits.runtimeConfirmed && ID(id, 'auth-bypass-confirmed', 'rls-anon-select')) {
    return true
  }

  // (kept for completeness — `ev` still consumed so lint stays quiet)
  void ev

  return false
}

// ---------------------------------------------------------------------------
// V6 — risk-category mapping + golden/recon classification
// ---------------------------------------------------------------------------

const AUTH_CATEGORIES: ReadonlySet<string> = new Set([
  'auth',
  'auth-enum',
  'auth-weak',
  'auth-disclosure',
])

const POSTURE_CATEGORIES: ReadonlySet<string> = new Set([
  'headers',
  'cookies',
  'tls',
  'integrity',
  'mixed-content',
  'html',
  'dns',
  'email',
  'methods',
  'deps',
  'sourcemaps',
])

/**
 * True for recon / fingerprinting observations — visibility only, zero score
 * impact (robots, sitemap, framework/WAF detection, GraphQL/Swagger presence,
 * server headers, health endpoints, public client identifiers, …).
 */
export function isReconFinding(
  finding: Pick<Finding, 'id' | 'category' | 'severity' | 'evidence' | 'description'>,
  opts: { knownPublicAsset: boolean },
): boolean {
  if (finding.severity === 'ok') return true
  if (finding.category === 'meta') return true
  if (opts.knownPublicAsset) return true
  const id = finding.id || ''
  if (isReconFindingId(id)) return true
  // "AI endpoint detected" is recon; an actual prompt-injection hit is not.
  if (finding.category === 'ai' && !isPromptInjectionId(id)) return true
  return false
}

/**
 * Map a finding to its V6 risk category. Order matters: recon first (zero
 * impact), then the specific exposure/exploit kinds, then auth/access, then
 * everything defense-in-depth falls to posture.
 */
export function mapToRiskCategory(
  finding: Pick<Finding, 'id' | 'category' | 'severity' | 'evidence' | 'description'>,
  opts: { knownPublicAsset: boolean },
): RiskCategory {
  const id = finding.id || ''
  const cat = finding.category

  if (isReconFinding(finding, opts)) return 'recon'

  // CSRF (the `html-form-no-csrf` form-token heuristic) is VISIBILITY-ONLY until
  // a real CSRF verification engine ships. Not seeing a hidden HTML token is NOT
  // evidence of a vulnerability — SameSite cookies, Origin/Referer checks,
  // framework middleware, custom CSRF headers, SPA/API auth, and double-submit
  // cookies all defend without a visible token and are invisible to a passive
  // scan. Classifying it `recon` (0% weight) makes it structurally incapable of
  // moving the score, grade, or critical/warning counts — even if its severity
  // is ever raised. When active forged-request verification exists, emit the
  // VERIFIED result under a new id and route THAT id to 'exploit'. (2026-06-25)
  //
  // The CSRF DECISION ENGINE emits distinct risk ids that MUST be routed BEFORE
  // the blanket `isCsrfId → recon` line below (they also contain "csrf"):
  //   • passive/unverified Low  → `posture` (small, clamped ≤5 — cannot move
  //     grade or warning count; passive CSRF can never exceed this).
  //   • active/verified Med+     → `exploit` (only a deep-scan verification path
  //     ever emits these).
  if (isCsrfPassiveRiskId(id)) return 'posture'
  if (isCsrfVerifiedRiskId(id)) return 'exploit'
  // Visibility-only heuristic + engine info id → recon (zero score impact).
  if (isCsrfId(id)) return 'recon'

  // data — secret & data exposure
  if (
    isRealProviderSecretId(id) ||
    isSensitiveFileId(id) ||
    isPublicDataStoreId(id) ||
    isSourceMapWithSecretsId(id) ||
    ID(id, 'localstorage-auth-token', 'sensitive-data')
  ) {
    return 'data'
  }
  if (cat === 'secrets') return 'data'

  // exploit — exploitable vulnerabilities (checked before the generic Stage-3
  // bucket so prompt-injection/XSS/SQLi confirmations land here, not access)
  if (
    isVerifiedXssId(id) ||
    isReflectedXssId(id) ||
    isSqliId(id) ||
    isSsrfId(id) ||
    isPathTraversalId(id) ||
    isOpenRedirectId(id) ||
    isRceId(id) ||
    // NOTE: CSRF is handled above as `recon` (visibility-only heuristic). When a
    // real CSRF verification detector ships, route its VERIFIED id here.
    isPromptInjectionId(id) ||
    isSubdomainTakeoverId(id)
  ) {
    return 'exploit'
  }
  // Broken transport (plain HTTP / expired cert / TLS 1.0-1.1) is a real,
  // MITM-exploitable break — NOT posture hygiene. Weak-but-working TLS config
  // stays posture below.
  if (isBrokenTlsId(id)) return 'exploit'
  if (cat === 'mixed-content' && ID(id, 'form')) return 'exploit'
  if (cat === 'html' && finding.severity === 'critical') return 'exploit'

  // access — access control & authorization
  if (
    isRlsBypassId(id) ||
    isIdorId(id) ||
    isAnonymousWriteId(id) ||
    isAdminUnauthDataId(id) ||
    isStage3ConfirmationId(id) ||
    isCorsId(id) ||
    isRateLimitId(id)
  ) {
    return 'access'
  }
  if (AUTH_CATEGORIES.has(cat)) return 'access'

  // posture — defense-in-depth
  if (POSTURE_CATEGORIES.has(cat)) return 'posture'
  if (isSourceMapId(id)) return 'posture'

  // Remaining path probes are about exposed surface → data; everything else
  // unclassified defaults to posture (safe: clamped, minimal influence).
  if (cat === 'paths') return 'data'
  return 'posture'
}

/**
 * A finding's KIND is golden (drives the penalty base). The finding IS a
 * Golden Finding — a verified major security failure — only when its kind is
 * golden AND it carries verified impact AND it isn't a public client
 * identifier mis-emitted as a secret.
 */
export function isGoldenKindFinding(
  finding: Pick<Finding, 'id' | 'category'>,
  opts: { knownPublicAsset: boolean },
): boolean {
  if (opts.knownPublicAsset) return false
  if (isGoldenKindId(finding.id || '')) return true
  // An unrecognized id in the `secrets` category is still a "secrets in
  // responses" kind (e.g. a future/renamed detector) — public client ids and
  // the AST heuristic were already excluded via knownPublicAsset above.
  return finding.category === 'secrets'
}

export function isGoldenFinding(
  finding: Pick<Finding, 'id' | 'category'>,
  opts: { knownPublicAsset: boolean; verifiedImpact: boolean },
): boolean {
  return opts.verifiedImpact && isGoldenKindFinding(finding, opts)
}

/** True when the SCORE-CAP rule applies to this finding (verified cap-set kind). */
export function gradeCapApplies(
  finding: Pick<Finding, 'id'>,
  opts: { knownPublicAsset: boolean; verifiedImpact: boolean },
): boolean {
  if (!opts.verifiedImpact || opts.knownPublicAsset) return false
  return isGradeCapGoldenId(finding.id || '')
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
