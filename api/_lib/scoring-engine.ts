/**
 * Vguard — Dynamic risk-based scoring engine.
 *
 * 2026-05-08 v2: strict-Critical-gate rewrite.
 *
 * Core principle: PASSIVE SIGNALS ARE NOT VERIFIED VULNERABILITIES.
 *
 * The previous engine treated CSP weakness, missing headers, cookies without
 * Secure, DOM sinks, public 2xx APIs, frontend tokens, and visible admin login
 * pages as `critical` and tanked the score. That punished enterprise sites
 * (apple.com, amazon.com) for normal frontend architecture.
 *
 * The new model:
 *  - A finding may be `critical-exploit` ONLY with verified impact:
 *      verified exploit, sensitive data exposed, auth bypass confirmed, usable
 *      server-side secret, confirmed SQLi error, confirmed reflected XSS in
 *      unsafe context, public write/delete confirmed, .env/.git with REAL
 *      sensitive content, weak TLS allowing real downgrade, expired cert.
 *  - Everything else — CSP weakness, unsafe-inline, missing headers, cookies
 *    without Secure on non-auth, DOM sinks without taint flow, public APIs
 *    returning 2xx, public client identifiers, visible admin login forms,
 *    source maps, robots.txt, COOP/COEP/CORP/Permissions-Policy — is
 *    `hardening` or `informational`.
 *
 *  - Impact-aware caps when no verified impact (NO artificial score floor —
 *    realism preserved; the caps alone bound the worst case to ~85):
 *      aggregateRiskBand capped at `low` (never `medium`/`high`/`severe`)
 *      Hardening-only total penalty: <= 10 pts
 *      Informational-only total penalty: <= 1 pt
 *      Cookie/header/CSP-only combined total penalty: <= 15 pts
 *    A site with many hardening gaps still legitimately loses points down to
 *    ~85 — we don't fake a perfect score.
 *
 *  - Detectors are not removed. Every detection still fires. We only change
 *    classification, severity, risk class, score impact, caps, and UI grouping.
 *
 * Pure module — no I/O, browser-safe.
 */

import type { Category, Finding, Severity } from '../../src/lib/scanner-types.js'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RiskClass =
  | 'critical-exploit'
  | 'high-impact-misconfig'
  | 'medium-weakness'
  | 'low-hardening'
  | 'informational'

export type Confidence = 'confirmed' | 'likely' | 'informational'

export type RouteContext = 'sensitive' | 'public' | 'unknown'

/**
 * Coarse UI section. Five buckets so the report can clearly separate
 * "fix now" from "tighten when you have time" from "FYI".
 */
export type UiGroup =
  | 'confirmed-vulnerabilities'
  | 'likely-risks'
  | 'needs-review'
  | 'hardening-recommendations'
  | 'informational-observations'

export interface ScoringContext {
  routeContext: RouteContext
  cspHasUnsafe?: boolean
  /** True when the site is HTTPS (plain HTTP escalates everything). */
  httpsActive: boolean
  /** Stage of the scan that produced these findings. Stage 2/3 raise confidence. */
  stage: 1 | 2 | 3
}

export interface FindingTraits {
  /** Active probe hit OR runtime-observed. */
  exploitable: boolean
  /** Looks like a credential/token pattern (NOT auto-meaning "leak"). */
  secretPattern: boolean
  /** Affects auth/authorization/RLS/admin surface. */
  authImpact: boolean
  /** Sits on a publicly reachable URL. */
  publicExposure: boolean
  /** Could leak PII/financial/session state once exploited. */
  sensitiveData: boolean
  /** Increases browser-side attack surface (XSS, clickjack, mixed content). */
  browserSurface: boolean
  /** Confirmed at runtime in Stage 2/3. */
  runtimeConfirmed: boolean
  /** Pure defense-in-depth — no exploit alone. */
  defenseInDepthOnly: boolean
  /** A CSP/header *misconfiguration* (e.g. unsafe-inline) rather than absence. */
  configurationFlaw: boolean
  /** Real-world abuse rate is high (env files, .git, source maps with code). */
  highAbuseLikelihood: boolean
  /**
   * STRICT GATE for `critical-exploit`. True only when there's *verified*
   * impact: exploit confirmed, sensitive data observed in evidence, auth
   * bypass demonstrated, usable server-side secret detected, etc.
   */
  verifiedImpact: boolean
  /**
   * The finding represents a known-public asset (client ID, public API key,
   * public 2xx endpoint, login page, robots.txt, sitemap). Demotes to info.
   */
  knownPublicAsset: boolean
  /** Cookie context: is it actually an auth/session cookie? */
  authCookie: boolean
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ID = (s: string, ...ps: string[]) => ps.some((p) => s.startsWith(p) || s.includes(p))

const ADVANCED_HARDENING_TOKENS = [
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

function isAdvancedHardeningHeader(id: string, evidence: string, description: string): boolean {
  const hay = `${id} ${evidence} ${description}`.toLowerCase()
  return ADVANCED_HARDENING_TOKENS.some((t) => hay.includes(t))
}

const SENSITIVE_BODY_PATTERNS = [
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----/i,
  /\bDB_PASSWORD\b|\bDATABASE_URL\b|\bSECRET_KEY\b|\bAPI_KEY\b/,
  /\b(?:ssn|credit_card|card_number|iban|cvv|cvc)\b/i,
  /\bpassword\s*[:=]/i,
  /\bauthorization\s*:\s*bearer\b/i,
]

function evidenceLooksSensitive(evidence: string): boolean {
  if (!evidence) return false
  return SENSITIVE_BODY_PATTERNS.some((re) => re.test(evidence))
}

const PUBLIC_CLIENT_ID_TOKENS = [
  'client_id',
  'clientid',
  'public_key',
  'publishable_key',
  'pk_live_',
  'pk_test_',
  'next_public_',
  'vite_',
  'react_app_',
  'expo_public_',
  'analytics',
  'gtag',
  'gtm',
  'mapbox',
  'google_maps_api',
  'sentry_dsn',
  'recaptcha_site_key',
  'turnstile_site_key',
  'hcaptcha_site_key',
  'firebase_api_key', // public web SDK key — NOT a secret
  'supabase_anon_key',
]

function looksLikePublicClientIdentifier(id: string, evidence: string, description: string): boolean {
  const hay = `${id} ${evidence} ${description}`.toLowerCase()
  return PUBLIC_CLIENT_ID_TOKENS.some((t) => hay.includes(t))
}

// ---------------------------------------------------------------------------
// Trait extraction — pattern-driven
// ---------------------------------------------------------------------------

export function extractTraits(finding: Finding, ctx: ScoringContext): FindingTraits {
  const id = finding.id || ''
  const cat = finding.category
  const sev = finding.severity
  const ev = (finding.evidence || '').toLowerCase()
  const desc = (finding.description || '').toLowerCase()

  const isStage2 = id.startsWith('stage2-')
  const isStage3 = id.startsWith('stage3-') || id.startsWith('deep-')
  const runtimeConfirmed = isStage2 || isStage3 || ctx.stage > 1

  // Active-probe hits ARE exploitable evidence.
  const activeProbeHit = ID(id, 'paths-xss-reflected', 'paths-sqli', 'paths-open-redirect', 'paths-traversal', 'paths-ssrf')
  const exploitable = activeProbeHit || (runtimeConfirmed && (cat === 'auth-disclosure' || ID(id, 'rls-anon-select', 'auth-idor')))

  // Pattern-only — does NOT mean "leak". Frontend public client IDs match
  // many of these patterns (Firebase web SDK key, Supabase anon JWT, Stripe pk_*).
  const secretPattern =
    cat === 'secrets' ||
    ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials', 'paths-database-sql', 'paths-backup', 'sourcemaps-exposed') ||
    ID(id, 'stage2-localstorage-auth-tokens')

  // Public client identifiers / publishable keys — these LOOK like secrets
  // but are intended to ship to the browser.
  const knownPublicClientId = looksLikePublicClientIdentifier(id, ev, desc)
  // A "known-public asset" is anything the user can already hit on the public
  // web by design: robots/sitemap, login page, public swagger, public 2xx APIs,
  // or a client identifier that is publishable by spec.
  const knownPublicAsset =
    knownPublicClientId ||
    ID(id, 'paths-robots', 'paths-sitemap', 'paths-swagger', 'paths-openapi', 'paths-api-docs', 'paths-graphql', 'paths-status', 'paths-well-known') ||
    // visible admin login page (200/302 to login, no admin content seen)
    ID(id, 'paths-admin-login-visible') ||
    // first-party API returned 2xx but no sensitive content was extracted
    ID(id, 'stage2-public-api-2xx', 'paths-api-public-2xx')

  const authImpact =
    cat === 'auth' ||
    cat === 'auth-enum' ||
    cat === 'auth-weak' ||
    cat === 'auth-disclosure' ||
    ID(id, 'auth-', 'rls-', 'idor-', 'jwt-')

  const publicExposure = cat !== 'meta' && finding.severity !== 'ok'

  // Auth-named cookies only — analytics/preference cookies don't count.
  const authCookie =
    /(\b|_)(sess|session|auth|token|jwt|sid|csrf|xsrf|access_token|refresh_token)\b/i.test(ev) ||
    /(\b|_)(sess|session|auth|token|jwt|sid|csrf|xsrf|access_token|refresh_token)\b/i.test(desc)

  const sensitiveData =
    (secretPattern && !knownPublicClientId) ||
    (cat === 'cookies' && authCookie) ||
    ID(id, 'paths-firebase-rtdb-root') ||
    ID(id, 'paths-supabase-storage-public-list', 'paths-s3-list')

  const browserSurface =
    cat === 'headers' ||
    cat === 'mixed-content' ||
    cat === 'integrity' ||
    cat === 'html' ||
    ID(id, 'paths-xss', 'cookies-')

  const defenseInDepthOnly =
    !exploitable &&
    !sensitiveData &&
    sev !== 'critical' &&
    (
      isAdvancedHardeningHeader(id, ev, desc) ||
      // Per the new strict policy, a missing X-Frame-Options/HSTS/CSP/etc on
      // a non-auth surface is hardening, not exploit.
      ID(id, 'headers-no-x-content-type', 'headers-no-hsts', 'headers-no-x-frame-options',
            'headers-csp-missing', 'headers-csp-weak', 'headers-csp-unsafe-inline',
            'headers-csp-unsafe-eval', 'headers-csp-wildcard',
            'headers-csp-no-base-uri', 'headers-csp-no-frame-ancestors', 'headers-csp-no-form-action') ||
      ID(id, 'cookies-no-secure', 'cookies-no-samesite') ||
      ID(id, 'dom-sink-innerhtml', 'dom-sink-outerhtml', 'dom-sink-insertadjacent', 'dom-sink-document-write') ||
      ID(id, 'dns-no-caa', 'dns-no-dnssec') ||
      ID(id, 'email-dmarc-monitor', 'email-spf-softfail') ||
      ID(id, 'integrity-no-sri') ||
      ID(id, 'meta-')
    )

  const configurationFlaw =
    /unsafe-inline|unsafe-eval/.test(ev) ||
    /unsafe-inline|unsafe-eval/.test(desc) ||
    ID(id, 'headers-csp-unsafe', 'headers-csp-weak') ||
    ID(id, 'cors-wildcard', 'cors-credentials-wildcard')

  const highAbuseLikelihood =
    ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials', 'sourcemaps-exposed') ||
    ID(id, 'secrets-stripe-secret', 'secrets-aws', 'secrets-supabase-service-role', 'secrets-anthropic', 'secrets-openai') ||
    ID(id, 'paths-xss-reflected', 'paths-sqli')

  // -------------------------------------------------------------------------
  // STRICT VERIFIED-IMPACT GATE — the only way a finding becomes critical.
  // -------------------------------------------------------------------------

  // The detectors already filter false positives and decide severity. The
  // scoring engine should TRUST the detector when it commits to a critical
  // severity on a class of findings that is real-world dangerous, instead
  // of demanding additional evidence patterns the detector may not surface
  // in the `evidence` field. Otherwise legitimately bad scans land at 95.
  const detectorFlaggedCritical = finding.severity === 'critical'

  // Only provider-specific secret detectors qualify as verifiedImpact.
  // The AST-heuristic detector (`js-ast-hardcoded-creds`) finds
  // "credential-shaped patterns" that include public app-store IDs,
  // analytics tags, and media identifiers — too noisy to gate Critical on.
  // Those still fire as findings; they just don't open the Critical class.
  const isProviderSpecificSecret = ID(
    id,
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
  )

  const verifiedImpact =
    // Active probe with confirmed reflection / error / location follow
    activeProbeHit ||
    // Server-side secret detected by a provider-specific regex (NOT the
    // AST heuristic, which has too many false positives on public IDs).
    (isProviderSpecificSecret && detectorFlaggedCritical && !knownPublicClientId) ||
    // .env / .git config / backup / aws creds / DB dump / firebase RTDB /
    // S3 ListBucket — when the detector escalated to critical it has
    // already validated the path returned a hit. 200-with-empty-body is
    // demoted by the detector itself, so trusting `severity:critical` here
    // is safe and matches Royi's spec "exposed .env/.git with real sensitive data".
    (detectorFlaggedCritical && ID(id, 'paths-env', 'paths-git', 'paths-aws-credentials',
        'paths-database-sql', 'paths-backup', 'paths-firebase-rtdb-root', 'paths-s3-list',
        'paths-supabase-storage-public', 'paths-firebase-storage-public', 'paths-phpinfo')) ||
    // Source maps publicly accessible — the detector emits this only when
    // the .map file actually returned 200 with map contents (not 404).
    ID(id, 'sourcemaps-exposed') ||
    // Plain-HTTP traffic on what should be HTTPS (real downgrade surface)
    (!ctx.httpsActive && cat === 'tls' && publicExposure) ||
    // TLS broken in a way that allows real downgrade (expired, weak version <1.2)
    ID(id, 'tls-cert-expired', 'tls-old-version', 'tls-weak-cipher', 'tls-weak-cipher-real') ||
    // Stage 3 confirmations
    ID(id, 'stage3-rls-broken', 'stage3-storage-public-write', 'stage3-admin-unauth-data',
          'stage3-mass-assignment', 'stage3-idor', 'stage3-path-traversal') ||
    // Auth bypass confirmed at runtime
    (authImpact && runtimeConfirmed && ID(id, 'auth-bypass-confirmed', 'rls-anon-select')) ||
    // Subdomain takeover ready (NXDOMAIN target)
    ID(id, 'dns-subdomain-takeover-ready') ||
    // Mixed content with sensitive form action (POST creds over HTTP)
    (cat === 'mixed-content' && (ID(id, 'mixed-content-form-credentials') || ID(id, 'mixed-content-form'))) ||
    // Vulnerable dependency with exploitable version evidence — the detector
    // emits these only when the Server / X-Powered-By string matched a known
    // CVE signature, OR an npm dep in a public bundle matched a CVE entry.
    // Trust the detector when it commits to severity=critical.
    (detectorFlaggedCritical && ID(id, 'deps-server-cve-', 'deps-npm-')) ||
    // Dangerous CORS — `Access-Control-Allow-Origin: *` + `Allow-Credentials: true`
    // is a spec violation that, when a server actually returns it, exposes
    // any same-site cookies to any origin that loads a `<img>` / `fetch` from
    // it. Detector emits severity=critical only when both headers are present
    // on the same response — that's verified config.
    (detectorFlaggedCritical && ID(id, 'cors-credentials-wildcard', 'cors-creds-wildcard')) ||
    // Directory listing exposed (autoindex/directory listing) — observed at
    // runtime by the path probe. Real attack surface (asset enumeration).
    (detectorFlaggedCritical && ID(id, 'paths-directory-listing', 'paths-dir-listing')) ||
    // Public write/delete confirmed (storage bucket public-write, etc.)
    (detectorFlaggedCritical && ID(id, 'paths-supabase-storage-public-write', 'paths-s3-public-write'))
  void evidenceLooksSensitive // kept for future detectors; not used now

  return {
    exploitable,
    secretPattern,
    authImpact,
    publicExposure,
    sensitiveData,
    browserSurface,
    runtimeConfirmed,
    defenseInDepthOnly,
    configurationFlaw,
    highAbuseLikelihood,
    verifiedImpact,
    knownPublicAsset,
    authCookie,
  }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export function classifyRiskClass(
  finding: Finding,
  traits: FindingTraits,
  ctx: ScoringContext,
): RiskClass {
  if (finding.severity === 'ok') return 'informational'

  // Known-public assets are always informational regardless of declared severity.
  if (traits.knownPublicAsset && !traits.verifiedImpact) {
    return 'informational'
  }

  // STRICT GATE: critical-exploit requires verifiedImpact.
  if (traits.verifiedImpact) {
    return 'critical-exploit'
  }

  // High-impact-misconfig — only on real impact signals, not configFlaw alone.
  if (
    traits.runtimeConfirmed &&
    (traits.exploitable || traits.sensitiveData || (traits.authImpact && finding.severity !== 'info'))
  ) {
    return 'high-impact-misconfig'
  }

  // Auth/session cookies missing Secure/HttpOnly/SameSite are a direct session-theft
  // surface — the detector observed the cookie name + missing flag from the
  // Set-Cookie header itself, that IS observation. Per spec: "auth/session
  // cookies missing Secure/HttpOnly = likely/needs-review". We elevate to
  // high-impact so the score reflects real session compromise risk, while the
  // confidence stays `likely` (no runtime exploit yet) — together they land
  // the finding in `likely-risks` UI section.
  if (finding.category === 'cookies' && traits.authCookie && finding.severity !== 'info') {
    return 'high-impact-misconfig'
  }

  // Medium-weakness — defense-in-depth on truly sensitive surface, OR auth-cookie hardening.
  if (traits.defenseInDepthOnly) {
    if (ctx.routeContext === 'sensitive' && traits.browserSurface) return 'medium-weakness'
    if (finding.category === 'cookies' && traits.authCookie) return 'medium-weakness'
    return 'low-hardening'
  }

  // Auth-impact passive (no runtime) — at most medium.
  if (traits.authImpact && finding.severity !== 'info') {
    return 'medium-weakness'
  }

  // Configuration flaws on browser surface (CSP unsafe-inline etc) without
  // verified exploit path — capped at low-hardening per the new policy.
  if (traits.configurationFlaw && traits.browserSurface) {
    return 'low-hardening'
  }

  if (finding.severity === 'critical' || finding.severity === 'warn') {
    return 'medium-weakness'
  }

  return 'informational'
}

export function classifyConfidence(
  finding: Finding,
  traits: FindingTraits,
): Confidence {
  if (finding.severity === 'ok') return 'informational'
  if (traits.verifiedImpact) return 'confirmed'
  if (traits.runtimeConfirmed) return 'confirmed'
  if (traits.knownPublicAsset) return 'informational'
  if (traits.defenseInDepthOnly) return 'informational'
  if (finding.severity === 'info') return 'informational'
  return 'likely'
}

export function uiGroupFor(finding: Finding, riskClass: RiskClass, traits: FindingTraits): UiGroup {
  if (finding.severity === 'ok') return 'informational-observations'
  if (traits.verifiedImpact) return 'confirmed-vulnerabilities'
  if (riskClass === 'critical-exploit') return 'confirmed-vulnerabilities' // shouldn't happen given gate, but safe
  if (riskClass === 'high-impact-misconfig') return 'likely-risks'
  if (riskClass === 'medium-weakness') return 'needs-review'
  if (riskClass === 'low-hardening') return 'hardening-recommendations'
  return 'informational-observations'
}

// ---------------------------------------------------------------------------
// Per-finding 0–10 risk
// ---------------------------------------------------------------------------

const CLASS_BASE: Record<RiskClass, number> = {
  'critical-exploit': 9.0,
  'high-impact-misconfig': 6.0,
  'medium-weakness': 3.5,
  'low-hardening': 1.2,
  informational: 0.4,
}

const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  confirmed: 1.0,
  likely: 0.85,
  informational: 0.6,
}

export function computeFindingRisk(
  finding: Finding,
  traits: FindingTraits,
  riskClass: RiskClass,
  confidence: Confidence,
  ctx: ScoringContext,
): number {
  if (finding.severity === 'ok') return 0
  let raw = CLASS_BASE[riskClass] * CONFIDENCE_MULTIPLIER[confidence]

  if (traits.runtimeConfirmed && traits.verifiedImpact) raw += 0.6
  if (traits.highAbuseLikelihood && traits.verifiedImpact) raw += 0.4
  if (traits.authImpact && ctx.routeContext === 'sensitive') raw += 0.3
  if (traits.sensitiveData && ctx.routeContext === 'sensitive') raw += 0.2
  if (traits.defenseInDepthOnly && ctx.routeContext === 'public') raw -= 0.5

  return Math.round(Math.max(0, Math.min(10, raw)) * 10) / 10
}

// ---------------------------------------------------------------------------
// Aggregate vibe score — diminishing returns + STRICT CAPS
// ---------------------------------------------------------------------------

const CLASS_DAMAGE: Record<RiskClass, number> = {
  'critical-exploit': 30,
  'high-impact-misconfig': 12,
  'medium-weakness': 4,
  'low-hardening': 1.0,
  informational: 0.15,
}

function diminishingSum(penalties: number[]): number {
  const sorted = [...penalties].sort((a, b) => b - a)
  let total = 0
  let factor = 1.0
  for (const p of sorted) {
    total += p * factor
    factor *= 0.6
  }
  return total
}

export function bandForRiskScore(score: number): NonNullable<Finding['riskBand']> {
  if (score >= 8) return 'severe'
  if (score >= 6) return 'high'
  if (score >= 3) return 'medium'
  return 'low'
}

export interface ScoredFinding {
  finding: Finding
  traits: FindingTraits
  riskClass: RiskClass
  confidence: Confidence
  riskScore: number
  scoreImpact: number
}

export interface EngineOutput {
  vibeScore: number
  scored: ScoredFinding[]
  groupCounts: Record<RiskClass, number>
  /** True iff at least one finding has verifiedImpact — drives caps. */
  hasVerifiedImpact: boolean
}

export function runScoringEngine(findings: Finding[], ctx: ScoringContext): EngineOutput {
  const scored: ScoredFinding[] = findings.map((f) => {
    const traits = extractTraits(f, ctx)
    const riskClass = classifyRiskClass(f, traits, ctx)
    const confidence = classifyConfidence(f, traits)
    const riskScore = computeFindingRisk(f, traits, riskClass, confidence, ctx)
    const baseDamage = CLASS_DAMAGE[riskClass]
    const impact =
      f.severity === 'ok'
        ? 0
        : baseDamage * CONFIDENCE_MULTIPLIER[confidence] * (riskScore / 10 + 0.4)
    return { finding: f, traits, riskClass, confidence, riskScore, scoreImpact: impact }
  })

  const byClass: Record<RiskClass, number[]> = {
    'critical-exploit': [],
    'high-impact-misconfig': [],
    'medium-weakness': [],
    'low-hardening': [],
    informational: [],
  }
  for (const s of scored) {
    if (s.finding.severity !== 'ok') byClass[s.riskClass].push(s.scoreImpact)
  }

  const criticalSum = diminishingSum(byClass['critical-exploit'])
  const highSum = diminishingSum(byClass['high-impact-misconfig'])
  const mediumSum = diminishingSum(byClass['medium-weakness'])

  // CAPS (per spec, refined):
  //   Hardening-only total  <= 10  (always)
  //   Informational total   <=  1  (always)
  //   Cookie/header/CSP-ONLY combined cap <= 15 — applied ONLY when EVERY
  //     non-ok finding sits in {headers, cookies, html} categories AND there
  //     is no verified impact. A scan with diverse categories (DNS, email,
  //     auth, paths, ai, deps, tls) gets to subtract real points; a scan
  //     that is purely "missing some headers" tops out at 15 off.
  const hardeningSumRaw = diminishingSum(byClass['low-hardening'])
  const hardeningSum = Math.min(hardeningSumRaw, 10)
  const informationalSumRaw = diminishingSum(byClass.informational)
  const informationalSum = Math.min(informationalSumRaw, 1)

  const hasVerifiedImpact = scored.some((s) => s.traits.verifiedImpact)
  const HARDENING_CATS = new Set(['headers', 'cookies', 'html'])
  const allHardeningOnlyCats = scored
    .filter((s) => s.finding.severity !== 'ok')
    .every((s) => HARDENING_CATS.has(s.finding.category as string))

  let mediumLowInfo = mediumSum + hardeningSum + informationalSum
  if (!hasVerifiedImpact && allHardeningOnlyCats) {
    mediumLowInfo = Math.min(mediumLowInfo, 15)
  }

  const totalPenaltyRaw = criticalSum + highSum + mediumLowInfo
  // No artificial floor. Real findings legitimately reduce score. A site
  // with diverse hardening + auth-cookie + DNS + email-auth gaps but no
  // verified exploit will land in the 70-85 range, which reflects "could
  // be improved" without falsely declaring an active risk.
  const vibeScore = Math.max(0, Math.min(100, Math.round(100 - totalPenaltyRaw)))

  const groupCounts: Record<RiskClass, number> = {
    'critical-exploit': byClass['critical-exploit'].length,
    'high-impact-misconfig': byClass['high-impact-misconfig'].length,
    'medium-weakness': byClass['medium-weakness'].length,
    'low-hardening': byClass['low-hardening'].length,
    informational: byClass.informational.length,
  }

  return { vibeScore, scored, groupCounts, hasVerifiedImpact }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

export interface EnrichedFinding extends Finding {
  riskClass?: RiskClass
  confidence?: Confidence
  uiGroup?: UiGroup
}

export interface ApplyResult {
  vibeScore: number
  findings: EnrichedFinding[]
  groupCounts: Record<RiskClass, number>
  hasVerifiedImpact: boolean
  /**
   * Aggregate band — clamped to <= medium when there's no verified impact.
   * "low" = 0–14, "medium" = 15–35, "high" = 36–60, "severe" = 61+.
   */
  aggregateBand: 'low' | 'medium' | 'high' | 'severe'
}

export function applyEngine(findings: Finding[], ctx: ScoringContext): ApplyResult {
  const { vibeScore, scored, groupCounts, hasVerifiedImpact } = runScoringEngine(findings, ctx)

  const enriched: EnrichedFinding[] = scored.map((s) => ({
    ...s.finding,
    riskScore: s.riskScore,
    riskBand: bandForRiskScore(s.riskScore),
    riskClass: s.riskClass,
    confidence: s.confidence,
    uiGroup: uiGroupFor(s.finding, s.riskClass, s.traits),
  }))

  // Aggregate band reads off the inverse of vibeScore but clamps to medium
  // when there's no verified impact (per spec).
  const inverted = 100 - vibeScore
  let aggregateBand: ApplyResult['aggregateBand']
  if (inverted >= 61) aggregateBand = 'severe'
  else if (inverted >= 36) aggregateBand = 'high'
  else if (inverted >= 15) aggregateBand = 'medium'
  else aggregateBand = 'low'

  // Without verified impact, the band can still be `medium` to reflect
  // real cumulative pressure (auth cookies, DNSSEC missing, weak SPF,
  // etc.) — but it can never escalate to `high` or `severe`. Those bands
  // require a verified exploit / leak / bypass.
  if (!hasVerifiedImpact && (aggregateBand === 'severe' || aggregateBand === 'high')) {
    aggregateBand = 'medium'
  }

  return { vibeScore, findings: enriched, groupCounts, hasVerifiedImpact, aggregateBand }
}

// Helper for callers that don't want to touch ScoringContext directly.
export function defaultContext(opts: {
  pathname: string
  isHttps: boolean
  cspHasUnsafe?: boolean
  stage?: 1 | 2 | 3
}): ScoringContext {
  const p = (opts.pathname || '/').toLowerCase()
  const sensitive =
    /\/(?:admin|login|signin|sign-in|signup|register|account|profile|settings|billing|payments?|checkout|cart|order|invoice|subscription|pay|wallet|kyc|verify|verification|onboarding|reset|forgot|password|2fa|mfa|otp|auth|oauth|sso|api\/auth|api\/admin|api\/internal|dashboard|backoffice|cms|wp-admin)\b/i.test(p)
  const publicMarketing =
    /^\/?(?:|index\.html?|home|about|blog|news|press|legal|terms|privacy|cookies|contact|help|faq|features|pricing|docs|documentation|case-studies?|customers|stories|team|company|jobs|careers)(?:\/|$)/i.test(p)
  const routeContext: RouteContext = sensitive ? 'sensitive' : publicMarketing ? 'public' : 'unknown'
  return {
    routeContext,
    httpsActive: opts.isHttps,
    cspHasUnsafe: opts.cspHasUnsafe ?? false,
    stage: opts.stage ?? 1,
  }
}
