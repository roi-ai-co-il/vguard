/**
 * Vguard — Professional finding-trait derivation (v5, 2026-06-07).
 *
 * Turns a raw `Finding` into the structured, evidence-based dimensions the
 * exposure model scores on:
 *
 *   Risk ≈ Severity × Exploitability × Verified-Impact × Exposure × Confidence
 *
 * Inspired by CVSS / EPSS / OWASP risk methodology. 100% deterministic "Smart
 * Scoring" — NO telemetry, NO ML. Every field is derived from observable scan
 * evidence (the finding id via the shared `finding-ids` contract, its category,
 * detector severity, and route/transport context).
 *
 * `verifiedImpact` is delegated to `scoring-policy.verifiedImpactPredicate` so
 * there is exactly ONE gate definition shared with the engine.
 *
 * Pure module — no I/O, browser-safe.
 */

import type {
  AttackPrerequisite,
  BusinessImpact,
  EvidenceKind,
  EvidenceStrength,
  Exploitability,
  Finding,
  ImpactType,
} from '../../src/lib/scanner-types.js'
import {
  isActiveProbeHitId,
  isAdminUnauthDataId,
  isBrokenTlsId,
  isCorsId,
  isCriticalDepId,
  isHardeningHeaderId,
  isOpenRedirectId,
  isPathTraversalId,
  isPublicClientIdentifier,
  isPublicDataStoreId,
  isReflectedXssId,
  isRealProviderSecretId,
  isSensitiveFileId,
  isSourceMapId,
  isSourceMapWithSecretsId,
  isServiceRoleKeyId,
  isSqliId,
  isSsrfId,
  isStage2Id,
  isStage3ConfirmationId,
  isSubdomainTakeoverId,
} from './finding-ids.js'
import { verifiedImpactPredicate, type ScoringContext } from './scoring-policy.js'

export interface ProfessionalTraits {
  verifiedImpact: boolean
  exploitability: Exploitability
  attackPrerequisite: AttackPrerequisite
  remoteReachable: boolean
  publicInternetExposure: boolean
  activeProbeConfirmed: boolean
  impactType: ImpactType
  evidenceKind: EvidenceKind
  evidenceStrength: EvidenceStrength
  /** V6 — sensitivity of the affected asset (multiplies the penalty). */
  businessImpact: BusinessImpact
}

const lc = (s: string | undefined | null) => (s || '').toLowerCase()

/** Where the evidence came from — drives confidence, not just display. */
function deriveEvidenceKind(finding: Finding): EvidenceKind {
  const id = finding.id || ''
  if (isStage3ConfirmationId(id)) return 'ownershipVerifiedDeepScan'
  if (isActiveProbeHitId(id)) return 'activeProbe'
  if (isStage2Id(id)) return 'runtime'
  if (id.startsWith('js-ast-') || lc(id).includes('dom-sink')) return 'heuristic'
  return 'passive'
}

/** What the finding would let an attacker do, if real. */
function deriveImpactType(finding: Finding): ImpactType {
  const id = finding.id || ''
  const cat = finding.category
  if (cat === 'meta') return 'none'
  if (finding.severity === 'ok') return 'none'

  if (isRealProviderSecretId(id) && !isPublicClientIdentifier(id, finding.evidence, finding.description)) {
    return 'credentialExposure'
  }
  if (isSensitiveFileId(id)) return 'credentialExposure'
  // Auth tokens observed in localStorage/sessionStorage at runtime are
  // credential exposure, not cookie hygiene (even though the category is
  // `cookies` for display grouping).
  if (lc(id).includes('localstorage-auth-token')) return 'credentialExposure'
  if (isPublicDataStoreId(id) || isAdminUnauthDataId(id)) return 'dataExposure'
  if (isReflectedXssId(id)) return 'codeExecution'
  if (isSqliId(id)) return 'dataExposure'
  if (isSsrfId(id)) return 'abusePath'
  if (isPathTraversalId(id)) return 'dataExposure'
  if (isStage3ConfirmationId(id)) {
    if (lc(id).includes('rls') || lc(id).includes('idor') || lc(id).includes('storage')) return 'dataExposure'
    if (lc(id).includes('prompt-injection') || lc(id).includes('mcp')) return 'abusePath'
    return 'authBypass'
  }
  if (isBrokenTlsId(id) || cat === 'tls' || cat === 'mixed-content') return 'transportBreak'
  if (cat === 'auth' || cat === 'auth-enum' || cat === 'auth-weak' || cat === 'auth-disclosure') {
    return 'authBypass'
  }
  if (isCorsId(id)) return 'abusePath'
  if (isCriticalDepId(id) || cat === 'deps') return 'supplyChain'
  // Unrecognized id in the secrets category (e.g. a future detector) — the
  // category itself says what the impact is.
  if (cat === 'secrets') return 'credentialExposure'
  if (isSourceMapId(id) && !isSourceMapWithSecretsId(id)) return 'infoDisclosure'
  if (isOpenRedirectId(id)) return 'abusePath'
  if (
    isHardeningHeaderId(id) ||
    cat === 'headers' ||
    cat === 'cookies' ||
    cat === 'integrity' ||
    cat === 'dns' ||
    cat === 'email'
  ) {
    return 'hardening'
  }
  if (cat === 'html') return finding.severity === 'critical' ? 'codeExecution' : 'hardening'
  return 'infoDisclosure'
}

/** How realistically usable the finding is by an attacker. */
function deriveExploitability(finding: Finding, verifiedImpact: boolean): Exploitability {
  const id = finding.id || ''
  if (finding.severity === 'ok' || finding.category === 'meta') return 'none'

  // Exploitation-confirmed signals only (V6): Stage-3 confirmations, traversal
  // with real file content, SSRF out-of-band, browser-executed XSS.
  if (isStage3ConfirmationId(id)) return 'confirmed'
  if (verifiedImpact && isActiveProbeHitId(id) && !isOpenRedirectId(id)) return 'confirmed'

  // Confirmed exposures (a real key sitting in the bundle, a listable bucket,
  // broken transport) are "easy" — no skill needed to abuse what's already open.
  if (verifiedImpact) return 'easy'

  // V6 — reflected canary / SQL error signature are detection, not
  // exploitation: realistically usable but unproven.
  if (isReflectedXssId(id) || isSqliId(id)) return 'plausible'

  // Open CORS+creds, weak CSP with unsafe-inline, auth-enum surfaces.
  if (isCorsId(id)) return 'plausible'
  if (lc(id).includes('csp') && /unsafe-(inline|eval)/.test(lc(finding.evidence) + lc(finding.description))) {
    return 'plausible'
  }
  if (isOpenRedirectId(id)) return 'plausible'
  if (finding.category === 'auth-enum' || lc(id).includes('enum')) return 'plausible'

  // Missing/weak hardening is a theoretical pre-condition, not an exploit.
  if (isHardeningHeaderId(id) || finding.category === 'headers' || finding.category === 'cookies') {
    return 'theoretical'
  }
  if (finding.severity === 'info') return 'theoretical'
  return 'plausible'
}

/** What an attacker needs before the finding is usable. */
function deriveAttackPrerequisite(finding: Finding): AttackPrerequisite {
  const id = finding.id || ''
  const cat = finding.category
  if (finding.severity === 'ok' || cat === 'meta') return 'none'
  if (isReflectedXssId(id) || (cat === 'html' && finding.severity === 'critical')) return 'userInteraction'
  // Authenticated-mode IDOR / authenticated RLS need a valid session.
  if (lc(id).includes('idor') || lc(id).includes('authenticated')) return 'authRequired'
  if (cat === 'auth' && lc(id).includes('auth-bypass')) return 'authRequired'
  // Most exposures (open secret, listable bucket, anon RLS, broken TLS) need
  // nothing — they're abusable straight from the public internet.
  if (
    isRealProviderSecretId(id) ||
    isSensitiveFileId(id) ||
    isPublicDataStoreId(id) ||
    isBrokenTlsId(id) ||
    isActiveProbeHitId(id) ||
    isCorsId(id)
  ) {
    return 'none'
  }
  if (cat === 'headers' || cat === 'cookies' || cat === 'integrity') return 'none'
  return 'unknown'
}

function deriveEvidenceStrength(
  finding: Finding,
  verifiedImpact: boolean,
  exploitability: Exploitability,
): EvidenceStrength {
  if (exploitability === 'confirmed') return 'confirmed'
  if (verifiedImpact) return 'strong'
  if (finding.severity === 'critical' || finding.severity === 'warn') return 'moderate'
  return 'weak'
}

/** Payment / cloud-infrastructure secret shapes (financial-grade blast radius). */
const FINANCIAL_EVIDENCE = /\bsk_live_|\bAKIA[0-9A-Z]{8,}|stripe|billing|payment|invoice|checkout/i

/**
 * V6 — business-impact derivation from observable signals only (impact type,
 * the asset the finding touches, the route context). Never a brand/domain list.
 *
 *   public        — marketing/public content, hardening observations
 *   userData      — user data surfaces (the default for data/auth findings)
 *   financial     — payment credentials, billing surfaces, PII
 *   adminInternal — admin/internal systems, service-role-grade access
 */
export function deriveBusinessImpact(
  finding: Finding,
  ctx: ScoringContext,
  impactType: ImpactType,
): BusinessImpact {
  const id = finding.id || ''
  const ev = `${finding.evidence || ''} ${finding.description || ''}`

  // Administrative / internal systems — the worst blast radius.
  if (isServiceRoleKeyId(id)) return 'adminInternal'
  if (isAdminUnauthDataId(id)) return 'adminInternal'
  if (
    ctx.routeContext === 'sensitive' &&
    (impactType === 'authBypass' || impactType === 'dataExposure' || impactType === 'credentialExposure')
  ) {
    return 'adminInternal'
  }

  // Financial-grade credentials / data.
  if (impactType === 'credentialExposure') {
    return FINANCIAL_EVIDENCE.test(ev) || FINANCIAL_EVIDENCE.test(id) ? 'financial' : 'userData'
  }
  if (FINANCIAL_EVIDENCE.test(ev)) return 'financial'

  // User-data surfaces. CORS abuse, supply-chain and transport breaks expose
  // credentialed responses / sessions — user data, not public content.
  if (impactType === 'dataExposure' || impactType === 'authBypass') return 'userData'
  if (impactType === 'codeExecution' || impactType === 'transportBreak') return 'userData'
  if (impactType === 'abusePath' || impactType === 'supplyChain') return 'userData'

  // Hardening / info-disclosure / recon on public content.
  if (impactType === 'hardening' || impactType === 'infoDisclosure' || impactType === 'none') {
    return 'public'
  }
  if (ctx.routeContext === 'public') return 'public'
  return 'userData'
}

/**
 * Derive the full professional trait set for a finding. `knownPublicAsset` and
 * the other gate inputs are computed here from the shared contract so callers
 * only need the finding + context.
 */
export function deriveFindingTraits(finding: Finding, ctx: ScoringContext): ProfessionalTraits {
  const id = finding.id || ''
  const cat = finding.category

  const knownPublicAsset =
    isPublicClientIdentifier(id, finding.evidence || '', finding.description || '') ||
    id === 'js-ast-hardcoded-creds'

  // Per-finding, NOT per-scan-stage (see scoring-engine v5.7) — a passive
  // Stage-1 finding must not become "runtime confirmed" just because the merged
  // report is at stage 2/3.
  const runtimeConfirmed = isStage2Id(id) || isStage3ConfirmationId(id)

  const authImpact =
    cat === 'auth' ||
    cat === 'auth-enum' ||
    cat === 'auth-weak' ||
    cat === 'auth-disclosure' ||
    lc(id).startsWith('auth-') ||
    lc(id).includes('rls') ||
    lc(id).includes('idor') ||
    lc(id).includes('jwt')

  const verifiedImpact = verifiedImpactPredicate(
    finding,
    { authImpact, runtimeConfirmed, knownPublicAsset },
    ctx,
  )

  const exploitability = deriveExploitability(finding, verifiedImpact)
  const attackPrerequisite = deriveAttackPrerequisite(finding)
  const impactType = deriveImpactType(finding)
  const evidenceKind = deriveEvidenceKind(finding)
  const evidenceStrength = deriveEvidenceStrength(finding, verifiedImpact, exploitability)
  const businessImpact = deriveBusinessImpact(finding, ctx, impactType)

  const activeProbeConfirmed =
    isActiveProbeHitId(id) || isStage3ConfirmationId(id) || isStage2Id(id)

  // Everything we flag is reachable over the public internet (the scanner only
  // talks to public surfaces). `meta`/`ok` observations are not "reachable
  // weaknesses". Subdomain-takeover is remotely reachable by definition.
  const remoteReachable =
    finding.severity !== 'ok' && cat !== 'meta'
      ? true
      : isSubdomainTakeoverId(id)

  const publicInternetExposure = remoteReachable && attackPrerequisite !== 'authRequired'

  return {
    verifiedImpact,
    exploitability,
    attackPrerequisite,
    remoteReachable,
    publicInternetExposure,
    activeProbeConfirmed,
    impactType,
    evidenceKind,
    evidenceStrength,
    businessImpact,
  }
}
