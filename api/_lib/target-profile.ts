/**
 * Vguard — Target fingerprinting + scan coverage/confidence (v5, 2026-06-07).
 *
 * Classifies WHAT kind of target we're scanning from OBSERVABLE signals only —
 * never from the brand/domain name. This drives two things kept strictly
 * separate from the security score:
 *   1. `targetProfile`  — adaptive scan intensity + report tone.
 *   2. `coverage`/`confidence` — "how much of the relevant surface this scan
 *      type could actually examine", which is NOT the same as "how secure it is".
 *
 * Honesty rules baked in:
 *   - A big professional site gets NO score boost; if passive coverage is
 *     limited that lowers CONFIDENCE, not the score.
 *   - A small static site legitimately gets high coverage/confidence for its
 *     context (there isn't much surface to miss).
 *   - A WAF block lowers confidence; it never inflates OR deflates the score.
 *
 * Pure module — no I/O, browser-safe.
 */

import type {
  ScanConfidence,
  TargetProfile,
} from '../../src/lib/scanner-types.js'

export interface TargetSignals {
  framework: string | null
  /** SPA root mount / __NEXT_DATA__ / hydrated bundle present. */
  hasAppShell: boolean
  /** Login or signup surface (forms, auth-provider globals, auth routes). */
  hasLoginSurface: boolean
  /** First-party API surface (`/api/*`, GraphQL, OpenAPI). */
  hasApiSurface: boolean
  /** Checkout / cart / payment surface. */
  hasCheckout: boolean
  /** Admin / dashboard route discovered. */
  hasAdminRoute: boolean
  usesSupabase: boolean
  usesFirebase: boolean
  usesS3: boolean
  /** Lovable / Bolt / Replit / Cursor / v0-style build traces. */
  vibeStackTrace: boolean
  /** Number of distinct cross-origin third-party scripts. */
  thirdPartyScriptCount: number
  /** Number of JS bundles fetched. */
  bundleCount: number
  /** Hosted on a shared platform apex (*.vercel.app, *.netlify.app, …). */
  isSharedPlatform: boolean
  /** Professional CDN/edge in front (cloudflare/akamai/fastly/cloudfront/…). */
  hasProfessionalEdge: boolean
  /** A WAF blocked us AND the stealth retry could not get through. */
  coverageBlocked: boolean
  /** Discovered subdomain count (CT lookup). */
  subdomainCount: number
}

/**
 * Classify the target. Order matters — most specific / highest-signal first.
 * Returns `unknown` only when nothing observable distinguishes the target.
 */
export function deriveTargetProfile(s: TargetSignals): TargetProfile {
  if (s.coverageBlocked) return 'wafLimitedTarget'

  if (s.hasCheckout) return 'ecommerceCheckout'

  // Vibe-coded: backend-as-a-service traces or known no-code/AI-builder output.
  const baasApp = (s.usesSupabase || s.usesFirebase) && (s.hasAppShell || s.hasLoginSurface)
  if (s.vibeStackTrace || baasApp) return 'vibeCodedApp'

  if (s.hasLoginSurface) return 'saasLoginApp'

  if (s.hasApiSurface && !s.hasAppShell) return 'apiHeavyApp'

  if (s.hasAppShell) return 'spaAppShell'

  // No app/login/api surface → it's a content site. Distinguish a polished
  // enterprise marketing site (professional edge + lots of third-party tooling
  // + own domain + subdomains) from a small static/business site.
  const enterprise =
    s.hasProfessionalEdge &&
    !s.isSharedPlatform &&
    (s.thirdPartyScriptCount >= 5 || s.subdomainCount >= 4)
  if (enterprise) return 'enterpriseProfessionalSite'

  if (s.thirdPartyScriptCount >= 1 || s.bundleCount >= 1) return 'smallBusinessSite'

  return 'staticMarketingSite'
}

export interface Coverage {
  coverageScore: number // 0–100
  scanConfidence: ScanConfidence
}

/**
 * How much of the RELEVANT surface a passive Stage-1 scan could examine.
 *
 * Anchored at 100 for a target whose entire surface is passively visible (a
 * static site). Each surface that exists but a passive scan cannot verify
 * (auth-gated areas, API behaviour, RLS, a WAF block) subtracts — because those
 * are real unknowns, not because the site is large or famous.
 */
export function computeCoverage(s: TargetSignals, hasVerifiedImpact: boolean): Coverage {
  let coverage = 100

  if (s.coverageBlocked) coverage -= 55 // we couldn't even read the page reliably
  if (s.hasLoginSurface) coverage -= 18 // authenticated area not tested in Stage 1
  if (s.hasApiSurface) coverage -= 12 // API behaviour/authz not exercised
  if (s.usesSupabase || s.usesFirebase) coverage -= 15 // RLS/rules need Stage 3
  if (s.hasAdminRoute) coverage -= 8
  if (s.hasCheckout) coverage -= 8
  // A large, multi-subdomain professional surface means one URL is a small
  // sample of the whole — lowers confidence, NOT the score.
  if (s.subdomainCount >= 6) coverage -= 8
  if (s.thirdPartyScriptCount >= 12) coverage -= 4

  // If we DID confirm real impact, our confidence in the (low) score is high —
  // we proved something concrete, regardless of unexplored surface.
  if (hasVerifiedImpact) coverage = Math.max(coverage, 75)

  coverage = Math.max(20, Math.min(100, Math.round(coverage)))

  const scanConfidence: ScanConfidence =
    coverage >= 80 ? 'high' : coverage >= 55 ? 'medium' : 'low'

  return { coverageScore: coverage, scanConfidence }
}
