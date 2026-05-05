/**
 * Vguard — Risk scorer.
 *
 * Maps each Finding to a CVSS-style 0.0–10.0 score so the UI can rank
 * "fix-first" within the same severity bucket. Severity alone is too coarse:
 * a missing X-Frame-Options on a marketing site (warn) and a leaked Stripe
 * live secret (critical) are both important, but the latter is *much* more
 * urgent. Risk score makes that explicit.
 *
 * Pure function — no I/O, no Node-only imports — so it can run in any runtime.
 */

import type { Category, Finding, Severity } from '../../src/lib/scanner-types.js'

type RiskBand = NonNullable<Finding['riskBand']>

/**
 * S1+5 — Content-aware context. Classifies the URL path the scan ran
 * against. Sensitive contexts (admin/auth/checkout/settings) bump risk
 * for finding categories that gain real exploit value when the page
 * IS user-facing privileged surface (e.g. headers + cookies on /admin
 * matter more than on /about).
 */
export type RouteContext = 'sensitive' | 'public' | 'unknown'

export function classifyRouteContext(pathname: string): RouteContext {
  const p = (pathname || '/').toLowerCase()
  // Sensitive: admin / auth / payment / settings
  if (
    /\/(?:admin|adm|administrator|backoffice|control|console|cms|manage(?:ment)?|root|sysadmin|superuser|impersonate|tenant|wp-admin|dashboard|account|profile|settings|preferences|billing|payments?|checkout|cart|order|invoice|receipt|subscription|pay|wallet|bank|transfer|withdraw|deposit|kyc|verify|verification|onboarding|signup|register|login|signin|sign-in|sign-up|signout|logout|auth|oauth|sso|reset|forgot|password|2fa|mfa|otp|api\/auth|api\/admin|api\/internal)\b/i.test(
      p,
    )
  ) {
    return 'sensitive'
  }
  // Clearly public marketing surface
  if (/^\/?(?:|index\.html?|home|about|blog|news|press|legal|terms|privacy|cookies|contact|help|faq|features|pricing|docs|documentation|api-docs|case-studies?|customers|stories|team|company|jobs|careers)(?:\/|$)/i.test(p)) {
    return 'public'
  }
  return 'unknown'
}

/**
 * Categories whose risk genuinely changes based on whether the URL is
 * a privileged surface vs marketing. Missing X-Frame-Options on /admin
 * is materially worse than on /about (clickjacking the admin = takeover;
 * clickjacking marketing = confusion).
 */
const CONTEXT_AWARE_CATEGORIES: Set<Category> = new Set([
  'headers',
  'cookies',
  'mixed-content',
  'sourcemaps',
  'auth',
  'tls',
])

const BASE_BY_SEVERITY: Record<Severity, number> = {
  critical: 8.0,
  warn: 5.0,
  info: 2.5,
  ok: 0.0,
}

const CATEGORY_BUMP: Partial<Record<Category, number>> = {
  secrets: 1.5,
  auth: 1.0,
  ai: 0.5,
  paths: 0.8,
  tls: 0.5,
  // headers / cookies / dns / email / methods / integrity / mixed-content /
  // sourcemaps / html / deps / meta — base only.
}

/**
 * ID-prefix overrides for known-very-bad findings. The longest matching prefix
 * wins. Keys must match the `id` set in `scanner.ts`. When overriding, the
 * resulting score replaces the (severity + category-bump) calculation entirely.
 */
const ID_PREFIX_OVERRIDES: { prefix: string; score: number }[] = [
  // Live secret keys in shipped JS = "rotate now" tier.
  { prefix: 'secrets-supabase-service-role', score: 9.8 },
  { prefix: 'secrets-stripe', score: 9.8 },
  { prefix: 'secrets-aws', score: 9.8 },
  { prefix: 'secrets-anthropic', score: 9.5 },
  { prefix: 'secrets-openai', score: 9.5 },
  { prefix: 'secrets-github', score: 9.5 },
  { prefix: 'secrets-resend', score: 9.0 },
  { prefix: 'secrets-slack', score: 8.5 },
  { prefix: 'secrets-google', score: 7.5 },
  { prefix: 'secrets-', score: 8.5 }, // generic secret fallback
  // Public data exfiltration via misconfig.
  { prefix: 'paths-firebase-rtdb-root', score: 9.5 },
  { prefix: 'paths-supabase-storage-public', score: 9.0 },
  { prefix: 'paths-firebase-storage-public', score: 9.0 },
  { prefix: 'paths-s3-listbucket', score: 9.0 },
  { prefix: 'paths-env', score: 9.5 },
  { prefix: 'paths-git', score: 8.5 },
  { prefix: 'paths-backup', score: 8.5 },
  { prefix: 'paths-database-sql', score: 9.0 },
  { prefix: 'paths-aws-credentials', score: 9.5 },
  // Transport.
  { prefix: 'tls-http', score: 9.0 },
  { prefix: 'tls-weak-version', score: 8.0 },
  { prefix: 'tls-cert-expired', score: 8.0 },
  // Active probe hits.
  { prefix: 'paths-xss-reflected', score: 8.5 },
  { prefix: 'paths-sqli-error', score: 8.5 },
  { prefix: 'paths-open-redirect', score: 6.5 },
  // Auth.
  { prefix: 'auth-signup-supabase-open', score: 7.5 },
  { prefix: 'auth-signup', score: 6.5 },
  // Source maps revealing source.
  { prefix: 'sourcemaps-exposed', score: 6.0 },
]

function lookupOverride(id: string): number | null {
  let best: { prefix: string; score: number } | null = null
  for (const entry of ID_PREFIX_OVERRIDES) {
    if (id.startsWith(entry.prefix)) {
      if (!best || entry.prefix.length > best.prefix.length) best = entry
    }
  }
  return best?.score ?? null
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n))
}

function bandFor(score: number): RiskBand {
  if (score >= 8) return 'severe'
  if (score >= 6) return 'high'
  if (score >= 3) return 'medium'
  return 'low'
}

/** Pure: returns score 0.0–10.0 for a single Finding (rounded to 1 decimal). */
export function computeRiskScore(
  finding: Finding,
  context: RouteContext = 'unknown',
): number {
  if (finding.severity === 'ok') return 0
  const override = lookupOverride(finding.id)
  let raw: number
  if (override !== null) {
    raw = override
  } else {
    const base = BASE_BY_SEVERITY[finding.severity]
    const bump = CATEGORY_BUMP[finding.category] ?? 0
    raw = base + bump
  }
  // S1+5: context-aware bump. Sensitive surface adds 1.0; public surface
  // shaves 0.5 (so a missing CSP on /about ranks lower than the same
  // finding on /admin). Only applied for categories where context matters.
  if (CONTEXT_AWARE_CATEGORIES.has(finding.category)) {
    if (context === 'sensitive') raw += 1.0
    else if (context === 'public') raw -= 0.5
  }
  return Math.round(clamp(raw, 0, 10) * 10) / 10
}

/**
 * Returns a fresh array of findings with `riskScore` and `riskBand` set.
 * Doesn't mutate the input. `context` lets the scorer adjust scores based
 * on the page's privilege level (S1+5 — content-aware severity).
 */
export function applyRisk(
  findings: Finding[],
  context: RouteContext = 'unknown',
): Finding[] {
  return findings.map((f) => {
    const riskScore = computeRiskScore(f, context)
    return {
      ...f,
      riskScore,
      riskBand: bandFor(riskScore),
    }
  })
}

/**
 * Aggregate risk for the whole scan, 0–100 (100 = worst).
 *
 * Mixes top-finding magnitude (so one severe issue dominates) with cumulative
 * pressure (so a wall of medium findings still moves the needle):
 *
 *   aggregate = clamp(  max * 8  +  sum * 0.6  ,  0,  100 )
 *
 * 8 × max means a single severe (≥8) finding pushes us into the "high"
 * aggregate band by itself; 0.6 × sum means a flood of medium findings adds
 * up but doesn't dwarf one critical.
 */
export function computeAggregateRisk(findings: Finding[]): number {
  const scores = findings
    .filter((f) => f.severity !== 'ok')
    .map((f) => f.riskScore ?? computeRiskScore(f))
  if (scores.length === 0) return 0
  const max = Math.max(...scores)
  const sum = scores.reduce((a, b) => a + b, 0)
  const composite = max * 8 + sum * 0.6
  return Math.round(clamp(composite, 0, 100))
}

export function aggregateBand(score: number): RiskBand {
  if (score >= 70) return 'severe'
  if (score >= 40) return 'high'
  if (score >= 15) return 'medium'
  return 'low'
}
