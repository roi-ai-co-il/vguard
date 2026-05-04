/**
 * VibeSecure — Risk scorer.
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
export function computeRiskScore(finding: Finding): number {
  if (finding.severity === 'ok') return 0
  const override = lookupOverride(finding.id)
  if (override !== null) {
    return Math.round(clamp(override, 0, 10) * 10) / 10
  }
  const base = BASE_BY_SEVERITY[finding.severity]
  const bump = CATEGORY_BUMP[finding.category] ?? 0
  return Math.round(clamp(base + bump, 0, 10) * 10) / 10
}

/**
 * Returns a fresh array of findings with `riskScore` and `riskBand` set.
 * Doesn't mutate the input.
 */
export function applyRisk(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    const riskScore = computeRiskScore(f)
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
