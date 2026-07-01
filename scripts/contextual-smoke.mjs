/**
 * Contextual-classifier smoke test (2026-07-01).
 *
 * Runs the LOCAL scanner (`runScan` — the working-tree code, NOT production)
 * against real sites and reports how the contextual-risk-classifier graded the
 * `cookie-*` and `tls-no-http-redirect` findings. Purpose: prove strong sites
 * are not punished for hardening-only observations (false-positive guard) and
 * weak/HTTP sites are escalated correctly (false-negative guard).
 *
 * SAFETY: this drives the normal passive Stage-1 scan (GET/HEAD, header/cookie/
 * redirect/form inspection + the product's existing benign canaries). No
 * brute-force, no exploit payloads, no auth-bypass. One scan per target.
 *
 * Usage:
 *   node --import ./api/__tests__/_register.mjs --experimental-strip-types \
 *     scripts/contextual-smoke.mjs [group=A|B|C|all] [url ...]
 *
 * Group A — strong real-world sites   (expect: hardening-only, no HIGH/CRITICAL)
 * Group B — intentionally weak labs   (expect: escalation when HTTP/session risk)
 * Group C — user-provided weak prod    (verified spelling: perekbet.co.il)
 */

import { runScan } from '../api/_lib/scanner.ts'
import { writeFileSync } from 'node:fs'

const GROUPS = {
  A: ['https://google.com', 'https://apple.com', 'https://github.com', 'https://stripe.com', 'https://cloudflare.com'],
  // Public intentionally-vulnerable labs (often down / geo-blocked — skipped if unreachable).
  B: ['http://demo.testfire.net', 'http://zero.webappsecurity.com'],
  // Group C — user-provided. `perekbet.co.il` verified via DNS (perakbet.co.il is NXDOMAIN).
  C: ['https://perekbet.co.il'],
}

const CTX_IDS = (id) => id === 'tls-no-http-redirect' || id.startsWith('cookie-')

function pick(argv) {
  const args = argv.slice(2)
  const urls = args.filter((a) => a.includes('.') || a.startsWith('http'))
  if (urls.length) return urls
  const g = (args.find((a) => /^group=/.test(a)) || 'group=A').split('=')[1].toUpperCase()
  if (g === 'ALL') return [...GROUPS.A, ...GROUPS.B, ...GROUPS.C]
  return GROUPS[g] ?? GROUPS.A
}

function verdict(group, res, ctxFindings) {
  const hasHC = ctxFindings.some((f) => f.effectiveSeverity === 'high' || f.effectiveSeverity === 'critical')
  if (group === 'A') {
    return hasHC
      ? 'REVIEW — strong site shows HIGH/CRITICAL from a hardening finding (possible false positive)'
      : 'CORRECT — hardening-only, not punished (no false positive)'
  }
  // Weak groups: escalation is the desired behavior when the risk is present.
  if (hasHC) return 'CORRECT — escalated a real HTTP/session/cookie risk (no false negative)'
  // A site served entirely over plain HTTP is already the maximal transport
  // finding: the existing `tls-http` critical (hard-cap 49). The contextual
  // classifier intentionally leaves it as-is, so treat it as correctly escalated.
  const servedOverHttp = res.meta?.finalUrl?.startsWith('http://') || res.findings.some((f) => f.id === 'tls-http')
  if (servedOverHttp) return 'CORRECT — served over plain HTTP (tls-http critical, hard-capped 49)'
  const httpAlsoReachable = res.findings.some((f) => f.id === 'tls-no-http-redirect')
  return httpAlsoReachable
    ? 'REVIEW — HTTP reachable but not escalated (check for missed sensitive context)'
    : 'CORRECT — no HTTP/session risk observed to escalate'
}

function groupOf(url) {
  for (const [g, list] of Object.entries(GROUPS)) if (list.some((u) => url.includes(new URL(u).hostname.replace(/^www\./, '')))) return g
  return '?'
}

const rows = []

for (const url of pick(process.argv)) {
  const group = groupOf(url)
  process.stderr.write(`\n▶ [${group}] ${url}\n`)
  let res
  try {
    res = await runScan(url)
  } catch (e) {
    process.stderr.write(`  ✗ scan threw: ${e?.message ?? e}\n`)
    rows.push({ target: url, group, status: 'threw', error: String(e?.message ?? e) })
    continue
  }
  if (!res.ok) {
    process.stderr.write(`  ⚠ scan not ok: ${res.error.code} — ${res.error.message}\n`)
    rows.push({ target: url, group, status: res.error.code })
    continue
  }

  const ctxFindings = res.findings
    .filter((f) => CTX_IDS(f.id))
    .map((f) => ({
      id: f.id,
      effectiveSeverity: f.effectiveSeverity,
      confidence: f.confidence,
      blocksPerfectScore: f.blocksPerfectScore ?? false,
      contextClass: f.contextClass,
      reasonCodes: f.reasonCodes,
      explanation: f.contextExplanation,
    }))

  const sc = res.severityCounts ?? {}
  const row = {
    target: url,
    group,
    status: 'ok',
    rawScore: res.vibeScore,
    displayScore: res.displayScore ?? res.vibeScore,
    grade: res.grade,
    scoreAdjustedForDisplay: res.scoreAdjustedForDisplay ?? false,
    counts: { critical: sc.critical ?? 0, high: sc.high ?? 0, medium: sc.medium ?? 0, low: sc.low ?? 0 },
    blockedPerfect: res.findings.filter((f) => f.blocksPerfectScore).map((f) => `${f.id} (${f.effectiveSeverity})`),
    downgradedHardening: ctxFindings
      .filter((f) => (f.effectiveSeverity === 'low' || f.effectiveSeverity === 'info') && f.contextClass)
      .map((f) => `${f.id} → ${f.effectiveSeverity} [${(f.reasonCodes || []).join(',')}]`),
    contextual: ctxFindings,
    verdict: verdict(group, res, ctxFindings),
  }
  rows.push(row)

  process.stderr.write(
    `  score ${row.rawScore}/${row.grade} (display ${row.displayScore}, adjusted=${row.scoreAdjustedForDisplay}) ` +
      `· C${row.counts.critical}/H${row.counts.high}/M${row.counts.medium}/L${row.counts.low}\n`,
  )
  for (const f of ctxFindings) {
    process.stderr.write(`    • ${f.id}: ${f.effectiveSeverity}/${f.confidence} blocksPerfect=${f.blocksPerfectScore} [${(f.reasonCodes || []).join(', ')}]\n`)
  }
  process.stderr.write(`  ⇒ ${row.verdict}\n`)
}

// ---- final report ----
const out = { generatedAt: new Date().toISOString(), rows }
const path = process.env.SMOKE_OUT || '/private/tmp/contextual-smoke-report.json'
writeFileSync(path, JSON.stringify(out, null, 2))
process.stderr.write(`\n📄 JSON report → ${path}\n`)

// Machine-readable summary line for CI/consumption.
console.log(JSON.stringify(out))
