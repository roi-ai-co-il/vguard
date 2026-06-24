// Captures real Stage-1 finding-sets from the live API for a panel of sites,
// writes them as a committed fixture for the calibration regression test.
// Run: node scripts/capture-calibration.mjs
import { writeFileSync } from 'node:fs'

const API = process.env.VGUARD_API || 'https://v-guards.com'
const PANEL = [
  { url: 'https://apple.com', kind: 'professional' },
  { url: 'https://www.paloaltonetworks.com', kind: 'professional' },
  { url: 'https://www.nvidia.com', kind: 'professional' },
  { url: 'https://www.dell.com', kind: 'professional' },
  { url: 'https://www.microsoft.com', kind: 'professional' },
  { url: 'https://www.cloudflare.com', kind: 'professional' },
  { url: 'https://stripe.com', kind: 'professional' },
  { url: 'https://vercel.com', kind: 'professional' },
]

const out = []
for (const { url, kind } of PANEL) {
  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    const r = await res.json()
    if (!r.ok) { console.error(url, 'ERR', r.error.code); continue }
    const findings = r.findings
      .filter((x) => x.severity !== 'ok')
      .map((x) => ({ id: x.id, severity: x.severity, category: x.category, evidence: (x.evidence || '').slice(0, 80) }))
    out.push({ url, kind, liveScore: r.vibeScore, findings })
    console.error(url, `${r.vibeScore}/${r.grade}`, `${findings.length} findings`)
  } catch (e) {
    console.error(url, 'FAIL', e.message)
  }
}
writeFileSync(new URL('../api/__tests__/calibration-fixtures.json', import.meta.url), JSON.stringify(out, null, 2))
console.error(`\nWrote ${out.length} fixtures.`)
