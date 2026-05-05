import type { VercelRequest, VercelResponse } from '@vercel/node'
import { promises as dns } from 'node:dns'
import { runScan } from './_lib/scanner.js'
import { runDeepScan } from './_lib/deep-scanner.js'
import { getCachedVerification, incrementScanCount } from './_lib/verification-store.js'
import { enrichFindings } from './_lib/fix-prompt-composer.js'
import { aggregateBand, applyRisk, classifyRouteContext, computeAggregateRisk } from './_lib/risk-scorer.js'
import type { ScanResponse } from '../src/lib/scanner-types.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 60,
}

interface ScanDeepBody {
  url?: string
  uuid?: string
  method?: 'file' | 'dns' | 'oauth'
  /** Optional user-supplied JWT for authenticated-mode IDOR/RLS probing */
  userJwt?: string
}

async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<Response> {
  const controller = new AbortController()
  const t = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { signal: controller.signal, redirect: 'follow' })
  } finally {
    clearTimeout(t)
  }
}

async function verifyOwnership(
  domain: string,
  uuid: string,
  method: 'file' | 'dns' | 'oauth',
): Promise<boolean> {
  // 'oauth' is handled separately — it lands as a cached entry in vs_verified_domains
  // already. If we got here with method='oauth' we trust the cache check below.
  if (method === 'oauth') return false
  if (method === 'file') {
    try {
      const r = await fetchWithTimeout(`https://${domain}/.well-known/Vguard-verify.txt`, 5000)
      if (!r.ok) return false
      const body = (await r.text()).trim()
      return body === uuid || body.includes(uuid)
    } catch {
      return false
    }
  }
  // DNS
  try {
    const records = await dns.resolveTxt(`_Vguard-verify.${domain}`).catch(() => [] as string[][])
    return records.map((parts) => parts.join('')).some((rec) => rec.includes(uuid))
  } catch {
    return false
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({
      ok: false,
      error: { code: 'internal', message: 'Method not allowed.' },
    })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as ScanDeepBody
  const targetUrl = (body.url ?? '').trim()
  const uuid = (body.uuid ?? '').trim()
  const method = body.method ?? 'file'
  const userJwt = typeof body.userJwt === 'string' ? body.userJwt.trim() : ''

  if (!targetUrl) {
    return res.status(400).json({
      ok: false,
      error: { code: 'invalid_url', message: 'Missing url.' },
    })
  }
  if (!uuid) {
    return res.status(400).json({
      ok: false,
      error: { code: 'invalid_url', message: 'Missing verification UUID.' },
    })
  }

  // Re-verify ownership before any active probing
  let parsedUrl: URL
  try {
    parsedUrl = new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`)
  } catch {
    return res.status(400).json({
      ok: false,
      error: { code: 'invalid_url', message: 'Invalid URL.' },
    })
  }
  // First try cached verification (Supabase) — falls back to live re-verify on miss
  const cached = await getCachedVerification(parsedUrl.hostname).catch(() => null)
  let verified = false
  if (cached && cached.uuid === uuid) {
    verified = true
  } else {
    verified = await verifyOwnership(parsedUrl.hostname, uuid, method)
  }
  if (!verified) {
    return res.status(403).json({
      ok: false,
      error: {
        code: 'rate_limited',
        message: 'Ownership verification failed. Re-verify before running the deep scan.',
      },
    })
  }
  // Bump scan_count (fire-and-forget, fail-soft)
  incrementScanCount(parsedUrl.hostname).catch(() => {
    // ignore
  })

  try {
    // Stage 1 baseline first (provides detected.supabaseAnonKey for RLS probes)
    const stage1 = await runScan(targetUrl)
    if (!stage1.ok) {
      return res.status(200).json(stage1)
    }

    const detectedProjectId = stage1.detected?.supabaseProjectIds[0] ?? null
    const detectedAnonKey = stage1.detected?.supabaseAnonKey ?? null
    const detectedAiEndpoints = stage1.detected?.aiEndpoints ?? []

    const deep = await runDeepScan({
      baselineUrl: stage1.meta.finalUrl,
      supabaseProjectId: detectedProjectId,
      supabaseAnonKey: detectedAnonKey,
      aiEndpoints: detectedAiEndpoints,
      userJwt: userJwt || null,
    })

    // stage1.findings are already enriched by runScan. Enrich deep findings
    // with the same context so the merged report has consistent fix prompts.
    const enrichedDeep = enrichFindings(deep.findings, {
      finalUrl: stage1.meta.finalUrl,
      detectedFramework: stage1.meta.detectedFramework,
    })
    // Stage 1 findings already carry riskScore from runScan; score the deep
    // additions with the same route context and concat. Aggregate risk is
    // recomputed over the union.
    const stage1Context = (stage1.meta as { routeContext?: 'sensitive' | 'public' | 'unknown' })
      .routeContext ?? classifyRouteContext(new URL(stage1.meta.finalUrl).pathname)
    const scoredDeep = applyRisk(enrichedDeep, stage1Context)
    const allFindings = [...stage1.findings, ...scoredDeep]
    const totals = {
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      warn: allFindings.filter((f) => f.severity === 'warn').length,
      info: allFindings.filter((f) => f.severity === 'info').length,
      ok: allFindings.filter((f) => f.severity === 'ok').length,
    }
    const vibeScore = Math.max(
      0,
      100 - totals.critical * 20 - totals.warn * 7 - totals.info * 2,
    )
    const aggregateRisk = computeAggregateRisk(allFindings)
    const sevOrder = { critical: 0, warn: 1, info: 2, ok: 3 } as const
    allFindings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity])

    const merged: ScanResponse = {
      ...stage1,
      findings: allFindings,
      totals,
      vibeScore,
      aggregateRisk,
      aggregateRiskBand: aggregateBand(aggregateRisk),
      durationMs: stage1.durationMs + deep.durationMs,
      stage: 3,
    }
    return res.status(200).json(merged)
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({
      ok: false,
      error: { code: 'internal', message: msg },
    })
  }
}
