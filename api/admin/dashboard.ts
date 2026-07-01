import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { authorizeAdmin, adminSupabaseEnv } from '../_lib/admin-auth.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 15,
}

// Cap the rows we pull for in-memory aggregation. The tables are small today
// (~300 scans, ~450 events); this keeps the endpoint O(1) cost as they grow and
// avoids a heavy query. The cap is surfaced to the UI so a future "older than
// N rows not counted" note can be shown honestly.
const AGG_CAP = 5000
const RECENT_SCANS = 500
const LEADS_LIMIT = 300

type ScanRow = {
  id: number
  hostname: string
  vibe_score: number | null
  top_finding_id: string | null
  top_finding_severity: string | null
  top_finding_title: string | null
  country: string | null
  scanned_at: string
  waf_vendor: string | null
  waf_blocked: boolean | null
  stealth_retry_attempted: boolean | null
  stealth_retry_succeeded: boolean | null
  scan_outcome: string | null
}

function grade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

function bump<K extends string | number>(m: Map<K, number>, k: K, by = 1) {
  m.set(k, (m.get(k) ?? 0) + by)
}

function mapToSorted(m: Map<string, number>, limit?: number) {
  const arr = [...m.entries()].map(([key, count]) => ({ key, count }))
  arr.sort((a, b) => b.count - a.count)
  return limit ? arr.slice(0, limit) : arr
}

async function buildOverview(client: SupabaseClient) {
  // Pull the rows we aggregate in-memory (cheap at current scale).
  const [scansRes, eventsRes, verifiedRes, stage2Res] = await Promise.all([
    client
      .from('vs_scan_log')
      .select(
        'id, hostname, vibe_score, top_finding_id, top_finding_severity, top_finding_title, country, scanned_at, waf_vendor, waf_blocked, stealth_retry_attempted, stealth_retry_succeeded, scan_outcome',
      )
      .order('scanned_at', { ascending: false })
      .limit(AGG_CAP),
    client
      .from('vs_audit_log')
      .select('event_type, created_at')
      .order('created_at', { ascending: false })
      .limit(AGG_CAP),
    client
      .from('vs_domain_authorizations')
      .select('domain, email, method, verified_at, revoked_at')
      .order('verified_at', { ascending: false }),
    client.from('vs_stage2_collections').select('uuid', { count: 'exact', head: true }),
  ])

  const scans = (scansRes.data as ScanRow[] | null) ?? []
  const events = (eventsRes.data as { event_type: string; created_at: string }[] | null) ?? []

  const now = Date.now()
  const DAY = 86_400_000
  let scans24h = 0
  let scans7d = 0
  let scans30d = 0
  let successCount = 0
  let failCount = 0
  let wafBlocked = 0
  let stealthRescued = 0
  let scoreSum = 0
  let scoreN = 0

  const hosts = new Set<string>()
  const gradeDist = new Map<string, number>([['A', 0], ['B', 0], ['C', 0], ['D', 0], ['F', 0]])
  const countries = new Map<string, number>()
  const findings = new Map<string, number>()
  const findingSeverity = new Map<string, string>()
  const wafVendors = new Map<string, number>()
  const hostAgg = new Map<string, { scans: number; lastScore: number | null; lastAt: string }>()

  for (const s of scans) {
    const t = new Date(s.scanned_at).getTime()
    if (now - t <= DAY) scans24h++
    if (now - t <= 7 * DAY) scans7d++
    if (now - t <= 30 * DAY) scans30d++

    if (s.hostname) hosts.add(s.hostname)
    if (s.country) bump(countries, s.country)
    if (s.waf_vendor) bump(wafVendors, s.waf_vendor)
    if (s.waf_blocked) wafBlocked++
    if (s.stealth_retry_succeeded) stealthRescued++

    const ok = s.scan_outcome === 'success'
    if (ok) {
      successCount++
      if (typeof s.vibe_score === 'number') {
        scoreSum += s.vibe_score
        scoreN++
        bump(gradeDist, grade(s.vibe_score))
      }
    } else {
      failCount++
    }

    if (s.top_finding_title) {
      bump(findings, s.top_finding_title)
      if (s.top_finding_severity) findingSeverity.set(s.top_finding_title, s.top_finding_severity)
    }

    const ex = hostAgg.get(s.hostname)
    if (!ex) {
      hostAgg.set(s.hostname, { scans: 1, lastScore: s.vibe_score, lastAt: s.scanned_at })
    } else {
      ex.scans++
    }
  }

  const funnel = new Map<string, number>()
  for (const e of events) bump(funnel, e.event_type)

  const topHosts = [...hostAgg.entries()]
    .map(([hostname, v]) => ({ hostname, ...v }))
    .sort((a, b) => b.scans - a.scans)
    .slice(0, 15)

  const topFindings = mapToSorted(findings, 10).map((f) => ({
    title: f.key,
    count: f.count,
    severity: findingSeverity.get(f.key) ?? 'info',
  }))

  return {
    kpis: {
      totalScans: scans.length,
      scans24h,
      scans7d,
      scans30d,
      uniqueHosts: hosts.size,
      avgScore: scoreN > 0 ? Math.round(scoreSum / scoreN) : null,
      successCount,
      failCount,
      wafBlocked,
      stealthRescued,
      verifiedDomains:
        (verifiedRes.data as { revoked_at: string | null }[] | null)?.filter((r) => !r.revoked_at)
          .length ?? 0,
      stage2Runs: stage2Res.count ?? 0,
      aggCapped: scans.length >= AGG_CAP || events.length >= AGG_CAP,
    },
    gradeDist: Object.fromEntries(gradeDist),
    countries: mapToSorted(countries, 20),
    wafVendors: mapToSorted(wafVendors),
    topFindings,
    topHosts,
    funnel: Object.fromEntries(funnel),
    recentScans: scans.slice(0, RECENT_SCANS),
    verified: verifiedRes.data ?? [],
  }
}

async function buildLeads(client: SupabaseClient) {
  // Tolerate the table not existing yet (migration 0002 not applied) — the rest
  // of the dashboard still works; the leads tab just shows empty + a hint.
  const { data, error } = await client
    .from('vs_leads')
    .select('id, created_at, source, name, email, message, domain, method, verified, status')
    .order('created_at', { ascending: false })
    .limit(LEADS_LIMIT)

  if (error) {
    return { leads: [], leadsTableMissing: true, statusCounts: {} as Record<string, number> }
  }

  const statusCounts = new Map<string, number>()
  for (const l of data ?? []) bump(statusCounts, (l as { status: string }).status)

  return {
    leads: data ?? [],
    leadsTableMissing: false,
    statusCounts: Object.fromEntries(statusCounts),
  }
}

const ALLOWED_STATUS = new Set(['new', 'read', 'replied', 'archived'])

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Allow', 'GET, POST')
    return res.status(404).json({ ok: false, error: 'not_found' })
  }

  const gate = await authorizeAdmin(req, res)
  if (!gate.ok) {
    if (gate.code === 429) return res.status(429).json({ ok: false, error: 'rate_limited' })
    return res.status(404).json({ ok: false, error: 'not_found' })
  }

  const env = adminSupabaseEnv()
  if (!env) {
    return res.status(503).json({ ok: false, error: 'storage_not_configured' })
  }

  const client = createClient(env.url, env.key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  })

  // POST → update a lead's status (mark read / replied / archived).
  if (req.method === 'POST') {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as {
      action?: string
      id?: unknown
      status?: unknown
    }
    if (body.action !== 'lead_status') {
      return res.status(400).json({ ok: false, error: 'unknown_action' })
    }
    const id = typeof body.id === 'number' ? body.id : parseInt(String(body.id), 10)
    const status = typeof body.status === 'string' ? body.status : ''
    if (!Number.isFinite(id) || !ALLOWED_STATUS.has(status)) {
      return res.status(400).json({ ok: false, error: 'invalid_params' })
    }
    const { error } = await client.from('vs_leads').update({ status }).eq('id', id)
    if (error) {
      return res.status(500).json({ ok: false, error: error.message })
    }
    return res.status(200).json({ ok: true })
  }

  // GET → full dashboard payload.
  const section = typeof req.query.section === 'string' ? req.query.section : 'all'
  try {
    if (section === 'leads') {
      return res.status(200).json({ ok: true, ...(await buildLeads(client)) })
    }
    const [overview, leads] = await Promise.all([buildOverview(client), buildLeads(client)])
    return res.status(200).json({ ok: true, ...overview, ...leads })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown'
    return res.status(500).json({ ok: false, error: msg })
  }
}
