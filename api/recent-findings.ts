import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface RecentFindingRow {
  hostname: string
  vibe_score: number
  top_finding_id: string | null
  top_finding_severity: string | null
  top_finding_title: string | null
  country: string | null
  scanned_at: string
}

interface RecentFindingPublic {
  hostname: string
  secondsAgo: number
  finding: string
  country: string | null
  severity: string
}

function redactHostname(host: string): string {
  // Keep first 2 + last 2 chars of label, rest as ***. Preserves "feel" without leaking which user site.
  const labels = host.split('.')
  if (labels.length === 0) return '***'
  const root = labels[0]
  if (root.length <= 4) {
    return root.slice(0, 1) + '***' + (labels.length > 1 ? '.' + labels.slice(1).join('.') : '')
  }
  return (
    root.slice(0, 2) +
    '***' +
    root.slice(-2) +
    (labels.length > 1 ? '.' + labels.slice(1).join('.') : '')
  )
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'public, max-age=30, s-maxage=30')

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) {
    // Fail-soft: return empty list, frontend will fall back to placeholder
    return res.status(200).json({ ok: true, items: [] })
  }

  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const { data, error } = await client
      .from('vs_scan_log')
      .select('hostname, vibe_score, top_finding_id, top_finding_severity, top_finding_title, country, scanned_at')
      .not('top_finding_id', 'is', null)
      .order('scanned_at', { ascending: false })
      .limit(8)
    if (error) {
      return res.status(200).json({ ok: true, items: [] })
    }
    const rows = (data ?? []) as RecentFindingRow[]
    const now = Date.now()
    const items: RecentFindingPublic[] = rows.slice(0, 4).map((r) => ({
      hostname: redactHostname(r.hostname),
      secondsAgo: Math.max(1, Math.round((now - new Date(r.scanned_at).getTime()) / 1000)),
      finding: r.top_finding_title ?? r.top_finding_id ?? 'Issue detected',
      country: r.country,
      severity: r.top_finding_severity ?? 'info',
    }))
    return res.status(200).json({ ok: true, items })
  } catch {
    return res.status(200).json({ ok: true, items: [] })
  }
}
