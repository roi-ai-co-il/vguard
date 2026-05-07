import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'

/**
 * GET /api/badge?url=<host>
 *
 * Returns an SVG badge ("shields.io"-style) showing the latest Vguard score
 * for the given hostname. Designed to be embedded in README files:
 *
 *   ![Vguard score](https://vguardus.com/api/badge?url=example.com)
 *
 * Lookup strategy:
 *  1. Normalize the input to a bare hostname (strip scheme, www, path).
 *  2. Query `vs_scan_log` for the most recent row matching that hostname.
 *  3. Render a colored SVG. If no scan exists yet, render a neutral "scan now"
 *     badge that links the README reader back to Vguard.
 *
 * Cached at the edge for 5 minutes — frequent README hits don't pummel the
 * database, and the score doesn't move in seconds anyway.
 */

const CACHE_SECONDS = 300

function normalizeHost(input: string): string | null {
  if (!input) return null
  let s = input.trim().toLowerCase()
  // Strip scheme + path so users can paste either `example.com` or
  // `https://www.example.com/dashboard` and get the same result.
  s = s.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split('?')[0].split('#')[0]
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return null
  return s
}

function colorForScore(score: number): { bg: string; label: string } {
  if (score >= 90) return { bg: '#3fb950', label: 'A' }
  if (score >= 75) return { bg: '#a3e635', label: 'B' }
  if (score >= 60) return { bg: '#facc15', label: 'C' }
  if (score >= 40) return { bg: '#fb923c', label: 'D' }
  return { bg: '#ef4444', label: 'F' }
}

/**
 * Approximate width of the score side. SVG text doesn't reflow, so we size
 * the right-hand box to fit. 7.5px per char is conservative for the 11px
 * Verdana we use; small enough that the right edge doesn't get clipped.
 */
function rightSideWidth(scoreText: string): number {
  return Math.max(38, scoreText.length * 9 + 14)
}

function badgeSvg(scoreText: string, color: string, sub: string | null): string {
  const labelText = 'vguard'
  const labelW = 56 // visually balanced for "vguard" in 11px Verdana
  const scoreW = rightSideWidth(scoreText)
  const total = labelW + scoreW
  const subText = sub ? `<title>${escapeXml(sub)}</title>` : ''

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="vguard: ${scoreText}">
${subText}
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-color="#000" stop-opacity=".3"/>
    <stop offset="1" stop-color="#000" stop-opacity=".5"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="#1f2937"/>
    <rect x="${labelW}" width="${scoreW}" height="20" fill="${color}"/>
    <rect width="${total}" height="20" fill="url(#g)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelW / 2}" y="14" fill="#000" fill-opacity=".3">${labelText}</text>
    <text x="${labelW / 2}" y="13">${labelText}</text>
    <text x="${labelW + scoreW / 2}" y="14" fill="#000" fill-opacity=".3">${escapeXml(scoreText)}</text>
    <text x="${labelW + scoreW / 2}" y="13">${escapeXml(scoreText)}</text>
  </g>
</svg>`
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Use GET' })
    return
  }
  const raw = (req.query.url ?? req.query.domain ?? '').toString()
  const host = normalizeHost(raw)

  // Always SVG — even on errors. README readers expect an image.
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8')
  // Short cache so a fresh re-scan reflects within ~5 minutes.
  res.setHeader('Cache-Control', `public, max-age=${CACHE_SECONDS}, s-maxage=${CACHE_SECONDS}, stale-while-revalidate=86400`)

  if (!host) {
    res.status(200).send(badgeSvg('invalid url', '#6b7280', 'Pass ?url=<domain> e.g. ?url=example.com'))
    return
  }

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) {
    res.status(200).send(badgeSvg('not configured', '#6b7280', 'Vguard badge service not configured'))
    return
  }

  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const { data, error } = await client
      .from('vs_scan_log')
      .select('vibe_score, scanned_at, top_finding_severity')
      .eq('hostname', host)
      .order('scanned_at', { ascending: false })
      .limit(1)
    if (error) throw error
    const row = data?.[0]
    if (!row) {
      // No scan yet — neutral badge that invites a scan.
      res.status(200).send(
        badgeSvg('not scanned', '#6b7280', `No Vguard scan yet for ${host}. Run one at https://vguardus.com`),
      )
      return
    }
    const score = Math.round(row.vibe_score as number)
    const c = colorForScore(score)
    const tooltip = `Vguard score for ${host}: ${score}/100 (grade ${c.label}). Last scanned ${new Date(row.scanned_at as string).toUTCString()}.`
    res.status(200).send(badgeSvg(`${score}/100`, c.bg, tooltip))
  } catch {
    res.status(200).send(badgeSvg('error', '#6b7280', 'Vguard badge lookup failed'))
  }
}
