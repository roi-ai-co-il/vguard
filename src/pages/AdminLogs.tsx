import { useEffect, useMemo, useState } from 'react'

interface AuditRow {
  id: number
  created_at: string
  event_type: string
  user_id: string | null
  session_id: string | null
  ip_hash: string | null
  user_agent: string | null
  path: string | null
  scanned_url: string | null
  scan_outcome: string | null
  vibe_score: number | null
  waf_vendor: string | null
  metadata: Record<string, unknown> | null
}

interface ApiResponse {
  ok: boolean
  count?: number
  logs?: AuditRow[]
  error?: string
}

const EVENT_TYPES = [
  '',
  'page_visit',
  'scan_started',
  'scan_completed',
  'scan_failed',
  'stage2_started',
  'stage2_completed',
  'badge_requested',
  'terms_viewed',
  'privacy_viewed',
] as const

function fmt(d: string) {
  try {
    return new Date(d).toLocaleString('en-GB', { hour12: false })
  } catch {
    return d
  }
}

function shortHash(h: string | null): string {
  if (!h) return '—'
  return h.slice(0, 8)
}

function shortUa(ua: string | null): string {
  if (!ua) return '—'
  if (ua.length > 60) return ua.slice(0, 60) + '…'
  return ua
}

export default function AdminLogs() {
  const [secret, setSecret] = useState<string>(() => (sessionStorage.getItem('vg_admin_secret') ?? '').trim())
  const [submittedSecret, setSubmittedSecret] = useState<string>('')
  const [eventType, setEventType] = useState<string>('')
  const [domain, setDomain] = useState<string>('')
  const [scanOutcome, setScanOutcome] = useState<string>('')
  const [wafVendor, setWafVendor] = useState<string>('')
  const [since, setSince] = useState<string>('')
  const [until, setUntil] = useState<string>('')
  const [data, setData] = useState<ApiResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [authError, setAuthError] = useState<string>('')

  const queryString = useMemo(() => {
    const p = new URLSearchParams()
    if (eventType) p.set('event_type', eventType)
    if (domain) p.set('domain', domain)
    if (scanOutcome) p.set('scan_outcome', scanOutcome)
    if (wafVendor) p.set('waf_vendor', wafVendor)
    if (since) p.set('since', new Date(since).toISOString())
    if (until) p.set('until', new Date(until).toISOString())
    p.set('limit', '100')
    return p.toString()
  }, [eventType, domain, scanOutcome, wafVendor, since, until])

  async function fetchLogs(s: string) {
    setLoading(true)
    setAuthError('')
    try {
      const r = await fetch(`/api/admin/logs?${queryString}`, {
        headers: { 'x-admin-secret': s },
      })
      if (r.status === 404) {
        setAuthError('Access denied.')
        setData(null)
        sessionStorage.removeItem('vg_admin_secret')
        setSubmittedSecret('')
        return
      }
      if (r.status === 429) {
        setAuthError('Too many requests. Slow down.')
        return
      }
      const j = (await r.json()) as ApiResponse
      setData(j)
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : 'unknown error')
    } finally {
      setLoading(false)
    }
  }

  function login(e: React.FormEvent) {
    e.preventDefault()
    const clean = secret.trim()
    setSecret(clean)
    sessionStorage.setItem('vg_admin_secret', clean)
    setSubmittedSecret(clean)
    fetchLogs(clean)
  }

  useEffect(() => {
    if (submittedSecret) fetchLogs(submittedSecret)
  }, [queryString, submittedSecret]) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-attempt with stored secret on first mount.
  useEffect(() => {
    if (secret && !submittedSecret) {
      setSubmittedSecret(secret)
      fetchLogs(secret)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (!submittedSecret || authError === 'Access denied.') {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-6">
        <form onSubmit={login} className="w-full max-w-sm space-y-4 border border-zinc-800 rounded-lg p-6 bg-zinc-900/50">
          <h1 className="text-xl font-semibold">Vguard · Admin</h1>
          <p className="text-sm text-zinc-400">Enter the admin secret to view audit logs.</p>
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value.replace(/\s+/g, ''))}
            placeholder="ADMIN_SECRET"
            autoFocus
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            inputMode="text"
            name="vg-admin-token"
            className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-zinc-500"
          />
          {authError && <p className="text-sm text-red-400">{authError}</p>}
          <button
            type="submit"
            className="w-full bg-zinc-100 text-zinc-900 py-2 rounded text-sm font-medium hover:bg-white"
          >
            Sign in
          </button>
        </form>
      </div>
    )
  }

  const logs = data?.logs ?? []

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <div className="max-w-7xl mx-auto space-y-4">
        <div className="flex items-baseline justify-between">
          <h1 className="text-2xl font-semibold">Vguard · Audit Logs</h1>
          <button
            onClick={() => {
              sessionStorage.removeItem('vg_admin_secret')
              setSecret('')
              setSubmittedSecret('')
              setData(null)
            }}
            className="text-sm text-zinc-400 hover:text-zinc-200 underline"
          >
            Sign out
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-sm">
          <select
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          >
            {EVENT_TYPES.map((t) => (
              <option key={t || 'all'} value={t}>
                {t || 'event_type · all'}
              </option>
            ))}
          </select>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="scanned_url contains…"
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          />
          <input
            value={scanOutcome}
            onChange={(e) => setScanOutcome(e.target.value)}
            placeholder="scan_outcome"
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          />
          <input
            value={wafVendor}
            onChange={(e) => setWafVendor(e.target.value)}
            placeholder="waf_vendor"
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          />
          <input
            type="datetime-local"
            value={since}
            onChange={(e) => setSince(e.target.value)}
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          />
          <input
            type="datetime-local"
            value={until}
            onChange={(e) => setUntil(e.target.value)}
            className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1.5"
          />
        </div>

        <div className="text-xs text-zinc-500">
          {loading ? 'Loading…' : `${logs.length} of latest 100 rows. Sensitive values (cookies, tokens, raw IPs) are never stored — see Privacy Policy.`}
          {data?.error && <span className="text-red-400 ml-2">· {data.error}</span>}
          {authError && authError !== 'Access denied.' && (
            <span className="text-red-400 ml-2">· {authError}</span>
          )}
        </div>

        <div className="overflow-x-auto border border-zinc-800 rounded-lg">
          <table className="w-full text-xs">
            <thead className="bg-zinc-900/70 text-zinc-400">
              <tr>
                <th className="text-left px-3 py-2">Time</th>
                <th className="text-left px-3 py-2">Event</th>
                <th className="text-left px-3 py-2">Path</th>
                <th className="text-left px-3 py-2">Scanned URL</th>
                <th className="text-left px-3 py-2">Outcome</th>
                <th className="text-right px-3 py-2">Score</th>
                <th className="text-left px-3 py-2">WAF</th>
                <th className="text-left px-3 py-2">IP hash</th>
                <th className="text-left px-3 py-2">UA</th>
                <th className="text-left px-3 py-2">Meta</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((r) => (
                <tr key={r.id} className="border-t border-zinc-800 hover:bg-zinc-900/40">
                  <td className="px-3 py-2 whitespace-nowrap text-zinc-400">{fmt(r.created_at)}</td>
                  <td className="px-3 py-2 font-mono">{r.event_type}</td>
                  <td className="px-3 py-2 text-zinc-400">{r.path ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-300 max-w-[280px] truncate" title={r.scanned_url ?? ''}>
                    {r.scanned_url ?? '—'}
                  </td>
                  <td className="px-3 py-2 text-zinc-400">{r.scan_outcome ?? '—'}</td>
                  <td className="px-3 py-2 text-right text-zinc-300">{r.vibe_score ?? '—'}</td>
                  <td className="px-3 py-2 text-zinc-400">{r.waf_vendor ?? '—'}</td>
                  <td className="px-3 py-2 font-mono text-zinc-500">{shortHash(r.ip_hash)}</td>
                  <td className="px-3 py-2 text-zinc-500" title={r.user_agent ?? ''}>
                    {shortUa(r.user_agent)}
                  </td>
                  <td className="px-3 py-2 text-zinc-500 max-w-[200px] truncate" title={JSON.stringify(r.metadata)}>
                    {r.metadata && Object.keys(r.metadata).length > 0
                      ? JSON.stringify(r.metadata)
                      : '—'}
                  </td>
                </tr>
              ))}
              {!loading && logs.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-3 py-6 text-center text-zinc-500">
                    No matching logs.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
