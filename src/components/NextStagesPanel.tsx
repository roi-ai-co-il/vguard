import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, ShieldCheck, Lock, Check, Copy, RefreshCw, X, ArrowRight, Loader2, Sparkles } from 'lucide-react'
import type { ScanResult } from '@/lib/scanner-types'

interface NextStagesPanelProps {
  scannedUrl: string
  /** Stage 2 auto-cascade status from the parent ScanForm. */
  stage2Status?: 'idle' | 'running' | 'done' | 'failed' | 'unavailable'
  /** Number of actionable Stage 2 findings (excludes 'ok'). */
  stage2FindingCount?: number
  /** True after a verified Stage 3 deep scan completes. */
  stage3Done?: boolean
  onDeepScanComplete?: (result: ScanResult) => void
}

interface ServerScanFinding {
  id: string
  severity: string
  category: string
  title: string
  description: string
  evidence: string
  fixPrompt: string
}

export function NextStagesPanel({ scannedUrl, stage2Status, stage2FindingCount, stage3Done, onDeepScanComplete }: NextStagesPanelProps) {
  const [stage2Open, setStage2Open] = useState(false)
  const [stage3Open, setStage3Open] = useState(false)

  let domain = ''
  try {
    domain = new URL(scannedUrl).hostname
  } catch {
    domain = scannedUrl
  }

  const stage2Badge = (() => {
    switch (stage2Status) {
      case 'done': return { text: `done · ${stage2FindingCount ?? 0} runtime finding${stage2FindingCount === 1 ? '' : 's'}`, tone: 'ok' as const }
      case 'running': return { text: 'running…', tone: 'warn' as const }
      case 'failed': return { text: 'worker error', tone: 'warn' as const }
      case 'unavailable': return { text: 'use bookmarklet', tone: 'muted' as const }
      default: return { text: 'auto', tone: 'muted' as const }
    }
  })()
  const stage2BadgeClass = stage2Badge.tone === 'ok'
    ? 'border-(--color-accent) text-(--color-accent)'
    : stage2Badge.tone === 'warn'
      ? 'border-(--color-warning) text-(--color-warning)'
      : 'border-(--color-border-strong) text-(--color-fg-dim)'

  return (
    <>
      <div className="mt-8">
        <div className="flex items-center gap-2 mb-3">
          <span className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim)">
            Want a deeper scan?
          </span>
          <span className="font-mono text-[10px] text-(--color-fg-dim)">·</span>
          <span className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-muted)">
            Stage 1 ✓ &nbsp; Stage 2 auto &nbsp; Stage 3 unlock
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Stage 2 card — informational, since it ran automatically */}
          <button
            type="button"
            onClick={() => setStage2Open(true)}
            className="text-left rounded-xl border border-(--color-border) hover:border-(--color-accent-border) bg-(--color-surface) hover:bg-(--color-surface-elevated) transition-colors p-5 cursor-pointer group"
          >
            <div className="flex items-start gap-3">
              <span className="flex items-center justify-center w-9 h-9 rounded-md flex-shrink-0 bg-(--color-accent-muted) text-(--color-accent)">
                <Globe size={17} strokeWidth={2} aria-hidden="true" />
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-mono text-[10px] tracking-widest uppercase text-(--color-accent)">
                    Stage 2
                  </span>
                  <span className={`font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border ${stage2BadgeClass}`}>
                    {stage2Badge.text}
                  </span>
                </div>
                <h4 className="text-sm sm:text-base font-semibold text-(--color-fg) leading-snug">
                  Browser-Assisted Scan
                </h4>
                <p className="mt-1.5 text-sm text-(--color-fg-muted) leading-relaxed">
                  {stage2Status === 'done'
                    ? 'A real headless browser ran your site to catch what only happens at runtime — cookies without HttpOnly, auth tokens in localStorage, runtime-only API calls. Findings already merged above.'
                    : stage2Status === 'unavailable'
                      ? 'Server-side worker isn\'t configured on this deployment. Tap to use the bookmarklet flow on your own browser instead.'
                      : 'Runs automatically after Stage 1. Catches what only loads at runtime — async APIs, anon keys, window globals, client-set cookies.'}
                </p>
                <div className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-(--color-accent) opacity-0 group-hover:opacity-100 transition-opacity">
                  Learn more / use bookmarklet
                  <ArrowRight size={12} aria-hidden="true" />
                </div>
              </div>
            </div>
          </button>

          {/* Stage 3 card — the real next step, prominent */}
          <button
            type="button"
            onClick={() => setStage3Open(true)}
            className={`text-left rounded-xl border-2 transition-colors p-5 cursor-pointer group ${stage3Done ? 'border-(--color-accent) bg-(--color-surface)' : 'border-(--color-warning) bg-(--color-surface) hover:bg-(--color-surface-elevated) shadow-[0_0_30px_-12px_rgba(251,191,36,0.4)]'}`}
          >
            <div className="flex items-start gap-3">
              <span className={`flex items-center justify-center w-9 h-9 rounded-md flex-shrink-0 ${stage3Done ? 'bg-(--color-accent-muted) text-(--color-accent)' : 'bg-(--color-warning) text-(--color-bg)'}`}>
                {stage3Done ? <Check size={17} strokeWidth={2.5} aria-hidden="true" /> : <Lock size={17} strokeWidth={2} aria-hidden="true" />}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className={`font-mono text-[10px] tracking-widest uppercase ${stage3Done ? 'text-(--color-accent)' : 'text-(--color-warning)'}`}>
                    Stage 3 — {stage3Done ? 'unlocked' : 'next step'}
                  </span>
                  {!stage3Done && (
                    <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border border-(--color-warning) text-(--color-warning)">
                      verify to unlock
                    </span>
                  )}
                </div>
                <h4 className="text-sm sm:text-base font-semibold text-(--color-fg) leading-snug">
                  {stage3Done ? 'Verified Deep Scan complete' : 'Unlock active probes — Verified Deep Scan'}
                </h4>
                <p className="mt-1.5 text-sm text-(--color-fg-muted) leading-relaxed">
                  {stage3Done
                    ? `Active probes ran against ${domain}. Findings merged into the report above.`
                    : (
                      <>
                        Prove you own <span className="font-mono">{domain}</span> in 30 seconds (DNS, file, or Vercel token). Unlocks <strong>active probing</strong>: real Supabase RLS testing, storage write-probes, aggressive XSS/SQLi payloads, AI prompt-injection canaries. Stage 1+2 only check what's <em>visible</em>; Stage 3 checks what's <em>exploitable</em>.
                      </>
                    )}
                </p>
                {!stage3Done && (
                  <div className="mt-3 inline-flex items-center gap-1.5 font-mono text-xs text-(--color-warning) font-bold">
                    Start ownership verification
                    <ArrowRight size={12} strokeWidth={2.5} aria-hidden="true" />
                  </div>
                )}
              </div>
            </div>
          </button>
        </div>
      </div>

      <Stage2Modal open={stage2Open} onClose={() => setStage2Open(false)} />
      <Stage3Modal
        open={stage3Open}
        onClose={() => setStage3Open(false)}
        domain={domain}
        scannedUrl={scannedUrl}
        onDeepScanComplete={onDeepScanComplete}
      />
    </>
  )
}

function ModalShell({
  open,
  onClose,
  children,
}: {
  open: boolean
  onClose: () => void
  children: React.ReactNode
}) {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="backdrop"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="fixed inset-0 z-50 flex items-center justify-center px-4 py-8 bg-(--color-bg)/85 backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.div
            key="dialog"
            initial={{ opacity: 0, y: 8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.98 }}
            transition={{ duration: 0.25 }}
            className="relative w-full max-w-xl rounded-xl bg-(--color-surface) border border-(--color-accent-border) shadow-[0_0_60px_-12px_rgba(34,211,238,0.4)] overflow-hidden max-h-[85vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="absolute top-3 right-3 p-1.5 rounded-md text-(--color-fg-dim) hover:text-(--color-fg) hover:bg-(--color-surface-elevated) transition-colors cursor-pointer"
            >
              <X size={16} strokeWidth={2} />
            </button>
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

interface Stage2Finding {
  id: string
  severity: string
  category: string
  title: string
  description: string
  evidence: string
  fixPrompt: string
}

interface Stage2ResultsResponse {
  ok: boolean
  ready?: boolean
  url?: string
  collectedAt?: string
  findings?: Stage2Finding[]
  error?: string
}

function buildBookmarkletSource(uuid: string, collectorOrigin: string): string {
  // Compact JS — single statement so it can live in a javascript: URL.
  // Collector hits /api/stage2-collect with the user's bookmarklet UUID.
  return [
    `(()=>{`,
    `try{`,
    `var u='${uuid}';`,
    `var ck=document.cookie.split(';').map(function(c){return c.split('=')[0].trim()}).filter(Boolean);`,
    `var lk=Object.keys(localStorage||{});`,
    `var sk=Object.keys(sessionStorage||{});`,
    `var w=window;`,
    `var g={hasSupabase:typeof w.supabase!=='undefined',hasFirebase:typeof w.firebase!=='undefined',hasFirebaseConfig:typeof w.firebaseConfig!=='undefined',hasAppConfig:typeof w.__APP_CONFIG!=='undefined'||typeof w.__NEXT_DATA__!=='undefined',hasReactRoot:!!document.getElementById('root')};`,
    `var p=performance.getEntriesByType('resource').map(function(e){return e.name}).slice(0,80);`,
    `var data={uuid:u,url:location.href,cookieKeys:ck,localStorageKeys:lk,sessionStorageKeys:sk,globals:g,performanceUrls:p,userAgent:navigator.userAgent};`,
    `fetch('${collectorOrigin}/api/stage2-collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(function(r){return r.json()}).then(function(j){alert('Vguard Stage 2: data sent. Return to the scanner tab.')}).catch(function(e){alert('Vguard error: '+e.message)});`,
    `}catch(e){alert('Vguard error: '+e.message)}`,
    `})()`,
  ].join('')
}

function Stage2Modal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [uuid] = useState(() => `vs2-${generateUuid()}`)
  const [copied, setCopied] = useState(false)
  const [pollState, setPollState] = useState<'idle' | 'waiting' | 'ready' | 'error'>('idle')
  const [findings, setFindings] = useState<Stage2Finding[]>([])
  const [errorMsg, setErrorMsg] = useState('')
  const [serverScanState, setServerScanState] = useState<'idle' | 'running' | 'done' | 'error'>('idle')
  const [serverFindings, setServerFindings] = useState<ServerScanFinding[]>([])
  const [serverScanUrl, setServerScanUrl] = useState('')
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const collectorOrigin =
    typeof window !== 'undefined' ? window.location.origin : 'https://vibesecure-tau.vercel.app'
  const bookmarkletSrc = buildBookmarkletSource(uuid, collectorOrigin)
  const bookmarkletHref = `javascript:${encodeURIComponent(bookmarkletSrc)}`

  useEffect(() => {
    if (!open) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
      pollTimerRef.current = null
      return
    }
    setPollState('waiting')
    pollTimerRef.current = setInterval(async () => {
      try {
        const r = await fetch(`/api/stage2-results?uuid=${encodeURIComponent(uuid)}`)
        const data = (await r.json()) as Stage2ResultsResponse
        if (data.ready && data.findings) {
          setFindings(data.findings)
          setPollState('ready')
          if (pollTimerRef.current) clearInterval(pollTimerRef.current)
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'poll failed'
        setErrorMsg(msg)
      }
    }, 3000)
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
    }
  }, [open, uuid])

  async function runServerSideScan() {
    setServerScanState('running')
    setServerFindings([])
    try {
      const r = await fetch('/api/scan-browser-assisted', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: serverScanUrl || (typeof window !== 'undefined' ? window.location.href : '') }),
      })
      const data = (await r.json()) as
        | {
            ok: true
            url: string
            finalUrl: string
            cookies: { name: string; httpOnly: boolean; secure: boolean; sameSite: string | undefined; domain: string }[]
            localStorageKeys: string[]
            windowGlobals: Record<string, boolean>
            networkRequests: { url: string }[]
            durationMs: number
          }
        | { ok: false; error: { message: string } | string }
      if (!('ok' in data) || !data.ok) {
        setServerScanState('error')
        const msg =
          'error' in data
            ? typeof data.error === 'string'
              ? data.error
              : data.error.message
            : 'Server-side scan failed'
        setErrorMsg(msg)
        return
      }
      // Synthesize findings from collected data
      const out: ServerScanFinding[] = []
      const sensitiveCookies = data.cookies.filter(
        (c) => /sess|auth|token|jwt|sid|csrf|access/i.test(c.name) && !c.httpOnly,
      )
      if (sensitiveCookies.length > 0) {
        out.push({
          id: 'serverscan-cookie-not-httponly',
          severity: 'warn',
          category: 'cookies',
          title: `${sensitiveCookies.length} sensitive cookie(s) without HttpOnly`,
          description: `Playwright captured cookies from your live site. ${sensitiveCookies.length} have session/auth-pattern names but no HttpOnly flag — readable from JS, exfiltrable via XSS.`,
          evidence: sensitiveCookies.map((c) => `${c.name}: HttpOnly=${c.httpOnly} Secure=${c.secure} SameSite=${c.sameSite ?? '?'}`).join('\n'),
          fixPrompt: `Set HttpOnly on every session/auth cookie. Express: res.cookie(name, value, { httpOnly: true, secure: true, sameSite: 'lax' }). Supabase/NextAuth: configure in cookie options.`,
        })
      }
      const lsAuthKeys = data.localStorageKeys.filter((k) =>
        /sb-.*-auth-token|supabase\.auth\.token|firebase:authUser|access_token|refresh_token/i.test(k),
      )
      if (lsAuthKeys.length > 0) {
        out.push({
          id: 'serverscan-localstorage-auth',
          severity: 'warn',
          category: 'cookies',
          title: 'Auth tokens stored in localStorage',
          description: `Headless browser found ${lsAuthKeys.length} auth-token-style keys in localStorage. Any XSS reads them.`,
          evidence: lsAuthKeys.slice(0, 5).join('\n'),
          fixPrompt: `Move auth tokens to HttpOnly cookies. For Supabase use @supabase/ssr server-side session pattern. For Firebase use session cookies.`,
        })
      }
      const exposedGlobals = Object.entries(data.windowGlobals).filter(([, v]) => v).map(([k]) => k)
      if (exposedGlobals.includes('hasFirebaseConfig')) {
        out.push({
          id: 'serverscan-firebase-global',
          severity: 'info',
          category: 'meta',
          title: 'window.firebaseConfig exposed',
          description: 'Headless browser detected Firebase config attached to window. While public per Firebase design, exposing on window globals lets any 3rd-party script trivially dump it.',
          evidence: 'window.firebaseConfig is defined',
          fixPrompt: 'Initialize Firebase in module scope, not on window. Enable Firebase App Check.',
        })
      }
      if (data.networkRequests.length > 0) {
        const externalApis = data.networkRequests
          .map((n) => n.url)
          .filter((u) =>
            /supabase\.co\/(rest|auth|storage|functions)|firebaseapp\.com|googleapis\.com|api\.openai\.com|api\.anthropic\.com/i.test(
              u,
            ),
          )
        if (externalApis.length > 0) {
          out.push({
            id: 'serverscan-external-apis',
            severity: 'info',
            category: 'meta',
            title: `${externalApis.length} runtime API call(s) detected`,
            description: 'Real browser confirmed runtime hits to external APIs. Useful for CSP connect-src auditing.',
            evidence: Array.from(new Set(externalApis)).slice(0, 6).join('\n'),
            fixPrompt: 'Audit connect-src against this list. Hosts seen at runtime should be allowed; allowlisted hosts not seen at runtime are tech debt.',
          })
        }
      }
      if (out.length === 0) {
        out.push({
          id: 'serverscan-clean',
          severity: 'ok',
          category: 'meta',
          title: 'Server-side browser scan completed clean',
          description: `Loaded ${data.finalUrl} in headless Chromium for ${data.durationMs}ms. No HttpOnly-bypassed cookies, no auth tokens in localStorage, no exposed config globals.`,
          evidence: `${data.networkRequests.length} requests captured, ${data.cookies.length} cookies, ${data.localStorageKeys.length} localStorage keys.`,
          fixPrompt: '',
        })
      }
      setServerFindings(out)
      setServerScanState('done')
    } catch (e) {
      setServerScanState('error')
      const msg = e instanceof Error ? e.message : 'Network error'
      setErrorMsg(msg)
    }
  }

  async function copyBookmarklet() {
    let ok = false
    try {
      await navigator.clipboard.writeText(bookmarkletHref)
      ok = true
    } catch {
      const ta = document.createElement('textarea')
      ta.value = bookmarkletHref
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try {
        ok = document.execCommand('copy')
      } catch {
        ok = false
      }
      document.body.removeChild(ta)
    }
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    }
  }

  return (
    <ModalShell open={open} onClose={onClose}>
      <div className="p-6 sm:p-8">
        <div className="flex items-center gap-2 font-mono text-[10px] tracking-widest uppercase text-(--color-accent) mb-3">
          <Globe size={12} strokeWidth={2.5} aria-hidden="true" />
          Stage 2 — Browser-Assisted Scan
        </div>
        <h3 className="text-xl sm:text-2xl font-semibold tracking-tight">
          Let your own browser do the looking.
        </h3>
        <p className="mt-3 text-sm text-(--color-fg-muted) leading-relaxed">
          Stage 1 looked at your site from outside. Stage 2 runs a tiny snippet INSIDE your browser, on YOUR site's origin, and reports back what only the browser can see: cookies visible to JS, localStorage keys, runtime API calls, exposed globals.
        </p>

        <div className="mt-5 mb-5 rounded-md border border-(--color-accent-border) bg-(--color-accent-muted) px-4 py-3">
          <div className="flex items-center gap-2 font-mono text-[10px] tracking-widest uppercase text-(--color-accent) mb-2">
            <Globe size={12} strokeWidth={2.5} aria-hidden="true" />
            Quick path — server-side browser scan
          </div>
          <p className="text-xs text-(--color-fg-muted) mb-3 leading-relaxed">
            Skip the bookmarklet. We run your URL in our headless Chromium and report what the browser saw. Works for public pages and any URL you'd open without logging in.
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            <input
              type="url"
              value={serverScanUrl}
              onChange={(e) => setServerScanUrl(e.target.value)}
              placeholder={typeof window !== 'undefined' ? window.location.origin : 'https://your-app.com'}
              className="flex-1 min-w-0 px-3 py-2 rounded-md bg-(--color-surface) border border-(--color-border) focus:border-(--color-accent-border) text-(--color-fg) placeholder:text-(--color-fg-dim) font-mono text-xs focus:outline-none transition-colors"
            />
            <button
              type="button"
              onClick={runServerSideScan}
              disabled={serverScanState === 'running'}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {serverScanState === 'running' ? (
                <>
                  <Loader2 size={13} className="animate-spin" strokeWidth={2.5} />
                  Scanning…
                </>
              ) : (
                <>
                  <Globe size={13} strokeWidth={2.5} />
                  Scan with Chromium
                </>
              )}
            </button>
          </div>
          {serverScanState === 'done' && serverFindings.length > 0 && (
            <ul className="mt-3 space-y-2">
              {serverFindings.map((f) => (
                <li
                  key={f.id}
                  className="rounded-md bg-(--color-bg) border border-(--color-border) px-3 py-2"
                >
                  <div className="flex items-center gap-2 mb-0.5 font-mono text-[10px] tracking-widest uppercase">
                    <span
                      className="px-1.5 py-0.5 rounded border"
                      style={{
                        color:
                          f.severity === 'critical'
                            ? 'var(--color-danger)'
                            : f.severity === 'warn'
                              ? 'var(--color-warning)'
                              : f.severity === 'ok'
                                ? 'var(--color-ok)'
                                : 'var(--color-fg-muted)',
                        borderColor:
                          f.severity === 'critical'
                            ? 'var(--color-danger)'
                            : f.severity === 'warn'
                              ? 'var(--color-warning)'
                              : f.severity === 'ok'
                                ? 'var(--color-ok)'
                                : 'var(--color-border)',
                      }}
                    >
                      {f.severity === 'info' ? 'improve' : f.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-(--color-fg) leading-snug">{f.title}</h4>
                  <p className="mt-1 text-xs text-(--color-fg-muted) leading-relaxed">{f.description}</p>
                </li>
              ))}
            </ul>
          )}
          {serverScanState === 'error' && (
            <p className="mt-2 text-xs text-(--color-warning) font-mono">{errorMsg}</p>
          )}
        </div>

        <div className="mb-3 font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim)">
          ── or — slower path: bookmarklet (works on logged-in / private pages)
        </div>

        <div className="space-y-4">
          <div>
            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-1.5">
              Step 1 — drag this to your bookmarks bar
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <a
                href={bookmarkletHref}
                onClick={(e) => e.preventDefault()}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold cursor-grab active:cursor-grabbing select-none"
                draggable
                title="Drag this to your bookmarks bar, then click it on your own site"
              >
                <ShieldCheck size={13} strokeWidth={2.5} />
                Vguard scan
              </a>
              <button
                type="button"
                onClick={copyBookmarklet}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
              >
                {copied ? (
                  <>
                    <Check size={13} className="text-(--color-accent)" strokeWidth={2.5} aria-hidden="true" />
                    Copied JS
                  </>
                ) : (
                  <>
                    <Copy size={13} aria-hidden="true" />
                    Copy as JS
                  </>
                )}
              </button>
            </div>
            <p className="mt-2 font-mono text-[11px] text-(--color-fg-dim) leading-relaxed">
              The button above contains your unique scan UUID embedded as a "javascript:" bookmarklet. Drag it to your bookmarks bar (or copy the JS and paste into a new bookmark).
            </p>
          </div>

          <div>
            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-1.5">
              Step 2 — open your site, click the bookmark
            </div>
            <p className="text-sm text-(--color-fg-muted) leading-relaxed">
              Visit your app in a new tab — log in if you usually do. Then click the Vguard bookmark. The snippet will collect runtime data and POST it back to us. You'll see an alert when it's done.
            </p>
          </div>

          <div>
            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-1.5">
              Step 3 — come back here
            </div>
            <p className="text-sm text-(--color-fg-muted) leading-relaxed">
              We'll detect the data and show findings below automatically.
            </p>
          </div>
        </div>

        <div className="mt-6">
          {pollState === 'waiting' && (
            <div className="rounded-md bg-(--color-bg) border border-(--color-accent-border) px-4 py-3 flex items-center gap-2">
              <Loader2 size={14} className="text-(--color-accent) animate-spin" strokeWidth={2.5} aria-hidden="true" />
              <span className="font-mono text-xs text-(--color-fg-muted)">
                Waiting for bookmarklet to fire on your site…
              </span>
            </div>
          )}

          {pollState === 'ready' && findings.length > 0 && (
            <div>
              <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-ok) mb-2 flex items-center gap-1.5">
                <Check size={12} strokeWidth={3} aria-hidden="true" />
                Browser scan complete · {findings.length} finding{findings.length === 1 ? '' : 's'}
              </div>
              <ul className="space-y-3">
                {findings.map((f) => (
                  <li
                    key={f.id}
                    className="rounded-md bg-(--color-bg) border border-(--color-border) px-4 py-3"
                  >
                    <div className="flex items-center gap-2 mb-1 font-mono text-[10px] tracking-widest uppercase">
                      <span
                        className="px-2 py-0.5 rounded border"
                        style={{
                          color:
                            f.severity === 'critical'
                              ? 'var(--color-danger)'
                              : f.severity === 'warn'
                                ? 'var(--color-warning)'
                                : f.severity === 'ok'
                                  ? 'var(--color-ok)'
                                  : 'var(--color-fg-muted)',
                          borderColor:
                            f.severity === 'critical'
                              ? 'var(--color-danger)'
                              : f.severity === 'warn'
                                ? 'var(--color-warning)'
                                : f.severity === 'ok'
                                  ? 'var(--color-ok)'
                                  : 'var(--color-border)',
                        }}
                      >
                        {f.severity}
                      </span>
                      <span className="text-(--color-fg-dim)">{f.category}</span>
                    </div>
                    <h4 className="text-sm font-semibold text-(--color-fg) leading-snug">
                      {f.title}
                    </h4>
                    <p className="mt-1 text-sm text-(--color-fg-muted) leading-relaxed">
                      {f.description}
                    </p>
                    {f.evidence && (
                      <div className="mt-2 font-mono text-[11px] text-(--color-fg-dim) bg-(--color-surface) border border-(--color-border) rounded px-2 py-1.5 overflow-x-auto whitespace-pre-wrap break-all">
                        {f.evidence}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {errorMsg && (
            <div className="mt-3 font-mono text-xs text-(--color-warning)">{errorMsg}</div>
          )}
        </div>

        <p className="mt-5 text-xs text-(--color-fg-dim) leading-relaxed">
          We do NOT collect cookie values, localStorage values, or any HTML body. Only key NAMES (so we can flag if a session cookie has no HttpOnly), URLs the page hit (so we can audit CSP connect-src), and which globals exist (yes/no). The full list of what we send is visible in the bookmarklet source — it's just JavaScript you can read.
        </p>

        <div className="mt-6 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg-muted) hover:text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
          >
            Done
          </button>
        </div>
      </div>
    </ModalShell>
  )
}

type VerifyMethod = 'file' | 'dns' | 'vercel'

interface VerifyApiResponse {
  ok: boolean
  verified?: boolean
  method?: VerifyMethod
  error?: string
  hint?: string
}

function generateUuid(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  // Fallback
  return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
}

interface FreeTierProvider {
  name: string
  /** Short, one-line instructions for the file-upload path on this provider. */
  fileHint: string
  /** True if Vercel personal-access-token verification is meaningful here. */
  vercelTokenWorks: boolean
}

/**
 * Generate a paste-ready prompt for any AI coding agent (Cursor, Claude Code,
 * Codex, Lovable, Bolt, Replit, etc.) to perform the file-challenge ownership
 * verification on the user's behalf. Tool-agnostic: the agent reads it cold
 * and executes — create file, commit, push, curl-verify.
 */
function buildFileVerifyAiPrompt(domain: string, uuid: string, providerName: string | null): string {
  return [
    `# 🛡️ Vguard — Ownership verification task`,
    ``,
    `I'm using Vguard to run a security deep-scan on **${domain}**. To prove I own this site, I need you to drop a verification file at \`/.well-known/Vguard-verify.txt\` and redeploy.`,
    ``,
    `## What to do`,
    ``,
    `1. **Create the file** at one of these paths (whichever matches this project's framework — check the existing folders):`,
    `   - \`public/.well-known/Vguard-verify.txt\` — Next.js, Vite, CRA, React`,
    `   - \`static/.well-known/Vguard-verify.txt\` — SvelteKit`,
    `   - \`.well-known/Vguard-verify.txt\` (project root) — Astro, plain HTML`,
    ``,
    `2. **The file content must be EXACTLY this UUID** — plain text, no quotes, no JSON, no newline-padding, no headers:`,
    ``,
    '   ```',
    `   ${uuid}`,
    '   ```',
    ``,
    `3. **Commit and push** to the branch that auto-deploys to production:`,
    `   \`\`\``,
    `   git add <the-file-path>`,
    `   git commit -m "Add Vguard ownership-verification token"`,
    `   git push`,
    `   \`\`\``,
    ``,
    `4. **Wait ~30 seconds** for the deploy to finish (Vercel/Netlify/Cloudflare Pages auto-deploy from main).`,
    ``,
    `5. **Confirm it's live** by curling — should print exactly the UUID, nothing else:`,
    `   \`\`\``,
    `   curl -s https://${domain}/.well-known/Vguard-verify.txt`,
    `   \`\`\``,
    ``,
    `## Then`,
    ``,
    `Tell me when the curl returns the UUID, and I'll click "Verify now" in Vguard to start the deep scan.`,
    ``,
    `## After Stage 3 finishes (optional cleanup)`,
    ``,
    `The file is harmless to leave in production — it's a random UUID, contains no secrets. But if you want to clean up afterwards:`,
    `\`\`\``,
    `git rm <the-file-path>`,
    `git commit -m "Remove Vguard verification token"`,
    `git push`,
    `\`\`\``,
    ``,
    `## Constraints`,
    ``,
    `- Don't add any other content to the file (no JSON wrapping, no Markdown, no leading/trailing whitespace).`,
    `- Don't create the file inside \`src/\` — it must end up at the URL path \`/.well-known/Vguard-verify.txt\` after build.`,
    `- ${providerName ? `This project deploys to **${providerName}** — push the commit and the deploy is automatic.` : `If your hosting requires a manual deploy step, run that after pushing.`}`,
  ].join('\n')
}

/**
 * AI prompt for DNS verification — has a hard caveat: most AI agents can't
 * change DNS records unless they have CLI/API access to the user's DNS
 * provider. Useful for projects with Cloudflare wrangler / Vercel CLI in scope.
 */
function buildDnsVerifyAiPrompt(baseDomain: string, uuid: string): string {
  return [
    `# 🛡️ Vguard — DNS ownership verification task`,
    ``,
    `I'm using Vguard to run a security deep-scan on **${baseDomain}**. To prove I own this domain, I need a DNS TXT record added.`,
    ``,
    `## The record`,
    `\`\`\``,
    `Type:  TXT`,
    `Name:  _Vguard-verify.${baseDomain}`,
    `Value: ${uuid}`,
    `TTL:   300 (or your provider's default)`,
    `\`\`\``,
    ``,
    `## How to add it`,
    ``,
    `**If this project has Cloudflare wrangler or DNS API credentials:** add the record via API/CLI. Examples:`,
    ``,
    `\`\`\`bash`,
    `# Cloudflare (needs CLOUDFLARE_API_TOKEN with Zone:DNS:Edit)`,
    `curl -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records" \\`,
    `  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"type":"TXT","name":"_Vguard-verify.${baseDomain}","content":"${uuid}","ttl":300}'`,
    ``,
    `# Vercel (if Vercel manages this domain's DNS, needs VERCEL_TOKEN)`,
    `curl -X POST "https://api.vercel.com/v2/domains/${baseDomain}/records" \\`,
    `  -H "Authorization: Bearer $VERCEL_TOKEN" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"type":"TXT","name":"_Vguard-verify","value":"${uuid}","ttl":300}'`,
    `\`\`\``,
    ``,
    `**If you don't have DNS API access in this project,** stop and tell me — I'll add it manually at my DNS provider's dashboard (Cloudflare, Namecheap, GoDaddy, Vercel DNS, etc.).`,
    ``,
    `## After adding`,
    ``,
    `Verify propagation:`,
    `\`\`\``,
    `dig +short TXT _Vguard-verify.${baseDomain}`,
    `\`\`\``,
    `Should return: \`"${uuid}"\` (with quotes — that's normal for TXT records).`,
    ``,
    `Propagation can take 30 seconds to 5 minutes. Tell me when dig returns the value, and I'll click "Verify now" in Vguard.`,
  ].join('\n')
}

/**
 * Detect well-known free-tier hosting providers where the user does NOT own
 * the parent domain. For these, DNS verification cannot work — file upload is
 * the right default, and we surface platform-specific upload instructions.
 */
function detectFreeTierProvider(domain: string): FreeTierProvider | null {
  const d = domain.toLowerCase()
  if (/\.vercel\.app$/.test(d)) {
    return {
      name: 'Vercel',
      fileHint: 'Add the file to your project\'s public/ folder, commit, and push — Vercel auto-deploys it on the next build.',
      vercelTokenWorks: true,
    }
  }
  if (/\.netlify\.app$/.test(d)) {
    return {
      name: 'Netlify',
      fileHint: 'Add the file to your project\'s public/ (or static/) folder, commit, push — Netlify rebuilds and serves it.',
      vercelTokenWorks: false,
    }
  }
  if (/\.pages\.dev$/.test(d)) {
    return {
      name: 'Cloudflare Pages',
      fileHint: 'Add the file to your project\'s public/ (or static/) folder, commit, push — Cloudflare Pages auto-deploys.',
      vercelTokenWorks: false,
    }
  }
  if (/\.lovable\.(app|dev)$/.test(d)) {
    return {
      name: 'Lovable',
      fileHint: 'In Lovable: open the file tree → public/ → add a new file named .well-known/Vguard-verify.txt with the UUID inside → click Publish.',
      vercelTokenWorks: false,
    }
  }
  if (/\.bolt\.(host|new)$/.test(d)) {
    return {
      name: 'Bolt',
      fileHint: 'In Bolt: ask the AI to "create a static file at public/.well-known/Vguard-verify.txt with content: <UUID>" then redeploy.',
      vercelTokenWorks: false,
    }
  }
  if (/\.replit\.(app|dev)$/.test(d)) {
    return {
      name: 'Replit',
      fileHint: 'In Replit: create the file at public/.well-known/Vguard-verify.txt with the UUID inside, then redeploy.',
      vercelTokenWorks: false,
    }
  }
  if (/\.fly\.dev$/.test(d)) {
    return {
      name: 'Fly.io',
      fileHint: 'Add the file to your static-files directory served by your app, then `fly deploy`.',
      vercelTokenWorks: false,
    }
  }
  if (/\.(ngrok-free\.app|ngrok\.app|ngrok\.io|loca\.lt|trycloudflare\.com)$/.test(d)) {
    return {
      name: 'tunnel',
      fileHint: 'You\'re scanning through a tunnel. Drop .well-known/Vguard-verify.txt into your local public/ folder — the tunnel forwards to it automatically.',
      vercelTokenWorks: false,
    }
  }
  if (/\.webflow\.io$/.test(d)) {
    return {
      name: 'Webflow',
      fileHint: 'Webflow doesn\'t expose .well-known easily. The cleanest path is buying a domain ($10/yr) and using DNS verification instead.',
      vercelTokenWorks: false,
    }
  }
  if (/\.wixsite\.com$/.test(d)) {
    return {
      name: 'Wix',
      fileHint: 'Wix subdomains don\'t allow custom .well-known files. To run Stage 3 here, connect a custom domain in Wix settings (~$10/yr) and use DNY verification.',
      vercelTokenWorks: false,
    }
  }
  return null
}

function Stage3Modal({
  open,
  onClose,
  domain,
  scannedUrl,
  onDeepScanComplete,
}: {
  open: boolean
  onClose: () => void
  domain: string
  scannedUrl: string
  onDeepScanComplete?: (result: ScanResult) => void
}) {
  const [uuid] = useState(() => `vs-${generateUuid()}`)
  // Detect free-tier hosting subdomains — for these, the user does NOT own the
  // parent domain, so DNS verification can't work. File upload is the right path.
  const freeTier = detectFreeTierProvider(domain)
  // Default method: File for free subdomains (DNS won't work for them), DNS otherwise.
  const [method, setMethod] = useState<VerifyMethod>(freeTier ? 'file' : 'dns')
  const [status, setStatus] = useState<
    'idle' | 'checking' | 'verified' | 'failed' | 'scanning' | 'done'
  >('idle')
  const [hint, setHint] = useState('')
  const [copied, setCopied] = useState<'uuid' | 'cmd' | 'ai' | null>(null)
  const [deepFindingsCount, setDeepFindingsCount] = useState(0)
  const [userJwt, setUserJwt] = useState('')
  const [authMode, setAuthMode] = useState(false)
  const [vercelToken, setVercelToken] = useState('')
  // Vercel-token method is hidden behind an "Advanced" disclosure — pasting a
  // PAT into a 3rd-party scanner is a real trust ask, not for every user.
  const [showAdvanced, setShowAdvanced] = useState(false)

  async function copyToClipboard(text: string, what: 'uuid' | 'cmd' | 'ai') {
    let ok = false
    try {
      await navigator.clipboard.writeText(text)
      ok = true
    } catch {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try {
        ok = document.execCommand('copy')
      } catch {
        ok = false
      }
      document.body.removeChild(ta)
    }
    if (ok) {
      setCopied(what)
      setTimeout(() => setCopied(null), 1800)
    }
  }

  async function verifyNow() {
    setStatus('checking')
    setHint('')
    try {
      let data: VerifyApiResponse
      if (method === 'vercel') {
        if (!vercelToken || vercelToken.length < 20) {
          setStatus('failed')
          setHint('Paste a Vercel personal access token from vercel.com/account/tokens')
          return
        }
        const r = await fetch('/api/verify-vercel-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, uuid, vercelToken }),
        })
        data = (await r.json()) as VerifyApiResponse
      } else {
        const r = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, uuid, method }),
        })
        data = (await r.json()) as VerifyApiResponse
      }
      if (data.verified) {
        setStatus('verified')
        // Auto-trigger deep scan
        setTimeout(() => runDeepScan(), 600)
      } else {
        setStatus('failed')
        setHint(data.hint ?? data.error ?? 'Could not verify ownership.')
      }
    } catch (e) {
      setStatus('failed')
      const msg = e instanceof Error ? e.message : 'Network error'
      setHint(msg)
    }
  }

  async function runDeepScan() {
    setStatus('scanning')
    setHint('')
    try {
      const r = await fetch('/api/scan-deep', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: scannedUrl,
          uuid,
          // 'vercel' verification was recorded under 'oauth' in the cache
          method: method === 'vercel' ? 'oauth' : method,
          userJwt: authMode && userJwt ? userJwt : undefined,
        }),
      })
      const data = (await r.json()) as ScanResult | { ok: false; error: { message: string } }
      if ('ok' in data && data.ok === false) {
        setStatus('failed')
        setHint(data.error.message ?? 'Deep scan failed.')
        return
      }
      const result = data as ScanResult
      // Count NEW findings (Stage 3 deep findings have IDs starting with auth-rls or paths-aggressive or paths-traversal)
      const deepFindings = result.findings.filter(
        (f) =>
          f.id === 'auth-rls-leak' ||
          f.id === 'paths-supabase-storage-anon-write' ||
          f.id === 'paths-aggressive-xss' ||
          f.id === 'paths-traversal',
      )
      setDeepFindingsCount(deepFindings.length)
      setStatus('done')
      onDeepScanComplete?.(result)
    } catch (e) {
      setStatus('failed')
      const msg = e instanceof Error ? e.message : 'Network error'
      setHint(msg)
    }
  }

  const fileCmd =
    method === 'file'
      ? `echo "${uuid}" > .well-known/Vguard-verify.txt`
      : `_Vguard-verify.${domain}  TXT  "${uuid}"`

  const baseDomain = domain.replace(/^www\./, '')
  return (
    <ModalShell open={open} onClose={onClose}>
      <div className="p-6 sm:p-8">
        <div className="flex items-center gap-2 font-mono text-[10px] tracking-widest uppercase text-(--color-accent) mb-3">
          <ShieldCheck size={12} strokeWidth={2.5} aria-hidden="true" />
          Stage 3 — Verified Deep Scan
        </div>
        <h3 className="text-xl sm:text-2xl font-semibold tracking-tight">
          Prove you own <span className="font-mono text-(--color-accent)">{domain}</span>
        </h3>

        {/* Honest preamble — explains the friction so the user accepts it */}
        <div className="mt-4 rounded-md bg-(--color-bg) border border-(--color-warning)/40 px-4 py-3">
          <div className="flex items-start gap-2">
            <Lock size={14} className="text-(--color-warning) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
            <div className="text-sm text-(--color-fg-muted) leading-relaxed">
              <span className="text-(--color-fg) font-semibold">Why this extra step?</span> Stage 3 fires real attack payloads at your site — XSS, SQLi, RLS testing, prompt injection, storage write-probes. On someone else's site that's <span className="text-(--color-warning) font-semibold">illegal</span>. So we ask for 30 seconds of proof this is yours.
            </div>
          </div>
        </div>

        {freeTier && (
          <div className="mt-3 rounded-md bg-(--color-bg) border border-(--color-accent-border) px-4 py-3">
            <div className="flex items-start gap-2">
              <Globe size={14} className="text-(--color-accent) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
              <div className="text-sm text-(--color-fg-muted) leading-relaxed">
                <span className="text-(--color-fg) font-semibold">No domain? No problem.</span> We see you're on a {freeTier.name} subdomain — you don't own the parent domain (<span className="font-mono">{domain.split('.').slice(-2).join('.')}</span>), so DNS verification won't work for you. <span className="text-(--color-fg) font-semibold">Use file upload instead</span> — it works perfectly on {freeTier.name}.
              </div>
            </div>
          </div>
        )}

        <div className="mt-5 font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-2">
          Pick the method that fits your hosting
        </div>

        {/* Method cards — DNS first (recommended), then File. Vercel token under "Advanced". */}
        <div className="space-y-2.5">
          {/* File challenge — recommended for free-tier subdomains */}
          <button
            type="button"
            onClick={() => {
              setMethod('file')
              setStatus('idle')
            }}
            className={`w-full text-left rounded-lg border-2 transition-colors p-4 cursor-pointer ${
              method === 'file'
                ? 'border-(--color-accent) bg-(--color-surface-elevated)'
                : 'border-(--color-border) bg-(--color-surface) hover:border-(--color-accent-border)'
            }`}
          >
            <div className="flex items-start gap-3">
              <span className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${method === 'file' ? 'bg-(--color-accent) text-(--color-bg)' : 'border border-(--color-border-strong) text-(--color-fg-dim)'}`}>
                {method === 'file' ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : freeTier ? '1' : '2'}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-semibold text-(--color-fg) text-sm">Upload a file to your site</span>
                  {freeTier && (
                    <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border border-(--color-accent) text-(--color-accent)">
                      Recommended for {freeTier.name}
                    </span>
                  )}
                  <span className="font-mono text-[10px] text-(--color-fg-dim)">{freeTier ? '~ 2 min' : '~ 5 min'}</span>
                </div>
                <p className="text-xs text-(--color-fg-muted) leading-relaxed">
                  Add a file at <span className="font-mono text-(--color-fg-muted)">/.well-known/Vguard-verify.txt</span>. {freeTier ? `Works on ${freeTier.name}: ${freeTier.fileHint}` : 'Easiest if you can edit and redeploy your code (Vercel / Netlify / Lovable / Bolt / Replit users — push the file and you\'re done).'}
                </p>
              </div>
            </div>
          </button>

          {/* DNS TXT — recommended for owned domains, dimmed for free-tier subdomains */}
          <button
            type="button"
            onClick={() => {
              setMethod('dns')
              setStatus('idle')
            }}
            className={`w-full text-left rounded-lg border-2 transition-colors p-4 cursor-pointer ${
              method === 'dns'
                ? 'border-(--color-accent) bg-(--color-surface-elevated)'
                : freeTier
                  ? 'border-(--color-border) bg-(--color-surface) opacity-60 hover:opacity-100'
                  : 'border-(--color-border) bg-(--color-surface) hover:border-(--color-accent-border)'
            }`}
          >
            <div className="flex items-start gap-3">
              <span className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${method === 'dns' ? 'bg-(--color-accent) text-(--color-bg)' : 'border border-(--color-border-strong) text-(--color-fg-dim)'}`}>
                {method === 'dns' ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : freeTier ? '2' : '1'}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-semibold text-(--color-fg) text-sm">Add a DNS TXT record</span>
                  {!freeTier ? (
                    <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border border-(--color-accent) text-(--color-accent)">
                      Recommended
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border border-(--color-warning)/60 text-(--color-warning)">
                      Won't work — you don't own {domain.split('.').slice(-2).join('.')}
                    </span>
                  )}
                  <span className="font-mono text-[10px] text-(--color-fg-dim)">~ 1–3 min</span>
                </div>
                <p className="text-xs text-(--color-fg-muted) leading-relaxed">
                  {freeTier
                    ? `${freeTier.name} owns the parent domain, so you can't add DNS records on it. This method only works once you connect a domain you own.`
                    : 'Add one TXT record at your DNS provider (Cloudflare, Vercel DNS, Namecheap, GoDaddy…). Works for any domain regardless of where the app is hosted. Same flow as Google Search Console / AWS / Stripe verification.'}
                </p>
              </div>
            </div>
          </button>

          {/* Vercel token — under Advanced disclosure */}
          {!showAdvanced ? (
            <button
              type="button"
              onClick={() => setShowAdvanced(true)}
              className="w-full text-left rounded-lg border border-dashed border-(--color-border) hover:border-(--color-fg-dim) bg-(--color-bg) transition-colors px-4 py-2.5 cursor-pointer"
            >
              <span className="font-mono text-[11px] text-(--color-fg-dim) hover:text-(--color-fg-muted) inline-flex items-center gap-1.5">
                <ArrowRight size={11} aria-hidden="true" />
                Advanced — verify with a Vercel token (1 method)
              </span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => {
                setMethod('vercel')
                setStatus('idle')
              }}
              className={`w-full text-left rounded-lg border-2 transition-colors p-4 cursor-pointer ${
                method === 'vercel'
                  ? 'border-(--color-accent) bg-(--color-surface-elevated)'
                  : 'border-(--color-border) bg-(--color-surface) hover:border-(--color-accent-border)'
              }`}
            >
              <div className="flex items-start gap-3">
                <span className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${method === 'vercel' ? 'bg-(--color-accent) text-(--color-bg)' : 'border border-(--color-border-strong) text-(--color-fg-dim)'}`}>
                  {method === 'vercel' ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : '3'}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-semibold text-(--color-fg) text-sm">Paste a Vercel personal access token</span>
                    <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border border-(--color-warning)/60 text-(--color-warning)">
                      Advanced
                    </span>
                    <span className="font-mono text-[10px] text-(--color-fg-dim)">~ 30 sec</span>
                  </div>
                  <p className="text-xs text-(--color-fg-muted) leading-relaxed">
                    Fastest method, but it's an honest trust ask: a Vercel PAT grants account access. We list your projects via the Vercel API to confirm <span className="font-mono">{domain}</span> is yours, then discard the token (never logged, never stored). Many teams won't paste tokens into a 3rd-party scanner — that's reasonable. Use DNS or file instead.
                  </p>
                </div>
              </div>
            </button>
          )}
        </div>

        {/* Per-method instructions */}
        {method === 'dns' && (
          <div className="mt-5 rounded-md bg-(--color-bg) border border-(--color-border) p-4">
            {/* AI prompt for DNS — works only if the agent has DNS API access */}
            <div className="rounded-md bg-(--color-surface-elevated) border border-(--color-accent-border) px-4 py-3 mb-4">
              <div className="flex items-start gap-2 mb-2">
                <Sparkles size={14} className="text-(--color-accent) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
                <div className="text-sm text-(--color-fg-muted) leading-relaxed">
                  <span className="text-(--color-fg) font-semibold">Have an AI agent with DNS API access?</span> (e.g. Cloudflare wrangler, Vercel CLI, or env vars in your project) — copy this prompt and paste in. Otherwise add the record manually below.
                </div>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(buildDnsVerifyAiPrompt(baseDomain, uuid), 'ai')}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
              >
                {copied === 'ai' ? (
                  <>
                    <Check size={13} strokeWidth={2.5} aria-hidden="true" />
                    Copied · paste into your AI agent
                  </>
                ) : (
                  <>
                    <Copy size={13} strokeWidth={2} aria-hidden="true" />
                    Copy prompt for your AI
                  </>
                )}
              </button>
            </div>

            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-3">
              Or add it manually — TXT record at your DNS provider
            </div>
            <div className="space-y-2.5">
              <div className="grid grid-cols-[60px_1fr] gap-2 items-center">
                <span className="font-mono text-[10px] uppercase text-(--color-fg-dim) text-right">Type</span>
                <code className="font-mono text-xs text-(--color-fg) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2">TXT</code>
              </div>
              <div className="grid grid-cols-[60px_1fr_auto] gap-2 items-center">
                <span className="font-mono text-[10px] uppercase text-(--color-fg-dim) text-right">Name</span>
                <code className="font-mono text-xs text-(--color-fg) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-nowrap">_Vguard-verify.{baseDomain}</code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(`_Vguard-verify.${baseDomain}`, 'cmd')}
                  className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  aria-label="Copy DNS record name"
                >
                  <Copy size={13} aria-hidden="true" />
                </button>
              </div>
              <div className="grid grid-cols-[60px_1fr_auto] gap-2 items-center">
                <span className="font-mono text-[10px] uppercase text-(--color-fg-dim) text-right">Value</span>
                <code className="font-mono text-xs text-(--color-fg) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-nowrap">{uuid}</code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(uuid, 'uuid')}
                  className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  aria-label="Copy DNS record value"
                >
                  {copied === 'uuid' ? <Check size={13} className="text-(--color-accent)" strokeWidth={2.5} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                </button>
              </div>
            </div>
            <p className="mt-3 text-xs text-(--color-fg-muted) leading-relaxed">
              <span className="font-semibold text-(--color-fg)">Where to add it:</span> Cloudflare → DNS → Add record. Vercel → Project → Domains → Manage DNS. Namecheap → Advanced DNS → Add new record. After saving, wait ~30 seconds and click "Verify now". (DNS propagation can take up to 5 min.)
            </p>
          </div>
        )}

        {method === 'file' && (
          <div className="mt-5 rounded-md bg-(--color-bg) border border-(--color-border) p-4">
            {/* Quick path: paste a single prompt into your AI agent and it does it all */}
            <div className="rounded-md bg-(--color-surface-elevated) border border-(--color-accent-border) px-4 py-3 mb-4">
              <div className="flex items-start gap-2 mb-2">
                <Sparkles size={14} className="text-(--color-accent) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
                <div className="text-sm text-(--color-fg-muted) leading-relaxed">
                  <span className="text-(--color-fg) font-semibold">Easiest path — let your AI do it.</span> Copy this prompt and paste into your AI coding agent (Cursor, Claude Code, Codex, Lovable, Bolt, Replit). It'll create the file, commit, push, and confirm the deploy.
                </div>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(buildFileVerifyAiPrompt(domain, uuid, freeTier?.name ?? null), 'ai')}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
              >
                {copied === 'ai' ? (
                  <>
                    <Check size={13} strokeWidth={2.5} aria-hidden="true" />
                    Copied · paste into your AI agent
                  </>
                ) : (
                  <>
                    <Copy size={13} strokeWidth={2} aria-hidden="true" />
                    Copy prompt for your AI
                  </>
                )}
              </button>
            </div>

            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-3">
              Or do it yourself — upload a file with this exact content
            </div>
            <div className="space-y-2.5">
              <div className="grid grid-cols-[60px_1fr_auto] gap-2 items-center">
                <span className="font-mono text-[10px] uppercase text-(--color-fg-dim) text-right">Path</span>
                <code className="font-mono text-xs text-(--color-fg) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-nowrap">/.well-known/Vguard-verify.txt</code>
                <button
                  type="button"
                  onClick={() => copyToClipboard('.well-known/Vguard-verify.txt', 'cmd')}
                  className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  aria-label="Copy file path"
                >
                  <Copy size={13} aria-hidden="true" />
                </button>
              </div>
              <div className="grid grid-cols-[60px_1fr_auto] gap-2 items-center">
                <span className="font-mono text-[10px] uppercase text-(--color-fg-dim) text-right">Content</span>
                <code className="font-mono text-xs text-(--color-fg) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-nowrap">{uuid}</code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(uuid, 'uuid')}
                  className="inline-flex items-center gap-1 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  aria-label="Copy file content"
                >
                  {copied === 'uuid' ? <Check size={13} className="text-(--color-accent)" strokeWidth={2.5} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                </button>
              </div>
            </div>
            <div className="mt-3 text-xs text-(--color-fg-muted) leading-relaxed space-y-1.5">
              {freeTier ? (
                <div>
                  <span className="font-semibold text-(--color-fg)">For your hosting ({freeTier.name}):</span> {freeTier.fileHint}
                </div>
              ) : (
                <div>
                  <span className="font-semibold text-(--color-fg)">Where to put it:</span> drop the file in your project's <span className="font-mono">public/</span> (Next/Vite/CRA), <span className="font-mono">static/</span> (SvelteKit), or root <span className="font-mono">.well-known/</span> (Astro). Commit, push, redeploy.
                </div>
              )}
              <div>
                <span className="font-semibold text-(--color-fg)">Quick check:</span> open <span className="font-mono break-all">https://{domain}/.well-known/Vguard-verify.txt</span> in a new tab — you should see just the UUID.
              </div>
              <div>
                <span className="font-semibold text-(--color-fg)">Shell shortcut</span> (if you have terminal access):
                <code className="block mt-1 font-mono text-[11px] text-(--color-fg-muted) bg-(--color-surface-elevated) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-nowrap">{fileCmd}</code>
              </div>
            </div>
          </div>
        )}

        {method === 'vercel' && (
          <div className="mt-5 rounded-md bg-(--color-bg) border border-(--color-warning)/40 p-4">
            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-warning) mb-2">
              ⚠ Trust check before you paste
            </div>
            <p className="text-xs text-(--color-fg-muted) leading-relaxed mb-3">
              A Vercel PAT grants <span className="font-semibold text-(--color-fg)">full account access</span>. We send it once to <span className="font-mono">api.vercel.com</span> to list your projects, confirm <span className="font-mono">{domain}</span> is one of them, and discard. Source for this endpoint is in our repo. <span className="text-(--color-fg)">If pasting feels off, use DNS or file instead — same outcome.</span>
            </p>
            <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-1.5">
              Paste your Vercel personal access token
            </div>
            <input
              type="password"
              value={vercelToken}
              onChange={(e) => setVercelToken(e.target.value)}
              placeholder="vercel_token_xxxx..."
              className="w-full px-3 py-2 rounded-md bg-(--color-surface-elevated) border border-(--color-border) focus:border-(--color-accent-border) text-(--color-fg) placeholder:text-(--color-fg-dim) font-mono text-xs focus:outline-none transition-colors"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="mt-2 font-mono text-[11px] text-(--color-fg-dim) leading-relaxed">
              Get a token at{' '}
              <a
                href="https://vercel.com/account/tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-(--color-accent) underline"
              >
                vercel.com/account/tokens
              </a>
              {' '}with "Full Account" scope.
            </p>
          </div>
        )}

        {/* Authenticated IDOR mode — small, advanced, opt-in */}
        <div className="mt-5">
          {!authMode ? (
            <button
              type="button"
              onClick={() => setAuthMode(true)}
              className="font-mono text-[11px] text-(--color-fg-dim) hover:text-(--color-fg-muted) inline-flex items-center gap-1.5 cursor-pointer"
            >
              <ArrowRight size={11} aria-hidden="true" />
              Optional — also test for IDOR (paste a logged-in user's JWT)
            </button>
          ) : (
            <div className="rounded-md bg-(--color-bg) border border-(--color-border) px-4 py-3">
              <div className="flex items-start justify-between gap-2 mb-1.5">
                <span className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg)">
                  IDOR test — paste a user JWT
                </span>
                <button
                  type="button"
                  onClick={() => { setAuthMode(false); setUserJwt('') }}
                  className="font-mono text-[10px] text-(--color-fg-dim) hover:text-(--color-fg-muted) cursor-pointer"
                >
                  Skip
                </button>
              </div>
              <p className="text-xs text-(--color-fg-muted) leading-relaxed mb-2.5">
                Get a JWT from your app: open it in the browser, login, DevTools → Application → Local Storage → <span className="font-mono">sb-...-auth-token</span> → copy the <span className="font-mono">access_token</span> field. We'll re-run RLS probes as that user — if they can SELECT 50+ rows from another user's table, that's IDOR.
              </p>
              <input
                type="password"
                value={userJwt}
                onChange={(e) => setUserJwt(e.target.value)}
                placeholder="eyJ..."
                className="w-full px-3 py-2 rounded-md bg-(--color-surface-elevated) border border-(--color-border) focus:border-(--color-accent-border) text-(--color-fg) placeholder:text-(--color-fg-dim) font-mono text-xs focus:outline-none transition-colors"
                autoComplete="off"
                spellCheck={false}
              />
              <p className="mt-1.5 font-mono text-[10px] text-(--color-fg-dim) leading-relaxed">
                Held only in browser memory for this scan. Sent once with the deep-scan request. Not logged.
              </p>
            </div>
          )}
        </div>

        <div className="mt-5 flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={verifyNow}
            disabled={status === 'checking'}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {status === 'checking' ? (
              <>
                <Loader2 size={13} className="animate-spin" strokeWidth={2.5} aria-hidden="true" />
                Verifying…
              </>
            ) : status === 'verified' ? (
              <>
                <Check size={13} strokeWidth={2.5} aria-hidden="true" />
                Verified
              </>
            ) : (
              <>
                <RefreshCw size={13} strokeWidth={2.5} aria-hidden="true" />
                Verify now
              </>
            )}
          </button>
          {status !== 'idle' && status !== 'checking' && (
            <button
              type="button"
              onClick={() => setStatus('idle')}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) text-(--color-fg-muted) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
            >
              Reset
            </button>
          )}
        </div>

        {status === 'verified' && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 rounded-md bg-(--color-bg) border border-(--color-ok)/40 px-4 py-3"
          >
            <div className="flex items-start gap-2">
              <Check size={14} className="text-(--color-ok) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
              <div>
                <div className="font-mono text-xs text-(--color-ok) tracking-widest uppercase mb-1">
                  Ownership verified
                </div>
                <p className="text-sm text-(--color-fg) leading-relaxed">
                  Starting deep scan on {domain}…
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {status === 'scanning' && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 rounded-md bg-(--color-bg) border border-(--color-accent-border) px-4 py-3"
          >
            <div className="flex items-start gap-2">
              <Loader2 size={14} className="text-(--color-accent) mt-0.5 flex-shrink-0 animate-spin" strokeWidth={2.5} aria-hidden="true" />
              <div>
                <div className="font-mono text-xs text-(--color-accent) tracking-widest uppercase mb-1">
                  Deep scan in progress
                </div>
                <p className="text-sm text-(--color-fg-muted) leading-relaxed">
                  Probing Supabase RLS, storage permissions, aggressive XSS payloads, path traversal. Up to 30 seconds.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {status === 'done' && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 rounded-md bg-(--color-bg) border border-(--color-ok)/40 px-4 py-3"
          >
            <div className="flex items-start gap-2">
              <Check size={14} className="text-(--color-ok) mt-0.5 flex-shrink-0" strokeWidth={2.5} aria-hidden="true" />
              <div className="flex-1">
                <div className="font-mono text-xs text-(--color-ok) tracking-widest uppercase mb-1">
                  Deep scan complete
                </div>
                <p className="text-sm text-(--color-fg) leading-relaxed">
                  {deepFindingsCount > 0
                    ? `Found ${deepFindingsCount} additional Stage 3 finding${
                        deepFindingsCount === 1 ? '' : 's'
                      }. Close this dialog — they're added to the report above with copy-prompt buttons.`
                    : `Stage 3 probes ran clean. No RLS leaks, no aggressive-XSS hits, no path traversal. Your verified domain passes the deep scan.`}
                </p>
                <button
                  type="button"
                  onClick={onClose}
                  className="mt-3 inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
                >
                  See report
                  <ArrowRight size={12} aria-hidden="true" />
                </button>
              </div>
            </div>
          </motion.div>
        )}

        {status === 'failed' && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 rounded-md bg-(--color-bg) border border-(--color-warning)/40 px-4 py-3"
          >
            <div className="font-mono text-xs text-(--color-warning) tracking-widest uppercase mb-1">
              Not yet verified
            </div>
            <p className="text-sm text-(--color-fg-muted) leading-relaxed">{hint}</p>
          </motion.div>
        )}
      </div>
    </ModalShell>
  )
}

export default NextStagesPanel
