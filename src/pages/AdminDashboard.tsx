import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  motion,
  AnimatePresence,
  useMotionValue,
  animate,
  type PanInfo,
} from 'framer-motion'
import {
  ChevronLeft,
  RefreshCw,
  X,
  ArrowDown,
  Activity,
  BarChart3,
  Filter,
  TriangleAlert,
  Globe,
  ShieldCheck,
  BadgeCheck,
  Inbox,
  ScanLine,
  Ban,
  CheckCircle2,
  type LucideIcon,
} from 'lucide-react'
import { iosAdmin as T } from '../lib/design-tokens'
import { VGuardsLogo, MascotScanMark } from '../components/ui/vguards-logo'

/**
 * V-Guards admin dashboard — iOS-DARK design (Hebrew, RTL). For Royi + Oded.
 *
 * iOS interaction patterns (grouped inset lists, segmented control, bottom
 * sheets, spring physics, pull-to-refresh, swipe-to-reveal) on V-Guards' dark
 * "Terminal Trust" brand (`iosAdmin` palette: #09090b canvas, cyan accent,
 * raccoon mark, grid + glow). Stays logged in across visits (7-day session +
 * localStorage) and auto-reloads when a newer deploy ships.
 *
 * Behind the secret ADMIN_LOGS_PATH route (middleware.ts) + ADMIN_SECRET +
 * Turnstile gate (api/_lib/admin-auth.ts). Four tabs: סקירה · סריקות · לידים · יומן.
 * Data: /api/admin/dashboard + /api/admin/logs (shared Turnstile session cookie).
 */

const TURNSTILE_SITE_KEY =
  (import.meta.env.VITE_TURNSTILE_SITE_KEY as string | undefined) ||
  '0x4AAAAAAC_BzqF_UH-VXX5R'

// iOS feel = the device system font (SF Pro on Apple, incl. Hebrew). Heebo is
// the fallback for non-Apple; loaded lazily so the marketing site stays lean.
const ADMIN_FONT =
  '-apple-system, BlinkMacSystemFont, system-ui, "Heebo", "Segoe UI", sans-serif'

function useHebrewFont() {
  useEffect(() => {
    const ID = 'vg-admin-heebo'
    if (document.getElementById(ID)) return
    const link = document.createElement('link')
    link.id = ID
    link.rel = 'stylesheet'
    link.href = 'https://fonts.googleapis.com/css2?family=Heebo:wght@400;500;600;700;800&display=swap'
    document.head.appendChild(link)
  }, [])
}

// ── Deploy freshness ────────────────────────────────────────────────────────
// Capture the hash of the JS bundle currently running. On re-entry (tab focus /
// becomes visible) we fetch the live index and compare; if a newer deploy
// shipped, hard-reload so the admin always reflects the latest deploy. In dev
// there's no hashed bundle, so CURRENT_BUILD is null and the check no-ops.
const CURRENT_BUILD: string | null = (() => {
  try {
    const s = document.querySelector(
      'script[type="module"][src*="/assets/index-"]',
    ) as HTMLScriptElement | null
    return s?.src.match(/index-([A-Za-z0-9_-]+)\./)?.[1] ?? null
  } catch {
    return null
  }
})()

async function latestBuild(): Promise<string | null> {
  try {
    const html = await fetch('/?_v=' + Date.now(), { cache: 'no-store' }).then((r) => r.text())
    return html.match(/assets\/index-([A-Za-z0-9_-]+)\.js/)?.[1] ?? null
  } catch {
    return null
  }
}

function useAutoRefreshOnReturn(onRefetch: () => void) {
  const cb = useRef(onRefetch)
  cb.current = onRefetch
  useEffect(() => {
    let busy = false
    const check = async () => {
      if (busy || document.visibilityState !== 'visible') return
      busy = true
      try {
        const latest = await latestBuild()
        if (latest && CURRENT_BUILD && latest !== CURRENT_BUILD) {
          location.reload()
          return
        }
        cb.current()
      } catch {
        /* ignore */
      } finally {
        busy = false
      }
    }
    document.addEventListener('visibilitychange', check)
    window.addEventListener('focus', check)
    return () => {
      document.removeEventListener('visibilitychange', check)
      window.removeEventListener('focus', check)
    }
  }, [])
}

// ── Pull-to-refresh (touch) ──────────────────────────────────────────────────
function usePullToRefresh(onRefresh: () => Promise<void> | void) {
  const [pull, setPull] = useState(0)
  const [refreshing, setRefreshing] = useState(false)
  const startY = useRef<number | null>(null)
  const active = useRef(false)
  const pullRef = useRef(0)
  const busy = useRef(false)
  useEffect(() => {
    pullRef.current = pull
  }, [pull])
  useEffect(() => {
    const ts = (e: TouchEvent) => {
      if (window.scrollY <= 0 && !busy.current) {
        startY.current = e.touches[0].clientY
        active.current = true
      } else {
        active.current = false
      }
    }
    const tm = (e: TouchEvent) => {
      if (!active.current || startY.current == null) return
      const dy = e.touches[0].clientY - startY.current
      if (dy > 0 && window.scrollY <= 0) {
        const dist = Math.min(96, Math.pow(dy, 0.85))
        setPull(dist)
        if (dist > 6) e.preventDefault()
      } else {
        setPull(0)
      }
    }
    const te = async () => {
      if (!active.current) return
      active.current = false
      startY.current = null
      if (pullRef.current > 58 && !busy.current) {
        busy.current = true
        setRefreshing(true)
        setPull(54)
        try {
          await onRefresh()
        } finally {
          setRefreshing(false)
          setPull(0)
          busy.current = false
        }
      } else {
        setPull(0)
      }
    }
    window.addEventListener('touchstart', ts, { passive: true })
    window.addEventListener('touchmove', tm, { passive: false })
    window.addEventListener('touchend', te, { passive: true })
    return () => {
      window.removeEventListener('touchstart', ts)
      window.removeEventListener('touchmove', tm)
      window.removeEventListener('touchend', te)
    }
  }, [onRefresh])
  return { pull, refreshing }
}

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement | string,
        opts: {
          sitekey: string
          theme?: 'light' | 'dark' | 'auto'
          size?: 'normal' | 'flexible' | 'compact' | 'invisible'
          callback?: (token: string) => void
          'error-callback'?: () => void
          'expired-callback'?: () => void
        },
      ) => string | null
      remove: (id: string) => void
      reset: (id?: string) => void
      getResponse: (id?: string) => string | undefined
    }
  }
}

// ─────────────────────────────────────────────────────────── types

interface Kpis {
  totalScans: number
  scans24h: number
  scans7d: number
  scans30d: number
  uniqueHosts: number
  avgScore: number | null
  successCount: number
  failCount: number
  wafBlocked: number
  stealthRescued: number
  verifiedDomains: number
  stage2Runs: number
  aggCapped: boolean
}

interface ScanRow {
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
  stealth_retry_succeeded: boolean | null
  scan_outcome: string | null
}

interface VerifiedDomain {
  domain: string
  email: string | null
  method: string | null
  verified_at: string
  expires_at: string | null
  scan_count: number | null
}

interface Lead {
  id: number
  created_at: string
  source: 'contact' | 'verify'
  name: string | null
  email: string
  message: string | null
  domain: string | null
  method: string | null
  verified: boolean | null
  status: 'new' | 'read' | 'replied' | 'archived'
}

interface DashboardData {
  ok: boolean
  kpis: Kpis
  gradeDist: Record<string, number>
  countries: { key: string; count: number }[]
  wafVendors: { key: string; count: number }[]
  topFindings: { title: string; count: number; severity: string }[]
  topHosts: { hostname: string; scans: number; lastScore: number | null; lastAt: string }[]
  funnel: Record<string, number>
  recentScans: ScanRow[]
  verified: VerifiedDomain[]
  leads: Lead[]
  leadsTableMissing: boolean
  statusCounts: Record<string, number>
  error?: string
}

interface AuditRow {
  id: number
  created_at: string
  event_type: string
  ip_hash: string | null
  user_agent: string | null
  path: string | null
  scanned_url: string | null
  scan_outcome: string | null
  vibe_score: number | null
  waf_vendor: string | null
  metadata: Record<string, unknown> | null
}

// ─────────────────────────────────────────────────────────── helpers

function fmt(d: string) {
  try {
    return new Date(d).toLocaleString('he-IL', { hour12: false, dateStyle: 'short', timeStyle: 'short' })
  } catch {
    return d
  }
}
function fmtDate(d: string) {
  try {
    return new Date(d).toLocaleDateString('he-IL', { dateStyle: 'medium' })
  } catch {
    return d
  }
}
function gradeOf(score: number | null): string {
  if (score === null) return '—'
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

// Brand-only: severity is conveyed by the finding text, not by color. Dots stay cyan.
const SEV_COLOR: Record<string, string> = {
  critical: T.accent,
  warn: T.accent,
  info: T.accent,
  ok: T.label4,
}
const OUTCOME_LABEL: Record<string, string> = {
  success: 'הצליחה',
  blocked_by_waf: 'נחסם ע"י WAF',
  blocked_by_target: 'נדחה ע"י האתר',
  unreachable: 'לא נגיש',
  invalid_url: 'כתובת לא תקינה',
  internal: 'שגיאה פנימית',
  internal_error: 'שגיאה פנימית',
}
const SOURCE_LABEL: Record<string, string> = { contact: 'יצירת קשר', verify: 'אימות בעלות' }
const STATUS_LABEL: Record<string, string> = { new: 'חדש', read: 'נקרא', replied: 'נענה', archived: 'אורכב' }
const STATUS_COLOR: Record<string, string> = { new: T.accent, read: T.label3, replied: T.label2, archived: T.label4 }
const FUNNEL_STEPS: { key: string; label: string }[] = [
  { key: 'page_visit', label: 'ביקורים בדף' },
  { key: 'scan_started', label: 'התחילו סריקה' },
  { key: 'scan_completed', label: 'השלימו סריקה' },
  { key: 'stage2_started', label: 'Stage 2 התחילו' },
  { key: 'stage2_completed', label: 'Stage 2 הושלמו' },
]

// ─────────────────────────────────────────────────────────── iOS primitives

// Icon tile — single brand treatment: cyan glyph on a faint cyan surface.
function IconTile({ icon: Icon, size = 28 }: { icon: LucideIcon; size?: number }) {
  return (
    <span
      className="inline-flex items-center justify-center rounded-[7px] shrink-0"
      style={{ width: size, height: size, background: T.accentSoft }}
    >
      <Icon size={Math.round(size * 0.56)} color={T.accent} strokeWidth={2.2} />
    </span>
  )
}

function ListGroup({
  header,
  footer,
  icon,
  children,
}: {
  header?: string
  footer?: string
  icon?: LucideIcon
  children: React.ReactNode
}) {
  return (
    <div className="space-y-2">
      {header && (
        <div className="flex items-center gap-2 px-1">
          {icon && <IconTile icon={icon} size={22} />}
          <span className="text-[13px] font-semibold uppercase tracking-wide" style={{ color: T.label3 }}>
            {header}
          </span>
        </div>
      )}
      <div className="overflow-hidden rounded-2xl" style={{ background: T.card, border: `1px solid ${T.separator}` }}>
        <div className="flex flex-col">{children}</div>
      </div>
      {footer && (
        <div className="px-4 text-[12px] leading-snug" style={{ color: T.label3 }}>
          {footer}
        </div>
      )}
    </div>
  )
}

function Cell({
  title,
  subtitle,
  leading,
  trailing,
  onPress,
  last,
  align = 'center',
}: {
  title: React.ReactNode
  subtitle?: React.ReactNode
  leading?: React.ReactNode
  trailing?: React.ReactNode
  onPress?: () => void
  last?: boolean
  align?: 'center' | 'start'
}) {
  const inner = (
    <>
      {leading && <div className="shrink-0">{leading}</div>}
      <div className="min-w-0 flex-1">
        <div className="text-[15px] truncate" style={{ color: T.label }}>
          {title}
        </div>
        {subtitle && (
          <div className="text-[13px] mt-0.5 truncate" style={{ color: T.label3 }}>
            {subtitle}
          </div>
        )}
      </div>
      {trailing && <div className="shrink-0 text-[14px]" style={{ color: T.label2 }}>{trailing}</div>}
      {onPress && <ChevronLeft size={18} style={{ color: T.label4 }} className="shrink-0" />}
    </>
  )
  const cls = `flex w-full gap-3 px-4 py-3 text-right ${align === 'start' ? 'items-start' : 'items-center'} ${
    onPress ? 'active:bg-white/[0.05]' : ''
  }`
  const style = { borderBottom: last ? 'none' : `0.5px solid ${T.separator}` }
  return onPress ? (
    <button onClick={onPress} className={cls} style={style}>
      {inner}
    </button>
  ) : (
    <div className={cls} style={style}>
      {inner}
    </div>
  )
}

function Segmented<T_ extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T_; label: string; badge?: number }[]
  value: T_
  onChange: (v: T_) => void
}) {
  return (
    <div className="flex gap-0.5 p-1 rounded-[12px]" style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${T.separator}` }}>
      {tabs.map((t) => {
        const sel = t.id === value
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className="relative flex-1 py-2 px-1 text-[13px] font-semibold rounded-[8px]"
          >
            {sel && (
              <motion.span
                layoutId="vg-seg-pill"
                className="absolute inset-0 rounded-[8px]"
                style={{ background: T.bgElevated, border: `1px solid ${T.separatorStrong}`, boxShadow: '0 1px 3px rgba(0,0,0,0.4)' }}
                transition={{ type: 'spring', damping: 30, stiffness: 420 }}
              />
            )}
            <span className="relative z-10 inline-flex items-center justify-center gap-1" style={{ color: sel ? T.label : T.label2 }}>
              {t.label}
              {!!t.badge && (
                <span
                  className="inline-flex items-center justify-center rounded-full text-[10px] font-bold px-1.5 min-w-[16px] h-4"
                  style={{ background: T.accent, color: T.onAccent }}
                >
                  {t.badge}
                </span>
              )}
            </span>
          </button>
        )
      })}
    </div>
  )
}

function KpiTile({
  label,
  value,
  accent,
  sub,
  icon,
  onPress,
}: {
  label: string
  value: React.ReactNode
  accent?: string
  sub?: string
  icon?: LucideIcon
  onPress?: () => void
}) {
  const Comp: React.ElementType = onPress ? 'button' : 'div'
  return (
    <Comp
      onClick={onPress}
      className={`rounded-2xl p-3.5 text-right ${onPress ? 'active:scale-[0.97] transition-transform' : ''}`}
      style={{ background: T.card, border: `1px solid ${T.separator}` }}
    >
      {icon && (
        <div className="mb-2.5">
          <IconTile icon={icon} size={26} />
        </div>
      )}
      <div className="text-[24px] font-bold leading-none tabular-nums" style={{ color: accent ?? T.label }}>
        {value}
      </div>
      <div className="mt-1.5 text-[12px] leading-tight" style={{ color: T.label2 }}>
        {label}
      </div>
      {sub && (
        <div className="mt-0.5 text-[11px]" style={{ color: T.label4 }}>
          {sub}
        </div>
      )}
    </Comp>
  )
}

// Circular score ring (premium hero stat).
function ScoreRing({ score }: { score: number | null }) {
  const g = gradeOf(score)
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100
  const r = 30
  const circ = 2 * Math.PI * r
  return (
    <div className="relative" style={{ width: 76, height: 76 }}>
      <svg width="76" height="76" viewBox="0 0 76 76" className="-rotate-90">
        <circle cx="38" cy="38" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
        <motion.circle
          cx="38" cy="38" r={r} fill="none" stroke={T.accent} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: circ * (1 - pct) }}
          transition={{ type: 'spring', damping: 24, stiffness: 120 }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[20px] font-bold leading-none tabular-nums" style={{ color: T.label }}>
          {score ?? '—'}
        </span>
        <span className="text-[11px] font-bold leading-none mt-0.5" style={{ color: T.label3 }}>
          {g}
        </span>
      </div>
    </div>
  )
}

function ScoreBadge({ score }: { score: number | null }) {
  const g = gradeOf(score)
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[13px] font-bold tabular-nums"
      style={{ color: T.accent, background: T.accentSoft }}
    >
      {g}
      <span style={{ color: T.label2 }}>{score ?? '—'}</span>
    </span>
  )
}

function Bar({ value, max, color }: { value: number; max: number; color: string }) {
  return (
    <div className="h-2 rounded-full overflow-hidden" style={{ background: T.separator }}>
      <motion.div
        className="h-full rounded-full"
        style={{ background: color }}
        initial={{ width: 0 }}
        animate={{ width: `${(value / Math.max(1, max)) * 100}%` }}
        transition={{ type: 'spring', damping: 26, stiffness: 200 }}
      />
    </div>
  )
}

function Sheet({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean
  onClose: () => void
  title?: string
  children: React.ReactNode
}) {
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-40"
            style={{ background: 'rgba(0,0,0,0.6)' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            dir="rtl"
            className="fixed inset-x-0 bottom-0 z-50 rounded-t-[20px] max-h-[85vh] overflow-y-auto"
            style={{ background: T.bg, fontFamily: ADMIN_FONT, boxShadow: '0 -8px 40px rgba(0,0,0,0.2)' }}
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            transition={{ type: 'spring', damping: 34, stiffness: 350 }}
            drag="y"
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.5 }}
            onDragEnd={(_e: unknown, info: PanInfo) => {
              if (info.offset.y > 120 || info.velocity.y > 700) onClose()
            }}
          >
            <div className="sticky top-0 z-10 flex items-center justify-between px-4 pt-2.5 pb-3" style={{ background: T.bg }}>
              <div className="absolute left-1/2 -translate-x-1/2 top-1.5 h-1.5 w-9 rounded-full" style={{ background: T.separatorStrong }} />
              <h3 className="text-[17px] font-bold mt-2" style={{ color: T.label }}>
                {title}
              </h3>
              <button
                onClick={onClose}
                className="mt-2 flex items-center justify-center h-8 w-8 rounded-full active:scale-90 transition-transform"
                style={{ background: 'rgba(118,118,128,0.12)' }}
              >
                <X size={17} style={{ color: T.label2 }} />
              </button>
            </div>
            <div className="px-4 pb-8 space-y-3">{children}</div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}

// Swipe-to-reveal quick actions (family-ledger style). RTL: swipe LEFT reveals
// the action buttons docked on the left edge.
function SwipeRow({
  actions,
  children,
}: {
  actions: { label: string; color: string; textColor?: string; onPress: () => void }[]
  children: React.ReactNode
}) {
  const x = useMotionValue(0)
  const W = actions.length * 76
  const close = () => animate(x, 0, { type: 'spring', damping: 34, stiffness: 400 })
  return (
    <div className="relative overflow-hidden rounded-2xl" style={{ background: T.card, border: `1px solid ${T.separator}` }}>
      {/* actions sit BEHIND the card (z-0); revealed only when the card is swiped away */}
      <div className="absolute inset-y-0 left-0 flex" style={{ zIndex: 0 }}>
        {actions.map((a) => (
          <button
            key={a.label}
            onClick={() => {
              a.onPress()
              close()
            }}
            className="flex items-center justify-center text-[13px] font-semibold active:opacity-80"
            style={{ width: 76, background: a.color, color: a.textColor ?? '#fff' }}
          >
            {a.label}
          </button>
        ))}
      </div>
      <motion.div
        drag="x"
        style={{ x, background: T.card, position: 'relative', zIndex: 1 }}
        dragConstraints={{ left: -W, right: 0 }}
        dragElastic={0.06}
        dragDirectionLock
        onDragEnd={(_e: unknown, info: PanInfo) => {
          const open = info.offset.x < -W / 2 || info.velocity.x < -400
          animate(x, open ? -W : 0, { type: 'spring', damping: 34, stiffness: 400 })
        }}
      >
        {children}
      </motion.div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────── Turnstile

function TurnstileBox({ onToken, resetSignal }: { onToken: (t: string) => void; resetSignal: number }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const widgetIdRef = useRef<string | null>(null)
  useEffect(() => {
    let cancelled = false
    let attempt = 0
    const tryRender = () => {
      if (cancelled || !containerRef.current) return
      if (!window.turnstile) {
        if (attempt++ < 50) setTimeout(tryRender, 200)
        return
      }
      if (widgetIdRef.current) return
      const id = window.turnstile.render(containerRef.current, {
        sitekey: TURNSTILE_SITE_KEY,
        theme: 'dark',
        size: 'normal',
        callback: (token) => onToken(token),
        'error-callback': () => onToken(''),
        'expired-callback': () => onToken(''),
      })
      if (id) widgetIdRef.current = id
    }
    tryRender()
    return () => {
      cancelled = true
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current)
        } catch {
          /* ignore */
        }
        widgetIdRef.current = null
      }
    }
  }, [onToken])
  useEffect(() => {
    if (resetSignal > 0 && widgetIdRef.current && window.turnstile) {
      try {
        window.turnstile.reset(widgetIdRef.current)
      } catch {
        /* ignore */
      }
    }
  }, [resetSignal])
  return <div ref={containerRef} />
}

// ─────────────────────────────────────────────────────────── main

type Tab = 'overview' | 'scans' | 'leads' | 'events'
type SheetState =
  | { kind: 'scan'; row: ScanRow }
  | { kind: 'lead'; row: Lead }
  | null

export default function AdminDashboard() {
  useHebrewFont()
  const [username, setUsername] = useState<string>(() => localStorage.getItem('vg_admin_user') ?? '')
  const [secret, setSecret] = useState<string>(() => (localStorage.getItem('vg_admin_secret') ?? '').trim())
  // Optimistically skip the login screen if we have a stored secret — the 7-day
  // HMAC session cookie usually still authorizes us. If it expired, the first
  // fetch returns 404 and we bounce back to the login screen.
  const [submittedSecret, setSubmittedSecret] = useState<string>(
    (localStorage.getItem('vg_admin_secret') ?? '').trim(),
  )
  const [authError, setAuthError] = useState<string>('')
  const [turnstileToken, setTurnstileToken] = useState<string>('')
  const [turnstileResetSignal, setTurnstileResetSignal] = useState<number>(0)

  const [tab, setTab] = useState<Tab>('overview')
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(false)
  const [sheet, setSheet] = useState<SheetState>(null)
  const [scanFilter, setScanFilter] = useState<string>('')

  const handleTurnstileToken = useCallback((token: string) => {
    setTurnstileToken(token)
    if (token) setAuthError('')
  }, [])

  const authHeaders = useCallback((): Record<string, string> => {
    const h: Record<string, string> = { 'x-admin-secret': submittedSecret || secret }
    const u = localStorage.getItem('vg_admin_user')
    if (u) h['x-admin-user'] = u
    if (turnstileToken) h['x-turnstile-token'] = turnstileToken
    return h
  }, [submittedSecret, secret, turnstileToken])

  const fetchDashboard = useCallback(
    async (s: string, ts?: string) => {
        setLoading(true)
      setAuthError('')
      try {
        const headers: Record<string, string> = { 'x-admin-secret': s }
        const u = localStorage.getItem('vg_admin_user')
        if (u) headers['x-admin-user'] = u
        const t = ts ?? turnstileToken
        if (t) headers['x-turnstile-token'] = t
        const r = await fetch('/api/admin/dashboard', { headers })
        if (r.status === 404) {
          setAuthError('הגישה נדחתה.')
          setData(null)
          localStorage.removeItem('vg_admin_secret')
          setSubmittedSecret('')
          setTurnstileToken('')
          setTurnstileResetSignal((n) => n + 1)
          return
        }
        if (r.status === 429) {
          setAuthError('יותר מדי בקשות. האט קצת.')
          return
        }
        setData((await r.json()) as DashboardData)
      } catch (e) {
        setAuthError(e instanceof Error ? e.message : 'שגיאה לא ידועה')
      } finally {
        setLoading(false)
      }
    },
    [turnstileToken],
  )

  const refresh = useCallback(async () => {
    if (submittedSecret) await fetchDashboard(submittedSecret)
  }, [submittedSecret, fetchDashboard])

  // On mount: if a secret is stored, auto-authenticate via the session cookie
  // (no Turnstile needed). Keeps Royi/Oded logged in across visits for 7 days.
  useEffect(() => {
    const s = (localStorage.getItem('vg_admin_secret') ?? '').trim()
    if (s) fetchDashboard(s)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Re-entry: on tab focus / visible, reload if a newer deploy shipped, else refetch.
  useAutoRefreshOnReturn(() => {
    void refresh()
  })

  const { pull, refreshing } = usePullToRefresh(refresh)

  function login(e: React.FormEvent) {
    e.preventDefault()
    const liveToken = turnstileToken || window.turnstile?.getResponse() || ''
    if (TURNSTILE_SITE_KEY && !liveToken) {
      setAuthError('יש להשלים את אימות האבטחה.')
      return
    }
    if (liveToken && liveToken !== turnstileToken) setTurnstileToken(liveToken)
    const cleanUser = username.trim().toLowerCase()
    setUsername(cleanUser)
    localStorage.setItem('vg_admin_user', cleanUser)
    const clean = secret.trim()
    setSecret(clean)
    localStorage.setItem('vg_admin_secret', clean)
    setSubmittedSecret(clean)
    fetchDashboard(clean, liveToken)
  }

  function signOut() {
    localStorage.removeItem('vg_admin_secret')
    localStorage.removeItem('vg_admin_user')
    setSecret('')
    setUsername('')
    setSubmittedSecret('')
    setData(null)
  }

  async function setLeadStatus(id: number, status: Lead['status']) {
    setData((d) => (d ? { ...d, leads: d.leads.map((l) => (l.id === id ? { ...l, status } : l)) } : d))
    setSheet((s) => (s && s.kind === 'lead' && s.row.id === id ? { kind: 'lead', row: { ...s.row, status } } : s))
    try {
      await fetch('/api/admin/dashboard', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'lead_status', id, status }),
      })
    } catch {
      /* optimistic */
    }
  }

  function openScansFiltered(outcome: string) {
    setScanFilter(outcome)
    setTab('scans')
  }

  // ── login screen (iOS) ──
  if (!submittedSecret || authError === 'הגישה נדחתה.') {
    return (
      <div
        dir="rtl"
        style={{ fontFamily: ADMIN_FONT, backgroundColor: T.bg }}
        className="bg-grid relative min-h-screen flex items-center justify-center p-6"
      >
        <div className="hero-glow pointer-events-none absolute inset-x-0 top-0 h-72" />
        <form onSubmit={login} className="relative w-full max-w-sm space-y-5">
          <div className="flex flex-col items-center text-center gap-3.5">
            <span
              className="flex items-center justify-center h-40 w-40 rounded-[36px] overflow-hidden"
              style={{ background: T.card, border: `1px solid ${T.separator}`, boxShadow: `0 0 80px ${T.accentSoft}` }}
            >
              <MascotScanMark size={158} />
            </span>
            <div>
              <h1 className="text-[22px] font-bold tracking-tight" style={{ color: T.label }}>
                V<span style={{ color: T.accent }}>-</span>Guards
              </h1>
              <p className="text-[14px] mt-1" style={{ color: T.label2 }}>
                לוח בקרה · הזינו סיסמת אדמין
              </p>
            </div>
          </div>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value.replace(/\s+/g, ''))}
            placeholder="שם משתמש"
            autoFocus
            autoComplete="username"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            dir="ltr"
            name="vg-admin-user"
            className="w-full rounded-xl px-4 py-3.5 text-[16px] text-left focus:outline-none"
            style={{ background: T.card, border: `1px solid ${T.separator}`, color: T.label }}
          />
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value.replace(/\s+/g, ''))}
            placeholder="סיסמה"
            autoComplete="current-password"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            dir="ltr"
            name="vg-admin-token"
            className="w-full rounded-xl px-4 py-3.5 text-[16px] text-left focus:outline-none"
            style={{ background: T.card, border: `1px solid ${T.separator}`, color: T.label }}
          />
          <div className="flex justify-center">
            <TurnstileBox onToken={handleTurnstileToken} resetSignal={turnstileResetSignal} />
          </div>
          {authError && <p className="text-[14px] text-center" style={{ color: T.red }}>{authError}</p>}
          <button
            type="submit"
            className="w-full rounded-xl py-3.5 text-[16px] font-bold active:scale-[0.98] transition-transform"
            style={{ background: T.accentFill, color: T.onAccent }}
          >
            כניסה
          </button>
        </form>
      </div>
    )
  }

  const newLeads = data?.leads.filter((l) => l.status === 'new').length ?? 0
  const TABS: { id: Tab; label: string; badge?: number }[] = [
    { id: 'overview', label: 'סקירה' },
    { id: 'scans', label: 'סריקות' },
    { id: 'leads', label: 'לידים', badge: newLeads || undefined },
    { id: 'events', label: 'יומן' },
  ]

  return (
    <div dir="rtl" style={{ fontFamily: ADMIN_FONT, backgroundColor: T.bg }} className="bg-grid relative min-h-screen" data-vg-admin>
      <div className="hero-glow pointer-events-none absolute inset-x-0 top-0 h-72" />
      {/* pull-to-refresh indicator */}
      <div
        className="fixed left-1/2 -translate-x-1/2 z-30 flex items-center justify-center pointer-events-none"
        style={{ top: 8, opacity: refreshing ? 1 : Math.min(1, pull / 56) }}
      >
        <div className="flex items-center justify-center h-9 w-9 rounded-full" style={{ background: T.card, border: `1px solid ${T.separator}`, boxShadow: '0 4px 16px rgba(0,0,0,0.4)' }}>
          {refreshing ? (
            <RefreshCw size={17} className="animate-spin" style={{ color: T.accent }} />
          ) : (
            <ArrowDown size={17} style={{ color: T.accent, transform: `rotate(${Math.min(180, pull * 3)}deg)`, transition: 'transform .1s' }} />
          )}
        </div>
      </div>

      <div
        className="relative"
        style={{ transform: `translateY(${pull}px)`, transition: pull === 0 ? 'transform .3s cubic-bezier(.2,.8,.2,1)' : 'none' }}
      >
        <div className="max-w-3xl mx-auto px-4 pb-16 pt-3">
          {/* large title header */}
          <div className="flex items-end justify-between gap-3 mb-3">
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <VGuardsLogo size={18} />
                <span className="text-[13px] font-bold tracking-wide" style={{ color: T.accent }}>V-GUARDS</span>
              </div>
              <h1 className="text-[30px] font-bold leading-tight" style={{ color: T.label }}>לוח בקרה</h1>
            </div>
            <button onClick={signOut} className="text-[15px] pb-1" style={{ color: T.accent }}>
              יציאה
            </button>
          </div>

          {/* segmented tabs */}
          <div className="sticky top-2 z-20 mb-4">
            <Segmented tabs={TABS} value={tab} onChange={(v) => setTab(v)} />
          </div>

          {data?.error && <p className="text-[14px] mb-3" style={{ color: T.red }}>שגיאה: {data.error}</p>}
          {authError && authError !== 'הגישה נדחתה.' && <p className="text-[14px] mb-3" style={{ color: T.red }}>{authError}</p>}

          <AnimatePresence mode="wait">
            <motion.div
              key={tab}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18 }}
            >
              {tab === 'overview' && data?.kpis && <OverviewTab data={data} onKpi={openScansFiltered} />}
              {tab === 'scans' && data && (
                <ScansTab
                  scans={data.recentScans}
                  initialFilter={scanFilter}
                  onOpen={(row) => setSheet({ kind: 'scan', row })}
                />
              )}
              {tab === 'leads' && data && (
                <LeadsTab data={data} onStatus={setLeadStatus} onOpen={(row) => setSheet({ kind: 'lead', row })} />
              )}
              {tab === 'events' && <EventsTab secret={submittedSecret} turnstileToken={turnstileToken} />}
            </motion.div>
          </AnimatePresence>

          {!data && loading && <DashboardSkeleton />}
        </div>
      </div>

      {/* detail sheet */}
      <Sheet
        open={!!sheet}
        onClose={() => setSheet(null)}
        title={sheet?.kind === 'scan' ? 'פרטי סריקה' : sheet?.kind === 'lead' ? 'פרטי ליד' : ''}
      >
        {sheet?.kind === 'scan' && <ScanDetail row={sheet.row} />}
        {sheet?.kind === 'lead' && <LeadDetail row={sheet.row} onStatus={setLeadStatus} />}
      </Sheet>
    </div>
  )
}

// ─────────────────────────────────────────────────────────── Overview

function DashboardSkeleton() {
  const block = (h: number, w = '100%') => (
    <div className="animate-pulse rounded-2xl" style={{ height: h, width: w, background: T.card, border: `1px solid ${T.separator}` }} />
  )
  return (
    <div className="space-y-6">
      {block(118)}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i}>{block(96)}</div>
        ))}
      </div>
      {block(150)}
      {block(150)}
    </div>
  )
}

function OverviewTab({ data, onKpi }: { data: DashboardData; onKpi: (outcome: string) => void }) {
  const k = data.kpis
  const funnelMax = Math.max(1, ...FUNNEL_STEPS.map((s) => data.funnel[s.key] ?? 0))
  const gradeTotal = Math.max(1, Object.values(data.gradeDist).reduce((a, b) => a + b, 0))

  return (
    <div className="space-y-6">
      {/* hero: total scans + avg-score ring */}
      <div className="rounded-2xl p-5" style={{ background: T.card, border: `1px solid ${T.separator}` }}>
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <IconTile icon={ScanLine} size={24} />
              <span className="text-[13px] font-medium" style={{ color: T.label2 }}>סה"כ סריקות</span>
            </div>
            <div className="font-mono text-[42px] font-bold leading-none tabular-nums" style={{ color: T.label }}>
              {k.totalScans.toLocaleString('he-IL')}
            </div>
            <div className="flex items-center gap-2 mt-3">
              <span className="rounded-full px-2.5 py-1 text-[12px] tabular-nums" style={{ background: 'rgba(255,255,255,0.05)', color: T.label2 }}>
                24ש' · <b style={{ color: T.label }}>{k.scans24h}</b>
              </span>
              <span className="rounded-full px-2.5 py-1 text-[12px] tabular-nums" style={{ background: 'rgba(255,255,255,0.05)', color: T.label2 }}>
                7 ימים · <b style={{ color: T.label }}>{k.scans7d}</b>
              </span>
            </div>
          </div>
          <div className="flex flex-col items-center gap-1.5 shrink-0">
            <ScoreRing score={k.avgScore} />
            <span className="text-[11px]" style={{ color: T.label3 }}>ציון ממוצע</span>
          </div>
        </div>
      </div>

      {/* KPI grid with icon tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
        <KpiTile label="דומיינים ייחודיים" value={k.uniqueHosts} icon={Globe} />
        <KpiTile label="דומיינים מאומתים" value={k.verifiedDomains} accent={T.accent} icon={BadgeCheck} />
        <KpiTile label="לידים" value={data.leads.length} accent={T.accent} icon={Inbox} />
        <KpiTile label="סריקות מוצלחות" value={k.successCount} icon={CheckCircle2} onPress={() => onKpi('success')} />
        <KpiTile label="נחסמו ע״י WAF" value={k.wafBlocked} sub={`${k.stealthRescued} חולצו`} icon={ShieldCheck} onPress={() => onKpi('blocked_by_waf')} />
        <KpiTile label="סריקות שנכשלו" value={k.failCount} icon={Ban} onPress={() => onKpi('')} />
      </div>

      <ListGroup header="משפך המרה" icon={Filter}>
        <div className="px-4 py-3.5 space-y-3">
          {FUNNEL_STEPS.map((s) => {
            const v = data.funnel[s.key] ?? 0
            return (
              <div key={s.key}>
                <div className="flex justify-between text-[13px] mb-1.5">
                  <span style={{ color: T.label2 }}>{s.label}</span>
                  <span className="tabular-nums font-semibold" style={{ color: T.label }}>{v.toLocaleString('he-IL')}</span>
                </div>
                <Bar value={v} max={funnelMax} color={T.accentFill} />
              </div>
            )
          })}
        </div>
      </ListGroup>

      <ListGroup header="התפלגות ציונים" footer="סריקות מוצלחות בלבד" icon={BarChart3}>
        <div className="px-4 py-3.5 space-y-2.5">
          {(['A', 'B', 'C', 'D', 'F'] as const).map((g) => {
            const v = data.gradeDist[g] ?? 0
            return (
              <div key={g} className="flex items-center gap-3">
                <span className="w-5 text-[15px] font-bold" style={{ color: T.label }}>{g}</span>
                <div className="flex-1">
                  <Bar value={v} max={gradeTotal} color={T.accent} />
                </div>
                <span className="w-9 text-left text-[13px] tabular-nums" style={{ color: T.label2 }}>{v}</span>
              </div>
            )
          })}
        </div>
      </ListGroup>

      {data.topFindings.length > 0 && (
        <ListGroup header="הממצאים הנפוצים ביותר" icon={TriangleAlert}>
          {data.topFindings.map((f, i) => (
            <Cell
              key={i}
              last={i === data.topFindings.length - 1}
              leading={<span className="block h-2.5 w-2.5 rounded-full" style={{ background: SEV_COLOR[f.severity] ?? T.label4 }} />}
              title={f.title}
              trailing={<span className="tabular-nums">{f.count}</span>}
            />
          ))}
        </ListGroup>
      )}

      <div className="grid sm:grid-cols-2 gap-5">
        <ListGroup header="מדינות" icon={Globe}>
          {(data.countries.length ? data.countries.slice(0, 6) : [{ key: '—', count: 0 }]).map((c, i, arr) => (
            <Cell key={c.key} last={i === arr.length - 1} title={c.key} trailing={<span className="tabular-nums">{c.count}</span>} />
          ))}
        </ListGroup>
        <ListGroup header="ספקי WAF" icon={ShieldCheck}>
          {(data.wafVendors.length ? data.wafVendors.slice(0, 6) : [{ key: '—', count: 0 }]).map((w, i, arr) => (
            <Cell key={w.key} last={i === arr.length - 1} title={w.key} trailing={<span className="tabular-nums">{w.count}</span>} />
          ))}
        </ListGroup>
      </div>

      <ListGroup header="דומיינים שנסרקו הכי הרבה" icon={Activity} footer={k.aggCapped ? 'נתונים מצרפיים מבוססים על 5,000 הרשומות האחרונות' : undefined}>
        {data.topHosts.map((h, i) => (
          <Cell
            key={h.hostname}
            last={i === data.topHosts.length - 1}
            title={<span className="font-medium">{h.hostname}</span>}
            subtitle={`${h.scans} סריקות · ${fmt(h.lastAt)}`}
            trailing={<ScoreBadge score={h.lastScore} />}
            onPress={() => window.open(`https://v-guards.com/?url=${encodeURIComponent('https://' + h.hostname)}`, '_blank')}
          />
        ))}
      </ListGroup>
    </div>
  )
}

// ─────────────────────────────────────────────────────────── Scans

function ScansTab({
  scans,
  initialFilter,
  onOpen,
}: {
  scans: ScanRow[]
  initialFilter: string
  onOpen: (row: ScanRow) => void
}) {
  const [q, setQ] = useState('')
  const [outcome, setOutcome] = useState(initialFilter)
  useEffect(() => {
    setOutcome(initialFilter)
  }, [initialFilter])

  const filtered = useMemo(
    () =>
      scans.filter((s) => {
        if (q && !s.hostname.toLowerCase().includes(q.toLowerCase())) return false
        if (outcome && s.scan_outcome !== outcome) return false
        return true
      }),
    [scans, q, outcome],
  )

  return (
    <div className="space-y-3">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="חיפוש דומיין…"
        className="w-full rounded-xl px-4 py-2.5 text-[15px] focus:outline-none"
        style={{ background: T.card, border: `1px solid ${T.separator}`, color: T.label }}
      />
      <div className="flex gap-2 overflow-x-auto pb-1 -mx-4 px-4">
        {[
          { v: '', l: 'הכל' },
          { v: 'success', l: 'הצליחו' },
          { v: 'blocked_by_waf', l: 'WAF' },
          { v: 'blocked_by_target', l: 'נדחו' },
          { v: 'unreachable', l: 'לא נגישים' },
        ].map((o) => {
          const sel = outcome === o.v
          return (
            <button
              key={o.v || 'all'}
              onClick={() => setOutcome(o.v)}
              className="shrink-0 rounded-full px-3.5 py-1.5 text-[13px] font-medium transition-colors"
              style={{
                background: sel ? T.accentFill : T.card,
                color: sel ? T.onAccent : T.label2,
                border: `1px solid ${sel ? T.accentFill : T.separator}`,
              }}
            >
              {o.l}
            </button>
          )
        })}
      </div>

      <div className="text-[13px]" style={{ color: T.label3 }}>{filtered.length} סריקות</div>

      <ListGroup>
        {filtered.length === 0 ? (
          <Cell last title={<span style={{ color: T.label3 }}>אין סריקות תואמות</span>} />
        ) : (
          filtered.map((s, i) => (
            <Cell
              key={s.id}
              last={i === filtered.length - 1}
              onPress={() => onOpen(s)}
              leading={
                <span
                  className="block h-2.5 w-2.5 rounded-full"
                  style={{ background: s.scan_outcome === 'success' ? (s.top_finding_severity ? SEV_COLOR[s.top_finding_severity] : T.accent) : T.label4 }}
                />
              }
              title={<span className="font-medium">{s.hostname}</span>}
              subtitle={
                s.scan_outcome === 'success'
                  ? s.top_finding_title ?? 'נקי — אין ממצאים'
                  : OUTCOME_LABEL[s.scan_outcome ?? ''] ?? s.scan_outcome ?? ''
              }
              trailing={s.scan_outcome === 'success' ? <ScoreBadge score={s.vibe_score} /> : undefined}
            />
          ))
        )}
      </ListGroup>
    </div>
  )
}

function ScanDetail({ row }: { row: ScanRow }) {
  return (
    <>
      <ListGroup>
        <Cell title="דומיין" trailing={<span className="font-medium" dir="ltr">{row.hostname}</span>} />
        <Cell
          title="תוצאה"
          trailing={
            <span style={{ color: row.scan_outcome === 'success' ? T.accent : T.label4 }}>
              {OUTCOME_LABEL[row.scan_outcome ?? ''] ?? row.scan_outcome}
            </span>
          }
        />
        {row.scan_outcome === 'success' && <Cell title="ציון" trailing={<ScoreBadge score={row.vibe_score} />} />}
        {row.top_finding_title && (
          <Cell
            title="ממצא מוביל"
            subtitle={row.top_finding_title}
            align="start"
            leading={<span className="block h-2.5 w-2.5 rounded-full mt-1.5" style={{ background: SEV_COLOR[row.top_finding_severity ?? 'info'] }} />}
          />
        )}
        <Cell title="ספק WAF" trailing={row.waf_vendor ?? '—'} />
        <Cell title="מדינה" trailing={row.country ?? '—'} />
        <Cell title="זמן" trailing={fmt(row.scanned_at)} last />
      </ListGroup>
      <a
        href={`https://v-guards.com/?url=${encodeURIComponent('https://' + row.hostname)}`}
        target="_blank"
        rel="noreferrer"
        className="block w-full rounded-xl py-3.5 text-center text-[16px] font-semibold active:scale-[0.98] transition-transform"
        style={{ background: T.accentFill }}
      >
        סרוק מחדש
      </a>
    </>
  )
}

// ─────────────────────────────────────────────────────────── Leads

function LeadsTab({
  data,
  onStatus,
  onOpen,
}: {
  data: DashboardData
  onStatus: (id: number, s: Lead['status']) => void
  onOpen: (row: Lead) => void
}) {
  const [source, setSource] = useState('')
  const [showArchived, setShowArchived] = useState(false)
  const filtered = data.leads.filter((l) => {
    if (source && l.source !== source) return false
    if (!showArchived && l.status === 'archived') return false
    return true
  })

  return (
    <div className="space-y-4">
      {data.leadsTableMissing && (
        <div className="rounded-2xl p-4 text-[13px] leading-relaxed" style={{ background: T.accentSoft, color: T.label2, border: `1px solid ${T.separator}` }}>
          טבלת הלידים (vs_leads) עדיין לא קיימת ב-Supabase. הריצו את המיגרציה
          <span className="font-mono"> 0002_vs_leads.sql</span> כדי להתחיל לאסוף פניות ואימותים. עד אז מוצגים רק הדומיינים המאומתים מטה.
        </div>
      )}

      <div className="flex items-center gap-2 overflow-x-auto pb-1 -mx-4 px-4">
        {[
          { v: '', l: 'כל המקורות' },
          { v: 'contact', l: 'יצירת קשר' },
          { v: 'verify', l: 'אימות בעלות' },
        ].map((o) => {
          const sel = source === o.v
          return (
            <button
              key={o.v || 'all'}
              onClick={() => setSource(o.v)}
              className="shrink-0 rounded-full px-3.5 py-1.5 text-[13px] font-medium"
              style={{ background: sel ? T.accentFill : T.card, color: sel ? T.onAccent : T.label2, border: `1px solid ${sel ? T.accentFill : T.separator}` }}
            >
              {o.l}
            </button>
          )
        })}
        <button
          onClick={() => setShowArchived((s) => !s)}
          className="shrink-0 rounded-full px-3.5 py-1.5 text-[13px] font-medium"
          style={{ background: showArchived ? T.accentFill : T.card, color: showArchived ? T.onAccent : T.label2, border: `1px solid ${showArchived ? T.accentFill : T.separator}` }}
        >
          מאורכבים
        </button>
      </div>

      {/* leads — swipe to reveal quick actions, tap to open detail */}
      <div className="space-y-2">
        {filtered.map((l) => (
          <SwipeRow
            key={l.id}
            actions={[
              { label: 'נקרא', color: T.accentFill, textColor: T.onAccent, onPress: () => onStatus(l.id, 'read') },
              { label: 'ארכב', color: '#3a3a44', onPress: () => onStatus(l.id, 'archived') },
            ]}
          >
            <button onClick={() => onOpen(l)} className="block w-full text-right px-4 py-3.5 active:bg-white/[0.04]">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className="text-[11px] font-semibold rounded-full px-2 py-0.5" style={{ color: T.accent, background: T.accentSoft }}>
                  {SOURCE_LABEL[l.source]}
                </span>
                <span className="text-[11px] font-semibold rounded-full px-2 py-0.5" style={{ color: STATUS_COLOR[l.status], background: `${STATUS_COLOR[l.status]}1f` }}>
                  {STATUS_LABEL[l.status]}
                </span>
                {l.source === 'verify' && l.verified !== null && (
                  <span className="text-[11px] font-semibold" style={{ color: l.verified ? T.accent : T.label4 }}>
                    {l.verified ? 'מאומת' : 'לא מאומת'}
                  </span>
                )}
                <span className="text-[11px] mr-auto" style={{ color: T.label4 }}>{fmt(l.created_at)}</span>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {l.name && <span className="text-[15px] font-semibold" style={{ color: T.label }}>{l.name}</span>}
                <span className="text-[14px]" dir="ltr" style={{ color: T.accent }}>{l.email}</span>
              </div>
              {l.domain && <div className="text-[13px] mt-0.5" dir="ltr" style={{ color: T.label3 }}>{l.domain}</div>}
              {l.message && <p className="text-[13px] mt-1 line-clamp-2" style={{ color: T.label2 }}>{l.message}</p>}
            </button>
          </SwipeRow>
        ))}
        {filtered.length === 0 && !data.leadsTableMissing && (
          <p className="text-center py-10 text-[15px]" style={{ color: T.label3 }}>אין לידים עדיין</p>
        )}
      </div>

      <ListGroup header="דומיינים מאומתים" icon={BadgeCheck} footer="הוכיחו בעלות לסריקת Stage 3">
        {data.verified.length === 0 ? (
          <Cell last title={<span style={{ color: T.label3 }}>אין דומיינים מאומתים עדיין</span>} />
        ) : (
          data.verified.map((v, i) => (
            <Cell
              key={v.domain}
              last={i === data.verified.length - 1}
              title={<span className="font-medium" dir="ltr">{v.domain}</span>}
              subtitle={`${v.email ? v.email + ' · ' : ''}${(v.method ?? '').toUpperCase()} · אומת ${fmtDate(v.verified_at)} · ${v.scan_count ?? 0} סריקות`}
              onPress={() => window.open(`https://v-guards.com/?url=${encodeURIComponent('https://' + v.domain)}`, '_blank')}
            />
          ))
        )}
      </ListGroup>
    </div>
  )
}

function LeadDetail({ row, onStatus }: { row: Lead; onStatus: (id: number, s: Lead['status']) => void }) {
  return (
    <>
      <ListGroup>
        <Cell title="מקור" trailing={SOURCE_LABEL[row.source]} />
        <Cell title="סטטוס" trailing={<span style={{ color: STATUS_COLOR[row.status] }}>{STATUS_LABEL[row.status]}</span>} />
        {row.name && <Cell title="שם" trailing={<span className="font-medium">{row.name}</span>} />}
        <Cell title="מייל" trailing={<a href={`mailto:${row.email}`} dir="ltr" style={{ color: T.accent }}>{row.email}</a>} />
        {row.domain && <Cell title="דומיין" trailing={<span dir="ltr">{row.domain}</span>} />}
        {row.source === 'verify' && row.verified !== null && (
          <Cell title="אומת" trailing={<span style={{ color: row.verified ? T.accent : T.label4 }}>{row.verified ? 'כן' : 'לא'}</span>} />
        )}
        <Cell title="זמן" trailing={fmt(row.created_at)} last={!row.message} />
        {row.message && <Cell title="הודעה" subtitle={row.message} align="start" last />}
      </ListGroup>

      <div className="grid grid-cols-3 gap-2">
        {(['read', 'replied', 'archived'] as const).map((s) => (
          <button
            key={s}
            onClick={() => onStatus(row.id, s)}
            disabled={row.status === s}
            className="rounded-xl py-3 text-[14px] font-semibold active:scale-95 transition-transform disabled:opacity-40"
            style={{ background: T.card, color: T.accent, border: `1px solid ${T.separator}` }}
          >
            {STATUS_LABEL[s]}
          </button>
        ))}
      </div>
      <a
        href={`mailto:${row.email}`}
        className="block w-full rounded-xl py-3.5 text-center text-[16px] font-semibold active:scale-[0.98] transition-transform"
        style={{ background: T.accentFill }}
      >
        שלח מייל
      </a>
    </>
  )
}

// ─────────────────────────────────────────────────────────── Events

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

function EventsTab({ secret, turnstileToken }: { secret: string; turnstileToken: string }) {
  const [eventType, setEventType] = useState('')
  const [rows, setRows] = useState<AuditRow[]>([])
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const fetchLogs = useCallback(async () => {
    if (secret === 'preview') {
      setRows([])
      return
    }
    setLoading(true)
    setErr('')
    try {
      const p = new URLSearchParams()
      if (eventType) p.set('event_type', eventType)
      p.set('limit', '200')
      const headers: Record<string, string> = { 'x-admin-secret': secret }
      const u = localStorage.getItem('vg_admin_user')
      if (u) headers['x-admin-user'] = u
      if (turnstileToken) headers['x-turnstile-token'] = turnstileToken
      const r = await fetch(`/api/admin/logs?${p.toString()}`, { headers })
      if (!r.ok) {
        setErr(r.status === 429 ? 'יותר מדי בקשות.' : 'הגישה נדחתה.')
        return
      }
      const j = (await r.json()) as { logs?: AuditRow[]; error?: string }
      setRows(j.logs ?? [])
      if (j.error) setErr(j.error)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'שגיאה')
    } finally {
      setLoading(false)
    }
  }, [eventType, secret, turnstileToken])

  useEffect(() => {
    fetchLogs()
  }, [fetchLogs])

  return (
    <div className="space-y-3">
      <div className="flex gap-2 overflow-x-auto pb-1 -mx-4 px-4">
        {EVENT_TYPES.map((t) => {
          const sel = eventType === t
          return (
            <button
              key={t || 'all'}
              onClick={() => setEventType(t)}
              className="shrink-0 rounded-full px-3.5 py-1.5 text-[13px] font-medium whitespace-nowrap"
              style={{ background: sel ? T.accentFill : T.card, color: sel ? T.onAccent : T.label2, border: `1px solid ${sel ? T.accentFill : T.separator}` }}
            >
              {t || 'הכל'}
            </button>
          )
        })}
      </div>

      <div className="text-[13px]" style={{ color: T.label3 }}>
        {loading ? 'טוען…' : `${rows.length} אירועים`}
        {err && <span style={{ color: T.red }}> · {err}</span>}
      </div>

      <ListGroup footer="ערכים רגישים (עוגיות, טוקנים, IP גולמי) לעולם לא נשמרים.">
        {rows.length === 0 ? (
          <Cell last title={<span style={{ color: T.label3 }}>{loading ? 'טוען…' : 'אין אירועים תואמים'}</span>} />
        ) : (
          rows.map((r, i) => (
            <Cell
              key={r.id}
              last={i === rows.length - 1}
              title={<span className="font-medium">{r.event_type}</span>}
              subtitle={r.scanned_url ?? r.path ?? '—'}
              trailing={
                <span className="text-[12px] tabular-nums" style={{ color: T.label3 }}>
                  {r.vibe_score != null ? `${r.vibe_score} · ` : ''}
                  {fmt(r.created_at)}
                </span>
              }
            />
          ))
        )}
      </ListGroup>
    </div>
  )
}
