import { useState, useEffect, useRef, type FormEvent } from 'react'
import {
  motion,
  AnimatePresence,
  useReducedMotion,
  useMotionValue,
  useTransform,
  animate,
} from 'framer-motion'
import {
  ArrowRight,
  ArrowLeft,
  Check,
  Copy,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  KeyRound,
  FileWarning,
  Sparkles,
  Database,
  Lock,
  Bot,
  Folder,
  FileCode,
  Cookie,
  Link2,
  ShieldAlert,
  Shield,
  Code,
  Globe,
  Mail,
  ArrowRightLeft,
  Loader2,
  type LucideIcon,
} from 'lucide-react'
import { VibeScoreGauge } from '@/components/ui/vibe-score-gauge'
import { NextStagesPanel, Stage2Modal } from '@/components/NextStagesPanel'
import type {
  Category,
  Finding as ApiFinding,
  ScanError,
  ScanResponse,
  ScanResult,
  Severity,
  WafVendor,
} from '@/lib/scanner-types'

const WAF_VENDOR_LABEL: Record<WafVendor, string> = {
  cloudflare: 'Cloudflare',
  akamai: 'Akamai',
  imperva: 'Imperva',
  fastly: 'Fastly',
  'aws-cloudfront': 'AWS CloudFront',
  'aws-waf': 'AWS WAF',
  'vercel-bot-protection': 'Vercel Bot Protection',
  sucuri: 'Sucuri',
  stackpath: 'StackPath',
  'ddos-guard': 'DDoS-Guard',
  unknown: 'WAF / firewall',
}

type ScanState = 'idle' | 'scanning' | 'result' | 'error'

interface StreamPhaseEvent {
  type: 'phase'
  step: number
  total: number
  name: string
  label: string
}
type StreamEvent = StreamPhaseEvent | { type: 'result'; result: ScanResponse }

/**
 * Consume the NDJSON stream from /api/scan-stream, dispatching each event
 * to the supplied callbacks. Resolves when the stream closes (after the
 * `result` event); rejects on network/abort errors.
 */
async function consumeScanStream(
  url: string,
  signal: AbortSignal,
  onPhase: (e: StreamPhaseEvent) => void,
  onResult: (r: ScanResponse) => void,
): Promise<void> {
  const resp = await fetch('/api/scan-stream', {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`)
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      const t = line.trim()
      if (!t) continue
      try {
        const ev = JSON.parse(t) as StreamEvent
        if (ev.type === 'phase') onPhase(ev)
        else if (ev.type === 'result') onResult(ev.result)
      } catch {
        // Malformed line — ignore, the scan can still complete with the next event.
      }
    }
  }
  if (buffer.trim()) {
    try {
      const ev = JSON.parse(buffer.trim()) as StreamEvent
      if (ev.type === 'result') onResult(ev.result)
    } catch {
      // ignore trailing partial
    }
  }
}

const SCAN_STEPS = [
  'Resolving DNS & TLS handshake',
  'Fetching response headers',
  'Inspecting CSP, HSTS, X-Frame-Options',
  'Probing JS bundles for hardcoded secrets',
  'Checking for exposed source maps',
  'Path probing — .git, .env, .DS_Store',
  'Decoding JWTs for service-role keys',
  'Compiling report',
]

const CATEGORY_META: Record<Category, { label: string; Icon: LucideIcon }> = {
  secrets: { label: 'Secrets & API keys', Icon: KeyRound },
  auth: { label: 'Auth & sessions', Icon: ShieldCheck },
  'auth-enum': { label: 'User enumeration', Icon: ShieldCheck },
  'auth-weak': { label: 'Auth weaknesses', Icon: ShieldCheck },
  'auth-disclosure': { label: 'Auth info disclosure', Icon: ShieldCheck },
  headers: { label: 'HTTP security headers', Icon: FileWarning },
  paths: { label: 'Exposed paths', Icon: Folder },
  sourcemaps: { label: 'Source maps', Icon: FileCode },
  tls: { label: 'Transport & TLS', Icon: Lock },
  cookies: { label: 'Cookies & sessions', Icon: Cookie },
  integrity: { label: 'Subresource integrity', Icon: ShieldAlert },
  'mixed-content': { label: 'Mixed content', Icon: Link2 },
  html: { label: 'HTML hygiene', Icon: Code },
  dns: { label: 'DNS & domain', Icon: Globe },
  email: { label: 'Email auth (SPF / DMARC)', Icon: Mail },
  methods: { label: 'HTTP methods', Icon: ArrowRightLeft },
  ai: { label: 'AI surfaces & prompt injection', Icon: Sparkles },
  deps: { label: 'Dependencies & CVEs', Icon: Bot },
  meta: { label: 'Scan metadata', Icon: Database },
}

/**
 * Minimum wall-clock duration of the scanning UI. Even when the API resolves
 * faster, we hold the visualization for this long so users see the step-list
 * progression and percentage climb. Longer than this, we wait for the API.
 */
const MIN_SCAN_VISUAL_MS = 4200

function normalizeUrl(input: string): string {
  const trimmed = input.trim()
  if (!trimmed) return ''
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  return `https://${trimmed}`
}

function severityColor(s: Severity) {
  if (s === 'critical') return 'var(--color-danger)'
  if (s === 'warn') return 'var(--color-warning)'
  if (s === 'info') return 'var(--color-fg-muted)'
  return 'var(--color-ok)'
}

function severityMuted(s: Severity) {
  if (s === 'critical') return 'var(--color-danger-muted)'
  if (s === 'warn') return 'var(--color-warning-muted)'
  if (s === 'info') return 'rgba(192, 192, 200, 0.08)'
  return 'rgba(74, 222, 128, 0.1)'
}

function severityLabel(s: Severity) {
  if (s === 'critical') return 'critical'
  if (s === 'warn') return 'warning'
  if (s === 'info') return 'improve'
  return 'clean'
}

function severityTooltip(s: Severity) {
  if (s === 'critical') return 'Active vulnerability — fix now before deploy.'
  if (s === 'warn') return 'Real hardening gap — fix this week.'
  if (s === 'info') return 'Defense-in-depth recommendation. Not a current vulnerability — fix at your pace.'
  return 'Clean — verified working.'
}

function CircleProgress({ progress, reduceMotion }: { progress: number; reduceMotion: boolean }) {
  const size = 184
  const stroke = 6
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - progress)
  const targetPct = Math.round(progress * 100)

  // Smooth animated counter
  const displayCount = useMotionValue(0)
  const displayText = useTransform(displayCount, (v) => Math.round(v).toString())

  useEffect(() => {
    const controls = animate(displayCount, targetPct, {
      duration: reduceMotion ? 0 : 0.45,
      ease: 'easeOut',
    })
    return controls.stop
  }, [displayCount, reduceMotion, targetPct])

  return (
    <div
      className="relative"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Analysis progress: ${targetPct} percent`}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden="true">
        <defs>
          <linearGradient id="scan-progress-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--color-accent)" />
            <stop offset="100%" stopColor="var(--color-accent-strong)" />
          </linearGradient>
        </defs>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="var(--color-border)"
          strokeWidth={stroke}
          fill="none"
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="url(#scan-progress-grad)"
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: reduceMotion ? 0 : 0.4, ease: [0.16, 1, 0.3, 1] }}
          style={{ filter: 'drop-shadow(0 0 14px rgba(34, 211, 238, 0.55))' }}
        />
        {/* Subtle outer ring pulse */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius + 4}
          stroke="var(--color-accent)"
          strokeWidth={1}
          fill="none"
          opacity={0.18}
          animate={
            reduceMotion
              ? undefined
              : { opacity: [0.05, 0.25, 0.05], r: [radius + 2, radius + 8, radius + 2] }
          }
          transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="font-mono text-5xl font-semibold tabular-nums text-(--color-fg) leading-none">
          <motion.span>{displayText}</motion.span>
          <span className="text-(--color-fg-muted) text-3xl">%</span>
        </div>
        <div className="font-mono text-[10px] tracking-[0.25em] uppercase text-(--color-accent) mt-2">
          Analyzing
        </div>
      </div>
    </div>
  )
}

interface StepListProps {
  steps: string[]
  currentStep: number
  reduceMotion: boolean
}

function ScanStepList({ steps, currentStep, reduceMotion }: StepListProps) {
  return (
    <ul className="space-y-1.5 text-left">
      {steps.map((step, i) => {
        const isComplete = i < currentStep
        const isCurrent = i === currentStep
        const isPending = i > currentStep
        return (
          <li
            key={step}
            className="flex items-center gap-2.5 font-mono text-xs leading-tight"
          >
            <span
              className="flex items-center justify-center flex-shrink-0"
              style={{ width: 14, height: 14 }}
              aria-hidden="true"
            >
              {isComplete && (
                <motion.svg
                  width={14}
                  height={14}
                  viewBox="0 0 14 14"
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ duration: reduceMotion ? 0 : 0.25 }}
                >
                  <circle cx={7} cy={7} r={6} fill="var(--color-accent-muted)" stroke="var(--color-accent)" strokeWidth={1} />
                  <path
                    d="M4 7.2L6 9L10 5"
                    stroke="var(--color-accent)"
                    strokeWidth={1.5}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    fill="none"
                  />
                </motion.svg>
              )}
              {isCurrent && (
                <motion.span
                  className="block rounded-full"
                  style={{
                    width: 10,
                    height: 10,
                    background: 'var(--color-accent)',
                    boxShadow: '0 0 12px rgba(34, 211, 238, 0.7)',
                  }}
                  animate={
                    reduceMotion
                      ? undefined
                      : { scale: [0.8, 1.2, 0.8], opacity: [0.7, 1, 0.7] }
                  }
                  transition={{ duration: 1.2, repeat: Infinity, ease: 'easeInOut' }}
                />
              )}
              {isPending && (
                <span
                  className="block rounded-full"
                  style={{
                    width: 6,
                    height: 6,
                    background: 'var(--color-border-strong)',
                  }}
                />
              )}
            </span>
            <span
              className={
                isCurrent
                  ? 'text-(--color-fg) font-medium'
                  : isComplete
                    ? 'text-(--color-fg-muted) line-through-none'
                    : 'text-(--color-fg-dim)'
              }
            >
              {step}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

interface StageTrackerProps {
  stage1Done: boolean
  stage1DurationMs: number
  stage1FrameworkLabel: string | null
  stage2Status: Stage2Status
  stage2DurationMs?: number
  stage3Verified: boolean
}

function StageTracker({ stage1Done, stage1DurationMs, stage1FrameworkLabel, stage2Status, stage2DurationMs, stage3Verified }: StageTrackerProps) {
  const stage2Label = (() => {
    switch (stage2Status) {
      case 'idle': return 'Queued'
      case 'running': return 'Running headless browser…'
      case 'done': return `Done · ${stage2DurationMs ? `${(stage2DurationMs / 1000).toFixed(1)}s` : ''}`
      case 'failed': return 'Skipped (worker error)'
      case 'unavailable': return 'Skipped (not configured)'
    }
  })()
  const stage2State: 'pending' | 'running' | 'done' | 'skipped' = stage2Status === 'done'
    ? 'done'
    : stage2Status === 'running'
      ? 'running'
      : stage2Status === 'idle'
        ? 'pending'
        : 'skipped'

  return (
    <div className="rounded-lg border border-(--color-border) bg-(--color-surface-elevated) px-4 py-3 mb-4">
      <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mb-2">
        Scan stages
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3">
        {/* Stage 1 */}
        <div className="flex items-start gap-2">
          <span className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${stage1Done ? 'bg-(--color-accent) text-(--color-bg)' : 'bg-(--color-bg) text-(--color-fg-dim) border border-(--color-border)'}`}>
            {stage1Done ? <Check size={11} strokeWidth={3} /> : '1'}
          </span>
          <div className="min-w-0">
            <div className="font-mono text-xs text-(--color-fg) font-semibold leading-tight">Stage 1 · Passive</div>
            <div className="font-mono text-[11px] text-(--color-fg-muted) leading-snug">
              {stage1Done
                ? `Done · ${(stage1DurationMs / 1000).toFixed(1)}s${stage1FrameworkLabel ? ` · ${stage1FrameworkLabel}` : ''}`
                : 'Pending'}
            </div>
          </div>
        </div>
        {/* Stage 2 */}
        <div className="flex items-start gap-2">
          <span
            className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${stage2State === 'done' ? 'bg-(--color-accent) text-(--color-bg)' : stage2State === 'running' ? 'bg-(--color-warning) text-(--color-bg)' : stage2State === 'skipped' ? 'bg-(--color-bg) text-(--color-fg-dim) border border-(--color-border)' : 'bg-(--color-bg) text-(--color-fg-dim) border border-(--color-border)'}`}
            aria-hidden="true"
          >
            {stage2State === 'done' ? <Check size={11} strokeWidth={3} /> : stage2State === 'running' ? <Loader2 size={11} strokeWidth={2.5} className="animate-spin" /> : '2'}
          </span>
          <div className="min-w-0">
            <div className="font-mono text-xs text-(--color-fg) font-semibold leading-tight">Stage 2 · Browser-assisted</div>
            <div className="font-mono text-[11px] text-(--color-fg-muted) leading-snug">{stage2Label}</div>
          </div>
        </div>
        {/* Stage 3 */}
        <div className="flex items-start gap-2">
          <span className={`mt-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full font-mono text-[10px] font-bold flex-shrink-0 ${stage3Verified ? 'bg-(--color-accent) text-(--color-bg)' : 'bg-(--color-bg) text-(--color-fg-dim) border border-(--color-border)'}`}>
            {stage3Verified ? <Check size={11} strokeWidth={3} /> : <Lock size={10} strokeWidth={2.5} />}
          </span>
          <div className="min-w-0">
            <div className="font-mono text-xs text-(--color-fg) font-semibold leading-tight">Stage 3 · Verified deep</div>
            <div className="font-mono text-[11px] text-(--color-fg-muted) leading-snug">
              {stage3Verified ? 'Done · active probes ran' : 'Locked · verify ownership to unlock active probes'}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function buildBulkFixPrompt(result: ScanResult): string {
  const actionable = result.findings.filter((f) => f.fixPrompt && f.severity !== 'ok')
  if (actionable.length === 0) return ''

  const buckets: Record<'critical' | 'warn' | 'info', ApiFinding[]> = {
    critical: actionable.filter((f) => f.severity === 'critical'),
    warn: actionable.filter((f) => f.severity === 'warn'),
    info: actionable.filter((f) => f.severity === 'info'),
  }

  const fw = result.meta.detectedFramework ?? 'unknown — confirm via package.json'
  const rescanLink = `https://vguards.com/?url=${encodeURIComponent(result.meta.finalUrl)}`

  const lines: string[] = [
    `# 🛡️ Vguard — Bulk Fix Plan`,
    ``,
    `**Site:** ${result.meta.finalUrl}`,
    `**Detected stack:** ${fw}`,
    `**Vibe score:** ${result.vibeScore}/100`,
    `**To fix:** ${buckets.critical.length} critical · ${buckets.warn.length} warnings · ${buckets.info.length} improvements`,
    `**Total findings in this plan:** ${actionable.length}`,
    ``,
    `## Mission`,
    `Fix every finding listed below in priority order:`,
    `1. **All critical** first → redeploy → rescan. Confirm zero critical remain.`,
    `2. **All warnings** next → redeploy → rescan.`,
    `3. **All improvements** last → redeploy → rescan. Target: 100/100.`,
    ``,
    `Don't try to fix everything in one diff. Ship critical, verify, then move on.`,
    `Each finding below has its own evidence + per-stack instructions. Read them carefully — don't guess from the title.`,
    ``,
    `## Universal guardrails (apply to every finding)`,
    `- Don't disable a security check just to make the scan pass — fix the root cause.`,
    `- Don't commit secrets. If a key was leaked, **rotate it at the provider FIRST**, then edit the code.`,
    `- Use each finding's "Evidence" block to find the exact source line. The title alone is not enough.`,
    `- After each priority batch, redeploy and rescan: ${rescanLink}`,
    `- The scan is your acceptance test. A clean diff is not done; a clean rescan is.`,
    ``,
    `---`,
  ]

  const sectionFor = (label: string, severityIcon: string, items: ApiFinding[]) => {
    if (items.length === 0) return
    lines.push(``, `## ${severityIcon} ${label} (${items.length})`, ``)
    items.forEach((f, idx) => {
      lines.push(
        `### ${idx + 1}. ${f.title}`,
        `**Category:** ${f.category}`,
        ``,
        `**Evidence:**`,
        '```',
        f.evidence,
        '```',
        ``,
        `**Fix prompt (full per-stack instructions):**`,
        ``,
        f.fixPrompt,
        ``,
        `---`,
        ``,
      )
    })
  }

  sectionFor('Critical findings', '🔴', buckets.critical)
  sectionFor('Warnings', '🟠', buckets.warn)
  sectionFor('Improvements', '🟡', buckets.info)

  lines.push(
    ``,
    `## When you're done`,
    `Run a fresh scan: ${rescanLink}`,
    ``,
    `Target state:`,
    `- 0 critical, 0 warnings`,
    `- Vibe score ≥ 90/100`,
    `- Every finding above either gone or downgraded to "improvement" with explicit justification`,
    ``,
    `If you can't fix something (e.g. a third-party CDN you don't control), document why in the codebase (a comment near the relevant config) so the next scan run knows it's a known accepted risk.`,
  )

  return lines.join('\n')
}

async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-1000px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    let ok = false
    try {
      ok = document.execCommand('copy')
    } catch {
      ok = false
    }
    document.body.removeChild(ta)
    return ok
  }
}

function CopyAllFixPromptsButton({ result }: { result: ScanResult }) {
  const [copied, setCopied] = useState(false)
  const bulk = buildBulkFixPrompt(result)
  if (!bulk) return null
  const actionableCount = result.findings.filter((f) => f.fixPrompt && f.severity !== 'ok').length

  async function handleCopy() {
    const ok = await copyTextToClipboard(bulk)
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 2500)
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? 'All fix prompts copied to clipboard' : `Copy all ${actionableCount} fix prompts to clipboard as one bulk plan`}
      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
    >
      {copied ? (
        <>
          <Check size={13} strokeWidth={2.5} className="text-(--color-accent)" aria-hidden="true" />
          Copied · paste into Cursor / Claude
        </>
      ) : (
        <>
          <Copy size={13} strokeWidth={2} aria-hidden="true" />
          Copy all {actionableCount} fix prompts
        </>
      )}
    </button>
  )
}

/**
 * Surface the detected WAF / edge protection at the top of the result panel.
 * Two purposes:
 *   1. Show the user what's in front of their origin (informational — this is
 *      defense, not a problem).
 *   2. If the initial scan was blocked and the stealth retry rescued it, say
 *      so explicitly. Builds trust: the report covers the live site even
 *      though the WAF tried to deny us.
 */
function WafSurfacePanel({ surface }: { surface: NonNullable<ScanResult['attackSurface']> }) {
  const vendor = surface.wafVendor
  if (!vendor) return null
  const blocked = surface.wafBlocked === true
  const stealthOk = surface.stealthRetrySucceeded === true
  return (
    <div className="mb-3 px-3 py-2.5 rounded-md border border-amber-500/30 bg-amber-500/5 flex items-start gap-2.5">
      <Shield size={14} strokeWidth={2.5} className="text-amber-300 mt-0.5 flex-shrink-0" aria-hidden="true" />
      <div className="min-w-0 flex-1 text-xs leading-relaxed">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-[10px] uppercase tracking-widest text-amber-300/80">
            Edge protection detected
          </span>
          <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-200 font-mono text-[11px] font-semibold">
            {WAF_VENDOR_LABEL[vendor]}
          </span>
        </div>
        {blocked && stealthOk && (
          <p className="mt-1.5 text-(--color-fg-muted)">
            <span className="text-amber-200">Initial automated request was blocked, browser-like retry succeeded.</span>{' '}
            The findings below cover the live site — Vguard adapted by sending stealth headers (Sec-Ch-Ua + Sec-Fetch-*) on the second try.
          </p>
        )}
        {!blocked && (
          <p className="mt-1.5 text-(--color-fg-muted)">
            Detected from response headers — the scan was not blocked. Recorded in the attack surface map.
          </p>
        )}
      </div>
    </div>
  )
}

type ChipTone = 'default' | 'danger' | 'warn' | 'ok' | 'muted'
function FilterChip({
  label,
  count,
  active,
  onClick,
  tone = 'default',
}: {
  label: string
  count: number
  active: boolean
  onClick: () => void
  tone?: ChipTone
}) {
  const tones: Record<ChipTone, { active: string; idle: string }> = {
    default: {
      active: 'bg-(--color-accent) text-(--color-bg) border-transparent',
      idle: 'bg-(--color-surface) text-(--color-fg-muted) border-(--color-border) hover:border-(--color-accent-border) hover:text-(--color-fg)',
    },
    danger: {
      active: 'bg-(--color-danger) text-white border-transparent',
      idle: 'bg-(--color-surface) text-(--color-danger) border-(--color-danger)/30 hover:border-(--color-danger)',
    },
    warn: {
      active: 'bg-amber-500 text-black border-transparent',
      idle: 'bg-(--color-surface) text-amber-300 border-amber-500/30 hover:border-amber-400',
    },
    ok: {
      active: 'bg-emerald-500 text-black border-transparent',
      idle: 'bg-(--color-surface) text-emerald-300 border-emerald-500/30 hover:border-emerald-400',
    },
    muted: {
      active: 'bg-(--color-fg-muted) text-(--color-bg) border-transparent',
      idle: 'bg-(--color-surface) text-(--color-fg-dim) border-(--color-border) hover:text-(--color-fg-muted)',
    },
  }
  const cls = active ? tones[tone].active : tones[tone].idle
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`inline-flex items-center gap-1.5 px-2.5 h-7 rounded-full border font-mono text-[11px] uppercase tracking-wider transition-colors cursor-pointer ${cls}`}
    >
      {label}
      <span className={`tabular-nums ${active ? 'opacity-90' : 'opacity-60'}`}>{count}</span>
    </button>
  )
}

function FindingCard({ finding }: { finding: ApiFinding }) {
  const [copied, setCopied] = useState(false)
  const meta = CATEGORY_META[finding.category]
  const color = severityColor(finding.severity)
  const muted = severityMuted(finding.severity)
  const Icon = meta.Icon

  async function handleCopy() {
    if (!finding.fixPrompt) return
    let ok = false
    try {
      await navigator.clipboard.writeText(finding.fixPrompt)
      ok = true
    } catch {
      const ta = document.createElement('textarea')
      ta.value = finding.fixPrompt
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.top = '-1000px'
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
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <motion.li
      variants={{
        hidden: { opacity: 0, y: 8 },
        show: { opacity: 1, y: 0 },
      }}
      transition={{ duration: 0.3 }}
      className="px-6 py-5 border-b border-(--color-border) last:border-b-0"
    >
      <div className="flex items-start gap-3">
        <span
          className="flex items-center justify-center w-9 h-9 rounded-md flex-shrink-0 mt-0.5"
          style={{ background: muted, color }}
          aria-hidden="true"
        >
          <Icon size={17} strokeWidth={2} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <span
              className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded border cursor-help"
              style={{ color, borderColor: color, background: muted }}
              title={severityTooltip(finding.severity)}
            >
              {severityLabel(finding.severity)}
            </span>
            <span className="font-mono text-[10px] text-(--color-fg-dim) tracking-widest uppercase">
              {meta.label}
            </span>
          </div>
          <h4 className="text-sm sm:text-base font-semibold text-(--color-fg) leading-snug">
            {finding.title}
          </h4>
          <p className="mt-1.5 text-sm text-(--color-fg-muted) leading-relaxed">
            {finding.description}
          </p>
          <div className="mt-3 font-mono text-[11px] text-(--color-fg-dim) bg-(--color-bg) border border-(--color-border) rounded-md px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all">
            {finding.evidence}
          </div>
          {finding.fixPrompt && (
            <button
              type="button"
              onClick={handleCopy}
              aria-label={copied ? 'Fix prompt copied to clipboard' : 'Copy fix prompt to clipboard'}
              className="mt-3 inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-bg) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
            >
              {copied ? (
                <>
                  <Check size={13} strokeWidth={2.5} className="text-(--color-accent)" aria-hidden="true" />
                  Copied · paste into Cursor / Claude
                </>
              ) : (
                <>
                  <Copy size={13} strokeWidth={2} aria-hidden="true" />
                  Copy fix prompt
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </motion.li>
  )
}

type Stage2Status = 'idle' | 'running' | 'done' | 'failed' | 'unavailable'
interface Stage2State {
  status: Stage2Status
  findings: ApiFinding[]
  cookieCount?: number
  networkRequestCount?: number
  durationMs?: number
  errorMessage?: string
}
const STAGE2_INITIAL: Stage2State = { status: 'idle', findings: [] }

const SEV_ORDER: Record<Severity, number> = { critical: 0, warn: 1, info: 2, ok: 3 }
function recomputeTotals(findings: ApiFinding[]): { critical: number; warn: number; info: number; ok: number } {
  return {
    critical: findings.filter((f) => f.severity === 'critical').length,
    warn: findings.filter((f) => f.severity === 'warn').length,
    info: findings.filter((f) => f.severity === 'info').length,
    ok: findings.filter((f) => f.severity === 'ok').length,
  }
}
function recomputeScore(t: { critical: number; warn: number; info: number }): number {
  return Math.max(0, 100 - t.critical * 20 - t.warn * 7 - t.info * 2)
}

export function ScanForm() {
  const reduceMotion = useReducedMotion() ?? false
  const [state, setState] = useState<ScanState>('idle')
  const [url, setUrl] = useState('')
  const [stepIdx, setStepIdx] = useState(0)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [stage2, setStage2] = useState<Stage2State>(STAGE2_INITIAL)
  const [errorMsg, setErrorMsg] = useState('')
  const [scanError, setScanError] = useState<ScanError | null>(null)
  const [stage2OpenStandalone, setStage2OpenStandalone] = useState(false)
  type FindingFilter =
    | { kind: 'all' }
    | { kind: 'severity'; value: Severity }
    | { kind: 'category'; value: Category }
  const [findingFilter, setFindingFilter] = useState<FindingFilter>({ kind: 'all' })
  const [livePhaseLabel, setLivePhaseLabel] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const stage2AbortRef = useRef<AbortController | null>(null)
  const apiDoneRef = useRef(false)

  // Step progression is now driven by the real /api/scan-stream NDJSON events.
  // Each `phase` event from the server bumps stepIdx; no fake timer needed.
  // We keep STEP_DURATION_MS only as a fallback hint (unused after this rewrite).

  // Auto-cascade Stage 1 -> Stage 2.
  // After Stage 1 result lands, kick off the browser-assisted scan in the background.
  // Don't run on Stage 3 results (those already include everything).
  useEffect(() => {
    if (state !== 'result') return
    if (!result) return
    if (result.stage === 3) return
    if (stage2.status !== 'idle') return

    setStage2({ status: 'running', findings: [] })
    stage2AbortRef.current?.abort()
    const controller = new AbortController()
    stage2AbortRef.current = controller

    fetch('/api/scan-browser-assisted', {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: result.meta.finalUrl,
        framework: result.meta.detectedFramework,
      }),
    })
      .then(async (resp) => {
        if (resp.status === 503) {
          setStage2({ status: 'unavailable', findings: [] })
          return
        }
        const data = await resp.json()
        if (!resp.ok || !data.ok) {
          setStage2({
            status: 'failed',
            findings: [],
            errorMessage: data?.error?.message ?? `Stage 2 failed (HTTP ${resp.status})`,
          })
          return
        }
        setStage2({
          status: 'done',
          findings: (data.findings ?? []) as ApiFinding[],
          cookieCount: data.cookieCount,
          networkRequestCount: data.networkRequestCount,
          durationMs: data.durationMs,
        })
      })
      .catch((e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        setStage2({
          status: 'failed',
          findings: [],
          errorMessage: e instanceof Error ? e.message : 'Network error',
        })
      })
  }, [state, result, stage2.status])

  async function handleScanSubmit(e: FormEvent) {
    e.preventDefault()
    const normalized = normalizeUrl(url)
    if (!normalized) return
    setUrl(normalized)
    setStepIdx(0)
    setErrorMsg('')
    setFindingFilter({ kind: 'all' })
    setResult(null)
    setStage2(STAGE2_INITIAL)
    stage2AbortRef.current?.abort()
    apiDoneRef.current = false
    setState('scanning')

    const startedAt = performance.now()
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      let receivedResult: ScanResponse | null = null
      await consumeScanStream(
        normalized,
        controller.signal,
        (phase) => {
          // Map server's 1-based step to client's 0-based stepIdx; clamp to
          // SCAN_STEPS length so the visual list never overflows.
          setStepIdx(Math.min(phase.step - 1, SCAN_STEPS.length - 1))
          setLivePhaseLabel(phase.label)
        },
        (data) => {
          receivedResult = data
        },
      )
      apiDoneRef.current = true
      if (!receivedResult) {
        // Stream closed without a result event — treat as network error.
        setErrorMsg('Scan stream ended without a result.')
        setScanError(null)
        setState('error')
        return
      }
      const data = receivedResult as ScanResponse
      if (!data.ok) {
        setErrorMsg(data.error.message)
        setScanError(data.error)
        setState('error')
        return
      }
      setResult(data)
      const elapsed = performance.now() - startedAt
      const wait = Math.max(0, MIN_SCAN_VISUAL_MS - elapsed)
      setTimeout(() => {
        setStepIdx(SCAN_STEPS.length)
        setLivePhaseLabel(null)
        setTimeout(() => setState('result'), 450)
      }, wait)
    } catch (e: unknown) {
      apiDoneRef.current = true
      const aborted = e instanceof DOMException && e.name === 'AbortError'
      if (aborted) return
      const msg = e instanceof Error ? e.message : 'Network error'
      setErrorMsg(msg)
      setScanError(null)
      setState('error')
    }
  }

  function rescan() {
    setStepIdx(0)
    setErrorMsg('')
    setScanError(null)
    setFindingFilter({ kind: 'all' })
    setStage2(STAGE2_INITIAL)
    stage2AbortRef.current?.abort()
    apiDoneRef.current = false
    setState('scanning')

    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    let receivedResult: ScanResponse | null = null
    consumeScanStream(
      url,
      controller.signal,
      (phase) => {
        setStepIdx(Math.min(phase.step - 1, SCAN_STEPS.length - 1))
        setLivePhaseLabel(phase.label)
      },
      (data) => {
        receivedResult = data
      },
    )
      .then(() => {
        apiDoneRef.current = true
        if (!receivedResult) {
          setErrorMsg('Scan stream ended without a result.')
          setScanError(null)
          setState('error')
          return
        }
        const data = receivedResult as ScanResponse
        if (!data.ok) {
          setErrorMsg(data.error.message)
          setScanError(data.error)
          setState('error')
          return
        }
        setResult(data)
        setStepIdx(SCAN_STEPS.length)
        setLivePhaseLabel(null)
        setTimeout(() => setState('result'), 350)
      })
      .catch((e) => {
        apiDoneRef.current = true
        const aborted = e instanceof DOMException && e.name === 'AbortError'
        if (aborted) return
        const msg = e instanceof Error ? e.message : 'Network error'
        setErrorMsg(msg)
        setScanError(null)
        setState('error')
      })
  }

  function reset() {
    abortRef.current?.abort()
    stage2AbortRef.current?.abort()
    setStage2(STAGE2_INITIAL)
    setUrl('')
    setStepIdx(0)
    setErrorMsg('')
    setScanError(null)
    setFindingFilter({ kind: 'all' })
    setResult(null)
    apiDoneRef.current = false
    setState('idle')
  }

  const progress = Math.min(stepIdx / SCAN_STEPS.length, 1)

  const inputClass =
    'w-full px-4 py-3.5 rounded-lg bg-(--color-surface) border text-(--color-fg) placeholder:text-(--color-fg-dim) font-mono text-sm focus:outline-none transition-colors min-h-[48px]'
  const buttonClass =
    'inline-flex items-center justify-center gap-2 px-5 py-3.5 rounded-lg bg-(--color-accent) text-(--color-bg) font-semibold text-sm hover:bg-(--color-accent-strong) active:scale-[0.98] transition-all cursor-pointer whitespace-nowrap min-h-[48px] disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100'

  return (
    <div className="w-full max-w-2xl">
      <AnimatePresence mode="wait">
        {state === 'idle' && (
          <motion.form
            key="idle"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
            onSubmit={handleScanSubmit}
            className="flex flex-col sm:flex-row gap-3 max-w-xl"
            aria-label="Scan your app for security issues"
          >
            <label htmlFor="scan-url" className="sr-only">
              Your app's URL
            </label>
            <input
              id="scan-url"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              required
              placeholder="https://your-app.vercel.app"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className={`${inputClass} flex-1 border-(--color-border) focus:border-(--color-accent-border)`}
            />
            <button type="submit" className={buttonClass}>
              Scan now
              <ArrowRight size={16} strokeWidth={2.5} aria-hidden="true" />
            </button>
          </motion.form>
        )}

        {state === 'scanning' && (
          <motion.div
            key="scanning"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
            className="rounded-xl bg-(--color-surface) border border-(--color-border) p-6 sm:p-8 max-w-2xl shadow-[0_0_60px_-20px_rgba(34,211,238,0.25)]"
            role="status"
            aria-live="polite"
            aria-busy="true"
          >
            <div className="mb-5 font-mono text-xs text-(--color-fg-dim) truncate flex items-center gap-1.5">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-(--color-accent) animate-pulse" aria-hidden="true" />
              <ArrowRight size={11} className="text-(--color-accent)" aria-hidden="true" />
              <span className="truncate">{url}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 sm:gap-8 items-center">
              <div className="flex justify-center sm:justify-start">
                <CircleProgress progress={progress} reduceMotion={reduceMotion} />
              </div>
              <div>
                <div className="font-mono text-[10px] tracking-[0.25em] uppercase text-(--color-fg-dim) mb-3 flex items-center justify-between">
                  <span>Probes</span>
                  <span className="tabular-nums text-(--color-accent)">
                    {Math.min(stepIdx, SCAN_STEPS.length)}/{SCAN_STEPS.length}
                  </span>
                </div>
                <ScanStepList
                  steps={SCAN_STEPS}
                  currentStep={Math.min(stepIdx, SCAN_STEPS.length)}
                  reduceMotion={reduceMotion}
                />
                {livePhaseLabel && (
                  <div className="mt-3 flex items-center gap-2 font-mono text-[11px] text-(--color-accent)">
                    <Loader2 size={12} className="animate-spin flex-shrink-0" aria-hidden="true" />
                    <span className="truncate">{livePhaseLabel}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="mt-5 pt-4 border-t border-(--color-border) flex items-start gap-2.5 text-xs text-(--color-fg-muted)">
              <Globe size={14} strokeWidth={2.25} className="text-(--color-accent) mt-0.5 flex-shrink-0" aria-hidden="true" />
              <p className="leading-relaxed">
                <span className="font-semibold text-(--color-fg)">Stage 2 (browser-assisted)</span> runs automatically right after — a real headless Chromium loads your page, captures live cookies, network calls, and runtime globals to catch the things a static probe can&apos;t.
              </p>
            </div>
          </motion.div>
        )}

        {state === 'error' && scanError?.code === 'blocked_by_waf' && (
          <motion.div
            key="error-waf"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="rounded-xl bg-(--color-surface) border border-amber-500/40 p-6 sm:p-8 max-w-xl"
            role="alert"
          >
            <div className="flex items-start gap-3">
              <span
                className="flex items-center justify-center w-10 h-10 rounded-md flex-shrink-0"
                style={{ background: 'rgba(245, 158, 11, 0.15)', color: 'rgb(245, 158, 11)' }}
                aria-hidden="true"
              >
                <ShieldAlert size={18} strokeWidth={2} />
              </span>
              <div className="min-w-0 flex-1">
                <h3 className="text-base font-semibold text-(--color-fg)">
                  Target denied automated access
                </h3>
                <p className="mt-1 text-sm text-(--color-fg-muted) leading-relaxed">
                  This isn&apos;t a Vguard failure — the target&apos;s edge protection blocked
                  our scanner&apos;s IP. Vercel Lambda IPs (where Vguard runs) are widely
                  flagged as automated traffic. Real browsers and your visitors aren&apos;t
                  affected.
                </p>
                <div className="mt-3 flex items-center gap-2 flex-wrap">
                  {scanError.wafVendor && (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono text-[11px] font-semibold">
                      <Shield size={11} strokeWidth={2.5} aria-hidden="true" />
                      {WAF_VENDOR_LABEL[scanError.wafVendor]}
                    </span>
                  )}
                  {typeof scanError.httpStatus === 'number' && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-(--color-surface-elevated) border border-(--color-border) text-(--color-fg-muted) font-mono text-[11px]">
                      HTTP {scanError.httpStatus}
                    </span>
                  )}
                </div>
                <p className="mt-3 font-mono text-xs text-(--color-fg-dim) truncate">{url}</p>
                <div className="mt-4 flex items-center gap-2 flex-wrap">
                  {scanError.suggestedAction === 'stage2-bookmarklet' && (
                    <button
                      type="button"
                      onClick={() => setStage2OpenStandalone(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
                    >
                      <Globe size={13} strokeWidth={2.5} aria-hidden="true" />
                      Run Stage 2 (browser-assisted)
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={rescan}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-surface) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg-muted) hover:text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  >
                    <RefreshCw size={13} strokeWidth={2.5} aria-hidden="true" />
                    Retry Stage 1
                  </button>
                  <button
                    type="button"
                    onClick={reset}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-surface) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg-muted) hover:text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  >
                    <ArrowLeft size={12} aria-hidden="true" />
                    Try another URL
                  </button>
                </div>
              </div>
            </div>
            <Stage2Modal
              open={stage2OpenStandalone}
              onClose={() => setStage2OpenStandalone(false)}
            />
          </motion.div>
        )}

        {state === 'error' && scanError?.code !== 'blocked_by_waf' && (
          <motion.div
            key="error"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="rounded-xl bg-(--color-surface) border border-(--color-danger)/40 p-6 sm:p-8 max-w-xl"
            role="alert"
          >
            <div className="flex items-start gap-3">
              <span
                className="flex items-center justify-center w-10 h-10 rounded-md flex-shrink-0"
                style={{ background: 'var(--color-danger-muted)', color: 'var(--color-danger)' }}
                aria-hidden="true"
              >
                <AlertTriangle size={18} strokeWidth={2} />
              </span>
              <div className="min-w-0 flex-1">
                <h3 className="text-base font-semibold text-(--color-fg)">Scan failed</h3>
                <p className="mt-1 text-sm text-(--color-fg-muted) leading-relaxed">{errorMsg}</p>
                <p className="mt-2 font-mono text-xs text-(--color-fg-dim) truncate">{url}</p>
                <div className="mt-4 flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={rescan}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
                  >
                    <RefreshCw size={13} strokeWidth={2.5} aria-hidden="true" />
                    Retry
                  </button>
                  <button
                    type="button"
                    onClick={reset}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-surface) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg-muted) hover:text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                  >
                    <ArrowLeft size={12} aria-hidden="true" />
                    Try another URL
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {state === 'result' && result && (() => {
          const mergedFindings: ApiFinding[] = [...result.findings, ...stage2.findings].slice().sort(
            (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
          )
          const displayTotals = recomputeTotals(mergedFindings)
          const displayScore = recomputeScore(displayTotals)
          const displayResult: ScanResult = {
            ...result,
            findings: mergedFindings,
            totals: displayTotals,
            vibeScore: displayScore,
          }
          // Filter chips: derive available severities/categories from actual
          // findings so we never show an empty chip.
          const presentSeverities = (['critical', 'warn', 'info', 'ok'] as Severity[]).filter((s) =>
            mergedFindings.some((f) => f.severity === s),
          )
          const presentCategories = Array.from(
            new Set(mergedFindings.map((f) => f.category)),
          ).sort() as Category[]
          const visibleFindings = mergedFindings.filter((f) => {
            if (findingFilter.kind === 'all') return true
            if (findingFilter.kind === 'severity') return f.severity === findingFilter.value
            return f.category === findingFilter.value
          })
          return (
          <motion.div
            key="result"
            id="vguard-report"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="rounded-xl bg-(--color-surface) border border-(--color-accent-border) overflow-hidden shadow-[0_0_40px_-12px_rgba(34,211,238,0.25)] scroll-mt-8"
            role="region"
            aria-label="Scan results"
          >
            <div className="px-4 sm:px-6 py-5 sm:py-8 border-b border-(--color-border) bg-(--color-surface-elevated)">
              <StageTracker
                stage1Done={true}
                stage1DurationMs={result.durationMs}
                stage1FrameworkLabel={result.meta.detectedFramework}
                stage2Status={stage2.status}
                stage2DurationMs={stage2.durationMs}
                stage3Verified={result.stage === 3}
              />
              {result.attackSurface?.wafVendor && (
                <WafSurfacePanel surface={result.attackSurface} />
              )}
              <div className="flex items-center gap-2 font-mono text-[10px] tracking-widest uppercase text-(--color-accent) mb-3">
                <Check size={12} strokeWidth={3} aria-hidden="true" />
                <span>
                  Vibe report
                  {result.meta.detectedFramework
                    ? ` · ${result.meta.detectedFramework}`
                    : ''}
                </span>
              </div>
              <div className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-5 sm:gap-6">
                <div className="min-w-0 flex-1">
                  <h3 className="text-xl sm:text-xl font-semibold leading-tight">Vibe report</h3>
                  <div className="mt-1 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) truncate max-w-full">
                    {result.meta.finalUrl}
                  </div>
                  <div className="mt-4 flex items-center gap-5 font-mono text-xs flex-wrap">
                    <span className="flex items-center gap-2" title={severityTooltip('critical')}>
                      <span
                        className="inline-block w-2 h-2 rounded-full"
                        style={{
                          background: 'var(--color-danger)',
                          boxShadow: '0 0 8px var(--color-danger)',
                        }}
                        aria-hidden="true"
                      />
                      <span className="text-(--color-fg-muted)">
                        <span className="text-(--color-fg) font-semibold">
                          {displayTotals.critical}
                        </span>{' '}
                        critical
                      </span>
                    </span>
                    <span className="flex items-center gap-2" title={severityTooltip('warn')}>
                      <span
                        className="inline-block w-2 h-2 rounded-full"
                        style={{
                          background: 'var(--color-warning)',
                          boxShadow: '0 0 8px var(--color-warning)',
                        }}
                        aria-hidden="true"
                      />
                      <span className="text-(--color-fg-muted)">
                        <span className="text-(--color-fg) font-semibold">{displayTotals.warn}</span>{' '}
                        warnings
                      </span>
                    </span>
                    {displayTotals.info > 0 && (
                      <span className="flex items-center gap-2" title={severityTooltip('info')}>
                        <span
                          className="inline-block w-2 h-2 rounded-full"
                          style={{
                            background: 'var(--color-fg-muted)',
                            boxShadow: '0 0 8px var(--color-fg-muted)',
                          }}
                          aria-hidden="true"
                        />
                        <span className="text-(--color-fg-muted)">
                          <span className="text-(--color-fg) font-semibold">
                            {displayTotals.info}
                          </span>{' '}
                          improvements
                        </span>
                      </span>
                    )}
                    <span className="flex items-center gap-2" title={severityTooltip('ok')}>
                      <span
                        className="inline-block w-2 h-2 rounded-full"
                        style={{
                          background: 'var(--color-ok)',
                          boxShadow: '0 0 8px var(--color-ok)',
                        }}
                        aria-hidden="true"
                      />
                      <span className="text-(--color-fg-muted)">
                        <span className="text-(--color-fg) font-semibold">{displayTotals.ok}</span>{' '}
                        clean
                      </span>
                    </span>
                  </div>
                  <div className="mt-3 font-mono text-[10px] text-(--color-fg-dim) leading-relaxed flex flex-wrap gap-x-4 gap-y-1">
                    <span><span className="text-(--color-danger)">●</span> critical = fix before deploy</span>
                    <span><span className="text-(--color-warning)">●</span> warning = fix this week</span>
                    <span><span className="text-(--color-fg-muted)">●</span> improve = hardening, not exploit</span>
                  </div>
                  {result.meta.bundlesFetched > 0 && (
                    <div className="mt-3 font-mono text-[11px] text-(--color-fg-dim)">
                      Scanned {result.meta.bundlesFetched} JS bundle
                      {result.meta.bundlesFetched === 1 ? '' : 's'} ·{' '}
                      {(result.meta.bundlesSizeBytes / 1024).toFixed(0)} KB
                    </div>
                  )}
                </div>
                <div className="flex-shrink-0 self-center sm:self-auto">
                  <VibeScoreGauge
                    score={displayScore}
                    size={typeof window !== 'undefined' && window.innerWidth < 640 ? 160 : 200}
                  />
                </div>
              </div>
            </div>

            {stage2.status === 'running' && (
              <div className="px-6 py-3 border-b border-(--color-border) bg-(--color-bg) flex items-center gap-2 font-mono text-[11px] text-(--color-fg-muted)">
                <Loader2 size={13} strokeWidth={2.5} className="animate-spin text-(--color-warning)" aria-hidden="true" />
                <span>Stage 2 in progress · launching a real headless browser to catch what only loads at runtime…</span>
              </div>
            )}
            {stage2.status === 'done' && stage2.findings.filter((f) => f.severity !== 'ok').length > 0 && (
              <div className="px-6 py-3 border-b border-(--color-border) bg-(--color-bg) flex items-center gap-2 font-mono text-[11px] text-(--color-fg-muted)">
                <Check size={13} strokeWidth={3} className="text-(--color-accent)" aria-hidden="true" />
                <span>
                  Stage 2 added {stage2.findings.filter((f) => f.severity !== 'ok').length} runtime finding
                  {stage2.findings.filter((f) => f.severity !== 'ok').length === 1 ? '' : 's'}
                  {stage2.cookieCount !== undefined ? ` · saw ${stage2.cookieCount} cookies` : ''}
                  {stage2.networkRequestCount !== undefined ? ` · ${stage2.networkRequestCount} network requests` : ''}
                </span>
              </div>
            )}

            {/* Filter chips — present severities first, then categories. Counts shown so users see how the filter narrows the list. */}
            {mergedFindings.length > 1 && (
              <div className="px-4 sm:px-6 py-3 border-b border-(--color-border) bg-(--color-bg) flex items-center gap-1.5 flex-wrap">
                <FilterChip
                  label="All"
                  count={mergedFindings.length}
                  active={findingFilter.kind === 'all'}
                  onClick={() => setFindingFilter({ kind: 'all' })}
                />
                {presentSeverities.map((sev) => (
                  <FilterChip
                    key={`sev-${sev}`}
                    label={sev[0].toUpperCase() + sev.slice(1)}
                    count={mergedFindings.filter((f) => f.severity === sev).length}
                    active={findingFilter.kind === 'severity' && findingFilter.value === sev}
                    tone={
                      sev === 'critical' ? 'danger' : sev === 'warn' ? 'warn' : sev === 'ok' ? 'ok' : 'muted'
                    }
                    onClick={() => setFindingFilter({ kind: 'severity', value: sev })}
                  />
                ))}
                <span className="text-(--color-fg-dim) text-[11px] mx-1 select-none">·</span>
                {presentCategories.map((cat) => (
                  <FilterChip
                    key={`cat-${cat}`}
                    label={cat}
                    count={mergedFindings.filter((f) => f.category === cat).length}
                    active={findingFilter.kind === 'category' && findingFilter.value === cat}
                    onClick={() => setFindingFilter({ kind: 'category', value: cat })}
                  />
                ))}
              </div>
            )}

            <motion.ul
              initial="hidden"
              animate="show"
              variants={{
                hidden: {},
                show: { transition: { staggerChildren: 0.05, delayChildren: 0.1 } },
              }}
              className="bg-(--color-surface)"
            >
              {visibleFindings.length === 0 ? (
                <li className="px-6 py-10 text-center text-(--color-fg-muted) text-sm">
                  No findings match this filter.{' '}
                  <button
                    type="button"
                    onClick={() => setFindingFilter({ kind: 'all' })}
                    className="text-(--color-accent) hover:underline cursor-pointer"
                  >
                    Show all
                  </button>
                </li>
              ) : (
                visibleFindings.map((f) => <FindingCard key={f.id} finding={f} />)
              )}
            </motion.ul>

            <div className="px-6 py-5 border-t border-(--color-border) bg-(--color-bg) flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-2 flex-wrap">
                <CopyAllFixPromptsButton result={displayResult} />
                <button
                  type="button"
                  onClick={rescan}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-accent) text-(--color-bg) hover:bg-(--color-accent-strong) font-mono text-xs font-semibold transition-colors cursor-pointer min-h-[36px]"
                >
                  <RefreshCw size={13} strokeWidth={2.5} aria-hidden="true" />
                  Rescan
                </button>
                <button
                  type="button"
                  onClick={reset}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-(--color-surface-elevated) hover:bg-(--color-surface) border border-(--color-border) hover:border-(--color-accent-border) text-(--color-fg-muted) hover:text-(--color-fg) font-mono text-xs transition-colors cursor-pointer min-h-[36px]"
                >
                  <ArrowLeft size={12} aria-hidden="true" />
                  Try another URL
                </button>
              </div>
              <p className="font-mono text-[10px] text-(--color-fg-dim) leading-relaxed">
                Paste each prompt back into Cursor / Claude / Lovable. Rescan to prove it's fixed.
              </p>
            </div>

            <div className="px-6 pb-6">
              <NextStagesPanel
                scannedUrl={result.meta.finalUrl}
                stage2Status={stage2.status}
                stage2FindingCount={stage2.findings.filter((f) => f.severity !== 'ok').length}
                stage3Done={result.stage === 3}
                onDeepScanComplete={(deep) => setResult(deep)}
              />
            </div>
          </motion.div>
          )
        })()}
      </AnimatePresence>
    </div>
  )
}
