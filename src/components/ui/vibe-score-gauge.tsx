import { motion, useReducedMotion } from 'framer-motion'
import { cn } from '@/lib/utils'
import type { Grade } from '@/lib/scanner-types'

export type AggregateBand = 'low' | 'medium' | 'high' | 'severe'

export interface VibeScoreGaugeProps {
  score: number
  /** Letter grade (A+ … F) shown as a chip next to the band label. */
  grade?: Grade
  /**
   * Authoritative band from the scoring engine. When provided, the gauge
   * color + label come from the band — NOT from the score number. This is
   * how a passive-only profile (apple.com etc.) shows green/Healthy at
   * vibeScore=85 instead of yellow/At-risk.
   */
  band?: AggregateBand
  className?: string
  size?: number
}

function severityForBand(band: AggregateBand) {
  if (band === 'severe') return { color: 'var(--color-danger)', label: 'Critical' }
  if (band === 'high') return { color: 'var(--color-danger)', label: 'High risk' }
  if (band === 'medium') return { color: 'var(--color-warning)', label: 'Needs review' }
  return { color: 'var(--color-ok)', label: 'Healthy' }
}

// Fallback only — used when no band is passed (legacy callers).
function severityForScore(score: number) {
  if (score < 50) return { color: 'var(--color-danger)', label: 'Critical' }
  if (score < 75) return { color: 'var(--color-warning)', label: 'At risk' }
  return { color: 'var(--color-ok)', label: 'Healthy' }
}

export function VibeScoreGauge({ score, grade, band, className, size = 220 }: VibeScoreGaugeProps) {
  const reduceMotion = useReducedMotion() ?? false
  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  const severity = band ? severityForBand(band) : severityForScore(clamped)

  const stroke = 14
  const r = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  const arcSweep = 0.75
  const visible = circumference * arcSweep
  const fillFraction = clamped / 100
  const targetOffset = visible * (1 - fillFraction)

  const startAngleDeg = 135
  const endAngleDeg = startAngleDeg + 270 * fillFraction
  const indicatorRad = (endAngleDeg * Math.PI) / 180
  const ix = cx + r * Math.cos(indicatorRad)
  const iy = cy + r * Math.sin(indicatorRad)

  const ticks = [0, 25, 50, 75, 100]
  const tickAngles = ticks.map((t) => 135 + 270 * (t / 100))

  return (
    <div
      className={cn('relative inline-flex flex-col items-center justify-center', className)}
      role="img"
      aria-label={`Vibe Score ${clamped} out of 100, ${severity.label}`}
      style={{ width: size, height: size + 28 }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="overflow-visible"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="vibe-gauge-grad" x1="0%" y1="100%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--color-danger)" />
            <stop offset="40%" stopColor="var(--color-warning)" />
            <stop offset="75%" stopColor="#eab308" />
            <stop offset="100%" stopColor="var(--color-ok)" />
          </linearGradient>
          <radialGradient id="vibe-gauge-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={severity.color} stopOpacity="0.22" />
            <stop offset="70%" stopColor={severity.color} stopOpacity="0.05" />
            <stop offset="100%" stopColor={severity.color} stopOpacity="0" />
          </radialGradient>
          <filter id="vibe-gauge-blur" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" />
          </filter>
        </defs>

        <circle cx={cx} cy={cy} r={r * 0.92} fill="url(#vibe-gauge-glow)" />

        {tickAngles.map((deg, i) => {
          const rad = (deg * Math.PI) / 180
          const inner = r - 4
          const outer = r + 6
          const x1 = cx + inner * Math.cos(rad)
          const y1 = cy + inner * Math.sin(rad)
          const x2 = cx + outer * Math.cos(rad)
          const y2 = cy + outer * Math.sin(rad)
          return (
            <line
              key={i}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="var(--color-border-strong)"
              strokeWidth={1.5}
              strokeLinecap="round"
            />
          )
        })}

        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${visible} ${circumference}`}
          transform={`rotate(135 ${cx} ${cy})`}
        />

        <motion.circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="url(#vibe-gauge-grad)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${visible} ${circumference}`}
          initial={{ strokeDashoffset: visible }}
          animate={{ strokeDashoffset: targetOffset }}
          transition={{
            duration: reduceMotion ? 0 : 1.4,
            ease: [0.16, 1, 0.3, 1],
            delay: 0.2,
          }}
          transform={`rotate(135 ${cx} ${cy})`}
          style={{ filter: `drop-shadow(0 0 12px ${severity.color}66)` }}
        />

        <motion.circle
          cx={ix}
          cy={iy}
          r={10}
          fill={severity.color}
          opacity={0.18}
          filter="url(#vibe-gauge-blur)"
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.18 }}
          transition={{ delay: reduceMotion ? 0 : 1.4, duration: 0.4 }}
        />
        <motion.circle
          cx={ix}
          cy={iy}
          r={5}
          fill={severity.color}
          stroke="var(--color-bg)"
          strokeWidth={2}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: reduceMotion ? 0 : 1.4, duration: 0.35, ease: 'backOut' }}
          style={{ transformOrigin: `${ix}px ${iy}px` }}
        />

        {ticks.map((t, i) => {
          const deg = tickAngles[i]
          const rad = (deg * Math.PI) / 180
          const labelR = r + 22
          const lx = cx + labelR * Math.cos(rad)
          const ly = cy + labelR * Math.sin(rad)
          return (
            <text
              key={t}
              x={lx}
              y={ly}
              textAnchor="middle"
              dominantBaseline="middle"
              className="font-mono"
              fontSize={10}
              fill="var(--color-fg-dim)"
              letterSpacing={1}
            >
              {t}
            </text>
          )
        })}
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: reduceMotion ? 0 : 0.6, duration: 0.4 }}
          className="font-mono text-[10px] tracking-[0.2em] uppercase text-(--color-fg-dim) mb-1"
        >
          Vibe Score
        </motion.div>
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: reduceMotion ? 0 : 0.7, duration: 0.5, ease: 'backOut' }}
          className="font-bold tabular-nums tracking-tight leading-none"
          style={{ color: severity.color, fontSize: size * 0.32 }}
        >
          {clamped}
          <span
            className="ml-1 align-top text-(--color-fg-dim) font-mono font-medium"
            style={{ fontSize: size * 0.1 }}
          >
            /100
          </span>
        </motion.div>
        {/* Grade + status as one cohesive pill with its own surface — reads
            cleanly and never looks like it's sitting on the gauge arc. */}
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: reduceMotion ? 0 : 1.2, duration: 0.4, ease: 'backOut' }}
          className="mt-2 inline-flex items-center gap-2 rounded-full pl-1.5 pr-3 py-1"
          style={{
            color: severity.color,
            background: `color-mix(in oklab, ${severity.color} 14%, var(--color-bg))`,
            border: `1px solid color-mix(in oklab, ${severity.color} 32%, transparent)`,
            boxShadow: `0 2px 12px -6px ${severity.color}`,
          }}
        >
          {grade && (
            <span
              className="inline-flex items-center justify-center rounded-full font-bold leading-none"
              style={{
                background: severity.color,
                color: 'var(--color-bg)',
                width: 20,
                height: 20,
                fontSize: 12,
              }}
            >
              {grade}
            </span>
          )}
          <span className="font-mono text-[10px] tracking-widest uppercase font-medium">
            {severity.label}
          </span>
        </motion.div>
      </div>
    </div>
  )
}

export default VibeScoreGauge
