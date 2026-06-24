import { motion, useReducedMotion } from 'framer-motion'
import { cn } from '@/lib/utils'
import type { Grade, ScoreTier } from '@/lib/scanner-types'

export type AggregateBand = 'low' | 'medium' | 'high' | 'severe'

const TIER_LABELS: Record<ScoreTier, string> = {
  excellent: 'Excellent security',
  outstanding: 'Outstanding security',
  exceptional: 'Exceptional security',
}

export interface VibeScoreGaugeProps {
  score: number
  /** Letter grade (A … F) shown as a chip next to the band label. */
  grade?: Grade
  /** V6 A-band qualifier — when present, replaces the generic band label. */
  tier?: ScoreTier
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

/**
 * Clean single-hue score ring. The arc is ONE color — the one that matches the
 * actual result band — so a perfect 100 reads as fully green, not a rainbow
 * that still shows red/orange. No tick marks, no 0/25/50/75/100 labels, no
 * blurred indicator dot: the number is the message, the ring is just its frame.
 */
export function VibeScoreGauge({ score, grade, tier, band, className, size = 220 }: VibeScoreGaugeProps) {
  const reduceMotion = useReducedMotion() ?? false
  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  const severity = band ? severityForBand(band) : severityForScore(clamped)
  const statusLabel = tier ? TIER_LABELS[tier] : severity.label

  const stroke = Math.round(size * 0.07)
  const r = (size - stroke) / 2 - 2
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  const arcSweep = 0.75 // 270° open-bottom ring
  const visible = circumference * arcSweep
  const fillFraction = clamped / 100
  const targetOffset = visible * (1 - fillFraction)

  // Same-hue depth: a lighter tint of the band color into the band color.
  const tint = `color-mix(in oklab, ${severity.color} 50%, white)`

  return (
    <div
      className={cn('relative inline-flex flex-col items-center justify-center', className)}
      role="img"
      aria-label={`Vibe Score ${clamped} out of 100, ${statusLabel}`}
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="overflow-visible"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="vibe-gauge-arc" x1="0%" y1="100%" x2="100%" y2="0%">
            <stop offset="0%" style={{ stopColor: tint }} />
            <stop offset="100%" style={{ stopColor: severity.color }} />
          </linearGradient>
        </defs>

        {/* track — subtle, shows the ring is "out of" a full circle */}
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

        {/* progress — single hue, fills to the score */}
        <motion.circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="url(#vibe-gauge-arc)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${visible} ${circumference}`}
          initial={{ strokeDashoffset: visible }}
          animate={{ strokeDashoffset: targetOffset }}
          transition={{
            duration: reduceMotion ? 0 : 1.3,
            ease: [0.16, 1, 0.3, 1],
            delay: 0.2,
          }}
          transform={`rotate(135 ${cx} ${cy})`}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: reduceMotion ? 0 : 0.5, duration: 0.5, ease: 'backOut' }}
          className="flex items-baseline font-bold tabular-nums tracking-tight leading-none"
          style={{ color: severity.color, fontSize: size * 0.34 }}
        >
          {clamped}
          <span
            className="ml-0.5 text-(--color-fg-dim) font-mono font-medium"
            style={{ fontSize: size * 0.095 }}
          >
            /100
          </span>
        </motion.div>

        {/* grade + plain-language verdict, as one clear pill */}
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: reduceMotion ? 0 : 0.85, duration: 0.4, ease: 'backOut' }}
          className="mt-2.5 inline-flex items-center gap-1.5 rounded-full pl-1 pr-2.5 py-1"
          style={{
            color: severity.color,
            background: `color-mix(in oklab, ${severity.color} 13%, var(--color-bg))`,
            border: `1px solid color-mix(in oklab, ${severity.color} 30%, transparent)`,
          }}
        >
          {grade && (
            <span
              className="inline-flex items-center justify-center rounded-full font-bold leading-none"
              style={{
                background: severity.color,
                color: 'var(--color-bg)',
                width: 18,
                height: 18,
                fontSize: 11,
              }}
            >
              {grade}
            </span>
          )}
          <span className="text-[11px] font-semibold tracking-tight">{statusLabel}</span>
        </motion.div>
      </div>
    </div>
  )
}

export default VibeScoreGauge
