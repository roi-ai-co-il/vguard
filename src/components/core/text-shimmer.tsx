import type { CSSProperties } from 'react'
import { useMemo } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

export type TextShimmerProps = {
  children: string
  className?: string
  /** Seconds per shimmer sweep. */
  duration?: number
  /** Width of the bright band, scaled by text length. */
  spread?: number
}

/**
 * A brand-cyan light band that sweeps across the text on an infinite loop —
 * the "working / generating" affordance. Base text sits in a muted color; the
 * moving gradient reveals the accent as it passes. Adapted from
 * motion-primitives' TextShimmer to use framer-motion (already installed) and
 * the V-Guards color tokens.
 */
export function TextShimmer({ children, className, duration = 2, spread = 2 }: TextShimmerProps) {
  const dynamicSpread = useMemo(() => children.length * spread, [children, spread])

  return (
    <motion.span
      className={cn(
        'relative inline-block bg-[length:250%_100%,auto] bg-clip-text text-transparent',
        '[--base-color:var(--color-fg-dim)] [--base-gradient-color:var(--color-accent)]',
        '[--bg:linear-gradient(90deg,#0000_calc(50%-var(--spread)),var(--base-gradient-color),#0000_calc(50%+var(--spread)))]',
        '[background-repeat:no-repeat,padding-box]',
        className,
      )}
      initial={{ backgroundPosition: '100% center' }}
      animate={{ backgroundPosition: '0% center' }}
      transition={{ repeat: Infinity, duration, ease: 'linear' }}
      style={
        {
          '--spread': `${dynamicSpread}px`,
          backgroundImage: 'var(--bg), linear-gradient(var(--base-color), var(--base-color))',
        } as CSSProperties
      }
    >
      {children}
    </motion.span>
  )
}
