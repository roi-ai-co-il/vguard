import { motion } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface BentoCardProps {
  className?: string
  eyebrow: ReactNode
  title: ReactNode
  description: ReactNode
  graphic?: ReactNode
}

export function BentoCard({ className, eyebrow, title, description, graphic }: BentoCardProps) {
  return (
    <motion.div
      initial="idle"
      whileHover="active"
      variants={{ idle: {}, active: {} }}
      className={cn(
        'group relative flex flex-col overflow-hidden rounded-2xl',
        'bg-(--color-surface) border border-(--color-border) transition-colors',
        'hover:border-(--color-accent-border) hover:bg-(--color-surface-elevated)',
        'shadow-[0_0_0_1px_rgba(255,255,255,0.02)_inset]',
        className,
      )}
    >
      <div className="relative h-[14rem] sm:h-[16rem] shrink-0 overflow-hidden">
        {graphic}
        <div className="absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-(--color-surface) via-(--color-surface)/80 to-transparent pointer-events-none" />
      </div>
      <div className="relative px-6 pt-2 pb-6 z-10">
        <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-accent)">
          {eyebrow}
        </div>
        <h3 className="mt-1.5 text-lg sm:text-xl font-semibold tracking-tight text-(--color-fg) leading-snug">
          {title}
        </h3>
        <p className="mt-2 text-sm text-(--color-fg-muted) leading-relaxed">{description}</p>
      </div>
    </motion.div>
  )
}

interface BentoGridProps {
  className?: string
  cards: BentoCardProps[]
}

export function BentoGrid({ className, cards }: BentoGridProps) {
  return (
    <div
      className={cn(
        'grid grid-cols-1 gap-4 sm:gap-5 lg:grid-cols-6 lg:grid-rows-2',
        className,
      )}
    >
      {cards.map((card, i) => (
        <BentoCard key={i} {...card} />
      ))}
    </div>
  )
}

export default BentoGrid
