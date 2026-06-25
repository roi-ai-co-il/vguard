import { motion } from 'framer-motion'
import { VGuardsLogo } from '@/components/ui/vguards-logo'

/**
 * Pricing — intentionally a single statement: everything is free right now.
 * No tiers, no price figures, no feature columns. If a paid plan is ever
 * introduced, reinstate the tier cards from git history (commit before this).
 */
export function PricingSection() {
  return (
    <section className="border-t border-(--color-border) bg-(--color-surface) relative overflow-hidden">
      {/* Ambient glow + grid — pure CSS, on-brand. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 [mask-image:radial-gradient(60%_55%_at_50%_0%,black,transparent)]"
      >
        <div className="absolute inset-0 bg-[linear-gradient(to_right,color-mix(in_oklab,var(--color-fg)_8%,transparent)_1px,transparent_1px),linear-gradient(to_bottom,color-mix(in_oklab,var(--color-fg)_8%,transparent)_1px,transparent_1px)] bg-[size:64px_64px]" />
        <div className="absolute left-1/2 top-[-30%] h-[420px] w-[680px] -translate-x-1/2 rounded-full bg-(--color-accent) opacity-[0.10] blur-[120px]" />
      </div>

      <div className="relative max-w-2xl mx-auto px-4 sm:px-6 py-20 sm:py-28">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 'some' }}
          transition={{ duration: 0.5 }}
          className="text-center flex flex-col items-center"
        >
          <VGuardsLogo size={48} className="mb-5" />
          <div className="font-mono text-[10px] sm:text-xs text-(--color-fg-dim) tracking-widest uppercase mb-4">
            Pricing
          </div>
          <h2 className="text-[2rem] sm:text-5xl font-bold tracking-tight leading-[1.1] text-balance">
            All services are <span className="text-(--color-accent)">free</span> right now.
          </h2>
        </motion.div>
      </div>
    </section>
  )
}

export default PricingSection
