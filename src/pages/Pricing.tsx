import { motion } from 'framer-motion'
import { ArrowRight, ChevronDown } from 'lucide-react'
import { VGuardsLogo } from '@/components/ui/vguards-logo'

const revealUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

/**
 * Pricing (/pricing) — one continuous flowing section. The "free" statement and
 * the closing CTA share a single background (transparent → the site's smoke +
 * grid show through, same top and bottom) with one ambient glow spanning both,
 * and a gradient connector links the two beats. No dividers — it reads as a
 * single thought: it's free, so go scan.
 */
export default function Pricing() {
  return (
    <section className="relative overflow-hidden">
      {/* One ambient glow spanning the whole page — the visual thread that ties
          the "free" beat to the CTA beat. Masked so it fades at the edges. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 [mask-image:radial-gradient(75%_70%_at_50%_30%,black,transparent)]"
      >
        <div className="absolute left-1/2 top-[6%] h-[560px] w-[820px] -translate-x-1/2 rounded-full bg-(--color-accent) opacity-[0.09] blur-[140px]" />
      </div>

      <div className="relative max-w-2xl mx-auto px-4 sm:px-6 pt-20 sm:pt-32 pb-20 sm:pb-28 flex flex-col items-center text-center">
        {/* Beat 1 — the price. Staggered so the logo → eyebrow → headline → line
            reveal one after another instead of as one block. */}
        <motion.div
          initial="hidden"
          animate="show"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.1, delayChildren: 0.05 } } }}
          className="flex flex-col items-center"
        >
          <motion.div variants={revealUp} transition={{ duration: 0.5 }}>
            <VGuardsLogo size={48} className="mb-5" />
          </motion.div>
          <motion.div
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="font-mono text-[10px] sm:text-xs text-(--color-fg-dim) tracking-widest uppercase mb-4"
          >
            Pricing
          </motion.div>
          <motion.h1
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="text-[2rem] sm:text-5xl font-bold tracking-tight leading-[1.1] text-balance"
          >
            All services are <span className="text-(--color-accent)">free</span> right now.
          </motion.h1>
          <motion.p
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="mt-5 text-(--color-fg-muted) text-[15px] sm:text-lg leading-relaxed max-w-md"
          >
            Every stage — scan, report, and the ready-to-paste fixes — is free. No card, no
            account, no catch.
          </motion.p>
        </motion.div>

        {/* Connector — a gradient line + chevron that physically links the two
            beats so the eye flows from "free" straight into the CTA. */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="my-10 sm:my-14 flex flex-col items-center gap-1.5"
          aria-hidden="true"
        >
          <span className="h-14 w-px bg-gradient-to-b from-(--color-accent)/0 via-(--color-accent)/40 to-(--color-accent)/60" />
          <ChevronDown size={18} className="text-(--color-accent)/70 -mt-1 animate-bounce" />
        </motion.div>

        {/* Beat 2 — the ask */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="flex flex-col items-center"
        >
          <h2 className="text-[1.6rem] sm:text-4xl font-bold tracking-tight leading-[1.1] text-balance">
            Free today. <span className="text-(--color-accent)">Scan your app</span> now.
          </h2>
          <p className="mt-3 text-(--color-fg-muted) text-[14px] sm:text-base leading-relaxed max-w-lg">
            Paste your URL, get a clear score and ready-to-paste fixes in under a minute.
          </p>
          <a
            href="/#vguard-scan"
            className="mt-7 inline-flex items-center justify-center gap-2 h-12 px-6 rounded-xl bg-(--color-cta) text-(--color-cta-fg) font-mono text-sm font-semibold shadow-[0_0_24px_-4px_var(--color-cta)] hover:bg-(--color-cta-strong) hover:shadow-[0_0_30px_0_var(--color-cta)] active:scale-[0.99] transition-all"
          >
            Scan my app
            <ArrowRight size={16} strokeWidth={2.5} aria-hidden="true" />
          </a>
        </motion.div>
      </div>
    </section>
  )
}
