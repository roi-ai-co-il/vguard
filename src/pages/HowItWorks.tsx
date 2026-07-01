import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, FileCheck2, Wrench, ArrowRight } from 'lucide-react'
import { VGuardsLogo } from '@/components/ui/vguards-logo'
import { CpuArchitecture } from '@/components/ui/cpu-architecture'

const revealUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

/** The STP acronym → its words. The capital of each word IS the acronym letter,
 *  so a tight "STP" can visibly unfold into "Scan To Prompt". The trailing
 *  no-break space on the first two lives inside the width-animated span so it
 *  collapses too — closed reads "STP", open reads "Scan To Prompt". */
const STP = [
  { cap: 'S', rest: 'can ' },
  { cap: 'T', rest: 'o ' },
  { cap: 'P', rest: 'rompt' },
] as const

/** STP reveal — the three capitals flip up tight together ("STP"), then each
 *  word's remaining letters write themselves in one-by-one with a per-char
 *  flip-up (rotateX 90°→0), while `layout` smoothly spreads the letters apart
 *  into "Scan To Prompt". */
function StpReveal() {
  const [open, setOpen] = useState(false)
  return (
    <motion.div
      viewport={{ once: true, amount: 'some' }}
      onViewportEnter={() => window.setTimeout(() => setOpen(true), 700)}
      className="flex flex-wrap justify-center items-baseline font-sans font-bold tracking-tight text-[2.25rem] sm:text-6xl leading-none [perspective:800px]"
    >
      {STP.map((w, i) => (
        <motion.span layout key={w.rest} className="inline-flex items-baseline">
          <motion.span
            layout
            initial={{ opacity: 0, rotateX: 90, y: 10 }}
            whileInView={{ opacity: 1, rotateX: 0, y: 0 }}
            viewport={{ once: true, amount: 'some' }}
            transition={{ delay: 0.1 + i * 0.12, duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            style={{ transformOrigin: 'bottom' }}
            className="inline-block text-(--color-accent)"
          >
            {w.cap}
          </motion.span>
          <AnimatePresence>
            {open &&
              w.rest.split('').map((ch, ci) => (
                <motion.span
                  layout
                  key={ci}
                  initial={{ opacity: 0, rotateX: 90, y: 10 }}
                  animate={{ opacity: 1, rotateX: 0, y: 0 }}
                  transition={{ delay: i * 0.18 + ci * 0.045, duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                  style={{ transformOrigin: 'bottom' }}
                  className="inline-block text-(--color-fg)"
                >
                  {ch === ' ' ? ' ' : ch}
                </motion.span>
              ))}
          </AnimatePresence>
        </motion.span>
      ))}
    </motion.div>
  )
}

const STEPS = [
  {
    n: '01',
    title: 'Scan',
    Icon: Search,
    body: 'Paste your link. We check your connection, hunt for leaked passwords and keys, and find private files left exposed.',
  },
  {
    n: '02',
    title: 'Report',
    Icon: FileCheck2,
    body: 'One score, every issue ranked by urgency — each with the exact proof, so you can verify it yourself.',
  },
  {
    n: '03',
    title: 'Fix',
    Icon: Wrench,
    body: 'Each issue ships with a ready-to-paste fix for Cursor / Claude / Lovable. Rescan to confirm.',
  },
]

/**
 * How it works (/how-it-works) — the 3-step journey (Scan → Report → Fix) plus
 * the "scoring engine" credibility beat. Lifted out of the old single-page App
 * so the home page can stay focused on the scan.
 */
export default function HowItWorks() {
  return (
    <>
      {/* Page intro */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6 pt-14 sm:pt-24 pb-2 sm:pb-6 text-center">
        <motion.div
          initial="hidden"
          animate="show"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.1, delayChildren: 0.05 } } }}
          className="max-w-2xl mx-auto"
        >
          <motion.div
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="font-mono text-[10px] sm:text-xs text-(--color-accent) tracking-widest uppercase mb-3"
          >
            How it works
          </motion.div>
          <motion.h1
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="text-[1.75rem] sm:text-4xl lg:text-5xl font-bold tracking-tight leading-[1.12] text-balance"
          >
            From paste to fixed in under a minute.
          </motion.h1>
          <motion.p
            variants={revealUp}
            transition={{ duration: 0.5 }}
            className="mt-4 text-(--color-fg-muted) text-[15px] sm:text-lg leading-relaxed"
          >
            Three steps. No source code, no setup — just a URL.
          </motion.p>
        </motion.div>
      </section>

      {/* 3 steps — smooth iOS-style entrance: a soft fade + gentle rise + tiny
          scale, animated on MOUNT (not on scroll), so it replays cleanly every
          time the tab mounts or the page refreshes. Only opacity + transform
          animate (GPU, no reflow) → buttery, never a jump. */}
      <section>
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-12 sm:py-16">
          <motion.div
            initial="hidden"
            animate="show"
            variants={{
              hidden: {},
              show: { transition: { staggerChildren: 0.09, delayChildren: 0.06 } },
            }}
            className="grid grid-cols-1 sm:grid-cols-3 gap-5 sm:gap-6"
          >
            {STEPS.map((s) => (
              <motion.div
                key={s.n}
                variants={{
                  hidden: { opacity: 0, y: 14, scale: 0.98 },
                  show: { opacity: 1, y: 0, scale: 1 },
                }}
                transition={{ duration: 0.55, ease: [0.25, 0.1, 0.25, 1] }}
                className="group rounded-2xl border border-(--color-border) bg-(--color-surface-elevated) p-6 sm:p-7 shadow-[0_1px_2px_rgba(0,0,0,0.04)] hover:shadow-[0_16px_40px_-20px_rgba(2,8,23,0.25)] hover:border-(--color-accent-border) hover:-translate-y-1 transition-all duration-300"
              >
                <div className="flex items-center gap-3 mb-3 sm:mb-4">
                  <span className="flex items-center justify-center w-10 h-10 rounded-xl bg-(--color-accent-muted) text-(--color-accent) border border-(--color-accent-border) group-hover:scale-105 transition-transform">
                    <s.Icon size={18} strokeWidth={2} aria-hidden="true" />
                  </span>
                  <div className="font-mono text-[11px] sm:text-xs text-(--color-accent) tracking-widest uppercase">
                    {s.n} · {s.title}
                  </div>
                </div>
                <p className="text-[14px] sm:text-base text-(--color-fg-muted) leading-relaxed">{s.body}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Scoring engine */}
      <section className="border-t border-(--color-border)">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 'some' }}
          transition={{ duration: 0.5 }}
          className="max-w-6xl mx-auto px-4 sm:px-6 py-12 sm:py-20 flex flex-col items-center text-center"
        >
          <VGuardsLogo size={48} className="mb-4" />
          <div className="font-mono text-[10px] sm:text-xs text-(--color-fg-dim) tracking-widest uppercase mb-3">
            The scoring engine
          </div>
          <h2 className="text-[1.4rem] sm:text-2xl lg:text-3xl font-semibold tracking-tight leading-[1.2] max-w-2xl text-balance">
            Eight signal streams. <span className="text-(--color-fg-muted)">One verdict.</span>
          </h2>
          <p className="mt-3 text-(--color-fg-muted) text-[13.5px] sm:text-base leading-relaxed max-w-xl">
            Dozens of checks — leaked keys, exposed files, weak connections, open
            storage — roll up into one score you can act on.
          </p>
          <div className="mt-6 sm:mt-9 w-full max-w-md sm:max-w-2xl rounded-2xl border border-(--color-border) bg-(--color-surface)/40 px-6 sm:px-10 py-7 sm:py-10 shadow-[0_16px_50px_-24px_rgba(2,8,23,0.25)]">
            <div className="w-full aspect-[2/1] text-(--color-accent)/70">
              <CpuArchitecture text="secure" />
            </div>
          </div>
        </motion.div>
      </section>

      {/* Closing CTA — sends the reader back to the scan on the home page. */}
      <section className="border-t border-(--color-border) relative overflow-hidden">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute left-1/2 top-1/2 h-[360px] w-[620px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-(--color-accent) opacity-[0.08] blur-[120px]"
        />
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 'some' }}
          transition={{ duration: 0.5 }}
          className="relative max-w-3xl mx-auto px-4 sm:px-6 py-16 sm:py-24 flex flex-col items-center text-center"
        >
          <h2 className="text-[1.6rem] sm:text-4xl font-bold tracking-tight leading-[1.1] text-balance">
            Find your <span className="text-(--color-accent)">leaks</span> before attackers do.
          </h2>
          <p className="mt-3 text-(--color-fg-muted) text-[14px] sm:text-base leading-relaxed max-w-lg">
            Paste your URL, get a clear score and ready-to-paste fixes in under a minute. Free —
            no card, no account.
          </p>
          <a
            href="/#vguard-scan"
            className="mt-7 inline-flex items-center justify-center gap-2 h-12 px-6 rounded-xl bg-(--color-cta) text-(--color-cta-fg) font-mono text-sm font-semibold shadow-[0_0_24px_-4px_var(--color-cta)] hover:bg-(--color-cta-strong) hover:shadow-[0_0_30px_0_var(--color-cta)] active:scale-[0.99] transition-all"
          >
            Scan my app
            <ArrowRight size={16} strokeWidth={2.5} aria-hidden="true" />
          </a>
        </motion.div>
      </section>

      {/* STP sign-off — the acronym S · T · P lands first, then each capital
          unfurls into its full word (left-to-right clip): S→Scan, T→To,
          P→Prompt. One clean reveal, nothing else. */}
      <section className="border-t border-(--color-border)">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-16 sm:py-28 flex flex-col items-center">
          <div className="font-mono text-[10px] sm:text-xs text-(--color-fg-dim) tracking-widest uppercase mb-8 sm:mb-10">
            The whole loop
          </div>

          <StpReveal />
        </div>
      </section>
    </>
  )
}
