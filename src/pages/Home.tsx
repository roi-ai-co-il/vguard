import { motion } from 'framer-motion'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { ScanForm } from '@/components/ScanForm'
import { MascotScanMark } from '@/components/ui/vguards-logo'
import { TypingEffect } from '@/components/ui/typing-effect'

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

/**
 * Home (/) — the hero + scan form, the single job of this page. Everything
 * else (how-it-works, pricing, contact) lives on its own tab/page now, so the
 * landing experience stays focused on "paste a URL, get a score".
 */
export default function Home() {
  return (
    <section className="relative overflow-hidden max-w-6xl mx-auto px-4 sm:px-6 pt-12 sm:pt-32 pb-14 sm:pb-28">
        {/* Mascot watermark with a cyan scan wave (right side). Hidden on
            phones — at 260px it sits behind the headline and reads as noise. */}
        <div className="pointer-events-none absolute inset-0 hidden sm:block" aria-hidden="true">
          <div className="absolute -top-6 right-2 sm:right-8">
            <MascotScanMark size={260} />
          </div>
        </div>
        <motion.div
          className="relative z-10"
          initial="hidden"
          animate="show"
          variants={{
            hidden: {},
            show: { transition: { staggerChildren: 0.1, delayChildren: 0.1 } },
          }}
        >
          <motion.div
            variants={fadeUp}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 font-mono text-[10px] sm:text-xs text-(--color-accent) mb-5 sm:mb-6 tracking-widest uppercase px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-full bg-(--color-accent-muted) border border-(--color-accent-border)"
          >
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-(--color-accent) animate-pulse" aria-hidden="true" />
            Security · for vibe-coded apps
          </motion.div>
          <motion.h1
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="text-[2rem] sm:text-6xl lg:text-7xl font-bold tracking-tight leading-[1.1] sm:leading-[1.05] max-w-4xl text-balance"
          >
            45% of AI-generated code <span className="text-(--color-fg-muted)">fails</span> security tests.
          </motion.h1>
          <motion.p
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-2 font-mono text-[11px] sm:text-xs text-(--color-fg-dim)"
          >
            Source:{' '}
            <a
              href="https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/"
              target="_blank"
              rel="noopener noreferrer"
              className="underline decoration-dotted underline-offset-2 hover:text-(--color-fg-muted) transition-colors"
            >
              Veracode 2025 GenAI Code Security Report
            </a>
          </motion.p>
          <motion.p
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-5 sm:mt-6 text-[15px] sm:text-lg lg:text-xl text-(--color-fg-muted) max-w-2xl leading-relaxed"
          >
            Scan your{' '}
            <TypingEffect
              texts={['Cursor', 'Lovable', 'Bolt', 'Replit']}
              className="text-(--color-accent) font-mono font-semibold tracking-tight"
              cursorClassName="bg-(--color-accent)"
              rotationInterval={2000}
              typingSpeed={110}
            />{' '}
            app in 60 seconds. Get the fixes as prompts you paste straight back into your AI.
          </motion.p>
          <motion.p
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-3 text-[13px] sm:text-sm text-(--color-fg-dim) max-w-2xl leading-relaxed"
          >
            <span className="text-(--color-accent)">▸</span> No source code. No enterprise plan. Just a URL.
          </motion.p>
          <motion.div id="vguard-scan" variants={fadeUp} transition={{ duration: 0.6 }} className="mt-7 sm:mt-10 scroll-mt-24">
            <ScanForm />
          </motion.div>
          <motion.div
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-4 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) flex items-center gap-1.5"
          >
            <ArrowRight size={11} className="text-(--color-accent)" aria-hidden="true" />
            Every scan free. No card. No catch.
          </motion.div>
          <motion.p
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-3 text-[12px] sm:text-[13px] text-(--color-fg-dim) max-w-2xl leading-relaxed flex items-start gap-1.5"
          >
            <ShieldCheck size={13} className="text-(--color-accent) mt-0.5 flex-shrink-0" aria-hidden="true" />
            <span>
              We only read your public pages — we never log in, change anything, or store your
              site. <a href="/privacy" className="underline decoration-dotted underline-offset-2 hover:text-(--color-fg-muted) transition-colors">How we handle your data</a>.
            </span>
          </motion.p>

          {/* Inline signposts to the dedicated pages — the page is focused on the
              scan, but visitors still need a path to the rest. */}
          <motion.div
            variants={fadeUp}
            transition={{ duration: 0.6 }}
            className="mt-8 sm:mt-10 flex flex-wrap items-center gap-3"
          >
            <a
              href="/how-it-works"
              className="group inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg bg-(--color-accent-muted) border border-(--color-accent-border) text-(--color-accent) font-mono text-sm font-medium tracking-tight shadow-[0_0_0_0_var(--color-cta)] hover:bg-(--color-accent)/15 hover:shadow-[0_0_20px_-4px_var(--color-cta)] active:scale-[0.98] transition-all cursor-pointer min-h-[48px]"
            >
              See how it works
              <ArrowRight size={16} strokeWidth={2.5} className="transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
            </a>
            <a
              href="/pricing"
              className="group inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg bg-(--color-accent-muted) border border-(--color-accent-border) text-(--color-accent) font-mono text-sm font-medium tracking-tight shadow-[0_0_0_0_var(--color-cta)] hover:bg-(--color-accent)/15 hover:shadow-[0_0_20px_-4px_var(--color-cta)] active:scale-[0.98] transition-all cursor-pointer min-h-[48px]"
            >
              Pricing
              <ArrowRight size={16} strokeWidth={2.5} className="transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
            </a>
          </motion.div>
        </motion.div>
      </section>
  )
}
