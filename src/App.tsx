import { motion } from 'framer-motion'
import {
  Search,
  FileCheck2,
  Wrench,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react'
import { ScanForm } from './components/ScanForm'
import ContactSection from './components/ContactSection'
import { VGuardsLogo, MascotScanMark } from '@/components/ui/vguards-logo'
import { TypingEffect } from '@/components/ui/typing-effect'
import { CpuArchitecture } from '@/components/ui/cpu-architecture'
import { PricingSection } from '@/components/PricingSection'
import { SmokeBackground } from '@/components/ui/spooky-smoke-animation'

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

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

export default function App() {
  return (
    <div className="relative min-h-svh bg-(--color-bg) text-(--color-fg) flex flex-col">
      {/* Cyan-and-white drifting smoke field — fixed, behind all content (z-10) */}
      <div className="smoke-field fixed inset-0 pointer-events-none" aria-hidden="true">
        <SmokeBackground smokeColor="#22d3ee" intensity={0.55} density={26} />
      </div>
      <div className="bg-grid absolute inset-0 pointer-events-none" aria-hidden="true" />
      <div className="hero-glow absolute top-0 left-0 right-0 h-[60vh] pointer-events-none" aria-hidden="true" />

      <motion.header
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="relative border-b border-(--color-border) backdrop-blur-sm bg-(--color-bg)/60 z-10"
      >
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 sm:py-5 flex items-center justify-between gap-3">
          <a href="/" className="flex items-center gap-2.5 font-mono text-base sm:text-lg" aria-label="V-Guards home">
            <VGuardsLogo size={44} />
            <span className="font-semibold tracking-tight">V-Guards</span>
            <span className="text-(--color-fg-dim) animate-pulse">_</span>
          </a>
        </div>
      </motion.header>

      <main className="relative flex-1 z-10">
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
              Every scan free. No card. No bullshit.
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
          </motion.div>
        </section>

        {/* How it works — the 3-step user journey (Scan → Report → Fix).
            Comes first after the hero: explain what happens when you scan
            before asking for deeper trust. Sits on a faint surface band (vs
            the white hero) to give the page rhythm; each step is a real
            card with a soft shadow + hover lift (clean-premium-SaaS look). */}
        <section className="border-t border-(--color-border) bg-(--color-surface)">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-16 sm:py-24">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 'some' }}
              transition={{ duration: 0.5 }}
              className="text-center max-w-2xl mx-auto mb-10 sm:mb-14"
            >
              <div className="font-mono text-[10px] sm:text-xs text-(--color-accent) tracking-widest uppercase mb-3">
                How it works
              </div>
              <h2 className="text-[1.5rem] sm:text-3xl lg:text-4xl font-bold tracking-tight leading-[1.15] text-balance">
                From paste to fixed in under a minute.
              </h2>
            </motion.div>
            <motion.div
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, amount: 'some' }}
              variants={{
                hidden: {},
                show: { transition: { staggerChildren: 0.12 } },
              }}
              className="grid grid-cols-1 sm:grid-cols-3 gap-5 sm:gap-6"
            >
              {STEPS.map((s) => (
                <motion.div
                  key={s.n}
                  variants={{
                    hidden: { opacity: 0, y: 12 },
                    show: { opacity: 1, y: 0 },
                  }}
                  transition={{ duration: 0.4 }}
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

        {/* Architecture visual — 8 colored signal streams converge into a
            central CPU. Why the one score is trustworthy: many detector
            categories → one Vibe Score. Sits after the 3 steps as the
            "under the hood" credibility beat.
            Mobile: SVG container is `max-w-md` so it never gets too big on
            phones, and aspect-[2/1] preserves the 200×100 viewBox. */}
        <section className="border-t border-(--color-border)">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 'some' }}
            transition={{ duration: 0.5 }}
            className="max-w-6xl mx-auto px-4 sm:px-6 py-10 sm:py-16 flex flex-col items-center text-center"
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

        <PricingSection />

        {/* Closing CTA — its natural home is the bottom: it re-engages the
            visitor who has read the whole page and scrolls them back up to the
            hero scan form (#vguard-scan). "Free" right above (Pricing) clears
            the price objection just before the ask. */}
        <section className="border-t border-(--color-border) relative overflow-hidden">
          {/* Ambient cyan glow — premium finish behind the closing CTA. */}
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
              href="#vguard-scan"
              className="mt-7 inline-flex items-center justify-center gap-2 h-12 px-6 rounded-xl bg-(--color-cta) text-(--color-cta-fg) font-mono text-sm font-semibold shadow-[0_0_24px_-4px_var(--color-cta)] hover:bg-(--color-cta-strong) hover:shadow-[0_0_30px_0_var(--color-cta)] active:scale-[0.99] transition-all"
            >
              Scan my app
              <ArrowRight size={16} strokeWidth={2.5} aria-hidden="true" />
            </a>
          </motion.div>
        </section>

        <ContactSection />
      </main>

      <footer className="relative border-t border-(--color-border) mt-auto z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-5 sm:py-6 flex flex-col gap-2 font-mono text-[11px] sm:text-xs text-(--color-fg-dim)">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 sm:gap-0">
            <span className="flex items-center gap-2">
              <VGuardsLogo size={26} />
              © 2026 V-Guards
            </span>
            <span>in stealth</span>
          </div>
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 sm:gap-0">
            <span>Founders · Royi Argaman · Oded Safdie</span>
            <a href="mailto:infovguards@gmail.com" className="hover:text-(--color-fg-muted) transition-colors">infovguards@gmail.com</a>
          </div>
          <div className="flex items-center gap-4 pt-1">
            <a href="/terms" className="hover:text-(--color-fg-muted) transition-colors">Terms</a>
            <a href="/privacy" className="hover:text-(--color-fg-muted) transition-colors">Privacy</a>
            <a href="/accessibility" className="hover:text-(--color-fg-muted) transition-colors">Accessibility</a>
            <span className="opacity-40">·</span>
            <a href="https://roiai.co.il" target="_blank" rel="noopener noreferrer" className="hover:text-(--color-accent) transition-colors text-(--color-accent)/70">Built by ROI AI</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
