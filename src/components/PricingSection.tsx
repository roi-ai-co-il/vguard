import { motion } from 'framer-motion'
import { Check, ShieldCheck, Zap, ArrowRight } from 'lucide-react'

/**
 * Two-tier pricing — adapted from a 21st.dev animated pricing section into
 * Vguard's terminal/security DNA (no generic blue gradient, no heavy particle
 * deps — just framer-motion + the design tokens). The model is intentionally
 * simple: Free unlocks Stage 1 + Stage 2; Pro adds the verified Stage 3 deep
 * scan as a one-time unlock per domain.
 */
interface Tier {
  name: string
  tagline: string
  price: string
  priceNote: string
  cta: string
  popular: boolean
  Icon: typeof Zap
  includes: string[]
}

const TIERS: Tier[] = [
  {
    name: 'Free',
    tagline: 'Passive + browser-assisted scanning, forever.',
    price: '$0',
    priceNote: 'no account needed',
    cta: 'Scan a URL',
    popular: false,
    Icon: Zap,
    includes: [
      'Stage 1 — passive scan: headers, TLS, secrets, DNS, exposed paths',
      'Stage 2 — browser-assisted: cookies, JWTs, runtime APIs',
      'Vibe Score + letter grade + full breakdown',
      'Paste-ready AI fix prompt for every finding',
      'Unlimited public scans',
    ],
  },
  {
    name: 'Pro',
    tagline: 'Everything in Free, plus the verified deep scan.',
    price: '$29',
    priceNote: 'one-time · per domain',
    cta: 'Unlock Stage 3',
    popular: true,
    Icon: ShieldCheck,
    includes: [
      'Everything in Free',
      'Stage 3 — verified deep scan (you prove you own the domain)',
      'Real RLS / XSS / SQLi / path-traversal probes',
      'Supabase anon-key + storage write tests',
      'Re-scan free for 30 days',
    ],
  },
]

function scrollToScan() {
  if (typeof document === 'undefined') return
  const el = document.getElementById('vguard-scan')
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  else window.scrollTo({ top: 0, behavior: 'smooth' })
}

export function PricingSection() {
  return (
    <section className="border-t border-(--color-border) relative overflow-hidden">
      {/* Ambient glow + grid — pure CSS, on-brand (no particle engine). */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 [mask-image:radial-gradient(60%_55%_at_50%_0%,black,transparent)]"
      >
        <div className="absolute inset-0 bg-[linear-gradient(to_right,color-mix(in_oklab,var(--color-fg)_8%,transparent)_1px,transparent_1px),linear-gradient(to_bottom,color-mix(in_oklab,var(--color-fg)_8%,transparent)_1px,transparent_1px)] bg-[size:64px_64px]" />
        <div className="absolute left-1/2 top-[-30%] h-[420px] w-[680px] -translate-x-1/2 rounded-full bg-(--color-accent) opacity-[0.10] blur-[120px]" />
      </div>

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 py-14 sm:py-24">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 'some' }}
          transition={{ duration: 0.5 }}
          className="text-center max-w-2xl mx-auto"
        >
          <div className="font-mono text-[10px] sm:text-xs text-(--color-fg-dim) tracking-widest uppercase mb-3">
            Pricing
          </div>
          <h2 className="text-[1.5rem] sm:text-3xl font-semibold tracking-tight leading-[1.15] text-balance">
            Scan for free. <span className="text-(--color-fg-muted)">Pay only to go deep.</span>
          </h2>
          <p className="mt-3 text-(--color-fg-muted) text-[13.5px] sm:text-base leading-relaxed">
            Stages 1 &amp; 2 are free for everyone. Stage 3 fires real attack payloads —
            so it's gated behind a one-time unlock per domain you own.
          </p>
        </motion.div>

        <div className="mt-10 sm:mt-14 grid grid-cols-1 md:grid-cols-2 gap-5 sm:gap-6 items-stretch">
          {TIERS.map((tier, i) => (
            <motion.div
              key={tier.name}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 'some' }}
              transition={{ duration: 0.5, delay: i * 0.12 }}
              className={
                'relative flex flex-col rounded-2xl border p-6 sm:p-8 ' +
                (tier.popular
                  ? 'border-(--color-accent-border) bg-(--color-surface) shadow-[0_0_60px_-20px_var(--color-accent)]'
                  : 'border-(--color-border) bg-(--color-surface)/60')
              }
            >
              {tier.popular && (
                <span className="absolute -top-3 right-6 inline-flex items-center gap-1 rounded-full bg-(--color-accent) text-(--color-bg) font-mono text-[10px] font-bold uppercase tracking-widest px-3 py-1">
                  Most value
                </span>
              )}

              <div className="flex items-center gap-2.5">
                <span
                  className={
                    'flex items-center justify-center w-9 h-9 rounded-lg border ' +
                    (tier.popular
                      ? 'bg-(--color-accent-muted) text-(--color-accent) border-(--color-accent-border)'
                      : 'bg-(--color-bg) text-(--color-fg-muted) border-(--color-border)')
                  }
                >
                  <tier.Icon size={17} strokeWidth={2} aria-hidden="true" />
                </span>
                <h3 className="text-xl font-semibold tracking-tight">{tier.name}</h3>
              </div>

              <p className="mt-3 text-[13.5px] text-(--color-fg-muted) leading-relaxed min-h-[2.5rem]">
                {tier.tagline}
              </p>

              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-4xl font-semibold tracking-tight tabular-nums">{tier.price}</span>
                <span className="font-mono text-[11px] text-(--color-fg-dim) uppercase tracking-wider">
                  {tier.priceNote}
                </span>
              </div>

              <button
                type="button"
                onClick={scrollToScan}
                className={
                  'mt-6 inline-flex items-center justify-center gap-2 w-full h-12 rounded-xl font-mono text-sm font-semibold transition-all cursor-pointer ' +
                  (tier.popular
                    ? 'bg-(--color-accent) text-(--color-bg) hover:opacity-90 active:scale-[0.99]'
                    : 'border border-(--color-border) text-(--color-fg) hover:border-(--color-accent-border) hover:text-(--color-accent)')
                }
              >
                {tier.cta}
                <ArrowRight size={15} strokeWidth={2.5} aria-hidden="true" />
              </button>

              <ul className="mt-7 space-y-3 pt-6 border-t border-(--color-border)">
                {tier.includes.map((feature, fi) => (
                  <li key={fi} className="flex items-start gap-2.5">
                    <Check
                      size={15}
                      strokeWidth={2.5}
                      className={'mt-0.5 flex-shrink-0 ' + (tier.popular ? 'text-(--color-accent)' : 'text-(--color-ok)')}
                      aria-hidden="true"
                    />
                    <span className="text-[13.5px] text-(--color-fg-muted) leading-snug">{feature}</span>
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>

        <p className="mt-8 text-center font-mono text-[11px] text-(--color-fg-dim)">
          One-time payment · re-scan free for 30 days · secure checkout
        </p>
      </div>
    </section>
  )
}

export default PricingSection
