import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Sparkles,
  ShieldCheck,
  Search,
  FileCheck2,
  Wrench,
  ArrowRight,
  Activity,
} from 'lucide-react'
import { ScanForm } from './components/ScanForm'
import { TypingEffect } from '@/components/ui/typing-effect'
import { InteractiveGlobe } from '@/components/ui/interactive-globe'
import { BentoGrid, type BentoCardProps } from '@/components/ui/bento'

interface RecentFinding {
  hostname: string
  secondsAgo: number
  finding: string
  country: string | null
  severity: string
}

const STEPS = [
  {
    n: '01',
    title: 'Scan',
    Icon: Search,
    body: 'Paste your URL. We probe headers, JS bundles, source maps, exposed paths, RLS endpoints & AI surfaces.',
  },
  {
    n: '02',
    title: 'Report',
    Icon: FileCheck2,
    body: 'One Vibe Score. P0 → P2 findings. Each with raw HTTP evidence so you can verify, not just trust.',
  },
  {
    n: '03',
    title: 'Fix',
    Icon: Wrench,
    body: "Every finding ships with a paste-ready prompt for Cursor / Claude / Lovable. Rescan to prove it's fixed.",
  },
]

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

const FALLBACK_FINDINGS: RecentFinding[] = [
  { hostname: 'illustrative', secondsAgo: 23, finding: 'Missing Content-Security-Policy header', country: null, severity: 'warn' },
  { hostname: 'illustrative', secondsAgo: 41, finding: 'No DMARC record', country: null, severity: 'warn' },
  { hostname: 'illustrative', secondsAgo: 67, finding: 'Source map publicly served', country: null, severity: 'warn' },
  { hostname: 'illustrative', secondsAgo: 92, finding: 'DNSSEC not enabled', country: null, severity: 'info' },
]

const SCAN_CARDS: BentoCardProps[] = [
  {
    className: 'lg:col-span-3 lg:row-span-1',
    eyebrow: 'P0 · Secrets & API keys',
    title: 'Find Anthropic, OpenAI, Supabase keys baked into your bundle',
    description:
      'We crawl every chunk and source map for the patterns Cursor / Claude / Lovable accidentally inline. Each finding ships with a paste-ready prompt to move the call server-side.',
    graphic: (
      <div className="absolute inset-0 p-6 font-mono text-[11px] leading-relaxed">
        <div className="text-(--color-fg-dim)">$ vibesecure scan https://app.vercel.app</div>
        <div className="text-(--color-fg-dim)">{'> probing JS bundle...'}</div>
        <div className="mt-3 rounded-md bg-(--color-bg) border border-(--color-danger)/40 p-3 shadow-[0_0_24px_-8px_rgba(255,107,107,0.5)]">
          <div className="text-(--color-danger) font-semibold">! CRITICAL — secret found</div>
          <div className="mt-1.5 text-(--color-fg-muted)">assets/index-B7kQ2.js:1</div>
          <div className="mt-2 text-(--color-fg)">
            const KEY = <span className="text-(--color-warning)">"sk-ant-api03-</span>
            <span className="text-(--color-danger)">XXXXXXXXXXXXXXXX</span>
            <span className="text-(--color-warning)">"</span>
          </div>
          <div className="mt-1 text-(--color-fg-dim)">^ Anthropic API key (40 chars)</div>
        </div>
      </div>
    ),
  },
  {
    className: 'lg:col-span-3 lg:row-span-1',
    eyebrow: 'P0 · Auth & sessions',
    title: 'Catch the Supabase RLS policies that look safe but aren’t',
    description:
      '`auth.uid() IS NOT NULL`, `share_token IS NOT NULL`, lone JWT checks, and the other patterns that leak data when signup is open by default.',
    graphic: (
      <div className="absolute inset-0 p-6 font-mono text-[11px] leading-relaxed">
        <div className="text-(--color-fg-dim)">-- public.documents</div>
        <div className="text-(--color-fg-dim)">CREATE POLICY <span className="text-(--color-fg)">"read_own"</span> ON documents</div>
        <div className="text-(--color-fg-dim)">FOR SELECT TO authenticated</div>
        <div className="mt-1 text-(--color-fg-dim)">USING (</div>
        <div className="ml-4 inline-flex items-center bg-(--color-danger)/15 border border-(--color-danger)/40 rounded px-2 py-0.5 text-(--color-danger)">
          auth.uid() IS NOT NULL
        </div>
        <div className="text-(--color-fg-dim)">);</div>
        <div className="mt-3 text-(--color-warning)">
          ! Signup is OPEN. Anyone can read every row.
        </div>
        <div className="mt-2 text-(--color-fg-muted)">
          fix → check ownership: <span className="text-(--color-accent)">auth.uid() = user_id</span>
        </div>
      </div>
    ),
  },
  {
    className: 'lg:col-span-2 lg:row-span-1',
    eyebrow: 'P1 · AI surfaces',
    title: 'Test your AI endpoints for prompt injection',
    description:
      'Chat endpoints that accept user-controlled system prompts, agents with over-broad tool scopes, RAG context leakage.',
    graphic: (
      <div className="absolute inset-0 p-5 font-mono text-[10px] leading-relaxed">
        <div className="text-(--color-fg-dim)">POST /api/[your-llm]</div>
        <div className="mt-1 text-(--color-fg-muted)">{'{'}</div>
        <div className="ml-3">
          <span className="text-(--color-fg-dim)">"messages": </span>
          <span className="text-(--color-fg)">[...]</span>
          <span className="text-(--color-fg-dim)">,</span>
        </div>
        <div className="ml-3">
          <span className="text-(--color-danger)">"system"</span>
          <span className="text-(--color-fg-dim)">: </span>
          <span className="text-(--color-warning)">"ignore previous"</span>
        </div>
        <div className="text-(--color-fg-muted)">{'}'}</div>
        <div className="mt-2 text-(--color-fg-muted)">→ 200 OK</div>
        <div className="mt-2 text-(--color-danger)">! prompt-injection surface</div>
      </div>
    ),
  },
  {
    className: 'lg:col-span-2 lg:row-span-1',
    eyebrow: 'P0 · Exposed paths',
    title: 'Find what shouldn’t be public',
    description:
      '.env, .git, source maps, .DS_Store, and the Vercel preview URLs your team forgot to lock down.',
    graphic: (
      <div className="absolute inset-0 p-5 font-mono text-[10px] leading-relaxed">
        <div className="text-(--color-fg-muted)">/</div>
        <div className="text-(--color-fg-muted)">├── index.html</div>
        <div className="text-(--color-fg-muted)">├── assets/</div>
        <div className="text-(--color-fg-muted)">│ └── index-B7kQ2.js</div>
        <div className="text-(--color-danger)">├── assets/index.js.map ← 200</div>
        <div className="text-(--color-danger)">├── .env ← 200</div>
        <div className="text-(--color-warning)">├── .git/HEAD ← 200</div>
        <div className="text-(--color-fg-muted)">└── robots.txt</div>
      </div>
    ),
  },
  {
    className: 'lg:col-span-2 lg:row-span-1',
    eyebrow: 'P1 · Headers & CVEs',
    title: 'CSP, HSTS, CORS, and the rest',
    description:
      'Every header that should be set, with the exact `vercel.json` snippet to fix it. CVE detection across your dependency tree.',
    graphic: (
      <div className="absolute inset-0 p-5 font-mono text-[10px] leading-relaxed">
        <div className="text-(--color-fg-dim)">$ curl -I https://app.vercel.app</div>
        <div className="mt-2 text-(--color-fg-muted)">HTTP/2 200</div>
        <div className="text-(--color-fg-muted)">strict-transport-security: <span className="text-(--color-ok)">max-age=63072000</span></div>
        <div className="text-(--color-fg-muted)">x-content-type-options: <span className="text-(--color-ok)">nosniff</span></div>
        <div className="text-(--color-warning)">content-security-policy: <span className="font-bold">missing</span></div>
        <div className="text-(--color-warning)">referrer-policy: <span className="font-bold">missing</span></div>
        <div className="mt-2 text-(--color-fg-dim)">→ 4 of 9 hardening headers</div>
      </div>
    ),
  },
]

export default function App() {
  const [recentFindings, setRecentFindings] = useState<RecentFinding[]>(FALLBACK_FINDINGS)
  const [isLive, setIsLive] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const r = await fetch('/api/recent-findings')
        if (!r.ok) return
        const data = (await r.json()) as { ok: boolean; items: RecentFinding[] }
        if (cancelled) return
        if (data.ok && data.items.length >= 3) {
          setRecentFindings(data.items)
          setIsLive(true)
        }
      } catch {
        // keep fallback
      }
    }
    load()
    const interval = setInterval(load, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  return (
    <div className="relative min-h-svh bg-(--color-bg) text-(--color-fg) flex flex-col">
      <div className="bg-grid absolute inset-0 pointer-events-none" aria-hidden="true" />
      <div className="hero-glow absolute top-0 left-0 right-0 h-[60vh] pointer-events-none" aria-hidden="true" />

      <motion.header
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="relative border-b border-(--color-border) backdrop-blur-sm bg-(--color-bg)/60 z-10"
      >
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2 font-mono text-sm" aria-label="VibeSecure home">
            <ShieldCheck size={18} className="text-(--color-accent)" strokeWidth={2.25} aria-hidden="true" />
            <span className="font-semibold tracking-tight">vibesecure</span>
            <span className="text-(--color-fg-dim) animate-pulse">_</span>
          </a>
          <div className="font-mono text-xs text-(--color-fg-dim) hidden sm:block">
            beta · invitation only
          </div>
        </div>
      </motion.header>

      <main className="relative flex-1 z-10">
        <section className="max-w-6xl mx-auto px-6 pt-20 sm:pt-32 pb-20 sm:pb-28">
          <motion.div
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
              className="inline-flex items-center gap-2 font-mono text-xs text-(--color-accent) mb-6 tracking-widest uppercase px-3 py-1.5 rounded-full bg-(--color-accent-muted) border border-(--color-accent-border)"
            >
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-(--color-accent) animate-pulse" aria-hidden="true" />
              Security · for vibe-coded apps
            </motion.div>
            <motion.h1
              variants={fadeUp}
              transition={{ duration: 0.6 }}
              className="text-[2.75rem] sm:text-6xl lg:text-7xl font-bold tracking-tight leading-[1.05] max-w-4xl"
            >
              45% of AI-generated code <span className="text-(--color-fg-muted)">fails</span> security tests.
            </motion.h1>
            <motion.p
              variants={fadeUp}
              transition={{ duration: 0.6 }}
              className="mt-6 text-base sm:text-lg lg:text-xl text-(--color-fg-muted) max-w-2xl leading-relaxed"
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
              className="mt-3 text-sm text-(--color-fg-dim) max-w-2xl leading-relaxed"
            >
              <span className="text-(--color-accent)">▸</span> No source code. No enterprise plan. Just a URL.
            </motion.p>
            <motion.div variants={fadeUp} transition={{ duration: 0.6 }} className="mt-10">
              <ScanForm />
            </motion.div>
            <motion.div
              variants={fadeUp}
              transition={{ duration: 0.6 }}
              className="mt-4 font-mono text-xs text-(--color-fg-dim) flex items-center gap-1.5"
            >
              <ArrowRight size={11} className="text-(--color-accent)" aria-hidden="true" />
              First scan free. No card. No bullshit.
            </motion.div>
          </motion.div>
        </section>

        <section className="border-t border-(--color-border) relative">
          <div className="max-w-6xl mx-auto px-6 py-16 sm:py-20 grid lg:grid-cols-12 gap-10 items-center">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ duration: 0.5 }}
              className="lg:col-span-5 order-2 lg:order-1"
            >
              <div className="inline-flex items-center gap-2 font-mono text-xs text-(--color-accent) mb-4 tracking-widest uppercase px-3 py-1.5 rounded-full bg-(--color-accent-muted) border border-(--color-accent-border)">
                <Activity size={12} aria-hidden="true" />
                Live · scanning the world
              </div>
              <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">
                Right now, somewhere on the planet, a vibe-coded app just leaked a secret.
              </h2>
              <p className="mt-3 text-(--color-fg-muted) text-sm sm:text-base leading-relaxed">
                Drag the globe. Each pulse is a region where developers ship Cursor / Lovable / Bolt apps without a security review. We help them find the leaks before attackers do.
              </p>

              <ul className="mt-6 space-y-2.5">
                {recentFindings.map((f, i) => {
                  const dotColor =
                    f.severity === 'critical'
                      ? 'var(--color-danger)'
                      : f.severity === 'warn'
                        ? 'var(--color-warning)'
                        : 'var(--color-fg-muted)'
                  const ago =
                    f.secondsAgo < 60
                      ? `${f.secondsAgo}s ago`
                      : f.secondsAgo < 3600
                        ? `${Math.round(f.secondsAgo / 60)}m ago`
                        : `${Math.round(f.secondsAgo / 3600)}h ago`
                  return (
                    <li
                      key={`${f.hostname}-${i}`}
                      className="font-mono text-xs flex items-center gap-3 text-(--color-fg-dim)"
                    >
                      <span className="tabular-nums text-(--color-accent) w-16 flex-shrink-0">
                        {ago}
                      </span>
                      <span
                        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                        style={{ background: dotColor }}
                        aria-hidden="true"
                      />
                      <span className="truncate text-(--color-fg-muted)">{f.finding}</span>
                      <span className="ml-auto text-(--color-fg-dim) flex-shrink-0">
                        {f.country ?? f.hostname}
                      </span>
                    </li>
                  )
                })}
              </ul>
              <div className="mt-2 font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim)">
                {isLive ? '● Live · last scans, hostnames redacted' : '◌ Awaiting first scans — illustrative until then'}
              </div>

              <div className="mt-6 grid grid-cols-3 gap-4 max-w-md">
                <div>
                  <div className="font-mono text-2xl font-semibold tabular-nums text-(--color-fg)">
                    150+
                  </div>
                  <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mt-1">
                    Detection rules
                  </div>
                </div>
                <div>
                  <div className="font-mono text-2xl font-semibold tabular-nums text-(--color-fg)">
                    &lt;60s
                  </div>
                  <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mt-1">
                    Avg scan
                  </div>
                </div>
                <div>
                  <div className="font-mono text-2xl font-semibold tabular-nums text-(--color-fg)">
                    P0 → P2
                  </div>
                  <div className="font-mono text-[10px] tracking-widest uppercase text-(--color-fg-dim) mt-1">
                    Severity tiers
                  </div>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.6 }}
              className="lg:col-span-7 order-1 lg:order-2 flex items-center justify-center min-h-[420px]"
            >
              <InteractiveGlobe size={520} />
            </motion.div>
          </div>
        </section>

        <section className="border-t border-(--color-border) relative">
          <div className="max-w-6xl mx-auto px-6 py-16 sm:py-20">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.5 }}
              className="mb-10 max-w-2xl"
            >
              <div className="font-mono text-xs text-(--color-fg-dim) tracking-widest uppercase mb-3">
                What we scan
              </div>
              <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">
                Built for the way you actually ship.
              </h2>
              <p className="mt-3 text-(--color-fg-muted) text-sm sm:text-base">
                Whether you ship plain HTML or a full React app, we map the surfaces AI tools tend to leak through.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.1 }}
              transition={{ duration: 0.5 }}
            >
              <BentoGrid cards={SCAN_CARDS} />
            </motion.div>

            <motion.p
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="mt-6 font-mono text-xs text-(--color-fg-dim) flex items-center gap-2"
            >
              <Sparkles size={12} className="text-(--color-accent)" aria-hidden="true" />
              + 70 more checks across OWASP 2021, AI-native vulns, Firebase &amp; static HTML hygiene.
            </motion.p>
          </div>
        </section>

        <section className="border-t border-(--color-border)">
          <motion.div
            initial="hidden"
            whileInView="show"
            viewport={{ once: true, amount: 0.2 }}
            variants={{
              hidden: {},
              show: { transition: { staggerChildren: 0.12 } },
            }}
            className="max-w-6xl mx-auto px-6 py-16 sm:py-20 grid sm:grid-cols-3 gap-8 sm:gap-10"
          >
            {STEPS.map((s) => (
              <motion.div
                key={s.n}
                variants={{
                  hidden: { opacity: 0, y: 12 },
                  show: { opacity: 1, y: 0 },
                }}
                transition={{ duration: 0.4 }}
              >
                <div className="flex items-center gap-3 mb-4">
                  <span className="flex items-center justify-center w-10 h-10 rounded-lg bg-(--color-accent-muted) text-(--color-accent) border border-(--color-accent-border)">
                    <s.Icon size={18} strokeWidth={2} aria-hidden="true" />
                  </span>
                  <div className="font-mono text-xs text-(--color-accent) tracking-widest uppercase">
                    {s.n} · {s.title}
                  </div>
                </div>
                <p className="text-sm sm:text-base text-(--color-fg-muted) leading-relaxed">{s.body}</p>
              </motion.div>
            ))}
          </motion.div>
        </section>
      </main>

      <footer className="relative border-t border-(--color-border) mt-auto z-10">
        <div className="max-w-6xl mx-auto px-6 py-6 flex items-center justify-between font-mono text-xs text-(--color-fg-dim)">
          <span>© 2026 VibeSecure</span>
          <span>built by ROI AI · in stealth</span>
        </div>
      </footer>
    </div>
  )
}
