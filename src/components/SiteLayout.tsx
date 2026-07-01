import { motion } from 'framer-motion'
import { ArrowRight } from 'lucide-react'
import { VGuardsLogo } from '@/components/ui/vguards-logo'
import { SmokeBackground } from '@/components/ui/spooky-smoke-animation'
import { cn } from '@/lib/utils'

/** The site's primary navigation tabs. Each tab is its own page/URL — the
 *  routing is pathname-based (see main.tsx + vercel.json rewrites), so these
 *  are plain anchors that trigger a normal navigation. */
const TABS = [
  { href: '/', label: 'Home' },
  { href: '/how-it-works', label: 'How it works' },
  { href: '/pricing', label: 'Pricing' },
] as const

/** True when `tab` matches the current path. Computed at render — every tab
 *  click is a full navigation, so there's no need to make this reactive. */
function isActive(href: string, pathname: string): boolean {
  if (href === '/') return pathname === '/' || pathname === ''
  return pathname === href || pathname === href + '/'
}

/**
 * Shared chrome for every public page: the cyan smoke field + grid + hero glow,
 * the tabbed header, and the footer. Each page renders only its own <main>
 * content inside <SiteLayout>. Keeping this in one place means the background,
 * nav, and footer never drift between pages.
 */
export default function SiteLayout({
  children,
  pathname,
}: {
  children: React.ReactNode
  /** Current route — drives the active-tab highlight. Passed in by the tab
   *  router (App.tsx) so the header updates on client-side navigation. */
  pathname: string
}) {
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
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between gap-3">
          <a href="/" className="flex items-center gap-2.5 font-mono text-base sm:text-lg" aria-label="V-Guards home">
            <VGuardsLogo size={40} />
            <span className="font-semibold tracking-tight">V-Guards</span>
            <span className="text-(--color-fg-dim) animate-pulse hidden sm:inline">_</span>
          </a>

          {/* Primary tabs — inline on desktop. On mobile they move to the row
              below so the logo + Contact CTA always stay visible. */}
          <nav className="hidden sm:flex items-center gap-1" aria-label="Primary">
            {TABS.map((tab) => (
              <a
                key={tab.href}
                href={tab.href}
                aria-current={isActive(tab.href, pathname) ? 'page' : undefined}
                className={cn(
                  'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive(tab.href, pathname)
                    ? 'text-(--color-accent) bg-(--color-accent-muted)'
                    : 'text-(--color-fg-muted) hover:text-(--color-fg) hover:bg-(--color-surface)',
                )}
              >
                {tab.label}
              </a>
            ))}
          </nav>

          <a
            href="/contact"
            aria-current={isActive('/contact', pathname) ? 'page' : undefined}
            className={cn(
              'inline-flex items-center gap-1.5 h-9 px-3.5 sm:px-4 rounded-lg font-mono text-[13px] sm:text-sm font-semibold shrink-0 transition-all',
              isActive('/contact', pathname)
                ? 'bg-(--color-cta-strong) text-(--color-cta-fg)'
                : 'bg-(--color-cta) text-(--color-cta-fg) hover:bg-(--color-cta-strong) shadow-[0_0_20px_-6px_var(--color-cta)]',
            )}
          >
            Contact us
            <ArrowRight size={14} strokeWidth={2.5} aria-hidden="true" />
          </a>
        </div>

        {/* Mobile tab row — horizontally scrollable so long labels never wrap. */}
        <nav className="sm:hidden border-t border-(--color-border) overflow-x-auto" aria-label="Primary">
          <div className="flex items-center gap-1 px-3 py-1.5 min-w-max">
            {TABS.map((tab) => (
              <a
                key={tab.href}
                href={tab.href}
                aria-current={isActive(tab.href, pathname) ? 'page' : undefined}
                className={cn(
                  'px-3 py-1.5 rounded-lg text-[13px] font-medium whitespace-nowrap transition-colors',
                  isActive(tab.href, pathname)
                    ? 'text-(--color-accent) bg-(--color-accent-muted)'
                    : 'text-(--color-fg-muted) hover:text-(--color-fg)',
                )}
              >
                {tab.label}
              </a>
            ))}
          </div>
        </nav>
      </motion.header>

      <main className="relative flex-1 z-10">{children}</main>

      <footer className="relative border-t border-(--color-border) mt-auto z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
          {/* Top: brand block on the left, two clearly-labelled link columns on
              the right. Links are styled as links at rest (fg-muted + hover to
              full fg/accent), grouped under uppercase headings, so it reads as
              navigation — not a wall of identical mono text. */}
          <div className="flex flex-col gap-8 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex flex-col gap-3 max-w-xs">
              <a href="/" className="flex items-center gap-2 font-mono text-sm font-semibold text-(--color-fg)" aria-label="V-Guards home">
                <VGuardsLogo size={28} />
                V-Guards
                <span className="ml-1 inline-flex items-center rounded-full border border-(--color-border) px-2 py-0.5 font-mono text-[10px] font-normal text-(--color-fg-dim)">
                  in stealth
                </span>
              </a>
              <p className="font-mono text-[11px] leading-relaxed text-(--color-fg-dim)">
                Security scanning for vibe-coded apps. Paste a URL, get the fixes.
              </p>
              <a
                href="mailto:infovguards@gmail.com"
                className="font-mono text-[11px] text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max"
              >
                infovguards@gmail.com
              </a>
            </div>

            <div className="grid grid-cols-2 gap-x-10 gap-y-2 sm:gap-x-14">
              <nav className="flex flex-col gap-2.5" aria-label="Product">
                <span className="font-mono text-[10px] uppercase tracking-wider text-(--color-fg-dim)">Product</span>
                <a href="/how-it-works" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">How it works</a>
                <a href="/pricing" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">Pricing</a>
                <a href="/contact" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">Contact</a>
              </nav>
              <nav className="flex flex-col gap-2.5" aria-label="Legal">
                <span className="font-mono text-[10px] uppercase tracking-wider text-(--color-fg-dim)">Legal</span>
                <a href="/terms" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">Terms</a>
                <a href="/privacy" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">Privacy</a>
                <a href="/accessibility" className="font-mono text-xs text-(--color-fg-muted) underline decoration-(--color-border) underline-offset-4 hover:text-(--color-accent) hover:decoration-(--color-accent) transition-colors w-max">Accessibility</a>
              </nav>
            </div>
          </div>

          {/* Bottom bar: copyright + founders on one side, build credit on the
              other, separated from the links above by a hairline divider. */}
          <div className="mt-8 pt-5 border-t border-(--color-border) flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between font-mono text-[11px] text-(--color-fg-dim)">
            <span>© 2026 V-Guards · Founders Royi Argaman &amp; Oded Safdie</span>
            <a
              href="https://roiai.co.il"
              target="_blank"
              rel="noopener noreferrer"
              className="text-(--color-accent)/70 hover:text-(--color-accent) transition-colors w-max"
            >
              Built by ROI AI
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
