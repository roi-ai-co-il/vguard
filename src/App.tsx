import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import SiteLayout from './components/SiteLayout'
import Home from './pages/Home'
import HowItWorks from './pages/HowItWorks'
import Pricing from './pages/Pricing'
import Contact from './pages/Contact'

/** The four tab routes that share the SiteLayout chrome. Navigation between
 *  these happens client-side (no full reload) so switching tabs is instant and
 *  animated. Legal/admin pages are NOT here — they full-load (see main.tsx). */
const TAB_PATHS = new Set(['/', '/how-it-works', '/pricing', '/contact'])

function normalize(p: string): string {
  if (p.length > 1 && p.endsWith('/')) return p.slice(0, -1)
  return p
}

function pageFor(path: string) {
  switch (path) {
    case '/how-it-works':
      return <HowItWorks />
    case '/pricing':
      return <Pricing />
    case '/contact':
      return <Contact />
    default:
      return <Home />
  }
}

/**
 * Tab router for the four public tabs. Intercepts clicks on internal tab links,
 * swaps the page with `history.pushState` (no reload → no white/black flash),
 * and plays a fast fade-up so the new page "builds in". The header + footer +
 * background stay mounted across navigations, so only the content changes.
 */
export default function App({ initialPath }: { initialPath: string }) {
  const [path, setPath] = useState(normalize(initialPath))

  // Intercept internal tab-link clicks → client-side navigation.
  useEffect(() => {
    function onClick(e: MouseEvent) {
      // Respect modifier clicks / non-primary buttons (open-in-new-tab, etc.)
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      const anchor = (e.target as HTMLElement | null)?.closest('a')
      if (!anchor) return
      const href = anchor.getAttribute('href')
      if (!href || anchor.target === '_blank' || /^(https?:|mailto:|tel:)/.test(href)) return

      const url = new URL(href, window.location.origin)
      const dest = normalize(url.pathname)
      // Only handle the tab routes; legal/admin links fall through to a normal
      // full navigation.
      if (!TAB_PATHS.has(dest)) return

      e.preventDefault()
      const sameRoute = dest === path

      if (!sameRoute) {
        window.history.pushState({}, '', url.pathname + url.hash)
        setPath(dest)
      } else if (url.hash) {
        // Same route + hash (e.g. the "/#vguard-scan" CTA when already home).
        window.history.replaceState({}, '', url.pathname + url.hash)
      }

      if (url.hash) {
        // Wait for the destination page's enter animation to mount the target.
        const scrollToHash = () => {
          const el = document.querySelector(url.hash)
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
        }
        sameRoute ? scrollToHash() : window.setTimeout(scrollToHash, 60)
      } else if (!sameRoute) {
        window.scrollTo({ top: 0, left: 0 })
      }
    }

    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [path])

  // Browser back/forward buttons.
  useEffect(() => {
    function onPop() {
      setPath(normalize(window.location.pathname))
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  return (
    <SiteLayout pathname={path}>
      {/* key={path} remounts on each navigation so the enter animation replays.
          No exit animation = zero gap → the new page builds in immediately. */}
      <motion.div
        key={path}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      >
        {pageFor(path)}
      </motion.div>
    </SiteLayout>
  )
}
