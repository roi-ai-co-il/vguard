import { useEffect, useState, useCallback } from 'react'
import { Accessibility, X, RotateCcw, Plus, Minus, Contrast, Underline, Pause } from 'lucide-react'

type Prefs = {
  fontScale: number
  highContrast: boolean
  underlineLinks: boolean
  reduceMotion: boolean
}

const DEFAULTS: Prefs = {
  fontScale: 1,
  highContrast: false,
  underlineLinks: false,
  reduceMotion: false,
}

const STORAGE_KEY = 'vg_a11y_prefs'
const FONT_STEPS = [0.85, 0.9, 1, 1.1, 1.25, 1.5]

function loadPrefs(): Prefs {
  if (typeof window === 'undefined') return DEFAULTS
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULTS
    const parsed = JSON.parse(raw) as Partial<Prefs>
    return { ...DEFAULTS, ...parsed }
  } catch {
    return DEFAULTS
  }
}

function savePrefs(p: Prefs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(p))
  } catch {
    // ignore
  }
}

function applyPrefs(p: Prefs) {
  const root = document.documentElement
  root.style.setProperty('--a11y-font-scale', String(p.fontScale))
  root.dataset.a11yContrast = p.highContrast ? 'high' : 'default'
  root.dataset.a11yLinks = p.underlineLinks ? 'underlined' : 'default'
  root.dataset.a11yMotion = p.reduceMotion ? 'reduced' : 'default'
}

export default function AccessibilityWidget() {
  const [open, setOpen] = useState(false)
  const [prefs, setPrefs] = useState<Prefs>(DEFAULTS)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const loaded = loadPrefs()
    setPrefs(loaded)
    applyPrefs(loaded)
    setMounted(true)
  }, [])

  useEffect(() => {
    if (!mounted) return
    applyPrefs(prefs)
    savePrefs(prefs)
  }, [prefs, mounted])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  const update = useCallback(<K extends keyof Prefs>(key: K, value: Prefs[K]) => {
    setPrefs((p) => ({ ...p, [key]: value }))
  }, [])

  const stepFont = useCallback((dir: 1 | -1) => {
    setPrefs((p) => {
      const idx = FONT_STEPS.indexOf(p.fontScale)
      const next = Math.max(0, Math.min(FONT_STEPS.length - 1, (idx === -1 ? 2 : idx) + dir))
      return { ...p, fontScale: FONT_STEPS[next] }
    })
  }, [])

  const reset = useCallback(() => setPrefs(DEFAULTS), [])

  return (
    <>
      <button
        type="button"
        aria-label="Open accessibility menu"
        aria-expanded={open}
        aria-controls="a11y-panel"
        onClick={() => setOpen((o) => !o)}
        className="fixed bottom-4 right-4 z-50 w-12 h-12 rounded-full bg-(--color-bg) border border-(--color-accent-border) text-(--color-accent) shadow-lg flex items-center justify-center hover:bg-(--color-accent-muted) transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-(--color-accent)"
      >
        <Accessibility size={22} aria-hidden="true" />
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            aria-hidden="true"
            onClick={() => setOpen(false)}
          />
          <div
            id="a11y-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="a11y-title"
            className="fixed bottom-20 right-4 z-50 w-[min(360px,calc(100vw-2rem))] rounded-xl border border-(--color-border) bg-(--color-bg) shadow-2xl"
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-(--color-border)">
              <h2 id="a11y-title" className="font-mono text-sm tracking-widest uppercase text-(--color-accent)">
                Accessibility
              </h2>
              <button
                type="button"
                aria-label="Close accessibility menu"
                onClick={() => setOpen(false)}
                className="text-(--color-fg-muted) hover:text-(--color-fg) p-1"
              >
                <X size={18} aria-hidden="true" />
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <label htmlFor="a11y-font" className="text-sm text-(--color-fg)">Text size</label>
                <div id="a11y-font" className="flex items-center gap-2">
                  <button
                    type="button"
                    aria-label="Decrease text size"
                    onClick={() => stepFont(-1)}
                    className="w-8 h-8 rounded border border-(--color-border) text-(--color-fg) hover:bg-(--color-fg-muted)/10 flex items-center justify-center"
                  >
                    <Minus size={14} aria-hidden="true" />
                  </button>
                  <span className="font-mono text-xs text-(--color-fg-muted) min-w-[3.5ch] text-center">
                    {Math.round(prefs.fontScale * 100)}%
                  </span>
                  <button
                    type="button"
                    aria-label="Increase text size"
                    onClick={() => stepFont(1)}
                    className="w-8 h-8 rounded border border-(--color-border) text-(--color-fg) hover:bg-(--color-fg-muted)/10 flex items-center justify-center"
                  >
                    <Plus size={14} aria-hidden="true" />
                  </button>
                </div>
              </div>

              <Toggle
                id="a11y-contrast"
                icon={<Contrast size={16} aria-hidden="true" />}
                label="High contrast"
                checked={prefs.highContrast}
                onChange={(v) => update('highContrast', v)}
              />
              <Toggle
                id="a11y-links"
                icon={<Underline size={16} aria-hidden="true" />}
                label="Underline links"
                checked={prefs.underlineLinks}
                onChange={(v) => update('underlineLinks', v)}
              />
              <Toggle
                id="a11y-motion"
                icon={<Pause size={16} aria-hidden="true" />}
                label="Pause animations"
                checked={prefs.reduceMotion}
                onChange={(v) => update('reduceMotion', v)}
              />

              <div className="flex items-center justify-between pt-2 border-t border-(--color-border)">
                <button
                  type="button"
                  onClick={reset}
                  className="inline-flex items-center gap-1.5 text-xs font-mono text-(--color-fg-muted) hover:text-(--color-fg)"
                >
                  <RotateCcw size={12} aria-hidden="true" />
                  Reset
                </button>
                <a
                  href="/accessibility"
                  className="text-xs font-mono text-(--color-accent) hover:underline"
                >
                  Accessibility statement →
                </a>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  )
}

function Toggle({
  id,
  icon,
  label,
  checked,
  onChange,
}: {
  id: string
  icon: React.ReactNode
  label: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between">
      <label htmlFor={id} className="flex items-center gap-2 text-sm text-(--color-fg) cursor-pointer">
        <span className="text-(--color-fg-muted)">{icon}</span>
        {label}
      </label>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-6 rounded-full transition-colors ${
          checked ? 'bg-(--color-accent)' : 'bg-(--color-fg-muted)/30'
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-(--color-bg) transition-transform ${
            checked ? 'translate-x-4' : ''
          }`}
        />
      </button>
    </div>
  )
}
