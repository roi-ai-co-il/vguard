/**
 * Vguard design tokens — single source of truth.
 *
 * Direction: "Terminal Trust" — dark-first, cyan-electric accent,
 * Inter + JetBrains Mono. Built for vibe coders (Cursor / Lovable / Bolt).
 *
 * Mirrored in `src/index.css` via `@theme` for Tailwind 4.
 * Never import roi-ai-internal's `lg-surface` / purple-pink gradient.
 */

export const tokens = {
  color: {
    bg: '#09090b',
    surface: '#111114',
    surfaceElevated: '#17171c',
    border: '#1f1f29',
    borderStrong: '#2a2a36',
    text: '#f5f5f7',
    textMuted: '#9b9ba3',
    textDim: '#6b6b75',
    accent: '#22d3ee',
    accentMuted: 'rgba(34, 211, 238, 0.12)',
    accentBorder: 'rgba(34, 211, 238, 0.4)',
    danger: '#ff5c5c',
    warning: '#ffb84d',
    ok: '#4ade80',
  },
  font: {
    sans: '"Inter", system-ui, -apple-system, "Segoe UI", sans-serif',
    mono: '"JetBrains Mono", ui-monospace, "SF Mono", Consolas, monospace',
  },
} as const

export type Tokens = typeof tokens

/**
 * iOS-DARK palette for the internal admin dashboard
 * (`src/pages/AdminDashboard.tsx`). iOS structure (grouped lists, segmented
 * control, sheets, spring) on V-Guards' dark "Terminal Trust" brand — keeps the
 * admin unmistakably V-Guards (dark canvas, cyan accent) rather than a generic
 * iOS Settings clone. Mirrors the `tokens` brand above but tuned for iOS-style
 * elevated surfaces + hairlines on dark.
 */
export const iosAdmin = {
  bg: '#09090b', // brand canvas
  bgElevated: '#1c1c22',
  card: '#131318', // grouped-list surface
  cardPressed: '#1c1c22',
  separator: 'rgba(255,255,255,0.07)', // hairline on dark
  separatorStrong: 'rgba(255,255,255,0.16)',
  label: '#f5f5f7',
  label2: '#a8a8b2',
  label3: '#8a8a96',
  label4: '#6b6b75',
  accent: '#22d3ee', // V-Guards cyan — bright, reads great on dark
  accentFill: '#22d3ee',
  accentSoft: 'rgba(34,211,238,0.12)',
  onAccent: '#04161c', // near-black text on cyan fills (cyan is light → needs dark text)
  red: '#ff453a',
  orange: '#ff9f0a',
  green: '#30d158',
  blue: '#0a84ff',
  grade: {
    A: '#30d158',
    B: '#a3e635',
    C: '#ff9f0a',
    D: '#ff7a45',
    F: '#ff453a',
    '—': '#6b6b75',
  } as Record<string, string>,
} as const

