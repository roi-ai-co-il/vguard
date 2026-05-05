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
