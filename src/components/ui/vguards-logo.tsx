interface VGuardsLogoProps {
  size?: number
  className?: string
  strokeWidth?: number
  ariaHidden?: boolean
}

/**
 * V-Guards brand mark — the raccoon mascot (robber-mask face + rounded ears +
 * whisker tufts) set inside the security shield. Strokes/fills use currentColor
 * so the parent controls the color (defaults to the cyan accent token); the eye
 * cut-outs use the bg token so they read as dark eyes inside the cyan mask.
 */
export function VGuardsLogo({ size = 18, className, strokeWidth = 2.6, ariaHidden = true }: VGuardsLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeLinejoin="round"
      strokeLinecap="round"
      className={className}
      aria-hidden={ariaHidden}
      role={ariaHidden ? 'presentation' : 'img'}
    >
      {/* Shield */}
      <path d="M32 6 L54 13.5 L54 31 Q54 49 32 58 Q10 49 10 31 L10 13.5 Z" strokeWidth={strokeWidth} />
      {/* Ears */}
      <path d="M26 24 Q20.5 23.5 19 18 Q25 17.5 29 23 Z" fill="currentColor" strokeWidth="1.6" />
      <path d="M38 24 Q43.5 23.5 45 18 Q39 17.5 35 23 Z" fill="currentColor" strokeWidth="1.6" />
      {/* Head / cheeks */}
      <path
        d="M27.5 22.5 Q19 26 19.5 35 Q20 41 24.5 45 Q28 47.5 32 47.5 Q36 47.5 39.5 45 Q44 41 44.5 35 Q45 26 36.5 22.5"
        strokeWidth="1.8"
      />
      {/* Whisker / cheek tufts */}
      <path
        d="M19.7 33 L16.6 32.2 M20.2 37 L17.2 37.8 M44.3 33 L47.4 32.2 M43.8 37 L46.8 37.8"
        strokeWidth="1.2"
        strokeOpacity={0.8}
      />
      {/* Robber mask */}
      <path
        d="M19 31 Q25 28 30 31 Q31 32.5 32 31.5 Q33 32.5 34 31 Q39 28 45 31 Q46 36 40.5 38 Q35 40 33 36.5 Q32 35 31 36.5 Q29 40 23.5 38 Q18 36 19 31 Z"
        fill="currentColor"
        strokeWidth="1"
      />
      {/* Eyes (dark cut-outs) + glints */}
      <circle cx="25.5" cy="33.2" r="2.3" fill="var(--color-bg)" stroke="none" />
      <circle cx="38.5" cy="33.2" r="2.3" fill="var(--color-bg)" stroke="none" />
      <circle cx="26.2" cy="32.4" r="0.75" fill="currentColor" stroke="none" />
      <circle cx="39.2" cy="32.4" r="0.75" fill="currentColor" stroke="none" />
      {/* Muzzle + nose */}
      <path d="M32 38.5 L32 42.5" strokeWidth="1.3" />
      <path d="M29 43.5 Q32 41 35 43.5 Q32 46.8 29 43.5 Z" fill="currentColor" strokeWidth="0.8" />
    </svg>
  )
}

export default VGuardsLogo
