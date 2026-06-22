interface VGuardsLogoProps {
  size?: number
  className?: string
  strokeWidth?: number
  ariaHidden?: boolean
}

/**
 * V-Guards brand mark — a recon radar scope set inside a geometric shield.
 * The scope (ring + crosshair + sweep needle + target blip) reads as
 * "scanning / reconnaissance", which is exactly what the product does.
 * All strokes/fills use currentColor, so the parent controls the color
 * (defaults to the cyan accent token via Tailwind classes).
 */
export function VGuardsLogo({ size = 18, className, strokeWidth = 3, ariaHidden = true }: VGuardsLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      className={className}
      aria-hidden={ariaHidden}
      role={ariaHidden ? 'presentation' : 'img'}
    >
      {/* Shield silhouette */}
      <path
        d="M32 5 L55 13.5 L55 32 Q55 50.5 32 60 Q9 50.5 9 32 L9 13.5 Z"
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
      />
      {/* Radar sweep wedge (trailing glow behind the needle) */}
      <path d="M32 31 L32 18 A13 13 0 0 1 42.65 23.54 Z" fill="currentColor" fillOpacity={0.22} stroke="none" />
      {/* Scope rings */}
      <circle cx="32" cy="31" r="13" strokeWidth="2" />
      <circle cx="32" cy="31" r="6.5" strokeWidth="1.3" strokeOpacity={0.55} />
      {/* Crosshair */}
      <line x1="19" y1="31" x2="45" y2="31" strokeWidth="1.3" strokeOpacity={0.5} />
      <line x1="32" y1="18" x2="32" y2="44" strokeWidth="1.3" strokeOpacity={0.5} />
      {/* Sweep needle + target blip + origin */}
      <line x1="32" y1="31" x2="42.65" y2="23.54" strokeWidth="2" strokeLinecap="round" />
      <circle cx="42.65" cy="23.54" r="2.3" fill="currentColor" stroke="none" />
      <circle cx="32" cy="31" r="1.8" fill="currentColor" stroke="none" />
    </svg>
  )
}

export default VGuardsLogo
