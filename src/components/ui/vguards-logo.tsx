interface VGuardsLogoProps {
  size?: number
  className?: string
  strokeWidth?: number
  ariaHidden?: boolean
}

/**
 * V-Guards brand mark — geometric shield silhouette with a V chevron inside.
 * Strokes use currentColor so the parent controls the color (defaults to the
 * accent token via Tailwind classes).
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
      <path
        d="M32 6 L54 14 L54 32 Q54 50 32 60 Q10 50 10 32 L10 14 Z"
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
      />
      <path
        d="M22 26 L32 44 L42 26"
        strokeWidth={strokeWidth + 1}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default VGuardsLogo
