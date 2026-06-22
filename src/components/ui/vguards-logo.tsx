import markUrl from '@/assets/vguards-mark.svg'

interface VGuardsLogoProps {
  size?: number
  className?: string
  /** @deprecated kept for call-site compatibility; the mark is a fixed-color asset now. */
  strokeWidth?: number
  ariaHidden?: boolean
}

/**
 * V-Guards brand mark — the raccoon mascot (robber-mask face + ears + striped
 * tail) inside the security shield, in the cyan DNA accent. Rendered from the
 * vector asset `src/assets/vguards-mark.svg` (transparent background).
 */
export function VGuardsLogo({ size = 18, className, ariaHidden = true }: VGuardsLogoProps) {
  return (
    <img
      src={markUrl}
      width={size}
      height={size}
      className={className}
      alt={ariaHidden ? '' : 'V-Guards'}
      aria-hidden={ariaHidden}
      draggable={false}
      style={{ display: 'block' }}
    />
  )
}

export default VGuardsLogo
