import markUrl from '@/assets/vguards-mark.svg'
import markLightUrl from '@/assets/vguards-mark-light.svg'
import { cn } from '@/lib/utils'

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

/**
 * Decorative watermark variant of the mascot: a dim cyan raccoon with a brighter
 * cyan "scan wave" sweeping top→bottom (the security-scanner motif). Two stacked
 * copies of the mark — a faint base + a bright copy revealed by an animated band
 * (clip-path). Always aria-hidden; respects prefers-reduced-motion.
 */
export function MascotScanMark({ size, className }: { size: number; className?: string }) {
  return (
    <div className={cn('vg-mascot-scan', className)} style={{ width: size, height: size }} aria-hidden="true">
      {/* light-background variant: inner shield fill is white, not the dark
          rgb(9,9,11), so the watermark has no black box on the white theme */}
      <img src={markLightUrl} alt="" draggable={false} className="vg-mascot-scan__base" />
      <img src={markLightUrl} alt="" draggable={false} className="vg-mascot-scan__beam" />
    </div>
  )
}

export default VGuardsLogo
