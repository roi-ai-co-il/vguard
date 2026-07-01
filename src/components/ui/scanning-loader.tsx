import { VGuardsLogo } from '@/components/ui/vguards-logo'

interface ScanningLoaderProps {
  size?: number
}

/**
 * Inline "scanning" loader — a rotating cyan scan ring with the V-Guards mark
 * pulsing at its center (like a radar sweeping around the brand). Recolored to
 * the accent; keyframes live in index.css (`vgScanningRing` / `vgScanningLogo`).
 *
 * Replaces the old mono "SCANNING" lettering, which clashed with the site's
 * sans-forward GUI. Drops in anywhere a 0–100% progress UI used to live.
 */
export function ScanningLoader({ size = 140 }: ScanningLoaderProps) {
  return (
    <div
      className="relative flex items-center justify-center select-none"
      style={{ width: size, height: size }}
      role="progressbar"
      aria-busy="true"
      aria-label="Scanning…"
      aria-valuetext="Scanning…"
    >
      <div className="vg-scanning-logo" aria-hidden="true">
        <VGuardsLogo size={Math.round(size * 0.4)} />
      </div>
      <div className="vg-scanning-ring absolute inset-0 rounded-full pointer-events-none" aria-hidden="true" />
    </div>
  )
}

export default ScanningLoader
