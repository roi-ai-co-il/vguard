interface ScanningLoaderProps {
  size?: number
  text?: string
}

/**
 * Inline "scanning" loader — adapted from the 21st.dev ai-loader concept,
 * recolored to V-Guards' cyan accent and converted from styled-jsx to plain
 * CSS (keyframes live in index.css as `vgScanningRing` / `vgScanningLetter`).
 *
 * Drops in anywhere a 0–100% progress UI used to live; replaces the
 * "filling bar" metaphor with a continuous, text-forward signal that the
 * scan is actively running.
 */
export function ScanningLoader({ size = 140, text = 'SCANNING' }: ScanningLoaderProps) {
  const letters = text.split('')
  return (
    <div
      className="relative flex items-center justify-center select-none"
      style={{ width: size, height: size }}
      role="progressbar"
      aria-busy="true"
      aria-label={`${text}…`}
      aria-valuetext={`${text}…`}
    >
      {letters.map((letter, index) => (
        <span
          key={index}
          className="vg-scanning-letter inline-block font-mono font-semibold text-(--color-accent) opacity-50 tracking-[0.18em]"
          style={{
            animationDelay: `${index * 0.12}s`,
            fontSize: `${Math.round(size * 0.11)}px`,
          }}
        >
          {letter}
        </span>
      ))}
      <div className="vg-scanning-ring absolute inset-0 rounded-full pointer-events-none" aria-hidden="true" />
    </div>
  )
}

export default ScanningLoader
