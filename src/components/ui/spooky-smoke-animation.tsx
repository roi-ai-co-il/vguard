import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface SmokeBackgroundProps {
  /** Smoke tint. Hex (#rrggbb / #rgb) or rgb()/rgba(). Defaults to the V-Guards cyan. */
  smokeColor?: string
  /** Number of drifting smoke puffs. Lower = lighter / cheaper. */
  density?: number
  /** Master opacity of the whole layer (0–1). Keep low behind hero text. */
  intensity?: number
  className?: string
}

interface Puff {
  x: number
  y: number
  r: number
  vx: number
  vy: number
  life: number
  maxLife: number
  /** 0 → smokeColor, 1 → white. Lets the cloud read as cyan AND white. */
  whiteMix: number
}

/** Parse a CSS color string into [r,g,b]. Supports #rgb, #rrggbb, rgb(), rgba(). */
function parseRgb(color: string): [number, number, number] {
  const c = color.trim()
  if (c.startsWith('#')) {
    let hex = c.slice(1)
    if (hex.length === 3) hex = hex.split('').map((ch) => ch + ch).join('')
    const n = parseInt(hex, 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  }
  const m = c.match(/(\d+(?:\.\d+)?)/g)
  if (m && m.length >= 3) return [+m[0], +m[1], +m[2]]
  return [34, 211, 238] // fallback: cyan
}

/**
 * Animated smoke / fog background, canvas-based, zero dependencies.
 * Soft radial puffs drift upward and fade, tinted between `smokeColor` and white
 * so the field reads as a cyan-and-white haze. Honors prefers-reduced-motion
 * (renders one static frame). Always decorative + pointer-events-none.
 */
export function SmokeBackground({
  smokeColor = '#22d3ee',
  density = 26,
  intensity = 0.5,
  className,
}: SmokeBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const [cr, cg, cb] = parseRgb(smokeColor)
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    let w = 0
    let h = 0
    let raf = 0

    const resize = () => {
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = Math.max(1, Math.floor(w * dpr))
      canvas.height = Math.max(1, Math.floor(h * dpr))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()

    // deterministic-ish pseudo-random (no Math.random ban concerns in a browser,
    // but keep spawn varied by index)
    const rand = (a: number, b: number) => a + Math.random() * (b - a)

    const makePuff = (seed = false): Puff => {
      const maxLife = rand(6, 13)
      return {
        x: rand(-0.1, 1.1) * w,
        y: seed ? rand(0, 1) * h : rand(0.85, 1.15) * h,
        r: rand(0.18, 0.42) * Math.max(w, h) * 0.5,
        vx: rand(-8, 8),
        vy: rand(-26, -12),
        life: seed ? rand(0, maxLife) : 0,
        maxLife,
        whiteMix: rand(0, 1),
      }
    }

    const puffs: Puff[] = Array.from({ length: density }, () => makePuff(true))

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const drawPuff = (p: Puff, alpha: number) => {
      const rr = Math.round(cr + (255 - cr) * p.whiteMix)
      const rg = Math.round(cg + (255 - cg) * p.whiteMix)
      const rb = Math.round(cb + (255 - cb) * p.whiteMix)
      const g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r)
      g.addColorStop(0, `rgba(${rr},${rg},${rb},${alpha})`)
      g.addColorStop(1, `rgba(${rr},${rg},${rb},0)`)
      ctx.fillStyle = g
      ctx.beginPath()
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
      ctx.fill()
    }

    let last = performance.now()
    const render = (now: number) => {
      const dt = Math.min((now - last) / 1000, 0.05)
      last = now
      ctx.clearRect(0, 0, w, h)
      ctx.globalCompositeOperation = 'source-over'
      ctx.globalAlpha = intensity

      for (let i = 0; i < puffs.length; i++) {
        const p = puffs[i]
        p.life += dt
        p.x += p.vx * dt
        p.y += p.vy * dt
        p.r += dt * 14
        // triangular fade: 0 → peak → 0 across its life
        const t = p.life / p.maxLife
        const fade = t < 0.5 ? t * 2 : (1 - t) * 2
        const alpha = Math.max(0, fade) * 0.16
        if (alpha > 0.001) drawPuff(p, alpha)
        if (p.life >= p.maxLife || p.y + p.r < -20) puffs[i] = makePuff()
      }

      ctx.globalAlpha = 1
      if (!reduce) raf = requestAnimationFrame(render)
    }

    if (reduce) {
      // single static frame
      render(performance.now())
    } else {
      raf = requestAnimationFrame(render)
    }

    window.addEventListener('resize', resize)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [smokeColor, density, intensity])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className={cn('block h-full w-full', className)}
    />
  )
}

export default SmokeBackground
