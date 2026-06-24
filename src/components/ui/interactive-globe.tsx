import { useRef, useEffect, useCallback, type PointerEvent } from 'react'
import { cn } from '@/lib/utils'

interface GlobeProps {
  className?: string
  size?: number
  dotColor?: string
  arcColor?: string
  markerColor?: string
  autoRotateSpeed?: number
  connections?: { from: [number, number]; to: [number, number] }[]
  markers?: { lat: number; lng: number; label?: string }[]
}

// Global hub coordinates — a denser, more real-world spread of cities so the
// connection mesh reads like genuine cross-planet traffic.
const CITY = {
  sf: [37.78, -122.42] as [number, number],
  la: [34.05, -118.24] as [number, number],
  ny: [40.71, -74.01] as [number, number],
  toronto: [43.65, -79.38] as [number, number],
  saopaulo: [-23.55, -46.63] as [number, number],
  mexico: [19.43, -99.13] as [number, number],
  london: [51.51, -0.13] as [number, number],
  paris: [48.85, 2.35] as [number, number],
  berlin: [52.52, 13.4] as [number, number],
  moscow: [55.76, 37.62] as [number, number],
  telaviv: [32.08, 34.78] as [number, number],
  dubai: [25.2, 55.27] as [number, number],
  cairo: [30.04, 31.24] as [number, number],
  lagos: [6.52, 3.38] as [number, number],
  joburg: [-26.2, 28.05] as [number, number],
  delhi: [28.61, 77.21] as [number, number],
  bangalore: [12.97, 77.59] as [number, number],
  singapore: [1.35, 103.82] as [number, number],
  hongkong: [22.32, 114.17] as [number, number],
  tokyo: [35.68, 139.69] as [number, number],
  seoul: [37.57, 126.98] as [number, number],
  sydney: [-33.87, 151.21] as [number, number],
}

// Only the major hubs carry a text label — every city still renders a dot, but
// labelling all 22 would clutter the sphere.
const DEFAULT_MARKERS: { lat: number; lng: number; label?: string }[] = [
  { lat: CITY.sf[0], lng: CITY.sf[1], label: 'San Francisco' },
  { lat: CITY.la[0], lng: CITY.la[1] },
  { lat: CITY.ny[0], lng: CITY.ny[1], label: 'New York' },
  { lat: CITY.toronto[0], lng: CITY.toronto[1] },
  { lat: CITY.saopaulo[0], lng: CITY.saopaulo[1], label: 'São Paulo' },
  { lat: CITY.mexico[0], lng: CITY.mexico[1] },
  { lat: CITY.london[0], lng: CITY.london[1], label: 'London' },
  { lat: CITY.paris[0], lng: CITY.paris[1] },
  { lat: CITY.berlin[0], lng: CITY.berlin[1] },
  { lat: CITY.moscow[0], lng: CITY.moscow[1] },
  { lat: CITY.telaviv[0], lng: CITY.telaviv[1] },
  { lat: CITY.dubai[0], lng: CITY.dubai[1] },
  { lat: CITY.cairo[0], lng: CITY.cairo[1] },
  { lat: CITY.lagos[0], lng: CITY.lagos[1] },
  { lat: CITY.joburg[0], lng: CITY.joburg[1] },
  { lat: CITY.delhi[0], lng: CITY.delhi[1], label: 'Delhi' },
  { lat: CITY.bangalore[0], lng: CITY.bangalore[1] },
  { lat: CITY.singapore[0], lng: CITY.singapore[1], label: 'Singapore' },
  { lat: CITY.hongkong[0], lng: CITY.hongkong[1] },
  { lat: CITY.tokyo[0], lng: CITY.tokyo[1], label: 'Tokyo' },
  { lat: CITY.seoul[0], lng: CITY.seoul[1] },
  { lat: CITY.sydney[0], lng: CITY.sydney[1], label: 'Sydney' },
]

const DEFAULT_CONNECTIONS: { from: [number, number]; to: [number, number] }[] = [
  { from: CITY.sf, to: CITY.london },
  { from: CITY.sf, to: CITY.tokyo },
  { from: CITY.sf, to: CITY.singapore },
  { from: CITY.sf, to: CITY.ny },
  { from: CITY.la, to: CITY.mexico },
  { from: CITY.la, to: CITY.sydney },
  { from: CITY.ny, to: CITY.london },
  { from: CITY.ny, to: CITY.saopaulo },
  { from: CITY.ny, to: CITY.toronto },
  { from: CITY.toronto, to: CITY.paris },
  { from: CITY.saopaulo, to: CITY.lagos },
  { from: CITY.mexico, to: CITY.saopaulo },
  { from: CITY.london, to: CITY.berlin },
  { from: CITY.london, to: CITY.telaviv },
  { from: CITY.london, to: CITY.moscow },
  { from: CITY.paris, to: CITY.dubai },
  { from: CITY.berlin, to: CITY.moscow },
  { from: CITY.moscow, to: CITY.delhi },
  { from: CITY.cairo, to: CITY.london },
  { from: CITY.cairo, to: CITY.dubai },
  { from: CITY.telaviv, to: CITY.delhi },
  { from: CITY.telaviv, to: CITY.lagos },
  { from: CITY.dubai, to: CITY.singapore },
  { from: CITY.dubai, to: CITY.joburg },
  { from: CITY.lagos, to: CITY.joburg },
  { from: CITY.delhi, to: CITY.bangalore },
  { from: CITY.bangalore, to: CITY.singapore },
  { from: CITY.singapore, to: CITY.hongkong },
  { from: CITY.singapore, to: CITY.sydney },
  { from: CITY.hongkong, to: CITY.tokyo },
  { from: CITY.tokyo, to: CITY.seoul },
  { from: CITY.tokyo, to: CITY.sydney },
  { from: CITY.seoul, to: CITY.sf },
  { from: CITY.joburg, to: CITY.sydney },
]

function latLngToXYZ(lat: number, lng: number, radius: number): [number, number, number] {
  const phi = ((90 - lat) * Math.PI) / 180
  const theta = ((lng + 180) * Math.PI) / 180
  return [
    -(radius * Math.sin(phi) * Math.cos(theta)),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  ]
}

function rotateY(x: number, y: number, z: number, angle: number): [number, number, number] {
  const cos = Math.cos(angle)
  const sin = Math.sin(angle)
  return [x * cos + z * sin, y, -x * sin + z * cos]
}

function rotateX(x: number, y: number, z: number, angle: number): [number, number, number] {
  const cos = Math.cos(angle)
  const sin = Math.sin(angle)
  return [x, y * cos - z * sin, y * sin + z * cos]
}

function project(
  x: number,
  y: number,
  z: number,
  cx: number,
  cy: number,
  fov: number,
): [number, number, number] {
  const scale = fov / (fov + z)
  return [x * scale + cx, y * scale + cy, z]
}

export function InteractiveGlobe({
  className,
  size = 600,
  dotColor = 'rgba(34, 211, 238, ALPHA)',
  arcColor = 'rgba(34, 211, 238, 0.5)',
  markerColor = 'rgba(125, 240, 255, 1)',
  autoRotateSpeed = 0.002,
  connections = DEFAULT_CONNECTIONS,
  markers = DEFAULT_MARKERS,
}: GlobeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const rotYRef = useRef(0.4)
  const rotXRef = useRef(0.3)
  const dragRef = useRef<{
    active: boolean
    startX: number
    startY: number
    startRotY: number
    startRotX: number
  }>({ active: false, startX: 0, startY: 0, startRotY: 0, startRotX: 0 })
  const animRef = useRef<number>(0)
  const timeRef = useRef(0)
  const dotsRef = useRef<[number, number, number][]>([])

  useEffect(() => {
    const dots: [number, number, number][] = []
    const numDots = 1200
    const goldenRatio = (1 + Math.sqrt(5)) / 2
    for (let i = 0; i < numDots; i++) {
      const theta = (2 * Math.PI * i) / goldenRatio
      const phi = Math.acos(1 - (2 * (i + 0.5)) / numDots)
      const x = Math.cos(theta) * Math.sin(phi)
      const y = Math.cos(phi)
      const z = Math.sin(theta) * Math.sin(phi)
      dots.push([x, y, z])
    }
    dotsRef.current = dots
  }, [])

  const draw = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    // Guard against pre-layout zero dimensions — drawing with w=0 yields NaN
    // in subsequent radius/cosine math and pollutes the console.
    const w = canvas.clientWidth || size
    const h = canvas.clientHeight || size
    if (w < 1 || h < 1) return
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr
      canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    const cx = w / 2
    const cy = h / 2
    const radius = Math.min(w, h) * 0.38
    const fov = 600

    if (!dragRef.current.active) {
      rotYRef.current += autoRotateSpeed
    }

    timeRef.current += 0.015
    const time = timeRef.current

    ctx.clearRect(0, 0, w, h)

    const glowGrad = ctx.createRadialGradient(cx, cy, radius * 0.8, cx, cy, radius * 1.5)
    glowGrad.addColorStop(0, 'rgba(34, 211, 238, 0.05)')
    glowGrad.addColorStop(1, 'rgba(34, 211, 238, 0)')
    ctx.fillStyle = glowGrad
    ctx.fillRect(0, 0, w, h)

    ctx.beginPath()
    ctx.arc(cx, cy, radius, 0, Math.PI * 2)
    ctx.strokeStyle = 'rgba(34, 211, 238, 0.08)'
    ctx.lineWidth = 1
    ctx.stroke()

    const ry = rotYRef.current
    const rx = rotXRef.current

    // Graticule — meridians + parallels traced on the sphere give it a real
    // globe's wireframe read (front hemisphere only, depth-faded). Drawn under
    // the dot field so the dots sit on top like surface texture.
    const drawGraticule = (samples: [number, number][]) => {
      let prev: { sx: number; sy: number; z: number; front: boolean } | null = null
      for (const [glat, glng] of samples) {
        let [gx, gy, gz] = latLngToXYZ(glat, glng, radius)
        ;[gx, gy, gz] = rotateX(gx, gy, gz, rx)
        ;[gx, gy, gz] = rotateY(gx, gy, gz, ry)
        const [sx, sy] = project(gx, gy, gz, cx, cy, fov)
        const front = gz < 0
        if (prev && prev.front && front) {
          const meanZ = (gz + prev.z) / 2
          const depthT = Math.max(0, Math.min(1, -meanZ / radius))
          ctx.beginPath()
          ctx.moveTo(prev.sx, prev.sy)
          ctx.lineTo(sx, sy)
          ctx.strokeStyle = `rgba(34, 211, 238, ${(0.05 + 0.13 * depthT).toFixed(2)})`
          ctx.lineWidth = 0.6
          ctx.stroke()
        }
        prev = { sx, sy, z: gz, front }
      }
    }
    for (let lng = -180; lng < 180; lng += 30) {
      const meridian: [number, number][] = []
      for (let lat = -90; lat <= 90; lat += 4) meridian.push([lat, lng])
      drawGraticule(meridian)
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const parallel: [number, number][] = []
      for (let lng = -180; lng <= 180; lng += 4) parallel.push([lat, lng])
      drawGraticule(parallel)
    }

    const dots = dotsRef.current
    for (let i = 0; i < dots.length; i++) {
      const [dx, dy, dz] = dots[i]
      let x = dx * radius
      let y = dy * radius
      let z = dz * radius

      ;[x, y, z] = rotateX(x, y, z, rx)
      ;[x, y, z] = rotateY(x, y, z, ry)

      if (z > 0) continue

      const [sx, sy] = project(x, y, z, cx, cy, fov)
      const depthAlpha = Math.max(0.1, 1 - (z + radius) / (2 * radius))
      const dotSize = 1 + depthAlpha * 0.8

      ctx.beginPath()
      ctx.arc(sx, sy, dotSize, 0, Math.PI * 2)
      ctx.fillStyle = dotColor.replace('ALPHA', depthAlpha.toFixed(2))
      ctx.fill()
    }

    // Occlusion threshold matches the markers below (z > radius * 0.1) so an
    // arc only renders when BOTH endpoints will have a visible marker dot.
    // The previous `z > 0.3 && z > 0.3` (AND) drew a line whenever even ONE
    // endpoint was visible, leaving the other end floating in mid-air where
    // the hidden marker would have been — visually broken.
    const OCCLUDE_Z = radius * 0.1
    for (const conn of connections) {
      const [lat1, lng1] = conn.from
      const [lat2, lng2] = conn.to

      let [x1, y1, z1] = latLngToXYZ(lat1, lng1, radius)
      let [x2, y2, z2] = latLngToXYZ(lat2, lng2, radius)

      ;[x1, y1, z1] = rotateX(x1, y1, z1, rx)
      ;[x1, y1, z1] = rotateY(x1, y1, z1, ry)
      ;[x2, y2, z2] = rotateX(x2, y2, z2, rx)
      ;[x2, y2, z2] = rotateY(x2, y2, z2, ry)

      // Either endpoint hidden → drop the arc entirely. We accept a few
      // missing connections rather than show "lines into nothing".
      if (z1 > OCCLUDE_Z || z2 > OCCLUDE_Z) continue

      const [sx1, sy1] = project(x1, y1, z1, cx, cy, fov)
      const [sx2, sy2] = project(x2, y2, z2, cx, cy, fov)

      const midX = (x1 + x2) / 2
      const midY = (y1 + y2) / 2
      const midZ = (z1 + z2) / 2
      const midLen = Math.sqrt(midX * midX + midY * midY + midZ * midZ)
      const arcHeight = radius * 1.25
      const elevX = (midX / midLen) * arcHeight
      const elevY = (midY / midLen) * arcHeight
      const elevZ = (midZ / midLen) * arcHeight
      const [scx, scy] = project(elevX, elevY, elevZ, cx, cy, fov)

      // Depth-based alpha: arcs near the front are crisp, arcs that lean
      // toward the visible horizon fade — gives the globe more "depth" feel.
      const meanZ = (z1 + z2) / 2
      const depthT = Math.max(0, Math.min(1, (radius - meanZ) / (2 * radius)))
      const arcAlpha = 0.25 + 0.55 * depthT

      ctx.beginPath()
      ctx.moveTo(sx1, sy1)
      ctx.quadraticCurveTo(scx, scy, sx2, sy2)
      ctx.strokeStyle = arcColor.replace(/[\d.]+\)$/, `${arcAlpha.toFixed(2)})`)
      ctx.lineWidth = 1.2
      ctx.lineCap = 'round'
      ctx.stroke()

      // Anchor "studs" at both endpoints so each arc visibly terminates IN a
      // dot — fixes the perception that lines are floating.
      ctx.beginPath()
      ctx.arc(sx1, sy1, 1.3, 0, Math.PI * 2)
      ctx.fillStyle = arcColor.replace(/[\d.]+\)$/, '0.85)')
      ctx.fill()
      ctx.beginPath()
      ctx.arc(sx2, sy2, 1.3, 0, Math.PI * 2)
      ctx.fill()

      // Travelling pulse along the arc.
      const t = (Math.sin(time * 1.2 + lat1 * 0.1) + 1) / 2
      const tx = (1 - t) * (1 - t) * sx1 + 2 * (1 - t) * t * scx + t * t * sx2
      const ty = (1 - t) * (1 - t) * sy1 + 2 * (1 - t) * t * scy + t * t * sy2

      // Glow halo around the moving pulse.
      const glow = ctx.createRadialGradient(tx, ty, 0, tx, ty, 6)
      glow.addColorStop(0, markerColor)
      glow.addColorStop(1, markerColor.replace('1)', '0)'))
      ctx.beginPath()
      ctx.arc(tx, ty, 6, 0, Math.PI * 2)
      ctx.fillStyle = glow
      ctx.fill()

      ctx.beginPath()
      ctx.arc(tx, ty, 2, 0, Math.PI * 2)
      ctx.fillStyle = markerColor
      ctx.fill()
    }

    for (const marker of markers) {
      let [x, y, z] = latLngToXYZ(marker.lat, marker.lng, radius)
      ;[x, y, z] = rotateX(x, y, z, rx)
      ;[x, y, z] = rotateY(x, y, z, ry)

      if (z > radius * 0.1) continue

      const [sx, sy] = project(x, y, z, cx, cy, fov)

      const pulse = Math.sin(time * 2 + marker.lat) * 0.5 + 0.5
      ctx.beginPath()
      ctx.arc(sx, sy, 4 + pulse * 4, 0, Math.PI * 2)
      ctx.strokeStyle = markerColor.replace('1)', `${0.2 + pulse * 0.15})`)
      ctx.lineWidth = 1
      ctx.stroke()

      ctx.beginPath()
      ctx.arc(sx, sy, 2.5, 0, Math.PI * 2)
      ctx.fillStyle = markerColor
      ctx.fill()

      if (marker.label) {
        ctx.font = '10px ui-monospace, "JetBrains Mono", monospace'
        ctx.fillStyle = markerColor.replace('1)', '0.6)')
        ctx.fillText(marker.label, sx + 8, sy + 3)
      }
    }

    animRef.current = requestAnimationFrame(draw)
  }, [dotColor, arcColor, markerColor, autoRotateSpeed, connections, markers])

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(animRef.current)
  }, [draw])

  const onPointerDown = useCallback((e: PointerEvent) => {
    dragRef.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      startRotY: rotYRef.current,
      startRotX: rotXRef.current,
    }
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }, [])

  const onPointerMove = useCallback((e: PointerEvent) => {
    if (!dragRef.current.active) return
    const dx = e.clientX - dragRef.current.startX
    const dy = e.clientY - dragRef.current.startY
    rotYRef.current = dragRef.current.startRotY + dx * 0.005
    rotXRef.current = Math.max(-1, Math.min(1, dragRef.current.startRotX + dy * 0.005))
  }, [])

  const onPointerUp = useCallback(() => {
    dragRef.current.active = false
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={cn('cursor-grab active:cursor-grabbing', className)}
      // touch-action: pan-y lets a vertical swipe scroll the page (instead of
      // being trapped rotating the globe); horizontal drags still rotate it.
      style={{ width: size, height: size, maxWidth: '100%', touchAction: 'pan-y' }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      aria-label="Interactive globe of recent V-Guards scans"
      role="img"
    />
  )
}

export default InteractiveGlobe
