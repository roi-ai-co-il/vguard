import { useRef, useEffect, type PointerEvent } from 'react'
import * as THREE from 'three'
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

// Global hub coordinates — a real-world spread of cities so the connection
// mesh reads like genuine cross-planet traffic.
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
  { lat: CITY.telaviv[0], lng: CITY.telaviv[1], label: 'Tel Aviv' },
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
  { from: CITY.sf, to: CITY.ny },
  { from: CITY.la, to: CITY.sydney },
  { from: CITY.ny, to: CITY.london },
  { from: CITY.ny, to: CITY.saopaulo },
  { from: CITY.saopaulo, to: CITY.lagos },
  { from: CITY.london, to: CITY.telaviv },
  { from: CITY.london, to: CITY.moscow },
  { from: CITY.paris, to: CITY.dubai },
  { from: CITY.moscow, to: CITY.delhi },
  { from: CITY.cairo, to: CITY.dubai },
  { from: CITY.telaviv, to: CITY.delhi },
  { from: CITY.dubai, to: CITY.singapore },
  { from: CITY.dubai, to: CITY.joburg },
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

const GLOBE_RADIUS = 1

// lat/lng → point on the sphere, oriented to match the equirectangular Earth
// texture (so Tel Aviv, Tokyo, etc. land on the right country). The earth mesh
// carries a -PI/2 Y rotation that this convention is calibrated against.
function latLngToVec3(lat: number, lng: number, radius: number): THREE.Vector3 {
  const phi = ((90 - lat) * Math.PI) / 180
  const theta = ((lng + 180) * Math.PI) / 180
  return new THREE.Vector3(
    -(radius * Math.sin(phi) * Math.cos(theta)),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  )
}

function parseRGB(s: string): THREE.Color {
  const m = s.match(/(\d+(?:\.\d+)?)/g)
  if (m && m.length >= 3) {
    return new THREE.Color(+m[0] / 255, +m[1] / 255, +m[2] / 255)
  }
  return new THREE.Color(s)
}

// Sprite label rendered from a small offscreen canvas — keeps the mono /
// terminal type on the 3D globe without a separate CSS overlay renderer.
function makeLabelSprite(text: string, color: THREE.Color): THREE.Sprite {
  const pad = 8
  const fontPx = 34
  const canvas = document.createElement('canvas')
  const ctx = canvas.getContext('2d')!
  ctx.font = `500 ${fontPx}px ui-monospace, "JetBrains Mono", monospace`
  const w = ctx.measureText(text).width
  canvas.width = Math.ceil(w + pad * 2)
  canvas.height = fontPx + pad * 2
  ctx.font = `500 ${fontPx}px ui-monospace, "JetBrains Mono", monospace`
  ctx.fillStyle = `rgba(${Math.round(color.r * 255)}, ${Math.round(color.g * 255)}, ${Math.round(color.b * 255)}, 0.9)`
  ctx.textBaseline = 'middle'
  ctx.fillText(text, pad, canvas.height / 2)
  const tex = new THREE.CanvasTexture(canvas)
  tex.minFilter = THREE.LinearFilter
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false })
  const sprite = new THREE.Sprite(mat)
  const scale = 0.0022
  sprite.scale.set(canvas.width * scale, canvas.height * scale, 1)
  return sprite
}

export function InteractiveGlobe({
  className,
  size = 600,
  arcColor = 'rgba(34, 211, 238, 0.6)',
  markerColor = 'rgba(125, 240, 255, 1)',
  autoRotateSpeed = 0.0016,
  connections = DEFAULT_CONNECTIONS,
  markers = DEFAULT_MARKERS,
}: GlobeProps) {
  const mountRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef({ active: false, x: 0, y: 0, rotY: 0, rotX: 0 })

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    const cyan = parseRGB(arcColor)
    const markerCol = parseRGB(markerColor)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100)
    camera.position.set(0, 0, 3.1)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    renderer.setSize(size, size)
    renderer.outputColorSpace = THREE.SRGBColorSpace
    mount.appendChild(renderer.domElement)
    renderer.domElement.style.width = '100%'
    renderer.domElement.style.height = '100%'
    renderer.domElement.style.cursor = 'grab'
    renderer.domElement.style.touchAction = 'pan-y'

    // ── Lighting: a "sun" from the upper right gives a real day/night
    //    terminator as the globe turns; gentle ambient keeps the night side
    //    from going pure black.
    scene.add(new THREE.AmbientLight(0x6b7a8f, 0.55))
    const sun = new THREE.DirectionalLight(0xfff4e6, 1.6)
    sun.position.set(3, 1.5, 2)
    scene.add(sun)
    const rim = new THREE.DirectionalLight(cyan.getHex(), 0.5)
    rim.position.set(-2, -0.5, -1)
    scene.add(rim)

    // ── Earth — the group everything (texture, markers, arcs) lives in so it
    //    all rotates together. The -PI/2 offset aligns the texture seam with
    //    the latLngToVec3 convention.
    const earthGroup = new THREE.Group()
    earthGroup.rotation.y = -Math.PI / 2
    earthGroup.rotation.x = 0.35
    scene.add(earthGroup)

    const loader = new THREE.TextureLoader()
    const dayMap = loader.load('/globe/earth-day.jpg', (t) => {
      t.colorSpace = THREE.SRGBColorSpace
    })
    const specMap = loader.load('/globe/earth-bump.jpg')

    const earth = new THREE.Mesh(
      new THREE.SphereGeometry(GLOBE_RADIUS, 96, 96),
      new THREE.MeshPhongMaterial({
        map: dayMap,
        specularMap: specMap,
        specular: new THREE.Color(0x223344),
        shininess: 12,
        emissive: new THREE.Color(0x0a1a2a),
        emissiveIntensity: 0.55,
      }),
    )
    earthGroup.add(earth)

    // ── Cyan atmosphere — a slightly larger back-side sphere with a fresnel
    //    shader gives the glowing rim that ties the globe to the brand.
    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(GLOBE_RADIUS * 1.16, 64, 64),
      new THREE.ShaderMaterial({
        transparent: true,
        side: THREE.BackSide,
        blending: THREE.AdditiveBlending,
        uniforms: { uColor: { value: cyan } },
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }`,
        fragmentShader: `
          varying vec3 vNormal;
          uniform vec3 uColor;
          void main() {
            float intensity = pow(0.62 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 3.0);
            gl_FragColor = vec4(uColor, 1.0) * intensity;
          }`,
      }),
    )
    scene.add(atmosphere)

    // ── Markers (city dots + labels) ─────────────────────────────────────
    const markerGeo = new THREE.SphereGeometry(0.012, 12, 12)
    const markerMat = new THREE.MeshBasicMaterial({ color: markerCol })
    for (const m of markers) {
      const pos = latLngToVec3(m.lat, m.lng, GLOBE_RADIUS * 1.005)
      const dot = new THREE.Mesh(markerGeo, markerMat)
      dot.position.copy(pos)
      earthGroup.add(dot)
      if (m.label) {
        const sprite = makeLabelSprite(m.label, markerCol)
        sprite.position.copy(latLngToVec3(m.lat, m.lng, GLOBE_RADIUS * 1.04))
        earthGroup.add(sprite)
      }
    }

    // ── Connection arcs + travelling pulses ──────────────────────────────
    const arcMat = new THREE.LineBasicMaterial({ color: cyan, transparent: true, opacity: 0.55 })
    const pulseGeo = new THREE.SphereGeometry(0.018, 10, 10)
    const pulseMat = new THREE.MeshBasicMaterial({ color: markerCol, transparent: true, opacity: 0.95 })
    const pulses: { mesh: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; speed: number; phase: number }[] = []

    for (let i = 0; i < connections.length; i++) {
      const c = connections[i]
      const start = latLngToVec3(c.from[0], c.from[1], GLOBE_RADIUS)
      const end = latLngToVec3(c.to[0], c.to[1], GLOBE_RADIUS)
      const mid = start.clone().add(end).multiplyScalar(0.5)
      const lift = 1 + start.distanceTo(end) * 0.4
      mid.normalize().multiplyScalar(GLOBE_RADIUS * lift)
      const curve = new THREE.QuadraticBezierCurve3(start, mid, end)
      const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(48))
      earthGroup.add(new THREE.Line(geo, arcMat))

      const pulse = new THREE.Mesh(pulseGeo, pulseMat)
      earthGroup.add(pulse)
      pulses.push({ mesh: pulse, curve, speed: 0.12 + (i % 5) * 0.03, phase: (i * 0.137) % 1 })
    }

    // ── Animation loop ───────────────────────────────────────────────────
    let raf = 0
    let last = 0
    let elapsed = 0
    const render = (now: number) => {
      if (!last) last = now
      const dt = (now - last) / 1000
      last = now
      elapsed += dt
      if (!dragRef.current.active) {
        earthGroup.rotation.y += autoRotateSpeed * 60 * dt
      }
      for (const p of pulses) {
        const u = (elapsed * p.speed + p.phase) % 1
        p.mesh.position.copy(p.curve.getPoint(u))
        p.mesh.scale.setScalar(0.7 + Math.sin(u * Math.PI) * 0.8)
      }
      renderer.render(scene, camera)
      raf = requestAnimationFrame(render)
    }
    raf = requestAnimationFrame(render)

    // ── Drag to rotate ───────────────────────────────────────────────────
    const el = renderer.domElement
    const onDown = (e: globalThis.PointerEvent) => {
      dragRef.current = {
        active: true,
        x: e.clientX,
        y: e.clientY,
        rotY: earthGroup.rotation.y,
        rotX: earthGroup.rotation.x,
      }
      el.setPointerCapture(e.pointerId)
      el.style.cursor = 'grabbing'
    }
    const onMove = (e: globalThis.PointerEvent) => {
      if (!dragRef.current.active) return
      earthGroup.rotation.y = dragRef.current.rotY + (e.clientX - dragRef.current.x) * 0.005
      earthGroup.rotation.x = Math.max(
        -1,
        Math.min(1, dragRef.current.rotX + (e.clientY - dragRef.current.y) * 0.005),
      )
    }
    const onUp = () => {
      dragRef.current.active = false
      el.style.cursor = 'grab'
    }
    el.addEventListener('pointerdown', onDown)
    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerup', onUp)
    el.addEventListener('pointercancel', onUp)

    return () => {
      cancelAnimationFrame(raf)
      el.removeEventListener('pointerdown', onDown)
      el.removeEventListener('pointermove', onMove)
      el.removeEventListener('pointerup', onUp)
      el.removeEventListener('pointercancel', onUp)
      renderer.dispose()
      scene.traverse((o) => {
        const any = o as THREE.Mesh
        if (any.geometry) any.geometry.dispose()
        const mat = (any as THREE.Mesh).material
        if (Array.isArray(mat)) mat.forEach((m) => m.dispose())
        else if (mat) (mat as THREE.Material).dispose()
      })
      dayMap.dispose()
      specMap.dispose()
      if (renderer.domElement.parentNode === mount) mount.removeChild(renderer.domElement)
    }
  }, [size, arcColor, markerColor, autoRotateSpeed, connections, markers])

  // The pointer handlers live on the canvas itself (added in the effect); the
  // wrapper just sizes the stage.
  const noop = (_e: PointerEvent) => {}
  return (
    <div
      ref={mountRef}
      className={cn(className)}
      style={{ width: size, height: size, maxWidth: '100%', aspectRatio: '1 / 1' }}
      onPointerDown={noop}
      aria-label="Interactive globe of recent V-Guards scans"
      role="img"
    />
  )
}

export default InteractiveGlobe
