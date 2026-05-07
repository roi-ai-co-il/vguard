import { useState, useEffect, useRef, useMemo } from 'react'
import * as THREE from 'three'

const ASCII_CHARS =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789(){}[]<>;:,._-+=!@#$%^&*|\\/\"'`~?"

function generateCode(width: number, height: number): string {
  let text = ''
  for (let i = 0; i < width * height; i++) {
    text += ASCII_CHARS[Math.floor(Math.random() * ASCII_CHARS.length)]
  }
  let out = ''
  for (let i = 0; i < height; i++) {
    out += text.substring(i * width, (i + 1) * width) + '\n'
  }
  return out
}

const DEFAULT_CARDS = [
  '/cards/cursor.svg',
  '/cards/lovable.svg',
  '/cards/bolt.svg',
  '/cards/replit.svg',
  '/cards/v0.svg',
]

interface ScannerCardStreamProps {
  initialSpeed?: number
  direction?: -1 | 1
  cardImages?: string[]
  repeat?: number
  cardGap?: number
  friction?: number
  height?: number
}

export function ScannerCardStream({
  initialSpeed = 80,
  direction = -1,
  cardImages = DEFAULT_CARDS,
  repeat = 4,
  cardGap = 48,
  friction = 0.985,
  height = 250,
}: ScannerCardStreamProps) {
  const [isScanning, setIsScanning] = useState(false)

  const cards = useMemo(() => {
    const total = cardImages.length * repeat
    return Array.from({ length: total }, (_, i) => ({
      id: i,
      image: cardImages[i % cardImages.length],
      ascii: generateCode(Math.floor(400 / 6.5), Math.floor(height / 13)),
    }))
  }, [cardImages, repeat, height])

  const containerRef = useRef<HTMLDivElement>(null)
  const cardLineRef = useRef<HTMLDivElement>(null)
  const particleCanvasRef = useRef<HTMLCanvasElement>(null)
  const scannerCanvasRef = useRef<HTMLCanvasElement>(null)
  const originalAscii = useRef(new Map<number, string>())
  const isPausedRef = useRef(false)

  const cardStreamState = useRef({
    position: 0,
    velocity: initialSpeed,
    direction,
    isDragging: false,
    lastMouseX: 0,
    lastTime: performance.now(),
    cardLineWidth: (400 + cardGap) * cards.length,
    friction,
    minVelocity: 25,
  })

  const scannerState = useRef({ isScanning: false })

  useEffect(() => {
    const container = containerRef.current
    const cardLine = cardLineRef.current
    const particleCanvas = particleCanvasRef.current
    const scannerCanvas = scannerCanvasRef.current
    if (!container || !cardLine || !particleCanvas || !scannerCanvas) return

    cards.forEach((c) => originalAscii.current.set(c.id, c.ascii))

    const dimensions = () => ({
      width: Math.max(container.clientWidth || window.innerWidth || 320, 320),
      height: Math.max(height, 1),
    })
    const initial = dimensions()
    let canvasW = initial.width
    let canvasH = initial.height

    // === Three.js particle field ===
    const scene = new THREE.Scene()
    const camera = new THREE.OrthographicCamera(-canvasW / 2, canvasW / 2, canvasH / 2, -canvasH / 2, 1, 1000)
    camera.position.z = 100
    const renderer = new THREE.WebGLRenderer({ canvas: particleCanvas, alpha: true, antialias: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setSize(canvasW, canvasH, false)
    renderer.setClearColor(0x000000, 0)

    const particleCount = 300
    const geometry = new THREE.BufferGeometry()
    const positions = new Float32Array(particleCount * 3)
    const velocities = new Float32Array(particleCount)
    const alphas = new Float32Array(particleCount)
    const texCanvas = document.createElement('canvas')
    texCanvas.width = 100
    texCanvas.height = 100
    const texCtx = texCanvas.getContext('2d')!
    const half = 50
    const gradient = texCtx.createRadialGradient(half, half, 0, half, half, half)
    gradient.addColorStop(0.025, '#ffffff')
    gradient.addColorStop(0.1, 'hsl(189, 80%, 40%)')
    gradient.addColorStop(0.25, 'hsl(189, 70%, 12%)')
    gradient.addColorStop(1, 'transparent')
    texCtx.fillStyle = gradient
    texCtx.beginPath()
    texCtx.arc(half, half, half, 0, Math.PI * 2)
    texCtx.fill()
    const texture = new THREE.CanvasTexture(texCanvas)

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3] = (Math.random() - 0.5) * canvasW * 2
      positions[i * 3 + 1] = (Math.random() - 0.5) * canvasH
      velocities[i] = Math.random() * 60 + 30
      alphas[i] = (Math.random() * 8 + 2) / 10
    }
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('alpha', new THREE.BufferAttribute(alphas, 1))
    const material = new THREE.ShaderMaterial({
      uniforms: { pointTexture: { value: texture } },
      vertexShader: `attribute float alpha; varying float vAlpha; void main() { vAlpha = alpha; vec4 mvPosition = modelViewMatrix * vec4(position, 1.0); gl_PointSize = 12.0; gl_Position = projectionMatrix * mvPosition; }`,
      fragmentShader: `uniform sampler2D pointTexture; varying float vAlpha; void main() { gl_FragColor = vec4(0.6, 0.95, 1.0, vAlpha) * texture2D(pointTexture, gl_PointCoord); }`,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
    const particles = new THREE.Points(geometry, material)
    scene.add(particles)

    // === Scanner sparks canvas ===
    const ctx = scannerCanvas.getContext('2d')!
    const setScannerSize = () => {
      const dpr = Math.min(window.devicePixelRatio, 2)
      scannerCanvas.width = canvasW * dpr
      scannerCanvas.height = canvasH * dpr
      scannerCanvas.style.width = `${canvasW}px`
      scannerCanvas.style.height = `${canvasH}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    setScannerSize()

    type Spark = { x: number; y: number; vx: number; vy: number; radius: number; alpha: number; life: number; decay: number }
    let scannerParticles: Spark[] = []
    const baseMax = 600
    let currentMax = baseMax
    const scanTargetMax = 1800
    const createSpark = (): Spark => ({
      x: canvasW / 2 + (Math.random() - 0.5) * 3,
      y: Math.random() * canvasH,
      vx: Math.random() * 0.8 + 0.2,
      vy: (Math.random() - 0.5) * 0.3,
      radius: Math.random() * 0.6 + 0.4,
      alpha: Math.random() * 0.4 + 0.6,
      life: 1,
      decay: Math.random() * 0.02 + 0.005,
    })
    for (let i = 0; i < baseMax; i++) scannerParticles.push(createSpark())

    const runScrambleEffect = (element: HTMLElement, cardId: number) => {
      if (element.dataset.scrambling === 'true') return
      element.dataset.scrambling = 'true'
      const original = originalAscii.current.get(cardId) || ''
      let count = 0
      const max = 10
      const interval = window.setInterval(() => {
        element.textContent = generateCode(Math.floor(400 / 6.5), Math.floor(height / 13))
        count++
        if (count >= max) {
          window.clearInterval(interval)
          element.textContent = original
          delete element.dataset.scrambling
        }
      }, 30)
    }

    const updateCardEffects = () => {
      const containerRect = container.getBoundingClientRect()
      const scannerX = containerRect.left + containerRect.width / 2
      const scannerWidth = 8
      const scannerLeft = scannerX - scannerWidth / 2
      const scannerRight = scannerX + scannerWidth / 2
      let anyScanning = false
      cardLine.querySelectorAll<HTMLElement>('.card-wrapper').forEach((wrapper, index) => {
        const rect = wrapper.getBoundingClientRect()
        const normalCard = wrapper.querySelector<HTMLElement>('.card-normal')!
        const asciiCard = wrapper.querySelector<HTMLElement>('.card-ascii')!
        const asciiContent = asciiCard.querySelector<HTMLElement>('pre')!
        if (rect.left < scannerRight && rect.right > scannerLeft) {
          anyScanning = true
          if (wrapper.dataset.scanned !== 'true') runScrambleEffect(asciiContent, index)
          wrapper.dataset.scanned = 'true'
          const intersectLeft = Math.max(scannerLeft - rect.left, 0)
          const intersectRight = Math.min(scannerRight - rect.left, rect.width)
          normalCard.style.setProperty('--clip-right', `${(intersectLeft / rect.width) * 100}%`)
          asciiCard.style.setProperty('--clip-left', `${(intersectRight / rect.width) * 100}%`)
        } else {
          delete wrapper.dataset.scanned
          if (rect.right < scannerLeft) {
            normalCard.style.setProperty('--clip-right', '100%')
            asciiCard.style.setProperty('--clip-left', '100%')
          } else {
            normalCard.style.setProperty('--clip-right', '0%')
            asciiCard.style.setProperty('--clip-left', '0%')
          }
        }
      })
      setIsScanning(anyScanning)
      scannerState.current.isScanning = anyScanning
    }

    // === Drag interaction ===
    const getEventX = (e: MouseEvent | TouchEvent): number => {
      if ('touches' in e && e.touches.length > 0) return e.touches[0].clientX
      if ('changedTouches' in e && e.changedTouches.length > 0) return e.changedTouches[0].clientX
      return (e as MouseEvent).clientX
    }
    const handleDown = (e: MouseEvent | TouchEvent) => {
      cardStreamState.current.isDragging = true
      cardStreamState.current.lastMouseX = getEventX(e)
      cardStreamState.current.velocity = 0
      cardLine.style.cursor = 'grabbing'
    }
    const handleMove = (e: MouseEvent | TouchEvent) => {
      if (!cardStreamState.current.isDragging) return
      const x = getEventX(e)
      const dx = x - cardStreamState.current.lastMouseX
      cardStreamState.current.position += dx
      cardStreamState.current.lastMouseX = x
      cardStreamState.current.velocity = Math.min(1200, Math.abs(dx) * 30)
      cardStreamState.current.direction = dx < 0 ? -1 : 1
    }
    const handleUp = () => {
      cardStreamState.current.isDragging = false
      cardLine.style.cursor = 'grab'
    }
    const handleWheel = (e: WheelEvent) => {
      e.preventDefault()
      cardStreamState.current.velocity = Math.min(800, Math.abs(e.deltaY) * 4)
      cardStreamState.current.direction = e.deltaY > 0 ? -1 : 1
    }
    cardLine.addEventListener('mousedown', handleDown)
    window.addEventListener('mousemove', handleMove)
    window.addEventListener('mouseup', handleUp)
    cardLine.addEventListener('touchstart', handleDown, { passive: true })
    window.addEventListener('touchmove', handleMove, { passive: true })
    window.addEventListener('touchend', handleUp)
    cardLine.addEventListener('wheel', handleWheel, { passive: false })

    // === Resize observer ===
    const resizeObserver = new ResizeObserver(() => {
      const next = dimensions()
      if (!Number.isFinite(next.width) || !Number.isFinite(next.height) || next.width < 1) return
      canvasW = next.width
      canvasH = next.height
      camera.left = -canvasW / 2
      camera.right = canvasW / 2
      camera.top = canvasH / 2
      camera.bottom = -canvasH / 2
      camera.updateProjectionMatrix()
      renderer.setSize(canvasW, canvasH, false)
      setScannerSize()
      cardStreamState.current.cardLineWidth = (400 + cardGap) * cards.length
    })
    resizeObserver.observe(container)

    let animationFrameId = 0
    const animate = (currentTime: number) => {
      const deltaTime = (currentTime - cardStreamState.current.lastTime) / 1000
      cardStreamState.current.lastTime = currentTime
      if (!isPausedRef.current && !cardStreamState.current.isDragging) {
        if (cardStreamState.current.velocity > cardStreamState.current.minVelocity) {
          cardStreamState.current.velocity *= cardStreamState.current.friction
        } else {
          cardStreamState.current.velocity = cardStreamState.current.minVelocity
        }
        cardStreamState.current.position +=
          cardStreamState.current.velocity * cardStreamState.current.direction * deltaTime
      }
      const { position, cardLineWidth } = cardStreamState.current
      const containerWidth = container.offsetWidth
      if (position < -cardLineWidth) cardStreamState.current.position = containerWidth
      else if (position > containerWidth) cardStreamState.current.position = -cardLineWidth
      cardLine.style.transform = `translate3d(${cardStreamState.current.position}px, 0, 0)`
      updateCardEffects()

      const t = currentTime * 0.001
      for (let i = 0; i < particleCount; i++) {
        positions[i * 3] += velocities[i] * 0.016
        if (positions[i * 3] > canvasW / 2 + 100) positions[i * 3] = -canvasW / 2 - 100
        positions[i * 3 + 1] += Math.sin(t + i * 0.1) * 0.4
        alphas[i] = Math.max(0.1, Math.min(1, alphas[i] + (Math.random() - 0.5) * 0.05))
      }
      geometry.attributes.position.needsUpdate = true
      geometry.attributes.alpha.needsUpdate = true
      renderer.render(scene, camera)

      ctx.clearRect(0, 0, canvasW, canvasH)
      const target = scannerState.current.isScanning ? scanTargetMax : baseMax
      currentMax += (target - currentMax) * 0.05
      while (scannerParticles.length < currentMax) scannerParticles.push(createSpark())
      while (scannerParticles.length > currentMax) scannerParticles.pop()
      scannerParticles.forEach((p) => {
        p.x += p.vx
        p.y += p.vy
        p.life -= p.decay
        if (p.life <= 0 || p.x > canvasW) Object.assign(p, createSpark())
        ctx.globalAlpha = p.alpha * p.life
        ctx.fillStyle = '#a3e9f4'
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2)
        ctx.fill()
      })

      animationFrameId = requestAnimationFrame(animate)
    }
    animationFrameId = requestAnimationFrame(animate)

    // pause when off-screen — saves CPU on slow devices
    const visibilityObserver = new IntersectionObserver(
      ([entry]) => {
        isPausedRef.current = !entry.isIntersecting
      },
      { threshold: 0.05 },
    )
    visibilityObserver.observe(container)

    return () => {
      cancelAnimationFrame(animationFrameId)
      cardLine.removeEventListener('mousedown', handleDown)
      window.removeEventListener('mousemove', handleMove)
      window.removeEventListener('mouseup', handleUp)
      cardLine.removeEventListener('touchstart', handleDown)
      window.removeEventListener('touchmove', handleMove)
      window.removeEventListener('touchend', handleUp)
      cardLine.removeEventListener('wheel', handleWheel)
      resizeObserver.disconnect()
      visibilityObserver.disconnect()
      geometry.dispose()
      material.dispose()
      texture.dispose()
      renderer.dispose()
    }
  }, [cards, cardGap, friction, height])

  return (
    <div
      ref={containerRef}
      className="relative w-full overflow-hidden bg-(--color-bg)"
      style={{ height }}
      role="img"
      aria-label="Live demo of V-Guards scanning vibe-coded apps from Cursor, Lovable, Bolt, Replit, and v0 — each app's bundle is decoded as the scanner passes over it."
    >
      <canvas
        ref={particleCanvasRef}
        className="absolute inset-0 w-full h-full z-0 pointer-events-none"
      />
      <canvas
        ref={scannerCanvasRef}
        className="absolute inset-0 w-full h-full z-10 pointer-events-none"
      />
      <div
        className={`vg-scanner-line absolute top-0 bottom-0 left-1/2 w-0.5 -translate-x-1/2 bg-gradient-to-b from-transparent via-(--color-accent) to-transparent rounded-full z-20 pointer-events-none transition-opacity duration-300 ${
          isScanning ? 'opacity-100' : 'opacity-60'
        }`}
        style={{
          boxShadow:
            '0 0 10px var(--color-accent), 0 0 20px var(--color-accent), 0 0 40px var(--color-accent-strong)',
          animation: 'vgScanPulse 1.5s infinite alternate ease-in-out',
        }}
        aria-hidden="true"
      />
      <div className="absolute inset-0 flex items-center pointer-events-none">
        <div
          ref={cardLineRef}
          className="flex items-center whitespace-nowrap cursor-grab select-none will-change-transform pointer-events-auto"
          style={{ gap: `${cardGap}px` }}
        >
          {cards.map((card) => (
            <div key={card.id} className="card-wrapper relative w-[400px] h-[250px] shrink-0">
              <div
                className="card-normal absolute inset-0 rounded-[15px] overflow-hidden bg-transparent shadow-[0_15px_40px_rgba(0,0,0,0.4)] z-[2]"
                style={{ clipPath: 'inset(0 var(--clip-right, 0%) 0 0)' }}
              >
                <img
                  src={card.image}
                  alt=""
                  className="w-full h-full object-cover rounded-[15px]"
                  loading="lazy"
                  decoding="async"
                  draggable={false}
                />
              </div>
              <div
                className="card-ascii absolute inset-0 rounded-[15px] overflow-hidden bg-transparent z-[1]"
                style={{ clipPath: 'inset(0 calc(100% - var(--clip-left, 0%)) 0 0)' }}
              >
                <pre
                  className="absolute inset-0 text-[rgba(180,235,250,0.55)] font-mono text-[11px] leading-[13px] overflow-hidden whitespace-pre m-0 p-0 text-left"
                  style={{
                    maskImage:
                      'linear-gradient(to right, rgba(0,0,0,1) 0%, rgba(0,0,0,0.7) 40%, rgba(0,0,0,0.4) 70%, rgba(0,0,0,0.15) 100%)',
                    WebkitMaskImage:
                      'linear-gradient(to right, rgba(0,0,0,1) 0%, rgba(0,0,0,0.7) 40%, rgba(0,0,0,0.4) 70%, rgba(0,0,0,0.15) 100%)',
                    animation: 'vgGlitch 0.1s infinite linear alternate-reverse',
                  }}
                >
                  {card.ascii}
                </pre>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default ScannerCardStream
