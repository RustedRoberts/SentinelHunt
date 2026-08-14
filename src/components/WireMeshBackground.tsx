import { useEffect, useRef } from 'react'

const CELL_SIZE = 46
const AMBIENT_AMPLITUDE = 6
const RIPPLE_AMPLITUDE = 16
const RIPPLE_SPEED = 340 // px/s the wavefront travels outward
const RIPPLE_LIFE = 1500 // ms before a ripple fully decays
const RIPPLE_BAND = 70 // px width of the traveling wavefront
const MAX_RIPPLES = 24
const MIN_SPAWN_DIST = 22 // px the cursor must move before spawning a new ripple

const BASE = { r: 82, g: 88, b: 100 }
const LIME = { r: 212, g: 255, b: 63 }
const VIOLET = { r: 120, g: 130, b: 255 }

type Rgb = { r: number; g: number; b: number }

function mix(from: Rgb, to: Rgb, t: number): Rgb {
  const c = t < 0 ? 0 : t > 1 ? 1 : t
  return {
    r: from.r + (to.r - from.r) * c,
    g: from.g + (to.g - from.g) * c,
    b: from.b + (to.b - from.b) * c,
  }
}

interface Ripple {
  x: number
  y: number
  start: number
}

export default function WireMeshBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    let width = 0
    let height = 0
    let cols = 0
    let rows = 0

    const ripples: Ripple[] = []
    let lastSpawn = { x: -1000, y: -1000 }

    function resize() {
      width = window.innerWidth
      height = window.innerHeight
      cols = Math.ceil(width / CELL_SIZE) + 1
      rows = Math.ceil(height / CELL_SIZE) + 1
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas!.width = width * dpr
      canvas!.height = height * dpr
      canvas!.style.width = `${width}px`
      canvas!.style.height = `${height}px`
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    window.addEventListener('resize', resize)

    function drawStatic() {
      ctx!.clearRect(0, 0, width, height)
      ctx!.strokeStyle = `rgba(${BASE.r}, ${BASE.g}, ${BASE.b}, 0.14)`
      ctx!.lineWidth = 1
      for (let iy = 0; iy <= rows; iy++) {
        ctx!.beginPath()
        ctx!.moveTo(0, iy * CELL_SIZE)
        ctx!.lineTo(cols * CELL_SIZE, iy * CELL_SIZE)
        ctx!.stroke()
      }
      for (let ix = 0; ix <= cols; ix++) {
        ctx!.beginPath()
        ctx!.moveTo(ix * CELL_SIZE, 0)
        ctx!.lineTo(ix * CELL_SIZE, rows * CELL_SIZE)
        ctx!.stroke()
      }
    }

    if (reduceMotion) {
      drawStatic()
      return () => window.removeEventListener('resize', resize)
    }

    function handleMove(e: MouseEvent) {
      const dx = e.clientX - lastSpawn.x
      const dy = e.clientY - lastSpawn.y
      if (Math.hypot(dx, dy) > MIN_SPAWN_DIST) {
        ripples.push({ x: e.clientX, y: e.clientY, start: performance.now() })
        if (ripples.length > MAX_RIPPLES) ripples.shift()
        lastSpawn = { x: e.clientX, y: e.clientY }
      }
    }
    window.addEventListener('mousemove', handleMove)

    let frame: number
    const startTime = performance.now()

    function pointOffset(x: number, y: number, t: number, now: number) {
      let dz = AMBIENT_AMPLITUDE * Math.sin(x * 0.01 + t * 0.6) * Math.cos(y * 0.012 + t * 0.5)
      for (const r of ripples) {
        const age = now - r.start
        if (age > RIPPLE_LIFE) continue
        const dist = Math.hypot(x - r.x, y - r.y)
        const front = (age / 1000) * RIPPLE_SPEED
        const band = Math.abs(dist - front)
        if (band < RIPPLE_BAND) {
          const decay = 1 - age / RIPPLE_LIFE
          const falloff = 1 - band / RIPPLE_BAND
          dz += RIPPLE_AMPLITUDE * decay * falloff * Math.sin((dist - front) * 0.08)
        }
      }
      return dz
    }

    function colorFor(dz: number): Rgb {
      const t = dz / (RIPPLE_AMPLITUDE * 0.8)
      return t >= 0 ? mix(BASE, LIME, t) : mix(BASE, VIOLET, -t)
    }

    function draw(now: number) {
      const t = (now - startTime) / 1000
      ctx!.clearRect(0, 0, width, height)

      for (let i = ripples.length - 1; i >= 0; i--) {
        if (now - ripples[i].start > RIPPLE_LIFE) ripples.splice(i, 1)
      }

      const offsets: number[][] = []
      for (let iy = 0; iy <= rows; iy++) {
        offsets[iy] = []
        for (let ix = 0; ix <= cols; ix++) {
          offsets[iy][ix] = pointOffset(ix * CELL_SIZE, iy * CELL_SIZE, t, now)
        }
      }

      ctx!.lineWidth = 1

      for (let iy = 0; iy <= rows; iy++) {
        for (let ix = 0; ix < cols; ix++) {
          const x0 = ix * CELL_SIZE
          const x1 = (ix + 1) * CELL_SIZE
          const y0 = iy * CELL_SIZE + offsets[iy][ix]
          const y1 = iy * CELL_SIZE + offsets[iy][ix + 1]
          const c = colorFor((offsets[iy][ix] + offsets[iy][ix + 1]) / 2)
          ctx!.strokeStyle = `rgba(${c.r | 0}, ${c.g | 0}, ${c.b | 0}, 0.16)`
          ctx!.beginPath()
          ctx!.moveTo(x0, y0)
          ctx!.lineTo(x1, y1)
          ctx!.stroke()
        }
      }

      for (let ix = 0; ix <= cols; ix++) {
        for (let iy = 0; iy < rows; iy++) {
          const x = ix * CELL_SIZE
          const y0 = iy * CELL_SIZE + offsets[iy][ix]
          const y1 = (iy + 1) * CELL_SIZE + offsets[iy + 1][ix]
          const c = colorFor((offsets[iy][ix] + offsets[iy + 1][ix]) / 2)
          ctx!.strokeStyle = `rgba(${c.r | 0}, ${c.g | 0}, ${c.b | 0}, 0.16)`
          ctx!.beginPath()
          ctx!.moveTo(x, y0)
          ctx!.lineTo(x, y1)
          ctx!.stroke()
        }
      }

      frame = requestAnimationFrame(draw)
    }
    frame = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('mousemove', handleMove)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <canvas ref={canvasRef} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10" />
  )
}
