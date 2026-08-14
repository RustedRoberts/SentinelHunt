import { useEffect, useRef } from 'react'

export default function SmokeBackground() {
  const ref = useRef<HTMLDivElement>(null)
  const pos = useRef({ x: 0.5, y: 0.5 })
  const current = useRef({ x: 0.5, y: 0.5 })

  useEffect(() => {
    const handleMove = (e: MouseEvent) => {
      pos.current = { x: e.clientX / window.innerWidth, y: e.clientY / window.innerHeight }
    }
    window.addEventListener('mousemove', handleMove)

    let frame: number
    const animate = () => {
      current.current.x += (pos.current.x - current.current.x) * 0.04
      current.current.y += (pos.current.y - current.current.y) * 0.04
      const el = ref.current
      if (el) {
        el.style.setProperty('--smoke-x', `${current.current.x * 100}%`)
        el.style.setProperty('--smoke-y', `${current.current.y * 100}%`)
      }
      frame = requestAnimationFrame(animate)
    }
    frame = requestAnimationFrame(animate)

    return () => {
      window.removeEventListener('mousemove', handleMove)
      cancelAnimationFrame(frame)
    }
  }, [])

  return (
    <div
      ref={ref}
      aria-hidden="true"
      className="smoke-bg pointer-events-none fixed inset-0 -z-10 overflow-hidden"
    >
      <div className="smoke-layer smoke-layer-1" />
      <div className="smoke-layer smoke-layer-2" />
    </div>
  )
}
