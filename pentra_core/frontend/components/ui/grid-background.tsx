"use client"

import { useEffect, useRef } from "react"

export function GridBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Resize handler
    let width = window.innerWidth
    let height = window.innerHeight
    canvas.width = width
    canvas.height = height

    const handleResize = () => {
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = width
      canvas.height = height
    }
    window.addEventListener("resize", handleResize)

    // Particle logic
    class Particle {
      x: number
      y: number
      z: number
      size: number
      speed: number
      pulse: number

      constructor() {
        this.x = Math.random() * width
        this.y = Math.random() * height
        this.z = Math.random() * 2
        this.size = Math.random() * 2 + 0.1
        this.speed = Math.random() * 0.5 + 0.1
        this.pulse = Math.random() * Math.PI * 2
      }

      update() {
        this.y -= this.speed
        if (this.y < -10) {
          this.y = height + 10
          this.x = Math.random() * width
        }
        this.pulse += 0.02
      }

      draw() {
        if (!ctx) return
        const alpha = (Math.sin(this.pulse) * 0.5 + 0.5) * (1 - this.z / 2)
        ctx.fillStyle = `rgba(255, 82, 92, ${alpha})`
        ctx.beginPath()
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2)
        ctx.fill()
      }
    }

    const particles = Array.from({ length: 150 }, () => new Particle())

    // Matrix Rain Data
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~"
    const charArray = chars.split('')
    const fontSize = 14
    const columns = Math.floor(width / fontSize)
    const drops = Array.from({ length: columns }, () => Math.random() * -100)

    let animationFrameId: number

    const render = () => {
      if (!ctx) return
      // Fade out for trails
      ctx.fillStyle = "rgba(0, 0, 0, 0.1)"
      ctx.fillRect(0, 0, width, height)

      // 1. Matrix Background (Deep Red, blurred)
      ctx.fillStyle = "rgba(255, 82, 92, 0.15)"
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`
      
      for (let i = 0; i < drops.length; i++) {
        // Occasional red glint
        if (Math.random() > 0.98) {
          ctx.fillStyle = "rgba(255, 255, 255, 0.4)"
        } else {
          ctx.fillStyle = "rgba(255, 82, 92, 0.15)"
        }

        const text = charArray[Math.floor(Math.random() * charArray.length)]
        ctx.fillText(text, i * fontSize, drops[i] * fontSize)

        if (drops[i] * fontSize > height && Math.random() > 0.975) {
          drops[i] = 0
        }
        drops[i]++
      }

      // 2. Rising Embers / 3D Dust Particles
      particles.forEach((p) => {
        p.update()
        p.draw()
      })

      // 3. Cinematic Grid Lines
      ctx.strokeStyle = "rgba(255, 82, 92, 0.03)"
      ctx.lineWidth = 1
      const gridSize = 60
      const offset = (Date.now() / 50) % gridSize

      // Horizontal moving grid
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath()
        ctx.moveTo(0, y + offset)
        ctx.lineTo(width, y + offset)
        ctx.stroke()
      }
      
      // Vertical static grid
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath()
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
        ctx.stroke()
      }

      animationFrameId = requestAnimationFrame(render)
    }

    render()

    return () => {
      window.removeEventListener("resize", handleResize)
      cancelAnimationFrame(animationFrameId)
    }
  }, [])

  return (
    <div className="fixed inset-0 w-full h-full bg-[#000000] z-0 overflow-hidden pointer-events-none">
      <canvas
        ref={canvasRef}
        className="block w-full h-full opacity-60"
        style={{ filter: "blur(1px) contrast(1.2)" }}
      />
      {/* Heavy vignette for deep cinematic immersion */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_0%,#000000_100%)] opacity-90" />
      {/* Horizontal scanline overlay */}
      <div className="absolute inset-0 bg-[repeating-linear-gradient(0deg,transparent,transparent_2px,rgba(0,0,0,0.2)_2px,rgba(0,0,0,0.2)_4px)] mix-blend-multiply opacity-50" />
    </div>
  )
}
