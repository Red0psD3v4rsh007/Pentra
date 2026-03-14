"use client"

import { useEffect, useRef } from "react"

interface Asset {
  angle: number
  distance: number // 0-1, 0 = center, 1 = edge
  severity: "critical" | "high" | "medium" | "low" | "info"
}

const assets: Asset[] = [
  { angle: 30, distance: 0.4, severity: "critical" },
  { angle: 75, distance: 0.7, severity: "high" },
  { angle: 120, distance: 0.5, severity: "medium" },
  { angle: 160, distance: 0.85, severity: "low" },
  { angle: 200, distance: 0.3, severity: "critical" },
  { angle: 240, distance: 0.6, severity: "high" },
  { angle: 280, distance: 0.75, severity: "info" },
  { angle: 320, distance: 0.5, severity: "medium" },
  { angle: 350, distance: 0.9, severity: "low" },
  { angle: 45, distance: 0.65, severity: "high" },
  { angle: 180, distance: 0.55, severity: "critical" },
]

const severityColors = {
  critical: "#ff003c",
  high: "#ff6b00",
  medium: "#ffd000",
  low: "#00ff88",
  info: "#8a8a8a",
}

export function ReconRadar() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animationRef = useRef<number>(0)
  const sweepAngleRef = useRef(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext("2d")
    if (!ctx) return

    const resize = () => {
      const rect = canvas.getBoundingClientRect()
      const size = Math.min(rect.width, rect.height)
      canvas.width = size * window.devicePixelRatio
      canvas.height = size * window.devicePixelRatio
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio)
    }
    resize()
    window.addEventListener("resize", resize)

    const draw = () => {
      const rect = canvas.getBoundingClientRect()
      const size = Math.min(rect.width, rect.height)
      
      // Guard against zero/negative size during initial render
      if (size < 20) {
        animationRef.current = requestAnimationFrame(draw)
        return
      }
      
      const centerX = size / 2
      const centerY = size / 2
      const maxRadius = Math.max((size / 2) - 10, 1)

      ctx.clearRect(0, 0, size, size)

      // Draw concentric rings
      ctx.strokeStyle = "#2b2b2b"
      ctx.lineWidth = 1
      for (let i = 1; i <= 3; i++) {
        ctx.beginPath()
        ctx.arc(centerX, centerY, (maxRadius / 3) * i, 0, Math.PI * 2)
        ctx.stroke()
      }

      // Draw crosshairs
      ctx.beginPath()
      ctx.moveTo(centerX, centerY - maxRadius)
      ctx.lineTo(centerX, centerY + maxRadius)
      ctx.moveTo(centerX - maxRadius, centerY)
      ctx.lineTo(centerX + maxRadius, centerY)
      ctx.stroke()

      // Draw sweep line with gradient
      const sweepAngle = (sweepAngleRef.current * Math.PI) / 180
      const gradient = ctx.createLinearGradient(
        centerX,
        centerY,
        centerX + Math.cos(sweepAngle) * maxRadius,
        centerY + Math.sin(sweepAngle) * maxRadius
      )
      gradient.addColorStop(0, "rgba(0, 234, 255, 0)")
      gradient.addColorStop(0.5, "rgba(0, 234, 255, 0.3)")
      gradient.addColorStop(1, "rgba(0, 234, 255, 0.8)")

      ctx.beginPath()
      ctx.moveTo(centerX, centerY)
      ctx.lineTo(
        centerX + Math.cos(sweepAngle) * maxRadius,
        centerY + Math.sin(sweepAngle) * maxRadius
      )
      ctx.strokeStyle = gradient
      ctx.lineWidth = 2
      ctx.stroke()

      // Draw sweep trail
      ctx.beginPath()
      ctx.moveTo(centerX, centerY)
      ctx.arc(centerX, centerY, maxRadius, sweepAngle - 0.5, sweepAngle, false)
      ctx.closePath()
      const trailGradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, maxRadius)
      trailGradient.addColorStop(0, "rgba(0, 234, 255, 0)")
      trailGradient.addColorStop(1, "rgba(0, 234, 255, 0.1)")
      ctx.fillStyle = trailGradient
      ctx.fill()

      // Draw asset dots
      assets.forEach((asset) => {
        const angle = (asset.angle * Math.PI) / 180
        const distance = asset.distance * maxRadius
        const x = centerX + Math.cos(angle) * distance
        const y = centerY + Math.sin(angle) * distance

        // Glow effect for critical/high
        if (asset.severity === "critical" || asset.severity === "high") {
          ctx.beginPath()
          ctx.arc(x, y, 6, 0, Math.PI * 2)
          ctx.fillStyle = `${severityColors[asset.severity]}33`
          ctx.fill()
        }

        ctx.beginPath()
        ctx.arc(x, y, 3, 0, Math.PI * 2)
        ctx.fillStyle = severityColors[asset.severity]
        ctx.fill()
      })

      // Center dot
      ctx.beginPath()
      ctx.arc(centerX, centerY, 4, 0, Math.PI * 2)
      ctx.fillStyle = "#00eaff"
      ctx.fill()

      sweepAngleRef.current = (sweepAngleRef.current + 1) % 360
      animationRef.current = requestAnimationFrame(draw)
    }

    draw()

    return () => {
      window.removeEventListener("resize", resize)
      cancelAnimationFrame(animationRef.current)
    }
  }, [])

  return (
    <div className="flex h-full flex-col rounded-[2px] border border-border bg-[#0f0f0f]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold tracking-wide text-foreground">
          RECON RADAR
        </span>
        <div className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse" />
          <span className="text-[10px] text-secondary">SCANNING</span>
        </div>
      </div>

      {/* Radar */}
      <div className="flex-1 flex items-center justify-center p-2">
        <canvas ref={canvasRef} className="w-full h-full max-w-[200px] max-h-[200px]" />
      </div>

      {/* Legend */}
      <div className="flex justify-center gap-3 border-t border-border px-3 py-1.5">
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-critical" />
          <span className="text-[9px] text-muted-foreground">CRIT</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-high" />
          <span className="text-[9px] text-muted-foreground">HIGH</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-medium" />
          <span className="text-[9px] text-muted-foreground">MED</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-low" />
          <span className="text-[9px] text-muted-foreground">LOW</span>
        </div>
      </div>
    </div>
  )
}
