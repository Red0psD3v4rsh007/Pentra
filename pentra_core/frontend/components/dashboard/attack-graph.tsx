"use client"

import { useEffect, useRef } from "react"

interface Node {
  id: string
  x: number
  y: number
  type: "asset" | "vulnerability" | "credential" | "exploit"
  label: string
}

interface Edge {
  from: string
  to: string
  critical?: boolean
}

const nodes: Node[] = [
  { id: "web-server", x: 80, y: 120, type: "asset", label: "Web Server" },
  { id: "sqli", x: 200, y: 80, type: "vulnerability", label: "SQLi" },
  { id: "auth-bypass", x: 200, y: 160, type: "vulnerability", label: "Auth Bypass" },
  { id: "db-creds", x: 320, y: 120, type: "credential", label: "DB Creds" },
  { id: "exploit-1", x: 440, y: 80, type: "exploit", label: "Data Exfil" },
  { id: "api-server", x: 80, y: 280, type: "asset", label: "API Server" },
  { id: "ssrf", x: 200, y: 280, type: "vulnerability", label: "SSRF" },
  { id: "aws-keys", x: 320, y: 240, type: "credential", label: "AWS Keys" },
  { id: "exploit-2", x: 440, y: 200, type: "exploit", label: "Lateral Move" },
  { id: "internal", x: 320, y: 320, type: "asset", label: "Internal DB" },
  { id: "rce", x: 440, y: 320, type: "vulnerability", label: "RCE" },
]

const edges: Edge[] = [
  { from: "web-server", to: "sqli", critical: true },
  { from: "web-server", to: "auth-bypass" },
  { from: "sqli", to: "db-creds", critical: true },
  { from: "auth-bypass", to: "db-creds" },
  { from: "db-creds", to: "exploit-1", critical: true },
  { from: "api-server", to: "ssrf" },
  { from: "ssrf", to: "aws-keys", critical: true },
  { from: "aws-keys", to: "exploit-2", critical: true },
  { from: "ssrf", to: "internal" },
  { from: "internal", to: "rce" },
  { from: "db-creds", to: "exploit-2" },
]

const nodeColors = {
  asset: "#00eaff",
  vulnerability: "#ff003c",
  credential: "#ff6b00",
  exploit: "#9d4edd",
}

const nodeShapes = {
  asset: "circle",
  vulnerability: "diamond",
  credential: "hexagon",
  exploit: "square",
}

export function AttackGraph() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animationRef = useRef<number>(0)
  const dashOffsetRef = useRef(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext("2d")
    if (!ctx) return

    const resize = () => {
      const rect = canvas.getBoundingClientRect()
      canvas.width = rect.width * window.devicePixelRatio
      canvas.height = rect.height * window.devicePixelRatio
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio)
    }
    resize()
    window.addEventListener("resize", resize)

    const draw = () => {
      const rect = canvas.getBoundingClientRect()
      ctx.clearRect(0, 0, rect.width, rect.height)

      // Draw grid dots
      ctx.fillStyle = "#1a1a1a"
      for (let x = 0; x < rect.width; x += 20) {
        for (let y = 0; y < rect.height; y += 20) {
          ctx.beginPath()
          ctx.arc(x, y, 1, 0, Math.PI * 2)
          ctx.fill()
        }
      }

      // Draw edges
      edges.forEach((edge) => {
        const fromNode = nodes.find((n) => n.id === edge.from)
        const toNode = nodes.find((n) => n.id === edge.to)
        if (!fromNode || !toNode) return

        ctx.beginPath()
        ctx.moveTo(fromNode.x, fromNode.y)
        ctx.lineTo(toNode.x, toNode.y)
        
        if (edge.critical) {
          ctx.strokeStyle = "#ff003c"
          ctx.setLineDash([6, 4])
          ctx.lineDashOffset = -dashOffsetRef.current
        } else {
          ctx.strokeStyle = "#2b2b2b"
          ctx.setLineDash([])
        }
        ctx.lineWidth = edge.critical ? 2 : 1
        ctx.stroke()
        ctx.setLineDash([])
      })

      // Draw nodes
      nodes.forEach((node) => {
        const color = nodeColors[node.type]
        ctx.fillStyle = color
        ctx.strokeStyle = color
        ctx.lineWidth = 2

        ctx.beginPath()
        switch (node.type) {
          case "asset": // Circle
            ctx.arc(node.x, node.y, 12, 0, Math.PI * 2)
            ctx.fill()
            break
          case "vulnerability": // Diamond
            ctx.save()
            ctx.translate(node.x, node.y)
            ctx.rotate(Math.PI / 4)
            ctx.fillRect(-9, -9, 18, 18)
            ctx.restore()
            break
          case "credential": // Hexagon
            const hex = 10
            ctx.beginPath()
            for (let i = 0; i < 6; i++) {
              const angle = (Math.PI / 3) * i - Math.PI / 2
              const x = node.x + hex * Math.cos(angle)
              const y = node.y + hex * Math.sin(angle)
              if (i === 0) ctx.moveTo(x, y)
              else ctx.lineTo(x, y)
            }
            ctx.closePath()
            ctx.fill()
            break
          case "exploit": // Square
            ctx.fillRect(node.x - 10, node.y - 10, 20, 20)
            break
        }

        // Label
        ctx.fillStyle = "#8a8a8a"
        ctx.font = "9px Inter"
        ctx.textAlign = "center"
        ctx.fillText(node.label, node.x, node.y + 24)
      })

      dashOffsetRef.current += 0.3
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
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold tracking-wide text-foreground">
            ATTACK GRAPH
          </span>
          <span className="text-[10px] text-muted-foreground">— LIVE</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-low animate-pulse" />
          <span className="text-[10px] text-low">ACTIVE</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-4 border-b border-border px-3 py-1.5">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-secondary" />
          <span className="text-[9px] text-muted-foreground">Asset</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rotate-45 bg-primary" />
          <span className="text-[9px] text-muted-foreground">Vuln</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 bg-high" style={{ clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)" }} />
          <span className="text-[9px] text-muted-foreground">Creds</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 bg-accent" />
          <span className="text-[9px] text-muted-foreground">Exploit</span>
        </div>
      </div>

      {/* Canvas */}
      <canvas ref={canvasRef} className="h-full w-full" />
    </div>
  )
}
