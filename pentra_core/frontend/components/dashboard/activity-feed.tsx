"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"

interface Activity {
  timestamp: string
  type: "recon" | "exploit" | "critical" | "info"
  description: string
}

const initialActivities: Activity[] = [
  { timestamp: "10:42:01", type: "recon", description: "Port scan initiated on 10.0.0.0/24" },
  { timestamp: "10:42:05", type: "info", description: "Service fingerprinting: nginx/1.21.0" },
  { timestamp: "10:42:08", type: "recon", description: "SSL certificate analysis complete" },
  { timestamp: "10:42:12", type: "exploit", description: "SQLi payload delivered to /api/auth" },
  { timestamp: "10:42:15", type: "critical", description: "Authentication bypass successful" },
  { timestamp: "10:42:18", type: "exploit", description: "JWT token extracted from response" },
  { timestamp: "10:42:22", type: "info", description: "Analyzing token claims and permissions" },
  { timestamp: "10:42:25", type: "critical", description: "Admin access confirmed via JWT" },
]

const newActivities: Activity[] = [
  { timestamp: "", type: "recon", description: "Internal network enumeration started" },
  { timestamp: "", type: "info", description: "Discovered 23 internal hosts" },
  { timestamp: "", type: "exploit", description: "Testing SSRF on /api/proxy endpoint" },
  { timestamp: "", type: "critical", description: "AWS metadata service accessible" },
  { timestamp: "", type: "exploit", description: "Extracting IAM credentials" },
]

const typeColors = {
  recon: "bg-secondary/20 text-secondary",
  exploit: "bg-accent/20 text-accent",
  critical: "bg-critical/20 text-critical",
  info: "bg-muted text-muted-foreground",
}

const typeLabels = {
  recon: "RECON",
  exploit: "EXPLOIT",
  critical: "CRITICAL",
  info: "INFO",
}

export function ActivityFeed() {
  const [activities, setActivities] = useState<Activity[]>(initialActivities)
  const [newIndex, setNewIndex] = useState(0)
  const [isPaused, setIsPaused] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (isPaused) return

    const interval = setInterval(() => {
      if (newIndex < newActivities.length) {
        const newActivity = {
          ...newActivities[newIndex],
          timestamp: new Date().toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
        }
        setActivities((prev) => [...prev, newActivity])
        setNewIndex((prev) => prev + 1)
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [newIndex, isPaused])

  useEffect(() => {
    if (scrollRef.current && !isPaused) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [activities, isPaused])

  return (
    <div className="flex h-full flex-col rounded-[2px] border border-border bg-[#0f0f0f]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold tracking-wide text-foreground">
          LIVE ACTIVITY FEED
        </span>
        <span className={cn(
          "text-[10px]",
          isPaused ? "text-medium" : "text-low"
        )}>
          {isPaused ? "PAUSED" : "STREAMING"}
        </span>
      </div>

      {/* Feed */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto"
        onMouseEnter={() => setIsPaused(true)}
        onMouseLeave={() => setIsPaused(false)}
      >
        {activities.map((activity, index) => (
          <div
            key={index}
            className="flex items-start gap-2 border-b border-border/30 px-3 py-1.5"
          >
            <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
              {activity.timestamp}
            </span>
            <span className={cn(
              "shrink-0 rounded-[2px] px-1 py-0.5 text-[9px] font-bold",
              typeColors[activity.type]
            )}>
              {typeLabels[activity.type]}
            </span>
            <span className="text-[11px] text-foreground leading-tight">
              {activity.description}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
