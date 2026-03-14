"use client"

import { useEffect, useState, useRef } from "react"
import { cn } from "@/lib/utils"
import { TrendingUp, TrendingDown } from "lucide-react"

interface MetricCardProps {
  label: string
  value: number
  subtext: string
  trend?: {
    value: string
    direction: "up" | "down"
  }
  severityPills?: { label: string; color: string }[]
}

function useCountUp(target: number, duration: number = 1000) {
  const [count, setCount] = useState(0)
  const startTimeRef = useRef<number | null>(null)

  useEffect(() => {
    const animate = (timestamp: number) => {
      if (!startTimeRef.current) startTimeRef.current = timestamp
      const progress = Math.min((timestamp - startTimeRef.current) / duration, 1)
      
      // Easing function
      const easeOutQuart = 1 - Math.pow(1 - progress, 4)
      setCount(Math.floor(easeOutQuart * target))
      
      if (progress < 1) {
        requestAnimationFrame(animate)
      }
    }
    
    requestAnimationFrame(animate)
  }, [target, duration])

  return count
}

function MetricCard({ label, value, subtext, trend, severityPills }: MetricCardProps) {
  const animatedValue = useCountUp(value)

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-6">
      <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-3xl font-medium text-foreground">
          {animatedValue.toLocaleString()}
        </span>
        {trend && (
          <span
            className={cn(
              "flex items-center gap-0.5 text-sm font-medium",
              trend.direction === "up" ? "text-green-500" : "text-red-500"
            )}
          >
            {trend.direction === "up" ? (
              <TrendingUp className="h-3.5 w-3.5" />
            ) : (
              <TrendingDown className="h-3.5 w-3.5" />
            )}
            {trend.value}
          </span>
        )}
      </div>
      {severityPills ? (
        <div className="flex items-center gap-2 text-xs">
          {severityPills.map((pill, i) => (
            <span
              key={i}
              className={cn(
                "inline-flex items-center gap-1",
                pill.color
              )}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", pill.color.replace("text-", "bg-"))} />
              {pill.label}
            </span>
          ))}
        </div>
      ) : (
        <span className="text-xs text-muted-foreground">{subtext}</span>
      )}
    </div>
  )
}

export function MetricCards() {
  return (
    <div className="grid grid-cols-4 gap-4">
      <MetricCard
        label="Active Scans"
        value={7}
        subtext="3 running, 4 queued"
        trend={{ value: "12%", direction: "up" }}
      />
      <MetricCard
        label="Open Findings"
        value={156}
        subtext=""
        severityPills={[
          { label: "4 critical", color: "text-critical" },
          { label: "12 high", color: "text-high" },
        ]}
      />
      <MetricCard
        label="Assets Monitored"
        value={342}
        subtext="Last scan 2h ago"
      />
      <MetricCard
        label="Exploit Success Rate"
        value={87}
        subtext="Based on 23 verified exploits"
        trend={{ value: "5%", direction: "up" }}
      />
    </div>
  )
}
