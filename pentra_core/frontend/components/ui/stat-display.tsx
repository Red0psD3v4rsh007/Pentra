"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"

/**
 * Animated stat display with count-up animation, accent line, and icon glow.
 * Used for hero metrics in the command dashboard.
 */
interface StatDisplayProps {
  label: string
  value: number
  icon: React.ReactNode
  accentColor?: string
  suffix?: string
  sublabel?: React.ReactNode
  className?: string
}

/** Simple eased count-up from 0 to target */
function useCountUp(target: number, duration = 800) {
  const [current, setCurrent] = useState(0)
  const ref = useRef<number | null>(null)

  useEffect(() => {
    if (target === 0) { setCurrent(0); return }
    const start = performance.now()
    function tick(now: number) {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      // ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setCurrent(Math.round(eased * target))
      if (progress < 1) ref.current = requestAnimationFrame(tick)
    }
    ref.current = requestAnimationFrame(tick)
    return () => { if (ref.current) cancelAnimationFrame(ref.current) }
  }, [target, duration])

  return current
}

export function StatDisplay({
  label,
  value,
  icon,
  accentColor = "#FF525C",
  suffix,
  sublabel,
  className,
}: StatDisplayProps) {
  const displayValue = useCountUp(value)

  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-md glass-panel p-4",
        "transition-all duration-300",
        "hover:border-[#FF525C]/30 hover:-translate-y-[1px]",
        "hover:shadow-[0_8px_32px_rgba(0,0,0,0.4)]",
        className
      )}
    >
      {/* Animated top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-[1px] opacity-60 group-hover:opacity-100 transition-opacity"
        style={{
          background: `linear-gradient(90deg, transparent, ${accentColor}, transparent)`,
        }}
      />

      {/* Inner glow on hover */}
      <div
        className="absolute top-0 left-0 right-0 h-20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `linear-gradient(to bottom, ${accentColor}06, transparent)`,
        }}
      />

      <div className="relative z-10">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground font-heading">
              {label}
            </p>
            <p className="mt-1.5 text-2xl font-bold tabular-nums text-foreground font-mono">
              {displayValue}
              {suffix && <span className="text-sm text-muted-foreground ml-1">{suffix}</span>}
            </p>
          </div>
          <div
            className="flex h-10 w-10 items-center justify-center rounded transition-shadow duration-200"
            style={{
              background: `${accentColor}15`,
              boxShadow: `0 0 0px ${accentColor}00`,
            }}
          >
            <div style={{ color: accentColor }} className="group-hover:drop-shadow-[0_0_8px_currentColor] transition-all duration-200">
              {icon}
            </div>
          </div>
        </div>

        {sublabel && (
          <div className="mt-2.5 text-[11px] text-muted-foreground font-mono">
            {sublabel}
          </div>
        )}
      </div>
    </div>
  )
}
