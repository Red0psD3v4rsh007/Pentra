"use client"

import { type ReactNode } from "react"
import { cn } from "@/lib/utils"

/**
 * Premium cyber-themed card with gradient top accent, animated border on hover,
 * and inner glow effect. The flagship card component for Pentra.
 */
interface CyberCardProps {
  children: ReactNode
  className?: string
  accentColor?: "green" | "cyan" | "red" | "orange" | "yellow" | "none"
  hover?: boolean
  glow?: boolean
}

const accentGradients = {
  green: "from-[#FF525C] via-[#FF525C]/60 to-transparent", // Rewired to Red
  cyan: "from-[#FFB3B2] via-[#FFB3B2]/60 to-transparent", // Rewired to Dim Red
  red: "from-[#FF2A2A] via-[#FF2A2A]/60 to-transparent",
  orange: "from-[#FF8C00] via-[#FF8C00]/60 to-transparent",
  yellow: "from-[#FFAA00] via-[#FFAA00]/60 to-transparent",
  none: "",
}

const glowColors = {
  green: "hover:shadow-[0_0_30px_rgba(255,82,92,0.15),0_8px_32px_rgba(0,0,0,0.6)]",
  cyan: "hover:shadow-[0_0_30px_rgba(255,179,178,0.1),0_8px_32px_rgba(0,0,0,0.6)]",
  red: "hover:shadow-[0_0_30px_rgba(255,42,42,0.15),0_8px_32px_rgba(0,0,0,0.6)]",
  orange: "hover:shadow-[0_0_30px_rgba(255,140,0,0.1),0_8px_32px_rgba(0,0,0,0.6)]",
  yellow: "hover:shadow-[0_0_30px_rgba(255,170,0,0.1),0_8px_32px_rgba(0,0,0,0.6)]",
  none: "hover:shadow-[0_8px_32px_rgba(0,0,0,0.4)]",
}

export function CyberCard({
  children,
  className,
  accentColor = "green",
  hover = true,
  glow = true,
}: CyberCardProps) {
  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-md glass-panel",
        "transition-all duration-300",
        hover && "hover:border-[#FF525C]/30 hover:-translate-y-[1px]",
        glow && glowColors[accentColor],
        className
      )}
    >
      {/* Top accent line */}
      {accentColor !== "none" && (
        <div
          className={cn(
            "absolute top-0 left-0 right-0 h-[1px]",
            "bg-gradient-to-r",
            accentGradients[accentColor],
            hover ? "opacity-60 group-hover:opacity-100" : "opacity-60",
            "transition-opacity duration-200"
          )}
        />
      )}

      {/* Inner gradient glow (appears on hover) */}
      {glow && accentColor !== "none" && (
        <div
          className={cn(
            "absolute top-0 left-0 right-0 h-24 opacity-0 group-hover:opacity-100",
            "transition-opacity duration-300",
            "bg-gradient-to-b",
            accentColor === "green" ? "from-[rgba(255,82,92,0.05)]" :
            accentColor === "cyan" ? "from-[rgba(255,179,178,0.05)]" :
            accentColor === "red" ? "from-[rgba(255,42,42,0.05)]" :
            accentColor === "orange" ? "from-[rgba(255,140,0,0.05)]" :
            "from-[rgba(255,170,0,0.03)]",
            "to-transparent"
          )}
        />
      )}

      {/* Content */}
      <div className="relative z-10">
        {children}
      </div>
    </div>
  )
}
