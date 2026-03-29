"use client"

import { cn } from "@/lib/utils"

/**
 * Status badge with animated pulse dot and mono font.
 * Maps scan/finding statuses to visual states.
 */
interface StatusBadgeProps {
  status: string
  label?: string
  className?: string
  size?: "sm" | "md"
}

const statusMap: Record<string, { dot: string; bg: string; text: string; pulse?: boolean }> = {
  running: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/8 border-[#00ff9f]/30", text: "text-[#00ff9f]", pulse: true },
  completed: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/8 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  failed: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/8 border-[#ff3b3b]/30", text: "text-[#ff3b3b]" },
  queued: { dot: "bg-[#888888]", bg: "bg-[#1a1a1e] border-[#1a1a1e]", text: "text-[#888888]", pulse: true },
  cancelled: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/8 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  cancelling: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/8 border-[#ffaa00]/20", text: "text-[#ffaa00]", pulse: true },
  validating: { dot: "bg-[#00cfff]", bg: "bg-[#00cfff]/8 border-[#00cfff]/20", text: "text-[#00cfff]", pulse: true },
  pending: { dot: "bg-[#888888]", bg: "bg-[#1a1a1e] border-[#1a1a1e]", text: "text-[#888888]", pulse: true },
  // severity badges
  critical: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/10 border-[#ff3b3b]/20", text: "text-[#ff3b3b]" },
  high: { dot: "bg-[#ff6b35]", bg: "bg-[#ff6b35]/10 border-[#ff6b35]/20", text: "text-[#ff6b35]" },
  medium: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/10 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  low: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  info: { dot: "bg-[#555555]", bg: "bg-[#555555]/10 border-[#555555]/20", text: "text-[#555555]" },
  // provenance badges
  live: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  simulated: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/10 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  derived: { dot: "bg-[#8b5cf6]", bg: "bg-[#8b5cf6]/10 border-[#8b5cf6]/20", text: "text-[#8b5cf6]" },
  blocked: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/10 border-[#ff3b3b]/20", text: "text-[#ff3b3b]" },
  inferred: { dot: "bg-[#00cfff]", bg: "bg-[#00cfff]/10 border-[#00cfff]/20", text: "text-[#00cfff]" },
  verified: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  suspected: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/10 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  detected: { dot: "bg-[#00cfff]", bg: "bg-[#00cfff]/10 border-[#00cfff]/20", text: "text-[#00cfff]" },
  online: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]", pulse: true },
  ok: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  degraded: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/10 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  unavailable: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/10 border-[#ff3b3b]/20", text: "text-[#ff3b3b]" },
  disabled: { dot: "bg-[#666666]", bg: "bg-[#666666]/10 border-[#666666]/20", text: "text-[#aaaaaa]" },
  configured_and_healthy: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  configured_but_fallback: { dot: "bg-[#ffaa00]", bg: "bg-[#ffaa00]/10 border-[#ffaa00]/20", text: "text-[#ffaa00]" },
  missing_api_key: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/10 border-[#ff3b3b]/20", text: "text-[#ff3b3b]" },
  provider_unreachable: { dot: "bg-[#ff6b35]", bg: "bg-[#ff6b35]/10 border-[#ff6b35]/20", text: "text-[#ff6b35]" },
  disabled_by_config: { dot: "bg-[#666666]", bg: "bg-[#666666]/10 border-[#666666]/20", text: "text-[#aaaaaa]" },
  acknowledged: { dot: "bg-[#00ff9f]", bg: "bg-[#00ff9f]/10 border-[#00ff9f]/20", text: "text-[#00ff9f]" },
  missing_acknowledgement: { dot: "bg-[#ff3b3b]", bg: "bg-[#ff3b3b]/10 border-[#ff3b3b]/20", text: "text-[#ff3b3b]" },
}

const fallback = { dot: "bg-[#888888]", bg: "bg-[#1a1a1e] border-[#1a1a1e]", text: "text-[#888888]" }

export function StatusBadge({ status, label, className, size = "sm" }: StatusBadgeProps) {
  const key = status.toLowerCase()
  const config = statusMap[key] ?? fallback
  const displayLabel = label ?? status

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border font-mono font-semibold",
        config.bg,
        config.text,
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs",
        className
      )}
    >
      <span
        className={cn(
          "rounded-full shrink-0",
          config.dot,
          size === "sm" ? "h-1 w-1" : "h-1.5 w-1.5",
          config.pulse && "animate-pulse"
        )}
      />
      {displayLabel}
    </span>
  )
}
