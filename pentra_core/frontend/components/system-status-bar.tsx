"use client"

import { useEffect, useState, useCallback } from "react"
import { getApiBaseUrl } from "@/lib/scans-store"
import { cn } from "@/lib/utils"
import { Activity, ChevronDown, ChevronUp } from "lucide-react"

interface SystemStatus {
  status: "ok" | "degraded"
  version: string
  uptime_seconds: number
  services: Record<string, string>
}

const SERVICE_LABELS: Record<string, string> = {
  db: "Database",
  redis: "Redis",
  orchestrator: "Orchestrator",
}

function StatusDot({ state }: { state: string }) {
  return (
    <span
      className={cn(
        "inline-block h-2 w-2 rounded-full",
        state === "ok"
          ? "bg-emerald-500"
          : state === "degraded"
          ? "bg-amber-500"
          : "bg-red-500"
      )}
    />
  )
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return m > 0 ? `${h}h ${m}m` : `${h}h`
}

export function SystemStatusBar({ collapsed = false }: { collapsed?: boolean }) {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [error, setError] = useState(false)

  const fetchStatus = useCallback(async () => {
    try {
      const resp = await fetch(`${getApiBaseUrl()}/api/v1/system/status`, {
        cache: "no-store",
      })
      if (resp.ok) {
        const data: SystemStatus = await resp.json()
        setStatus(data)
        setError(false)
      } else {
        setError(true)
      }
    } catch {
      setError(true)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30_000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  if (collapsed) {
    return (
      <div className="flex justify-center py-2" title={error ? "System unreachable" : status?.status === "ok" ? "All systems operational" : "System degraded"}>
        <StatusDot state={error ? "unavailable" : status?.status ?? "unavailable"} />
      </div>
    )
  }

  const overallLabel = error
    ? "Unreachable"
    : status?.status === "ok"
    ? "Operational"
    : "Degraded"

  const overallColor = error
    ? "text-red-400"
    : status?.status === "ok"
    ? "text-emerald-400"
    : "text-amber-400"

  return (
    <div className="rounded-md border border-border bg-elevated/50 px-3 py-2">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
      >
        <Activity className="h-3.5 w-3.5 shrink-0" />
        <span className="flex-1 text-left">
          <span className={overallColor}>{overallLabel}</span>
        </span>
        {status?.uptime_seconds != null && (
          <span className="text-[10px] text-muted-foreground/70">
            {formatUptime(status.uptime_seconds)}
          </span>
        )}
        {expanded ? (
          <ChevronUp className="h-3 w-3 shrink-0" />
        ) : (
          <ChevronDown className="h-3 w-3 shrink-0" />
        )}
      </button>

      {expanded && status && (
        <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2">
          {Object.entries(status.services).map(([key, state]) => (
            <div key={key} className="flex items-center gap-2 text-xs text-muted-foreground">
              <StatusDot state={state} />
              <span>{SERVICE_LABELS[key] ?? key}</span>
              <span className={cn("ml-auto", state === "ok" ? "text-emerald-400/80" : "text-red-400/80")}>
                {state}
              </span>
            </div>
          ))}
          <div className="text-[10px] text-muted-foreground/50 pt-1">
            v{status.version}
          </div>
        </div>
      )}

      {expanded && error && (
        <div className="mt-2 border-t border-border/50 pt-2 text-xs text-red-400/80">
          Cannot reach API server
        </div>
      )}
    </div>
  )
}
