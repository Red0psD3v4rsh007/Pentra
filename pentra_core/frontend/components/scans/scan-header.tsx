"use client"

import Link from "next/link"
import { ChevronRight, RefreshCw } from "lucide-react"

import { Progress } from "@/components/ui/progress"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

interface ScanHeaderProps {
  scan: {
    id: string
    name: string
    target: string
    status: "running" | "completed" | "failed" | "queued"
    statusLabel: string
    duration: string
    progress: number
    scanTypeLabel: string
    priorityLabel: string
    severity: {
      critical: number
      high: number
      medium: number
      low: number
    }
  }
  isRefreshing?: boolean
  onRefresh?: () => void
}

export function ScanHeader({ scan, isRefreshing = false, onRefresh }: ScanHeaderProps) {
  const statusConfig = {
    running: {
      dotClass: "bg-primary animate-pulse",
      textClass: "text-primary",
      bgClass: "bg-primary/10",
    },
    completed: {
      dotClass: "bg-low",
      textClass: "text-low",
      bgClass: "bg-low/10",
    },
    failed: {
      dotClass: "bg-critical",
      textClass: "text-critical",
      bgClass: "bg-critical/10",
    },
    queued: {
      dotClass: "bg-muted-foreground",
      textClass: "text-muted-foreground",
      bgClass: "bg-muted",
    },
  } as const

  const status = statusConfig[scan.status]

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur-md supports-[backdrop-filter]:bg-card/80">
      <div className="space-y-5 px-6 py-5">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0 space-y-3">
            <nav className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Link href="/scans" className="font-medium transition-colors hover:text-foreground">
                Scans
              </Link>
              <ChevronRight className="h-3 w-3" />
              <span className="truncate font-medium text-foreground">{scan.name}</span>
            </nav>

            <div>
              <h1 className="text-xl font-semibold tracking-tight text-foreground">{scan.name}</h1>
              <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
                <code className="rounded bg-muted/50 px-1.5 py-0.5 font-mono text-xs">
                  {scan.target}
                </code>
                <span className="h-1 w-1 rounded-full bg-border" />
                <span>{scan.scanTypeLabel}</span>
                <span className="h-1 w-1 rounded-full bg-border" />
                <span>{scan.priorityLabel}</span>
                <span className="h-1 w-1 rounded-full bg-border" />
                <span>{scan.duration}</span>
                <span className="h-1 w-1 rounded-full bg-border" />
                <span className="font-mono text-xs">#{scan.id}</span>
              </div>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-3">
            <div
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-2 shadow-sm",
                status.bgClass
              )}
            >
              <span className={cn("h-2 w-2 rounded-full", status.dotClass)} />
              <span className={cn("text-sm font-semibold", status.textClass)}>
                {scan.statusLabel}
              </span>
            </div>

            <button
              type="button"
              onClick={onRefresh}
              className="flex h-10 items-center gap-2 rounded-lg border border-border px-3 text-sm font-medium text-foreground transition-all hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
              disabled={!onRefresh || isRefreshing}
            >
              {isRefreshing ? <Spinner className="h-4 w-4" /> : <RefreshCw className="h-4 w-4" />}
              Refresh
            </button>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-center">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Scan progress</span>
              <span>{scan.progress}%</span>
            </div>
            <Progress value={scan.progress} />
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {scan.severity.critical > 0 ? (
              <span className="rounded-md bg-critical/10 px-2.5 py-1 text-xs font-semibold text-critical">
                {scan.severity.critical} Critical
              </span>
            ) : null}
            {scan.severity.high > 0 ? (
              <span className="rounded-md bg-high/10 px-2.5 py-1 text-xs font-semibold text-high">
                {scan.severity.high} High
              </span>
            ) : null}
            {scan.severity.medium > 0 ? (
              <span className="rounded-md bg-medium/10 px-2.5 py-1 text-xs font-semibold text-medium">
                {scan.severity.medium} Medium
              </span>
            ) : null}
            {scan.severity.low > 0 ? (
              <span className="rounded-md bg-low/10 px-2.5 py-1 text-xs font-semibold text-low">
                {scan.severity.low} Low
              </span>
            ) : null}
            {scan.severity.critical === 0 &&
            scan.severity.high === 0 &&
            scan.severity.medium === 0 &&
            scan.severity.low === 0 ? (
              <span className="rounded-md bg-muted px-2.5 py-1 text-xs font-semibold text-muted-foreground">
                No findings yet
              </span>
            ) : null}
          </div>
        </div>
      </div>
    </header>
  )
}
