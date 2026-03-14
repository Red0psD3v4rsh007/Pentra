"use client"

import Link from "next/link"
import { cn } from "@/lib/utils"
import { ArrowRight } from "lucide-react"
import { useScans } from "@/hooks/use-scans"

type ScanStatus = "running" | "completed" | "failed" | "queued"

const statusConfig: Record<ScanStatus, { label: string; className: string }> = {
  running: { label: "Running", className: "bg-blue-500/10 text-blue-500 border-blue-500/20" },
  completed: { label: "Completed", className: "bg-green-500/10 text-green-500 border-green-500/20" },
  failed: { label: "Failed", className: "bg-red-500/10 text-red-500 border-red-500/20" },
  queued: { label: "Queued", className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20" },
}

// Helper to format time ago
function formatTimeAgo(dateString: string): string {
  if (!dateString) return "Scheduled"
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return "Just now"
  if (diffMins < 60) return `${diffMins} min ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`
  return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`
}

export function RecentScans() {
  const { scans } = useScans()
  
  // Show only the 5 most recent scans
  const recentScans = scans.slice(0, 5)

  return (
    <div className="rounded-lg border border-border bg-card">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <h2 className="text-base font-semibold text-foreground">Recent Scans</h2>
        <Link
          href="/scans"
          className="flex items-center gap-1 text-sm font-medium text-primary transition-colors hover:text-primary/80"
        >
          View all
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border text-left text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <th className="px-6 py-3">Name</th>
              <th className="px-6 py-3">Target</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3">Findings</th>
              <th className="px-6 py-3">Duration</th>
              <th className="px-6 py-3">Started</th>
            </tr>
          </thead>
          <tbody>
            {recentScans.map((scan) => {
              const totalFindings = scan.findings.critical + scan.findings.high + scan.findings.medium + scan.findings.low
              return (
                <tr
                  key={scan.id}
                  className="group relative border-b border-border last:border-0 transition-colors hover:bg-elevated cursor-pointer"
                >
                  <td className="px-6 py-4">
                    <Link href={`/scans/${scan.id}`} className="text-sm font-medium text-foreground hover:text-primary">
                      {scan.name}
                    </Link>
                  </td>
                  <td className="px-6 py-4">
                    <span className="font-mono text-sm text-muted-foreground">{scan.target}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={cn(
                        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
                        statusConfig[scan.status].className
                      )}
                    >
                      {statusConfig[scan.status].label}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-foreground">{totalFindings}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="font-mono text-sm text-muted-foreground">{scan.duration}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-muted-foreground">{formatTimeAgo(scan.startedAt)}</span>
                  </td>
                  {/* Progress bar for running scans */}
                  {scan.status === "running" && (
                    <td className="absolute bottom-0 left-0 right-0 h-0.5">
                      <div
                        className="h-full bg-primary/50 transition-all duration-500 animate-pulse"
                        style={{ width: "60%" }}
                      />
                    </td>
                  )}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
