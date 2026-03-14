"use client"

import { cn } from "@/lib/utils"

interface Hypothesis {
  rank: number
  title: string
  target: string
  confidence: number
  severity: "critical" | "high" | "medium" | "low"
}

const hypotheses: Hypothesis[] = [
  { rank: 1, title: "Privilege Escalation via JWT", target: "/api/admin", confidence: 94, severity: "critical" },
  { rank: 2, title: "SSRF to Internal Services", target: "/api/fetch", confidence: 87, severity: "high" },
  { rank: 3, title: "SQL Injection (UNION)", target: "/api/search", confidence: 82, severity: "critical" },
  { rank: 4, title: "Path Traversal", target: "/api/files", confidence: 76, severity: "high" },
  { rank: 5, title: "XSS in Comment Field", target: "/blog/comment", confidence: 71, severity: "medium" },
]

const severityColors = {
  critical: "bg-critical text-critical-foreground",
  high: "bg-high text-high-foreground",
  medium: "bg-medium text-medium-foreground",
  low: "bg-low text-low-foreground",
}

const severityText = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
}

export function HypothesisQueue() {
  return (
    <div className="flex h-full flex-col rounded-[2px] border border-border bg-[#0f0f0f]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold tracking-wide text-foreground">
          HYPOTHESIS QUEUE
        </span>
        <span className="text-[10px] text-muted-foreground">
          {hypotheses.length} active
        </span>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {hypotheses.map((h) => (
          <div
            key={h.rank}
            className="group flex items-center gap-3 border-b border-border/50 px-3 py-2 transition-all hover:bg-muted hover:border-l-2 hover:border-l-primary cursor-pointer"
          >
            {/* Rank */}
            <span className="font-mono text-sm font-bold text-muted-foreground w-4">
              {h.rank}
            </span>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-foreground truncate">
                  {h.title}
                </span>
                <span className={cn(
                  "shrink-0 rounded-[2px] px-1 py-0.5 text-[9px] font-bold uppercase",
                  severityColors[h.severity]
                )}>
                  {h.severity}
                </span>
              </div>
              <span className="text-[10px] font-mono text-muted-foreground">
                {h.target}
              </span>
            </div>

            {/* Confidence */}
            <div className="flex flex-col items-end gap-1">
              <span className="text-[10px] font-mono text-accent">
                {h.confidence}%
              </span>
              <div className="h-1 w-12 rounded-full bg-border overflow-hidden">
                <div
                  className="h-full bg-accent transition-all"
                  style={{ width: `${h.confidence}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
