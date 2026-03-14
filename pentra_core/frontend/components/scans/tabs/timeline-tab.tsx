"use client"

import { motion } from "framer-motion"

import { type ApiTimelineEvent } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface TimelineTabProps {
  events: ApiTimelineEvent[]
}

const typeConfig: Record<
  string,
  {
    color: string
    pill: string
    label: string
  }
> = {
  system: {
    color: "bg-primary",
    pill: "bg-primary/10 text-primary",
    label: "System",
  },
  recon: {
    color: "bg-low",
    pill: "bg-low/10 text-low",
    label: "Recon",
  },
  vuln: {
    color: "bg-high",
    pill: "bg-high/10 text-high",
    label: "Vuln",
  },
  exploit: {
    color: "bg-critical",
    pill: "bg-critical/10 text-critical",
    label: "Exploit",
  },
  analysis: {
    color: "bg-medium",
    pill: "bg-medium/10 text-medium",
    label: "Analysis",
  },
  report: {
    color: "bg-primary",
    pill: "bg-primary/10 text-primary",
    label: "Report",
  },
  artifact: {
    color: "bg-muted-foreground",
    pill: "bg-muted text-muted-foreground",
    label: "Artifact",
  },
}

function formatClock(timestamp: string): string {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return "--:--:--"
  }
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })
}

export function TimelineTab({ events }: TimelineTabProps) {
  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-10 text-center shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">Timeline Pending</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Timeline entries will appear once the API has real scan and artifact state to display.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-semibold text-foreground">Scan Timeline</h2>
        {Object.entries(typeConfig).map(([key, value]) => (
          <span key={key} className={cn("rounded-md px-2 py-1 text-xs font-medium", value.pill)}>
            {value.label}
          </span>
        ))}
      </div>

      <div className="relative">
        <div className="absolute left-[72px] top-2 bottom-2 w-px bg-gradient-to-b from-transparent via-border to-transparent" />

        <div className="space-y-1">
          {events.map((event, index) => {
            const config = typeConfig[event.event_type] ?? typeConfig.system
            return (
              <motion.div
                key={event.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.02, duration: 0.18 }}
                className="group relative -mx-2 flex items-start gap-6 rounded-lg px-2 py-3 hover:bg-elevated/40"
              >
                <span className="w-14 shrink-0 font-mono text-xs text-muted-foreground">
                  {formatClock(event.timestamp)}
                </span>

                <div className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center">
                  <span className={cn("h-2.5 w-2.5 rounded-full", config.color)} />
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-foreground">{event.title}</p>
                  {event.details ? (
                    <p className="mt-1 text-sm text-muted-foreground">{event.details}</p>
                  ) : null}
                  {(event.tool || event.artifact_ref) ? (
                    <p className="mt-2 truncate text-xs text-muted-foreground">
                      {[event.tool, event.artifact_ref].filter(Boolean).join(" · ")}
                    </p>
                  ) : null}
                </div>

                <span className={cn("shrink-0 rounded-md px-2 py-1 text-xs font-medium", config.pill)}>
                  {config.label}
                </span>
              </motion.div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
