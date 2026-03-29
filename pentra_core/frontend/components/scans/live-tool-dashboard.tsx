"use client"

import { useState, useMemo } from "react"
import { cn } from "@/lib/utils"
import {
  CheckCircle2,
  Clock,
  AlertCircle,
  Play,
  Square,
  SkipForward,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Plus,
  Terminal,
  Zap,
} from "lucide-react"

interface ToolStatus {
  tool_id: string
  tool_name: string
  phase: string
  status: "queued" | "running" | "completed" | "failed" | "stopped" | "skipped"
  progress: number
  current_command?: string
  duration_seconds?: number
  findings_count?: number
  exit_code?: number
}

interface AISuggestion {
  tool_id: string
  tool_name: string
  rationale: string
  confidence: number
  expected_findings: string[]
}

interface LiveToolDashboardProps {
  toolStatuses: ToolStatus[]
  aiSuggestions?: AISuggestion[]
  scanMode: "customizable" | "autonomous"
  onStopTool?: (toolId: string) => void
  onSkipTool?: (toolId: string) => void
  onRerunTool?: (toolId: string) => void
  onAddTool?: (toolId: string) => void
  onAcceptSuggestion?: (suggestion: AISuggestion) => void
  onOpenTerminal?: (toolId: string) => void
  className?: string
}

const statusIcons: Record<string, typeof CheckCircle2> = {
  queued: Clock,
  running: Play,
  completed: CheckCircle2,
  failed: AlertCircle,
  stopped: Square,
  skipped: SkipForward,
}

const statusColors: Record<string, string> = {
  queued: "text-zinc-400",
  running: "text-primary",
  completed: "text-emerald-400",
  failed: "text-red-400",
  stopped: "text-amber-400",
  skipped: "text-zinc-500",
}

const statusBgColors: Record<string, string> = {
  queued: "bg-zinc-500/10 border-zinc-500/20",
  running: "bg-primary/10 border-primary/20",
  completed: "bg-emerald-500/10 border-emerald-500/20",
  failed: "bg-red-500/10 border-red-500/20",
  stopped: "bg-amber-500/10 border-amber-500/20",
  skipped: "bg-zinc-500/10 border-zinc-500/20",
}

export function LiveToolDashboard({
  toolStatuses,
  aiSuggestions = [],
  scanMode,
  onStopTool,
  onSkipTool,
  onRerunTool,
  onAddTool,
  onAcceptSuggestion,
  onOpenTerminal,
  className,
}: LiveToolDashboardProps) {
  const [expandedTools, setExpandedTools] = useState<Set<string>>(new Set())

  const stats = useMemo(() => {
    const total = toolStatuses.length
    const completed = toolStatuses.filter((t) => t.status === "completed").length
    const running = toolStatuses.filter((t) => t.status === "running").length
    const failed = toolStatuses.filter((t) => t.status === "failed").length
    const findings = toolStatuses.reduce((acc, t) => acc + (t.findings_count || 0), 0)
    return { total, completed, running, failed, findings }
  }, [toolStatuses])

  const toggleExpand = (toolId: string) => {
    setExpandedTools((prev) => {
      const next = new Set(prev)
      if (next.has(toolId)) {
        next.delete(toolId)
      } else {
        next.add(toolId)
      }
      return next
    })
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Progress summary bar */}
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-foreground">
              Pipeline Progress
            </span>
            <span className="text-xs text-muted-foreground">
              {stats.completed}/{stats.total} tools complete
            </span>
          </div>
          <div className="h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-primary to-emerald-400 transition-all duration-500"
              style={{
                width: `${stats.total > 0 ? (stats.completed / stats.total) * 100 : 0}%`,
              }}
            />
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs shrink-0">
          <div className="text-center">
            <div className="text-lg font-bold text-primary">{stats.running}</div>
            <div className="text-muted-foreground">Running</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-emerald-400">{stats.completed}</div>
            <div className="text-muted-foreground">Done</div>
          </div>
          {stats.failed > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-red-400">{stats.failed}</div>
              <div className="text-muted-foreground">Failed</div>
            </div>
          )}
          <div className="text-center">
            <div className="text-lg font-bold text-amber-400">{stats.findings}</div>
            <div className="text-muted-foreground">Findings</div>
          </div>
        </div>
      </div>

      {/* Tool pipeline */}
      <div className="space-y-1">
        {toolStatuses.map((tool, idx) => {
          const StatusIcon = statusIcons[tool.status] || Clock
          const isExpanded = expandedTools.has(tool.tool_id)
          const isRunning = tool.status === "running"

          return (
            <div
              key={`${tool.tool_id}-${idx}`}
              className={cn(
                "rounded-lg border transition-all",
                statusBgColors[tool.status] || "bg-card border-border"
              )}
            >
              {/* Tool row */}
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                onClick={() => toggleExpand(tool.tool_id)}
              >
                {/* Step number */}
                <span
                  className={cn(
                    "flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold shrink-0",
                    isRunning ? "bg-primary text-primary-foreground animate-pulse" : "bg-muted/50 text-muted-foreground"
                  )}
                >
                  {idx + 1}
                </span>

                {/* Status icon */}
                <StatusIcon
                  className={cn(
                    "h-4 w-4 shrink-0",
                    statusColors[tool.status],
                    isRunning && "animate-spin"
                  )}
                />

                {/* Tool name + phase */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground">
                      {tool.tool_name}
                    </span>
                    <span className="text-[10px] rounded bg-muted/30 px-1.5 py-0.5 text-muted-foreground">
                      {tool.phase}
                    </span>
                  </div>
                  {isRunning && tool.current_command && (
                    <code className="mt-0.5 block text-[11px] font-mono text-muted-foreground truncate">
                      $ {tool.current_command}
                    </code>
                  )}
                </div>

                {/* Duration */}
                {tool.duration_seconds != null && tool.duration_seconds > 0 && (
                  <span className="text-xs font-mono text-muted-foreground shrink-0">
                    {tool.duration_seconds.toFixed(1)}s
                  </span>
                )}

                {/* Findings badge */}
                {tool.findings_count != null && tool.findings_count > 0 && (
                  <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium text-amber-400 shrink-0">
                    {tool.findings_count} findings
                  </span>
                )}

                {/* Actions (customizable mode only) */}
                {scanMode === "customizable" && (
                  <div
                    className="flex items-center gap-1 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {isRunning && onStopTool && (
                      <button
                        onClick={() => onStopTool(tool.tool_id)}
                        className="flex h-7 w-7 items-center justify-center rounded text-red-400 hover:bg-red-500/20 transition-colors"
                        title="Stop tool"
                      >
                        <Square className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {tool.status === "queued" && onSkipTool && (
                      <button
                        onClick={() => onSkipTool(tool.tool_id)}
                        className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-elevated hover:text-foreground transition-colors"
                        title="Skip tool"
                      >
                        <SkipForward className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {(tool.status === "completed" || tool.status === "failed") && onRerunTool && (
                      <button
                        onClick={() => onRerunTool(tool.tool_id)}
                        className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-elevated hover:text-foreground transition-colors"
                        title="Re-run tool"
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {onOpenTerminal && (
                      <button
                        onClick={() => onOpenTerminal(tool.tool_id)}
                        className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-elevated hover:text-foreground transition-colors"
                        title="Open terminal"
                      >
                        <Terminal className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                )}

                {/* Expand arrow */}
                {isExpanded ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                )}
              </div>

              {/* Expanded: running progress bar */}
              {isRunning && (
                <div className="mx-4 mb-3">
                  <div className="h-1 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary animate-pulse transition-all duration-300"
                      style={{ width: `${tool.progress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* AI Suggestions */}
      {aiSuggestions.length > 0 && scanMode === "customizable" && (
        <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-purple-400" />
            <span className="text-sm font-medium text-purple-300">
              AI Suggestions
            </span>
          </div>

          {aiSuggestions.map((suggestion, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 rounded-lg border border-purple-500/10 bg-purple-500/5 p-3"
            >
              <Zap className="h-4 w-4 text-purple-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">
                    {suggestion.tool_name}
                  </span>
                  <span className="rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] text-purple-300">
                    {Math.round(suggestion.confidence * 100)}% confidence
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {suggestion.rationale}
                </p>
                {suggestion.expected_findings.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {suggestion.expected_findings.map((finding, fi) => (
                      <span
                        key={fi}
                        className="rounded bg-muted/30 px-1.5 py-0.5 text-[10px] text-muted-foreground"
                      >
                        {finding}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              {onAcceptSuggestion && (
                <button
                  onClick={() => onAcceptSuggestion(suggestion)}
                  className="shrink-0 flex items-center gap-1.5 rounded-lg bg-purple-500/20 px-3 py-1.5 text-xs font-medium text-purple-300 hover:bg-purple-500/30 transition-colors"
                >
                  <Plus className="h-3 w-3" />
                  Add
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
