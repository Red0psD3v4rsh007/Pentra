"use client"

import type { ReactNode } from "react"
import { Bot, RefreshCw, Sparkles } from "lucide-react"

import { type AiAdvisoryMode, type ApiScanAiReasoning } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface AIAdvisoryPanelProps {
  reasoning: ApiScanAiReasoning | null
  title: string
  description: string
  children: ReactNode
  className?: string
  onRegenerate?: () => void
  isRegenerating?: boolean
  currentMode?: AiAdvisoryMode
  onChangeMode?: (mode: AiAdvisoryMode) => void
}

export function AIAdvisoryPanel({
  reasoning,
  title,
  description,
  children,
  className,
  onRegenerate,
  isRegenerating = false,
  currentMode,
  onChangeMode,
}: AIAdvisoryPanelProps) {
  if (!reasoning) {
    return null
  }

  const isFallback = reasoning.status !== "generated"

  return (
    <section
      className={cn(
        "rounded-xl border border-border bg-card p-5 shadow-sm",
        className
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-primary">
            <Sparkles className="h-3.5 w-3.5" />
            AI Advisory
          </div>
          <h3 className="text-base font-semibold text-foreground">{title}</h3>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>

        <div className="space-y-2 text-right">
          <div className="flex flex-wrap justify-end gap-2">
            {currentMode && onChangeMode ? (
              <div className="inline-flex rounded-full border border-border bg-background p-1">
                <button
                  type="button"
                  onClick={() => onChangeMode("advisory_only")}
                  disabled={isRegenerating || currentMode === "advisory_only"}
                  className={cn(
                    "rounded-full px-3 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-70",
                    currentMode === "advisory_only"
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-elevated"
                  )}
                >
                  Standard
                </button>
                <button
                  type="button"
                  onClick={() => onChangeMode("deep_advisory")}
                  disabled={isRegenerating || currentMode === "deep_advisory"}
                  className={cn(
                    "rounded-full px-3 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-70",
                    currentMode === "deep_advisory"
                      ? "bg-high text-background"
                      : "text-muted-foreground hover:bg-elevated"
                  )}
                >
                  Deep Advisory
                </button>
              </div>
            ) : null}
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-2.5 py-1 text-xs text-muted-foreground">
              <Bot className="h-3.5 w-3.5" />
              {reasoning.provider} · {reasoning.model}
            </div>
            {onRegenerate ? (
              <button
                type="button"
                onClick={onRegenerate}
                disabled={isRegenerating}
                className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-2.5 py-1 text-xs text-foreground transition-colors hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", isRegenerating ? "animate-spin" : "")} />
                {isRegenerating ? "Regenerating" : "Regenerate"}
              </button>
            ) : null}
          </div>
          <p className="text-xs text-muted-foreground">
            {new Date(reasoning.generated_at).toLocaleString()}
          </p>
        </div>
      </div>

      <div className="mt-4">{children}</div>

      <div className="mt-4 space-y-2 border-t border-border pt-4">
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="rounded-full bg-muted px-2.5 py-1 text-muted-foreground">
            advisory only
          </span>
          <span className="rounded-full bg-primary/10 px-2.5 py-1 text-primary">
            {reasoning.advisory_mode === "deep_advisory" ? "deep advisory" : "standard advisory"}
          </span>
          <span
            className={cn(
              "rounded-full px-2.5 py-1",
              isFallback
                ? "bg-medium/10 text-medium"
                : "bg-low/10 text-low"
            )}
          >
            {reasoning.status}
          </span>
        </div>

        {reasoning.fallback_reason ? (
          <p className="text-xs text-muted-foreground">
            Fallback active: {reasoning.fallback_reason}
          </p>
        ) : null}

        {reasoning.audit.storage_ref ? (
          <p className="font-mono text-[11px] text-muted-foreground">
            Audit artifact: {reasoning.audit.storage_ref}
          </p>
        ) : null}
      </div>
    </section>
  )
}
