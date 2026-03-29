"use client"

import { type ReactNode, useMemo } from "react"
import Link from "next/link"
import { Brain, Radio, ShieldCheck, Sparkles, Swords, X } from "lucide-react"

import { Spinner } from "@/components/ui/spinner"
import { StatusBadge } from "@/components/ui/status-badge"
import { useRuntimeDiagnostics, useScans } from "@/hooks/use-scans"
import { useNotificationStore } from "@/lib/notification-store"
import { cn } from "@/lib/utils"

interface RightPanelProps {
  onClose: () => void
  children?: ReactNode
}

function timeAgo(ts: number): string {
  const seconds = Math.floor((Date.now() - ts) / 1000)
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export function RightPanel({ onClose, children }: RightPanelProps) {
  return (
    <aside className="flex w-[320px] shrink-0 flex-col border-l border-border-subtle bg-surface-0 overflow-hidden">
      <div className="flex h-12 items-center justify-between border-b border-border-subtle px-4">
        <div className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-neon" />
          <span className="text-xs font-semibold tracking-[0.15em] text-foreground font-heading">
            TACTICAL PANEL
          </span>
        </div>
        <button
          onClick={onClose}
          className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {children || <DefaultRightPanelContent />}
      </div>
    </aside>
  )
}

function DefaultRightPanelContent() {
  const {
    aiDiagnostics,
    systemStatus,
    isLoading: diagnosticsLoading,
    error: diagnosticsError,
  } = useRuntimeDiagnostics()
  const {
    scans,
    isLoading: scansLoading,
    error: scansError,
  } = useScans({ pageSize: 6, pollIntervalMs: 5000 })
  const notifications = useNotificationStore((state) => state.items)

  const featuredScans = useMemo(() => {
    const active = scans.filter((scan) => scan.status === "running" || scan.status === "queued")
    return (active.length > 0 ? active : scans).slice(0, 4)
  }, [scans])

  return (
    <div className="space-y-4 p-4">
      <section className="rounded border border-border-subtle bg-surface-1/60 p-3">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="h-3.5 w-3.5 text-neon" />
            <span className="text-xs font-semibold text-foreground">AI Runtime</span>
          </div>
          {diagnosticsLoading ? (
            <Spinner className="size-4 text-primary" />
          ) : (
            <StatusBadge
              status={aiDiagnostics?.operator_state ?? "unavailable"}
              label={aiDiagnostics?.operator_state?.replaceAll("_", " ") ?? "unavailable"}
            />
          )}
        </div>

        {diagnosticsError ? (
          <p className="text-xs text-critical">{diagnosticsError}</p>
        ) : (
          <div className="space-y-2 text-xs text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>Provider routing</span>
              <span className="text-foreground">
                {aiDiagnostics?.provider_priority?.slice(0, 3).join(" -> ") || "not available"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Healthy providers</span>
              <span className="text-foreground">
                {aiDiagnostics?.healthy_provider_count ?? 0}/{aiDiagnostics?.configured_provider_count ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Fallback providers</span>
              <span className="text-foreground">{aiDiagnostics?.fallback_provider_count ?? 0}</span>
            </div>
            {aiDiagnostics?.last_failure ? (
              <p className="rounded border border-[#ffaa00]/20 bg-[#ffaa00]/8 px-2 py-1.5 text-[11px] text-[#ffaa00]">
                Last failure: {aiDiagnostics.last_failure}
              </p>
            ) : null}
          </div>
        )}
      </section>

      <section className="rounded border border-border-subtle bg-surface-1/60 p-3">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-3.5 w-3.5 text-cyan" />
            <span className="text-xs font-semibold text-foreground">Runtime Status</span>
          </div>
          {diagnosticsLoading ? (
            <Spinner className="size-4 text-primary" />
          ) : (
            <StatusBadge
              status={systemStatus?.status ?? "unavailable"}
              label={systemStatus?.status ?? "unavailable"}
            />
          )}
        </div>

        <div className="space-y-2">
          {["api", "orchestrator", "worker", "redis", "ai", "external_target_scanning"].map((service) => (
            <div key={service} className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{service.replaceAll("_", " ")}</span>
              <StatusBadge
                status={systemStatus?.services?.[service] ?? "unavailable"}
                label={(systemStatus?.services?.[service] ?? "unavailable").replaceAll("_", " ")}
              />
            </div>
          ))}
        </div>
      </section>

      <section className="rounded border border-border-subtle bg-surface-1/60 p-3">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Swords className="h-3.5 w-3.5 text-primary" />
            <span className="text-xs font-semibold text-foreground">Scan Activity</span>
          </div>
          {scansLoading ? <Spinner className="size-4 text-primary" /> : null}
        </div>

        {scansError ? (
          <p className="text-xs text-critical">{scansError}</p>
        ) : featuredScans.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No scan activity has been recorded yet. Launch a scan to populate live tactical context.
          </p>
        ) : (
          <div className="space-y-2">
            {featuredScans.map((scan) => (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="block rounded border border-transparent bg-black/20 px-2.5 py-2 transition-colors hover:border-border hover:bg-black/30"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-semibold text-foreground">{scan.name}</p>
                    <p className="truncate text-[11px] text-muted-foreground">{scan.target}</p>
                  </div>
                  <StatusBadge status={scan.status} label={scan.statusLabel} />
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>{scan.progress}% progress</span>
                  <span>{scan.duration || "queued"}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      <section className="rounded border border-border-subtle bg-surface-1/60 p-3">
        <div className="mb-3 flex items-center gap-2">
          <Radio className="h-3 w-3 text-cyan" />
          <span className="text-[10px] font-semibold tracking-[0.15em] text-dim font-heading">
            LIVE EVENTS
          </span>
        </div>

        {notifications.length === 0 ? (
          <p className="text-xs text-muted-foreground">Awaiting real scan and finding events...</p>
        ) : (
          <div className="space-y-2">
            {notifications.slice(0, 6).map((event) => (
              <div
                key={event.id}
                className={cn(
                  "rounded border px-2.5 py-2",
                  event.read ? "border-border-subtle bg-black/15" : "border-primary/20 bg-primary/5"
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-foreground">{event.title}</p>
                    <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                      {event.message}
                    </p>
                  </div>
                  <span className="shrink-0 text-[10px] font-mono text-dim">{timeAgo(event.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
