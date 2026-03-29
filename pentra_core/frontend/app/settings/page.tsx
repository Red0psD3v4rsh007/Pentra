"use client"

import type { ReactNode } from "react"
import Link from "next/link"
import { Activity, AlertTriangle, CheckCircle2, RefreshCw, Settings2, Shield, Wrench } from "lucide-react"

import { CommandLayout } from "@/components/layout/command-layout"
import { StatusBadge } from "@/components/ui/status-badge"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useRuntimeDiagnostics, useScans } from "@/hooks/use-scans"

const SERVICE_LABELS: Record<string, string> = {
  api: "API",
  db: "Database",
  redis: "Redis",
  orchestrator: "Orchestrator",
  worker: "Worker",
  ai: "AI",
  external_target_scanning: "External Target Permission",
}

function humanizeTaskKey(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}

export default function SettingsPage() {
  const { scans, isLoading: scansLoading, error: scansError } = useScans({ pageSize: 100 })
  const {
    projects,
    assets,
    isLoading: assetsLoading,
    error: assetsError,
  } = useAssetCatalog()
  const {
    aiDiagnostics,
    systemStatus,
    isLoading: runtimeLoading,
    isRefreshing,
    isProbing,
    error: runtimeError,
    probeProviders,
    refresh,
  } = useRuntimeDiagnostics()

  const isLoading = scansLoading || assetsLoading || runtimeLoading
  const error = scansError ?? assetsError ?? runtimeError
  const providerEntries = Object.entries(aiDiagnostics?.tasks ?? {})
  const effectiveProviderPriority =
    aiDiagnostics?.effective_provider_priority?.length
      ? aiDiagnostics.effective_provider_priority
      : aiDiagnostics?.provider_priority ?? []
  const configuredProviderPriority = aiDiagnostics?.provider_priority ?? []

  return (
    <CommandLayout title="Settings">
      <main className="space-y-6 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-foreground">Runtime & Providers</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Live operator console for backend health, AI readiness, and external-target launch posture.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <button
              type="button"
              onClick={probeProviders}
              disabled={isProbing}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Activity className={`h-4 w-4 ${isProbing ? "animate-spin" : ""}`} />
              {isProbing ? "Running Probe" : "Live Probe"}
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="flex min-h-[32vh] items-center justify-center gap-3 rounded-lg border border-border bg-card">
            <Spinner className="h-5 w-5" />
            <span className="text-sm text-muted-foreground">Loading runtime state...</span>
          </div>
        ) : error ? (
          <div className="rounded-lg border border-critical/20 bg-critical/5 p-4 text-sm text-critical">
            {error}
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
              <MetricCard
                icon={Shield}
                label="Projects"
                value={String(projects.length)}
                tone="primary"
              />
              <MetricCard
                icon={Settings2}
                label="Assets"
                value={String(assets.length)}
                tone="high"
              />
              <MetricCard
                icon={Wrench}
                label="Scans Observed"
                value={String(scans.length)}
                tone="low"
              />
              <MetricCard
                icon={CheckCircle2}
                label="AI Operator State"
                value={aiDiagnostics?.operator_state ?? "unknown"}
                tone="primary"
                badge={
                  <StatusBadge
                    status={aiDiagnostics?.operator_state ?? "unavailable"}
                    label={aiDiagnostics?.configuration_ready ? "Configuration Ready" : "Attention Needed"}
                  />
                }
              />
            </div>

            <section className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
              <div className="rounded-lg border border-border bg-card p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Runtime Health</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      API, orchestrator, worker, Redis, AI, and external-target permission state.
                    </p>
                  </div>
                  <StatusBadge status={systemStatus?.status ?? "unavailable"} label={systemStatus?.status ?? "unknown"} />
                </div>

                <div className="mt-5 grid gap-3 md:grid-cols-2">
                  {Object.entries(systemStatus?.services ?? {}).map(([key, value]) => (
                    <div key={key} className="rounded-lg border border-border bg-background p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-foreground">
                            {SERVICE_LABELS[key] ?? key}
                          </p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {key === "external_target_scanning"
                              ? "Permission gate for authorized external scans"
                              : "Runtime service health"}
                          </p>
                        </div>
                        <StatusBadge status={value} label={value} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-border bg-card p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Provider Routing</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Config-only status plus live-probe results for advisory routing.
                    </p>
                  </div>
                  <StatusBadge
                    status={aiDiagnostics?.operator_state ?? "unavailable"}
                    label={aiDiagnostics?.operator_state ?? "unknown"}
                  />
                </div>

                <div className="mt-5 space-y-3 text-sm text-muted-foreground">
                  <div className="rounded-lg border border-border bg-background p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Advisory Runtime Chain
                    </p>
                    <p className="mt-2 font-mono text-xs text-foreground">
                      {effectiveProviderPriority.join(" -> ") || "No providers configured"}
                    </p>
                  </div>
                  {configuredProviderPriority.length > effectiveProviderPriority.length ? (
                    <div className="rounded-lg border border-border bg-background p-4">
                      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Configured Order
                      </p>
                      <p className="mt-2 font-mono text-xs text-foreground">
                        {configuredProviderPriority.join(" -> ")}
                      </p>
                    </div>
                  ) : null}
                  <div className="rounded-lg border border-border bg-background p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Configuration
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <StatusBadge
                        status={aiDiagnostics?.configuration_ready ? "configured_and_healthy" : "configured_but_fallback"}
                        label={
                          aiDiagnostics?.configuration_ready ? "Configuration Ready" : "Fallback Expected"
                        }
                      />
                      <StatusBadge
                        status="verified"
                        label={`${aiDiagnostics?.configured_provider_count ?? 0} configured`}
                      />
                      <StatusBadge
                        status="verified"
                        label={`${aiDiagnostics?.healthy_provider_count ?? 0} healthy`}
                      />
                    </div>
                  </div>
                  <div className="rounded-lg border border-border bg-background p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Last Failure
                    </p>
                    <p className="mt-2 text-xs text-foreground">
                      {aiDiagnostics?.last_failure ?? "No provider failures recorded."}
                    </p>
                  </div>
                </div>
              </div>
            </section>

            <section className="rounded-lg border border-border bg-card p-6">
              <h2 className="text-base font-semibold text-foreground">Provider Tasks</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Task-level routing, model selection, key presence, and live probe state.
              </p>
              <div className="mt-5 space-y-4">
                {providerEntries.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                    No provider task diagnostics are available yet.
                  </div>
                ) : (
                  providerEntries.map(([task, entries]) => (
                    <div key={task} className="rounded-lg border border-border bg-background p-4">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <div>
                          <h3 className="text-sm font-semibold text-foreground">{humanizeTaskKey(task)}</h3>
                          <p className="text-xs text-muted-foreground">
                            Operator-visible routing and fallback state for this task.
                          </p>
                        </div>
                      </div>
                      <div className="space-y-3">
                        {entries.map((entry) => (
                          <div key={`${task}-${entry.provider}-${entry.model}`} className="rounded-lg border border-border bg-card p-4">
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div>
                                <p className="text-sm font-semibold text-foreground">
                                  {entry.provider} | {entry.model}
                                </p>
                                <p className="text-xs text-muted-foreground">
                                  {entry.request_surface} | {entry.model_tier}
                                </p>
                              </div>
                              <div className="flex flex-wrap gap-2">
                                <StatusBadge status={entry.operator_state} label={entry.operator_state} />
                                <StatusBadge
                                  status={entry.api_key_configured ? "verified" : "missing_api_key"}
                                  label={entry.api_key_configured ? "Key Present" : "Key Missing"}
                                />
                              </div>
                            </div>
                            <div className="mt-3 grid gap-3 md:grid-cols-3">
                              <InfoItem label="Configured" value={entry.configured ? "Yes" : "No"} />
                              <InfoItem label="Base URL" value={entry.base_url} mono />
                              <InfoItem label="Live Probe" value={entry.probe?.status ?? "not_run"} />
                            </div>
                            {entry.probe?.error ? (
                              <p className="mt-3 text-xs text-critical">{entry.probe.error}</p>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="rounded-lg border border-border bg-card p-6">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-high" />
                <div>
                  <h2 className="text-base font-semibold text-foreground">Operator Actions</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Use the real product surfaces below to launch, inspect, and validate scans.
                  </p>
                </div>
              </div>
              <div className="mt-5 flex flex-wrap gap-3">
                <Link
                  href="/dashboard"
                  className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                >
                  Open Dashboard
                </Link>
                <Link
                  href="/scans/new"
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Launch Scan
                </Link>
                <Link
                  href="/scans"
                  className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                >
                  Inspect Scans
                </Link>
              </div>
            </section>
          </>
        )}
      </main>
    </CommandLayout>
  )
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
  badge,
}: {
  icon: typeof Shield
  label: string
  value: string
  tone: "primary" | "high" | "low"
  badge?: ReactNode
}) {
  const toneClasses =
    tone === "primary"
      ? "bg-primary/10 text-primary"
      : tone === "high"
        ? "bg-high/10 text-high"
        : "bg-low/10 text-low"

  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="flex items-center gap-3">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${toneClasses}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className="text-2xl font-semibold text-foreground">{value}</p>
        </div>
      </div>
      {badge ? <div className="mt-4">{badge}</div> : null}
    </div>
  )
}

function InfoItem({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-1 text-sm text-foreground ${mono ? "font-mono break-all" : ""}`}>{value}</p>
    </div>
  )
}
