"use client"

import Link from "next/link"
import { useMemo } from "react"
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FolderKanban,
  Radar,
  ShieldCheck,
} from "lucide-react"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useScans } from "@/hooks/use-scans"
import {
  extractExecutionSummary,
  extractVerificationCounts,
  type Scan,
  type ScanAsset,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type AssetRollup = {
  asset: ScanAsset
  totalFindings: number
  verifiedFindings: number
  latestScanId: string
  highestSeverity: "critical" | "high" | "medium" | "low" | "info"
  riskScore: number
}

const severityColors = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-muted-foreground",
}

const severityText = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-muted-foreground",
}

function totalFindings(scan: Scan) {
  return scan.findings.critical + scan.findings.high + scan.findings.medium + scan.findings.low
}

function severityScore(scan: Scan) {
  return (
    scan.findings.critical * 25 +
    scan.findings.high * 15 +
    scan.findings.medium * 8 +
    scan.findings.low * 3
  )
}

function highestSeverity(scan: Scan): AssetRollup["highestSeverity"] {
  if (scan.findings.critical > 0) return "critical"
  if (scan.findings.high > 0) return "high"
  if (scan.findings.medium > 0) return "medium"
  if (scan.findings.low > 0) return "low"
  return "info"
}

function formatLastActivity(timestamp: string) {
  if (!timestamp) return "No completed scans yet"
  const date = new Date(timestamp)
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export default function DashboardPage() {
  const {
    scans,
    isLoading: scansLoading,
    error: scansError,
  } = useScans({ pageSize: 100, pollIntervalMs: 5000 })
  const {
    assets,
    isLoading: assetsLoading,
    error: assetsError,
  } = useAssetCatalog()

  const dashboard = useMemo(() => {
    const openFindings = scans.reduce((sum, scan) => sum + totalFindings(scan), 0)
    const verification = scans.reduce(
      (acc, scan) => {
        const counts = extractVerificationCounts(scan.resultSummary)
        acc.verified += counts.verified
        acc.suspected += counts.suspected
        acc.detected += counts.detected
        return acc
      },
      { verified: 0, suspected: 0, detected: 0 }
    )
    const execution = scans.reduce(
      (acc, scan) => {
        const summary = extractExecutionSummary(scan.resultSummary)
        acc.live += summary.live
        acc.simulated += summary.simulated
        acc.blocked += summary.blocked
        acc.inferred += summary.inferred
        return acc
      },
      { live: 0, simulated: 0, blocked: 0, inferred: 0 }
    )
    const severity = scans.reduce(
      (acc, scan) => {
        acc.critical += scan.findings.critical
        acc.high += scan.findings.high
        acc.medium += scan.findings.medium
        acc.low += scan.findings.low
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    )

    const assetMap = new Map(assets.map((asset) => [asset.id, asset]))
    const rollups = new Map<string, AssetRollup>()
    for (const scan of scans) {
      const asset = assetMap.get(scan.assetId)
      if (!asset) continue
      const existing = rollups.get(asset.id)
      const verified = extractVerificationCounts(scan.resultSummary).verified
      const next: AssetRollup = existing
          ? {
            ...existing,
            totalFindings: existing.totalFindings + totalFindings(scan),
            verifiedFindings: existing.verifiedFindings + verified,
            latestScanId: scan.id,
            highestSeverity:
              ["critical", "high", "medium", "low", "info"].indexOf(highestSeverity(scan)) <
              ["critical", "high", "medium", "low", "info"].indexOf(existing.highestSeverity)
                ? highestSeverity(scan)
                : existing.highestSeverity,
            riskScore: Math.min(99, existing.riskScore + severityScore(scan) + verified * 8),
          }
        : {
            asset,
            totalFindings: totalFindings(scan),
            verifiedFindings: verified,
            latestScanId: scan.id,
            highestSeverity: highestSeverity(scan),
            riskScore: Math.min(99, severityScore(scan) + verified * 8),
          }
      rollups.set(asset.id, next)
    }

    return {
      activeScans: scans.filter((scan) => scan.status === "running" || scan.status === "queued").length,
      assetsMonitored: assets.length,
      openFindings,
      verification,
      execution,
      severity,
      recentScans: scans.slice(0, 5),
      topAssets: Array.from(rollups.values())
        .filter((item) => item.totalFindings > 0)
        .sort((left, right) => right.riskScore - left.riskScore)
        .slice(0, 5),
    }
  }, [assets, scans])

  const isLoading = scansLoading || assetsLoading
  const error = scansError ?? assetsError
  const severityTotal =
    dashboard.severity.critical +
    dashboard.severity.high +
    dashboard.severity.medium +
    dashboard.severity.low

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Dashboard" />

        <main className="p-6">
          <div className="mb-6">
            <h1 className="text-2xl font-semibold text-foreground">Operator Dashboard</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Real scan, asset, finding, and execution-truth aggregates across the current tenant.
            </p>
          </div>

          {isLoading ? (
            <div className="flex min-h-[40vh] items-center justify-center gap-3 rounded-lg border border-border bg-card">
              <Spinner className="h-5 w-5" />
              <span className="text-sm text-muted-foreground">Loading real dashboard data...</span>
            </div>
          ) : error ? (
            <div className="rounded-lg border border-critical/20 bg-critical/5 p-4 text-sm text-critical">
              {error}
            </div>
          ) : (
            <>
              <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Active Scans
                      </p>
                      <p className="mt-2 text-3xl font-semibold text-foreground">
                        {dashboard.activeScans}
                      </p>
                    </div>
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-primary/10">
                      <Radar className="h-5 w-5 text-primary" />
                    </div>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    {dashboard.recentScans.length} recent scans tracked in the operator view.
                  </p>
                </div>

                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Open Findings
                      </p>
                      <p className="mt-2 text-3xl font-semibold text-foreground">
                        {dashboard.openFindings}
                      </p>
                    </div>
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-critical/10">
                      <AlertTriangle className="h-5 w-5 text-critical" />
                    </div>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    {dashboard.severity.critical} critical, {dashboard.severity.high} high, {dashboard.severity.medium} medium.
                  </p>
                </div>

                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Monitored Assets
                      </p>
                      <p className="mt-2 text-3xl font-semibold text-foreground">
                        {dashboard.assetsMonitored}
                      </p>
                    </div>
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-high/10">
                      <FolderKanban className="h-5 w-5 text-high" />
                    </div>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Backed by the real project and asset inventory.
                  </p>
                </div>

                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Verified Proof
                      </p>
                      <p className="mt-2 text-3xl font-semibold text-foreground">
                        {dashboard.verification.verified}
                      </p>
                    </div>
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-low/10">
                      <ShieldCheck className="h-5 w-5 text-low" />
                    </div>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Live {dashboard.execution.live}, blocked {dashboard.execution.blocked}, inferred {dashboard.execution.inferred}.
                  </p>
                </div>
              </section>

              <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-5">
                <div className="xl:col-span-3 rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Findings by Severity</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Aggregated from persisted scan summaries.
                      </p>
                    </div>
                    <Link
                      href="/findings"
                      className="text-sm font-medium text-primary transition-colors hover:text-primary/80"
                    >
                      Open findings
                    </Link>
                  </div>

                  <div className="mt-6 overflow-hidden rounded-lg bg-elevated">
                    <div className="flex h-10 w-full">
                      {(["critical", "high", "medium", "low"] as const).map((severity) => {
                        const value = dashboard.severity[severity]
                        const width = severityTotal > 0 ? `${(value / severityTotal) * 100}%` : "0%"
                        return (
                          <div
                            key={severity}
                            className={cn(severityColors[severity], "h-full transition-all")}
                            style={{ width }}
                            title={`${severity}: ${value}`}
                          />
                        )
                      })}
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
                    {(["critical", "high", "medium", "low"] as const).map((severity) => (
                      <div key={severity} className="rounded-lg border border-border bg-background p-3">
                        <p className={cn("text-xs font-medium uppercase tracking-wide", severityText[severity])}>
                          {severity}
                        </p>
                        <p className="mt-2 text-2xl font-semibold text-foreground">
                          {dashboard.severity[severity]}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="xl:col-span-2 rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Top Vulnerable Assets</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Ranked from real scan summaries, not mock scores.
                      </p>
                    </div>
                    <Link
                      href="/assets"
                      className="text-sm font-medium text-primary transition-colors hover:text-primary/80"
                    >
                      Open assets
                    </Link>
                  </div>

                  <div className="mt-5 space-y-3">
                    {dashboard.topAssets.length === 0 ? (
                      <div className="rounded-lg border border-dashed border-border p-5 text-sm text-muted-foreground">
                        No persisted findings yet. Launch a real scan to populate asset risk.
                      </div>
                    ) : (
                      dashboard.topAssets.map((item) => (
                        <Link
                          key={item.asset.id}
                          href={`/assets/${item.asset.id}`}
                          className="block rounded-lg border border-border bg-background p-4 transition-colors hover:border-primary/40 hover:bg-elevated"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate text-sm font-medium text-foreground">
                                {item.asset.name}
                              </p>
                              <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                                {item.asset.target}
                              </p>
                            </div>
                            <span
                              className={cn(
                                "rounded-md px-2 py-1 text-xs font-semibold",
                                item.highestSeverity === "critical"
                                  ? "bg-critical/10 text-critical"
                                  : item.highestSeverity === "high"
                                    ? "bg-high/10 text-high"
                                    : item.highestSeverity === "medium"
                                      ? "bg-medium/10 text-medium"
                                      : "bg-low/10 text-low"
                              )}
                            >
                              {item.riskScore}
                            </span>
                          </div>

                          <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
                            <span>{item.totalFindings} findings</span>
                            <span>{item.verifiedFindings} verified</span>
                          </div>
                        </Link>
                      ))
                    )}
                  </div>
                </div>
              </section>

              <section className="mt-6 rounded-lg border border-border bg-card">
                <div className="flex items-center justify-between border-b border-border px-6 py-4">
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Recent Scans</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Most recent operator activity across the tenant.
                    </p>
                  </div>
                  <Link
                    href="/scans"
                    className="text-sm font-medium text-primary transition-colors hover:text-primary/80"
                  >
                    View all scans
                  </Link>
                </div>

                {dashboard.recentScans.length === 0 ? (
                  <div className="p-6 text-sm text-muted-foreground">
                    No scans have been launched yet.
                  </div>
                ) : (
                  <div className="divide-y divide-border">
                    {dashboard.recentScans.map((scan) => (
                      <Link
                        key={scan.id}
                        href={`/scans/${scan.id}`}
                        className="flex items-center justify-between gap-4 px-6 py-4 transition-colors hover:bg-elevated/60"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-foreground">{scan.name}</p>
                          <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                            {scan.target}
                          </p>
                        </div>
                        <div className="flex items-center gap-6">
                          <div className="text-right">
                            <p className="text-sm text-foreground">{totalFindings(scan)} findings</p>
                            <p className="mt-1 text-xs text-muted-foreground">
                              Last activity {formatLastActivity(scan.updatedAt)}
                            </p>
                          </div>
                          <div
                            className={cn(
                              "inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs font-medium",
                              scan.status === "completed"
                                ? "border-low/20 bg-low/10 text-low"
                                : scan.status === "failed"
                                  ? "border-critical/20 bg-critical/10 text-critical"
                                  : scan.status === "running"
                                    ? "border-primary/20 bg-primary/10 text-primary"
                                    : "border-border bg-background text-muted-foreground"
                            )}
                          >
                            <Activity className="h-3.5 w-3.5" />
                            {scan.statusLabel}
                          </div>
                          <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
                        </div>
                      </Link>
                    ))}
                  </div>
                )}
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  )
}
