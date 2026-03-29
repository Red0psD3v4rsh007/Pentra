"use client"

import type { ElementType } from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import {
  AlertCircle,
  ArrowUpRight,
  ChevronLeft,
  FolderKanban,
  ShieldCheck,
  Target,
} from "lucide-react"

import { CommandLayout } from "@/components/layout/command-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { useAsset, useAssetHistory, useAssetHistoricalFindings } from "@/hooks/use-scans"
import {
  formatAssetType,
  formatRelativeTime,
  getScanStatusMeta,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>()
  const assetId = typeof params?.id === "string" ? params.id : undefined
  const { asset, isLoading, error, refresh } = useAsset(assetId)
  const {
    history,
    isLoading: historyLoading,
    isRefreshing: historyRefreshing,
    error: historyError,
    refresh: refreshHistory,
  } = useAssetHistory(assetId, {
    limit: 20,
  })
  const {
    items: historicalFindings,
    isLoading: historicalFindingsLoading,
    isRefreshing: historicalFindingsRefreshing,
    error: historicalFindingsError,
    refresh: refreshHistoricalFindings,
  } = useAssetHistoricalFindings(assetId, {
    pageSize: 8,
    status: "all",
    occurrenceLimit: 2,
  })

  return (
    <CommandLayout title="Asset Detail">

        <header className="sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur-md">
          <div className="flex h-16 items-center justify-between px-6">
            <div className="flex items-center gap-4">
              <Link
                href="/assets"
                className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground"
              >
                <ChevronLeft className="h-4 w-4" />
              </Link>
              <div>
                <h1 className="text-lg font-semibold text-foreground">Asset Detail</h1>
                <p className="text-xs text-muted-foreground">
                  Real target metadata and scan history for this asset.
                </p>
              </div>
            </div>

            {assetId ? (
              <Link
                href={`/scans/new?assetId=${assetId}`}
                className="rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Launch Scan
              </Link>
            ) : null}
          </div>
        </header>

        <main className="space-y-6 p-6">
          {error ? (
            <Alert variant="destructive" className="border border-critical/40">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Could not load asset</AlertTitle>
              <AlertDescription>
                <p>{error}</p>
                <button
                  type="button"
                  onClick={refresh}
                  className="mt-2 text-sm font-medium underline underline-offset-4"
                >
                  Retry asset lookup
                </button>
              </AlertDescription>
            </Alert>
          ) : null}

          {isLoading ? (
            <div className="flex min-h-[260px] items-center justify-center rounded-3xl border border-border bg-card">
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <Spinner className="h-5 w-5" />
                Loading asset detail...
              </div>
            </div>
          ) : !asset ? (
            <Empty className="min-h-[260px] rounded-3xl border border-border bg-card">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Target className="h-6 w-6" />
                </EmptyMedia>
                <EmptyTitle>Asset not found</EmptyTitle>
                <EmptyDescription>
                  The requested asset is not available for the current tenant.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <>
              <section className="rounded-3xl border border-border bg-card p-6">
                <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                  <div className="max-w-3xl">
                    <div className="mb-3 flex flex-wrap items-center gap-2">
                      <span className="inline-flex rounded-full border border-border bg-background px-3 py-1 text-xs font-medium text-foreground">
                        {formatAssetType(asset.asset_type)}
                      </span>
                      <span
                        className={cn(
                          "inline-flex rounded-full px-3 py-1 text-xs font-medium",
                          asset.is_verified ? "bg-low/10 text-low" : "bg-medium/10 text-medium"
                        )}
                      >
                        {asset.is_verified ? "Verified ownership" : "Pending verification"}
                      </span>
                    </div>
                    <h2 className="text-2xl font-semibold text-foreground">{asset.name}</h2>
                    <p className="mt-2 font-mono text-sm text-muted-foreground">{asset.target}</p>
                    {asset.description ? (
                      <p className="mt-4 text-sm text-muted-foreground">{asset.description}</p>
                    ) : null}
                  </div>

                  <div className="grid w-full gap-4 sm:grid-cols-2 xl:w-[420px]">
                    <SummaryCard
                      icon={FolderKanban}
                      label="Project"
                      value={asset.project?.name ?? "Unassigned"}
                      helper={
                        asset.project
                          ? `${asset.project.asset_count} assets in this project`
                          : "No project metadata"
                      }
                    />
                    <SummaryCard
                      icon={ShieldCheck}
                      label="Updated"
                      value={formatRelativeTime(asset.updated_at)}
                      helper={`Created ${formatRelativeTime(asset.created_at)}`}
                    />
                  </div>
                </div>
              </section>

              <section className="rounded-3xl border border-border bg-card p-6">
                <div className="mb-5 flex items-center justify-between gap-4">
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">Scan history</h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Cross-scan history, diff movement, and knowledge retained for this asset.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={refreshHistory}
                    className="rounded-xl border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                  >
                    {historyRefreshing ? "Refreshing..." : "Refresh"}
                  </button>
                </div>

                {history ? (
                  <div className="mb-5 grid gap-4 lg:grid-cols-2">
                    <div className="rounded-2xl border border-border bg-background p-4">
                      <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Known technologies
                      </p>
                      <p className="mt-2 text-sm text-muted-foreground">
                        {history.total_scans} total scans retained for this asset.
                      </p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {history.known_technologies.length === 0 ? (
                          <span className="text-sm text-muted-foreground">No technology profile yet.</span>
                        ) : (
                          history.known_technologies.map((technology) => (
                            <span
                              key={technology}
                              className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                            >
                              {technology}
                            </span>
                          ))
                        )}
                      </div>
                    </div>
                    <div className="rounded-2xl border border-border bg-background p-4">
                      <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Tracked vulnerability types
                      </p>
                      <p className="mt-2 text-sm text-muted-foreground">
                        Cross-scan pressure areas Pentra has seen on this asset.
                      </p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {history.tracked_vulnerability_types.length === 0 ? (
                          <span className="text-sm text-muted-foreground">No recurring vulnerability types yet.</span>
                        ) : (
                          history.tracked_vulnerability_types.map((item) => (
                            <span
                              key={item}
                              className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                            >
                              {item}
                            </span>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                ) : null}

                {historyError ? (
                  <Alert variant="destructive" className="border border-critical/40">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Could not load scan history</AlertTitle>
                    <AlertDescription>{historyError}</AlertDescription>
                  </Alert>
                ) : historyLoading ? (
                  <div className="flex min-h-[180px] items-center justify-center rounded-2xl border border-border bg-background">
                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                      <Spinner className="h-5 w-5" />
                      Loading scans for this asset...
                    </div>
                  </div>
                ) : !history || history.entries.length === 0 ? (
                  <Empty className="min-h-[180px] rounded-2xl border border-dashed border-border bg-background">
                    <EmptyHeader>
                      <EmptyMedia variant="icon">
                        <Target className="h-6 w-6" />
                      </EmptyMedia>
                      <EmptyTitle>No scans yet</EmptyTitle>
                      <EmptyDescription>
                        This asset is ready, but it has not been scanned yet.
                      </EmptyDescription>
                    </EmptyHeader>
                  </Empty>
                ) : (
                  <div className="overflow-hidden rounded-2xl border border-border">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border bg-elevated/60">
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Scan
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Status
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Findings
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Trend
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Completed
                          </th>
                          <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Open
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {history.entries.map((entry) => {
                          const statusMeta = getScanStatusMeta(entry.status)
                          const trendSummary = formatComparisonSummary(entry.comparison_counts)

                          return (
                            <tr key={entry.scan_id} className="bg-card transition-colors hover:bg-elevated/40">
                              <td className="px-4 py-4 align-top">
                                <div>
                                  <p className="text-sm font-semibold text-foreground">
                                    {formatScanTypeLabel(entry.scan_type)}
                                  </p>
                                  <p className="mt-1 text-xs text-muted-foreground">
                                    Priority {entry.priority}
                                  </p>
                                </div>
                              </td>
                              <td className="px-4 py-4 align-top">
                                <span
                                  className={cn(
                                    "inline-flex rounded-full px-3 py-1 text-xs font-medium",
                                    statusMeta.bgClass,
                                    statusMeta.textClass
                                  )}
                                >
                                  {statusMeta.label}
                                </span>
                              </td>
                              <td className="px-4 py-4 align-top text-sm text-muted-foreground">
                                {entry.total_findings} total
                              </td>
                              <td className="px-4 py-4 align-top text-sm text-muted-foreground">
                                {trendSummary}
                              </td>
                              <td className="px-4 py-4 align-top text-sm text-muted-foreground">
                                {entry.completed_at ? formatRelativeTime(entry.completed_at) : "In progress"}
                              </td>
                              <td className="px-4 py-4 align-top text-right">
                                <Link
                                  href={`/scans/${entry.scan_id}`}
                                  className="inline-flex items-center gap-1 rounded-xl border border-border px-3 py-2 text-xs font-medium text-foreground transition-colors hover:bg-elevated"
                                >
                                  View scan
                                  <ArrowUpRight className="h-3.5 w-3.5" />
                                </Link>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section className="rounded-3xl border border-border bg-card p-6">
                <div className="mb-5 flex items-center justify-between gap-4">
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">Historical findings</h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Asset-scoped finding lineages deduplicated across completed scans.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={refreshHistoricalFindings}
                    className="rounded-xl border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                  >
                    {historicalFindingsRefreshing ? "Refreshing..." : "Refresh"}
                  </button>
                </div>

                {historicalFindingsError ? (
                  <Alert variant="destructive" className="border border-critical/40">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Could not load historical findings</AlertTitle>
                    <AlertDescription>{historicalFindingsError}</AlertDescription>
                  </Alert>
                ) : historicalFindingsLoading ? (
                  <div className="flex min-h-[160px] items-center justify-center rounded-2xl border border-border bg-background">
                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                      <Spinner className="h-5 w-5" />
                      Loading historical finding lineages...
                    </div>
                  </div>
                ) : historicalFindings.length === 0 ? (
                  <Empty className="min-h-[160px] rounded-2xl border border-dashed border-border bg-background">
                    <EmptyHeader>
                      <EmptyMedia variant="icon">
                        <ShieldCheck className="h-6 w-6" />
                      </EmptyMedia>
                      <EmptyTitle>No archived finding lineages yet</EmptyTitle>
                      <EmptyDescription>
                        Historical lineages appear after completed scans persist final findings.
                      </EmptyDescription>
                    </EmptyHeader>
                  </Empty>
                ) : (
                  <div className="space-y-3">
                    {historicalFindings.map((finding) => (
                      <div key={finding.id} className="rounded-2xl border border-border bg-background p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-foreground">{finding.title}</p>
                            <p className="mt-1 truncate text-xs text-muted-foreground">
                              {finding.vulnerability_type ?? "unclassified"} · {finding.route_group ?? finding.target}
                            </p>
                          </div>
                          <div className="flex flex-wrap items-center justify-end gap-2">
                            <span
                              className={cn(
                                "inline-flex rounded-full px-3 py-1 text-xs font-medium",
                                finding.status === "active" ? "bg-high/10 text-high" : "bg-low/10 text-low"
                              )}
                            >
                              {finding.status}
                            </span>
                            <span
                              className={cn(
                                "inline-flex rounded-full px-3 py-1 text-xs font-medium",
                                getSeverityPillClass(finding.latest_severity)
                              )}
                            >
                              {finding.latest_severity}
                            </span>
                          </div>
                        </div>

                        <div className="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
                          <span>seen in {finding.occurrence_count} completed scans</span>
                          <span>first seen {formatRelativeTime(finding.first_seen_at)}</span>
                          <span>last seen {formatRelativeTime(finding.last_seen_at)}</span>
                        </div>

                        {finding.recent_occurrences.length > 0 ? (
                          <div className="mt-3 flex flex-wrap gap-2">
                            {finding.recent_occurrences.map((occurrence) => (
                              <Link
                                key={occurrence.id}
                                href={`/scans/${occurrence.scan_id}`}
                                className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-elevated"
                              >
                                {occurrence.severity} · {occurrence.verification_state ?? "detected"}
                              </Link>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </>
          )}
        </main>
    </CommandLayout>
  )
}

function formatComparisonSummary(counts: Record<string, number>) {
  const parts: string[] = []
  const newCount = counts.new ?? 0
  const resolvedCount = counts.resolved ?? 0
  const escalatedCount = counts.escalated ?? 0

  if (newCount > 0) {
    parts.push(`+${newCount} new`)
  }
  if (resolvedCount > 0) {
    parts.push(`${resolvedCount} resolved`)
  }
  if (escalatedCount > 0) {
    parts.push(`${escalatedCount} escalated`)
  }

  if (parts.length === 0) {
    return "No baseline movement yet"
  }

  return parts.join(" · ")
}

function formatScanTypeLabel(scanType: string) {
  return scanType.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase())
}

function getSeverityPillClass(severity: string) {
  if (severity === "critical") return "bg-critical/10 text-critical"
  if (severity === "high") return "bg-high/10 text-high"
  if (severity === "medium") return "bg-medium/10 text-medium"
  if (severity === "low") return "bg-low/10 text-low"
  return "bg-elevated text-muted-foreground"
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  helper,
}: {
  icon: ElementType
  label: string
  value: string
  helper: string
}) {
  return (
    <div className="rounded-2xl border border-border bg-background p-4">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-2xl bg-elevated text-muted-foreground">
        <Icon className="h-4 w-4" />
      </div>
      <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-2 text-sm font-semibold text-foreground">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{helper}</p>
    </div>
  )
}
