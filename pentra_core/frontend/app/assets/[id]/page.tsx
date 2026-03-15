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

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { useAsset, useScans } from "@/hooks/use-scans"
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
    scans,
    isLoading: scansLoading,
    error: scansError,
    refresh: refreshScans,
  } = useScans({
    assetId,
    pageSize: 20,
  })

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
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
                      Every scan below is filtered to this asset using the live scans API.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={refreshScans}
                    className="rounded-xl border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                  >
                    Refresh
                  </button>
                </div>

                {scansError ? (
                  <Alert variant="destructive" className="border border-critical/40">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Could not load scan history</AlertTitle>
                    <AlertDescription>{scansError}</AlertDescription>
                  </Alert>
                ) : scansLoading ? (
                  <div className="flex min-h-[180px] items-center justify-center rounded-2xl border border-border bg-background">
                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                      <Spinner className="h-5 w-5" />
                      Loading scans for this asset...
                    </div>
                  </div>
                ) : scans.length === 0 ? (
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
                            Started
                          </th>
                          <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                            Open
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {scans.map((scan) => {
                          const statusMeta = getScanStatusMeta(scan.rawStatus)
                          const totalFindings =
                            scan.findings.critical +
                            scan.findings.high +
                            scan.findings.medium +
                            scan.findings.low

                          return (
                            <tr key={scan.id} className="bg-card transition-colors hover:bg-elevated/40">
                              <td className="px-4 py-4 align-top">
                                <div>
                                  <p className="text-sm font-semibold text-foreground">{scan.name}</p>
                                  <p className="mt-1 text-xs text-muted-foreground">{scan.profile}</p>
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
                                {totalFindings} total
                              </td>
                              <td className="px-4 py-4 align-top text-sm text-muted-foreground">
                                {scan.startedAt ? formatRelativeTime(scan.startedAt) : "Queued"}
                              </td>
                              <td className="px-4 py-4 align-top text-right">
                                <Link
                                  href={`/scans/${scan.id}`}
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
            </>
          )}
        </main>
      </div>
    </div>
  )
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
