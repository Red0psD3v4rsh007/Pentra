"use client"

import Link from "next/link"
import {
  AlertCircle,
  CheckCircle,
  ChevronRight,
  Clock,
  Plus,
  RefreshCw,
  XCircle,
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
import { Progress } from "@/components/ui/progress"
import { Spinner } from "@/components/ui/spinner"
import { useScans } from "@/hooks/use-scans"
import { cn } from "@/lib/utils"

const statusConfig: Record<string, { icon: typeof RefreshCw; dotClass: string; textClass: string }> = {
  running: {
    icon: RefreshCw,
    dotClass: "bg-primary animate-pulse",
    textClass: "text-primary",
  },
  completed: {
    icon: CheckCircle,
    dotClass: "bg-low",
    textClass: "text-low",
  },
  failed: {
    icon: XCircle,
    dotClass: "bg-critical",
    textClass: "text-critical",
  },
  queued: {
    icon: Clock,
    dotClass: "bg-muted-foreground",
    textClass: "text-muted-foreground",
  },
  pending: {
    icon: Clock,
    dotClass: "bg-muted-foreground animate-pulse",
    textClass: "text-muted-foreground",
  },
  cancelled: {
    icon: XCircle,
    dotClass: "bg-medium",
    textClass: "text-medium",
  },
  cancelling: {
    icon: RefreshCw,
    dotClass: "bg-medium animate-pulse",
    textClass: "text-medium",
  },
}

const defaultStatus = {
  icon: Clock,
  dotClass: "bg-muted-foreground",
  textClass: "text-muted-foreground",
}

export default function ScansPage() {
  const { scans, isLoading, isRefreshing, error, refresh } = useScans()

  return (
    <CommandLayout title="Attacks">
        <main className="p-5">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <h1 className="text-lg font-semibold text-foreground font-heading">All Attacks</h1>
              <p className="text-sm text-muted-foreground">
                Live scan queue, status, progress, and findings from the Pentra API.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={refresh}
                className="flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
              >
                {isRefreshing ? (
                  <Spinner className="h-4 w-4" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                Refresh
              </button>

              <Link
                href="/scans/new"
                className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Plus className="h-4 w-4" />
                New Scan
              </Link>
            </div>
          </div>

          {error ? (
            <Alert variant="destructive" className="mb-6 border border-critical/40">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Could not load scans</AlertTitle>
              <AlertDescription>
                <p>{error}</p>
                <button
                  type="button"
                  onClick={refresh}
                  className="mt-2 text-sm font-medium underline underline-offset-4"
                >
                  Try again
                </button>
              </AlertDescription>
            </Alert>
          ) : null}

          {isLoading ? (
            <div className="flex min-h-[320px] items-center justify-center rounded-lg border border-border bg-card">
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <Spinner className="h-5 w-5" />
                Loading scans from the API...
              </div>
            </div>
          ) : scans.length === 0 ? (
            <Empty className="min-h-[320px] rounded-lg border border-border bg-card">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Clock className="h-6 w-6" />
                </EmptyMedia>
                <EmptyTitle>No scans yet</EmptyTitle>
                <EmptyDescription>
                  Start a scan against a seeded asset to watch the real pipeline move from
                  queued to completion.
                </EmptyDescription>
              </EmptyHeader>
              <Link
                href="/scans/new"
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Create the first scan
              </Link>
            </Empty>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border bg-card">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    <th className="px-4 py-3">Scan</th>
                    <th className="px-4 py-3">Target</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Progress</th>
                    <th className="px-4 py-3">Duration</th>
                    <th className="px-4 py-3">Findings</th>
                    <th className="w-10 px-4 py-3"></th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-border">
                  {scans.map((scan) => {
                    const status = statusConfig[scan.status] ?? defaultStatus
                    const totalFindings =
                      scan.findings.critical +
                      scan.findings.high +
                      scan.findings.medium +
                      scan.findings.low

                    return (
                      <tr
                        key={scan.id}
                        className="group text-sm transition-colors hover:bg-elevated"
                      >
                        <td className="px-4 py-3">
                          <Link href={`/scans/${scan.id}`} className="flex flex-col gap-0.5">
                            <span className="font-medium text-foreground transition-colors group-hover:text-primary">
                              {scan.name}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {scan.profile} · {scan.assetName}
                            </span>
                          </Link>
                        </td>

                        <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                          {scan.target}
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className={cn("h-2 w-2 rounded-full", status.dotClass)} />
                            <span className={cn("text-sm", status.textClass)}>
                              {scan.statusLabel}
                            </span>
                          </div>
                        </td>

                        <td className="px-4 py-3">
                          <div className="min-w-[140px] space-y-2">
                            <div className="flex items-center justify-between text-xs text-muted-foreground">
                              <span>{scan.progress}%</span>
                              <span>{scan.status === "completed" ? "Done" : "Live"}</span>
                            </div>
                            <Progress value={scan.progress} />
                          </div>
                        </td>

                        <td className="px-4 py-3 text-muted-foreground">{scan.duration}</td>

                        <td className="px-4 py-3">
                          {totalFindings > 0 ? (
                            <div className="flex items-center gap-2">
                              {scan.findings.critical > 0 ? (
                                <span className="rounded bg-critical/15 px-1.5 py-0.5 text-xs font-medium text-critical">
                                  {scan.findings.critical}
                                </span>
                              ) : null}
                              {scan.findings.high > 0 ? (
                                <span className="rounded bg-high/15 px-1.5 py-0.5 text-xs font-medium text-high">
                                  {scan.findings.high}
                                </span>
                              ) : null}
                              {scan.findings.medium > 0 ? (
                                <span className="rounded bg-medium/15 px-1.5 py-0.5 text-xs font-medium text-medium">
                                  {scan.findings.medium}
                                </span>
                              ) : null}
                              {scan.findings.low > 0 ? (
                                <span className="rounded bg-low/15 px-1.5 py-0.5 text-xs font-medium text-low">
                                  {scan.findings.low}
                                </span>
                              ) : null}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">No findings yet</span>
                          )}
                        </td>

                        <td className="px-4 py-3">
                          <Link
                            href={`/scans/${scan.id}`}
                            className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                          >
                            <ChevronRight className="h-4 w-4" />
                          </Link>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </main>
    </CommandLayout>
  )
}
