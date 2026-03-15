"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import {
  CheckCircle,
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  Search,
  Shield,
  Target,
} from "lucide-react"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { Spinner } from "@/components/ui/spinner"
import { downloadScanReportExport, listScans, type ReportExportFormat, type Scan } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

function formatDate(dateString: string) {
  const date = new Date(dateString)
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  })
}

function formatTime(dateString: string) {
  const date = new Date(dateString)
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  })
}

const exportFormats: Array<{ id: "all" | ReportExportFormat; label: string; icon?: typeof FileText }> = [
  { id: "all", label: "All" },
  { id: "markdown", label: "MD", icon: FileText },
  { id: "json", label: "JSON", icon: FileJson },
  { id: "csv", label: "CSV", icon: FileSpreadsheet },
]

export default function ReportsPage() {
  const [reports, setReports] = useState<Scan[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [formatFilter, setFormatFilter] = useState<"all" | ReportExportFormat>("all")
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setIsLoading(true)
      setError(null)
      try {
        const response = await listScans({ status: "completed", pageSize: 100 })
        if (!cancelled) {
          setReports(response.items)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load reports.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [])

  const filteredReports = useMemo(() => {
    return reports.filter((report) => {
      const matchesSearch =
        report.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        report.target.toLowerCase().includes(searchQuery.toLowerCase())
      return matchesSearch
    })
  }, [reports, searchQuery])

  async function handleDownload(scanId: string, format: ReportExportFormat) {
    setDownloading(`${scanId}:${format}`)
    try {
      await downloadScanReportExport(scanId, format)
    } finally {
      setDownloading(null)
    }
  }

  const uniqueTargets = new Set(reports.map((report) => report.target)).size
  const criticalReports = reports.filter((report) => report.findings.critical > 0).length

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Reports" />

        <main className="p-6">
          <div className="mb-6 flex items-center justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Reports & Exports</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Real scan reports, exports, and engineering-ready offensive summaries.
              </p>
            </div>
          </div>

          <div className="mb-6 grid grid-cols-4 gap-4">
            {[
              { icon: FileText, label: "Completed Reports", value: reports.length, color: "text-foreground" },
              { icon: Shield, label: "Critical Present", value: criticalReports, color: "text-critical" },
              { icon: CheckCircle, label: "Buyer Ready", value: reports.length, color: "text-low" },
              { icon: Target, label: "Unique Targets", value: uniqueTargets, color: "text-high" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-lg border border-border bg-card p-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                    <stat.icon className={cn("h-5 w-5", stat.color)} />
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      {stat.label}
                    </p>
                    <p className={cn("text-xl font-semibold", stat.color)}>{stat.value}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mb-6 flex items-center gap-3">
            <div className="relative max-w-md flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                className="h-10 w-full rounded-md border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground transition-all focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </div>

            <div className="flex items-center gap-2">
              {exportFormats.map((format) => (
                <button
                  key={format.id}
                  onClick={() => setFormatFilter(format.id)}
                  className={cn(
                    "rounded-md px-3 py-2 text-sm font-medium transition-all",
                    formatFilter === format.id
                      ? "bg-primary text-primary-foreground"
                      : "border border-border text-muted-foreground hover:bg-elevated hover:text-foreground"
                  )}
                >
                  {format.label}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-hidden rounded-lg border border-border bg-card">
            {isLoading ? (
              <div className="flex items-center justify-center gap-3 p-10 text-sm text-muted-foreground">
                <Spinner className="h-5 w-5" />
                Loading real reports from completed scans...
              </div>
            ) : error ? (
              <div className="p-6 text-sm text-critical">{error}</div>
            ) : filteredReports.length === 0 ? (
              <div className="p-10 text-center text-sm text-muted-foreground">
                No completed scan reports match your current search.
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-elevated/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Report
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Target
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Findings
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Generated
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Export
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Open
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredReports.map((report) => {
                    const generatedAt = report.completedAt || report.updatedAt
                    const preferredFormats: ReportExportFormat[] =
                      formatFilter === "all" ? ["markdown", "json", "csv"] : [formatFilter]

                    return (
                      <tr key={report.id} className="group transition-colors hover:bg-elevated/50">
                        <td className="px-4 py-4">
                          <div>
                            <p className="text-sm font-medium text-foreground">{report.name}</p>
                            <p className="mt-1 text-xs text-muted-foreground">{report.id}</p>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <div>
                            <p className="text-sm text-foreground">{report.target}</p>
                            <p className="mt-1 text-xs text-muted-foreground">{report.profile}</p>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <div className="flex flex-wrap gap-2">
                            {report.findings.critical > 0 ? (
                              <span className="rounded-md bg-critical/10 px-2 py-1 text-xs text-critical">
                                C {report.findings.critical}
                              </span>
                            ) : null}
                            {report.findings.high > 0 ? (
                              <span className="rounded-md bg-high/10 px-2 py-1 text-xs text-high">
                                H {report.findings.high}
                              </span>
                            ) : null}
                            {report.findings.medium > 0 ? (
                              <span className="rounded-md bg-medium/10 px-2 py-1 text-xs text-medium">
                                M {report.findings.medium}
                              </span>
                            ) : null}
                            {report.findings.low > 0 ? (
                              <span className="rounded-md bg-low/10 px-2 py-1 text-xs text-low">
                                L {report.findings.low}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-4 text-sm text-muted-foreground">
                          <div>{formatDate(generatedAt)}</div>
                          <div className="mt-1 text-xs">{formatTime(generatedAt)}</div>
                        </td>
                        <td className="px-4 py-4">
                          <div className="flex flex-wrap gap-2">
                            {preferredFormats.map((format) => (
                              <button
                                key={`${report.id}:${format}`}
                                onClick={() => void handleDownload(report.id, format)}
                                disabled={downloading !== null}
                                className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-foreground hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
                              >
                                <Download className="h-3.5 w-3.5" />
                                {downloading === `${report.id}:${format}` ? "..." : format.toUpperCase()}
                              </button>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <Link
                            href={`/scans/${report.id}?tab=report`}
                            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground transition-all hover:bg-primary/90"
                          >
                            Open Report
                          </Link>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
