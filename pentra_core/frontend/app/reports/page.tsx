"use client"

import { useState } from "react"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { 
  FileText,
  FileJson,
  FileSpreadsheet,
  File,
  Plus,
  Download,
  Search,
  Calendar,
  ChevronRight,
  Clock,
  Target,
  CheckCircle
} from "lucide-react"
import { cn } from "@/lib/utils"

// Mock data for reports
const REPORTS = [
  {
    id: "RPT-001",
    name: "Q4 2024 Security Assessment",
    format: "pdf",
    scope: "Full Infrastructure",
    target: "acmecorp.com",
    generatedAt: "2024-12-15T14:30:00Z",
    size: "2.4 MB",
    status: "completed",
    findings: { critical: 3, high: 12, medium: 24, low: 18 },
  },
  {
    id: "RPT-002",
    name: "API Security Audit Export",
    format: "json",
    scope: "API Endpoints",
    target: "api.acmecorp.com",
    generatedAt: "2024-12-14T09:15:00Z",
    size: "856 KB",
    status: "completed",
    findings: { critical: 1, high: 5, medium: 8, low: 4 },
  },
  {
    id: "RPT-003",
    name: "Vulnerability Data Export",
    format: "csv",
    scope: "All Findings",
    target: "*.acmecorp.com",
    generatedAt: "2024-12-13T16:45:00Z",
    size: "1.1 MB",
    status: "completed",
    findings: { critical: 4, high: 17, medium: 32, low: 22 },
  },
  {
    id: "RPT-004",
    name: "Executive Summary Report",
    format: "pdf",
    scope: "High-Level Overview",
    target: "acmecorp.com",
    generatedAt: "2024-12-12T11:00:00Z",
    size: "945 KB",
    status: "completed",
    findings: { critical: 3, high: 12, medium: 24, low: 18 },
  },
  {
    id: "RPT-005",
    name: "Compliance Export (SOC2)",
    format: "pdf",
    scope: "Compliance Mapping",
    target: "acmecorp.com",
    generatedAt: "2024-12-10T08:30:00Z",
    size: "3.2 MB",
    status: "completed",
    findings: { critical: 2, high: 8, medium: 15, low: 10 },
  },
  {
    id: "RPT-006",
    name: "Weekly Scan Summary",
    format: "json",
    scope: "Weekly Delta",
    target: "*.acmecorp.com",
    generatedAt: "2024-12-09T12:00:00Z",
    size: "234 KB",
    status: "completed",
    findings: { critical: 0, high: 2, medium: 6, low: 3 },
  },
]

const formatConfig = {
  pdf: {
    icon: FileText,
    label: "PDF",
    bgClass: "bg-critical/10",
    textClass: "text-critical",
  },
  json: {
    icon: FileJson,
    label: "JSON",
    bgClass: "bg-primary/10",
    textClass: "text-primary",
  },
  csv: {
    icon: FileSpreadsheet,
    label: "CSV",
    bgClass: "bg-low/10",
    textClass: "text-low",
  },
}

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

export default function ReportsPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [formatFilter, setFormatFilter] = useState<string>("all")

  const filteredReports = REPORTS.filter((report) => {
    const matchesSearch =
      report.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      report.target.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesFormat = formatFilter === "all" || report.format === formatFilter
    return matchesSearch && matchesFormat
  })

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Reports" />

        <main className="p-6">
          {/* Header */}
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Reports & Exports</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Generate and download security assessment reports
              </p>
            </div>
            <button className="flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90 hover:shadow-lg hover:shadow-primary/20">
              <Plus className="h-4 w-4" />
              Generate Report
            </button>
          </div>

          {/* Stats Row */}
          <div className="mb-6 grid grid-cols-4 gap-4">
            {[
              { icon: FileText, label: "Total Reports", value: REPORTS.length, color: "text-foreground" },
              { icon: Calendar, label: "This Month", value: REPORTS.filter(r => new Date(r.generatedAt).getMonth() === 11).length, color: "text-primary" },
              { icon: CheckCircle, label: "Completed", value: REPORTS.filter(r => r.status === "completed").length, color: "text-low" },
              { icon: Target, label: "Unique Targets", value: [...new Set(REPORTS.map(r => r.target))].length, color: "text-high" },
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

          {/* Filter/Action Bar */}
          <div className="mb-6 flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-10 w-full rounded-md border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
              />
            </div>
            
            <div className="flex items-center gap-2">
              {["all", "pdf", "json", "csv"].map((format) => (
                <button
                  key={format}
                  onClick={() => setFormatFilter(format)}
                  className={cn(
                    "rounded-md px-3 py-2 text-sm font-medium transition-all",
                    formatFilter === format
                      ? "bg-primary text-primary-foreground"
                      : "border border-border text-muted-foreground hover:bg-elevated hover:text-foreground"
                  )}
                >
                  {format === "all" ? "All" : format.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Reports Table */}
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-elevated/50">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Report
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Format
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Scope / Target
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Findings
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Generated
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Size
                  </th>
                  <th className="w-10 px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredReports.map((report) => {
                  const format = formatConfig[report.format as keyof typeof formatConfig]
                  const FormatIcon = format.icon
                  const totalFindings = 
                    report.findings.critical + 
                    report.findings.high + 
                    report.findings.medium + 
                    report.findings.low

                  return (
                    <tr
                      key={report.id}
                      className="group transition-colors hover:bg-elevated/50"
                    >
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "flex h-10 w-10 items-center justify-center rounded-lg",
                            format.bgClass
                          )}>
                            <FormatIcon className={cn("h-5 w-5", format.textClass)} />
                          </div>
                          <div>
                            <span className="font-medium text-foreground group-hover:text-primary transition-colors">
                              {report.name}
                            </span>
                            <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                              {report.id}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className={cn(
                          "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium",
                          format.bgClass,
                          format.textClass
                        )}>
                          {format.label}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <div>
                          <span className="text-sm text-foreground">{report.scope}</span>
                          <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                            {report.target}
                          </p>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-1.5">
                          {report.findings.critical > 0 && (
                            <span className="rounded bg-critical/15 px-1.5 py-0.5 text-xs font-medium text-critical">
                              {report.findings.critical}
                            </span>
                          )}
                          {report.findings.high > 0 && (
                            <span className="rounded bg-high/15 px-1.5 py-0.5 text-xs font-medium text-high">
                              {report.findings.high}
                            </span>
                          )}
                          {report.findings.medium > 0 && (
                            <span className="rounded bg-medium/15 px-1.5 py-0.5 text-xs font-medium text-medium">
                              {report.findings.medium}
                            </span>
                          )}
                          {report.findings.low > 0 && (
                            <span className="rounded bg-low/15 px-1.5 py-0.5 text-xs font-medium text-low">
                              {report.findings.low}
                            </span>
                          )}
                          <span className="ml-1 text-xs text-muted-foreground">
                            ({totalFindings})
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Clock className="h-3.5 w-3.5" />
                          <div>
                            <span>{formatDate(report.generatedAt)}</span>
                            <span className="mx-1 text-border">|</span>
                            <span>{formatTime(report.generatedAt)}</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className="font-mono text-sm text-muted-foreground">
                          {report.size}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <button className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground opacity-0 transition-all hover:bg-primary/10 hover:text-primary group-hover:opacity-100">
                          <Download className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </main>
      </div>
    </div>
  )
}
