"use client"

import { useState } from "react"
import { Check, Copy, FileJson, FileText } from "lucide-react"

import { type ApiScanReport } from "@/lib/scans-store"

interface ReportTabProps {
  report: ApiScanReport | null
}

export function ReportTab({ report }: ReportTabProps) {
  const [copied, setCopied] = useState<"markdown" | "json" | null>(null)

  async function copyValue(value: string, kind: "markdown" | "json") {
    await navigator.clipboard.writeText(value)
    setCopied(kind)
    window.setTimeout(() => setCopied(null), 1500)
  }

  if (!report) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-10 text-center shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">Report Pending</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Reports are generated from persisted findings and will appear here once scan evidence lands.
        </p>
      </div>
    )
  }

  const counts = report.severity_counts ?? {}

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-sm">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Generated Scan Report</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Built from persisted scan findings on {new Date(report.generated_at).toLocaleString()}.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => copyValue(report.markdown, "markdown")}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            {copied === "markdown" ? <Check className="h-4 w-4" /> : <FileText className="h-4 w-4" />}
            Copy Markdown
          </button>
          <button
            type="button"
            onClick={() => copyValue(JSON.stringify(report, null, 2), "json")}
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground hover:bg-elevated"
          >
            {copied === "json" ? <Check className="h-4 w-4 text-low" /> : <FileJson className="h-4 w-4" />}
            Copy JSON
          </button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-4">
        <SummaryCard label="Critical" value={Number(counts.critical ?? 0)} className="text-critical" />
        <SummaryCard label="High" value={Number(counts.high ?? 0)} className="text-high" />
        <SummaryCard label="Medium" value={Number(counts.medium ?? 0)} className="text-medium" />
        <SummaryCard label="Evidence" value={report.evidence_count} className="text-primary" />
      </div>

      <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-foreground">Executive Summary</h3>
        <p className="mt-3 text-sm leading-7 text-muted-foreground">{report.executive_summary}</p>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-foreground">Top Findings</h3>
          <div className="mt-4 space-y-4">
            {report.top_findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings available for this report.</p>
            ) : (
              report.top_findings.map((finding) => (
                <div key={finding.id} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-sm font-semibold text-foreground">{finding.title}</h4>
                    <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
                      {finding.severity}
                      {finding.cvss_score != null ? ` · CVSS ${finding.cvss_score}` : ""}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    {finding.description ?? "No description provided."}
                  </p>
                  {finding.remediation ? (
                    <p className="mt-3 text-sm text-foreground">
                      <span className="font-medium">Remediation:</span> {finding.remediation}
                    </p>
                  ) : null}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-foreground">Markdown Preview</h3>
          <pre className="mt-4 max-h-[520px] overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-background p-4 font-mono text-xs text-foreground">
            {report.markdown}
          </pre>
        </div>
      </div>
    </div>
  )
}

function SummaryCard({
  label,
  value,
  className,
}: {
  label: string
  value: number
  className: string
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-2 text-3xl font-semibold ${className}`}>{value}</p>
    </div>
  )
}
