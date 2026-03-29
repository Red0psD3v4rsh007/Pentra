"use client"

import { useState, type ReactNode } from "react"
import { Check, Copy, Download, FileCode2, FileJson, FileSpreadsheet, FileText, RotateCcw } from "lucide-react"

import { AIAdvisoryPanel } from "@/components/scans/ai-advisory-panel"
import {
  downloadScanReportExport,
  type AiAdvisoryMode,
  type ApiScanAiReasoning,
  type ApiScanReport,
  type ReportExportFormat,
} from "@/lib/scans-store"

interface ReportTabProps {
  scanId: string
  report: ApiScanReport | null
  advisory: ApiScanAiReasoning | null
  advisoryMode: AiAdvisoryMode
  onChangeAdvisoryMode: (mode: AiAdvisoryMode) => void
  onRegenerateAdvisory: () => void
  isRegeneratingAdvisory: boolean
  isLaunchingRetest: boolean
  onLaunchRetest: () => Promise<void>
}

export function ReportTab({
  scanId,
  report,
  advisory,
  advisoryMode,
  onChangeAdvisoryMode,
  onRegenerateAdvisory,
  isRegeneratingAdvisory,
  isLaunchingRetest,
  onLaunchRetest,
}: ReportTabProps) {
  const [copied, setCopied] = useState<"markdown" | "json" | null>(null)
  const [isDownloading, setIsDownloading] = useState<ReportExportFormat | null>(null)

  async function copyValue(value: string, kind: "markdown" | "json") {
    await navigator.clipboard.writeText(value)
    setCopied(kind)
    window.setTimeout(() => setCopied(null), 1500)
  }

  async function downloadReport(format: ReportExportFormat) {
    setIsDownloading(format)
    try {
      await downloadScanReportExport(scanId, format)
    } finally {
      setIsDownloading(null)
    }
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
  const verificationCounts = report.verification_counts ?? {}
  const verificationPipeline = report.verification_pipeline
  const pipelineOverall = verificationPipeline?.overall ?? {
    total_findings: 0,
    verified: 0,
    reproduced: 0,
    queued: 0,
    needs_evidence: 0,
    rejected: 0,
    expired: 0,
    verified_share: 0,
    proof_ready_share: 0,
  }
  const executionSummary = report.execution_summary ?? {}
  const comparison = report.comparison
  const exportFormats = report.export_formats?.length ? report.export_formats : ["markdown", "json", "csv", "html"]

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-sm">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Generated Scan Report</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Built from persisted findings on {new Date(report.generated_at).toLocaleString()}.
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
          {exportFormats.includes("markdown") ? (
            <ActionButton
              icon={<Download className="h-4 w-4" />}
              label={isDownloading === "markdown" ? "Downloading..." : "Download MD"}
              onClick={() => downloadReport("markdown")}
              disabled={isDownloading !== null}
            />
          ) : null}
          {exportFormats.includes("json") ? (
            <ActionButton
              icon={<FileJson className="h-4 w-4" />}
              label={isDownloading === "json" ? "Downloading..." : "Download JSON"}
              onClick={() => downloadReport("json")}
              disabled={isDownloading !== null}
            />
          ) : null}
          {exportFormats.includes("csv") ? (
            <ActionButton
              icon={<FileSpreadsheet className="h-4 w-4" />}
              label={isDownloading === "csv" ? "Downloading..." : "Download CSV"}
              onClick={() => downloadReport("csv")}
              disabled={isDownloading !== null}
            />
          ) : null}
          {exportFormats.includes("html") ? (
            <ActionButton
              icon={<FileCode2 className="h-4 w-4" />}
              label={isDownloading === "html" ? "Downloading..." : "Download HTML"}
              onClick={() => downloadReport("html")}
              disabled={isDownloading !== null}
            />
          ) : null}
          {report.retest?.eligible ? (
            <button
              type="button"
              onClick={() => void onLaunchRetest()}
              disabled={isLaunchingRetest}
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RotateCcw className="h-4 w-4" />
              {isLaunchingRetest ? "Launching Retest..." : "Launch Retest"}
            </button>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-7">
        <SummaryCard label="Critical" value={Number(counts.critical ?? 0)} className="text-critical" />
        <SummaryCard label="High" value={Number(counts.high ?? 0)} className="text-high" />
        <SummaryCard label="Verified" value={Number(verificationCounts.verified ?? 0)} className="text-low" />
        <SummaryCard label="Evidence" value={report.evidence_count} className="text-primary" />
        <SummaryCard label="Live" value={Number(executionSummary.live ?? 0)} className="text-low" />
        <SummaryCard label="Derived" value={Number(executionSummary.derived ?? 0)} className="text-primary" />
        <SummaryCard label="Blocked" value={Number(executionSummary.blocked ?? 0)} className="text-critical" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-foreground">Executive Summary</h3>
          <p className="mt-3 text-sm leading-7 text-muted-foreground">{report.executive_summary}</p>

          {report.narrative ? (
            <div className="mt-6 space-y-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Attack Path Narrative
                </p>
                <p className="mt-2 text-sm leading-7 text-foreground">{report.narrative.summary}</p>
              </div>
              {report.narrative.impact ? (
                <div className="rounded-lg border border-border bg-background p-4">
                  <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Impact</p>
                  <p className="mt-2 text-sm leading-7 text-foreground">{report.narrative.impact}</p>
                </div>
              ) : null}
              {report.narrative.steps.length ? (
                <div className="space-y-3">
                  {report.narrative.steps.map((step) => (
                    <div key={`${step.step}-${step.description}`} className="rounded-lg border border-border bg-background p-4">
                      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Step {step.step} · {step.action}
                      </p>
                      <p className="mt-2 text-sm text-foreground">{step.description}</p>
                      <p className="mt-2 text-xs text-muted-foreground">
                        Target: {step.target} · Risk: {step.risk}
                      </p>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
        </section>

        <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-foreground">Asset & Retest</h3>
          <dl className="mt-4 space-y-3 text-sm">
            <div>
              <dt className="text-muted-foreground">Asset</dt>
              <dd className="mt-1 text-foreground">{report.asset.name}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Project</dt>
              <dd className="mt-1 text-foreground">{report.asset.project_name ?? "Unassigned"}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Target</dt>
              <dd className="mt-1 break-all text-foreground">{report.asset.target}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Retest Priority</dt>
              <dd className="mt-1 text-foreground">{report.retest?.recommended_priority ?? "normal"}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Execution Truth</dt>
              <dd className="mt-1 text-foreground">
                Live {Number(executionSummary.live ?? 0)} · Simulated {Number(executionSummary.simulated ?? 0)} ·
                Derived {Number(executionSummary.derived ?? 0)} · Blocked {Number(executionSummary.blocked ?? 0)} ·
                Inferred {Number(executionSummary.inferred ?? 0)}
              </dd>
            </div>
          </dl>

          {comparison ? (
            <div className="mt-6 rounded-lg border border-border bg-background p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Historical Comparison
              </p>
              <p className="mt-2 text-sm leading-7 text-foreground">{comparison.summary}</p>
              <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                <MiniMetric label="New" value={Number(comparison.counts.new ?? 0)} />
                <MiniMetric label="Resolved" value={Number(comparison.counts.resolved ?? 0)} />
                <MiniMetric label="Persistent" value={Number(comparison.counts.persistent ?? 0)} />
                <MiniMetric label="Escalated" value={Number(comparison.counts.escalated ?? 0)} />
              </div>
            </div>
          ) : null}
        </section>
      </div>

      <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-foreground">Verification Pipeline</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Detection, reproduced proof, queued verification, and evidence gaps are separated here.
            </p>
          </div>
          <div className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
            Proof-ready share {Math.round(Number(pipelineOverall.proof_ready_share ?? 0) * 100)}%
          </div>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-3 xl:grid-cols-6">
          <MiniMetric label="Verified" value={Number(pipelineOverall.verified ?? 0)} />
          <MiniMetric label="Reproduced" value={Number(pipelineOverall.reproduced ?? 0)} />
          <MiniMetric label="Queued" value={Number(pipelineOverall.queued ?? 0)} />
          <MiniMetric label="Needs Evidence" value={Number(pipelineOverall.needs_evidence ?? 0)} />
          <MiniMetric label="Rejected" value={Number(pipelineOverall.rejected ?? 0)} />
          <MiniMetric label="Expired" value={Number(pipelineOverall.expired ?? 0)} />
        </div>

        <div className="mt-6 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.9fr)]">
          <div className="space-y-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Queue By Type
            </p>
            {verificationPipeline?.by_type?.length ? (
              verificationPipeline.by_type.map((item) => (
                <div key={item.vulnerability_type} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-foreground">{item.vulnerability_type}</p>
                    <span className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">
                      Proof-ready {Math.round(Number(item.proof_ready_share ?? 0) * 100)}%
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-3 gap-2 text-xs text-muted-foreground md:grid-cols-6">
                    <span>V {Number(item.verified ?? 0)}</span>
                    <span>R {Number(item.reproduced ?? 0)}</span>
                    <span>Q {Number(item.queued ?? 0)}</span>
                    <span>E {Number(item.needs_evidence ?? 0)}</span>
                    <span>X {Number(item.rejected ?? 0)}</span>
                    <span>EX {Number(item.expired ?? 0)}</span>
                  </div>
                </div>
              ))
            ) : (
              <p className="rounded-lg border border-dashed border-border bg-background p-4 text-sm text-muted-foreground">
                No verification pipeline breakdown is available for this report.
              </p>
            )}
          </div>

          <div className="space-y-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Verification Queue
            </p>
            {verificationPipeline?.queue?.length ? (
              verificationPipeline.queue.map((item) => (
                <div key={item.finding_id} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-foreground">{item.title}</p>
                    <span className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">
                      {item.queue_state}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">{item.readiness_reason}</p>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {item.severity} · {item.vulnerability_type} · {item.target}
                  </p>
                  {item.required_actions.length ? (
                    <div className="mt-3 space-y-2">
                      {item.required_actions.map((action) => (
                        <div key={action} className="rounded-md border border-border px-3 py-2 text-sm text-foreground">
                          {action}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))
            ) : (
              <p className="rounded-lg border border-dashed border-border bg-background p-4 text-sm text-muted-foreground">
                No verification queue items are pending.
              </p>
            )}
          </div>
        </div>
      </section>

      <AIAdvisoryPanel
        reasoning={advisory}
        title="Report Drafting Advisory"
        description="Clearly labeled AI assistance layered on top of persisted findings, graph, and report data."
        currentMode={advisoryMode}
        onChangeMode={onChangeAdvisoryMode}
        onRegenerate={onRegenerateAdvisory}
        isRegenerating={isRegeneratingAdvisory}
      >
        <div className="space-y-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Draft Summary
            </p>
            <p className="mt-2 text-sm leading-7 text-foreground">
              {advisory?.report.draft_summary}
            </p>
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Prioritization Notes
            </p>
            <p className="mt-2 text-sm leading-7 text-muted-foreground">
              {advisory?.report.prioritization_notes}
            </p>
          </div>
        </div>
      </AIAdvisoryPanel>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.9fr)]">
        <section className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-foreground">Remediation Plan</h3>
            <div className="mt-4 space-y-4">
              {report.remediation_plan.length === 0 ? (
                <p className="text-sm text-muted-foreground">No remediation plan items were generated.</p>
              ) : (
                report.remediation_plan.map((item) => (
                  <div key={item.plan_id} className="rounded-lg border border-border bg-background p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className="text-sm font-semibold text-foreground">{item.title}</h4>
                      <span className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">
                        {item.priority}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-muted-foreground">{item.rationale}</p>
                    <p className="mt-3 text-xs uppercase tracking-wide text-muted-foreground">
                      Owner Hint: {item.owner_hint}
                    </p>
                    <ul className="mt-3 space-y-2 text-sm text-foreground">
                      {item.actions.map((action) => (
                        <li key={action} className="rounded-md border border-border px-3 py-2">
                          {action}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-foreground">Grouped Findings</h3>
            <div className="mt-4 space-y-4">
              {report.finding_groups.length === 0 ? (
                <p className="text-sm text-muted-foreground">No grouped findings are available for this report.</p>
              ) : (
                report.finding_groups.map((group) => (
                  <div key={group.group_id} className="rounded-lg border border-border bg-background p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h4 className="text-sm font-semibold text-foreground">{group.title}</h4>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {group.surface.toUpperCase()} · {group.target}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2 text-xs">
                        <span className="rounded-md bg-critical/10 px-2 py-1 text-critical">
                          C {Number(group.severity_counts.critical ?? 0)}
                        </span>
                        <span className="rounded-md bg-high/10 px-2 py-1 text-high">
                          H {Number(group.severity_counts.high ?? 0)}
                        </span>
                        <span className="rounded-md bg-low/10 px-2 py-1 text-low">
                          V {Number(group.verification_counts.verified ?? 0)}
                        </span>
                      </div>
                    </div>
                    <div className="mt-4 space-y-3">
                      {group.findings.map((finding) => (
                        <div key={finding.id} className="rounded-md border border-border px-3 py-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="text-sm font-medium text-foreground">{finding.title}</p>
                            <div className="flex flex-wrap gap-2 text-xs">
                              <span className="rounded-md bg-muted px-2 py-1 text-muted-foreground">
                                {finding.severity}
                              </span>
                              {finding.verification_state ? (
                                <span className="rounded-md bg-low/10 px-2 py-1 text-low">
                                  {finding.verification_state}
                                </span>
                              ) : null}
                            </div>
                          </div>
                          {finding.description ? (
                            <p className="mt-2 text-sm text-muted-foreground">{finding.description}</p>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-foreground">Compliance Mapping</h3>
            <div className="mt-4 space-y-3">
              {report.compliance.length === 0 ? (
                <p className="text-sm text-muted-foreground">No compliance mappings were generated.</p>
              ) : (
                report.compliance.map((item) => (
                  <div key={item.vulnerability_type} className="rounded-lg border border-border bg-background p-4">
                    <p className="text-sm font-semibold text-foreground">{item.vulnerability_type}</p>
                    <p className="mt-2 text-xs text-muted-foreground">
                      OWASP: {item.owasp.join(", ") || "None"} · CWE: {item.cwe.join(", ") || "None"}
                    </p>
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
        </section>
      </div>
    </div>
  )
}

function ActionButton({
  icon,
  label,
  onClick,
  disabled,
}: {
  icon: ReactNode
  label: string
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
    >
      {icon}
      {label}
    </button>
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

function MiniMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border px-3 py-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-lg font-semibold text-foreground">{value}</p>
    </div>
  )
}
