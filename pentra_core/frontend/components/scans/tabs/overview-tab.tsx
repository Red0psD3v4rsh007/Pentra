"use client"

import type { ReactNode } from "react"
import { Shield, Target } from "lucide-react"
import { motion } from "framer-motion"

import {
  formatExecutionClass,
  formatPhase,
  formatPriority,
  formatRelativeTime,
  formatScanType,
  formatExecutionProvenance,
  formatExecutionReason,
  getExpectedPhases,
  inferExecutionClass,
  type ApiFieldValidationAssessment,
  type ApiFinding,
  type ApiScanJob,
  type ApiScanProfileContract,
  type ApiScanTargetModel,
  type ScanAsset,
  type ScanType,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface OverviewTabProps {
  scan: {
    scanType: ScanType
    progress: number
    status: "running" | "completed" | "failed" | "queued" | "cancelled"
    statusLabel: string
    priority: "critical" | "high" | "normal" | "low"
    startedAt: string
    completedAt: string
    createdAt: string
    target: string
    errorMessage: string | null
    executionContract: ApiScanProfileContract | null
    severity: {
      critical: number
      high: number
      medium: number
      low: number
    }
  }
  asset?: ScanAsset
  jobs: ApiScanJob[]
  findings: ApiFinding[]
  targetModel: ApiScanTargetModel | null
  fieldValidation: ApiFieldValidationAssessment | null
  onApproveTools?: (tools: string[]) => Promise<unknown>
  isApprovingTools?: boolean
  toolApprovalError?: string | null
}

function phaseState(phase: number, jobs: ApiScanJob[]) {
  const phaseJobs = jobs.filter((job) => job.phase === phase)
  if (phaseJobs.length === 0) {
    return "pending"
  }

  if (phaseJobs.every((job) => job.status === "completed" || job.status === "skipped" || job.status === "blocked")) {
    return "completed"
  }

  if (
    phaseJobs.some((job) =>
      ["running", "assigned", "scheduled", "queued", "pending"].includes(job.status)
    )
  ) {
    return "active"
  }

  if (phaseJobs.some((job) => job.status === "failed")) {
    return "failed"
  }

  return "pending"
}

export function OverviewTab({
  scan,
  asset,
  jobs,
  findings,
  targetModel,
  fieldValidation,
  onApproveTools,
  isApprovingTools = false,
  toolApprovalError = null,
}: OverviewTabProps) {
  const phases = getExpectedPhases(scan.scanType)
  const latestJobs = [...jobs]
    .sort((left, right) => {
      const leftTime = new Date(left.completed_at ?? left.started_at ?? left.created_at).getTime()
      const rightTime = new Date(right.completed_at ?? right.started_at ?? right.created_at).getTime()
      return rightTime - leftTime
    })
    .slice(0, 6)
  const highlightedFindings = findings
    .slice()
    .sort((left, right) => {
      const truthGap = truthWeight(right.truth_state) - truthWeight(left.truth_state)
      if (truthGap !== 0) {
        return truthGap
      }
      const severityWeight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
      const severityGap = severityWeight[right.severity] - severityWeight[left.severity]
      if (severityGap !== 0) {
        return severityGap
      }
      return right.confidence - left.confidence
    })
    .slice(0, 5)

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Pipeline Progress</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Real orchestrator jobs grouped by expected scan phases.
            </p>
          </div>
          <div className="rounded-full bg-muted px-3 py-1 text-xs font-medium text-muted-foreground">
            {scan.progress}% complete
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {phases.map((phaseNumber) => {
            const state = phaseState(phaseNumber, jobs)
            const phaseJobs = jobs.filter((job) => job.phase === phaseNumber)

            return (
              <div
                key={phaseNumber}
                className={cn(
                  "rounded-xl border p-4 transition-colors",
                  state === "completed" && "border-low/30 bg-low/5",
                  state === "active" && "border-primary/30 bg-primary/5",
                  state === "failed" && "border-critical/30 bg-critical/5",
                  state === "pending" && "border-border bg-background"
                )}
              >
                <div className="mb-4 flex items-center justify-between">
                  <span className="text-sm font-semibold text-foreground">
                    {formatPhase(phaseNumber)}
                  </span>
                  <span
                    className={cn(
                      "rounded-full px-2 py-1 text-[11px] font-medium uppercase tracking-wide",
                      state === "completed" && "bg-low/10 text-low",
                      state === "active" && "bg-primary/10 text-primary",
                      state === "failed" && "bg-critical/10 text-critical",
                      state === "pending" && "bg-muted text-muted-foreground"
                    )}
                  >
                    {state}
                  </span>
                </div>

                <div className="space-y-2 text-sm text-muted-foreground">
                  <div className="flex items-center justify-between">
                    <span>Jobs</span>
                    <span className="font-medium text-foreground">{phaseJobs.length}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Completed</span>
                    <span className="font-medium text-foreground">
                      {
                        phaseJobs.filter(
                          (job) => job.status === "completed" || job.status === "skipped"
                        ).length
                      }
                    </span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
        <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Recent Jobs</h2>
            <span className="text-xs text-muted-foreground">{jobs.length} total jobs</span>
          </div>

          {latestJobs.length === 0 ? (
            <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-dashed border-border bg-background text-sm text-muted-foreground">
              Jobs will appear here after the orchestrator expands the scan DAG.
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    <th className="px-4 py-3">Tool</th>
                    <th className="px-4 py-3">Phase</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {latestJobs.map((job) => (
                    <tr key={job.id} className="text-sm group">
                      <td className="px-4 py-3 font-medium text-foreground">{job.tool}</td>
                      <td className="px-4 py-3 text-muted-foreground">{formatPhase(job.phase)}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={cn(
                              "rounded-full px-2 py-1 text-xs font-medium capitalize",
                              job.status === "completed" && "bg-low/10 text-low",
                              job.status === "failed" && "bg-critical/10 text-critical",
                              job.status === "running" && "bg-primary/10 text-primary",
                              job.status === "blocked" && "bg-amber-100 text-amber-800",
                              ["pending", "queued", "scheduled", "assigned"].includes(job.status) &&
                                "bg-muted text-muted-foreground"
                            )}
                          >
                            {job.status}
                          </span>
                          {job.execution_provenance ? (
                            <span
                              title={formatExecutionReason(job.execution_reason)}
                              className={cn(
                                "rounded-full px-2 py-1 text-[11px] font-medium",
                              job.execution_provenance === "live" && "bg-low/10 text-low",
                              job.execution_provenance === "simulated" && "bg-amber-100 text-amber-800",
                              job.execution_provenance === "derived" && "bg-primary/10 text-primary",
                              job.execution_provenance === "blocked" && "bg-critical/10 text-critical",
                              job.execution_provenance === "inferred" && "bg-primary/10 text-primary"
                            )}
                            >
                              {formatExecutionProvenance(job.execution_provenance)}
                            </span>
                          ) : null}
                          <span className="rounded-full border border-border px-2 py-1 text-[11px] font-medium text-muted-foreground">
                            {formatExecutionClass(job.execution_class ?? inferExecutionClass(job.tool))}
                          </span>
                          {job.retry_count > 0 ? (
                            <span className="rounded-full bg-amber-500/10 px-2 py-1 text-[11px] font-medium text-amber-600" title={`Retried ${job.retry_count} time(s)`}>
                              ↻ {job.retry_count}
                            </span>
                          ) : null}
                        </div>
                        {(job.status === "failed" || job.status === "blocked") && job.error_message ? (
                          <p className="mt-1.5 text-xs text-critical/80 leading-relaxed">
                            {job.error_message}
                          </p>
                        ) : null}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {formatRelativeTime(job.completed_at ?? job.started_at ?? job.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div className="space-y-6">
          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Target Profile</h2>
            </div>

            <div className="space-y-3 text-sm">
              <MetaRow label="Asset">{asset?.name ?? "Resolving asset..."}</MetaRow>
              <MetaRow label="Target">{scan.target}</MetaRow>
              <MetaRow label="Project">{asset?.project?.name ?? "Unassigned"}</MetaRow>
              <MetaRow label="Scan Type">{formatScanType(scan.scanType)}</MetaRow>
              <MetaRow label="Priority">{formatPriority(scan.priority)}</MetaRow>
              <MetaRow label="Execution Lane">
                {formatExecutionLane(scan.executionContract?.execution_mode)}
              </MetaRow>
              <MetaRow label="Scope Policy">
                {formatScopePolicy(scan.executionContract?.target_policy)}
              </MetaRow>
              <MetaRow label="Started">{scan.startedAt ? formatRelativeTime(scan.startedAt) : "Waiting"}</MetaRow>
              <MetaRow label="Created">{formatRelativeTime(scan.createdAt)}</MetaRow>
              <MetaRow label="Finished">
                {scan.completedAt ? formatRelativeTime(scan.completedAt) : "In progress"}
              </MetaRow>
            </div>

            {scan.executionContract ? (
              <div className="mt-4 space-y-3 border-t border-border pt-4">
                <ToolSection label="Live Tools" tone="live" tools={scan.executionContract.live_tools} />
                {scan.executionContract.approval_required_tools.length > 0 ? (
                  <ToolSection
                    label="Approval Required"
                    tone="conditional"
                    tools={scan.executionContract.approval_required_tools}
                  />
                ) : null}
                {scan.executionContract.conditional_live_tools.length > 0 ? (
                  <ToolSection
                    label="Conditional Verification"
                    tone="conditional"
                    tools={scan.executionContract.conditional_live_tools}
                  />
                ) : null}
                {scan.executionContract.derived_tools.length > 0 ? (
                  <ToolSection
                    label="Derived Layers"
                    tone="derived"
                    tools={scan.executionContract.derived_tools}
                  />
                ) : null}
                {scan.executionContract.unsupported_tools.length > 0 ? (
                  <ToolSection
                    label="Not Included In This Live Profile"
                    tone="unsupported"
                    tools={scan.executionContract.unsupported_tools}
                  />
                ) : null}
              </div>
            ) : null}

            {scan.errorMessage ? (
              <div className="mt-4 rounded-lg border border-critical/30 bg-critical/5 p-3 text-sm text-critical">
                {scan.errorMessage}
              </div>
            ) : null}
          </section>

          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Field Validation</h2>
            </div>

            {fieldValidation ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <SummaryPill
                    label="Proof-ready"
                    value={fieldValidation.proof_ready_attempts}
                    tone="low"
                  />
                  <SummaryPill
                    label="Needs evidence"
                    value={fieldValidation.heuristic_only_attempts}
                    tone="medium"
                  />
                </div>

                <div className="mt-4 space-y-3 text-sm">
                  <MetaRow label="Operating Mode">
                    {fieldValidation.operating_mode.replaceAll("_", " ")}
                  </MetaRow>
                  <MetaRow label="Assessment State">
                    {fieldValidation.assessment_state.replaceAll("_", " ")}
                  </MetaRow>
                  <MetaRow label="Top Profile">
                    {fieldValidation.target_profile_guess
                      ? formatTargetProfileKey(fieldValidation.target_profile_guess)
                      : "Pending"}
                  </MetaRow>
                  <MetaRow label="Benchmark Inputs">
                    {fieldValidation.benchmark_inputs_disabled_confirmed ? "Disabled" : "Enabled"}
                  </MetaRow>
                  <MetaRow label="AI Policy">
                    {fieldValidation.ai_policy_state.replaceAll("_", " ")}
                  </MetaRow>
                  <MetaRow label="AI Runtime">
                    {[fieldValidation.ai_provider, fieldValidation.ai_model, fieldValidation.ai_transport]
                      .filter(Boolean)
                      .join(" / ") || "Pending"}
                  </MetaRow>
                </div>

                <div className="mt-4 rounded-lg border border-border bg-background px-4 py-3 text-sm text-muted-foreground">
                  {fieldValidation.summary}
                </div>

                {fieldValidation.selected_capability_packs.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Active Capability Packs
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {fieldValidation.selected_capability_packs.map((packKey) => (
                        <span
                          key={packKey}
                          className="rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-[11px] font-medium text-primary"
                        >
                          {packKey}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {fieldValidation.approved_live_tools.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Approved Live Tools
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {fieldValidation.approved_live_tools.map((tool) => (
                        <span
                          key={tool}
                          className="rounded-full border border-low/20 bg-low/10 px-2.5 py-1 text-[11px] font-medium text-low"
                        >
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {fieldValidation.approval_pending_tools.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Approval Pending
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {fieldValidation.approval_pending_tools.map((tool) => (
                        <button
                          key={tool}
                          type="button"
                          onClick={() => void onApproveTools?.([tool])}
                          disabled={!onApproveTools || isApprovingTools}
                          className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[11px] font-medium text-amber-700 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {isApprovingTools ? `Approving ${tool}...` : `Approve ${tool}`}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}

                {fieldValidation.blocked_tools.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Blocked Tools
                    </p>
                    <div className="mt-2 space-y-2">
                      {fieldValidation.blocked_tools.map((blocked) => (
                        <div
                          key={`${blocked.tool}:${blocked.reason}:${blocked.provenance}`}
                          className="rounded-lg border border-critical/20 bg-critical/5 px-3 py-2 text-xs text-critical"
                        >
                          {blocked.tool} · {blocked.reason || blocked.provenance || "blocked"}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {fieldValidation.evidence_gaps.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Evidence Gaps
                    </p>
                    <div className="mt-2 space-y-2">
                      {fieldValidation.evidence_gaps.map((gap) => (
                        <div
                          key={gap}
                          className="rounded-lg border border-dashed border-medium/30 bg-medium/5 px-3 py-2 text-xs text-medium"
                        >
                          {gap}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {toolApprovalError ? (
                  <div className="mt-4 rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">
                    {toolApprovalError}
                  </div>
                ) : null}
              </>
            ) : (
              <div className="rounded-lg border border-dashed border-border bg-background px-4 py-5 text-sm text-muted-foreground">
                This scan has no dedicated field-validation assessment yet.
              </div>
            )}
          </section>

          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Finding Summary</h2>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <SummaryPill label="Critical" value={scan.severity.critical} tone="critical" />
              <SummaryPill label="High" value={scan.severity.high} tone="high" />
              <SummaryPill label="Medium" value={scan.severity.medium} tone="medium" />
              <SummaryPill label="Low" value={scan.severity.low} tone="low" />
            </div>

            <div className="mt-5 space-y-2">
              {highlightedFindings.length === 0 ? (
                <div className="rounded-lg border border-dashed border-border bg-background px-4 py-5 text-sm text-muted-foreground">
                  No findings have been persisted for this scan yet. Jobs and artifacts are still
                  being tracked in real time.
                </div>
              ) : (
                highlightedFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="rounded-lg border border-border bg-background px-4 py-3"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <p className="text-sm font-medium text-foreground">{finding.title}</p>
                      <span
                        className={cn(
                          "rounded-full px-2 py-1 text-xs font-medium capitalize",
                          finding.severity === "critical" && "bg-critical/10 text-critical",
                          finding.severity === "high" && "bg-high/10 text-high",
                          finding.severity === "medium" && "bg-medium/10 text-medium",
                          finding.severity === "low" && "bg-low/10 text-low",
                          finding.severity === "info" && "bg-muted text-muted-foreground"
                        )}
                      >
                        {finding.severity}
                      </span>
                    </div>
                    <div className="mt-2 flex items-center gap-3 text-xs text-muted-foreground">
                      <span
                        className={cn(
                          "rounded-full px-2 py-1 font-medium capitalize",
                          finding.truth_state === "verified" && "bg-low/10 text-low",
                          finding.truth_state === "reproduced" && "bg-primary/10 text-primary",
                          finding.truth_state === "suspected" && "bg-medium/15 text-medium",
                          finding.truth_state === "observed" && "bg-muted text-muted-foreground",
                          finding.truth_state === "rejected" && "bg-critical/10 text-critical",
                          finding.truth_state === "expired" && "bg-amber-100 text-amber-800"
                        )}
                      >
                        {finding.truth_state}
                      </span>
                      <span className="h-1 w-1 rounded-full bg-border" />
                      <span>{finding.truth_summary.promoted ? "trusted" : "held back"}</span>
                      <span className="h-1 w-1 rounded-full bg-border" />
                      <span>Confidence {finding.confidence}%</span>
                      <span className="h-1 w-1 rounded-full bg-border" />
                      <span>{finding.tool_source}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Target Model Pulse</h2>
            </div>

            {targetModel ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <SummaryPill label="Routes" value={targetModel.overview.route_group_count} tone="medium" />
                  <SummaryPill
                    label="Auth Surfaces"
                    value={targetModel.overview.auth_surface_count}
                    tone="low"
                  />
                  <SummaryPill
                    label="Parameters"
                    value={targetModel.overview.parameter_count}
                    tone="high"
                  />
                  <SummaryPill
                    label="Workflows"
                    value={targetModel.overview.workflow_edge_count}
                    tone="medium"
                  />
                </div>

                <div className="mt-5 space-y-3">
                  {targetModel.planner_focus.slice(0, 3).map((focus) => (
                    <div key={focus.route_group} className="rounded-lg border border-border bg-background px-4 py-3">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-medium text-foreground">{focus.route_group}</p>
                        <span className="rounded-full bg-primary/10 px-2 py-1 text-[11px] font-medium text-primary">
                          focus {focus.focus_score}
                        </span>
                      </div>
                      <p className="mt-2 text-xs leading-5 text-muted-foreground">{focus.objective}</p>
                    </div>
                  ))}

                  {targetModel.planner_focus.length === 0 ? (
                    <div className="rounded-lg border border-dashed border-border bg-background px-4 py-5 text-sm text-muted-foreground">
                      No prioritized route groups yet. The target model exists, but pressure is still low.
                    </div>
                  ) : null}
                </div>
              </>
            ) : (
              <div className="rounded-lg border border-dashed border-border bg-background px-4 py-5 text-sm text-muted-foreground">
                The normalized target model has not been generated for this scan yet.
              </div>
            )}
          </section>
        </div>
      </div>
    </motion.div>
  )
}

function truthWeight(state: ApiFinding["truth_state"]): number {
  switch (state) {
    case "verified":
      return 6
    case "reproduced":
      return 5
    case "suspected":
      return 4
    case "observed":
      return 3
    case "expired":
      return 2
    case "rejected":
      return 1
    default:
      return 0
  }
}

function MetaRow({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium text-foreground">{children}</span>
    </div>
  )
}

function formatExecutionLane(mode?: string | null): string {
  switch (mode) {
    case "controlled_live_local":
      return "Controlled Live · Local"
    case "controlled_live_scoped":
      return "Controlled Live · Scoped"
    case "demo_simulated":
      return "Demo Simulated"
    default:
      return "Not declared"
  }
}

function formatTargetProfileKey(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ")
}

function formatScopePolicy(policy?: string | null): string {
  switch (policy) {
    case "local_only":
      return "Loopback/private targets only"
    case "in_scope":
      return "Declared in-scope hosts and domains only"
    default:
      return "Not declared"
  }
}

function ToolSection({
  label,
  tools,
  tone,
}: {
  label: string
  tools: string[]
  tone: "live" | "conditional" | "derived" | "unsupported"
}) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {tools.map((tool) => (
          <span
            key={`${label}:${tool}`}
            className={cn(
              "rounded-full border px-2.5 py-1 text-[11px] font-medium",
              tone === "live" && "border-low/20 bg-low/10 text-low",
              tone === "conditional" && "border-primary/20 bg-primary/10 text-primary",
              tone === "derived" && "border-border bg-background text-foreground",
              tone === "unsupported" && "border-critical/20 bg-critical/10 text-critical"
            )}
          >
            {tool}
          </span>
        ))}
      </div>
    </div>
  )
}

function SummaryPill({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: "critical" | "high" | "medium" | "low"
}) {
  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-3",
        tone === "critical" && "border-critical/30 bg-critical/5",
        tone === "high" && "border-high/30 bg-high/5",
        tone === "medium" && "border-medium/30 bg-medium/5",
        tone === "low" && "border-low/30 bg-low/5"
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span
          className={cn(
            "text-lg font-semibold",
            tone === "critical" && "text-critical",
            tone === "high" && "text-high",
            tone === "medium" && "text-medium",
            tone === "low" && "text-low"
          )}
        >
          {value}
        </span>
      </div>
    </div>
  )
}
