"use client"

import { StatusBadge } from "@/components/ui/status-badge"
import {
  formatExecutionClass,
  formatExecutionProvenance,
  formatPhase,
  formatPolicyState,
  formatRelativeTime,
  inferExecutionClass,
  type ApiScanJob,
  type ApiToolExecutionLogEntry,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface JobsTabProps {
  jobs: ApiScanJob[]
  toolLogs: ApiToolExecutionLogEntry[]
  onApproveTools?: (tools: string[]) => Promise<unknown>
  isApprovingTools?: boolean
  toolApprovalError?: string | null
}

function toolLogForJob(
  toolLogs: ApiToolExecutionLogEntry[],
  job: ApiScanJob
): ApiToolExecutionLogEntry | undefined {
  return toolLogs.find((entry) => entry.job_id === job.id || (job.node_id && entry.node_id === job.node_id))
}

export function JobsTab({
  jobs,
  toolLogs,
  onApproveTools,
  isApprovingTools = false,
  toolApprovalError = null,
}: JobsTabProps) {
  const orderedJobs = [...jobs].sort((left, right) => {
    const phaseGap = left.phase - right.phase
    if (phaseGap !== 0) {
      return phaseGap
    }
    const leftTime = new Date(left.completed_at ?? left.started_at ?? left.created_at).getTime()
    const rightTime = new Date(right.completed_at ?? right.started_at ?? right.created_at).getTime()
    return rightTime - leftTime
  })

  if (orderedJobs.length === 0) {
    return (
      <section className="rounded-xl border border-border bg-card p-6 text-sm text-muted-foreground">
        Jobs will appear here once the orchestrator expands and dispatches the scan DAG.
      </section>
    )
  }

  return (
    <section className="rounded-xl border border-border bg-card shadow-sm">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <h3 className="text-sm font-semibold text-foreground">Full Job Ledger</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Every scheduled, blocked, running, failed, and completed job for this scan.
          </p>
        </div>
        <StatusBadge status="verified" label={`${orderedJobs.length} jobs`} />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[1120px]">
          <thead className="border-b border-border bg-background/60 text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-4 py-3">Tool</th>
              <th className="px-4 py-3">Phase</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Execution</th>
              <th className="px-4 py-3">Policy</th>
              <th className="px-4 py-3">Reason</th>
              <th className="px-4 py-3">Command</th>
              <th className="px-4 py-3">Updated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {orderedJobs.map((job) => {
              const logEntry = toolLogForJob(toolLogs, job)
              const executionClass = job.execution_class ?? logEntry?.execution_class ?? inferExecutionClass(job.tool)
              const policyState = job.policy_state ?? logEntry?.policy_state
              const commandPreview = logEntry?.display_command?.trim()
                ? logEntry.display_command
                : logEntry?.command?.length
                  ? logEntry.command.join(" ")
                : job.status === "failed"
                  ? "Command log missing — failure happened before runtime persistence"
                  : job.status === "blocked"
                    ? "Command not started — blocked before execution"
                    : job.output_ref
                      ? "Output artifact captured"
                      : "No executed command recorded"
              const toolBinary = logEntry?.tool_binary ?? logEntry?.canonical_command?.tool_binary
              const containerImage = logEntry?.container_image ?? logEntry?.canonical_command?.container_image

              return (
                <tr key={job.id} className="align-top text-sm">
                  <td className="px-4 py-3">
                    <div className="space-y-1">
                      <p className="font-medium text-foreground">{job.tool}</p>
                      <p className="text-xs text-muted-foreground">
                        Job {job.id.slice(0, 8)}
                        {job.node_id ? ` · Node ${job.node_id.slice(0, 8)}` : ""}
                      </p>
                    </div>
                  </td>
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
                      {job.retry_count > 0 ? (
                        <span className="rounded-full bg-amber-500/10 px-2 py-1 text-[11px] font-medium text-amber-600">
                          retry {job.retry_count}
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      {job.execution_provenance ? (
                        <StatusBadge
                          status={
                            job.execution_provenance === "live"
                              ? "configured_and_healthy"
                              : job.execution_provenance === "blocked"
                                ? "provider_unreachable"
                                : "configured_but_fallback"
                          }
                          label={formatExecutionProvenance(job.execution_provenance)}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">Pending</span>
                      )}
                      <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] font-medium text-muted-foreground">
                        {formatExecutionClass(executionClass)}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] font-medium text-muted-foreground">
                      {formatPolicyState(policyState)}
                    </span>
                    {policyState === "approval_required" && onApproveTools ? (
                      <div className="mt-2">
                        <button
                          type="button"
                          onClick={() => void onApproveTools([job.tool])}
                          disabled={isApprovingTools}
                          className="rounded-md border border-primary/30 bg-primary/10 px-2.5 py-1 text-[11px] font-medium text-primary transition-colors hover:bg-primary/20 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {isApprovingTools ? "Approving..." : "Approve And Requeue"}
                        </button>
                      </div>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <div className="max-w-xs text-xs leading-5 text-muted-foreground">
                      {job.execution_reason || job.error_message || "No explicit reason recorded."}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <code className="block max-w-md whitespace-pre-wrap break-all rounded border border-border bg-background px-3 py-2 text-[11px] text-foreground/80">
                      {commandPreview}
                    </code>
                    {toolBinary || containerImage ? (
                      <p className="mt-2 max-w-md text-[11px] leading-5 text-muted-foreground">
                        {[toolBinary ? `binary ${toolBinary}` : null, containerImage ? `image ${containerImage}` : null]
                          .filter(Boolean)
                          .join(" · ")}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {formatRelativeTime(job.completed_at ?? job.started_at ?? job.created_at)}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {toolApprovalError ? (
        <div className="border-t border-border px-5 py-3 text-xs text-critical">{toolApprovalError}</div>
      ) : null}
    </section>
  )
}
