"use client"

import { useMemo, useState } from "react"
import { Bot, Brain, Copy, Gauge, Route, ShieldAlert, Sparkles } from "lucide-react"

import { StatusBadge } from "@/components/ui/status-badge"
import type {
  ApiAgentTranscriptEntry,
  ApiFieldValidationAssessment,
  ApiScanPlannerContext,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface PlannerTabProps {
  plannerContext: ApiScanPlannerContext | null
  transcript: ApiAgentTranscriptEntry[]
  fieldValidation?: ApiFieldValidationAssessment | null
}

type PlannerViewMode = "transcript" | "summary"
type TranscriptFilterMode = "agent" | "timeline" | "all"

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function stringList(value: unknown): string[] {
  return asArray(value)
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean)
}

function formatPackKey(value: string): string {
  return value
    .replace(/^p3a_/, "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}

function formatProfileKey(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value ?? {}, null, 2)
  } catch {
    return String(value ?? "")
  }
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : ""
}

function unfenceCodeBlock(value: string): string {
  const trimmed = value.trim()
  if (!trimmed.startsWith("```")) {
    return trimmed
  }

  const withoutOpeningFence = trimmed.replace(/^```[a-zA-Z0-9_-]*\s*/, "")
  return withoutOpeningFence.replace(/\s*```$/, "").trim()
}

function summarizeStructuredNarrative(value: unknown): string {
  const record = asRecord(value)
  const recommendedTools = asArray(record["recommended_tools"])
    .map(asRecord)
    .map((item) => stringValue(item["tool_id"]))
    .filter(Boolean)
  const endpointFocus = asArray(record["endpoint_focus"]).map(asRecord)
  const firstFocus = endpointFocus[0] ?? {}
  const focusTarget =
    stringValue(firstFocus["route_group"]) ||
    stringValue(firstFocus["target_url"]) ||
    stringValue(firstFocus["target"])
  const phaseDecision = stringValue(record["phase_decision"])
  const reason =
    stringValue(record["summary"]) ||
    stringValue(record["reason"]) ||
    stringValue(record["rationale"])

  const parts = [
    phaseDecision ? `Phase decision: ${phaseDecision}.` : "",
    recommendedTools.length ? `Suggested tools: ${recommendedTools.slice(0, 4).join(", ")}.` : "",
    focusTarget ? `Focus: ${focusTarget}.` : "",
    reason ? reason : "",
  ].filter(Boolean)

  return parts.join(" ").trim()
}

function summarizePlannerNarrative(value: unknown): string {
  const text = stringValue(value)
  if (!text) {
    return ""
  }

  const normalized = unfenceCodeBlock(text)
  if (normalized.startsWith("{") || normalized.startsWith("[")) {
    try {
      const parsed = JSON.parse(normalized)
      const summary = summarizeStructuredNarrative(parsed)
      if (summary) {
        return summary
      }
    } catch {
      // Fall through to plain-text normalization.
    }
    return ""
  }

  return normalized.replace(/\s+/g, " ").trim()
}

function fallbackBadgeStatus(value: ApiAgentTranscriptEntry["fallback_status"]): string {
  switch (value) {
    case "healthy":
      return "configured_and_healthy"
    case "deterministic":
    case "fallback":
      return "configured_but_fallback"
    case "error":
      return "provider_unreachable"
    default:
      return "validating"
  }
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof Brain
  label: string
  value: string
  detail: string
}) {
  return (
    <div className="rounded-lg border border-border bg-background p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5 text-primary" />
        {label}
      </div>
      <p className="mt-3 text-sm font-semibold text-foreground">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
    </div>
  )
}

function TranscriptEntryCard({ entry }: { entry: ApiAgentTranscriptEntry }) {
  const [expanded, setExpanded] = useState(false)
  const payloadText = useMemo(() => prettyJson(entry.raw_payload), [entry.raw_payload])

  return (
    <article className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={fallbackBadgeStatus(entry.fallback_status)} label={entry.kind.replaceAll("_", " ")} />
            {entry.pack_key ? (
              <StatusBadge status="verified" label={formatPackKey(entry.pack_key)} />
            ) : null}
          </div>
          <h4 className="text-sm font-semibold text-foreground">{entry.summary || "Advisory artifact"}</h4>
          <p className="text-xs text-muted-foreground">
            {new Date(entry.timestamp).toLocaleString()}
            {entry.provider || entry.model || entry.transport
              ? ` · ${[entry.provider, entry.model, entry.transport].filter(Boolean).join(" / ")}`
              : ""}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {entry.artifact_ref ? (
            <code className="rounded bg-background px-2 py-1 text-[11px] text-muted-foreground">
              {entry.artifact_ref}
            </code>
          ) : null}
          <button
            type="button"
            onClick={() => void navigator.clipboard.writeText(payloadText)}
            className="inline-flex h-8 w-8 items-center justify-center rounded border border-border text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
            title="Copy raw payload"
          >
            <Copy className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-border bg-background">
        <button
          type="button"
          onClick={() => setExpanded((current) => !current)}
          className="flex w-full items-center justify-between px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          <span>Raw Payload</span>
          <span>{expanded ? "Collapse" : "Expand"}</span>
        </button>
        {expanded ? (
          <pre className="max-h-[32rem] overflow-auto border-t border-border px-4 py-4 text-xs leading-6 text-foreground whitespace-pre-wrap break-words">
            {payloadText}
          </pre>
        ) : (
          <div className="border-t border-border px-4 py-3 text-xs text-muted-foreground">
            Full payload is preserved. Expand to inspect the complete message without clipping.
          </div>
        )}
      </div>
    </article>
  )
}

export function PlannerTab({ plannerContext, transcript, fieldValidation }: PlannerTabProps) {
  const [viewMode, setViewMode] = useState<PlannerViewMode>("transcript")
  const [transcriptFilter, setTranscriptFilter] = useState<TranscriptFilterMode>("agent")

  const targetProfiles = [...(plannerContext?.target_profile_hypotheses ?? [])].sort(
    (left, right) => right.confidence - left.confidence
  )
  const capabilityPressures = [...(plannerContext?.capability_pressures ?? [])].sort(
    (left, right) => right.pressure_score - left.pressure_score
  )
  const topProfile = targetProfiles[0] ?? null
  const activePressure = capabilityPressures[0] ?? null
  const strategicPlan = asRecord(plannerContext?.strategic_plan)
  const tacticalPlan = asRecord(plannerContext?.tactical_plan)
  const plannerEffect = asRecord(plannerContext?.planner_effect)
  const plannerActions = asArray(strategicPlan["actions"]).map(asRecord)
  const suppressedTools = stringList(strategicPlan["suppressed_tool_ids"])
  const advisories = (plannerContext?.capability_advisories ?? []).map(asRecord)
  const activeAdvisory =
    advisories.find((item) => String(item["pack_key"] || "") === activePressure?.pack_key) ??
    advisories[0] ??
    {}
  const advisoryEvidenceGaps = stringList(activeAdvisory["evidence_gap_priorities"])
  const nextSuggestedStep =
    stringList(activeAdvisory["parameter_hypotheses"])[0] ||
    advisoryEvidenceGaps[0] ||
    stringList(tacticalPlan["planned_followups"])[0] ||
    stringList(plannerEffect["recommended_tool_ids"])[0] ||
    "Review the top planner action and its blocking evidence gaps."
  const transcriptEntries = useMemo(() => {
    const ordered = [...transcript].sort(
      (left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    )
    if (transcriptFilter === "all") {
      return ordered
    }
    return ordered.filter((entry) =>
      transcriptFilter === "timeline"
        ? entry.kind === "timeline_event"
        : entry.kind !== "timeline_event"
    )
  }, [transcript, transcriptFilter])
  const agentEntryCount = transcript.filter((entry) => entry.kind !== "timeline_event").length
  const timelineEntryCount = transcript.filter((entry) => entry.kind === "timeline_event").length
  const latestAgentEntry = [...transcriptEntries].find((entry) => entry.kind !== "timeline_event") ?? null
  const aiRuntimeValue =
    [fieldValidation?.ai_provider, fieldValidation?.ai_model].filter(Boolean).join(" / ") ||
    [latestAgentEntry?.provider, latestAgentEntry?.model].filter(Boolean).join(" / ") ||
    "Unavailable"
  const aiRuntimeDetail =
    [fieldValidation?.ai_transport, latestAgentEntry?.transport, fieldValidation?.ai_policy_state]
      .filter(Boolean)
      .join(" · ") || "No persisted AI runtime metadata yet"
  const plannerNarrative =
    summarizePlannerNarrative(strategicPlan["rationale"]) ||
    summarizePlannerNarrative(plannerEffect["decision_rationale"]) ||
    latestAgentEntry?.summary ||
    "Operator-facing planner, advisory, and transcript artifacts are available."

  return (
    <div className="space-y-5">
      <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-primary">
              <Bot className="h-3.5 w-3.5" />
              Pentra Agent
            </div>
            <h3 className="text-lg font-semibold text-foreground">
              {String(strategicPlan["objective"] || plannerContext?.planner_decision || "Planner context ready")}
            </h3>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap break-words">{plannerNarrative}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setViewMode("transcript")}
              className={cn(
                "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                viewMode === "transcript"
                  ? "bg-primary text-primary-foreground"
                  : "border border-border bg-background text-muted-foreground hover:text-foreground"
              )}
            >
              Transcript
            </button>
            <button
              type="button"
              onClick={() => setViewMode("summary")}
              className={cn(
                "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                viewMode === "summary"
                  ? "bg-primary text-primary-foreground"
                  : "border border-border bg-background text-muted-foreground hover:text-foreground"
              )}
            >
              Summary
            </button>
          </div>
        </div>
      </section>

      {viewMode === "transcript" ? (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card p-4 shadow-sm">
            <div>
              <h4 className="text-sm font-semibold text-foreground">Agent Transcript</h4>
              <p className="mt-1 text-xs text-muted-foreground">
                Full persisted history for planner, AI strategy, advisory, and runtime events.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setTranscriptFilter("agent")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  transcriptFilter === "agent"
                    ? "bg-primary text-primary-foreground"
                    : "border border-border bg-background text-muted-foreground hover:text-foreground"
                )}
              >
                Agent Updates ({agentEntryCount})
              </button>
              <button
                type="button"
                onClick={() => setTranscriptFilter("timeline")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  transcriptFilter === "timeline"
                    ? "bg-primary text-primary-foreground"
                    : "border border-border bg-background text-muted-foreground hover:text-foreground"
                )}
              >
                Timeline ({timelineEntryCount})
              </button>
              <button
                type="button"
                onClick={() => setTranscriptFilter("all")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  transcriptFilter === "all"
                    ? "bg-primary text-primary-foreground"
                    : "border border-border bg-background text-muted-foreground hover:text-foreground"
                )}
              >
                Everything ({transcript.length})
              </button>
            </div>
          </div>

          {transcriptEntries.length === 0 ? (
            <div className="rounded-xl border border-border bg-card p-6 text-sm text-muted-foreground">
              {transcript.length === 0
                ? "No persisted transcript entries are available for this scan yet."
                : "No transcript entries matched the current filter."}
            </div>
          ) : (
            transcriptEntries.map((entry) => <TranscriptEntryCard key={entry.id} entry={entry} />)
          )}
        </section>
      ) : (
        <>
          <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <SummaryCard
                icon={Brain}
                label="Current Target Profile"
                value={topProfile ? formatProfileKey(topProfile.key) : "Unclassified"}
                detail={topProfile ? `${Math.round(topProfile.confidence * 100)}% confidence` : "Waiting for route/runtime evidence"}
              />
              <SummaryCard
                icon={Sparkles}
                label="Active Capability Pack"
                value={activePressure ? formatPackKey(activePressure.pack_key) : "Unassigned"}
                detail={activePressure ? `${activePressure.pressure_score} pressure` : "No pack pressure yet"}
              />
              <SummaryCard
                icon={Route}
                label="Next Recommended Review Step"
                value={nextSuggestedStep}
                detail={String(tacticalPlan["mutation_kind"] || plannerEffect["mutation_kind"] || "planner_followup")}
              />
              <SummaryCard
                icon={Bot}
                label="AI Runtime"
                value={aiRuntimeValue}
                detail={aiRuntimeDetail}
              />
            </div>
          </section>

          <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
            <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
              <div className="mb-4 flex items-center gap-2">
                <Gauge className="h-4 w-4 text-primary" />
                <h4 className="text-sm font-semibold text-foreground">Capability Pressure Ranking</h4>
              </div>
              <div className="space-y-3">
                {capabilityPressures.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No capability pressures have been recorded yet.</p>
                ) : (
                  capabilityPressures.map((pressure) => (
                    <div key={pressure.pack_key} className="rounded-lg border border-border bg-background p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-foreground">{formatPackKey(pressure.pack_key)}</p>
                          <p className="text-xs text-muted-foreground">
                            {pressure.target_profile ? formatProfileKey(pressure.target_profile) : "No dominant target profile"}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <StatusBadge status="verified" label={`Pressure ${pressure.pressure_score}`} />
                          <StatusBadge
                            status={pressure.advisory_ready ? "configured_and_healthy" : "configured_but_fallback"}
                            label={pressure.advisory_ready ? "Advisor Ready" : "Deterministic Only"}
                          />
                        </div>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {pressure.planner_action_keys.slice(0, 4).map((action) => (
                          <span key={action} className="rounded-full bg-primary/10 px-2.5 py-1 text-xs text-primary">
                            {action}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="space-y-5">
              <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-primary" />
                  <h4 className="text-sm font-semibold text-foreground">Chosen Planner Actions</h4>
                </div>
                <div className="space-y-3">
                  {plannerActions.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No planner actions were captured for this scan yet.</p>
                  ) : (
                    plannerActions.map((action, index) => (
                      <div key={`${String(action["action_type"] || "action")}-${index}`} className="rounded-lg border border-border bg-background p-4">
                        <p className="text-sm font-semibold text-foreground">
                          {String(action["objective"] || action["action_type"] || "Planner action")}
                        </p>
                        <p className="mt-2 text-xs text-muted-foreground">
                          {String(action["hypothesis"] || action["rationale"] || "")}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="rounded-xl border border-border bg-card p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-primary" />
                  <h4 className="text-sm font-semibold text-foreground">Suppressed Tools and Evidence Gaps</h4>
                </div>
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    {suppressedTools.length ? (
                      suppressedTools.map((tool) => (
                        <span key={tool} className="rounded-full bg-critical/10 px-2.5 py-1 text-xs text-critical">
                          {tool}
                        </span>
                      ))
                    ) : (
                      <span className="text-sm text-muted-foreground">No tools are currently suppressed.</span>
                    )}
                  </div>
                  <div className="space-y-2">
                    {advisoryEvidenceGaps.length ? (
                      advisoryEvidenceGaps.map((gap) => (
                        <div key={gap} className="rounded-md border border-border bg-background px-3 py-2 text-sm text-muted-foreground">
                          {gap}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-muted-foreground">No explicit evidence gaps were recorded in the active advisory.</p>
                    )}
                  </div>
                </div>
              </section>
            </section>
          </div>
        </>
      )}
    </div>
  )
}
