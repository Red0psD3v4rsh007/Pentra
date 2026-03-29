"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import {
  CheckCircle2,
  Copy,
  RefreshCw,
  Search,
  Terminal,
  Wrench,
  XCircle,
} from "lucide-react"

import { InteractiveTerminal } from "@/components/scans/interactive-terminal"
import { StatusBadge } from "@/components/ui/status-badge"
import { Spinner } from "@/components/ui/spinner"
import { useJobSession } from "@/hooks/use-scans"
import {
  formatExecutionClass,
  formatExecutionProvenance,
  formatPhase,
  formatPolicyState,
  formatRelativeTime,
  formatRuntimeStage,
  inferExecutionClass,
  isLiveRuntimeStage,
  type ApiJobSessionFrame,
  type ApiJobSessionResponse,
  type ApiToolExecutionLogEntry,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface TerminalPanelProps {
  scanId: string
  executionLogs: ApiToolExecutionLogEntry[]
  liveJobSessions: Record<string, ApiJobSessionResponse>
  isActive: boolean
  streamConnectionState?: "idle" | "connecting" | "open" | "fallback" | "closed"
  isUsingPollingFallback?: boolean
}

type ConsoleMode = "replay" | "operator_shell"

function commandTextFor(entry: ApiToolExecutionLogEntry): string {
  if (entry.display_command.trim()) {
    return entry.display_command
  }
  if (entry.command.length) {
    return entry.command.join(" ")
  }
  if (entry.status === "failed") {
    return "Command log missing — failure happened before runtime persistence"
  }
  if (entry.status === "blocked") {
    return "Command not started — blocked before execution"
  }
  return "No executed command recorded"
}

function fallbackFramesForLog(entry: ApiToolExecutionLogEntry): ApiJobSessionFrame[] {
  const frames: ApiJobSessionFrame[] = []
  let chunkSeq = 0

  const commandText = commandTextFor(entry)
  if (commandText.trim()) {
    frames.push({
      channel: "command",
      chunk_seq: chunkSeq,
      chunk_text: commandText,
      timestamp: entry.started_at ?? entry.last_chunk_at ?? null,
      artifact_ref: entry.command_artifact_ref,
    })
    chunkSeq += 1
  }

  if (entry.stdout_preview.trim()) {
    frames.push({
      channel: "stdout",
      chunk_seq: chunkSeq,
      chunk_text: entry.stdout_preview,
      timestamp: entry.last_chunk_at ?? entry.completed_at ?? entry.started_at ?? null,
      artifact_ref: entry.full_stdout_artifact_ref,
    })
    chunkSeq += 1
  }

  if (entry.stderr_preview.trim()) {
    frames.push({
      channel: "stderr",
      chunk_seq: chunkSeq,
      chunk_text: entry.stderr_preview,
      timestamp: entry.last_chunk_at ?? entry.completed_at ?? entry.started_at ?? null,
      artifact_ref: entry.full_stderr_artifact_ref,
    })
  }

  return frames
}

function deriveRuntimeStage(
  entry: ApiToolExecutionLogEntry | null | undefined
): ApiJobSessionResponse["runtime_stage"] {
  if (!entry) {
    return null
  }
  if (entry.runtime_stage) {
    return entry.runtime_stage
  }
  switch (entry.status) {
    case "completed":
    case "failed":
    case "blocked":
      return entry.status
    case "running":
      if (entry.stdout_preview.trim() || entry.stderr_preview.trim()) {
        return "streaming"
      }
      if (entry.display_command.trim() || entry.command.length) {
        return "command_resolved"
      }
      return "container_starting"
    case "queued":
    case "pending":
    case "scheduled":
    case "assigned":
      return "queued"
    default:
      return null
  }
}

function mergeSessionData(
  persisted: ApiJobSessionResponse | null,
  live: ApiJobSessionResponse | null,
  logEntry: ApiToolExecutionLogEntry | null
): ApiJobSessionResponse | null {
  if (!persisted && !live && !logEntry) {
    return null
  }

  const base = live ?? persisted
  const logFallbackFrames = logEntry ? fallbackFramesForLog(logEntry) : []
  const combined = new Map<string, ApiJobSessionFrame>()

  for (const frame of persisted?.frames ?? []) {
    combined.set(`${frame.channel}:${frame.chunk_seq}`, frame)
  }
  for (const frame of live?.frames ?? []) {
    combined.set(`${frame.channel}:${frame.chunk_seq}`, frame)
  }
  if (combined.size === 0) {
    for (const frame of logFallbackFrames) {
      combined.set(`${frame.channel}:${frame.chunk_seq}`, frame)
    }
  }

  const frames = [...combined.values()].sort((left, right) => left.chunk_seq - right.chunk_seq)
  const runtimeStage =
    live?.runtime_stage ??
    persisted?.runtime_stage ??
    deriveRuntimeStage(logEntry)

  return {
    scan_id: base?.scan_id ?? "",
    job_id: base?.job_id ?? logEntry?.job_id ?? "",
    node_id: base?.node_id ?? logEntry?.node_id ?? null,
    tool: base?.tool ?? logEntry?.tool ?? "unknown",
    status: base?.status ?? logEntry?.status ?? "queued",
    policy_state: base?.policy_state ?? logEntry?.policy_state ?? "auto_live",
    execution_provenance:
      live?.execution_provenance ??
      persisted?.execution_provenance ??
      logEntry?.execution_provenance ??
      null,
    execution_reason:
      live?.execution_reason ??
      persisted?.execution_reason ??
      logEntry?.execution_reason ??
      null,
    execution_class:
      live?.execution_class ??
      persisted?.execution_class ??
      logEntry?.execution_class ??
      inferExecutionClass(logEntry?.tool),
    runtime_stage: runtimeStage,
    last_chunk_at:
      live?.last_chunk_at ??
      persisted?.last_chunk_at ??
      logEntry?.last_chunk_at ??
      logEntry?.completed_at ??
      logEntry?.started_at ??
      null,
    stream_complete:
      live?.stream_complete ??
      persisted?.stream_complete ??
      logEntry?.stream_complete ??
      Boolean(runtimeStage && ["completed", "failed", "blocked"].includes(runtimeStage)),
    started_at: base?.started_at ?? logEntry?.started_at ?? null,
    completed_at: base?.completed_at ?? logEntry?.completed_at ?? null,
    exit_code: base?.exit_code ?? logEntry?.exit_code ?? null,
    command: base?.command ?? logEntry?.command ?? [],
    display_command:
      base?.display_command ??
      persisted?.display_command ??
      logEntry?.display_command ??
      commandTextFor(logEntry ?? ({} as ApiToolExecutionLogEntry)),
    tool_binary:
      base?.tool_binary ??
      logEntry?.tool_binary ??
      logEntry?.canonical_command?.tool_binary ??
      null,
    container_image:
      base?.container_image ??
      logEntry?.container_image ??
      logEntry?.canonical_command?.container_image ??
      null,
    entrypoint:
      base?.entrypoint ??
      logEntry?.entrypoint ??
      logEntry?.canonical_command?.entrypoint ??
      [],
    working_dir:
      base?.working_dir ??
      logEntry?.working_dir ??
      logEntry?.canonical_command?.working_dir ??
      null,
    canonical_command:
      base?.canonical_command ??
      logEntry?.canonical_command ??
      null,
    command_artifact_ref:
      base?.command_artifact_ref ??
      logEntry?.command_artifact_ref ??
      null,
    full_stdout_artifact_ref:
      base?.full_stdout_artifact_ref ??
      logEntry?.full_stdout_artifact_ref ??
      null,
    full_stderr_artifact_ref:
      base?.full_stderr_artifact_ref ??
      logEntry?.full_stderr_artifact_ref ??
      null,
    session_artifact_ref:
      base?.session_artifact_ref ??
      logEntry?.session_artifact_ref ??
      null,
    frames,
  }
}

function CopyButton({ text, title }: { text: string; title: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1500)
      }}
      className="rounded border border-border px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
      title={title}
    >
      {copied ? "Copied" : <Copy className="h-3 w-3" />}
    </button>
  )
}

function statusBadgeFor(entry: ApiToolExecutionLogEntry | null) {
  if (!entry) {
    return {
      icon: Wrench,
      className: "text-amber-400",
      label: "Queued",
    }
  }
  if (entry.status === "completed" || entry.exit_code === 0) {
    return {
      icon: CheckCircle2,
      className: "text-emerald-400",
      label: "Completed",
    }
  }
  if (entry.status === "failed") {
    return {
      icon: XCircle,
      className: "text-critical",
      label: `Failed${entry.exit_code != null ? ` (${entry.exit_code})` : ""}`,
    }
  }
  return {
    icon: Wrench,
    className: "text-amber-400",
    label: entry.status,
  }
}

function channelClass(channel: string) {
  switch (channel) {
    case "command":
      return "text-cyan-300"
    case "stderr":
      return "text-red-300"
    case "system":
      return "text-amber-300"
    default:
      return "text-zinc-100"
  }
}

function framePrefix(channel: string): string {
  switch (channel) {
    case "stderr":
      return "stderr> "
    case "system":
      return "sys> "
    default:
      return ""
  }
}

function stageTone(runtimeStage?: string | null): string {
  switch ((runtimeStage ?? "").trim().toLowerCase()) {
    case "streaming":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
    case "command_resolved":
      return "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
    case "container_starting":
      return "border-amber-500/30 bg-amber-500/10 text-amber-300"
    case "completed":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
    case "failed":
    case "blocked":
      return "border-red-500/30 bg-red-500/10 text-red-300"
    case "stalled":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300"
    default:
      return "border-border bg-background text-muted-foreground"
  }
}

function stagePriority(entry: ApiToolExecutionLogEntry): number {
  const runtimeStage = deriveRuntimeStage(entry)
  if (runtimeStage === "streaming") {
    return 0
  }
  if (runtimeStage === "command_resolved") {
    return 1
  }
  if (runtimeStage === "container_starting") {
    return 2
  }
  if (entry.status === "running") {
    return 3
  }
  if (entry.status === "queued" || entry.status === "scheduled" || entry.status === "pending" || entry.status === "assigned") {
    return 4
  }
  return 5
}

function entryTimestamp(entry: ApiToolExecutionLogEntry): string {
  return (
    entry.last_chunk_at ??
    entry.completed_at ??
    entry.started_at ??
    new Date().toISOString()
  )
}

export function TerminalPanel({
  scanId,
  executionLogs,
  liveJobSessions,
  isActive,
  streamConnectionState = "idle",
  isUsingPollingFallback = false,
}: TerminalPanelProps) {
  const [mode, setMode] = useState<ConsoleMode>("replay")
  const [selectedJobId, setSelectedJobId] = useState<string | undefined>(undefined)
  const [pinnedJobId, setPinnedJobId] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const outputRef = useRef<HTMLDivElement>(null)

  const orderedLogs = useMemo(
    () =>
      [...executionLogs].sort((left, right) => {
        const priorityGap = stagePriority(left) - stagePriority(right)
        if (priorityGap !== 0) {
          return priorityGap
        }
        return new Date(entryTimestamp(right)).getTime() - new Date(entryTimestamp(left)).getTime()
      }),
    [executionLogs]
  )

  useEffect(() => {
    const validJobIds = new Set(orderedLogs.map((entry) => entry.job_id).filter(Boolean))
    if (pinnedJobId && !validJobIds.has(pinnedJobId)) {
      setPinnedJobId(null)
    }
  }, [orderedLogs, pinnedJobId])

  useEffect(() => {
    if (pinnedJobId) {
      if (selectedJobId !== pinnedJobId) {
        setSelectedJobId(pinnedJobId)
      }
      return
    }

    const nextAutoFollowJob =
      orderedLogs.find((entry) => isLiveRuntimeStage(deriveRuntimeStage(entry)) && entry.job_id)?.job_id ??
      orderedLogs.find((entry) => entry.status === "running" && entry.job_id)?.job_id ??
      orderedLogs.find((entry) => entry.job_id)?.job_id ??
      undefined

    if (nextAutoFollowJob && selectedJobId !== nextAutoFollowJob) {
      setSelectedJobId(nextAutoFollowJob)
      return
    }

    if (!selectedJobId && orderedLogs[0]?.job_id) {
      setSelectedJobId(orderedLogs[0].job_id ?? undefined)
    }
  }, [orderedLogs, pinnedJobId, selectedJobId])

  const selectedLog = useMemo(
    () => orderedLogs.find((entry) => entry.job_id === selectedJobId) ?? orderedLogs[0] ?? null,
    [orderedLogs, selectedJobId]
  )

  const { session, isLoading, error, refresh } = useJobSession(scanId, selectedJobId)
  const liveSession = selectedJobId ? liveJobSessions[selectedJobId] ?? null : null
  const mergedSession = useMemo(
    () => mergeSessionData(session, liveSession, selectedLog),
    [liveSession, selectedLog, session]
  )

  const filteredFrames = useMemo(() => {
    if (!mergedSession) {
      return []
    }
    const query = search.trim().toLowerCase()
    if (!query) {
      return mergedSession.frames
    }
    return mergedSession.frames.filter((frame) => frame.chunk_text.toLowerCase().includes(query))
  }, [mergedSession, search])

  useEffect(() => {
    if (!outputRef.current || mode !== "replay" || search.trim()) {
      return
    }
    outputRef.current.scrollTop = outputRef.current.scrollHeight
  }, [filteredFrames, mode, search, selectedJobId])

  if (orderedLogs.length === 0) {
    return (
      <section className="rounded-xl border border-border bg-card p-6 text-sm text-muted-foreground">
        {isActive
          ? "Waiting for the first live command to resolve for this scan."
          : "Command sessions will appear here once tool jobs start executing."}
      </section>
    )
  }

  const selectedStatus = statusBadgeFor(selectedLog)
  const selectedRuntimeStage =
    mergedSession?.runtime_stage ??
    deriveRuntimeStage(selectedLog)
  const selectedCommand =
    mergedSession?.display_command?.trim() ||
    (selectedLog ? commandTextFor(selectedLog) : "")
  const liveStateLabel = isUsingPollingFallback
    ? "Polling fallback"
    : streamConnectionState === "open"
      ? "Live stream connected"
      : streamConnectionState === "connecting"
        ? "Connecting stream"
        : streamConnectionState === "closed"
          ? "Stream closed"
          : "Stream idle"

  return (
    <section className="grid gap-5 xl:grid-cols-[23rem_minmax(0,1fr)]">
      <div className="rounded-xl border border-border bg-card shadow-sm">
        <div className="border-b border-border px-4 py-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Live Job Rail</h3>
              <p className="mt-1 text-xs text-muted-foreground">
                Auto-follows the newest running command until you pin a job.
              </p>
            </div>
            <StatusBadge status="verified" label={`${orderedLogs.length} jobs`} />
          </div>
        </div>

        <div className="max-h-[52rem] space-y-2 overflow-auto p-3">
          {orderedLogs.map((entry) => {
            const active = entry.job_id === selectedJobId
            const runtimeStage = deriveRuntimeStage(entry)
            const isPinned = pinnedJobId != null && entry.job_id === pinnedJobId

            return (
              <button
                key={`${entry.job_id ?? entry.node_id}:${entry.tool}`}
                type="button"
                onClick={() => {
                  setMode("replay")
                  setSelectedJobId(entry.job_id ?? undefined)
                  setPinnedJobId(entry.job_id ?? null)
                }}
                className={cn(
                  "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                  active
                    ? "border-primary/50 bg-primary/10"
                    : "border-border bg-background hover:border-primary/30 hover:bg-elevated/60"
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate text-sm font-semibold text-foreground">{entry.tool}</p>
                      {isPinned ? (
                        <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-primary">
                          Pinned
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-[11px] text-muted-foreground">
                      {formatPhase(entry.phase_number)} · {formatRelativeTime(entryTimestamp(entry))}
                    </p>
                  </div>
                  <span
                    className={cn(
                      "rounded-full border px-2 py-1 text-[10px] uppercase tracking-wide",
                      stageTone(runtimeStage)
                    )}
                  >
                    {formatRuntimeStage(runtimeStage)}
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                  <span>{formatPolicyState(entry.policy_state)}</span>
                  <span>•</span>
                  <span>{formatExecutionClass(entry.execution_class)}</span>
                </div>
                <code className="mt-3 block rounded border border-border/70 bg-card px-2 py-2 text-[11px] text-foreground/80 whitespace-pre-wrap break-all">
                  {commandTextFor(entry)}
                </code>
              </button>
            )
          })}
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card shadow-sm">
        <div className="border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setMode("replay")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === "replay"
                    ? "bg-primary text-primary-foreground"
                    : "border border-border bg-background text-muted-foreground hover:text-foreground"
                )}
              >
                Command Console
              </button>
              <button
                type="button"
                onClick={() => setMode("operator_shell")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === "operator_shell"
                    ? "bg-primary text-primary-foreground"
                    : "border border-border bg-background text-muted-foreground hover:text-foreground"
                )}
              >
                Operator Shell
              </button>
            </div>

            {mode === "replay" ? (
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search this session"
                    className="h-9 rounded-lg border border-border bg-background pl-8 pr-3 text-xs text-foreground outline-none transition-colors focus:border-primary"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => void refresh()}
                  className="inline-flex h-9 items-center gap-2 rounded-lg border border-border px-3 text-xs font-medium text-foreground transition-colors hover:bg-background"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh
                </button>
                {pinnedJobId ? (
                  <button
                    type="button"
                    onClick={() => setPinnedJobId(null)}
                    className="inline-flex h-9 items-center rounded-lg border border-primary/30 bg-primary/10 px-3 text-xs font-medium text-primary transition-colors hover:bg-primary/20"
                  >
                    Resume Auto-follow
                  </button>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>

        {mode === "operator_shell" ? (
          <div className="p-4">
            <div className="mb-3 rounded-lg border border-border bg-background px-4 py-3 text-xs text-muted-foreground">
              This is operator shell access for manual commands. It is separate from the executed-job console.
            </div>
            <InteractiveTerminal scanId={scanId} />
          </div>
        ) : (
          <div className="space-y-4 p-5">
            <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_auto]">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status="verified" label={selectedLog?.tool ?? "Unknown"} />
                  <StatusBadge
                    status={isUsingPollingFallback ? "configured_but_fallback" : "configured_and_healthy"}
                    label={liveStateLabel}
                  />
                  <span className={cn("rounded-full border px-2 py-1 text-[11px]", stageTone(selectedRuntimeStage))}>
                    {formatRuntimeStage(selectedRuntimeStage)}
                  </span>
                  <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
                    {selectedLog ? formatPhase(selectedLog.phase_number) : "Unknown phase"}
                  </span>
                  <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
                    {selectedLog?.execution_provenance
                      ? formatExecutionProvenance(
                          selectedLog.execution_provenance as
                            | "live"
                            | "simulated"
                            | "blocked"
                            | "inferred"
                            | "derived"
                        )
                      : "Unknown"}
                  </span>
                  <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
                    {formatExecutionClass(selectedLog?.execution_class)}
                  </span>
                  <span className="rounded-full border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
                    {formatPolicyState(selectedLog?.policy_state)}
                  </span>
                  <span className={cn("inline-flex items-center gap-1 text-xs font-medium", selectedStatus.className)}>
                    <selectedStatus.icon className="h-3.5 w-3.5" />
                    {selectedStatus.label}
                  </span>
                </div>

                <div className="rounded-lg border border-border bg-background px-4 py-3">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Full Command</p>
                    <CopyButton text={selectedCommand} title="Copy full command" />
                  </div>
                  <pre className="text-xs leading-6 text-foreground whitespace-pre-wrap break-all">
                    {selectedCommand}
                  </pre>
                </div>
              </div>

              <div className="space-y-2 text-xs text-muted-foreground">
                <div className="rounded-lg border border-border bg-background px-3 py-3">
                  <p className="uppercase tracking-wide">Last Output</p>
                  <p className="mt-2 text-foreground">
                    {formatRelativeTime(
                      mergedSession?.last_chunk_at ??
                        selectedLog?.last_chunk_at ??
                        selectedLog?.completed_at ??
                        selectedLog?.started_at ??
                        new Date().toISOString()
                    )}
                  </p>
                </div>
                <div className="rounded-lg border border-border bg-background px-3 py-3">
                  <p className="uppercase tracking-wide">Reason</p>
                  <p className="mt-2 text-foreground">
                    {mergedSession?.execution_reason ??
                      selectedLog?.execution_reason ??
                      "No explicit runtime reason recorded."}
                  </p>
                </div>
              </div>
            </div>

            <div className="overflow-hidden rounded-xl border border-border bg-[#05070a] shadow-inner">
              <div className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0a0f16]/95 px-4 py-3 backdrop-blur">
                <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
                  <Terminal className="h-4 w-4 text-cyan-300" />
                  Live Command Console
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className={cn("rounded-full border px-2 py-1", stageTone(selectedRuntimeStage))}>
                    {formatRuntimeStage(selectedRuntimeStage)}
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-slate-300">
                    {liveStateLabel}
                  </span>
                </div>
              </div>

              <div
                ref={outputRef}
                className="max-h-[44rem] overflow-auto px-4 py-4 font-mono text-[12px] leading-6"
              >
                {isLoading && !mergedSession ? (
                  <div className="flex items-center gap-2 text-slate-300">
                    <Spinner className="h-4 w-4" />
                    Loading session...
                  </div>
                ) : filteredFrames.length > 0 ? (
                  filteredFrames.map((frame) => (
                    <div
                      key={`${frame.channel}:${frame.chunk_seq}`}
                      className={cn("whitespace-pre-wrap break-words", channelClass(frame.channel))}
                    >
                      {framePrefix(frame.channel)}
                      {frame.chunk_text}
                    </div>
                  ))
                ) : error ? (
                  <div className="rounded border border-critical/40 bg-critical/10 px-3 py-3 text-critical">
                    {error}
                  </div>
                ) : selectedRuntimeStage === "container_starting" ? (
                  <div className="text-slate-500">
                    Waiting for the container to start for {selectedLog?.tool ?? "this job"}...
                  </div>
                ) : selectedRuntimeStage === "command_resolved" ? (
                  <div className="text-slate-500">
                    Command resolved. Waiting for the first output chunk from {selectedLog?.tool ?? "this job"}...
                  </div>
                ) : selectedRuntimeStage === "blocked" ? (
                  <div className="text-red-300">
                    Job blocked: {mergedSession?.execution_reason ?? selectedLog?.execution_reason ?? "No explicit reason recorded."}
                  </div>
                ) : selectedRuntimeStage === "failed" ? (
                  <div className="text-red-300">
                    Job failed before live output was captured.
                  </div>
                ) : search.trim() ? (
                  <div className="text-slate-500">No session frames matched the current filter.</div>
                ) : (
                  <div className="text-slate-500">Select a job to inspect its live or replayed command session.</div>
                )}
              </div>

              <div className="border-t border-white/10 bg-[#0a0f16]/90 px-4 py-3 text-[11px] text-slate-300">
                <div className="flex flex-wrap items-center gap-3">
                  <span>Runtime: {formatRuntimeStage(selectedRuntimeStage)}</span>
                  <span>
                    Output complete: {mergedSession?.stream_complete ?? selectedLog?.stream_complete ? "yes" : "no"}
                  </span>
                  {mergedSession?.exit_code != null || selectedLog?.exit_code != null ? (
                    <span>Exit code: {mergedSession?.exit_code ?? selectedLog?.exit_code}</span>
                  ) : null}
                  {selectedLog?.container_image ? <span>Image: {selectedLog.container_image}</span> : null}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
