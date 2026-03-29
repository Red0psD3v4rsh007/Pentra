import { useCallback, useEffect, useRef, useState } from "react"

import {
  approveScanTools as approveScanToolsRequest,
  cancelScan as cancelScanRequest,
  createAsset as createAssetRequest,
  createProject as createProjectRequest,
  createRetestScan as createRetestScanRequest,
  DEFAULT_AI_ADVISORY_MODE,
  createScan as createScanRequest,
  formatExecutionClass,
  formatPolicyState,
  getAiProviderDiagnostics,
  getScanJobSession,
  getScanToolLogContent,
  getAuthRuntime,
  getCurrentUser,
  getAsset,
  getAssetHistory as getAssetHistoryRequest,
  getScanStatusMeta,
  getScanStreamUrl,
  getProject,
  getSystemStatus,
  getScanDetail,
  getScanAiReasoning,
  inferExecutionClass,
  isActiveScanStatus,
  listAssetHistoricalFindings as listAssetHistoricalFindingsRequest,
  listProjectAssets,
  listScanProfiles,
  listProjects,
  listScans,
  runScanProfilePreflight as runScanProfilePreflightRequest,
  type AiAdvisoryMode,
  type ApiAgentTranscriptEntry,
  type ApiAiProviderDiagnostics,
  type ApiAsset,
  type ApiAssetHistory,
  type ApiAuthRuntime,
  type ApiCurrentUser,
  type ApiFieldValidationAssessment,
  type ApiHistoricalFinding,
  type ApiJobSessionResponse,
  type ApiProject,
  type ApiScanProfileContract,
  type ApiScanProfilePreflightResponse,
  type ApiScanStreamEvent,
  type ApiSystemStatus,
  type ApiTimelineEvent,
  type ApiToolExecutionLogContentResponse,
  type ApiToolExecutionLogEntry,
  type ApiToolApprovalResponse,
  type CreateAssetInput,
  type CreateProjectInput,
  type CreateScanInput,
  type RawScanStatus,
  type Scan,
  type ScanAsset,
  type ScanDetail,
  type ScanProfilePreflightInput,
  clearStoredAuthTokens,
} from "@/lib/scans-store"
import { useNotificationStore } from "@/lib/notification-store"

const DEFAULT_POLL_INTERVAL_MS = 5000
const STREAM_REFRESH_DELAY_MS = 1500

const RAW_SCAN_STATUSES: RawScanStatus[] = [
  "queued",
  "priority_queued",
  "validating",
  "running",
  "partial_success",
  "paused",
  "analyzing",
  "ai_queued",
  "reporting",
  "completed",
  "failed",
  "rejected",
  "checkpointed",
  "cancelled",
]

function isRawScanStatus(value: string | null | undefined): value is RawScanStatus {
  return RAW_SCAN_STATUSES.includes((value ?? "") as RawScanStatus)
}

function streamEventToTimelineEvent(event: ApiScanStreamEvent): ApiTimelineEvent | null {
  const timestamp = event.timestamp ?? new Date().toISOString()
  switch (event.event_type) {
    case "scan.progress":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.progress ?? 0}`,
        timestamp,
        event_type: "system",
        title: "Progress updated",
        details: `Progress ${event.progress ?? 0}%${event.phase ? ` · ${event.phase}` : ""}`,
        status: null,
        phase: null,
        tool: null,
        job_id: null,
        node_id: null,
        artifact_ref: null,
      }
    case "scan.phase":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.phase_number ?? 0}:${event.phase_status ?? "unknown"}`,
        timestamp,
        event_type: "system",
        title: event.phase_name ? `${event.phase_name} ${event.phase_status ?? "updated"}` : "Phase updated",
        details: event.phase_number != null ? `Phase ${event.phase_number}` : null,
        status: event.phase_status ?? null,
        phase: event.phase_number ?? null,
        tool: null,
        job_id: null,
        node_id: null,
        artifact_ref: null,
      }
    case "scan.node":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.node_id ?? "node"}`,
        timestamp,
        event_type: "analysis",
        title: event.tool ? `${event.tool} ${event.status ?? "updated"}` : "Node updated",
        details: event.status ?? null,
        status: event.status ?? null,
        phase: null,
        tool: event.tool ?? null,
        job_id: null,
        node_id: event.node_id ?? null,
        artifact_ref: null,
      }
    case "scan.job":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.job_id ?? event.node_id ?? "job"}`,
        timestamp,
        event_type: "analysis",
        title: event.tool ? `${event.tool} ${event.status ?? "updated"}` : "Job updated",
        details:
          [
            event.execution_class ? formatExecutionClass(event.execution_class) : null,
            event.execution_provenance,
            event.execution_reason,
            event.status,
          ]
            .filter(Boolean)
            .join(" · ") || null,
        status: event.status ?? null,
        phase: event.phase_number ?? null,
        tool: event.tool ?? null,
        job_id: event.job_id ?? null,
        node_id: event.node_id ?? null,
        artifact_ref: event.artifact_ref ?? null,
      }
    case "scan.command":
      if (
        event.channel !== "command" &&
        !["completed", "failed", "blocked", "cancelled"].includes(event.status ?? "")
      ) {
        return null
      }
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.node_id ?? event.job_id ?? "command"}`,
        timestamp,
        event_type: "analysis",
        title: event.tool ? `${event.tool} command updated` : "Command updated",
        details:
          [
            event.execution_class ? formatExecutionClass(event.execution_class) : null,
            event.execution_provenance,
            event.execution_reason,
          ]
            .filter(Boolean)
            .join(" · ") || null,
        status: event.status ?? null,
        phase: event.phase_number ?? null,
        tool: event.tool ?? null,
        job_id: event.job_id ?? null,
        node_id: event.node_id ?? null,
        artifact_ref: event.artifact_ref ?? null,
      }
    case "scan.advisory":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.pack_key ?? "advisory"}`,
        timestamp,
        event_type: "analysis",
        title: event.pack_key ? `${event.pack_key} advisory updated` : "Advisory updated",
        details:
          [event.provider, event.model, event.transport, event.fallback_status]
            .filter(Boolean)
            .join(" · ") || null,
        status: event.status ?? null,
        phase: null,
        tool: null,
        job_id: null,
        node_id: null,
        artifact_ref: event.artifact_ref ?? null,
      }
    case "scan.status":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.new_status ?? event.status ?? "unknown"}`,
        timestamp,
        event_type: "system",
        title: "Scan status changed",
        details: [event.old_status, event.new_status].filter(Boolean).join(" -> ") || event.status || null,
        status: event.new_status ?? event.status ?? null,
        phase: null,
        tool: null,
        job_id: null,
        node_id: null,
        artifact_ref: null,
      }
    case "scan.finding":
      return {
        id: `stream:${event.event_type}:${timestamp}:${event.title ?? "finding"}`,
        timestamp,
        event_type: "vuln",
        title: event.title ?? "Finding persisted",
        details: [event.severity, event.tool].filter(Boolean).join(" · ") || null,
        status: null,
        phase: null,
        tool: event.tool ?? null,
        job_id: null,
        node_id: null,
        artifact_ref: null,
      }
    default:
      return null
  }
}

function appendTimelineEvent(
  timeline: ApiTimelineEvent[],
  event: ApiTimelineEvent | null
): ApiTimelineEvent[] {
  if (!event) {
    return timeline
  }
  if (timeline.some((item) => item.id === event.id)) {
    return timeline
  }
  return [...timeline, event].sort(
    (left, right) =>
      new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime()
  )
}

function mergeStreamFindingCounts(
  current: ScanDetail["scan"]["findings"],
  event: ApiScanStreamEvent
): ScanDetail["scan"]["findings"] {
  const severity = String(event.severity ?? "").toLowerCase()
  const count = Number(event.count ?? 1) || 1
  if (severity !== "critical" && severity !== "high" && severity !== "medium" && severity !== "low") {
    return current
  }
  return {
    ...current,
    [severity]: current[severity] + count,
  }
}

function mergeJobFromStream(
  jobs: ScanDetail["jobs"],
  event: ApiScanStreamEvent
): ScanDetail["jobs"] {
  if (event.event_type !== "scan.job") {
    return jobs
  }

  const jobId = event.job_id ?? null
  const nodeId = event.node_id ?? null
  const index = jobs.findIndex(
    (job) => (jobId && job.id === jobId) || (nodeId && job.node_id === nodeId)
  )

  if (index >= 0) {
    const next = [...jobs]
    const current = next[index]
    next[index] = {
      ...current,
      tool: event.tool ?? current.tool,
      status: (event.status as typeof current.status | undefined) ?? current.status,
      execution_provenance:
        (event.execution_provenance as typeof current.execution_provenance | undefined) ??
        current.execution_provenance,
      execution_reason: event.execution_reason ?? current.execution_reason,
      execution_class: event.execution_class ?? current.execution_class,
      policy_state:
        (event.policy_state as typeof current.policy_state | undefined) ?? current.policy_state,
      node_id: event.node_id ?? current.node_id,
      output_ref: event.artifact_ref ?? current.output_ref,
    }
    return next
  }

  if (!jobId) {
    return jobs
  }

  return [
    {
      id: jobId,
      scan_id: event.scan_id ?? "",
      node_id: nodeId,
      phase: event.phase_number ?? 0,
      tool: event.tool ?? "unknown",
      status: (event.status as ScanDetail["jobs"][number]["status"] | undefined) ?? "queued",
      priority: "normal",
      worker_id: null,
      scheduled_at: null,
      claimed_at: null,
      started_at: event.status === "running" ? event.timestamp ?? null : null,
      completed_at:
        event.status === "completed" || event.status === "failed" || event.status === "blocked"
          ? event.timestamp ?? null
          : null,
      error_message: null,
      retry_count: 0,
      queue_delay_seconds: null,
      claim_to_start_seconds: null,
      execution_duration_seconds: event.duration_ms ? event.duration_ms / 1000 : null,
      end_to_end_seconds: event.duration_ms ? event.duration_ms / 1000 : null,
      execution_mode: null,
      execution_provenance:
        (event.execution_provenance as ScanDetail["jobs"][number]["execution_provenance"] | undefined) ??
        null,
      execution_reason: event.execution_reason ?? null,
      execution_class: event.execution_class ?? inferExecutionClass(event.tool),
      policy_state:
        (event.policy_state as ScanDetail["jobs"][number]["policy_state"] | undefined) ?? null,
      output_ref: event.artifact_ref ?? null,
      created_at: event.timestamp ?? new Date().toISOString(),
    },
    ...jobs,
  ]
}

function mergeToolLogFromStream(
  toolLogs: ScanDetail["toolLogs"],
  event: ApiScanStreamEvent
): ScanDetail["toolLogs"] {
  if (event.event_type !== "scan.command" && event.event_type !== "scan.job") {
    return toolLogs
  }

  const nextEntry: ApiToolExecutionLogEntry = {
    node_id: event.node_id ?? `stream:${event.timestamp ?? Date.now()}`,
    tool: event.tool ?? "unknown",
    worker_family: "unknown",
    phase_number: event.phase_number ?? 0,
    phase_name: event.phase_name ?? event.phase ?? "Command",
    status: event.status ?? "running",
    job_id: event.job_id ?? null,
    job_status: event.status ?? null,
    started_at: event.timestamp ?? null,
    completed_at:
      event.status === "completed" || event.status === "failed" || event.status === "blocked"
        ? event.timestamp ?? null
        : null,
    duration_ms: event.duration_ms ?? 0,
    execution_mode: "unknown",
    execution_provenance: event.execution_provenance ?? "unknown",
    execution_reason: event.execution_reason ?? null,
    execution_class: event.execution_class ?? inferExecutionClass(event.tool),
    policy_state: event.policy_state ?? null,
    runtime_stage: event.runtime_stage ?? null,
    last_chunk_at: event.last_chunk_at ?? event.timestamp ?? null,
    stream_complete: Boolean(event.stream_complete),
    error_message: null,
    item_count: 0,
    finding_count: 0,
    storage_ref: event.artifact_ref ?? null,
    command: event.command ?? [],
    stdout_preview: event.stdout_preview ?? "",
    stderr_preview: event.stderr_preview ?? "",
    exit_code: event.exit_code ?? null,
    display_command: event.display_command ?? "",
    tool_binary: event.tool_binary ?? null,
    container_image: event.container_image ?? null,
    entrypoint: event.entrypoint ?? [],
    working_dir: event.working_dir ?? null,
    canonical_command:
      event.display_command || event.tool_binary || event.container_image
        ? {
            argv: event.command ?? [],
            display_command: event.display_command ?? "",
            tool_binary: event.tool_binary ?? null,
            container_image: event.container_image ?? null,
            entrypoint: event.entrypoint ?? [],
            working_dir: event.working_dir ?? null,
            channel: event.container_image ? "container" : "unknown",
            execution_class: event.execution_class ?? inferExecutionClass(event.tool),
            policy_state: event.policy_state ?? null,
          }
        : null,
    full_stdout_artifact_ref: event.full_stdout_artifact_ref ?? null,
    full_stderr_artifact_ref: event.full_stderr_artifact_ref ?? null,
    command_artifact_ref: event.command_artifact_ref ?? event.artifact_ref ?? null,
    session_artifact_ref: event.session_artifact_ref ?? null,
  }

  const index = toolLogs.findIndex(
    (entry) =>
      (event.node_id && entry.node_id === event.node_id) ||
      (event.job_id && entry.job_id === event.job_id)
  )
  if (index >= 0) {
    const next = [...toolLogs]
    const existing = next[index]
    const nextStdoutPreview =
      event.channel === "stdout" && event.chunk_text
        ? `${existing.stdout_preview}${event.chunk_text}`.slice(-5000)
        : event.stdout_preview ?? existing.stdout_preview
    const nextStderrPreview =
      event.channel === "stderr" && event.chunk_text
        ? `${existing.stderr_preview}${event.chunk_text}`.slice(-2000)
        : event.stderr_preview ?? existing.stderr_preview
    next[index] = {
      ...existing,
      ...nextEntry,
      storage_ref: existing.storage_ref ?? nextEntry.storage_ref,
      display_command:
        nextEntry.display_command ||
        (event.channel === "command" ? event.chunk_text ?? "" : "") ||
        existing.display_command,
      tool_binary: nextEntry.tool_binary ?? existing.tool_binary,
      container_image: nextEntry.container_image ?? existing.container_image,
      entrypoint: nextEntry.entrypoint.length ? nextEntry.entrypoint : existing.entrypoint,
      working_dir: nextEntry.working_dir ?? existing.working_dir,
      canonical_command: nextEntry.canonical_command ?? existing.canonical_command,
      stdout_preview: nextStdoutPreview,
      stderr_preview: nextStderrPreview,
      command_artifact_ref: existing.command_artifact_ref ?? nextEntry.command_artifact_ref,
      full_stdout_artifact_ref:
        existing.full_stdout_artifact_ref ??
        event.full_stdout_artifact_ref ??
        nextEntry.full_stdout_artifact_ref,
      full_stderr_artifact_ref:
        existing.full_stderr_artifact_ref ??
        event.full_stderr_artifact_ref ??
        nextEntry.full_stderr_artifact_ref,
      session_artifact_ref:
        existing.session_artifact_ref ??
        event.session_artifact_ref ??
        nextEntry.session_artifact_ref,
      runtime_stage:
        event.runtime_stage ??
        nextEntry.runtime_stage ??
        existing.runtime_stage,
      last_chunk_at:
        event.last_chunk_at ??
        (event.chunk_text ? event.timestamp ?? null : null) ??
        existing.last_chunk_at ??
        nextEntry.last_chunk_at,
      stream_complete:
        event.stream_complete ??
        existing.stream_complete ??
        nextEntry.stream_complete,
    }
    return next
  }

  return [...toolLogs, nextEntry]
}

function mergeLiveJobSessionsFromStream(
  liveJobSessions: ScanDetail["liveJobSessions"],
  event: ApiScanStreamEvent
): ScanDetail["liveJobSessions"] {
  if (event.event_type !== "scan.command" || !event.job_id) {
    return liveJobSessions
  }

  const existing = liveJobSessions[event.job_id]
  const nextFrames = [...(existing?.frames ?? [])]
  if (event.chunk_text) {
    const frameIndex = nextFrames.findIndex(
      (frame) =>
        frame.channel === (event.channel ?? "system") &&
        frame.chunk_seq === (event.chunk_seq ?? nextFrames.length)
    )
    const nextFrame = {
      channel: (event.channel ?? "system") as ApiJobSessionResponse["frames"][number]["channel"],
      chunk_seq: event.chunk_seq ?? nextFrames.length,
      chunk_text: event.chunk_text,
      timestamp: event.last_chunk_at ?? event.timestamp ?? null,
      artifact_ref: event.artifact_ref ?? null,
    }
    if (frameIndex >= 0) {
      nextFrames[frameIndex] = nextFrame
    } else {
      nextFrames.push(nextFrame)
    }
  }
  nextFrames.sort((left, right) => left.chunk_seq - right.chunk_seq)

  return {
    ...liveJobSessions,
    [event.job_id]: {
      scan_id: event.scan_id ?? existing?.scan_id ?? "",
      job_id: event.job_id,
      node_id: event.node_id ?? existing?.node_id ?? null,
      tool: event.tool ?? existing?.tool ?? "unknown",
      status: event.status ?? existing?.status ?? "running",
      policy_state: event.policy_state ?? existing?.policy_state ?? "auto_live",
      execution_provenance: event.execution_provenance ?? existing?.execution_provenance ?? null,
      execution_reason: event.execution_reason ?? existing?.execution_reason ?? null,
      execution_class: event.execution_class ?? existing?.execution_class ?? inferExecutionClass(event.tool),
      runtime_stage: event.runtime_stage ?? existing?.runtime_stage ?? null,
      last_chunk_at:
        event.last_chunk_at ??
        (event.chunk_text ? event.timestamp ?? null : null) ??
        existing?.last_chunk_at ??
        null,
      stream_complete: event.stream_complete ?? existing?.stream_complete ?? false,
      started_at: existing?.started_at ?? (event.status === "running" ? event.timestamp ?? null : null),
      completed_at:
        event.status === "completed" || event.status === "failed" || event.status === "blocked"
          ? event.timestamp ?? existing?.completed_at ?? null
          : existing?.completed_at ?? null,
      exit_code: event.exit_code ?? existing?.exit_code ?? null,
      command: event.command ?? existing?.command ?? [],
      display_command: event.display_command ?? existing?.display_command ?? "",
      tool_binary: event.tool_binary ?? existing?.tool_binary ?? null,
      container_image: event.container_image ?? existing?.container_image ?? null,
      entrypoint: event.entrypoint ?? existing?.entrypoint ?? [],
      working_dir: event.working_dir ?? existing?.working_dir ?? null,
      canonical_command:
        event.display_command || event.tool_binary || event.container_image || event.command?.length
          ? {
              argv: event.command ?? existing?.canonical_command?.argv ?? [],
              display_command:
                event.display_command ??
                existing?.canonical_command?.display_command ??
                existing?.display_command ??
                "",
              tool_binary: event.tool_binary ?? existing?.canonical_command?.tool_binary ?? null,
              container_image:
                event.container_image ?? existing?.canonical_command?.container_image ?? null,
              entrypoint: event.entrypoint ?? existing?.canonical_command?.entrypoint ?? [],
              working_dir: event.working_dir ?? existing?.canonical_command?.working_dir ?? null,
              channel:
                event.container_image || existing?.canonical_command?.container_image
                  ? "container"
                  : "unknown",
              execution_class:
                event.execution_class ??
                existing?.canonical_command?.execution_class ??
                inferExecutionClass(event.tool),
              policy_state:
                event.policy_state ??
                existing?.canonical_command?.policy_state ??
                existing?.policy_state ??
                null,
            }
          : existing?.canonical_command ?? null,
      command_artifact_ref: event.command_artifact_ref ?? existing?.command_artifact_ref ?? null,
      full_stdout_artifact_ref:
        event.full_stdout_artifact_ref ?? existing?.full_stdout_artifact_ref ?? null,
      full_stderr_artifact_ref:
        event.full_stderr_artifact_ref ?? existing?.full_stderr_artifact_ref ?? null,
      session_artifact_ref: event.session_artifact_ref ?? existing?.session_artifact_ref ?? null,
      frames: nextFrames,
    },
  }
}

function mergeTranscriptFromStream(
  transcript: ScanDetail["agentTranscript"],
  event: ApiScanStreamEvent
): ScanDetail["agentTranscript"] {
  if (event.event_type !== "scan.advisory") {
    return transcript
  }

  const entry: ApiAgentTranscriptEntry = {
    id: `stream:${event.event_type}:${event.pack_key ?? "advisory"}:${event.timestamp ?? Date.now()}`,
    timestamp: event.timestamp ?? new Date().toISOString(),
    kind: "capability_advisory",
    pack_key: event.pack_key ?? null,
    provider: event.provider ?? null,
    model: event.model ?? null,
    transport: event.transport ?? null,
    fallback_status:
      (event.fallback_status as ApiAgentTranscriptEntry["fallback_status"] | undefined) ?? "unknown",
    summary:
      String(event.summary?.summary || event.message || `${event.pack_key ?? "Capability"} advisory updated`).trim(),
    raw_payload: event.summary ?? null,
    artifact_ref: event.artifact_ref ?? null,
  }
  if (transcript.some((item) => item.id === entry.id)) {
    return transcript
  }
  return [...transcript, entry].sort(
    (left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime()
  )
}

function mergeScanDetailFromStream(
  detail: ScanDetail | null,
  event: ApiScanStreamEvent
): ScanDetail | null {
  if (!detail) {
    return detail
  }

  let nextScan = detail.scan
  if (event.event_type === "scan.progress" && typeof event.progress === "number") {
    nextScan = {
      ...nextScan,
      progress: Math.max(nextScan.progress, event.progress),
    }
  }

  if (event.event_type === "scan.status") {
    const nextRawStatus = event.new_status ?? event.status
    if (isRawScanStatus(nextRawStatus)) {
      const meta = getScanStatusMeta(nextRawStatus)
      nextScan = {
        ...nextScan,
        rawStatus: nextRawStatus,
        status: meta.status,
        statusLabel: meta.label,
        completedAt:
          nextRawStatus === "completed" ||
          nextRawStatus === "failed" ||
          nextRawStatus === "cancelled"
            ? event.timestamp ?? nextScan.completedAt
            : nextScan.completedAt,
      }
    }
  }

  if (event.event_type === "scan.finding") {
    nextScan = {
      ...nextScan,
      findings: mergeStreamFindingCounts(nextScan.findings, event),
    }
  }

  return {
    ...detail,
    scan: nextScan,
    jobs: mergeJobFromStream(detail.jobs, event),
    toolLogs: mergeToolLogFromStream(detail.toolLogs, event),
    liveJobSessions: mergeLiveJobSessionsFromStream(detail.liveJobSessions, event),
    agentTranscript: mergeTranscriptFromStream(detail.agentTranscript, event),
    isTerminal: !isActiveScanStatus(nextScan.rawStatus),
    timeline: appendTimelineEvent(detail.timeline, streamEventToTimelineEvent(event)),
  }
}

function shouldRefreshFromStreamEvent(event: ApiScanStreamEvent): boolean {
  if (
    event.event_type === "scan.finding" ||
    event.event_type === "scan.node" ||
    event.event_type === "scan.advisory"
  ) {
    return true
  }

  if (event.event_type === "scan.job") {
    return ["completed", "failed", "blocked", "cancelled"].includes(event.status ?? "")
  }

  if (event.event_type === "scan.command") {
    return ["completed", "failed", "blocked", "cancelled"].includes(event.status ?? "")
  }

  if (event.event_type === "scan.status") {
    const nextStatus = event.new_status ?? event.status ?? ""
    return nextStatus === "completed" || nextStatus === "failed" || nextStatus === "cancelled"
  }

  return false
}

type ScanStreamConnectionState = "idle" | "connecting" | "open" | "fallback" | "closed"

export function useScanStream(
  id: string | undefined,
  options?: {
    enabled?: boolean
    onEvent?: (event: ApiScanStreamEvent) => void
  }
) {
  const [connectionState, setConnectionState] = useState<ScanStreamConnectionState>("idle")
  const [lastEvent, setLastEvent] = useState<ApiScanStreamEvent | null>(null)
  const callbackRef = useRef<((event: ApiScanStreamEvent) => void) | undefined>(options?.onEvent)

  useEffect(() => {
    callbackRef.current = options?.onEvent
  }, [options?.onEvent])

  useEffect(() => {
    if (!id || options?.enabled === false) {
      setConnectionState("idle")
      setLastEvent(null)
      return
    }

    let closedByEffect = false
    let terminalClose = false
    let ws: WebSocket | null = null
    let openTimeout: number | null = null
    setConnectionState("connecting")

    const openSocket = () => {
      if (closedByEffect) {
        return
      }

      ws = new WebSocket(getScanStreamUrl(id))

      ws.onopen = () => {
        if (closedByEffect) {
          return
        }
        setConnectionState("open")
      }

      ws.onmessage = (message) => {
        try {
          const parsed = JSON.parse(message.data) as ApiScanStreamEvent
          const event = {
            ...parsed,
            timestamp: parsed.timestamp ?? new Date().toISOString(),
          }
          setLastEvent(event)
          callbackRef.current?.(event)
          if (event.event_type === "ws.closing") {
            terminalClose = true
            setConnectionState("closed")
            ws?.close()
          }
        } catch {
          setConnectionState("fallback")
        }
      }

      ws.onerror = () => {
        if (closedByEffect || terminalClose) {
          return
        }
        setConnectionState("fallback")
      }

      ws.onclose = () => {
        if (closedByEffect) {
          setConnectionState("idle")
          return
        }
        setConnectionState(terminalClose ? "closed" : "fallback")
      }
    }

    if (typeof window !== "undefined") {
      openTimeout = window.setTimeout(openSocket, 0)
    } else {
      openSocket()
    }

    return () => {
      closedByEffect = true
      if (openTimeout !== null && typeof window !== "undefined") {
        window.clearTimeout(openTimeout)
      }
      try {
        ws?.close()
      } catch {}
    }
  }, [id, options?.enabled])

  return {
    connectionState,
    lastEvent,
    usingPollingFallback: connectionState === "fallback",
  }
}

export function useScanProfiles(
  assetType: ApiAsset["asset_type"] | undefined,
  target: string | undefined
) {
  const [profiles, setProfiles] = useState<ApiScanProfileContract[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    const normalizedTarget = target?.trim() ?? ""
    if (!assetType || !normalizedTarget) {
      setProfiles([])
      setIsLoading(false)
      setError(null)
      return
    }
    const currentAssetType: ApiAsset["asset_type"] = assetType

    let cancelled = false

    async function load() {
      setIsLoading(true)
      setError(null)
      try {
        const nextProfiles = await listScanProfiles({
          assetType: currentAssetType,
          target: normalizedTarget,
        })
        if (!cancelled) {
          setProfiles(nextProfiles)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scan profiles.")
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
  }, [assetType, target, reloadToken])

  return {
    profiles,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useScans(options?: {
  page?: number
  pageSize?: number
  pollIntervalMs?: number
  assetId?: string
}) {
  const [scans, setScans] = useState<Scan[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(options?.page ?? 1)
  const [pageSize, setPageSize] = useState(options?.pageSize ?? 20)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    setPage(options?.page ?? 1)
  }, [options?.page])

  useEffect(() => {
    setPageSize(options?.pageSize ?? 20)
  }, [options?.pageSize])

  useEffect(() => {
    let cancelled = false

    async function load() {
      const showFullLoader = scans.length === 0 && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const response = await listScans({ page, pageSize, assetId: options?.assetId })
        if (cancelled) {
          return
        }

        setScans(response.items)
        setTotal(response.total)
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scans.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [options?.assetId, page, pageSize, reloadToken])

  const hasActiveScans = scans.some((scan) => isActiveScanStatus(scan.rawStatus))

  useEffect(() => {
    if (!hasActiveScans) {
      return
    }

    const timer = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
    }, options?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS)

    return () => {
      window.clearTimeout(timer)
    }
  }, [hasActiveScans, options?.pollIntervalMs, reloadToken, scans])

  return {
    scans,
    total,
    page,
    pageSize,
    isLoading,
    isRefreshing,
    error,
    refresh: () => setReloadToken((current) => current + 1),
    setPage,
    setPageSize,
  }
}

export function useScan(id: string | undefined, pollIntervalMs: number = DEFAULT_POLL_INTERVAL_MS) {
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [advisoryMode, setAdvisoryMode] = useState<AiAdvisoryMode>(DEFAULT_AI_ADVISORY_MODE)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isRefreshingAiReasoning, setIsRefreshingAiReasoning] = useState(false)
  const [isLaunchingRetest, setIsLaunchingRetest] = useState(false)
  const [isApprovingTools, setIsApprovingTools] = useState(false)
  const [toolApprovalError, setToolApprovalError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    setAdvisoryMode(DEFAULT_AI_ADVISORY_MODE)
  }, [id])

  const addNotification = useNotificationStore.getState().addNotification
  const prevStatusRef = useRef<string | null>(null)
  const streamRefreshTimerRef = useRef<number | null>(null)

  const scheduleStreamRefresh = useCallback(() => {
    if (typeof window === "undefined") {
      return
    }
    if (streamRefreshTimerRef.current !== null) {
      window.clearTimeout(streamRefreshTimerRef.current)
    }
    streamRefreshTimerRef.current = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
      streamRefreshTimerRef.current = null
    }, STREAM_REFRESH_DELAY_MS)
  }, [])

  const handleStreamEvent = useCallback(
    (event: ApiScanStreamEvent) => {
      setDetail((current) => mergeScanDetailFromStream(current, event))

      if (event.event_type === "scan.finding") {
        addNotification({
          type: "finding",
          title: event.title ?? "Finding persisted",
          message: [event.severity, event.tool].filter(Boolean).join(" · ") || "New finding persisted",
          scanId: id,
          eventKey: `stream:${id}:${event.event_type}:${event.timestamp ?? ""}:${event.title ?? ""}`,
        })
      }

      if (event.event_type === "scan.job" && event.status === "blocked") {
        addNotification({
          type: "info",
          title: `${event.tool ?? "Tool"} blocked`,
          message:
            [
              event.execution_class ? formatExecutionClass(event.execution_class) : null,
              event.policy_state ? formatPolicyState(event.policy_state) : null,
              event.execution_provenance,
              event.execution_reason,
            ]
              .filter(Boolean)
              .join(" · ") || "Execution was blocked by current policy.",
          scanId: id,
          eventKey: `stream:${id}:${event.event_type}:${event.job_id ?? event.node_id ?? ""}:${event.status ?? ""}`,
        })
      }

      if (event.event_type === "scan.status") {
        const nextStatus = event.new_status ?? event.status ?? ""
        if (nextStatus === "completed") {
          addNotification({
            type: "scan_completed",
            title: "Scan Completed",
            message: `Scan ${id?.slice(0, 8)} completed`,
            scanId: id,
            eventKey: `stream:${id}:${event.event_type}:${event.timestamp ?? ""}:${nextStatus}`,
          })
        } else if (nextStatus === "failed" || nextStatus === "cancelled") {
          addNotification({
            type: "scan_failed",
            title: nextStatus === "cancelled" ? "Scan Cancelled" : "Scan Failed",
            message: `Scan ${id?.slice(0, 8)} ${nextStatus}`,
            scanId: id,
            eventKey: `stream:${id}:${event.event_type}:${event.timestamp ?? ""}:${nextStatus}`,
          })
        }
      }

      if (shouldRefreshFromStreamEvent(event)) {
        scheduleStreamRefresh()
      }
    },
    [addNotification, id, scheduleStreamRefresh]
  )

  const stream = useScanStream(id, {
    enabled: Boolean(id) && !(detail?.isTerminal ?? false),
    onEvent: handleStreamEvent,
  })

  useEffect(() => {
    return () => {
      if (streamRefreshTimerRef.current !== null && typeof window !== "undefined") {
        window.clearTimeout(streamRefreshTimerRef.current)
      }
    }
  }, [])

  useEffect(() => {
    if (!id) {
      setDetail(null)
      setIsLoading(false)
      setError("Invalid scan id.")
      return
    }

    const scanId = id
    let cancelled = false

    async function load() {
      const showFullLoader = detail === null && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const nextDetail = await getScanDetail(scanId, { advisoryMode })
        if (!cancelled) {
          // Push notification on terminal status change
          const nextStatus = nextDetail.scan.rawStatus
          const prevStatus = prevStatusRef.current
          if (prevStatus && prevStatus !== nextStatus) {
            if (nextStatus === "completed") {
              addNotification({
                type: "scan_completed",
                title: "Scan Completed",
                message: `${nextDetail.scan.name} finished with ${nextDetail.findings.length} findings`,
                scanId,
              })
            } else if (nextStatus === "failed") {
              addNotification({
                type: "scan_failed",
                title: "Scan Failed",
                message: `${nextDetail.scan.name} encountered an error`,
                scanId,
              })
            }
          }
          prevStatusRef.current = nextStatus

          setDetail(nextDetail)
          if (nextDetail.aiReasoning?.advisory_mode) {
            setAdvisoryMode(nextDetail.aiReasoning.advisory_mode)
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scan detail.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [id, reloadToken])

  async function loadAiReasoning(nextMode: AiAdvisoryMode, refresh: boolean) {
    if (!id || !detail?.isTerminal) {
      setAdvisoryMode(nextMode)
      return
    }

    setIsRefreshingAiReasoning(true)
    setError(null)
    try {
      const nextAdvisory = await getScanAiReasoning(id, {
        refresh,
        advisoryMode: nextMode,
      })
      setAdvisoryMode(nextMode)
      setDetail((current) =>
        current
          ? {
              ...current,
              aiReasoning: nextAdvisory,
            }
          : current
      )
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : refresh
            ? "Failed to regenerate AI advisory."
            : "Failed to load advisory mode."
      )
    } finally {
      setIsRefreshingAiReasoning(false)
    }
  }

  async function launchRetest() {
    if (!id) {
      throw new Error("Invalid scan id.")
    }

    setIsLaunchingRetest(true)
    setError(null)
    try {
      return await createRetestScanRequest(id)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to launch retest.")
      throw err
    } finally {
      setIsLaunchingRetest(false)
    }
  }

  async function approveTools(tools: string[]): Promise<ApiToolApprovalResponse> {
    if (!id) {
      throw new Error("Invalid scan id.")
    }
    const normalizedTools = tools
      .map((item) => item.trim())
      .filter(Boolean)
    if (normalizedTools.length === 0) {
      throw new Error("Select at least one tool to approve.")
    }

    setIsApprovingTools(true)
    setToolApprovalError(null)
    try {
      const payload = await approveScanToolsRequest(id, normalizedTools)
      addNotification({
        type: "info",
        title: "Tool approval updated",
        message:
          payload.results
            .map((result) => `${result.tool}: ${result.disposition}`)
            .join(" · ") || "Approval state updated.",
        scanId: id,
      })
      setReloadToken((current) => current + 1)
      return payload
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to approve tools."
      setToolApprovalError(message)
      setError(message)
      throw err
    } finally {
      setIsApprovingTools(false)
    }
  }

  const shouldPoll = detail
    ? isActiveScanStatus(detail.scan.rawStatus) && stream.usingPollingFallback
    : false

  useEffect(() => {
    if (!shouldPoll) {
      return
    }

    const timer = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
    }, pollIntervalMs)

    return () => {
      window.clearTimeout(timer)
    }
  }, [pollIntervalMs, reloadToken, shouldPoll])

  return {
    scan: detail?.scan,
    asset: detail?.asset,
    jobs: detail?.jobs ?? [],
    toolLogs: detail?.toolLogs ?? [],
    liveJobSessions: detail?.liveJobSessions ?? {},
    findings: detail?.findings ?? [],
    artifacts: detail?.artifacts ?? [],
    targetModel: detail?.targetModel ?? null,
    plannerContext: detail?.plannerContext ?? null,
    agentTranscript: detail?.agentTranscript ?? [],
    fieldValidation: detail?.fieldValidation ?? null,
    attackGraph: detail?.attackGraph ?? null,
    timeline: detail?.timeline ?? [],
    evidence: detail?.evidence ?? [],
    report: detail?.report ?? null,
    aiReasoning: detail?.aiReasoning ?? null,
    advisoryMode,
    isTerminal: detail?.isTerminal ?? false,
    isLoading,
    isRefreshing,
    isRefreshingAiReasoning,
    isLaunchingRetest,
    isApprovingTools,
    streamConnectionState: stream.connectionState,
    isUsingPollingFallback: stream.usingPollingFallback,
    toolApprovalError,
    error,
    selectAdvisoryMode: async (nextMode: AiAdvisoryMode) => {
      if (nextMode === advisoryMode) {
        return
      }
      await loadAiReasoning(nextMode, false)
    },
    refreshAiReasoning: async (nextMode: AiAdvisoryMode = advisoryMode) => {
      await loadAiReasoning(nextMode, true)
    },
    launchRetest,
    approveTools,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useScanCatalog() {
  const catalog = useAssetCatalog()

  return {
    assets: catalog.assets,
    isLoading: catalog.isLoading,
    error: catalog.error,
    refresh: catalog.refresh,
  }
}

export function useAssetCatalog() {
  const [projects, setProjects] = useState<ApiProject[]>([])
  const [assets, setAssets] = useState<ScanAsset[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setError(null)
      setIsLoading(true)

      try {
        const projectList = await listProjects()
        const assetGroups = await Promise.all(
          projectList
            .filter((project) => project.is_active)
            .map(async (project) => {
              const projectAssets = await listProjectAssets(project.id)
              return projectAssets
                .filter((asset) => asset.is_active)
                .map((asset) => ({
                  ...asset,
                  project,
                }))
            })
        )
        if (!cancelled) {
          setProjects(projectList)
          setAssets(
            assetGroups.flat().sort((left, right) => left.name.localeCompare(right.name))
          )
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load assets.")
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
  }, [reloadToken])

  return {
    projects,
    assets,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useAsset(id: string | undefined) {
  const [asset, setAsset] = useState<ScanAsset | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    if (!id) {
      setAsset(null)
      setIsLoading(false)
      setError("Invalid asset id.")
      return
    }

    const assetId = id
    let cancelled = false

    async function load() {
      setError(null)
      setIsLoading(true)

      try {
        const baseAsset = await getAsset(assetId)
        const project = await getProject(baseAsset.project_id)
        if (!cancelled) {
          setAsset({
            ...baseAsset,
            project,
          })
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load asset.")
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
  }, [id, reloadToken])

  return {
    asset,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useAssetHistory(id: string | undefined, options?: { limit?: number; pollIntervalMs?: number }) {
  const [history, setHistory] = useState<ApiAssetHistory | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    if (!id) {
      setHistory(null)
      setIsLoading(false)
      setError("Invalid asset id.")
      return
    }

    const assetId = id
    let cancelled = false

    async function load() {
      const showFullLoader = history === null && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const nextHistory = await getAssetHistoryRequest(assetId, options?.limit ?? 20)
        if (!cancelled) {
          setHistory(nextHistory)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load asset history.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [id, options?.limit, reloadToken])

  const hasActiveScans = (history?.entries ?? []).some((entry) => isActiveScanStatus(entry.status))

  useEffect(() => {
    if (!hasActiveScans) {
      return
    }

    const timer = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
    }, options?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS)

    return () => {
      window.clearTimeout(timer)
    }
  }, [hasActiveScans, options?.pollIntervalMs, reloadToken])

  return {
    history,
    isLoading,
    isRefreshing,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useAssetHistoricalFindings(
  id: string | undefined,
  options?: {
    page?: number
    pageSize?: number
    status?: "all" | "active" | "resolved"
    occurrenceLimit?: number
  }
) {
  const [items, setItems] = useState<ApiHistoricalFinding[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(options?.page ?? 1)
  const [pageSize, setPageSize] = useState(options?.pageSize ?? 10)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    setPage(options?.page ?? 1)
  }, [options?.page])

  useEffect(() => {
    setPageSize(options?.pageSize ?? 10)
  }, [options?.pageSize])

  useEffect(() => {
    if (!id) {
      setItems([])
      setTotal(0)
      setIsLoading(false)
      setError("Invalid asset id.")
      return
    }

    const assetId = id
    let cancelled = false

    async function load() {
      const showFullLoader = items.length === 0 && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const response = await listAssetHistoricalFindingsRequest({
          assetId,
          page,
          pageSize,
          status: options?.status ?? "all",
          occurrenceLimit: options?.occurrenceLimit ?? 3,
        })
        if (!cancelled) {
          setItems(response.items)
          setTotal(response.total)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load historical findings.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [id, options?.occurrenceLimit, options?.status, page, pageSize, reloadToken])

  return {
    items,
    total,
    page,
    pageSize,
    isLoading,
    isRefreshing,
    error,
    refresh: () => setReloadToken((current) => current + 1),
    setPage,
    setPageSize,
  }
}

export function useCreateProject() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createProject(input: CreateProjectInput): Promise<ApiProject> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createProjectRequest(input)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create project."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createProject,
    isSubmitting,
    error,
  }
}

export function useCreateAsset() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createAsset(input: CreateAssetInput): Promise<ApiAsset> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createAssetRequest(input)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create asset."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createAsset,
    isSubmitting,
    error,
  }
}

export function useCreateScan() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createScan(input: CreateScanInput): Promise<Scan> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createScanRequest(input)
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to create scan."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createScan,
    isSubmitting,
    error,
  }
}

export function useRuntimeDiagnostics() {
  const [aiDiagnostics, setAiDiagnostics] = useState<ApiAiProviderDiagnostics | null>(null)
  const [systemStatus, setSystemStatus] = useState<ApiSystemStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isProbing, setIsProbing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let cancelled = false

    async function load() {
      const showFullLoader = aiDiagnostics === null && systemStatus === null && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const [nextAiDiagnostics, nextSystemStatus] = await Promise.all([
          getAiProviderDiagnostics(false),
          getSystemStatus(),
        ])
        if (!cancelled) {
          setAiDiagnostics(nextAiDiagnostics)
          setSystemStatus(nextSystemStatus)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load runtime diagnostics.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [reloadToken])

  async function probeProviders() {
    setIsProbing(true)
    setError(null)
    try {
      const nextDiagnostics = await getAiProviderDiagnostics(true)
      setAiDiagnostics(nextDiagnostics)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run provider live probe.")
    } finally {
      setIsProbing(false)
    }
  }

  return {
    aiDiagnostics,
    systemStatus,
    isLoading,
    isRefreshing,
    isProbing,
    error,
    probeProviders,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useCurrentOperator() {
  const [user, setUser] = useState<ApiCurrentUser | null>(null)
  const [authRuntime, setAuthRuntime] = useState<ApiAuthRuntime | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setError(null)
      setIsLoading(true)

      try {
        const [runtimeResult, userResult] = await Promise.allSettled([
          getAuthRuntime(),
          getCurrentUser(),
        ])

        if (cancelled) {
          return
        }

        if (runtimeResult.status === "fulfilled") {
          setAuthRuntime(runtimeResult.value)
        } else {
          setAuthRuntime(null)
        }

        if (userResult.status === "fulfilled") {
          setUser(userResult.value)
        } else {
          setUser(null)
          const message =
            userResult.reason instanceof Error
              ? userResult.reason.message
              : "Failed to resolve current operator."
          setError(message)
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
  }, [reloadToken])

  return {
    user,
    authRuntime,
    isLoading,
    error,
    isDevBypass: authRuntime?.dev_auth_bypass_enabled ?? false,
    refresh: () => setReloadToken((current) => current + 1),
    signOut: () => {
      clearStoredAuthTokens()
      setUser(null)
      setReloadToken((current) => current + 1)
    },
  }
}

export function useScanPreflight() {
  const [preflight, setPreflight] = useState<ApiScanProfilePreflightResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runPreflight = useCallback(async (
    input: ScanProfilePreflightInput
  ): Promise<ApiScanProfilePreflightResponse> => {
    setIsLoading(true)
    setError(null)

    try {
      const nextPreflight = await runScanProfilePreflightRequest(input)
      setPreflight(nextPreflight)
      return nextPreflight
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to run scan preflight."
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  const clear = useCallback(() => {
    setPreflight(null)
    setError(null)
  }, [])

  return {
    preflight,
    isLoading,
    error,
    clear,
    runPreflight,
  }
}

export function useToolLogContent(scanId: string | undefined, storageRef: string | null) {
  const [content, setContent] = useState<ApiToolExecutionLogContentResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!scanId || !storageRef) {
      setContent(null)
      setError(null)
      return null
    }

    setIsLoading(true)
    setError(null)
    try {
      const payload = await getScanToolLogContent(scanId, storageRef)
      setContent(payload)
      return payload
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load full command log."
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [scanId, storageRef])

  return {
    content,
    isLoading,
    error,
    load,
  }
}

export function useJobSession(scanId: string | undefined, jobId: string | undefined) {
  const [session, setSession] = useState<ApiJobSessionResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!scanId || !jobId) {
      setSession(null)
      setError(null)
      return null
    }

    setIsLoading(true)
    setError(null)
    try {
      const payload = await getScanJobSession(scanId, jobId)
      setSession(payload)
      return payload
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load job session."
      setError(message)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [jobId, scanId])

  useEffect(() => {
    void load()
  }, [load])

  return {
    session,
    isLoading,
    error,
    refresh: load,
  }
}

export function useCancelScan() {
  const [isCancelling, setIsCancelling] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function cancelScan(scanId: string, onSuccess?: () => void): Promise<void> {
    setIsCancelling(true)
    setError(null)

    try {
      await cancelScanRequest(scanId)
      onSuccess?.()
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to cancel scan."
      setError(message)
      throw err
    } finally {
      setIsCancelling(false)
    }
  }

  return {
    cancelScan,
    isCancelling,
    error,
  }
}
