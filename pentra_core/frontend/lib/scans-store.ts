"use client"

export type UiScanStatus = "queued" | "running" | "completed" | "failed"
export type ScanType = "recon" | "vuln" | "full" | "exploit_verify"
export type ScanPriority = "critical" | "high" | "normal" | "low"
export type RawScanStatus =
  | "queued"
  | "priority_queued"
  | "validating"
  | "running"
  | "partial_success"
  | "paused"
  | "analyzing"
  | "ai_queued"
  | "reporting"
  | "completed"
  | "failed"
  | "rejected"
  | "checkpointed"

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface ApiProject {
  id: string
  tenant_id: string
  name: string
  slug: string
  description: string | null
  is_active: boolean
  asset_count: number
  created_at: string
  updated_at: string
}

export interface ApiAsset {
  id: string
  tenant_id: string
  project_id: string
  name: string
  asset_type: "web_app" | "api" | "network" | "repository" | "cloud"
  target: string
  description: string | null
  is_verified: boolean
  is_active: boolean
  tags: Record<string, string>
  created_at: string
  updated_at: string
}

export interface ApiScan {
  id: string
  tenant_id: string
  asset_id: string
  scan_type: ScanType
  status: RawScanStatus
  priority: ScanPriority
  progress: number
  config: Record<string, unknown>
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  result_summary: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface ApiScanJob {
  id: string
  scan_id: string
  phase: number
  tool: string
  status:
    | "queued"
    | "pending"
    | "scheduled"
    | "assigned"
    | "running"
    | "completed"
    | "failed"
    | "skipped"
    | "blocked"
  priority: string
  worker_id: string | null
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  retry_count: number
  execution_mode: string | null
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | null
  execution_reason: string | null
  created_at: string
}

export interface ApiFinding {
  id: string
  scan_id: string
  scan_job_id: string | null
  source_type: "scanner" | "exploit_verify" | "ai_analysis"
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  confidence: number
  cve_id: string | null
  cvss_score: number | null
  description: string | null
  evidence: Record<string, unknown> | null
  remediation: string | null
  tool_source: string
  vulnerability_type: string | null
  exploitability: string | null
  surface: string | null
  execution_mode: string | null
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | null
  execution_reason: string | null
  verification_state: "detected" | "suspected" | "verified" | null
  verification_confidence: number | null
  verified_at: string | null
  is_false_positive: boolean
  fp_probability: number | null
  created_at: string
}

export interface ApiArtifactSummary {
  id: string
  scan_id: string
  node_id: string | null
  artifact_type: string
  tool: string | null
  storage_ref: string
  content_type: string
  size_bytes: number | null
  checksum: string | null
  item_count: number
  finding_count: number
  evidence_count: number
  severity_counts: Record<string, number>
  summary: Record<string, unknown>
  execution_mode: string | null
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | null
  execution_reason: string | null
  created_at: string
}

export interface ApiAttackGraphNode {
  id: string
  node_type: "entrypoint" | "asset" | "service" | "endpoint" | "vulnerability" | "credential" | "privilege"
  label: string
  artifact_ref: string
  properties: Record<string, unknown>
}

export interface ApiAttackGraphEdge {
  source: string
  target: string
  edge_type: string
  properties: Record<string, unknown>
}

export interface ApiAttackGraph {
  scan_id: string
  tenant_id: string
  built_at: string | null
  node_count: number
  edge_count: number
  path_summary: Record<string, unknown>
  scoring_summary: Record<string, unknown>
  nodes: ApiAttackGraphNode[]
  edges: ApiAttackGraphEdge[]
}

export interface ApiTimelineEvent {
  id: string
  timestamp: string
  event_type: string
  title: string
  details: string | null
  status: string | null
  phase: number | null
  tool: string | null
  job_id: string | null
  node_id: string | null
  artifact_ref: string | null
}

export interface ApiEvidenceReference {
  id: string
  finding_id: string | null
  finding_title: string | null
  severity: "critical" | "high" | "medium" | "low" | "info"
  tool_source: string | null
  evidence_type: string
  label: string
  target: string
  content_preview: string
  content: string | null
  storage_ref: string | null
  metadata: Record<string, unknown>
}

export interface ApiScanReport {
  asset: {
    id: string
    name: string
    target: string
    asset_type: string
    project_id?: string
    project_name?: string | null
    description?: string | null
  }
  scan_id: string
  report_id: string
  generated_at: string
  executive_summary: string
  severity_counts: Record<string, number>
  verification_counts: Record<string, number>
  execution_summary: Record<string, number>
  vulnerability_count: number
  evidence_count: number
  narrative: {
    title: string
    summary: string
    impact: string
    steps: Array<{
      step: number
      action: string
      description: string
      target: string
      risk: string
      artifact_ref?: string | null
    }>
    recommendations: string[]
    targets_reached: string[]
  } | null
  compliance: Array<{
    vulnerability_type: string
    owasp: string[]
    cwe: string[]
  }>
  finding_groups: Array<{
    group_id: string
    title: string
    surface: string
    target: string
    route_group: string | null
    severity_counts: Record<string, number>
    verification_counts: Record<string, number>
    findings: Array<{
      id: string
      title: string
      severity: string
      confidence: number
      vulnerability_type: string | null
      target: string
      route_group: string | null
      verification_state: string | null
      verification_confidence: number | null
      exploitability: string | null
      surface: string | null
      cvss_score: number | null
      description: string | null
      remediation: string | null
      tool_source: string
      created_at: string
    }>
  }>
  remediation_plan: Array<{
    plan_id: string
    title: string
    priority: "immediate" | "high" | "medium" | "low"
    owner_hint: string
    rationale: string
    actions: string[]
    related_finding_ids: string[]
    related_vulnerability_types: string[]
    related_targets: string[]
  }>
  comparison: {
    current_scan_id: string
    baseline_scan_id: string | null
    generated_at: string
    baseline_generated_at: string | null
    summary: string
    counts: Record<string, number>
    severity_delta: Record<string, number>
    verification_delta: Record<string, number>
    new_findings: Array<Record<string, unknown>>
    resolved_findings: Array<Record<string, unknown>>
    escalated_findings: Array<Record<string, unknown>>
  } | null
  retest: {
    eligible: boolean
    recommended_scan_type: string
    recommended_priority: string
    baseline_scan_id: string
    compare_against_scan_id: string | null
    launch_endpoint: string
  } | null
  export_formats: Array<"markdown" | "json" | "csv">
  top_findings: Array<{
    id: string
    title: string
    severity: string
    vulnerability_type?: string | null
    verification_state: string | null
    verification_confidence: number | null
    cvss_score: number | null
    description: string | null
    remediation: string | null
  }>
  markdown: string
}

export type ReportExportFormat = "markdown" | "json" | "csv"

export interface ApiAiAdvisoryNextStep {
  title: string
  rationale: string
  confidence: number
}

export interface ApiAiAttackGraphSummary {
  summary: string
  risk_overview: string
  next_steps: ApiAiAdvisoryNextStep[]
  confidence: number
}

export interface ApiAiFindingExplanation {
  finding_id: string | null
  title: string
  why_it_matters: string
  business_impact: string
  exploitability_assessment: string
  triage_priority: "immediate" | "high" | "medium" | "low"
  next_steps: string[]
  confidence: number
}

export interface ApiAiReportAdvisory {
  draft_summary: string
  prioritization_notes: string
  remediation_focus: string[]
  confidence: number
}

export interface ApiAiReasoningAudit {
  artifact_id: string | null
  storage_ref: string | null
  context_hash: string
  prompt_version: string
  prompt_artifact_type: string
}

export type AiAdvisoryMode = "advisory_only" | "deep_advisory"

export interface ApiScanAiReasoning {
  scan_id: string
  generated_at: string
  provider: string
  model: string
  advisory_mode: AiAdvisoryMode
  status: "generated" | "fallback" | "disabled"
  fallback_reason: string | null
  attack_graph: ApiAiAttackGraphSummary
  report: ApiAiReportAdvisory
  findings: ApiAiFindingExplanation[]
  audit: ApiAiReasoningAudit
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface Scan {
  id: string
  name: string
  target: string
  status: UiScanStatus
  rawStatus: RawScanStatus
  statusLabel: string
  startedAt: string
  completedAt: string
  createdAt: string
  updatedAt: string
  duration: string
  profile: string
  scanType: ScanType
  priority: ScanPriority
  progress: number
  assetId: string
  assetName: string
  errorMessage: string | null
  resultSummary: Record<string, unknown> | null
  findings: Omit<SeverityCounts, "info">
}

export interface ScanAsset extends ApiAsset {
  project?: ApiProject
}

export interface ScanDetail {
  scan: Scan
  asset?: ScanAsset
  jobs: ApiScanJob[]
  findings: ApiFinding[]
  artifacts: ApiArtifactSummary[]
  attackGraph: ApiAttackGraph | null
  timeline: ApiTimelineEvent[]
  evidence: ApiEvidenceReference[]
  report: ApiScanReport | null
  aiReasoning: ApiScanAiReasoning | null
  isTerminal: boolean
}

export const DEFAULT_AI_ADVISORY_MODE: AiAdvisoryMode = "advisory_only"

export interface CreateScanInput {
  assetId: string
  scanType: ScanType
  priority?: ScanPriority
  config?: Record<string, unknown>
}

export interface CreateProjectInput {
  name: string
  slug?: string
  description?: string
}

export interface CreateAssetInput {
  projectId: string
  name: string
  assetType: ApiAsset["asset_type"]
  target: string
  description?: string
  tags?: Record<string, string>
}

export interface CreateRetestInput {
  priority?: ScanPriority
  configOverrides?: Record<string, unknown>
}

export interface ScanStatusMeta {
  status: UiScanStatus
  label: string
  textClass: string
  dotClass: string
  bgClass: string
}

export interface ScanProfileOption {
  id: ScanType
  name: string
  description: string
  duration: string
  priority: ScanPriority
  config?: Record<string, unknown>
}

const DEFAULT_API_BASE_URL = "http://localhost:8000"
const DEV_AUTH_MODE = process.env.NEXT_PUBLIC_PENTRA_DEV_AUTH_MODE ?? "bypass"
const DEV_AUTH_TOKEN = process.env.NEXT_PUBLIC_PENTRA_DEV_AUTH_TOKEN ?? ""

const assetCache = new Map<string, ApiAsset>()
const projectCache = new Map<string, ApiProject>()

export const scanProfiles: ScanProfileOption[] = [
  {
    id: "recon",
    name: "Recon Sweep",
    duration: "~3 min",
    description: "Scope validation, subdomain discovery, and host enumeration.",
    priority: "normal",
    config: { profile: "recon" },
  },
  {
    id: "vuln",
    name: "Vulnerability Assessment",
    duration: "~10 min",
    description: "Recon plus enumeration and vulnerability tooling coverage.",
    priority: "normal",
    config: { profile: "vuln" },
  },
  {
    id: "full",
    name: "Full Assessment",
    duration: "~20 min",
    description: "End-to-end offensive workflow with exploit validation and reporting.",
    priority: "high",
    config: { profile: "full" },
  },
]

const phaseLabels: Record<number, string> = {
  0: "Scope Validation",
  1: "Recon",
  2: "Enumeration",
  3: "Vulnerability Scan",
  4: "Exploit Verification",
  5: "AI Analysis",
  6: "Report Generation",
}

const scanTypePhaseMap: Record<ScanType, number[]> = {
  recon: [0, 1],
  vuln: [0, 1, 2, 3],
  full: [0, 1, 2, 3, 4, 5, 6],
  exploit_verify: [0, 4],
}

export function getApiBaseUrl(): string {
  const value =
    process.env.NEXT_PUBLIC_PENTRA_API_BASE_URL?.trim() || DEFAULT_API_BASE_URL
  return value.replace(/\/+$/, "")
}

export function isDevAuthBypassEnabled(): boolean {
  return DEV_AUTH_MODE === "bypass"
}

function buildHeaders(initHeaders?: HeadersInit): Headers {
  const headers = new Headers(initHeaders)

  if (DEV_AUTH_TOKEN && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${DEV_AUTH_TOKEN}`)
  }

  return headers
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = buildHeaders(init?.headers)

  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  })

  const contentType = response.headers.get("content-type") ?? ""
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text()

  if (!response.ok) {
    const detail =
      typeof payload === "object" &&
      payload !== null &&
      "detail" in payload &&
      typeof payload.detail === "string"
        ? payload.detail
        : `Request failed (${response.status})`
    throw new Error(detail)
  }

  return payload as T
}

async function apiFetchOptional<T>(path: string, fallback: T, init?: RequestInit): Promise<T> {
  const headers = buildHeaders(init?.headers)

  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  })

  if (response.status === 404) {
    return fallback
  }

  const contentType = response.headers.get("content-type") ?? ""
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text()

  if (!response.ok) {
    const detail =
      typeof payload === "object" &&
      payload !== null &&
      "detail" in payload &&
      typeof payload.detail === "string"
        ? payload.detail
        : `Request failed (${response.status})`
    throw new Error(detail)
  }

  return payload as T
}

function setAssetCache(asset: ApiAsset | undefined): void {
  if (asset) {
    assetCache.set(asset.id, asset)
  }
}

function setProjectCache(project: ApiProject | undefined): void {
  if (project) {
    projectCache.set(project.id, project)
  }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)))
}

export function formatScanType(scanType: ScanType): string {
  switch (scanType) {
    case "recon":
      return "Recon Sweep"
    case "vuln":
      return "Vulnerability Assessment"
    case "full":
      return "Full Assessment"
    case "exploit_verify":
      return "Exploit Verification"
    default:
      return scanType
  }
}

export function formatAssetType(assetType: ApiAsset["asset_type"]): string {
  switch (assetType) {
    case "web_app":
      return "Web App"
    case "api":
      return "API"
    case "network":
      return "Network"
    case "repository":
      return "Repository"
    case "cloud":
      return "Cloud"
    default:
      return assetType
  }
}

export function formatPriority(priority: ScanPriority): string {
  return priority.charAt(0).toUpperCase() + priority.slice(1)
}

export function formatPhase(phase: number): string {
  return phaseLabels[phase] ?? `Phase ${phase}`
}

export function getExpectedPhases(scanType: ScanType): number[] {
  return scanTypePhaseMap[scanType] ?? [0, 1]
}

export function normalizeScanStatus(rawStatus: RawScanStatus): UiScanStatus {
  switch (rawStatus) {
    case "completed":
      return "completed"
    case "failed":
    case "rejected":
      return "failed"
    case "queued":
    case "priority_queued":
    case "validating":
    case "ai_queued":
    case "paused":
    case "checkpointed":
      return "queued"
    default:
      return "running"
  }
}

export function isTerminalScanStatus(rawStatus: RawScanStatus): boolean {
  return rawStatus === "completed" || rawStatus === "failed" || rawStatus === "rejected"
}

export function isActiveScanStatus(rawStatus: RawScanStatus): boolean {
  return !isTerminalScanStatus(rawStatus)
}

export function getScanStatusMeta(rawStatus: RawScanStatus): ScanStatusMeta {
  const status = normalizeScanStatus(rawStatus)

  if (rawStatus === "completed") {
    return {
      status,
      label: "Completed",
      textClass: "text-low",
      dotClass: "bg-low",
      bgClass: "bg-low/10",
    }
  }

  if (rawStatus === "failed" || rawStatus === "rejected") {
    return {
      status,
      label: rawStatus === "rejected" ? "Rejected" : "Failed",
      textClass: "text-critical",
      dotClass: "bg-critical",
      bgClass: "bg-critical/10",
    }
  }

  if (status === "running") {
    const runningLabels: Record<string, string> = {
      running: "Running",
      partial_success: "Partial Success",
      analyzing: "Analyzing",
      reporting: "Reporting",
    }

    return {
      status,
      label: runningLabels[rawStatus] ?? "Running",
      textClass: "text-primary",
      dotClass: "bg-primary animate-pulse",
      bgClass: "bg-primary/10",
    }
  }

  const queuedLabels: Record<string, string> = {
    queued: "Queued",
    priority_queued: "Priority Queued",
    validating: "Validating",
    ai_queued: "AI Queued",
    paused: "Paused",
    checkpointed: "Checkpointed",
  }

  return {
    status,
    label: queuedLabels[rawStatus] ?? "Queued",
    textClass: "text-muted-foreground",
    dotClass: "bg-muted-foreground",
    bgClass: "bg-muted",
  }
}

export function formatDuration(
  startedAt?: string | null,
  completedAt?: string | null,
  now: number = Date.now()
): string {
  if (!startedAt) {
    return "Not started"
  }

  const start = new Date(startedAt).getTime()
  const end = completedAt ? new Date(completedAt).getTime() : now

  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return "Unknown"
  }

  const totalSeconds = Math.floor((end - start) / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60

  if (hours > 0) {
    return `${hours}h ${minutes}m`
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`
  }
  return `${seconds}s`
}

export function formatRelativeTime(timestamp?: string | null): string {
  if (!timestamp) {
    return "Waiting"
  }

  const time = new Date(timestamp).getTime()
  if (Number.isNaN(time)) {
    return "Unknown"
  }

  const deltaSeconds = Math.floor((Date.now() - time) / 1000)
  if (deltaSeconds < 60) {
    return "Just now"
  }

  const deltaMinutes = Math.floor(deltaSeconds / 60)
  if (deltaMinutes < 60) {
    return `${deltaMinutes}m ago`
  }

  const deltaHours = Math.floor(deltaMinutes / 60)
  if (deltaHours < 24) {
    return `${deltaHours}h ago`
  }

  const deltaDays = Math.floor(deltaHours / 24)
  return `${deltaDays}d ago`
}

export function formatExecutionProvenance(
  provenance?: "live" | "simulated" | "blocked" | "inferred" | null
): string {
  switch (provenance) {
    case "live":
      return "Live"
    case "simulated":
      return "Simulated"
    case "blocked":
      return "Blocked"
    case "inferred":
      return "Inferred"
    default:
      return "Unknown"
  }
}

export function formatExecutionReason(reason?: string | null): string {
  switch (reason) {
    case "not_supported":
      return "Not supported in this live mode"
    case "target_policy_blocked":
      return "Blocked by target policy"
    case "demo_simulated_mode":
      return "Explicit demo simulation mode"
    case "container_execution_error":
      return "Container execution error"
    default:
      return reason ?? "No additional detail"
  }
}

export function aggregateSeverityCounts(findings: ApiFinding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }

  for (const finding of findings) {
    counts[finding.severity] += 1
  }

  return counts
}

function normalizeSeverityCounts(input?: Partial<SeverityCounts>): SeverityCounts {
  return {
    critical: input?.critical ?? 0,
    high: input?.high ?? 0,
    medium: input?.medium ?? 0,
    low: input?.low ?? 0,
    info: input?.info ?? 0,
  }
}

function extractSeverityCounts(
  summary: Record<string, unknown> | null | undefined
): SeverityCounts {
  if (!summary) {
    return normalizeSeverityCounts()
  }

  const candidates = [
    summary["severity_counts"],
    summary["findings_by_severity"],
    summary["severity"],
    summary["counts"],
  ]

  for (const candidate of candidates) {
    if (typeof candidate === "object" && candidate !== null) {
      const values = candidate as Partial<Record<keyof SeverityCounts, unknown>>
      return normalizeSeverityCounts({
        critical: Number(values.critical ?? 0),
        high: Number(values.high ?? 0),
        medium: Number(values.medium ?? 0),
        low: Number(values.low ?? 0),
        info: Number(values.info ?? 0),
      })
    }
  }

  return normalizeSeverityCounts()
}

function buildScanName(scan: ApiScan, asset?: ApiAsset): string {
  if (asset?.name) {
    return `${formatScanType(scan.scan_type)} · ${asset.name}`
  }
  return `${formatScanType(scan.scan_type)} · Asset ${scan.asset_id.slice(0, 8)}`
}

export function toScanSummary(
  scan: ApiScan,
  asset?: ApiAsset,
  findings: SeverityCounts = extractSeverityCounts(scan.result_summary)
): Scan {
  const statusMeta = getScanStatusMeta(scan.status)
  const inferredStartedAt =
    scan.started_at ??
    (statusMeta.status === "queued" ? null : scan.created_at)

  return {
    id: scan.id,
    name: buildScanName(scan, asset),
    target: asset?.target ?? "Resolving target...",
    status: statusMeta.status,
    rawStatus: scan.status,
    statusLabel: statusMeta.label,
    startedAt: inferredStartedAt ?? "",
    completedAt: scan.completed_at ?? "",
    createdAt: scan.created_at,
    updatedAt: scan.updated_at,
    duration: formatDuration(inferredStartedAt, scan.completed_at),
    profile: formatScanType(scan.scan_type),
    scanType: scan.scan_type,
    priority: scan.priority,
    progress: scan.progress,
    assetId: scan.asset_id,
    assetName: asset?.name ?? "Unknown Asset",
    errorMessage: scan.error_message,
    resultSummary: scan.result_summary,
    findings: {
      critical: findings.critical,
      high: findings.high,
      medium: findings.medium,
      low: findings.low,
    },
  }
}

async function fetchAsset(assetId: string): Promise<ApiAsset> {
  const cached = assetCache.get(assetId)
  if (cached) {
    return cached
  }

  const asset = await apiFetch<ApiAsset>(`/api/v1/assets/${assetId}`)
  setAssetCache(asset)
  return asset
}

async function fetchProject(projectId: string): Promise<ApiProject> {
  const cached = projectCache.get(projectId)
  if (cached) {
    return cached
  }

  const project = await apiFetch<ApiProject>(`/api/v1/projects/${projectId}`)
  setProjectCache(project)
  return project
}

async function fetchAssetsByIds(ids: string[]): Promise<Map<string, ApiAsset>> {
  const uniqueIds = unique(ids)
  const assets = await Promise.all(uniqueIds.map((assetId) => fetchAsset(assetId)))

  return new Map(assets.map((asset) => [asset.id, asset]))
}

export async function listScans(options?: {
  page?: number
  pageSize?: number
  status?: string
  assetId?: string
}): Promise<PaginatedResponse<Scan>> {
  const params = new URLSearchParams()
  params.set("page", String(options?.page ?? 1))
  params.set("page_size", String(options?.pageSize ?? 20))

  if (options?.status) {
    params.set("status", options.status)
  }
  if (options?.assetId) {
    params.set("asset_id", options.assetId)
  }

  const response = await apiFetch<PaginatedResponse<ApiScan>>(
    `/api/v1/scans?${params.toString()}`
  )
  const assetMap = await fetchAssetsByIds(response.items.map((scan) => scan.asset_id))

  return {
    ...response,
    items: response.items.map((scan) => toScanSummary(scan, assetMap.get(scan.asset_id))),
  }
}

export async function listProjects(pageSize: number = 100): Promise<ApiProject[]> {
  const response = await apiFetch<PaginatedResponse<ApiProject>>(
    `/api/v1/projects?page=1&page_size=${pageSize}`
  )

  response.items.forEach((project) => setProjectCache(project))
  return response.items
}

export async function listProjectAssets(
  projectId: string,
  pageSize: number = 100
): Promise<ApiAsset[]> {
  const response = await apiFetch<PaginatedResponse<ApiAsset>>(
    `/api/v1/projects/${projectId}/assets?page=1&page_size=${pageSize}`
  )

  response.items.forEach((asset) => setAssetCache(asset))
  return response.items
}

export async function getProject(projectId: string): Promise<ApiProject> {
  return fetchProject(projectId)
}

export async function getAsset(assetId: string): Promise<ApiAsset> {
  return fetchAsset(assetId)
}

export async function createProject(input: CreateProjectInput): Promise<ApiProject> {
  const project = await apiFetch<ApiProject>("/api/v1/projects", {
    method: "POST",
    body: JSON.stringify({
      name: input.name,
      slug: input.slug,
      description: input.description,
    }),
  })

  setProjectCache(project)
  return project
}

export async function createAsset(input: CreateAssetInput): Promise<ApiAsset> {
  const asset = await apiFetch<ApiAsset>(`/api/v1/projects/${input.projectId}/assets`, {
    method: "POST",
    body: JSON.stringify({
      name: input.name,
      asset_type: input.assetType,
      target: input.target,
      description: input.description,
      tags: input.tags ?? {},
    }),
  })

  setAssetCache(asset)
  return asset
}

export async function listAvailableAssets(): Promise<ScanAsset[]> {
  const projects = await listProjects()
  const assetLists = await Promise.all(
    projects
      .filter((project) => project.is_active)
      .map(async (project) => {
        const assets = await listProjectAssets(project.id)
        return assets
          .filter((asset) => asset.is_active)
          .map((asset) => ({
            ...asset,
            project,
          }))
      })
  )

  return assetLists.flat().sort((left, right) => {
    return left.name.localeCompare(right.name)
  })
}

export async function createScan(input: CreateScanInput): Promise<Scan> {
  const created = await apiFetch<ApiScan>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({
      asset_id: input.assetId,
      scan_type: input.scanType,
      priority: input.priority ?? "normal",
      config: input.config ?? {},
    }),
  })

  const asset = await fetchAsset(created.asset_id).catch(() => undefined)
  return toScanSummary(created, asset)
}

export async function createRetestScan(
  scanId: string,
  input?: CreateRetestInput
): Promise<Scan> {
  const created = await apiFetch<ApiScan>(`/api/v1/scans/${scanId}/retest`, {
    method: "POST",
    body: JSON.stringify({
      priority: input?.priority,
      config_overrides: input?.configOverrides ?? {},
    }),
  })

  const asset = await fetchAsset(created.asset_id).catch(() => undefined)
  return toScanSummary(created, asset)
}

export async function downloadScanReportExport(
  scanId: string,
  format: ReportExportFormat
): Promise<void> {
  const headers = buildHeaders()
  const response = await fetch(
    `${getApiBaseUrl()}/api/v1/scans/${scanId}/report/export?format=${format}`,
    {
      headers,
      cache: "no-store",
    }
  )

  if (!response.ok) {
    const detail = await response.text()
    throw new Error(detail || `Failed to export report (${response.status})`)
  }

  const blob = await response.blob()
  const url = window.URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  const disposition = response.headers.get("Content-Disposition") ?? ""
  const match = disposition.match(/filename=\"([^\"]+)\"/)
  anchor.href = url
  anchor.download = match?.[1] ?? `pentra-report-${scanId}.${format === "markdown" ? "md" : format}`
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  window.URL.revokeObjectURL(url)
}

export async function getScanAiReasoning(
  scanId: string,
  options?: { refresh?: boolean; advisoryMode?: AiAdvisoryMode }
): Promise<ApiScanAiReasoning | null> {
  const params = new URLSearchParams()
  if (options?.refresh) {
    params.set("refresh", "true")
  }
  if (options?.advisoryMode) {
    params.set("mode", options.advisoryMode)
  }

  const suffix = params.size > 0 ? `?${params.toString()}` : ""
  return apiFetchOptional<ApiScanAiReasoning | null>(
    `/api/v1/scans/${scanId}/ai-reasoning${suffix}`,
    null
  )
}

export async function getScanDetail(
  scanId: string,
  options?: { advisoryMode?: AiAdvisoryMode }
): Promise<ScanDetail> {
  const scan = await apiFetch<ApiScan>(`/api/v1/scans/${scanId}`)

  const [jobs, findingsResponse, artifacts, attackGraph, timeline, evidence, report] = await Promise.all([
    apiFetch<ApiScanJob[]>(`/api/v1/scans/${scanId}/jobs`),
    apiFetch<PaginatedResponse<ApiFinding>>(
      `/api/v1/scans/${scanId}/findings?page=1&page_size=100`
    ),
    apiFetch<ApiArtifactSummary[]>(`/api/v1/scans/${scanId}/artifacts/summary`),
    apiFetchOptional<ApiAttackGraph | null>(`/api/v1/scans/${scanId}/attack-graph`, null),
    apiFetch<ApiTimelineEvent[]>(`/api/v1/scans/${scanId}/timeline`),
    apiFetch<ApiEvidenceReference[]>(`/api/v1/scans/${scanId}/evidence`),
    apiFetchOptional<ApiScanReport | null>(`/api/v1/scans/${scanId}/report`, null),
  ])

  const aiReasoning = isTerminalScanStatus(scan.status)
    ? await getScanAiReasoning(scanId, { advisoryMode: options?.advisoryMode })
    : null

  const asset = await fetchAsset(scan.asset_id).catch(() => undefined)
  const project =
    asset?.project_id != null
      ? await fetchProject(asset.project_id).catch(() => undefined)
      : undefined
  const severityCounts = aggregateSeverityCounts(findingsResponse.items)

  return {
    scan: toScanSummary(scan, asset, severityCounts),
    asset: asset
      ? {
          ...asset,
          project,
        }
      : undefined,
    jobs: jobs.sort((left, right) => left.phase - right.phase),
    findings: findingsResponse.items,
    artifacts,
    attackGraph,
    timeline,
    evidence,
    report,
    aiReasoning,
    isTerminal: isTerminalScanStatus(scan.status),
  }
}
