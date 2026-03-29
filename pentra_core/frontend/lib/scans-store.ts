"use client"

export type UiScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled"
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
  | "cancelled"

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
  scheduled_at: string | null
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
  node_id: string | null
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
  scheduled_at: string | null
  claimed_at: string | null
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  retry_count: number
  queue_delay_seconds: number | null
  claim_to_start_seconds: number | null
  execution_duration_seconds: number | null
  end_to_end_seconds: number | null
  execution_mode: string | null
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | "derived" | null
  execution_reason: string | null
  execution_class: "external_tool" | "pentra_native" | string | null
  policy_state: "auto_live" | "approval_required" | "approved" | "blocked" | "derived" | "unsupported" | null
  output_ref: string | null
  created_at: string
}

export type FindingTruthState =
  | "observed"
  | "suspected"
  | "reproduced"
  | "verified"
  | "rejected"
  | "expired"

export interface ApiFindingTruthSummary {
  state: FindingTruthState
  promoted: boolean
  provenance_complete: boolean
  replayable: boolean
  evidence_reference_count: number
  raw_evidence_present: boolean
  scan_job_bound: boolean
  notes: string[]
}

export type VerificationPipelineStage =
  | "verified"
  | "reproduced"
  | "queued"
  | "needs_evidence"
  | "rejected"
  | "expired"

export interface ApiVerificationPipelineTypeSummary {
  vulnerability_type: string
  total_findings: number
  verified: number
  reproduced: number
  queued: number
  needs_evidence: number
  rejected: number
  expired: number
  highest_severity: string
  verified_share: number
  proof_ready_share: number
}

export interface ApiVerificationPipelineQueueItem {
  finding_id: string
  title: string
  vulnerability_type: string
  target: string
  route_group: string | null
  severity: string
  verification_state: string | null
  truth_state: FindingTruthState
  queue_state: VerificationPipelineStage
  readiness_reason: string
  required_actions: string[]
  provenance_complete: boolean
  replayable: boolean
  evidence_reference_count: number
  raw_evidence_present: boolean
  scan_job_bound: boolean
}

export interface ApiVerificationPipelineSummary {
  profile_id: string | null
  scan_type: string
  overall: {
    total_findings: number
    verified: number
    reproduced: number
    queued: number
    needs_evidence: number
    rejected: number
    expired: number
    verified_share: number
    proof_ready_share: number
  }
  by_type: ApiVerificationPipelineTypeSummary[]
  queue: ApiVerificationPipelineQueueItem[]
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
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | "derived" | null
  execution_reason: string | null
  verification_state: "detected" | "suspected" | "verified" | null
  verification_confidence: number | null
  verified_at: string | null
  truth_state: FindingTruthState
  truth_summary: ApiFindingTruthSummary
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
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | "derived" | null
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

export interface ApiTargetModelOverview {
  endpoint_count: number
  authenticated_endpoint_count: number
  api_endpoint_count: number
  route_group_count: number
  workflow_edge_count: number
  technology_count: number
  parameter_count: number
  auth_surface_count: number
  finding_count: number
  source_artifact_types: string[]
  truth_counts: Record<string, number>
  severity_counts: Record<string, number>
}

export interface ApiTargetModelEndpoint {
  url: string
  host: string | null
  path: string
  route_group: string
  surface: string
  requires_auth: boolean
  auth_variants: string[]
  methods: string[]
  parameter_names: string[]
  hidden_parameter_names: string[]
  technologies: string[]
  finding_count: number
  vulnerability_types: string[]
  truth_counts: Record<string, number>
  severity_counts: Record<string, number>
  has_csrf: boolean
  safe_replay: boolean
  origin: "observed" | "seeded_probe" | "finding_derived" | "workflow_derived" | string
  origins: string[]
}

export interface ApiTargetModelRouteGroup {
  route_group: string
  endpoint_count: number
  requires_auth: boolean
  auth_variants: string[]
  methods: string[]
  parameter_names: string[]
  technologies: string[]
  finding_count: number
  vulnerability_types: string[]
  truth_counts: Record<string, number>
  severity_counts: Record<string, number>
  focus_score: number
  origin: "observed" | "seeded_probe" | "finding_derived" | "workflow_derived" | string
  origins: string[]
}

export interface ApiTargetModelTechnology {
  technology: string
  endpoint_count: number
  route_groups: string[]
  surfaces: string[]
}

export interface ApiTargetModelParameter {
  name: string
  locations: string[]
  endpoint_count: number
  route_groups: string[]
  related_vulnerability_types: string[]
  related_truth_states: string[]
  likely_sensitive: boolean
}

export interface ApiTargetModelAuthSurface {
  label: string
  auth_state: string
  endpoint_count: number
  route_groups: string[]
  csrf_form_count: number
  safe_replay_count: number
}

export interface ApiTargetModelWorkflowEdge {
  source_url: string
  target_url: string
  action: string
  source_route_group: string
  target_route_group: string
  requires_auth: boolean
}

export interface ApiTargetModelPlannerFocus {
  route_group: string
  objective: string
  reason: string
  requires_auth: boolean
  focus_score: number
  vulnerability_types: string[]
  parameter_names: string[]
}

export interface ApiScanTargetModel {
  scan_id: string
  tenant_id: string
  asset_id: string
  asset_name: string
  target: string
  generated_at: string
  overview: ApiTargetModelOverview
  endpoints: ApiTargetModelEndpoint[]
  route_groups: ApiTargetModelRouteGroup[]
  technologies: ApiTargetModelTechnology[]
  parameters: ApiTargetModelParameter[]
  auth_surfaces: ApiTargetModelAuthSurface[]
  workflows: ApiTargetModelWorkflowEdge[]
  planner_focus: ApiTargetModelPlannerFocus[]
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

function mergeEvidenceReference(
  current: ApiEvidenceReference,
  incoming: ApiEvidenceReference
): ApiEvidenceReference {
  const currentContent = current.content ?? ""
  const incomingContent = incoming.content ?? ""
  const currentPreview = current.content_preview ?? ""
  const incomingPreview = incoming.content_preview ?? ""

  return {
    ...current,
    ...incoming,
    finding_id: current.finding_id ?? incoming.finding_id,
    finding_title: current.finding_title ?? incoming.finding_title,
    tool_source: current.tool_source ?? incoming.tool_source,
    content: currentContent.length >= incomingContent.length ? current.content : incoming.content,
    content_preview:
      currentPreview.length >= incomingPreview.length ? current.content_preview : incoming.content_preview,
    storage_ref: current.storage_ref ?? incoming.storage_ref,
    metadata: {
      ...(incoming.metadata ?? {}),
      ...(current.metadata ?? {}),
    },
  }
}

function dedupeEvidenceReferences(evidence: ApiEvidenceReference[]): ApiEvidenceReference[] {
  const merged = new Map<string, ApiEvidenceReference>()

  for (const item of evidence) {
    const existing = merged.get(item.id)
    if (!existing) {
      merged.set(item.id, item)
      continue
    }
    merged.set(item.id, mergeEvidenceReference(existing, item))
  }

  return Array.from(merged.values())
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
  verification_pipeline: ApiVerificationPipelineSummary
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
      truth_state?: FindingTruthState
      truth_summary?: ApiFindingTruthSummary
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
  export_formats: Array<"markdown" | "json" | "csv" | "html">
  top_findings: Array<{
    id: string
    title: string
    severity: string
    vulnerability_type?: string | null
    verification_state: string | null
    verification_confidence: number | null
    truth_state?: FindingTruthState
    truth_summary?: ApiFindingTruthSummary
    cvss_score: number | null
    description: string | null
    remediation: string | null
  }>
  markdown: string
}

export type ReportExportFormat = "markdown" | "json" | "csv" | "html"

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

export interface ApiAiProviderProbe {
  status: string
  latency_ms?: number
  preview?: string
  error?: string
}

export interface ApiAiProviderDiagnosticsEntry {
  provider: string
  task_type: string
  model_tier: string
  configured: boolean
  model: string
  base_url: string
  request_surface: string
  requires_api_key: boolean
  api_key_configured: boolean
  operator_state: string
  probe?: ApiAiProviderProbe
}

export interface ApiAiProviderDiagnostics {
  generated_at: string
  enabled: boolean
  provider_priority: string[]
  effective_provider_priority: string[]
  operator_state: string
  configuration_ready: boolean
  configured_provider_count: number
  healthy_provider_count: number
  fallback_provider_count: number
  last_failure: string | null
  tasks: Record<string, ApiAiProviderDiagnosticsEntry[]>
}

export interface ApiSystemStatus {
  status: "ok" | "degraded"
  version: string
  uptime_seconds: number
  services: Record<string, string>
}

export interface ApiAuthRuntime {
  dev_auth_bypass_enabled: boolean
  google_oauth_configured: boolean
  auth_methods: string[]
}

export interface ApiCurrentUser {
  id: string
  tenant_id: string
  email: string
  full_name: string | null
  avatar_url: string | null
  is_active: boolean
  roles: string[]
  created_at: string
}

export interface ApiTokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface ApiTargetProfileHypothesis {
  key: string
  confidence: number
  evidence: string[]
  preferred_capability_pack_keys: string[]
  planner_bias_rules: string[]
  benchmark_target_keys: string[]
}

export interface ApiCapabilityPressure {
  pack_key: string
  pressure_score: number
  target_profile?: string | null
  target_profile_keys: string[]
  challenge_family_keys: string[]
  planner_action_keys: string[]
  proof_contract_keys: string[]
  top_route_groups: string[]
  advisory_ready: boolean
  advisory_mode?: string | null
  negative_evidence_count: number
  advisory_artifact_ref?: string | null
  graph_keys?: string[]
  graph_target_profile_keys?: string[]
  graph_planner_action_keys?: string[]
  graph_proof_contract_keys?: string[]
  graph_rationale?: string[]
}

export interface ApiScanPlannerContext {
  scan_id: string
  target_profile_hypotheses: ApiTargetProfileHypothesis[]
  capability_pressures: ApiCapabilityPressure[]
  advisory_artifact_refs: Array<{ pack_key: string; storage_ref: string }>
  planner_decision: string | null
  strategic_plan: Record<string, unknown> | null
  tactical_plan: Record<string, unknown> | null
  planner_effect: Record<string, unknown> | null
  capability_advisories: Record<string, unknown>[]
}

export interface ApiAgentTranscriptEntry {
  id: string
  timestamp: string
  kind: "capability_advisory" | "planner_effect" | "ai_strategy" | "ai_reasoning" | "timeline_event"
  pack_key: string | null
  provider: string | null
  model: string | null
  transport: string | null
  fallback_status: "healthy" | "fallback" | "error" | "deterministic" | "unknown"
  summary: string
  raw_payload: Record<string, unknown> | unknown[] | null
  artifact_ref: string | null
}

export interface ApiAgentTranscriptResponse {
  scan_id: string
  generated_at: string
  entries: ApiAgentTranscriptEntry[]
}

export interface ApiToolExecutionLogEntry {
  node_id: string
  tool: string
  worker_family: string
  phase_number: number
  phase_name: string
  status: string
  job_id: string | null
  job_status: string | null
  started_at: string | null
  completed_at: string | null
  duration_ms: number
  execution_mode: string
  execution_provenance: "live" | "simulated" | "blocked" | "inferred" | "derived" | string
  execution_reason: string | null
  execution_class: "external_tool" | "pentra_native" | string | null
  policy_state: "auto_live" | "approval_required" | "approved" | "blocked" | "derived" | "unsupported" | null
  runtime_stage:
    | "queued"
    | "container_starting"
    | "command_resolved"
    | "streaming"
    | "completed"
    | "failed"
    | "blocked"
    | "stalled"
    | null
  last_chunk_at: string | null
  stream_complete: boolean
  error_message: string | null
  item_count: number
  finding_count: number
  storage_ref: string | null
  command: string[]
  display_command: string
  tool_binary: string | null
  container_image: string | null
  entrypoint: string[]
  working_dir: string | null
  canonical_command: ApiCanonicalCommandRecord | null
  stdout_preview: string
  stderr_preview: string
  exit_code: number | null
  full_stdout_artifact_ref: string | null
  full_stderr_artifact_ref: string | null
  command_artifact_ref: string | null
  session_artifact_ref: string | null
}

export interface ApiCanonicalCommandRecord {
  argv: string[]
  display_command: string
  tool_binary: string | null
  container_image: string | null
  entrypoint: string[]
  working_dir: string | null
  channel: "container" | "native" | "unknown" | string
  execution_class: "external_tool" | "pentra_native" | string
  policy_state:
    | "auto_live"
    | "approval_required"
    | "approved"
    | "blocked"
    | "derived"
    | "unsupported"
    | null
}

export interface ApiToolExecutionLogResponse {
  scan_id: string
  total: number
  logs: ApiToolExecutionLogEntry[]
}

export interface ApiToolExecutionLogContentResponse {
  scan_id: string
  storage_ref: string
  content_type: "stdout" | "stderr" | "command"
  content: string
}

export interface ApiJobSessionFrame {
  channel: "command" | "stdout" | "stderr" | "system"
  chunk_seq: number
  chunk_text: string
  timestamp: string | null
  artifact_ref: string | null
}

export interface ApiJobSessionResponse {
  scan_id: string
  job_id: string
  node_id: string | null
  tool: string
  status: string
  policy_state: "auto_live" | "approval_required" | "approved" | "blocked" | "derived" | "unsupported"
  execution_provenance: string | null
  execution_reason: string | null
  execution_class: "external_tool" | "pentra_native" | string | null
  runtime_stage:
    | "queued"
    | "container_starting"
    | "command_resolved"
    | "streaming"
    | "completed"
    | "failed"
    | "blocked"
    | "stalled"
    | null
  last_chunk_at: string | null
  stream_complete: boolean
  started_at: string | null
  completed_at: string | null
  exit_code: number | null
  command: string[]
  display_command: string
  tool_binary: string | null
  container_image: string | null
  entrypoint: string[]
  working_dir: string | null
  canonical_command: ApiCanonicalCommandRecord | null
  command_artifact_ref: string | null
  full_stdout_artifact_ref: string | null
  full_stderr_artifact_ref: string | null
  session_artifact_ref: string | null
  frames: ApiJobSessionFrame[]
}

export interface ApiScanStreamEvent {
  event_type:
    | "ws.connected"
    | "ws.heartbeat"
    | "ws.closing"
    | "scan.progress"
    | "scan.phase"
    | "scan.node"
    | "scan.job"
    | "scan.command"
    | "scan.advisory"
    | "scan.status"
    | "scan.finding"
  scan_id?: string | null
  timestamp?: string | null
  message?: string | null
  reason?: string | null
  progress?: number | null
  phase?: string | null
  phase_number?: number | null
  phase_name?: string | null
  phase_status?: string | null
  node_id?: string | null
  job_id?: string | null
  tool?: string | null
  status?: string | null
  execution_provenance?: string | null
  execution_reason?: string | null
  execution_class?: string | null
  policy_state?: "auto_live" | "approval_required" | "approved" | "blocked" | "derived" | "unsupported" | null
  runtime_stage?:
    | "queued"
    | "container_starting"
    | "command_resolved"
    | "streaming"
    | "completed"
    | "failed"
    | "blocked"
    | "stalled"
    | null
  last_chunk_at?: string | null
  stream_complete?: boolean | null
  command?: string[]
  display_command?: string | null
  tool_binary?: string | null
  container_image?: string | null
  entrypoint?: string[]
  working_dir?: string | null
  channel?: "command" | "stdout" | "stderr" | "system" | null
  chunk_text?: string | null
  chunk_seq?: number | null
  stdout_preview?: string | null
  stderr_preview?: string | null
  exit_code?: number | null
  duration_ms?: number | null
  artifact_ref?: string | null
  full_stdout_artifact_ref?: string | null
  full_stderr_artifact_ref?: string | null
  command_artifact_ref?: string | null
  session_artifact_ref?: string | null
  pack_key?: string | null
  provider?: string | null
  model?: string | null
  transport?: string | null
  fallback_status?: string | null
  summary?: Record<string, unknown>
  old_status?: string | null
  new_status?: string | null
  severity?: string | null
  title?: string | null
  count?: number | null
}

export interface ApiFieldValidationAssessment {
  generated_at: string
  scan_id: string
  asset_id?: string | null
  asset_name?: string | null
  target: string
  status: string
  profile_id?: string | null
  profile_variant: string
  operating_mode: "field_validation" | "benchmark" | "standard"
  benchmark_inputs_enabled: boolean
  benchmark_inputs_disabled_confirmed: boolean
  target_profile_guess?: string | null
  target_profile_hypotheses: ApiTargetProfileHypothesis[]
  selected_capability_packs: string[]
  approved_live_tools: string[]
  approval_required_tools: string[]
  approval_pending_tools: string[]
  tool_policy_states: Array<{
    tool: string
    policy_state: string
  }>
  blocked_tools: Array<{
    tool: string
    reason: string
    provenance: string
    policy_state?: string
  }>
  proof_ready_attempts: number
  heuristic_only_attempts: number
  verification_outcomes: Record<string, number>
  evidence_gaps: string[]
  ai_policy_state: string
  ai_provider?: string | null
  ai_model?: string | null
  ai_transport?: string | null
  ai_fallback_active: boolean
  ai_failure_reason?: string | null
  assessment_state: "verified" | "reproduced" | "detected" | "needs_evidence" | "no_findings"
  summary: string
}

export interface ApiFieldValidationSummaryItem {
  scan_id: string
  asset_name?: string | null
  target: string
  status: string
  target_profile_guess?: string | null
  selected_capability_packs: string[]
  verified: number
  reproduced: number
  detected: number
  needs_evidence: number
  assessment_state: "verified" | "reproduced" | "detected" | "needs_evidence" | "no_findings"
  benchmark_inputs_disabled_confirmed: boolean
  generated_at: string
}

export interface ApiFieldValidationSummary {
  generated_at: string
  total_scans: number
  by_state: Record<string, number>
  items: ApiFieldValidationSummaryItem[]
}

export interface ApiToolApprovalResult {
  tool: string
  disposition: "approved" | "already_approved" | "requeued" | "skipped" | "error"
  message: string
  node_id: string | null
  job_id: string | null
}

export interface ApiToolApprovalResponse {
  scan_id: string
  approved_tools: string[]
  generated_at: string
  results: ApiToolApprovalResult[]
}

export interface ApiScanProfilePreflightResponse {
  contract: ApiScanProfileContract
  target_context: Record<string, unknown>
  target_profile_hypotheses: ApiTargetProfileHypothesis[]
  execution_contract: Record<string, unknown>
  scope_authorization: Record<string, unknown>
  auth_material: Record<string, unknown>
  repository_context: Record<string, unknown>
  rate_limit_policy: Record<string, unknown>
  safe_replay_policy: Record<string, unknown>
  ai_provider_readiness: Record<string, unknown>
  benchmark_inputs_enabled: boolean
  approved_live_tools: string[]
  warnings: string[]
  blocking_issues: string[]
  can_launch: boolean
}

export interface ScanProfilePreflightInput {
  assetType: ApiAsset["asset_type"]
  target: string
  contractId: string
  scanMode: string
  methodology?: string | null
  authorizationAcknowledged: boolean
  approvedLiveTools?: string[]
  credentials?: Record<string, unknown>
  repository?: Record<string, unknown>
  scope?: Record<string, unknown>
}

export interface ApiIntelligenceOverview {
  total_scans: number
  completed_scans: number
  active_scans: number
  assets_with_history: number
  verified_findings: number
  recurring_patterns: number
  technology_clusters: number
  route_groups: number
  trending_patterns: number
  tracked_assets: number
}

export interface ApiIntelligencePatternMatch {
  key: string
  title: string
  vulnerability_type: string | null
  route_group: string | null
  tool_sources: string[]
  scan_count: number
  finding_count: number
  highest_severity: "critical" | "high" | "medium" | "low" | "info"
  severity_counts: Record<string, number>
  verification_counts: Record<string, number>
  last_seen: string | null
}

export interface ApiIntelligenceTechnologyCluster {
  technology: string
  asset_count: number
  scan_count: number
  endpoint_count: number
  finding_count: number
  severity_counts: Record<string, number>
  related_assets: string[]
  related_targets: string[]
}

export interface ApiIntelligenceRouteGroup {
  route_group: string
  asset_targets: string[]
  scan_count: number
  finding_count: number
  highest_severity: "critical" | "high" | "medium" | "low" | "info"
  severity_counts: Record<string, number>
  verification_counts: Record<string, number>
  vulnerability_types: string[]
}

export interface ApiIntelligenceSurfaceExpansion {
  scan_id: string
  asset_id: string
  asset_name: string
  target: string
  generated_at: string | null
  discovered_targets: number
  discovered_forms: number
  technologies: string[]
  artifact_types: string[]
}

export interface ApiIntelligenceExploitTrend {
  scan_id: string
  asset_name: string
  generated_at: string | null
  verified: number
  suspected: number
  detected: number
}

export interface ApiIntelligenceRetestDelta {
  scan_id: string
  baseline_scan_id: string | null
  asset_name: string
  target: string
  generated_at: string | null
  summary: string
  counts: Record<string, number>
}

export interface ApiIntelligenceAdvisorySummary {
  scan_id: string
  asset_name: string
  generated_at: string | null
  advisory_mode: AiAdvisoryMode | null
  provider: string | null
  model: string | null
  draft_summary: string
  prioritization_notes: string | null
  remediation_focus: string[]
}

export interface ApiIntelligenceTrendingPattern {
  vulnerability_type: string
  recent_count: number
  previous_count: number
  direction: "new" | "increasing" | "decreasing" | "stable"
  delta: number
}

export interface ApiIntelligenceTargetKnowledge {
  asset_id: string
  asset_name: string
  target: string
  scan_count: number
  known_endpoints: number
  known_forms: number
  known_technologies: string[]
  known_auth_surfaces: string[]
  known_vulnerability_types: string[]
  first_seen: string | null
  last_seen: string | null
}

export interface ApiIntelligenceSummary {
  generated_at: string
  definition: string
  overview: ApiIntelligenceOverview
  pattern_matches: ApiIntelligencePatternMatch[]
  technology_clusters: ApiIntelligenceTechnologyCluster[]
  route_groups: ApiIntelligenceRouteGroup[]
  surface_expansions: ApiIntelligenceSurfaceExpansion[]
  exploit_trends: ApiIntelligenceExploitTrend[]
  retest_deltas: ApiIntelligenceRetestDelta[]
  advisory_summaries: ApiIntelligenceAdvisorySummary[]
  trending_patterns: ApiIntelligenceTrendingPattern[]
  target_knowledge: ApiIntelligenceTargetKnowledge[]
}

export interface ApiAssetHistoryEntry {
  scan_id: string
  scan_type: ScanType
  status: RawScanStatus
  priority: ScanPriority
  generated_at: string | null
  started_at: string | null
  completed_at: string | null
  severity_counts: Record<string, number>
  verification_counts: Record<string, number>
  total_findings: number
  comparison_summary: string | null
  comparison_counts: Record<string, number>
  baseline_scan_id: string | null
}

export interface ApiAssetHistory {
  asset_id: string
  asset_name: string
  target: string
  generated_at: string
  total_scans: number
  known_technologies: string[]
  tracked_vulnerability_types: string[]
  entries: ApiAssetHistoryEntry[]
}

export interface ApiHistoricalFindingOccurrence {
  id: string
  scan_id: string
  finding_id: string | null
  severity: string
  verification_state: string | null
  source_type: string
  observed_at: string
}

export interface ApiHistoricalFinding {
  id: string
  asset_id: string
  lineage_key: string
  fingerprint: string
  title: string
  vulnerability_type: string | null
  route_group: string | null
  target: string
  latest_severity: string
  latest_verification_state: string | null
  latest_source_type: string
  first_seen_scan_id: string | null
  first_seen_at: string
  last_seen_scan_id: string | null
  last_seen_at: string
  latest_finding_id: string | null
  occurrence_count: number
  status: "active" | "resolved"
  recent_occurrences: ApiHistoricalFindingOccurrence[]
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface VerificationCounts {
  verified: number
  suspected: number
  detected: number
}

export interface ExecutionSummary {
  live: number
  simulated: number
  blocked: number
  inferred: number
  derived: number
}

export interface ApiScanProfileContract {
  contract_id: string
  scan_type: ScanType
  profile_id: string
  profile_variant: string
  name: string
  description: string
  duration: string
  priority: ScanPriority
  execution_mode: string
  target_policy: string
  scope_summary: string
  target_profile_keys: string[]
  requires_preflight: boolean
  benchmark_inputs_enabled: boolean
  scheduled_tools: string[]
  live_tools: string[]
  approval_required_tools: string[]
  conditional_live_tools: string[]
  derived_tools: string[]
  unsupported_tools: string[]
  guardrails: string[]
  honesty_notes: string[]
  sellable: boolean
}

export interface Scan {
  id: string
  name: string
  target: string
  status: UiScanStatus
  rawStatus: RawScanStatus
  statusLabel: string
  startedAt: string
  scheduledAt: string
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
  executionContract: ApiScanProfileContract | null
  findings: Omit<SeverityCounts, "info">
  executionLogs?: Array<{
    tool_id: string
    phase: string
    command: string[]
    stdout: string
    stderr: string
    exit_code: number
    duration_seconds: number
    timestamp: string
    description: string
  }>
}

export interface ScanAsset extends ApiAsset {
  project?: ApiProject
}

export interface ScanDetail {
  scan: Scan
  asset?: ScanAsset
  jobs: ApiScanJob[]
  toolLogs: ApiToolExecutionLogEntry[]
  liveJobSessions: Record<string, ApiJobSessionResponse>
  findings: ApiFinding[]
  artifacts: ApiArtifactSummary[]
  targetModel: ApiScanTargetModel | null
  plannerContext: ApiScanPlannerContext | null
  agentTranscript: ApiAgentTranscriptEntry[]
  fieldValidation: ApiFieldValidationAssessment | null
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
  scheduledAt?: string | null
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
const ACCESS_TOKEN_STORAGE_KEY = "pentra.auth.access_token"
const REFRESH_TOKEN_STORAGE_KEY = "pentra.auth.refresh_token"
const TOKEN_TYPE_STORAGE_KEY = "pentra.auth.token_type"
const EXPIRES_IN_STORAGE_KEY = "pentra.auth.expires_in"

const assetCache = new Map<string, ApiAsset>()
const projectCache = new Map<string, ApiProject>()
let refreshRequest: Promise<string | null> | null = null

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
  const normalized = value.replace(/\/+$/, "")

  if (typeof window === "undefined") {
    return normalized
  }

  try {
    const parsed = new URL(normalized)
    const browserHost = window.location.hostname
    const loopbackHosts = new Set(["localhost", "127.0.0.1"])

    if (
      loopbackHosts.has(parsed.hostname) &&
      loopbackHosts.has(browserHost) &&
      parsed.hostname !== browserHost
    ) {
      parsed.hostname = browserHost
      return parsed.toString().replace(/\/+$/, "")
    }
  } catch {
    return normalized
  }

  return normalized
}

export function getScanStreamUrl(scanId: string): string {
  const base = getApiBaseUrl()
  const wsBase = base.startsWith("https://")
    ? `wss://${base.slice("https://".length)}`
    : base.startsWith("http://")
      ? `ws://${base.slice("http://".length)}`
      : base
  const url = new URL(`${wsBase}/ws/scans/${scanId}`)
  const accessToken = getStoredAccessToken()
  const devToken = getDevAuthToken()
  const token = accessToken || devToken
  if (token) {
    url.searchParams.set("token", token)
  }
  return url.toString()
}

export function isDevAuthBypassEnabled(): boolean {
  return DEV_AUTH_MODE === "bypass"
}

export function getDevAuthToken(): string {
  return DEV_AUTH_TOKEN
}

function canUseBrowserStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined"
}

export function getStoredAccessToken(): string {
  if (!canUseBrowserStorage()) {
    return ""
  }
  return window.localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY) ?? ""
}

export function getStoredRefreshToken(): string {
  if (!canUseBrowserStorage()) {
    return ""
  }
  return window.localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY) ?? ""
}

export function clearStoredAuthTokens(): void {
  if (!canUseBrowserStorage()) {
    return
  }
  window.localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY)
  window.localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY)
  window.localStorage.removeItem(TOKEN_TYPE_STORAGE_KEY)
  window.localStorage.removeItem(EXPIRES_IN_STORAGE_KEY)
}

export function storeAuthTokens(tokens: ApiTokenResponse): void {
  if (!canUseBrowserStorage()) {
    return
  }
  window.localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, tokens.access_token)
  window.localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, tokens.refresh_token)
  window.localStorage.setItem(TOKEN_TYPE_STORAGE_KEY, tokens.token_type)
  window.localStorage.setItem(EXPIRES_IN_STORAGE_KEY, String(tokens.expires_in))
}

export function completeFrontendGoogleAuthFromHash(hash: string): boolean {
  const fragment = hash.startsWith("#") ? hash.slice(1) : hash
  const params = new URLSearchParams(fragment)
  const accessToken = params.get("access_token")?.trim() ?? ""
  const refreshToken = params.get("refresh_token")?.trim() ?? ""
  if (!accessToken || !refreshToken) {
    return false
  }

  storeAuthTokens({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: params.get("token_type")?.trim() || "bearer",
    expires_in: Number(params.get("expires_in") || "0") || 0,
  })
  return true
}

export function getGoogleLoginUrl(): string {
  return `${getApiBaseUrl()}/auth/google?mode=frontend`
}

export function buildApiHeaders(initHeaders?: HeadersInit): Headers {
  const headers = new Headers(initHeaders)

  if (!headers.has("Authorization")) {
    const accessToken = getStoredAccessToken()
    if (accessToken) {
      headers.set("Authorization", `Bearer ${accessToken}`)
    } else if (DEV_AUTH_TOKEN) {
      headers.set("Authorization", `Bearer ${DEV_AUTH_TOKEN}`)
    }
  }

  return headers
}

async function refreshStoredAuthTokens(): Promise<string | null> {
  const refreshToken = getStoredRefreshToken()
  if (!refreshToken) {
    clearStoredAuthTokens()
    return null
  }

  if (refreshRequest) {
    return refreshRequest
  }

  refreshRequest = (async () => {
    const response = await fetch(`${getApiBaseUrl()}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
      cache: "no-store",
    })

    if (!response.ok) {
      clearStoredAuthTokens()
      return null
    }

    const payload = (await response.json()) as ApiTokenResponse
    storeAuthTokens(payload)
    return payload.access_token
  })()

  try {
    return await refreshRequest
  } finally {
    refreshRequest = null
  }
}

async function apiFetch<T>(path: string, init?: RequestInit, allowRefresh: boolean = true): Promise<T> {
  const headers = buildApiHeaders(init?.headers)

  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  })

  if (response.status === 401 && allowRefresh) {
    const refreshedAccessToken = await refreshStoredAuthTokens()
    if (refreshedAccessToken) {
      return apiFetch<T>(path, init, false)
    }
    if (isDevAuthBypassEnabled() && !getStoredAccessToken()) {
      return apiFetch<T>(path, init, false)
    }
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

async function apiFetchOptional<T>(
  path: string,
  fallback: T,
  init?: RequestInit,
  allowRefresh: boolean = true
): Promise<T> {
  const headers = buildApiHeaders(init?.headers)

  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  let response: Response
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      ...init,
      headers,
      cache: "no-store",
    })
  } catch (error) {
    console.warn(`Optional API request failed for ${path}`, error)
    return fallback
  }

  if (response.status === 401 && allowRefresh) {
    const refreshedAccessToken = await refreshStoredAuthTokens()
    if (refreshedAccessToken) {
      return apiFetchOptional<T>(path, fallback, init, false)
    }
    if (isDevAuthBypassEnabled() && !getStoredAccessToken()) {
      return apiFetchOptional<T>(path, fallback, init, false)
    }
  }

  if (response.status === 404) {
    return fallback
  }

  if (!response.ok) {
    console.warn(`Optional API request returned ${response.status} for ${path}`)
    return fallback
  }

  const contentType = response.headers.get("content-type") ?? ""
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text()

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

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
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
    case "cancelled":
      return "cancelled"
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
  return rawStatus === "completed" || rawStatus === "failed" || rawStatus === "rejected" || rawStatus === "cancelled"
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

  if (rawStatus === "cancelled") {
    return {
      status,
      label: "Cancelled",
      textClass: "text-muted-foreground",
      dotClass: "bg-muted-foreground",
      bgClass: "bg-muted/50",
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
  provenance?: "live" | "simulated" | "blocked" | "inferred" | "derived" | null
): string {
  switch (provenance) {
    case "live":
      return "Live"
    case "simulated":
      return "Simulated"
    case "derived":
      return "Derived"
    case "blocked":
      return "Blocked"
    case "inferred":
      return "Inferred"
    default:
      return "Unknown"
  }
}

export function inferExecutionClass(tool?: string | null): "external_tool" | "pentra_native" {
  switch ((tool ?? "").trim().toLowerCase()) {
    case "scope_check":
    case "custom_poc":
    case "web_interact":
      return "pentra_native"
    default:
      return "external_tool"
  }
}

export function formatExecutionClass(
  executionClass?: "external_tool" | "pentra_native" | string | null
): string {
  switch ((executionClass ?? "").trim().toLowerCase()) {
    case "external_tool":
      return "External Tool"
    case "pentra_native":
      return "Pentra Native"
    default:
      return "Unknown"
  }
}

export function formatPolicyState(policyState?: string | null): string {
  switch ((policyState ?? "").trim().toLowerCase()) {
    case "auto_live":
      return "Auto Live"
    case "approval_required":
      return "Approval Required"
    case "approved":
      return "Approved"
    case "blocked":
      return "Blocked"
    case "derived":
      return "Derived"
    case "unsupported":
      return "Unsupported"
    default:
      return "Unknown"
  }
}

export function formatRuntimeStage(runtimeStage?: string | null): string {
  switch ((runtimeStage ?? "").trim().toLowerCase()) {
    case "queued":
      return "Queued"
    case "container_starting":
      return "Container Starting"
    case "command_resolved":
      return "Command Ready"
    case "streaming":
      return "Streaming"
    case "completed":
      return "Completed"
    case "failed":
      return "Failed"
    case "blocked":
      return "Blocked"
    case "stalled":
      return "Stalled"
    default:
      return "Unknown"
  }
}

export function isLiveRuntimeStage(runtimeStage?: string | null): boolean {
  switch ((runtimeStage ?? "").trim().toLowerCase()) {
    case "container_starting":
    case "command_resolved":
    case "streaming":
      return true
    default:
      return false
  }
}

export function formatTargetModelOrigin(origin?: string | null): string {
  switch ((origin ?? "").trim().toLowerCase()) {
    case "observed":
      return "Observed"
    case "seeded_probe":
      return "Seeded Probe"
    case "finding_derived":
      return "Finding Derived"
    case "workflow_derived":
      return "Workflow Derived"
    default:
      return origin?.trim() || "Unknown"
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
    case "derived_phase":
      return "Derived from persisted artifacts"
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

function normalizeVerificationCounts(input?: Partial<VerificationCounts>): VerificationCounts {
  return {
    verified: input?.verified ?? 0,
    suspected: input?.suspected ?? 0,
    detected: input?.detected ?? 0,
  }
}

function normalizeExecutionSummary(input?: Partial<ExecutionSummary>): ExecutionSummary {
  return {
    live: input?.live ?? 0,
    simulated: input?.simulated ?? 0,
    blocked: input?.blocked ?? 0,
    inferred: input?.inferred ?? 0,
    derived: input?.derived ?? 0,
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

export function extractVerificationCounts(
  summary: Record<string, unknown> | null | undefined
): VerificationCounts {
  if (!summary) {
    return normalizeVerificationCounts()
  }

  const candidate = summary["verification_counts"]
  if (typeof candidate === "object" && candidate !== null) {
    const values = candidate as Partial<Record<keyof VerificationCounts, unknown>>
    return normalizeVerificationCounts({
      verified: Number(values.verified ?? 0),
      suspected: Number(values.suspected ?? 0),
      detected: Number(values.detected ?? 0),
    })
  }

  return normalizeVerificationCounts()
}

export function extractExecutionSummary(
  summary: Record<string, unknown> | null | undefined
): ExecutionSummary {
  if (!summary) {
    return normalizeExecutionSummary()
  }

  const candidate = summary["execution_summary"]
  if (typeof candidate === "object" && candidate !== null) {
    const values = candidate as Partial<Record<keyof ExecutionSummary, unknown>>
    return normalizeExecutionSummary({
      live: Number(values.live ?? 0),
      simulated: Number(values.simulated ?? 0),
      blocked: Number(values.blocked ?? 0),
      inferred: Number(values.inferred ?? 0),
      derived: Number(values.derived ?? 0),
    })
  }

  return normalizeExecutionSummary()
}

function buildScanName(
  scan: ApiScan,
  asset: ApiAsset | undefined,
  executionContract: ApiScanProfileContract | null
): string {
  const label = executionContract?.name?.trim() || formatScanType(scan.scan_type)
  if (asset?.name) {
    return `${label} · ${asset.name}`
  }
  return `${label} · Asset ${scan.asset_id.slice(0, 8)}`
}

function extractExecutionContract(
  config: Record<string, unknown> | null | undefined
): ApiScanProfileContract | null {
  if (!config) {
    return null
  }

  const candidate = config["execution_contract"]
  if (typeof candidate !== "object" || candidate === null) {
    return null
  }

  const payload = candidate as Record<string, unknown>
  const scanType = payload["scan_type"]
  const priority = payload["priority"]
  if (
    (scanType !== "recon" &&
      scanType !== "vuln" &&
      scanType !== "full" &&
      scanType !== "exploit_verify") ||
    (priority !== "critical" &&
      priority !== "high" &&
      priority !== "normal" &&
      priority !== "low")
  ) {
    return null
  }

  return {
    contract_id: String(payload["contract_id"] ?? ""),
    scan_type: scanType,
    profile_id: String(payload["profile_id"] ?? ""),
    profile_variant: String(payload["profile_variant"] ?? "standard"),
    name: String(payload["name"] ?? ""),
    description: String(payload["description"] ?? ""),
    duration: String(payload["duration"] ?? ""),
    priority,
    execution_mode: String(payload["execution_mode"] ?? ""),
    target_policy: String(payload["target_policy"] ?? ""),
    scope_summary: String(payload["scope_summary"] ?? ""),
    target_profile_keys: isStringArray(payload["target_profile_keys"])
      ? payload["target_profile_keys"]
      : [],
    requires_preflight: Boolean(payload["requires_preflight"]),
    benchmark_inputs_enabled: Boolean(payload["benchmark_inputs_enabled"]),
    scheduled_tools: isStringArray(payload["scheduled_tools"]) ? payload["scheduled_tools"] : [],
    live_tools: isStringArray(payload["live_tools"]) ? payload["live_tools"] : [],
    approval_required_tools: isStringArray(payload["approval_required_tools"])
      ? payload["approval_required_tools"]
      : [],
    conditional_live_tools: isStringArray(payload["conditional_live_tools"])
      ? payload["conditional_live_tools"]
      : [],
    derived_tools: isStringArray(payload["derived_tools"]) ? payload["derived_tools"] : [],
    unsupported_tools: isStringArray(payload["unsupported_tools"])
      ? payload["unsupported_tools"]
      : [],
    guardrails: isStringArray(payload["guardrails"]) ? payload["guardrails"] : [],
    honesty_notes: isStringArray(payload["honesty_notes"]) ? payload["honesty_notes"] : [],
    sellable: Boolean(payload["sellable"]),
  }
}

export function toScanSummary(
  scan: ApiScan,
  asset?: ApiAsset,
  findings: SeverityCounts = extractSeverityCounts(scan.result_summary)
): Scan {
  const statusMeta = getScanStatusMeta(scan.status)
  const executionContract = extractExecutionContract(scan.config)
  const inferredStartedAt =
    scan.started_at ??
    (statusMeta.status === "queued" ? null : scan.created_at)

  return {
    id: scan.id,
    name: buildScanName(scan, asset, executionContract),
    target: asset?.target ?? "Resolving target...",
    status: statusMeta.status,
    rawStatus: scan.status,
    statusLabel: statusMeta.label,
    startedAt: inferredStartedAt ?? "",
    scheduledAt: scan.scheduled_at ?? "",
    completedAt: scan.completed_at ?? "",
    createdAt: scan.created_at,
    updatedAt: scan.updated_at,
    duration: formatDuration(inferredStartedAt, scan.completed_at),
    profile: executionContract?.name?.trim() || formatScanType(scan.scan_type),
    scanType: scan.scan_type,
    priority: scan.priority,
    progress: scan.progress,
    assetId: scan.asset_id,
    assetName: asset?.name ?? "Unknown Asset",
    errorMessage: scan.error_message,
    resultSummary: scan.result_summary,
    executionContract,
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
      scheduled_at: input.scheduledAt ?? null,
      config: input.config ?? {},
    }),
  })

  const asset = await fetchAsset(created.asset_id).catch(() => undefined)
  return toScanSummary(created, asset)
}

export async function listScanProfiles(params: {
  assetType: ApiAsset["asset_type"]
  target: string
}): Promise<ApiScanProfileContract[]> {
  const query = new URLSearchParams({
    asset_type: params.assetType,
    target: params.target,
  })
  return apiFetch<ApiScanProfileContract[]>(`/api/v1/scan-profiles?${query.toString()}`)
}

export async function runScanProfilePreflight(
  input: ScanProfilePreflightInput
): Promise<ApiScanProfilePreflightResponse> {
  return apiFetch<ApiScanProfilePreflightResponse>("/api/v1/scan-profiles/preflight", {
    method: "POST",
    body: JSON.stringify({
      asset_type: input.assetType,
      target: input.target,
      contract_id: input.contractId,
      scan_mode: input.scanMode,
      methodology: input.methodology ?? null,
      authorization_acknowledged: input.authorizationAcknowledged,
      approved_live_tools: input.approvedLiveTools ?? [],
      credentials: input.credentials ?? {},
      repository: input.repository ?? {},
      scope: input.scope ?? {},
    }),
  })
}

export async function listScanFindings(
  scanId: string,
  pageSize: number = 100
): Promise<ApiFinding[]> {
  const response = await apiFetch<PaginatedResponse<ApiFinding>>(
    `/api/v1/scans/${scanId}/findings?page=1&page_size=${pageSize}`
  )

  return response.items
}

export async function getScanAttackGraph(scanId: string): Promise<ApiAttackGraph | null> {
  return apiFetchOptional<ApiAttackGraph | null>(`/api/v1/scans/${scanId}/attack-graph`, null)
}

export async function getIntelligenceSummary(scanLimit: number = 100): Promise<ApiIntelligenceSummary> {
  return apiFetch<ApiIntelligenceSummary>(`/api/v1/intelligence/summary?scan_limit=${scanLimit}`)
}

export async function getAssetHistory(
  assetId: string,
  limit: number = 20
): Promise<ApiAssetHistory> {
  return apiFetch<ApiAssetHistory>(`/api/v1/intelligence/assets/${assetId}/history?limit=${limit}`)
}

export async function listAssetHistoricalFindings(options: {
  assetId: string
  page?: number
  pageSize?: number
  status?: "all" | "active" | "resolved"
  occurrenceLimit?: number
}): Promise<PaginatedResponse<ApiHistoricalFinding>> {
  const params = new URLSearchParams({
    page: String(options.page ?? 1),
    page_size: String(options.pageSize ?? 20),
    status_filter: options.status ?? "all",
    occurrence_limit: String(options.occurrenceLimit ?? 3),
  })
  return apiFetch<PaginatedResponse<ApiHistoricalFinding>>(
    `/api/v1/assets/${options.assetId}/historical-findings?${params.toString()}`
  )
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

export async function cancelScan(scanId: string): Promise<Scan> {
  const updated = await apiFetch<ApiScan>(`/api/v1/scans/${scanId}/cancel`, {
    method: "POST",
  })
  const asset = await fetchAsset(updated.asset_id).catch(() => undefined)
  return toScanSummary(updated, asset)
}

export async function downloadScanReportExport(
  scanId: string,
  format: ReportExportFormat
): Promise<void> {
  const headers = buildApiHeaders()
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
  anchor.download =
    match?.[1] ??
    `pentra-report-${scanId}.${format === "markdown" ? "md" : format === "html" ? "html" : format}`
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

export async function getAiProviderDiagnostics(
  live: boolean = false
): Promise<ApiAiProviderDiagnostics> {
  const params = new URLSearchParams()
  if (live) {
    params.set("live", "true")
  }
  const suffix = params.size > 0 ? `?${params.toString()}` : ""
  return apiFetch<ApiAiProviderDiagnostics>(`/api/v1/scans/ai/providers/diagnostics${suffix}`)
}

export async function getSystemStatus(): Promise<ApiSystemStatus> {
  return apiFetch<ApiSystemStatus>("/api/v1/system/status")
}

export async function getAuthRuntime(): Promise<ApiAuthRuntime> {
  return apiFetch<ApiAuthRuntime>("/auth/runtime")
}

export async function getCurrentUser(): Promise<ApiCurrentUser> {
  return apiFetch<ApiCurrentUser>("/auth/me")
}

export async function getScanPlannerContext(
  scanId: string
): Promise<ApiScanPlannerContext | null> {
  return apiFetchOptional<ApiScanPlannerContext | null>(
    `/api/v1/scans/${scanId}/planner-context`,
    null
  )
}

export async function getScanAgentTranscript(
  scanId: string
): Promise<ApiAgentTranscriptResponse | null> {
  return apiFetchOptional<ApiAgentTranscriptResponse | null>(
    `/api/v1/scans/${scanId}/agent-transcript`,
    null
  )
}

export async function getScanFieldValidationAssessment(
  scanId: string
): Promise<ApiFieldValidationAssessment | null> {
  return apiFetchOptional<ApiFieldValidationAssessment | null>(
    `/api/v1/scans/${scanId}/field-validation`,
    null
  )
}

export async function getFieldValidationSummary(
  limit: number = 10
): Promise<ApiFieldValidationSummary> {
  return apiFetch<ApiFieldValidationSummary>(
    `/api/v1/scans/field-validation/summary?limit=${limit}`
  )
}

export async function getScanToolLogs(
  scanId: string
): Promise<ApiToolExecutionLogResponse | null> {
  return apiFetchOptional<ApiToolExecutionLogResponse | null>(
    `/api/v1/scans/${scanId}/tool-logs`,
    null
  )
}

export async function getScanToolLogContent(
  scanId: string,
  storageRef: string
): Promise<ApiToolExecutionLogContentResponse | null> {
  const params = new URLSearchParams({ storage_ref: storageRef })
  return apiFetchOptional<ApiToolExecutionLogContentResponse | null>(
    `/api/v1/scans/${scanId}/tool-logs/content?${params.toString()}`,
    null
  )
}

export async function getScanJobSession(
  scanId: string,
  jobId: string
): Promise<ApiJobSessionResponse | null> {
  return apiFetchOptional<ApiJobSessionResponse | null>(
    `/api/v1/scans/${scanId}/jobs/${jobId}/session`,
    null
  )
}

export async function approveScanTools(
  scanId: string,
  tools: string[]
): Promise<ApiToolApprovalResponse> {
  return apiFetch<ApiToolApprovalResponse>(`/api/v1/scans/${scanId}/tool-approvals`, {
    method: "POST",
    headers: buildApiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ tools }),
  })
}

export async function getScanDetail(
  scanId: string,
  options?: { advisoryMode?: AiAdvisoryMode }
): Promise<ScanDetail> {
  const scan = await apiFetch<ApiScan>(`/api/v1/scans/${scanId}`)

  const [jobs, toolLogResponse, findingsResponse, artifacts, targetModel, plannerContext, agentTranscript, fieldValidation, attackGraph, timeline, evidence, report] = await Promise.all([
    apiFetch<ApiScanJob[]>(`/api/v1/scans/${scanId}/jobs`),
    apiFetchOptional<ApiToolExecutionLogResponse | null>(`/api/v1/scans/${scanId}/tool-logs`, null),
    apiFetch<PaginatedResponse<ApiFinding>>(
      `/api/v1/scans/${scanId}/findings?page=1&page_size=100`
    ),
    apiFetch<ApiArtifactSummary[]>(`/api/v1/scans/${scanId}/artifacts/summary`),
    apiFetchOptional<ApiScanTargetModel | null>(`/api/v1/scans/${scanId}/target-model`, null),
    apiFetchOptional<ApiScanPlannerContext | null>(`/api/v1/scans/${scanId}/planner-context`, null),
    apiFetchOptional<ApiAgentTranscriptResponse | null>(`/api/v1/scans/${scanId}/agent-transcript`, null),
    apiFetchOptional<ApiFieldValidationAssessment | null>(`/api/v1/scans/${scanId}/field-validation`, null),
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
  const toolLogs = toolLogResponse?.logs ?? []

  return {
    scan: {
      ...toScanSummary(scan, asset, severityCounts),
      executionLogs: toolLogs.map((entry) => ({
        tool_id: entry.tool,
        phase: entry.phase_name,
        command: entry.command,
        stdout: entry.stdout_preview,
        stderr: entry.stderr_preview,
        exit_code: entry.exit_code ?? -1,
        duration_seconds: entry.duration_ms > 0 ? entry.duration_ms / 1000 : 0,
        timestamp: entry.completed_at ?? entry.started_at ?? "",
        description: `${formatExecutionClass(entry.execution_class ?? inferExecutionClass(entry.tool))} · ${entry.execution_provenance} · ${entry.execution_reason ?? entry.status}`,
      })),
    },
    asset: asset
      ? {
          ...asset,
          project,
        }
      : undefined,
    jobs: jobs.sort((left, right) => left.phase - right.phase),
    toolLogs,
    liveJobSessions: {},
    findings: findingsResponse.items,
    artifacts,
    targetModel,
    plannerContext,
    agentTranscript: agentTranscript?.entries ?? [],
    fieldValidation,
    attackGraph,
    timeline,
    evidence: dedupeEvidenceReferences(evidence),
    report,
    aiReasoning,
    isTerminal: isTerminalScanStatus(scan.status),
  }
}
