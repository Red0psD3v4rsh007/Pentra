"use client"

import { useEffect, useMemo, useState } from "react"
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  Position,
  Handle,
  useEdgesState,
  useNodesState,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import {
  AlertTriangle,
  Crosshair,
  Filter,
  Globe,
  KeyRound,
  Network,
  Route,
  Server,
  ShieldCheck,
  Target,
  Workflow,
  Zap,
} from "lucide-react"

import { AIAdvisoryPanel } from "@/components/scans/ai-advisory-panel"
import {
  type AiAdvisoryMode,
  type ApiAttackGraph,
  type ApiAttackGraphEdge,
  type ApiAttackGraphNode,
  type ApiEvidenceReference,
  type ApiScanAiReasoning,
  type ApiScanReport,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type GraphNodeData = {
  label: string
  nodeType: string
  properties: Record<string, unknown>
}

type AttackViewMode = "paths" | "graph"
type GroupMode = "route_group" | "host" | "vulnerability_class" | "verification_state"
type Severity = "critical" | "high" | "medium" | "low" | "info"
type VerificationState = "verified" | "suspected" | "detected"

type ReportFinding = ApiScanReport["finding_groups"][number]["findings"][number]
type NarrativeStep = NonNullable<ApiScanReport["narrative"]>["steps"][number]

type DerivedFinding = ReportFinding & {
  groupId: string
  groupTitle: string
  groupSurface: string
  host: string
  routeGroup: string | null
  verificationState: VerificationState
  vulnerabilityType: string | null
  stateful: boolean
}

type AttackPathCluster = {
  id: string
  label: string
  subtitle: string
  host: string | null
  routeGroups: string[]
  vulnerabilityTypes: string[]
  verificationState: VerificationState
  severity: Severity
  findings: DerivedFinding[]
  evidence: ApiEvidenceReference[]
  relatedNodeIds: string[]
  exploitChain: boolean
  stateful: boolean
  targetsReached: string[]
  narrativeSummary: string
  narrativeSteps: NarrativeStep[]
}

type ProjectedGraph = {
  nodes: Node<GraphNodeData>[]
  edges: Edge[]
}

const COLUMN_X: Record<string, number> = {
  entrypoint: 40,
  asset: 260,
  service: 470,
  endpoint: 710,
  vulnerability: 980,
  credential: 1240,
  privilege: 1240,
}

const TYPE_THEME: Record<
  string,
  {
    icon: typeof Server
    iconClass: string
    borderClass: string
    badgeClass: string
  }
> = {
  entrypoint: {
    icon: Crosshair,
    iconClass: "text-primary",
    borderClass: "border-primary/30",
    badgeClass: "bg-primary/10 text-primary",
  },
  asset: {
    icon: Globe,
    iconClass: "text-muted-foreground",
    borderClass: "border-border",
    badgeClass: "bg-muted text-muted-foreground",
  },
  service: {
    icon: Network,
    iconClass: "text-low",
    borderClass: "border-low/30",
    badgeClass: "bg-low/10 text-low",
  },
  endpoint: {
    icon: Route,
    iconClass: "text-medium",
    borderClass: "border-medium/30",
    badgeClass: "bg-medium/10 text-medium",
  },
  vulnerability: {
    icon: AlertTriangle,
    iconClass: "text-critical",
    borderClass: "border-critical/30",
    badgeClass: "bg-critical/10 text-critical",
  },
  credential: {
    icon: KeyRound,
    iconClass: "text-high",
    borderClass: "border-high/30",
    badgeClass: "bg-high/10 text-high",
  },
  privilege: {
    icon: ShieldCheck,
    iconClass: "text-low",
    borderClass: "border-low/30",
    badgeClass: "bg-low/10 text-low",
  },
}

const severityBadgeClass: Record<Severity, string> = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-low/10 text-low",
  info: "bg-muted text-muted-foreground",
}

const verificationBadgeClass: Record<VerificationState, string> = {
  verified: "bg-low/10 text-low",
  suspected: "bg-medium/10 text-medium",
  detected: "bg-muted text-muted-foreground",
}

const groupModeOptions: Array<{ id: GroupMode; label: string }> = [
  { id: "route_group", label: "Route Group" },
  { id: "host", label: "Host" },
  { id: "vulnerability_class", label: "Vuln Class" },
  { id: "verification_state", label: "Verification" },
]

const statefulIndicators = [
  "auth",
  "idor",
  "bola",
  "tenant",
  "workflow",
  "business_logic",
  "session",
  "csrf",
  "access_control",
]

function GraphNodeCard({ data }: NodeProps<Node<GraphNodeData>>) {
  const theme = TYPE_THEME[data.nodeType] ?? TYPE_THEME.asset
  const Icon = theme.icon

  return (
    <div
      className={cn(
        "min-w-[190px] rounded-xl border bg-card px-4 py-3 shadow-sm",
        theme.borderClass
      )}
    >
      <Handle type="target" position={Position.Left} className="!bg-border" />
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-md bg-background p-2">
          <Icon className={cn("h-4 w-4", theme.iconClass)} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-foreground">{data.label}</p>
          <p className="mt-1 text-xs text-muted-foreground">{data.nodeType}</p>
          {typeof data.properties.member_count === "number" && Number(data.properties.member_count) > 1 ? (
            <p className="mt-1 text-[11px] text-muted-foreground">
              {String(data.properties.member_count)} merged nodes
            </p>
          ) : null}
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-border" />
    </div>
  )
}

const nodeTypes = {
  pentraNode: GraphNodeCard,
}

function safeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : ""
}

function safeLower(value: unknown): string {
  return safeString(value).toLowerCase()
}

function extractHost(target: string | null | undefined): string {
  const value = (target ?? "").trim()
  if (!value) {
    return ""
  }

  try {
    return new URL(value).host
  } catch {
    const sanitized = value.replace(/^https?:\/\//, "")
    return sanitized.split("/")[0] ?? sanitized
  }
}

function titleize(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function severityRank(value: string | null | undefined): number {
  switch (value) {
    case "critical":
      return 5
    case "high":
      return 4
    case "medium":
      return 3
    case "low":
      return 2
    default:
      return 1
  }
}

function verificationRank(value: string | null | undefined): number {
  switch (value) {
    case "verified":
      return 3
    case "suspected":
      return 2
    default:
      return 1
  }
}

function normalizeSeverity(value: string | null | undefined): Severity {
  switch (value) {
    case "critical":
    case "high":
    case "medium":
    case "low":
      return value
    default:
      return "info"
  }
}

function normalizeVerificationState(value: string | null | undefined): VerificationState {
  switch (value) {
    case "verified":
    case "suspected":
      return value
    default:
      return "detected"
  }
}

function routeGroupFromTarget(target: string): string | null {
  try {
    const url = new URL(target)
    const segments = url.pathname.split("/").filter(Boolean)
    if (segments.length === 0) {
      return "/"
    }
    if (segments.length === 1) {
      return `/${segments[0]}`
    }
    return `/${segments[0]}/${segments[1]}`
  } catch {
    return null
  }
}

function isStatefulFinding(vulnerabilityType: string | null | undefined, title: string): boolean {
  const fingerprint = `${vulnerabilityType ?? ""} ${title}`.toLowerCase()
  return statefulIndicators.some((indicator) => fingerprint.includes(indicator))
}

function asStringArray(values: Iterable<string>): string[] {
  return Array.from(new Set(Array.from(values).filter(Boolean)))
}

function deriveReportFindings(report: ApiScanReport | null, graph: ApiAttackGraph | null): DerivedFinding[] {
  if (report?.finding_groups.length) {
    return report.finding_groups.flatMap((group) =>
      group.findings.map((finding) => ({
        ...finding,
        groupId: group.group_id,
        groupTitle: group.title,
        groupSurface: group.surface,
        host: extractHost(finding.target),
        routeGroup: finding.route_group ?? routeGroupFromTarget(finding.target),
        verificationState: normalizeVerificationState(finding.verification_state),
        vulnerabilityType: finding.vulnerability_type ?? null,
        stateful: isStatefulFinding(finding.vulnerability_type, finding.title),
      }))
    )
  }

  if (!graph) {
    return []
  }

  return graph.nodes
    .filter((node) => node.node_type === "vulnerability")
    .map((node) => {
      const target =
        safeString(node.properties.target) ||
        safeString(node.properties.endpoint) ||
        safeString(node.properties.url) ||
        node.label
      const severity = normalizeSeverity(safeString(node.properties.severity) || "medium")

      return {
        id: node.id,
        title: node.label,
        severity,
        confidence: 0,
        vulnerability_type: null,
        target,
        route_group: routeGroupFromTarget(target),
        verification_state: "detected",
        verification_confidence: null,
        exploitability: null,
        surface: null,
        cvss_score: null,
        description: null,
        remediation: null,
        tool_source: safeString(node.properties.artifact_type) || "graph",
        created_at: "",
        groupId: node.id,
        groupTitle: target,
        groupSurface: "unknown",
        host: extractHost(target),
        routeGroup: routeGroupFromTarget(target),
        verificationState: "detected",
        vulnerabilityType: null,
        stateful: isStatefulFinding(null, node.label),
      }
    })
}

function evidenceMatchesFinding(evidence: ApiEvidenceReference, finding: DerivedFinding): boolean {
  if (evidence.finding_id && evidence.finding_id === finding.id) {
    return true
  }

  const evidenceTitle = (evidence.finding_title ?? evidence.label).toLowerCase()
  const findingTitle = finding.title.toLowerCase()
  if (evidenceTitle === findingTitle) {
    return true
  }

  return evidence.target.toLowerCase().includes(finding.target.toLowerCase())
}

function nodeMatchesFinding(node: ApiAttackGraphNode, finding: DerivedFinding): boolean {
  const nodeText = [
    node.label,
    safeString(node.properties.target),
    safeString(node.properties.endpoint),
    safeString(node.properties.url),
    safeString(node.properties.host),
    safeString(node.properties.route_group),
    safeString(node.properties.artifact_type),
  ]
    .join(" ")
    .toLowerCase()

  const target = finding.target.toLowerCase()
  const routeGroup = (finding.routeGroup ?? "").toLowerCase()
  const host = finding.host.toLowerCase()
  const title = finding.title.toLowerCase()
  const vulnerabilityType = (finding.vulnerabilityType ?? "").replace(/_/g, " ").toLowerCase()

  if (routeGroup && nodeText.includes(routeGroup)) {
    return true
  }
  if (target && nodeText.includes(target)) {
    return true
  }
  if (host && nodeText.includes(host)) {
    return true
  }
  if (title && nodeText.includes(title)) {
    return true
  }
  return Boolean(vulnerabilityType && nodeText.includes(vulnerabilityType))
}

function stepsForFinding(report: ApiScanReport | null, finding: DerivedFinding): NarrativeStep[] {
  const steps = report?.narrative?.steps ?? []
  const routeGroup = (finding.routeGroup ?? "").toLowerCase()
  const target = finding.target.toLowerCase()
  const host = finding.host.toLowerCase()

  const matched = steps.filter((step) => {
    const haystack = `${step.target} ${step.description}`.toLowerCase()
    return Boolean(
      (routeGroup && haystack.includes(routeGroup)) ||
        (target && haystack.includes(target)) ||
        (host && haystack.includes(host))
    )
  })

  return matched.length ? matched : steps.slice(0, 3)
}

function summarizeFinding(report: ApiScanReport | null, finding: DerivedFinding): string {
  const matchedSteps = stepsForFinding(report, finding)
  if (matchedSteps[0]?.description) {
    return matchedSteps[0].description
  }

  if (finding.description) {
    return finding.description
  }

  const routeText = finding.routeGroup ?? finding.target
  return `${finding.title} remains a meaningful path component on ${routeText}.`
}

function groupKeyForFinding(finding: DerivedFinding, groupMode: GroupMode): string {
  switch (groupMode) {
    case "host":
      return finding.host || finding.target
    case "vulnerability_class":
      return finding.vulnerabilityType ?? "unclassified"
    case "verification_state":
      return finding.verificationState
    default:
      return finding.routeGroup ?? finding.target
  }
}

function buildClusterSubtitle(
  finding: DerivedFinding,
  groupMode: GroupMode,
  findingCount: number,
  routeCount: number
): string {
  switch (groupMode) {
    case "host":
      return `${findingCount} finding${findingCount === 1 ? "" : "s"} across ${routeCount} route${routeCount === 1 ? "" : "s"}`
    case "vulnerability_class":
      return `${finding.host || finding.target} · ${findingCount} affected item${findingCount === 1 ? "" : "s"}`
    case "verification_state":
      return `${findingCount} finding${findingCount === 1 ? "" : "s"} in ${finding.verificationState} state`
    default:
      return finding.host || finding.target
  }
}

function deriveAttackPathClusters({
  graph,
  report,
  evidence,
  groupMode,
}: {
  graph: ApiAttackGraph | null
  report: ApiScanReport | null
  evidence: ApiEvidenceReference[]
  groupMode: GroupMode
}): AttackPathCluster[] {
  const findings = deriveReportFindings(report, graph)
  const targetsReached = report?.narrative?.targets_reached ?? []
  const nodeMap = new Map((graph?.nodes ?? []).map((node) => [node.id, node]))
  const graphEdges = graph?.edges ?? []

  const clusters = new Map<string, AttackPathCluster>()

  for (const finding of findings) {
    const key = groupKeyForFinding(finding, groupMode)
    const label =
      groupMode === "vulnerability_class"
        ? titleize(key)
        : groupMode === "verification_state"
          ? titleize(finding.verificationState)
          : key

    const relatedNodeIds = (graph?.nodes ?? [])
      .filter((node) => nodeMatchesFinding(node, finding))
      .map((node) => node.id)
    const relatedNodeSet = new Set(relatedNodeIds)
    const findingEvidence = evidence.filter((item) => evidenceMatchesFinding(item, finding))
    const matchedSteps = stepsForFinding(report, finding)
    const exploitChain =
      relatedNodeIds.some((nodeId) => {
        const node = nodeMap.get(nodeId)
        return node?.node_type === "privilege" || node?.node_type === "credential"
      }) ||
      graphEdges.some(
        (edge) =>
          relatedNodeSet.has(edge.source) &&
          ["exploit", "credential_usage", "lateral_movement", "privilege_escalation"].includes(edge.edge_type)
      ) ||
      finding.verificationState !== "detected"

    const existing = clusters.get(key)
    if (!existing) {
      const routeGroups = asStringArray([finding.routeGroup ?? ""])
      clusters.set(key, {
        id: `cluster:${groupMode}:${key}`,
        label,
        subtitle: buildClusterSubtitle(finding, groupMode, 1, routeGroups.length),
        host: finding.host || null,
        routeGroups,
        vulnerabilityTypes: asStringArray([finding.vulnerabilityType ?? ""]),
        verificationState: finding.verificationState,
        severity: normalizeSeverity(finding.severity),
        findings: [finding],
        evidence: findingEvidence,
        relatedNodeIds,
        exploitChain,
        stateful: finding.stateful,
        targetsReached: targetsReached.filter((target) =>
          `${target}`.toLowerCase().includes((finding.vulnerabilityType ?? finding.target).toLowerCase())
        ),
        narrativeSummary: summarizeFinding(report, finding),
        narrativeSteps: matchedSteps,
      })
      continue
    }

    existing.findings.push(finding)
    existing.routeGroups = asStringArray([...existing.routeGroups, finding.routeGroup ?? ""])
    existing.vulnerabilityTypes = asStringArray([...existing.vulnerabilityTypes, finding.vulnerabilityType ?? ""])
    existing.verificationState =
      verificationRank(finding.verificationState) > verificationRank(existing.verificationState)
        ? finding.verificationState
        : existing.verificationState
    existing.severity =
      severityRank(finding.severity) > severityRank(existing.severity) ? normalizeSeverity(finding.severity) : existing.severity
    existing.evidence = Array.from(
      new Map([...existing.evidence, ...findingEvidence].map((item) => [item.id, item])).values()
    )
    existing.relatedNodeIds = asStringArray([...existing.relatedNodeIds, ...relatedNodeIds])
    existing.exploitChain = existing.exploitChain || exploitChain
    existing.stateful = existing.stateful || finding.stateful
    existing.targetsReached = asStringArray([...existing.targetsReached, ...targetsReached])
    existing.narrativeSteps = Array.from(
      new Map([...existing.narrativeSteps, ...matchedSteps].map((step) => [`${step.step}:${step.target}`, step])).values()
    )
    if (!existing.narrativeSummary || existing.narrativeSummary.length < summarizeFinding(report, finding).length) {
      existing.narrativeSummary = summarizeFinding(report, finding)
    }
    existing.subtitle = buildClusterSubtitle(
      existing.findings[0],
      groupMode,
      existing.findings.length,
      existing.routeGroups.length || 1
    )
  }

  return Array.from(clusters.values()).sort((left, right) => {
    return (
      verificationRank(right.verificationState) - verificationRank(left.verificationState) ||
      severityRank(right.severity) - severityRank(left.severity) ||
      Number(right.exploitChain) - Number(left.exploitChain) ||
      right.evidence.length - left.evidence.length ||
      right.findings.length - left.findings.length ||
      left.label.localeCompare(right.label)
    )
  })
}

function matchesClusterFilters(
  cluster: AttackPathCluster,
  filters: {
    verifiedOnly: boolean
    criticalHighOnly: boolean
    exploitChainOnly: boolean
    statefulOnly: boolean
  }
): boolean {
  if (filters.verifiedOnly && cluster.verificationState !== "verified") {
    return false
  }
  if (filters.criticalHighOnly && !["critical", "high"].includes(cluster.severity)) {
    return false
  }
  if (filters.exploitChainOnly && !cluster.exploitChain) {
    return false
  }
  if (filters.statefulOnly && !cluster.stateful) {
    return false
  }
  return true
}

function isLowValueInferredEdge(edge: ApiAttackGraphEdge): boolean {
  return edge.properties?.inferred === true && edge.edge_type === "discovery"
}

function projectionKeyForNode(node: ApiAttackGraphNode): string {
  const host = safeLower(node.properties.host || node.properties.target)
  const routeGroup = safeLower(node.properties.route_group)
  const endpoint = safeLower(node.properties.endpoint || node.properties.url)
  const artifactType = safeLower(node.properties.artifact_type)

  switch (node.node_type) {
    case "asset":
      return `asset:${host || safeLower(node.label)}`
    case "service":
      return `service:${host || safeLower(node.label)}:${safeLower(node.properties.port || node.properties.service)}`
    case "endpoint":
      return `endpoint:${routeGroup || endpoint || safeLower(node.label)}`
    case "vulnerability":
      return `vulnerability:${safeLower(node.properties.target || node.label)}:${safeLower(node.label)}`
    case "credential":
    case "privilege":
      return `${node.node_type}:${safeLower(node.properties.target || node.label)}:${artifactType || safeLower(node.label)}`
    default:
      return node.id
  }
}

function projectionLabelForNode(node: ApiAttackGraphNode): string {
  return (
    safeString(node.properties.route_group) ||
    safeString(node.properties.host) ||
    safeString(node.properties.target) ||
    safeString(node.properties.endpoint) ||
    node.label
  )
}

function buildProjectedGraph(
  graph: ApiAttackGraph,
  cluster: AttackPathCluster | null,
  showAllEdges: boolean
): ProjectedGraph {
  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]))
  const relevantNodeIds = new Set<string>()

  if (cluster?.relatedNodeIds.length) {
    for (const nodeId of cluster.relatedNodeIds) {
      relevantNodeIds.add(nodeId)
    }
    for (const edge of graph.edges) {
      if (cluster.relatedNodeIds.includes(edge.source) || cluster.relatedNodeIds.includes(edge.target)) {
        relevantNodeIds.add(edge.source)
        relevantNodeIds.add(edge.target)
      }
    }
  } else {
    for (const node of graph.nodes) {
      relevantNodeIds.add(node.id)
    }
  }

  const candidateEdges = graph.edges.filter(
    (edge) =>
      relevantNodeIds.has(edge.source) &&
      relevantNodeIds.has(edge.target) &&
      (showAllEdges || !isLowValueInferredEdge(edge))
  )

  const relevantNodes = graph.nodes.filter((node) => relevantNodeIds.has(node.id))
  const projectedNodes = new Map<
    string,
    {
      id: string
      nodeType: ApiAttackGraphNode["node_type"]
      label: string
      artifactRef: string
      properties: Record<string, unknown>
      memberIds: string[]
    }
  >()

  for (const node of relevantNodes) {
    const projectionKey = projectionKeyForNode(node)
    const label = projectionLabelForNode(node)
    const existing = projectedNodes.get(projectionKey)
    if (!existing) {
      projectedNodes.set(projectionKey, {
        id: projectionKey,
        nodeType: node.node_type,
        label,
        artifactRef: node.artifact_ref,
        properties: {
          ...node.properties,
          member_count: 1,
          merged_labels: [node.label],
        },
        memberIds: [node.id],
      })
      continue
    }

    existing.memberIds.push(node.id)
    existing.label = existing.label.length <= label.length ? existing.label : label
    existing.properties = {
      ...existing.properties,
      member_count: existing.memberIds.length,
      merged_labels: asStringArray([
        ...(Array.isArray(existing.properties.merged_labels)
          ? existing.properties.merged_labels.map((value) => String(value))
          : []),
        node.label,
      ]),
      route_group: existing.properties.route_group || node.properties.route_group,
      host: existing.properties.host || node.properties.host,
      target: existing.properties.target || node.properties.target,
    }
  }

  const projectionForMember = new Map<string, string>()
  for (const [projectionId, projection] of projectedNodes.entries()) {
    for (const memberId of projection.memberIds) {
      projectionForMember.set(memberId, projectionId)
    }
  }

  const projectedEdges = new Map<string, Edge>()
  for (const edge of candidateEdges) {
    const source = projectionForMember.get(edge.source)
    const target = projectionForMember.get(edge.target)
    if (!source || !target || source === target) {
      continue
    }

    const edgeId = `${source}:${target}:${edge.edge_type}`
    const existing = projectedEdges.get(edgeId)
    if (!existing) {
      projectedEdges.set(edgeId, {
        id: edgeId,
        source,
        target,
        label: edge.edge_type,
        animated: edge.edge_type === "exploit",
        style: {
          stroke:
            edge.edge_type === "exploit"
              ? "#ef4444"
              : edge.edge_type === "privilege_escalation"
                ? "#22c55e"
                : edge.edge_type === "workflow"
                  ? "#0ea5e9"
                  : "#52525b",
          strokeWidth: edge.edge_type === "discovery" ? 1.5 : 2.25,
          opacity: edge.properties?.inferred === true ? 0.7 : 1,
        },
        labelStyle: { fontSize: 10, fill: "#a1a1aa" },
        data: {
          member_count: 1,
          inferred: edge.properties?.inferred === true,
        },
      })
      continue
    }

    const memberCount = Number(existing.data?.member_count ?? 1) + 1
    existing.label = `${edge.edge_type} x${memberCount}`
    existing.data = {
      ...existing.data,
      member_count: memberCount,
      inferred: Boolean(existing.data?.inferred) && edge.properties?.inferred === true,
    }
  }

  const rowCounts = new Map<string, number>()
  const nodes: Node<GraphNodeData>[] = Array.from(projectedNodes.values()).map((projection) => {
    const currentRow = rowCounts.get(projection.nodeType) ?? 0
    rowCounts.set(projection.nodeType, currentRow + 1)

    return {
      id: projection.id,
      type: "pentraNode",
      position: {
        x: COLUMN_X[projection.nodeType] ?? 240,
        y: 80 + currentRow * 150,
      },
      data: {
        label: projection.label,
        nodeType: projection.nodeType,
        properties: projection.properties,
      },
    }
  })

  return {
    nodes,
    edges: Array.from(projectedEdges.values()),
  }
}

function clusterStatText(cluster: AttackPathCluster): string {
  const counts = [
    `${cluster.findings.length} finding${cluster.findings.length === 1 ? "" : "s"}`,
    `${cluster.evidence.length} evidence`,
  ]
  if (cluster.routeGroups.length > 0) {
    counts.push(`${cluster.routeGroups.length} route${cluster.routeGroups.length === 1 ? "" : "s"}`)
  }
  return counts.join(" · ")
}

interface AttackGraphTabProps {
  graph: ApiAttackGraph | null
  report: ApiScanReport | null
  evidence: ApiEvidenceReference[]
  advisory: ApiScanAiReasoning | null
  advisoryMode: AiAdvisoryMode
  onChangeAdvisoryMode: (mode: AiAdvisoryMode) => void
  onRegenerateAdvisory: () => void
  isRegeneratingAdvisory: boolean
}

export function AttackGraphTab({
  graph,
  report,
  evidence,
  advisory,
  advisoryMode,
  onChangeAdvisoryMode,
  onRegenerateAdvisory,
  isRegeneratingAdvisory,
}: AttackGraphTabProps) {
  const [viewMode, setViewMode] = useState<AttackViewMode>("paths")
  const [groupMode, setGroupMode] = useState<GroupMode>("route_group")
  const [filters, setFilters] = useState({
    verifiedOnly: false,
    criticalHighOnly: false,
    exploitChainOnly: false,
    statefulOnly: false,
  })
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null)
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [showAllEdges, setShowAllEdges] = useState(false)

  const graphSummary = graph?.path_summary ?? {}
  const scoringSummary = graph?.scoring_summary ?? {}

  const allClusters = useMemo(
    () => deriveAttackPathClusters({ graph, report, evidence, groupMode }),
    [evidence, graph, groupMode, report]
  )

  const filteredClusters = useMemo(
    () => allClusters.filter((cluster) => matchesClusterFilters(cluster, filters)),
    [allClusters, filters]
  )

  useEffect(() => {
    if (filteredClusters.length === 0) {
      setSelectedClusterId(null)
      return
    }

    const stillSelected = filteredClusters.some((cluster) => cluster.id === selectedClusterId)
    if (!stillSelected) {
      setSelectedClusterId(filteredClusters[0].id)
    }
  }, [filteredClusters, selectedClusterId])

  const selectedCluster =
    filteredClusters.find((cluster) => cluster.id === selectedClusterId) ?? filteredClusters[0] ?? null

  useEffect(() => {
    if (!selectedCluster?.evidence.length) {
      setSelectedEvidenceId(null)
      return
    }

    const stillSelected = selectedCluster.evidence.some((item) => item.id === selectedEvidenceId)
    if (!stillSelected) {
      setSelectedEvidenceId(selectedCluster.evidence[0].id)
    }
  }, [selectedCluster, selectedEvidenceId])

  const selectedEvidence =
    selectedCluster?.evidence.find((item) => item.id === selectedEvidenceId) ??
    selectedCluster?.evidence[0] ??
    null

  const projectedGraph = useMemo(() => {
    if (!graph) {
      return { nodes: [], edges: [] }
    }
    return buildProjectedGraph(graph, selectedCluster, showAllEdges)
  }, [graph, selectedCluster, showAllEdges])

  const [nodes, setNodes, onNodesChange] = useNodesState(projectedGraph.nodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(projectedGraph.edges)

  useEffect(() => {
    setNodes(projectedGraph.nodes)
    setEdges(projectedGraph.edges)
    setSelectedNodeId(projectedGraph.nodes[0]?.id ?? null)
  }, [projectedGraph.edges, projectedGraph.nodes, setEdges, setNodes])

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? nodes[0] ?? null

  if (!graph || graph.node_count === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-10 text-center shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">Attack Graph Pending</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Complete at least one artifact-producing phase to materialize graph nodes and edges.
        </p>
      </div>
    )
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
      <div className="space-y-4">
        <div className="rounded-xl border border-border bg-card shadow-sm">
          <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
            <h2 className="text-sm font-semibold text-foreground">Attack Path Triage</h2>
            <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
              {graph.node_count} nodes
            </span>
            <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
              {graph.edge_count} edges
            </span>
            {"total_paths" in graphSummary ? (
              <span className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">
                {String(graphSummary.total_paths)} attack paths
              </span>
            ) : null}
            <div className="ml-auto flex flex-wrap gap-2">
              {(["paths", "graph"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setViewMode(mode)}
                  className={cn(
                    "rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors",
                    viewMode === mode
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border bg-background text-muted-foreground hover:text-foreground"
                  )}
                >
                  {mode === "paths" ? "Attack Paths" : "Focused Graph"}
                </button>
              ))}
            </div>
          </div>

          <div className="border-b border-border px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <Filter className="h-3.5 w-3.5" />
                Group By
              </span>
              {groupModeOptions.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => setGroupMode(option.id)}
                  className={cn(
                    "rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors",
                    groupMode === option.id
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border bg-background text-muted-foreground hover:text-foreground"
                  )}
                >
                  {option.label}
                </button>
              ))}
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              <FilterToggle
                active={filters.verifiedOnly}
                label="Verified Only"
                onToggle={() =>
                  setFilters((current) => ({ ...current, verifiedOnly: !current.verifiedOnly }))
                }
              />
              <FilterToggle
                active={filters.criticalHighOnly}
                label="Critical / High"
                onToggle={() =>
                  setFilters((current) => ({
                    ...current,
                    criticalHighOnly: !current.criticalHighOnly,
                  }))
                }
              />
              <FilterToggle
                active={filters.exploitChainOnly}
                label="Exploit Chain"
                onToggle={() =>
                  setFilters((current) => ({
                    ...current,
                    exploitChainOnly: !current.exploitChainOnly,
                  }))
                }
              />
              <FilterToggle
                active={filters.statefulOnly}
                label="Stateful Issues"
                onToggle={() =>
                  setFilters((current) => ({ ...current, statefulOnly: !current.statefulOnly }))
                }
              />
            </div>
          </div>

          {viewMode === "paths" ? (
            filteredClusters.length === 0 ? (
              <div className="flex min-h-[360px] items-center justify-center px-6 py-16 text-center text-sm text-muted-foreground">
                No attack-path clusters match the selected filters.
              </div>
            ) : (
              <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,0.95fr)_minmax(320px,1.05fr)]">
                <div className="space-y-3">
                  {filteredClusters.map((cluster, index) => (
                    <button
                      key={cluster.id}
                      type="button"
                      onClick={() => setSelectedClusterId(cluster.id)}
                      className={cn(
                        "w-full rounded-xl border p-4 text-left transition-colors",
                        selectedCluster?.id === cluster.id
                          ? "border-primary bg-primary/5"
                          : "border-border bg-background hover:bg-elevated"
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-xs uppercase tracking-wide text-muted-foreground">
                            Path {index + 1}
                          </p>
                          <h3 className="mt-1 truncate text-sm font-semibold text-foreground">
                            {cluster.label}
                          </h3>
                          <p className="mt-1 text-xs text-muted-foreground">{cluster.subtitle}</p>
                        </div>
                        <span
                          className={cn(
                            "rounded-md px-2 py-1 text-[11px] font-medium capitalize",
                            severityBadgeClass[cluster.severity]
                          )}
                        >
                          {cluster.severity}
                        </span>
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2">
                        <Badge
                          className={verificationBadgeClass[cluster.verificationState]}
                          label={cluster.verificationState}
                        />
                        {cluster.exploitChain ? (
                          <Badge className="bg-primary/10 text-primary" label="Exploit Chain" />
                        ) : null}
                        {cluster.stateful ? (
                          <Badge className="bg-medium/10 text-medium" label="Stateful" />
                        ) : null}
                        {cluster.vulnerabilityTypes[0] ? (
                          <Badge
                            className="bg-background text-muted-foreground"
                            label={titleize(cluster.vulnerabilityTypes[0])}
                          />
                        ) : null}
                      </div>

                      <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">
                        {cluster.narrativeSummary}
                      </p>

                      <p className="mt-3 text-xs text-muted-foreground">{clusterStatText(cluster)}</p>
                    </button>
                  ))}
                </div>

                <div className="rounded-xl border border-border bg-background p-4">
                  {selectedCluster ? (
                    <div className="space-y-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <p className="text-xs uppercase tracking-wide text-muted-foreground">
                            Selected Attack Path
                          </p>
                          <h3 className="mt-1 text-base font-semibold text-foreground">
                            {selectedCluster.label}
                          </h3>
                          <p className="mt-1 text-sm text-muted-foreground">
                            {selectedCluster.subtitle}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge
                            className={severityBadgeClass[selectedCluster.severity]}
                            label={selectedCluster.severity}
                          />
                          <Badge
                            className={verificationBadgeClass[selectedCluster.verificationState]}
                            label={selectedCluster.verificationState}
                          />
                        </div>
                      </div>

                      <div className="grid gap-3 md:grid-cols-4">
                        <MetricCard label="Findings" value={String(selectedCluster.findings.length)} />
                        <MetricCard label="Evidence" value={String(selectedCluster.evidence.length)} />
                        <MetricCard label="Routes" value={String(selectedCluster.routeGroups.length || 1)} />
                        <MetricCard
                          label="Graph Nodes"
                          value={String(selectedCluster.relatedNodeIds.length)}
                        />
                      </div>

                      <div className="rounded-xl border border-border bg-card p-4">
                        <div className="flex items-center gap-2">
                          <Target className="h-4 w-4 text-primary" />
                          <p className="text-sm font-semibold text-foreground">Path Narrative</p>
                        </div>
                        <p className="mt-3 text-sm leading-7 text-foreground">
                          {selectedCluster.narrativeSummary}
                        </p>
                        {selectedCluster.narrativeSteps.length ? (
                          <div className="mt-4 space-y-3">
                            {selectedCluster.narrativeSteps.slice(0, 4).map((step) => (
                              <div key={`${step.step}-${step.target}`} className="rounded-lg bg-background p-3">
                                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                  Step {step.step} · {step.action}
                                </p>
                                <p className="mt-2 text-sm text-foreground">{step.description}</p>
                                <p className="mt-2 text-xs text-muted-foreground">
                                  {step.target} · {step.risk}
                                </p>
                              </div>
                            ))}
                          </div>
                        ) : null}
                      </div>

                      <div className="grid gap-4 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
                        <div className="rounded-xl border border-border bg-card p-4">
                          <div className="flex items-center gap-2">
                            <Workflow className="h-4 w-4 text-primary" />
                            <p className="text-sm font-semibold text-foreground">Evidence First</p>
                          </div>
                          {selectedCluster.evidence.length === 0 ? (
                            <p className="mt-3 text-sm text-muted-foreground">
                              No persisted evidence references are linked to this attack path yet.
                            </p>
                          ) : (
                            <div className="mt-3 space-y-2">
                              {selectedCluster.evidence.map((item) => (
                                <button
                                  key={item.id}
                                  type="button"
                                  onClick={() => setSelectedEvidenceId(item.id)}
                                  className={cn(
                                    "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                                    selectedEvidence?.id === item.id
                                      ? "border-primary bg-primary/5"
                                      : "border-border bg-background hover:bg-elevated"
                                  )}
                                >
                                  <div className="flex items-start justify-between gap-3">
                                    <div className="min-w-0">
                                      <p className="truncate text-sm font-medium text-foreground">
                                        {item.finding_title ?? item.label}
                                      </p>
                                      <p className="mt-1 truncate text-xs text-muted-foreground">
                                        {item.target}
                                      </p>
                                    </div>
                                    <span
                                      className={cn(
                                        "rounded-md px-2 py-1 text-[11px] font-medium",
                                        severityBadgeClass[item.severity]
                                      )}
                                    >
                                      {item.severity}
                                    </span>
                                  </div>
                                </button>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="rounded-xl border border-border bg-card p-4">
                          <p className="text-sm font-semibold text-foreground">Evidence Detail</p>
                          {selectedEvidence ? (
                            <div className="mt-3 space-y-3">
                              <div className="rounded-lg bg-background p-3">
                                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                                  Reference
                                </p>
                                <p className="mt-1 text-sm text-foreground">{selectedEvidence.label}</p>
                                <p className="mt-2 text-xs text-muted-foreground">
                                  {selectedEvidence.tool_source ?? "unknown tool"} · {selectedEvidence.evidence_type}
                                </p>
                              </div>
                              <div className="rounded-lg bg-background p-3">
                                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                                  Content Preview
                                </p>
                                <pre className="mt-2 max-h-[300px] overflow-auto whitespace-pre-wrap font-mono text-xs text-foreground">
                                  {selectedEvidence.content ?? selectedEvidence.content_preview}
                                </pre>
                              </div>
                            </div>
                          ) : (
                            <p className="mt-3 text-sm text-muted-foreground">
                              Select an evidence reference to inspect stored proof.
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            )
          ) : (
            <div className="space-y-4 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background px-4 py-3">
                <div>
                  <p className="text-sm font-semibold text-foreground">Focused Graph View</p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Duplicate discovery nodes are clustered, and inferred discovery edges are hidden by default.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowAllEdges((current) => !current)}
                  className={cn(
                    "rounded-lg border px-3 py-2 text-xs font-medium transition-colors",
                    showAllEdges
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border bg-card text-muted-foreground hover:text-foreground"
                  )}
                >
                  {showAllEdges ? "Showing All Edges" : "Hide Noisy Inferred Edges"}
                </button>
              </div>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
                <div className="overflow-hidden rounded-xl border border-border bg-card">
                  <div className="h-[680px] w-full bg-background">
                    <ReactFlow
                      nodes={nodes}
                      edges={edges}
                      nodeTypes={nodeTypes}
                      onNodesChange={onNodesChange}
                      onEdgesChange={onEdgesChange}
                      onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                      fitView
                      fitViewOptions={{ padding: 0.18 }}
                    >
                      <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
                      <MiniMap pannable zoomable />
                      <Controls showInteractive={false} />
                    </ReactFlow>
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
                  <h3 className="text-sm font-semibold text-foreground">Selected Node</h3>
                  {selectedNode ? (
                    <div className="mt-3 space-y-3">
                      <div>
                        <p className="text-sm font-medium text-foreground">{selectedNode.data.label}</p>
                        <span
                          className={cn(
                            "mt-2 inline-flex rounded-md px-2 py-1 text-xs font-medium",
                            TYPE_THEME[selectedNode.data.nodeType]?.badgeClass ?? TYPE_THEME.asset.badgeClass
                          )}
                        >
                          {selectedNode.data.nodeType}
                        </span>
                      </div>
                      <div className="space-y-2">
                        {Object.entries(selectedNode.data.properties)
                          .filter(([, value]) => value !== null && value !== undefined && value !== "")
                          .slice(0, 10)
                          .map(([key, value]) => (
                            <div
                              key={key}
                              className="rounded-lg border border-border/70 bg-background px-3 py-2"
                            >
                              <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
                                {key.replace(/_/g, " ")}
                              </p>
                              <p className="mt-1 break-words text-sm text-foreground">
                                {Array.isArray(value) ? value.join(", ") : String(value)}
                              </p>
                            </div>
                          ))}
                      </div>
                    </div>
                  ) : (
                    <p className="mt-3 text-sm text-muted-foreground">
                      Select a graph node to inspect the clustered properties that feed path triage.
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="space-y-4">
        <AIAdvisoryPanel
          reasoning={advisory}
          title="Attack Path Advisory"
          description="Bounded AI analysis of the persisted graph. It explains risk and suggests safe next moves, but it does not dispatch jobs."
          currentMode={advisoryMode}
          onChangeMode={onChangeAdvisoryMode}
          onRegenerate={onRegenerateAdvisory}
          isRegenerating={isRegeneratingAdvisory}
        >
          <div className="space-y-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Summary
              </p>
              <p className="mt-2 text-sm leading-7 text-foreground">{advisory?.attack_graph.summary}</p>
            </div>

            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Risk Overview
              </p>
              <p className="mt-2 text-sm leading-7 text-muted-foreground">
                {advisory?.attack_graph.risk_overview}
              </p>
            </div>

            {advisory?.attack_graph.next_steps.length ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Suggested Next Steps
                </p>
                <div className="mt-2 space-y-2">
                  {advisory.attack_graph.next_steps.map((step) => (
                    <div key={`${step.title}-${step.confidence}`} className="rounded-lg bg-background p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium text-foreground">{step.title}</p>
                        <span className="rounded-full bg-primary/10 px-2 py-1 text-[11px] text-primary">
                          {step.confidence}%
                        </span>
                      </div>
                      <p className="mt-2 text-sm text-muted-foreground">{step.rationale}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </AIAdvisoryPanel>

        <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-foreground">Graph Summary</h3>
          <div className="mt-3 grid gap-3">
            <div className="rounded-lg bg-background p-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Built</p>
              <p className="mt-1 text-sm text-foreground">
                {graph.built_at ? new Date(graph.built_at).toLocaleString() : "Pending"}
              </p>
            </div>
            <div className="rounded-lg bg-background p-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Targets Reached</p>
              <p className="mt-1 text-sm text-foreground">
                {Array.isArray(graphSummary.targets_reached) && graphSummary.targets_reached.length > 0
                  ? graphSummary.targets_reached.join(", ")
                  : "No terminal attack path yet"}
              </p>
            </div>
            <div className="rounded-lg bg-background p-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Highest Score</p>
              <p className="mt-1 text-sm text-foreground">
                {"highest_score" in scoringSummary ? String(scoringSummary.highest_score) : "N/A"}
              </p>
            </div>
            <div className="rounded-lg bg-background p-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Readable Paths</p>
              <p className="mt-1 text-sm text-foreground">
                {filteredClusters.length} clustered path{filteredClusters.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-foreground">Top Attack Path</h3>
          {selectedCluster ? (
            <div className="mt-3 space-y-3">
              <div className="flex items-start gap-3">
                <div className="rounded-lg bg-primary/10 p-2">
                  {selectedCluster.exploitChain ? (
                    <Zap className="h-4 w-4 text-primary" />
                  ) : (
                    <Workflow className="h-4 w-4 text-primary" />
                  )}
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">{selectedCluster.label}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{selectedCluster.narrativeSummary}</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {selectedCluster.routeGroups.slice(0, 3).map((routeGroup) => (
                  <Badge key={routeGroup} className="bg-background text-muted-foreground" label={routeGroup} />
                ))}
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-muted-foreground">
              Attack-path clustering will appear once the graph has enough persisted signal.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

function FilterToggle({
  active,
  label,
  onToggle,
}: {
  active: boolean
  label: string
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        "rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
        active
          ? "border-primary bg-primary/10 text-primary"
          : "border-border bg-background text-muted-foreground hover:text-foreground"
      )}
    >
      {label}
    </button>
  )
}

function Badge({ className, label }: { className: string; label: string }) {
  return <span className={cn("rounded-md px-2 py-1 text-[11px] font-medium", className)}>{label}</span>
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-3">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 text-lg font-semibold text-foreground">{value}</p>
    </div>
  )
}
