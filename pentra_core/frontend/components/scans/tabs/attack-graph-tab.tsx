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
  Globe,
  KeyRound,
  Network,
  Route,
  Server,
  ShieldCheck,
} from "lucide-react"

import { type ApiAttackGraph } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type GraphNodeData = {
  label: string
  nodeType: string
  properties: Record<string, unknown>
}

const COLUMN_X: Record<string, number> = {
  entrypoint: 40,
  asset: 240,
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

function GraphNodeCard({ data }: NodeProps<Node<GraphNodeData>>) {
  const theme = TYPE_THEME[data.nodeType] ?? TYPE_THEME.asset
  const Icon = theme.icon

  return (
    <div
      className={cn(
        "min-w-[180px] rounded-xl border bg-card px-4 py-3 shadow-sm",
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
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-border" />
    </div>
  )
}

const nodeTypes = {
  pentraNode: GraphNodeCard,
}

function buildGraphNodes(graph: ApiAttackGraph): Node<GraphNodeData>[] {
  const rowCounts = new Map<string, number>()

  return graph.nodes.map((node) => {
    const currentRow = rowCounts.get(node.node_type) ?? 0
    rowCounts.set(node.node_type, currentRow + 1)

    return {
      id: node.id,
      type: "pentraNode",
      position: {
        x: COLUMN_X[node.node_type] ?? 240,
        y: 80 + currentRow * 140,
      },
      data: {
        label: node.label,
        nodeType: node.node_type,
        properties: node.properties,
      },
    }
  })
}

function buildGraphEdges(graph: ApiAttackGraph): Edge[] {
  return graph.edges.map((edge, index) => ({
    id: `${edge.source}-${edge.target}-${index}`,
    source: edge.source,
    target: edge.target,
    label: edge.edge_type,
    animated: edge.edge_type === "exploit",
    style: {
      stroke:
        edge.edge_type === "exploit"
          ? "#ef4444"
          : edge.edge_type === "privilege_escalation"
            ? "#22c55e"
            : "#52525b",
      strokeWidth: edge.edge_type === "discovery" ? 1.5 : 2.25,
    },
    labelStyle: { fontSize: 10, fill: "#a1a1aa" },
  }))
}

interface AttackGraphTabProps {
  graph: ApiAttackGraph | null
}

export function AttackGraphTab({ graph }: AttackGraphTabProps) {
  const initialNodes = useMemo(() => (graph ? buildGraphNodes(graph) : []), [graph])
  const initialEdges = useMemo(() => (graph ? buildGraphEdges(graph) : []), [graph])
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(initialNodes[0]?.id ?? null)

  useEffect(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
    setSelectedNodeId(initialNodes[0]?.id ?? null)
  }, [initialEdges, initialNodes, setEdges, setNodes])

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null
  const graphSummary = graph?.path_summary ?? {}
  const scoringSummary = graph?.scoring_summary ?? {}

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
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="overflow-hidden rounded-xl border border-border bg-card shadow-sm">
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-foreground">Persisted Attack Graph</h2>
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
        </div>

        <div className="h-[720px] w-full bg-background">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            fitView
            fitViewOptions={{ padding: 0.15 }}
          >
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
            <MiniMap pannable zoomable />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      </div>

      <div className="space-y-4">
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
                      <p className="mt-1 break-words text-sm text-foreground">{String(value)}</p>
                    </div>
                  ))}
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-muted-foreground">
              Select a graph node to inspect the persisted properties that fed graph generation.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
