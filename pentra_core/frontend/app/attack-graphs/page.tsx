"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  GitBranch,
  Loader2,
  Network,
  Search,
  ShieldCheck,
  XCircle,
} from "lucide-react"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { Spinner } from "@/components/ui/spinner"
import {
  extractVerificationCounts,
  getScanAttackGraph,
  listScans,
  type ApiAttackGraph,
  type Scan,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type AttackGraphIndexItem = {
  scan: Scan
  graph: ApiAttackGraph | null
  totalPaths: number
  targetsReached: string[]
}

function statusConfig(status: Scan["status"]) {
  switch (status) {
    case "completed":
      return {
        icon: CheckCircle2,
        label: "Graph Ready",
        className: "bg-low/10 text-low border-low/20",
      }
    case "running":
      return {
        icon: Loader2,
        label: "Building",
        className: "bg-primary/10 text-primary border-primary/20",
        iconClass: "animate-spin",
      }
    case "failed":
      return {
        icon: XCircle,
        label: "Failed",
        className: "bg-critical/10 text-critical border-critical/20",
      }
    default:
      return {
        icon: Clock,
        label: "Queued",
        className: "bg-elevated text-muted-foreground border-border",
      }
  }
}

export default function AttackGraphsPage() {
  const [items, setItems] = useState<AttackGraphIndexItem[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setIsLoading(true)
      setError(null)
      try {
        const scanResponse = await listScans({ pageSize: 100 })
        const graphRows = await Promise.all(
          scanResponse.items.map(async (scan) => {
            const graph =
              scan.status === "queued" ? null : await getScanAttackGraph(scan.id).catch(() => null)
            const pathSummary =
              graph && typeof graph.path_summary === "object" && graph.path_summary !== null
                ? graph.path_summary
                : {}
            return {
              scan,
              graph,
              totalPaths: Number(pathSummary.total_paths ?? 0),
              targetsReached: Array.isArray(pathSummary.targets_reached)
                ? pathSummary.targets_reached.map((value) => String(value))
                : [],
            }
          })
        )

        if (!cancelled) {
          setItems(graphRows)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load attack graph index.")
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
  }, [])

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const matchesSearch =
        item.scan.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.scan.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.scan.assetName.toLowerCase().includes(searchQuery.toLowerCase())
      const matchesStatus = statusFilter === "all" || item.scan.status === statusFilter
      return matchesSearch && matchesStatus
    })
  }, [items, searchQuery, statusFilter])

  const totals = useMemo(() => {
    return filteredItems.reduce(
      (acc, item) => {
        if (item.graph?.built_at) {
          acc.ready += 1
        }
        acc.nodes += item.graph?.node_count ?? 0
        acc.edges += item.graph?.edge_count ?? 0
        acc.paths += item.totalPaths
        acc.verified += extractVerificationCounts(item.scan.resultSummary).verified
        return acc
      },
      { ready: 0, nodes: 0, edges: 0, paths: 0, verified: 0 }
    )
  }, [filteredItems])

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Attack Graphs" />

        <main className="p-6">
          <div className="mb-8">
            <div className="mb-2 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/20 bg-primary/10">
                <GitBranch className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-semibold text-foreground">Attack Graph Index</h1>
                <p className="text-sm text-muted-foreground">
                  Real graph readiness, path counts, and scan-linked attack context.
                </p>
              </div>
            </div>
          </div>

          <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-4">
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-sm text-muted-foreground">Graphs Ready</p>
              <p className="mt-2 text-2xl font-semibold text-foreground">{totals.ready}</p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-sm text-muted-foreground">Total Nodes</p>
              <p className="mt-2 text-2xl font-semibold text-foreground">{totals.nodes}</p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-sm text-muted-foreground">Attack Paths</p>
              <p className="mt-2 text-2xl font-semibold text-foreground">{totals.paths}</p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-sm text-muted-foreground">Verified Findings in Scope</p>
              <p className="mt-2 text-2xl font-semibold text-foreground">{totals.verified}</p>
            </div>
          </div>

          <div className="mb-6 flex flex-wrap items-center gap-3">
            <div className="relative min-w-[280px] flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search attack graphs..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                className="h-10 w-full rounded-lg border border-border bg-elevated pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            {(["all", "completed", "running", "failed", "queued"] as const).map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={cn(
                  "rounded-lg border px-3 py-2 text-xs font-medium transition-colors",
                  statusFilter === status
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card text-muted-foreground hover:bg-elevated hover:text-foreground"
                )}
              >
                {status === "all" ? "All" : status}
              </button>
            ))}
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center gap-3 rounded-xl border border-border bg-card py-16 text-sm text-muted-foreground">
              <Spinner className="h-5 w-5" />
              Loading persisted attack graph metadata...
            </div>
          ) : error ? (
            <div className="rounded-xl border border-critical/20 bg-critical/5 p-4 text-sm text-critical">
              {error}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-elevated">
                <GitBranch className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium text-foreground">No Attack Graphs Found</h3>
              <p className="mt-1 text-sm text-muted-foreground">
                {searchQuery || statusFilter !== "all"
                  ? "Try adjusting the current filters."
                  : "Launch and complete scans to populate attack-graph data."}
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {filteredItems.map((item) => {
                const config = statusConfig(item.scan.status)
                const StatusIcon = config.icon
                const hasGraph = Boolean(item.graph?.built_at)

                return (
                  <div key={item.scan.id} className="rounded-xl border border-border bg-card p-5">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-foreground">{item.scan.name}</p>
                        <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                          {item.scan.target}
                        </p>
                      </div>
                      <div className={cn("inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-xs font-medium", config.className)}>
                        <StatusIcon className={cn("h-3 w-3", config.iconClass)} />
                        {config.label}
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-3 gap-3">
                      <div className="rounded-lg border border-border bg-background p-3">
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Nodes</p>
                        <p className="mt-2 text-xl font-semibold text-foreground">
                          {item.graph?.node_count ?? 0}
                        </p>
                      </div>
                      <div className="rounded-lg border border-border bg-background p-3">
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Edges</p>
                        <p className="mt-2 text-xl font-semibold text-foreground">
                          {item.graph?.edge_count ?? 0}
                        </p>
                      </div>
                      <div className="rounded-lg border border-border bg-background p-3">
                        <p className="text-xs uppercase tracking-wide text-muted-foreground">Paths</p>
                        <p className="mt-2 text-xl font-semibold text-foreground">{item.totalPaths}</p>
                      </div>
                    </div>

                    <div className="mt-4 flex flex-wrap gap-2">
                      {(item.targetsReached.length > 0 ? item.targetsReached : ["no-path-summary"]).slice(0, 4).map((target) => (
                        <span
                          key={`${item.scan.id}:${target}`}
                          className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                        >
                          {target}
                        </span>
                      ))}
                    </div>

                    <div className="mt-4 flex items-center justify-between gap-3 border-t border-border pt-4">
                      <div className="text-xs text-muted-foreground">
                        {hasGraph
                          ? `Built ${new Date(item.graph?.built_at ?? item.scan.updatedAt).toLocaleString("en-US", {
                              month: "short",
                              day: "numeric",
                              hour: "2-digit",
                              minute: "2-digit",
                            })}`
                          : "No persisted graph artifact yet."}
                      </div>

                      {hasGraph ? (
                        <Link
                          href={`/scans/${item.scan.id}?tab=attack-graph`}
                          className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                        >
                          <Network className="h-3.5 w-3.5" />
                          Open Graph
                        </Link>
                      ) : (
                        <span className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          Waiting on graph output
                        </span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5" />
            This page now shows real graph metadata and removes the old synthetic preview graph.
          </div>
        </main>
      </div>
    </div>
  )
}
