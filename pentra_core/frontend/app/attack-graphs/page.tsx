"use client"

import { useState } from "react"
import Link from "next/link"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { useScans } from "@/hooks/use-scans"
import {
  Search,
  Filter,
  GitBranch,
  ExternalLink,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  XCircle,
  ChevronRight,
  Network,
  Shield,
  Zap,
} from "lucide-react"

export default function AttackGraphsPage() {
  const { scans } = useScans()
  const [searchQuery, setSearchQuery] = useState("")
  const [statusFilter, setStatusFilter] = useState<string>("all")

  // Filter scans - only show completed scans that would have attack graphs
  const filteredScans = scans.filter((scan) => {
    const matchesSearch =
      scan.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.target.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus = statusFilter === "all" || scan.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const completedScans = scans.filter((s) => s.status === "completed").length
  const totalNodes = completedScans * 12 // Mock calculation
  const totalPaths = completedScans * 8 // Mock calculation

  const getStatusConfig = (status: string) => {
    switch (status) {
      case "completed":
        return {
          icon: CheckCircle2,
          label: "Graph Ready",
          className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
        }
      case "running":
        return {
          icon: Loader2,
          label: "Generating...",
          className: "bg-blue-500/10 text-blue-400 border-blue-500/20",
          iconClass: "animate-spin",
        }
      case "failed":
        return {
          icon: XCircle,
          label: "Failed",
          className: "bg-red-500/10 text-red-400 border-red-500/20",
        }
      default:
        return {
          icon: Clock,
          label: "Pending",
          className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
        }
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />
      <div className="pl-60 transition-all duration-200">
        <TopBar title="Attack Graphs" />

        <main className="p-6">
          {/* Page Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 border border-primary/20">
                <GitBranch className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-semibold text-foreground">Attack Graphs</h1>
                <p className="text-sm text-muted-foreground">
                  Visualize attack paths and exploitation chains from your scans
                </p>
              </div>
            </div>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Graphs</p>
                  <p className="text-2xl font-semibold text-foreground mt-1">{completedScans}</p>
                </div>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                  <Network className="h-5 w-5 text-primary" />
                </div>
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Nodes</p>
                  <p className="text-2xl font-semibold text-foreground mt-1">{totalNodes}</p>
                </div>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10">
                  <Target className="h-5 w-5 text-emerald-400" />
                </div>
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Attack Paths</p>
                  <p className="text-2xl font-semibold text-foreground mt-1">{totalPaths}</p>
                </div>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10">
                  <Zap className="h-5 w-5 text-amber-400" />
                </div>
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Critical Chains</p>
                  <p className="text-2xl font-semibold text-foreground mt-1">
                    {scans.reduce((acc, s) => acc + (s.findings?.critical || 0), 0)}
                  </p>
                </div>
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
              </div>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-3 mb-6">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search scans..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-9 w-full rounded-lg border border-border bg-elevated pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setStatusFilter("all")}
                className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  statusFilter === "all"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-card text-muted-foreground hover:bg-elevated hover:text-foreground"
                }`}
              >
                All
              </button>
              <button
                onClick={() => setStatusFilter("completed")}
                className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  statusFilter === "completed"
                    ? "border-emerald-500 bg-emerald-500/10 text-emerald-400"
                    : "border-border bg-card text-muted-foreground hover:bg-elevated hover:text-foreground"
                }`}
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                Ready
              </button>
              <button
                onClick={() => setStatusFilter("running")}
                className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  statusFilter === "running"
                    ? "border-blue-500 bg-blue-500/10 text-blue-400"
                    : "border-border bg-card text-muted-foreground hover:bg-elevated hover:text-foreground"
                }`}
              >
                <Loader2 className="h-3.5 w-3.5" />
                Generating
              </button>
            </div>
          </div>

          {/* Scans Grid */}
          {filteredScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-elevated mb-4">
                <GitBranch className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium text-foreground mb-1">No Attack Graphs Found</h3>
              <p className="text-sm text-muted-foreground mb-4">
                {searchQuery || statusFilter !== "all"
                  ? "Try adjusting your filters"
                  : "Complete a scan to generate attack graphs"}
              </p>
              <Link
                href="/scans/new"
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
              >
                Start New Scan
              </Link>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredScans.map((scan) => {
                const statusConfig = getStatusConfig(scan.status)
                const StatusIcon = statusConfig.icon
                const isReady = scan.status === "completed"

                return (
                  <Link
                    key={scan.id}
                    href={isReady ? `/scans/${scan.id}?tab=attack-graph` : "#"}
                    className={`group relative rounded-xl border bg-card overflow-hidden transition-all ${
                      isReady
                        ? "border-border hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 cursor-pointer"
                        : "border-border/50 opacity-70 cursor-not-allowed"
                    }`}
                  >
                    {/* Graph Preview Area */}
                    <div className="relative h-32 bg-elevated/50 border-b border-border overflow-hidden">
                      {/* Mini Graph Visualization */}
                      <svg
                        className="absolute inset-0 w-full h-full"
                        viewBox="0 0 200 100"
                        preserveAspectRatio="xMidYMid meet"
                      >
                        {/* Grid lines */}
                        <defs>
                          <pattern
                            id={`grid-${scan.id}`}
                            width="20"
                            height="20"
                            patternUnits="userSpaceOnUse"
                          >
                            <path
                              d="M 20 0 L 0 0 0 20"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="0.5"
                              className="text-border/30"
                            />
                          </pattern>
                        </defs>
                        <rect width="200" height="100" fill={`url(#grid-${scan.id})`} />

                        {isReady && (
                          <>
                            {/* Attack path lines */}
                            <path
                              d="M 30 50 Q 60 30, 100 50 T 170 50"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="1.5"
                              className="text-primary/40"
                              strokeDasharray="4,2"
                            />
                            <path
                              d="M 30 50 Q 60 70, 100 50"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="1.5"
                              className="text-amber-500/40"
                              strokeDasharray="4,2"
                            />

                            {/* Nodes */}
                            <circle cx="30" cy="50" r="6" className="fill-emerald-500/80" />
                            <circle cx="70" cy="35" r="5" className="fill-primary/60" />
                            <circle cx="70" cy="65" r="5" className="fill-amber-500/60" />
                            <circle cx="100" cy="50" r="6" className="fill-primary/80" />
                            <circle cx="130" cy="40" r="5" className="fill-primary/60" />
                            <circle cx="170" cy="50" r="6" className="fill-red-500/80" />
                          </>
                        )}

                        {!isReady && (
                          <text
                            x="100"
                            y="55"
                            textAnchor="middle"
                            className="fill-muted-foreground text-xs"
                          >
                            {scan.status === "running" ? "Generating..." : "Not Available"}
                          </text>
                        )}
                      </svg>

                      {/* Status Badge */}
                      <div
                        className={`absolute top-3 right-3 flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${statusConfig.className}`}
                      >
                        <StatusIcon
                          className={`h-3 w-3 ${(statusConfig as any).iconClass || ""}`}
                        />
                        {statusConfig.label}
                      </div>

                      {/* Hover overlay */}
                      {isReady && (
                        <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                          <span className="flex items-center gap-2 rounded-lg bg-card/90 backdrop-blur-sm border border-border px-3 py-1.5 text-xs font-medium text-foreground">
                            View Full Graph
                            <ExternalLink className="h-3 w-3" />
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Card Content */}
                    <div className="p-4">
                      <div className="flex items-start justify-between gap-3 mb-3">
                        <div className="min-w-0 flex-1">
                          <h3 className="font-medium text-foreground truncate group-hover:text-primary transition-colors">
                            {scan.name}
                          </h3>
                          <p className="text-xs text-muted-foreground truncate mt-0.5">
                            {scan.target}
                          </p>
                        </div>
                        {isReady && (
                          <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition-all flex-shrink-0 mt-1" />
                        )}
                      </div>

                      {/* Stats Row */}
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          <span>{scan.duration || "—"}</span>
                        </div>
                        {isReady && (
                          <>
                            <div className="flex items-center gap-1">
                              <Network className="h-3 w-3" />
                              <span>12 nodes</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <Zap className="h-3 w-3" />
                              <span>8 paths</span>
                            </div>
                          </>
                        )}
                      </div>

                      {/* Severity indicators */}
                      {isReady && scan.findings && (
                        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-border">
                          {scan.findings.critical > 0 && (
                            <span className="flex items-center gap-1 text-xs">
                              <span className="h-2 w-2 rounded-full bg-red-500" />
                              <span className="text-red-400">{scan.findings.critical} Critical</span>
                            </span>
                          )}
                          {scan.findings.high > 0 && (
                            <span className="flex items-center gap-1 text-xs">
                              <span className="h-2 w-2 rounded-full bg-orange-500" />
                              <span className="text-orange-400">{scan.findings.high} High</span>
                            </span>
                          )}
                          {scan.findings.critical === 0 && scan.findings.high === 0 && (
                            <span className="flex items-center gap-1 text-xs text-muted-foreground">
                              <Shield className="h-3 w-3" />
                              No critical chains
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </Link>
                )
              })}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
