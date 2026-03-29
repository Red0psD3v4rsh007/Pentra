"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import {
  Brain,
  CheckCircle2,
  GitBranch,
  Layers,
  Radar,
  RefreshCw,
  Route,
  ShieldCheck,
  TrendingUp,
  Waypoints,
} from "lucide-react"

import { CommandLayout } from "@/components/layout/command-layout"
import { Spinner } from "@/components/ui/spinner"
import { getIntelligenceSummary, type ApiIntelligenceSummary } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

const severityClass = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-low/10 text-low",
  info: "bg-elevated text-muted-foreground",
}

const trendClass = {
  new: "bg-primary/10 text-primary",
  increasing: "bg-high/10 text-high",
  decreasing: "bg-low/10 text-low",
  stable: "bg-elevated text-muted-foreground",
}

function formatDate(value: string | null) {
  if (!value) return "N/A"
  return new Date(value).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export default function IntelligencePage() {
  const [summary, setSummary] = useState<ApiIntelligenceSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load(refresh: boolean) {
    setError(null)
    if (refresh) {
      setIsRefreshing(true)
    } else {
      setIsLoading(true)
    }
    try {
      const payload = await getIntelligenceSummary(100)
      setSummary(payload)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load intelligence summary.")
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }

  useEffect(() => {
    void load(false)
  }, [])

  return (
    <CommandLayout title="Intelligence">


        <main className="p-6">
          <div className="mb-6 flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Cross-Scan Intelligence</h1>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                {summary?.definition ??
                  "Loading the persisted cross-scan intelligence definition..."}
              </p>
            </div>
            <button
              onClick={() => void load(true)}
              disabled={isLoading || isRefreshing}
              className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
              Refresh
            </button>
          </div>

          {isLoading ? (
            <div className="flex min-h-[40vh] items-center justify-center gap-3 rounded-lg border border-border bg-card">
              <Spinner className="h-5 w-5" />
              <span className="text-sm text-muted-foreground">
                Loading intelligence from persisted scans, findings, artifacts, retests, and advisory history...
              </span>
            </div>
          ) : error ? (
            <div className="rounded-lg border border-critical/20 bg-critical/5 p-4 text-sm text-critical">
              {error}
            </div>
          ) : summary ? (
            <>
              <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                {[
                  {
                    icon: Brain,
                    label: "Recurring Patterns",
                    value: summary.overview.recurring_patterns,
                    detail: `${summary.overview.verified_findings} verified findings`,
                  },
                  {
                    icon: Layers,
                    label: "Technology Clusters",
                    value: summary.overview.technology_clusters,
                    detail: `${summary.overview.assets_with_history} assets with history`,
                  },
                  {
                    icon: Route,
                    label: "Route Groups",
                    value: summary.overview.route_groups,
                    detail: `${summary.overview.completed_scans} completed scans`,
                  },
                  {
                    icon: TrendingUp,
                    label: "Trending Vulnerabilities",
                    value: summary.overview.trending_patterns,
                    detail: `${summary.trending_patterns.filter((item) => item.direction !== "stable").length} active shifts`,
                  },
                  {
                    icon: Waypoints,
                    label: "Tracked Assets",
                    value: summary.overview.tracked_assets,
                    detail: `${summary.overview.assets_with_history} assets with history`,
                  },
                  {
                    icon: Radar,
                    label: "Active Scans",
                    value: summary.overview.active_scans,
                    detail: `${summary.overview.total_scans} total scans`,
                  },
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-border bg-card p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          {item.label}
                        </p>
                        <p className="mt-2 text-3xl font-semibold text-foreground">{item.value}</p>
                      </div>
                      <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-primary/10">
                        <item.icon className="h-5 w-5 text-primary" />
                      </div>
                    </div>
                    <p className="mt-3 text-xs text-muted-foreground">{item.detail}</p>
                  </div>
                ))}
              </section>

              <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Trend Pressure</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Vulnerability classes gaining or losing pressure across recent completed scans.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.trending_patterns.length} tracked
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.trending_patterns.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No trend data yet.</p>
                    ) : (
                      summary.trending_patterns.map((trend) => (
                        <div key={trend.vulnerability_type} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-foreground">
                                {trend.vulnerability_type.replaceAll("_", " ")}
                              </p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                recent {trend.recent_count} · previous {trend.previous_count}
                              </p>
                            </div>
                            <span className={cn("rounded-md px-2 py-1 text-xs font-medium", trendClass[trend.direction])}>
                              {trend.direction}
                            </span>
                          </div>
                          <p className="mt-3 text-xs text-muted-foreground">
                            Delta {trend.delta >= 0 ? `+${trend.delta}` : trend.delta}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Target Knowledge</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        What Pentra has learned about each asset across persisted scan history.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.target_knowledge.length} assets
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.target_knowledge.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No target knowledge yet.</p>
                    ) : (
                      summary.target_knowledge.map((asset) => (
                        <div key={asset.asset_id} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-foreground">{asset.asset_name}</p>
                              <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{asset.target}</p>
                            </div>
                            <Link
                              href={`/assets/${asset.asset_id}`}
                              className="text-xs font-medium text-primary transition-colors hover:text-primary/80"
                            >
                              Open asset
                            </Link>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                            <span>{asset.scan_count} scans</span>
                            <span>{asset.known_endpoints} endpoints</span>
                            <span>{asset.known_forms} forms</span>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {asset.known_technologies.slice(0, 4).map((technology) => (
                              <span
                                key={`${asset.asset_id}:${technology}`}
                                className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                              >
                                {technology}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </section>

              <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Pattern Matches</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Recurring findings clustered by vulnerability type and route group.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.pattern_matches.length} groups
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.pattern_matches.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No recurring patterns yet.</p>
                    ) : (
                      summary.pattern_matches.map((pattern) => (
                        <div key={pattern.key} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-foreground">{pattern.title}</p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {pattern.scan_count} scans · {pattern.finding_count} findings · last seen {formatDate(pattern.last_seen)}
                              </p>
                            </div>
                            <span className={cn("rounded-md px-2 py-1 text-xs font-medium", severityClass[pattern.highest_severity])}>
                              {pattern.highest_severity}
                            </span>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {pattern.tool_sources.map((tool) => (
                              <span
                                key={`${pattern.key}:${tool}`}
                                className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                              >
                                {tool}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Route Group Pressure</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Routes where findings repeatedly cluster across scan history.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.route_groups.length} routes
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.route_groups.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No route-group intelligence yet.</p>
                    ) : (
                      summary.route_groups.map((group) => (
                        <div key={group.route_group} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate font-mono text-sm text-foreground">{group.route_group}</p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {group.scan_count} scans · {group.finding_count} findings · {group.verification_counts.verified} verified
                              </p>
                            </div>
                            <span className={cn("rounded-md px-2 py-1 text-xs font-medium", severityClass[group.highest_severity])}>
                              {group.highest_severity}
                            </span>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {group.vulnerability_types.slice(0, 4).map((item) => (
                              <span
                                key={`${group.route_group}:${item}`}
                                className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                              >
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </section>

              <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Technology Clusters</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Technologies inferred from persisted artifact summaries and finding classification.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.technology_clusters.length} clusters
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.technology_clusters.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No technology clusters yet.</p>
                    ) : (
                      summary.technology_clusters.map((cluster) => (
                        <div key={cluster.technology} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-foreground">{cluster.technology}</p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {cluster.asset_count} assets · {cluster.scan_count} scans · {cluster.endpoint_count} related endpoints
                              </p>
                            </div>
                            <span className="rounded-md bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
                              {cluster.finding_count} findings
                            </span>
                          </div>
                          <p className="mt-3 text-xs text-muted-foreground">
                            {cluster.related_assets.slice(0, 3).join(", ") || "No related assets"}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Surface Expansion</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Discovery and stateful interaction expansion captured from artifact summaries.
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {summary.surface_expansions.length} snapshots
                    </span>
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.surface_expansions.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No surface-expansion summaries yet.</p>
                    ) : (
                      summary.surface_expansions.map((item) => (
                        <div key={item.scan_id} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-foreground">{item.asset_name}</p>
                              <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{item.target}</p>
                            </div>
                            <Link
                              href={`/scans/${item.scan_id}`}
                              className="text-xs font-medium text-primary transition-colors hover:text-primary/80"
                            >
                              Open scan
                            </Link>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                            <span>{item.discovered_targets} discovered targets</span>
                            <span>{item.discovered_forms} forms</span>
                            <span>{item.technologies.length} technologies</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </section>

              <section className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Verified Exploit Trends</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Verification-state movement across completed scans.
                      </p>
                    </div>
                    <ShieldCheck className="h-4 w-4 text-low" />
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.exploit_trends.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No completed exploit-trend history yet.</p>
                    ) : (
                      summary.exploit_trends.map((trend) => (
                        <div key={trend.scan_id} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-foreground">{trend.asset_name}</p>
                              <p className="mt-1 text-xs text-muted-foreground">{formatDate(trend.generated_at)}</p>
                            </div>
                            <Link
                              href={`/scans/${trend.scan_id}?tab=report`}
                              className="text-xs font-medium text-primary transition-colors hover:text-primary/80"
                            >
                              Open report
                            </Link>
                          </div>
                          <div className="mt-3 grid grid-cols-3 gap-3 text-sm">
                            <div>
                              <p className="text-xs text-muted-foreground">Verified</p>
                              <p className="font-semibold text-low">{trend.verified}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Suspected</p>
                              <p className="font-semibold text-high">{trend.suspected}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Detected</p>
                              <p className="font-semibold text-foreground">{trend.detected}</p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Retest Deltas</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Historical comparison summaries for scans launched as retests.
                      </p>
                    </div>
                    <GitBranch className="h-4 w-4 text-primary" />
                  </div>

                  <div className="mt-5 space-y-3">
                    {summary.retest_deltas.length === 0 ? (
                      <p className="text-sm text-muted-foreground">No retest deltas yet.</p>
                    ) : (
                      summary.retest_deltas.map((delta) => (
                        <div key={delta.scan_id} className="rounded-lg border border-border bg-background p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-foreground">{delta.asset_name}</p>
                              <p className="mt-1 font-mono text-xs text-muted-foreground">{delta.target}</p>
                            </div>
                            <Link
                              href={`/scans/${delta.scan_id}?tab=report`}
                              className="text-xs font-medium text-primary transition-colors hover:text-primary/80"
                            >
                              Open retest
                            </Link>
                          </div>
                          <p className="mt-3 text-sm text-muted-foreground">{delta.summary}</p>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                            <span>new {delta.counts.new ?? 0}</span>
                            <span>resolved {delta.counts.resolved ?? 0}</span>
                            <span>persistent {delta.counts.persistent ?? 0}</span>
                            <span>escalated {delta.counts.escalated ?? 0}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </section>

              <section className="mt-6 rounded-lg border border-border bg-card p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Advisory History</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      AI report-drafting summaries taken from persisted advisory artifacts.
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {summary.advisory_summaries.length} advisories
                  </span>
                </div>

                <div className="mt-5 grid grid-cols-1 gap-3 xl:grid-cols-2">
                  {summary.advisory_summaries.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No advisory artifacts yet.</p>
                  ) : (
                    summary.advisory_summaries.map((item) => (
                      <div key={`${item.scan_id}:${item.generated_at}`} className="rounded-lg border border-border bg-background p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="text-sm font-medium text-foreground">{item.asset_name}</p>
                            <p className="mt-1 text-xs text-muted-foreground">
                              {item.provider ?? "unknown provider"} · {item.model ?? "unknown model"} · {item.advisory_mode ?? "advisory_only"}
                            </p>
                          </div>
                          <Link
                            href={`/scans/${item.scan_id}?tab=report`}
                            className="text-xs font-medium text-primary transition-colors hover:text-primary/80"
                          >
                            Open scan
                          </Link>
                        </div>
                        <p className="mt-3 text-sm text-muted-foreground">{item.draft_summary}</p>
                        {item.prioritization_notes ? (
                          <p className="mt-3 text-xs text-muted-foreground">{item.prioritization_notes}</p>
                        ) : null}
                        <div className="mt-3 flex flex-wrap gap-2">
                          {item.remediation_focus.slice(0, 3).map((focus) => (
                            <span
                              key={`${item.scan_id}:${focus}`}
                              className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                            >
                              {focus}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </>
          ) : null}
        </main>
    </CommandLayout>
  )
}
