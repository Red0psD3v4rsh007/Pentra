"use client"

import { GitBranch, Shield, Target } from "lucide-react"

import { formatTargetModelOrigin, type ApiScanTargetModel } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface TargetModelTabProps {
  targetModel: ApiScanTargetModel | null
}

export function TargetModelTab({ targetModel }: TargetModelTabProps) {
  if (!targetModel) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-6 text-sm text-muted-foreground">
        No normalized target model is available for this scan yet. Pentra will populate this view
        once endpoints, workflows, auth surfaces, or findings can be fused into a planner-facing
        target snapshot.
      </div>
    )
  }

  const overview = targetModel.overview
  const routeGroups = targetModel.route_groups.slice(0, 8)
  const endpoints = targetModel.endpoints.slice(0, 6)
  const parameters = [...targetModel.parameters]
    .sort((left, right) => {
      if (left.likely_sensitive !== right.likely_sensitive) {
        return left.likely_sensitive ? -1 : 1
      }
      return right.endpoint_count - left.endpoint_count || left.name.localeCompare(right.name)
    })
    .slice(0, 8)

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Target Snapshot</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Planner-facing model generated from persisted artifacts and finding truth states.
            </p>
          </div>
          <div className="text-right text-xs text-muted-foreground">
            <div>{targetModel.asset_name}</div>
            <div>{targetModel.target}</div>
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Endpoints" value={overview.endpoint_count} />
          <MetricCard label="Route Groups" value={overview.route_group_count} />
          <MetricCard label="Auth Surfaces" value={overview.auth_surface_count} />
          <MetricCard label="Workflows" value={overview.workflow_edge_count} />
          <MetricCard label="Technologies" value={overview.technology_count} />
          <MetricCard label="Parameters" value={overview.parameter_count} />
          <MetricCard label="Authenticated" value={overview.authenticated_endpoint_count} />
          <MetricCard label="Findings" value={overview.finding_count} />
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {overview.source_artifact_types.map((artifactType) => (
            <span
              key={artifactType}
              className="rounded-full border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-muted-foreground"
            >
              {artifactType}
            </span>
          ))}
          {overview.source_artifact_types.length === 0 ? (
            <span className="rounded-full border border-dashed border-border px-2.5 py-1 text-[11px] text-muted-foreground">
              finding-derived only
            </span>
          ) : null}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-foreground">Planner Focus</h2>
          </div>

          {targetModel.planner_focus.length === 0 ? (
            <EmptyState text="No route groups are carrying enough target-model pressure yet to prioritize." />
          ) : (
            <div className="space-y-3">
              {targetModel.planner_focus.map((focus) => (
                <div key={focus.route_group} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-foreground">{focus.route_group}</p>
                      <p className="mt-1 text-sm text-muted-foreground">{focus.objective}</p>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="rounded-full bg-primary/10 px-2 py-1 font-medium text-primary">
                        focus {focus.focus_score}
                      </span>
                      {focus.requires_auth ? (
                        <span className="rounded-full bg-amber-100 px-2 py-1 font-medium text-amber-800">
                          auth
                        </span>
                      ) : (
                        <span className="rounded-full bg-muted px-2 py-1 font-medium text-muted-foreground">
                          public
                        </span>
                      )}
                    </div>
                  </div>
                  <p className="mt-3 text-xs leading-6 text-muted-foreground">{focus.reason}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {focus.vulnerability_types.map((item) => (
                      <Token key={`${focus.route_group}:vuln:${item}`} label={item} tone="risk" />
                    ))}
                    {focus.parameter_names.map((item) => (
                      <Token key={`${focus.route_group}:param:${item}`} label={item} tone="param" />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-foreground">Auth Surfaces</h2>
          </div>

          {targetModel.auth_surfaces.length === 0 ? (
            <EmptyState text="No auth-state grouping has been derived yet." />
          ) : (
            <div className="space-y-3">
              {targetModel.auth_surfaces.map((surface) => (
                <div key={surface.label} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-foreground">{surface.label}</p>
                      <p className="text-xs text-muted-foreground">{surface.auth_state}</p>
                    </div>
                    <span className="rounded-full bg-muted px-2 py-1 text-xs font-medium text-foreground">
                      {surface.endpoint_count} endpoints
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-muted-foreground">
                    <Stat label="CSRF Forms" value={surface.csrf_form_count} />
                    <Stat label="Safe Replay" value={surface.safe_replay_count} />
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {surface.route_groups.map((routeGroup) => (
                      <Token key={`${surface.label}:${routeGroup}`} label={routeGroup} tone="neutral" />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-foreground">Route Groups</h2>
          </div>

          {routeGroups.length === 0 ? (
            <EmptyState text="No route groups have been derived yet." />
          ) : (
            <div className="space-y-3">
              {routeGroups.map((group) => (
                <div key={group.route_group} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-foreground">{group.route_group}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {group.endpoint_count} endpoints · {group.finding_count} findings
                      </p>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="rounded-full bg-primary/10 px-2 py-1 font-medium text-primary">
                        focus {group.focus_score}
                      </span>
                      {group.requires_auth ? (
                        <span className="rounded-full bg-amber-100 px-2 py-1 font-medium text-amber-800">
                          auth
                        </span>
                      ) : null}
                      <span className="rounded-full border border-border bg-card px-2 py-1 font-medium text-muted-foreground">
                        {formatTargetModelOrigin(group.origin)}
                      </span>
                    </div>
                  </div>
                  <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                    <div>Methods: {group.methods.join(", ") || "unknown"}</div>
                    <div>Tech: {group.technologies.join(", ") || "unknown"}</div>
                    <div>Truth: {formatTruthSummary(group.truth_counts)}</div>
                    <div>Severity: {formatSeveritySummary(group.severity_counts)}</div>
                  </div>
                  {group.origin === "seeded_probe" ? (
                    <p className="mt-3 text-xs text-amber-700">
                      Seeded probe only. This route group is not yet confirmed as discovered truth.
                    </p>
                  ) : null}
                  <div className="mt-3 flex flex-wrap gap-2">
                    {group.parameter_names.map((name) => (
                      <Token key={`${group.route_group}:parameter:${name}`} label={name} tone="param" />
                    ))}
                    {group.vulnerability_types.map((name) => (
                      <Token key={`${group.route_group}:vulnerability:${name}`} label={name} tone="risk" />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <div className="space-y-6">
          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Workflow Edges</h2>
            </div>

            {targetModel.workflows.length === 0 ? (
              <EmptyState text="No workflow transitions have been extracted yet." />
            ) : (
              <div className="space-y-3">
                {targetModel.workflows.slice(0, 8).map((workflow) => (
                  <div key={`${workflow.source_url}:${workflow.target_url}:${workflow.action}`} className="rounded-lg border border-border bg-background p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
                        {workflow.action}
                      </span>
                      {workflow.requires_auth ? (
                        <span className="rounded-full bg-amber-100 px-2 py-1 text-[11px] font-medium text-amber-800">
                          auth required
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-2 text-sm font-medium text-foreground">{workflow.source_route_group}</p>
                    <p className="mt-1 text-xs text-muted-foreground">to {workflow.target_route_group}</p>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="rounded-lg border border-border bg-card p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Parameters And Endpoints</h2>
            </div>

            <div className="space-y-3">
              {parameters.map((parameter) => (
                <div key={parameter.name} className="rounded-lg border border-border bg-background p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-foreground">{parameter.name}</p>
                    {parameter.likely_sensitive ? (
                      <span className="rounded-full bg-critical/10 px-2 py-1 text-[11px] font-medium text-critical">
                        sensitive
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {parameter.endpoint_count} endpoints · {parameter.locations.join(", ") || "unknown source"}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {parameter.related_vulnerability_types.map((name) => (
                      <Token key={`${parameter.name}:vulnerability:${name}`} label={name} tone="risk" />
                    ))}
                    {parameter.related_truth_states.map((name) => (
                      <Token key={`${parameter.name}:truth:${name}`} label={name} tone="neutral" />
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {endpoints.length > 0 ? (
              <div className="mt-6 border-t border-border pt-6">
                <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  Highest-Pressure Endpoints
                </h3>
                <div className="mt-3 space-y-3">
                  {endpoints.map((endpoint) => (
                    <div key={endpoint.url} className="rounded-lg border border-border bg-background p-4">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-foreground">{endpoint.path}</p>
                          <p className="text-xs text-muted-foreground">{endpoint.route_group}</p>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded-full border border-border bg-card px-2 py-1 text-[11px] font-medium text-muted-foreground">
                            {formatTargetModelOrigin(endpoint.origin)}
                          </span>
                          <span className="rounded-full bg-muted px-2 py-1 text-[11px] font-medium text-foreground">
                            {endpoint.finding_count} findings
                          </span>
                        </div>
                      </div>
                      <div className="mt-3 grid gap-2 text-xs text-muted-foreground">
                        <div>Methods: {endpoint.methods.join(", ") || "unknown"}</div>
                        <div>Truth: {formatTruthSummary(endpoint.truth_counts)}</div>
                      </div>
                      {endpoint.origin === "seeded_probe" ? (
                        <p className="mt-3 text-xs text-amber-700">
                          Seeded probe only. Pentra has not yet promoted this endpoint to observed discovery.
                        </p>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </section>
        </div>
      </div>
    </div>
  )
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-background px-4 py-3">
      <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
    </div>
  )
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-dashed border-border bg-background px-4 py-5 text-sm text-muted-foreground">
      {text}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border/70 bg-card/60 px-3 py-2">
      <div>{label}</div>
      <div className="mt-1 text-sm font-semibold text-foreground">{value}</div>
    </div>
  )
}

function Token({
  label,
  tone,
}: {
  label: string
  tone: "risk" | "param" | "neutral"
}) {
  return (
    <span
      className={cn(
        "rounded-full border px-2.5 py-1 text-[11px] font-medium",
        tone === "risk" && "border-critical/20 bg-critical/10 text-critical",
        tone === "param" && "border-primary/20 bg-primary/10 text-primary",
        tone === "neutral" && "border-border bg-card text-muted-foreground"
      )}
    >
      {label}
    </span>
  )
}

function formatTruthSummary(counts: Record<string, number>): string {
  const parts = Object.entries(counts)
    .filter(([, value]) => value > 0)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([key, value]) => `${value} ${key}`)
  return parts.join(" · ") || "none"
}

function formatSeveritySummary(counts: Record<string, number>): string {
  const order = ["critical", "high", "medium", "low", "info"]
  const parts = order
    .filter((key) => (counts[key] ?? 0) > 0)
    .map((key) => `${counts[key]} ${key}`)
  return parts.join(" · ") || "none"
}
