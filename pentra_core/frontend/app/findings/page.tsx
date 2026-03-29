"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import { AlertTriangle, ExternalLink, Search, ShieldCheck, ShieldOff } from "lucide-react"

import { CommandLayout } from "@/components/layout/command-layout"
import { Spinner } from "@/components/ui/spinner"
import {
  listScanFindings,
  listScans,
  type ApiFinding,
  type Scan,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type FindingIndexItem = ApiFinding & {
  scan: Scan
}

const severityStyles = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-low/10 text-low",
  info: "bg-muted/10 text-muted-foreground",
}

const provenanceStyles = {
  live: "bg-low/10 text-low",
  derived: "bg-primary/10 text-primary",
  inferred: "bg-primary/10 text-primary",
  blocked: "bg-critical/10 text-critical",
  simulated: "bg-amber-500/10 text-amber-400",
}

export default function FindingsPage() {
  const [items, setItems] = useState<FindingIndexItem[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [verificationFilter, setVerificationFilter] = useState<string>("all")
  const [provenanceFilter, setProvenanceFilter] = useState<string>("all")
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setIsLoading(true)
      setError(null)
      try {
        const scanResponse = await listScans({ pageSize: 100 })
        const scansWithFindings = scanResponse.items.filter((scan) => {
          const count =
            scan.findings.critical + scan.findings.high + scan.findings.medium + scan.findings.low
          return count > 0
        })

        const findingGroups = await Promise.all(
          scansWithFindings.map(async (scan) => {
            const findings = await listScanFindings(scan.id, 100)
            return findings.map((finding) => ({ ...finding, scan }))
          })
        )

        if (!cancelled) {
          setItems(
            findingGroups
              .flat()
              .sort(
                (left, right) =>
                  new Date(right.created_at).getTime() - new Date(left.created_at).getTime()
              )
          )
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load persisted findings.")
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
      const haystack = [
        item.title,
        item.scan.target,
        item.scan.assetName,
        item.vulnerability_type ?? "",
        item.tool_source,
      ]
        .join(" ")
        .toLowerCase()

      const matchesSearch = haystack.includes(searchQuery.toLowerCase())
      const matchesSeverity = severityFilter === "all" || item.severity === severityFilter
      const matchesVerification =
        verificationFilter === "all" || (item.verification_state ?? "detected") === verificationFilter
      const matchesProvenance =
        provenanceFilter === "all" || (item.execution_provenance ?? "inferred") === provenanceFilter

      return matchesSearch && matchesSeverity && matchesVerification && matchesProvenance
    })
  }, [items, provenanceFilter, searchQuery, severityFilter, verificationFilter])

  const severityCounts = useMemo(
    () =>
      items.reduce(
        (acc, item) => {
          acc[item.severity] += 1
          return acc
        },
        { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      ),
    [items]
  )

  return (
    <CommandLayout title="Findings">
        <main className="p-5">
          <div className="mb-6 flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Persisted Findings</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Real findings aggregated from scan detail data. No hardcoded vulnerability rows remain here.
              </p>
            </div>
            <Link
              href="/reports"
              className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
            >
              <ShieldCheck className="h-4 w-4" />
              Open Reports
            </Link>
          </div>

          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-5">
            {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
              <div key={severity} className="rounded-lg border border-border bg-card p-4">
                <p className={cn("text-xs font-medium uppercase tracking-wide", severityStyles[severity])}>
                  {severity}
                </p>
                <p className="mt-2 text-2xl font-semibold text-foreground">{severityCounts[severity]}</p>
              </div>
            ))}
          </div>

          <div className="mb-6 flex flex-wrap items-center gap-3">
            <div className="relative min-w-[280px] flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search findings, targets, tools, or vulnerability types..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                className="h-10 w-full rounded-md border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground transition-all focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </div>

            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              className="h-10 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            <select
              value={verificationFilter}
              onChange={(event) => setVerificationFilter(event.target.value)}
              className="h-10 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="all">All proof states</option>
              <option value="verified">Verified</option>
              <option value="suspected">Suspected</option>
              <option value="detected">Detected</option>
            </select>

            <select
              value={provenanceFilter}
              onChange={(event) => setProvenanceFilter(event.target.value)}
              className="h-10 rounded-md border border-border bg-card px-3 text-sm text-foreground"
            >
              <option value="all">All provenance</option>
              <option value="live">Live</option>
              <option value="derived">Derived</option>
              <option value="inferred">Inferred</option>
              <option value="blocked">Blocked</option>
              <option value="simulated">Simulated</option>
            </select>
          </div>

          <div className="overflow-hidden rounded-lg border border-border bg-card">
            {isLoading ? (
              <div className="flex items-center justify-center gap-3 p-10 text-sm text-muted-foreground">
                <Spinner className="h-5 w-5" />
                Loading persisted findings from real scans...
              </div>
            ) : error ? (
              <div className="p-6 text-sm text-critical">{error}</div>
            ) : filteredItems.length === 0 ? (
              <div className="p-10 text-center text-sm text-muted-foreground">
                No persisted findings match the current filters.
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-elevated/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Finding
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Asset / Target
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Severity
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Proof
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Provenance
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Source
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Scan
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredItems.map((item) => (
                    <tr key={item.id} className="align-top transition-colors hover:bg-elevated/40">
                      <td className="px-4 py-4">
                        <div className="max-w-[360px]">
                          <p className="text-sm font-medium text-foreground">{item.title}</p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {item.vulnerability_type ?? "unclassified"} · confidence {item.confidence}%
                          </p>
                          {item.description ? (
                            <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">
                              {item.description}
                            </p>
                          ) : null}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-sm font-medium text-foreground">{item.scan.assetName}</p>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">{item.scan.target}</p>
                      </td>
                      <td className="px-4 py-4">
                        <span className={cn("rounded-md px-2 py-1 text-xs font-medium", severityStyles[item.severity])}>
                          {item.severity}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-2">
                          {(item.verification_state ?? "detected") === "verified" ? (
                            <ShieldCheck className="h-4 w-4 text-low" />
                          ) : (
                            <ShieldOff className="h-4 w-4 text-muted-foreground" />
                          )}
                          <div>
                            <p className="text-sm capitalize text-foreground">
                              {item.verification_state ?? "detected"}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {item.verification_confidence ?? item.confidence}% confidence
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={cn(
                            "rounded-md px-2 py-1 text-xs font-medium",
                            provenanceStyles[item.execution_provenance ?? "inferred"]
                          )}
                        >
                          {item.execution_provenance ?? "inferred"}
                        </span>
                        {item.execution_reason ? (
                          <p className="mt-1 max-w-[180px] text-xs text-muted-foreground">
                            {item.execution_reason}
                          </p>
                        ) : null}
                      </td>
                      <td className="px-4 py-4">
                        <div className="text-sm text-foreground">{item.tool_source}</div>
                        <div className="mt-1 text-xs text-muted-foreground">{item.source_type}</div>
                      </td>
                      <td className="px-4 py-4">
                        <Link
                          href={`/scans/${item.scan.id}?tab=findings`}
                          className="inline-flex items-center gap-2 text-sm font-medium text-primary transition-colors hover:text-primary/80"
                        >
                          Open
                          <ExternalLink className="h-3.5 w-3.5" />
                        </Link>
                        <p className="mt-1 text-xs text-muted-foreground">{item.scan.statusLabel}</p>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
            <AlertTriangle className="h-3.5 w-3.5" />
            This index is loaded from persisted scan findings. If a scan has not produced findings yet, it will not appear here.
          </div>
        </main>
    </CommandLayout>
  )
}
