"use client"

import type { ReactNode } from "react"
import { Fragment, useState } from "react"
import { ChevronDown, Filter } from "lucide-react"

import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { type ApiFinding } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

interface FindingsTabProps {
  findings: ApiFinding[]
}

const severityColors: Record<
  ApiFinding["severity"],
  { bg: string; text: string; border: string }
> = {
  critical: {
    bg: "bg-critical/15",
    text: "text-critical",
    border: "border-l-critical bg-critical/5",
  },
  high: {
    bg: "bg-high/15",
    text: "text-high",
    border: "border-l-high bg-high/5",
  },
  medium: {
    bg: "bg-medium/15",
    text: "text-medium",
    border: "border-l-medium bg-medium/5",
  },
  low: {
    bg: "bg-low/15",
    text: "text-low",
    border: "border-l-low bg-low/5",
  },
  info: {
    bg: "bg-muted",
    text: "text-muted-foreground",
    border: "border-l-border bg-muted/30",
  },
}

const sourceLabels: Record<ApiFinding["source_type"], string> = {
  scanner: "Scanner",
  exploit_verify: "Exploit Verify",
  ai_analysis: "AI Analysis",
}

export function FindingsTab({ findings }: FindingsTabProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<ApiFinding["severity"][]>([])
  const [sourceFilter, setSourceFilter] = useState<ApiFinding["source_type"][]>([])

  const filteredFindings = findings.filter((finding) => {
    if (severityFilter.length > 0 && !severityFilter.includes(finding.severity)) {
      return false
    }

    if (sourceFilter.length > 0 && !sourceFilter.includes(finding.source_type)) {
      return false
    }

    return true
  })

  function toggleSeverity(severity: ApiFinding["severity"]) {
    setSeverityFilter((current) =>
      current.includes(severity)
        ? current.filter((entry) => entry !== severity)
        : [...current, severity]
    )
  }

  function toggleSource(source: ApiFinding["source_type"]) {
    setSourceFilter((current) =>
      current.includes(source)
        ? current.filter((entry) => entry !== source)
        : [...current, source]
    )
  }

  if (findings.length === 0) {
    return (
      <Empty className="min-h-[320px] rounded-lg border border-border bg-card">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Filter className="h-6 w-6" />
          </EmptyMedia>
          <EmptyTitle>No persisted findings yet</EmptyTitle>
          <EmptyDescription>
            The findings list is already wired to the live API. In the current local simulation
            flow, jobs may finish before vulnerability findings are written.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <Filter className="h-4 w-4 text-muted-foreground" />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
              Severity
              {severityFilter.length > 0 ? (
                <span className="rounded bg-primary/15 px-1.5 text-xs text-primary">
                  {severityFilter.length}
                </span>
              ) : null}
              <ChevronDown className="h-3 w-3" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Filter by Severity</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
              <DropdownMenuCheckboxItem
                key={severity}
                checked={severityFilter.includes(severity)}
                onCheckedChange={() => toggleSeverity(severity)}
              >
                <span className={cn("capitalize", severityColors[severity].text)}>{severity}</span>
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
              Source
              {sourceFilter.length > 0 ? (
                <span className="rounded bg-primary/15 px-1.5 text-xs text-primary">
                  {sourceFilter.length}
                </span>
              ) : null}
              <ChevronDown className="h-3 w-3" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Filter by Source</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {(["scanner", "exploit_verify", "ai_analysis"] as const).map((source) => (
              <DropdownMenuCheckboxItem
                key={source}
                checked={sourceFilter.includes(source)}
                onCheckedChange={() => toggleSource(source)}
              >
                {sourceLabels[source]}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <span className="ml-auto text-sm text-muted-foreground">
          {filteredFindings.length} finding{filteredFindings.length === 1 ? "" : "s"}
        </span>
      </div>

      {filteredFindings.length === 0 ? (
        <div className="flex min-h-[220px] items-center justify-center text-sm text-muted-foreground">
          No findings match the selected filters.
        </div>
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-border text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
              <th className="w-10 px-4 py-3">#</th>
              <th className="px-4 py-3">Title</th>
              <th className="w-24 px-4 py-3">Severity</th>
              <th className="w-20 px-4 py-3">CVSS</th>
              <th className="w-24 px-4 py-3">Confidence</th>
              <th className="w-32 px-4 py-3">Source</th>
              <th className="w-28 px-4 py-3">Tool</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredFindings.map((finding, index) => (
              <Fragment key={finding.id}>
                <tr
                  onClick={() =>
                    setExpandedId((current) => (current === finding.id ? null : finding.id))
                  }
                  className={cn(
                    "cursor-pointer text-sm transition-colors",
                    expandedId === finding.id ? "bg-elevated/50" : "hover:bg-elevated/50"
                  )}
                >
                  <td className="px-4 py-3 font-mono text-muted-foreground">{index + 1}</td>
                  <td className="px-4 py-3 font-medium text-foreground">{finding.title}</td>
                  <td className="px-4 py-3">
                    <span
                      className={cn(
                        "rounded-md px-2 py-1 text-xs font-medium capitalize",
                        severityColors[finding.severity].bg,
                        severityColors[finding.severity].text
                      )}
                    >
                      {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-sm text-foreground">
                    {finding.cvss_score ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{finding.confidence}%</td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {sourceLabels[finding.source_type]}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {finding.tool_source}
                  </td>
                </tr>

                {expandedId === finding.id ? (
                  <tr className="bg-background/80">
                    <td colSpan={7} className="px-4 py-4">
                      <div
                        className={cn(
                          "rounded-lg border-l-4 p-4",
                          severityColors[finding.severity].border
                        )}
                      >
                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="space-y-3">
                            <DetailBlock label="Description">
                              {finding.description ?? "No description captured."}
                            </DetailBlock>
                            <DetailBlock label="Remediation">
                              {finding.remediation ?? "No remediation guidance captured yet."}
                            </DetailBlock>
                          </div>

                          <div className="space-y-3">
                            <DetailBlock label="Metadata">
                              <div className="space-y-1">
                                <p>CVE: {finding.cve_id ?? "Not assigned"}</p>
                                <p>
                                  False positive: {finding.is_false_positive ? "Yes" : "No"}
                                </p>
                                <p>
                                  FP probability:{" "}
                                  {finding.fp_probability !== null
                                    ? `${finding.fp_probability}%`
                                    : "Not scored"}
                                </p>
                              </div>
                            </DetailBlock>

                            <DetailBlock label="Evidence">
                              {finding.evidence ? (
                                <pre className="max-h-48 overflow-auto rounded-md bg-background p-3 text-xs text-muted-foreground">
                                  {JSON.stringify(finding.evidence, null, 2)}
                                </pre>
                              ) : (
                                "No structured evidence stored."
                              )}
                            </DetailBlock>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function DetailBlock({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <div className="text-sm leading-relaxed text-foreground">{children}</div>
    </div>
  )
}
