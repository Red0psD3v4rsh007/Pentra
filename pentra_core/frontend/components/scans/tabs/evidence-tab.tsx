"use client"

import { useEffect, useState } from "react"
import { Check, Copy, FileSearch } from "lucide-react"

import { type ApiEvidenceReference } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

const severityClass: Record<ApiEvidenceReference["severity"], string> = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-low/10 text-low",
  info: "bg-muted text-muted-foreground",
}

interface EvidenceTabProps {
  evidence: ApiEvidenceReference[]
}

export function EvidenceTab({ evidence }: EvidenceTabProps) {
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(evidence[0]?.id ?? null)
  const [copied, setCopied] = useState<"content" | "ref" | null>(null)

  useEffect(() => {
    setSelectedEvidenceId(evidence[0]?.id ?? null)
  }, [evidence])

  const selectedEvidence =
    evidence.find((item) => item.id === selectedEvidenceId) ?? evidence[0] ?? null

  async function copyValue(value: string, kind: "content" | "ref") {
    await navigator.clipboard.writeText(value)
    setCopied(kind)
    window.setTimeout(() => setCopied(null), 1500)
  }

  if (evidence.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-10 text-center shadow-sm">
        <h2 className="text-lg font-semibold text-foreground">No Evidence Stored Yet</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Once scans persist requests, responses, payloads, or exploit traces, they will appear here.
        </p>
      </div>
    )
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
      <div className="rounded-xl border border-border bg-card p-3 shadow-sm">
        <div className="mb-3 flex items-center gap-2 px-2">
          <FileSearch className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold text-foreground">Evidence References</h2>
        </div>

        <div className="space-y-2">
          {evidence.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setSelectedEvidenceId(item.id)}
              className={cn(
                "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                selectedEvidenceId === item.id
                  ? "border-primary bg-primary/5"
                  : "border-border bg-background hover:bg-elevated"
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-foreground">{item.finding_title ?? item.label}</p>
                  <p className="mt-1 truncate text-xs text-muted-foreground">{item.label}</p>
                </div>
                <span className={cn("rounded-md px-2 py-1 text-[11px] font-medium", severityClass[item.severity])}>
                  {item.severity}
                </span>
              </div>
              <p className="mt-2 truncate text-xs text-muted-foreground">{item.target}</p>
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
        {selectedEvidence ? (
          <>
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border pb-4">
              <div>
                <h3 className="text-base font-semibold text-foreground">{selectedEvidence.label}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{selectedEvidence.target}</p>
              </div>

              <div className="flex flex-wrap gap-2">
                {selectedEvidence.storage_ref ? (
                  <button
                    type="button"
                    onClick={() => copyValue(selectedEvidence.storage_ref ?? "", "ref")}
                    className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground hover:bg-elevated"
                  >
                    {copied === "ref" ? <Check className="h-4 w-4 text-low" /> : <Copy className="h-4 w-4" />}
                    Copy Ref
                  </button>
                ) : null}
                {selectedEvidence.content ? (
                  <button
                    type="button"
                    onClick={() => copyValue(selectedEvidence.content ?? "", "content")}
                    className="inline-flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                  >
                    {copied === "content" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    Copy Content
                  </button>
                ) : null}
              </div>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
              <div className="space-y-3">
                <DetailCard label="Finding" value={selectedEvidence.finding_title ?? "Unknown finding"} />
                <DetailCard label="Evidence Type" value={selectedEvidence.evidence_type} />
                <DetailCard label="Tool" value={selectedEvidence.tool_source ?? "Unknown tool"} />
                <DetailCard label="Storage Ref" value={selectedEvidence.storage_ref ?? "Inline only"} />
              </div>

              <div className="rounded-xl border border-border bg-background">
                <div className="border-b border-border px-4 py-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">Evidence Content</p>
                </div>
                <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap px-4 py-4 font-mono text-xs text-foreground">
                  {selectedEvidence.content ?? selectedEvidence.content_preview}
                </pre>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </div>
  )
}

function DetailCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-background px-3 py-3">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 break-words text-sm text-foreground">{value}</p>
    </div>
  )
}
