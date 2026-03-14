"use client"

import Link from "next/link"
import { cn } from "@/lib/utils"
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Cell,
} from "recharts"

// Severity chart data
const severityData = [
  { name: "Critical", value: 4, color: "#ef4444" },
  { name: "High", value: 12, color: "#f97316" },
  { name: "Medium", value: 28, color: "#eab308" },
  { name: "Low", value: 45, color: "#22c55e" },
]

// Top vulnerable assets
interface VulnerableAsset {
  id: string
  hostname: string
  riskScore: number
  severity: "critical" | "high" | "medium" | "low"
  findings: number
}

const vulnerableAssets: VulnerableAsset[] = [
  { id: "asset-001", hostname: "db-prod-01.internal", riskScore: 94, severity: "critical", findings: 12 },
  { id: "asset-002", hostname: "api-gateway.acme.com", riskScore: 87, severity: "critical", findings: 8 },
  { id: "asset-003", hostname: "jenkins.internal", riskScore: 72, severity: "high", findings: 6 },
  { id: "asset-004", hostname: "mail.acme.com", riskScore: 65, severity: "high", findings: 5 },
  { id: "asset-005", hostname: "ldap.internal", riskScore: 58, severity: "medium", findings: 4 },
]

const severityColors: Record<string, string> = {
  critical: "bg-critical text-white",
  high: "bg-high text-white",
  medium: "bg-medium text-zinc-900",
  low: "bg-low text-white",
}

export function SeverityBreakdown() {
  const total = severityData.reduce((acc, curr) => acc + curr.value, 0)

  return (
    <div className="grid grid-cols-5 gap-4">
      {/* Findings by Severity - 60% */}
      <div className="col-span-3 rounded-lg border border-border bg-card p-6">
        <h3 className="mb-6 text-base font-semibold text-foreground">Findings by Severity</h3>
        
        {/* Horizontal stacked bar */}
        <div className="mb-4 h-10 overflow-hidden rounded-lg">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={[{ name: "Severity", ...Object.fromEntries(severityData.map(d => [d.name, d.value])) }]}
              margin={{ top: 0, right: 0, bottom: 0, left: 0 }}
              barSize={40}
            >
              <XAxis type="number" hide domain={[0, total]} />
              <YAxis type="category" dataKey="name" hide />
              {severityData.map((entry, index) => (
                <Bar
                  key={entry.name}
                  dataKey={entry.name}
                  stackId="a"
                  fill={entry.color}
                  radius={index === 0 ? [6, 0, 0, 6] : index === severityData.length - 1 ? [0, 6, 6, 0] : 0}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-6">
          {severityData.map((item) => (
            <div key={item.name} className="flex items-center gap-2">
              <span
                className="h-3 w-3 rounded-sm"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-sm text-muted-foreground">
                {item.name}
              </span>
              <span className="text-sm font-medium text-foreground">
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Top Vulnerable Assets - 40% */}
      <div className="col-span-2 rounded-lg border border-border bg-card p-6">
        <h3 className="mb-4 text-base font-semibold text-foreground">Top Vulnerable Assets</h3>
        
        <div className="flex flex-col gap-3">
          {vulnerableAssets.map((asset) => (
            <Link
              key={asset.id}
              href={`/assets/${asset.id}`}
              className="group flex items-center justify-between rounded-md p-2 transition-colors hover:bg-elevated"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="font-mono text-sm text-foreground truncate group-hover:text-primary transition-colors">
                  {asset.hostname}
                </span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="text-xs text-muted-foreground">
                  {asset.findings} findings
                </span>
                <span
                  className={cn(
                    "inline-flex items-center justify-center rounded px-2 py-0.5 text-xs font-semibold",
                    severityColors[asset.severity]
                  )}
                >
                  {asset.riskScore}
                </span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
