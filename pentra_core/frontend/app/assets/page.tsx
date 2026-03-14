"use client"

import { useState } from "react"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { 
  Server, 
  Plus, 
  Search, 
  SlidersHorizontal, 
  ChevronRight,
  Globe,
  Database,
  Cloud,
  Monitor,
  ExternalLink,
  Shield
} from "lucide-react"
import { cn } from "@/lib/utils"

// Mock data for assets
const ASSETS = [
  {
    id: "AST-001",
    hostname: "api.acmecorp.com",
    ip: "192.168.1.101",
    type: "API Server",
    technologies: ["Node.js", "Express", "MongoDB"],
    riskScore: 87,
    lastScanned: "2 hours ago",
    openFindings: 12,
    status: "online",
  },
  {
    id: "AST-002",
    hostname: "db-primary.internal",
    ip: "10.0.0.50",
    type: "Database",
    technologies: ["PostgreSQL", "Redis"],
    riskScore: 72,
    lastScanned: "5 hours ago",
    openFindings: 8,
    status: "online",
  },
  {
    id: "AST-003",
    hostname: "cdn.acmecorp.com",
    ip: "203.0.113.45",
    type: "CDN Edge",
    technologies: ["Cloudflare", "Nginx"],
    riskScore: 34,
    lastScanned: "1 day ago",
    openFindings: 2,
    status: "online",
  },
  {
    id: "AST-004",
    hostname: "staging.acmecorp.com",
    ip: "192.168.2.200",
    type: "Web Server",
    technologies: ["React", "Next.js", "Vercel"],
    riskScore: 56,
    lastScanned: "12 hours ago",
    openFindings: 5,
    status: "online",
  },
  {
    id: "AST-005",
    hostname: "mail.acmecorp.com",
    ip: "192.168.1.25",
    type: "Mail Server",
    technologies: ["Postfix", "Dovecot"],
    riskScore: 45,
    lastScanned: "3 days ago",
    openFindings: 3,
    status: "offline",
  },
  {
    id: "AST-006",
    hostname: "auth.acmecorp.com",
    ip: "10.0.1.100",
    type: "Auth Server",
    technologies: ["Keycloak", "OAuth2"],
    riskScore: 91,
    lastScanned: "30 min ago",
    openFindings: 15,
    status: "online",
  },
]

const typeIcons: Record<string, React.ElementType> = {
  "API Server": Globe,
  "Database": Database,
  "CDN Edge": Cloud,
  "Web Server": Monitor,
  "Mail Server": Server,
  "Auth Server": Shield,
}

function getRiskColor(score: number) {
  if (score >= 80) return "text-critical"
  if (score >= 60) return "text-high"
  if (score >= 40) return "text-medium"
  return "text-low"
}

function getRiskBg(score: number) {
  if (score >= 80) return "bg-critical/10"
  if (score >= 60) return "bg-high/10"
  if (score >= 40) return "bg-medium/10"
  return "bg-low/10"
}

export default function AssetsPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [showFilters, setShowFilters] = useState(false)

  const filteredAssets = ASSETS.filter(
    (asset) =>
      asset.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.ip.includes(searchQuery) ||
      asset.technologies.some((t) =>
        t.toLowerCase().includes(searchQuery.toLowerCase())
      )
  )

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Assets" />

        <main className="p-6">
          {/* Header */}
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Asset Inventory</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Discovered infrastructure and attack surface mapping
              </p>
            </div>
            <button className="flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90 hover:shadow-lg hover:shadow-primary/20">
              <Plus className="h-4 w-4" />
              Add Asset Scope
            </button>
          </div>

          {/* Filter/Action Bar */}
          <div className="mb-6 flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search by hostname, IP, or technology..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-10 w-full rounded-md border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
              />
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={cn(
                "flex items-center gap-2 rounded-md border border-border px-4 py-2.5 text-sm font-medium transition-all hover:bg-elevated",
                showFilters ? "bg-elevated text-foreground" : "text-muted-foreground"
              )}
            >
              <SlidersHorizontal className="h-4 w-4" />
              More Filters
            </button>
          </div>

          {/* Stats Bar */}
          <div className="mb-6 grid grid-cols-4 gap-4">
            {[
              { label: "Total Assets", value: ASSETS.length, color: "text-foreground" },
              { label: "Critical Risk", value: ASSETS.filter(a => a.riskScore >= 80).length, color: "text-critical" },
              { label: "Online", value: ASSETS.filter(a => a.status === "online").length, color: "text-low" },
              { label: "Open Findings", value: ASSETS.reduce((acc, a) => acc + a.openFindings, 0), color: "text-high" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-lg border border-border bg-card p-4">
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{stat.label}</p>
                <p className={cn("mt-1 text-2xl font-semibold", stat.color)}>{stat.value}</p>
              </div>
            ))}
          </div>

          {/* Assets Table */}
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-elevated/50">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Asset / IP
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Technologies
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Risk Score
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Findings
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Last Scanned
                  </th>
                  <th className="w-10 px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredAssets.map((asset) => {
                  const TypeIcon = typeIcons[asset.type] || Server
                  return (
                    <tr
                      key={asset.id}
                      className="group transition-colors hover:bg-elevated/50"
                    >
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                            <TypeIcon className="h-5 w-5 text-muted-foreground" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-foreground group-hover:text-primary transition-colors">
                                {asset.hostname}
                              </span>
                              <span className={cn(
                                "h-2 w-2 rounded-full",
                                asset.status === "online" ? "bg-low" : "bg-muted-foreground"
                              )} />
                            </div>
                            <span className="font-mono text-xs text-muted-foreground">
                              {asset.ip}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className="text-sm text-muted-foreground">{asset.type}</span>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-wrap gap-1.5">
                          {asset.technologies.slice(0, 3).map((tech) => (
                            <span
                              key={tech}
                              className="rounded-md border border-border bg-elevated px-2 py-0.5 text-xs text-muted-foreground"
                            >
                              {tech}
                            </span>
                          ))}
                          {asset.technologies.length > 3 && (
                            <span className="rounded-md border border-border bg-elevated px-2 py-0.5 text-xs text-muted-foreground">
                              +{asset.technologies.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <div className={cn(
                          "inline-flex items-center gap-2 rounded-md px-2.5 py-1",
                          getRiskBg(asset.riskScore)
                        )}>
                          <span className={cn("font-mono text-sm font-semibold", getRiskColor(asset.riskScore))}>
                            {asset.riskScore}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <span className={cn(
                          "font-medium",
                          asset.openFindings > 10 ? "text-critical" : 
                          asset.openFindings > 5 ? "text-high" : 
                          asset.openFindings > 0 ? "text-medium" : "text-muted-foreground"
                        )}>
                          {asset.openFindings}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <span className="text-sm text-muted-foreground">{asset.lastScanned}</span>
                      </td>
                      <td className="px-4 py-4">
                        <button className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground opacity-0 transition-all hover:bg-muted hover:text-foreground group-hover:opacity-100">
                          <ChevronRight className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </main>
      </div>
    </div>
  )
}
