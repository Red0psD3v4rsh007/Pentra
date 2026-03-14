"use client"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { 
  Brain,
  Zap,
  TrendingUp,
  Shield,
  Server,
  Database,
  Globe,
  Cloud,
  Lock,
  Layers,
  GitBranch,
  Activity
} from "lucide-react"
import { cn } from "@/lib/utils"

// Mock data for learned patterns
const LEARNED_PATTERNS = [
  {
    id: "LP-001",
    name: "Common WAF Bypass Profile",
    description: "Optimized payload encoding for Cloudflare and AWS WAF",
    usageCount: 847,
    confidence: 94.2,
    category: "Evasion",
  },
  {
    id: "LP-002",
    name: "Authentication Flow Weakness",
    description: "Session fixation patterns in OAuth implementations",
    usageCount: 623,
    confidence: 89.7,
    category: "Auth",
  },
  {
    id: "LP-003",
    name: "API Rate Limit Evasion",
    description: "Header manipulation techniques for bypassing rate limits",
    usageCount: 512,
    confidence: 87.3,
    category: "Evasion",
  },
  {
    id: "LP-004",
    name: "SQL Injection Fingerprinting",
    description: "Database type detection via error-based injection",
    usageCount: 456,
    confidence: 92.1,
    category: "Injection",
  },
  {
    id: "LP-005",
    name: "JWT Algorithm Confusion",
    description: "Algorithm switching attacks on JWT implementations",
    usageCount: 389,
    confidence: 85.6,
    category: "Auth",
  },
  {
    id: "LP-006",
    name: "CORS Misconfiguration",
    description: "Origin reflection and null origin bypass patterns",
    usageCount: 298,
    confidence: 91.4,
    category: "Config",
  },
]

// Mock data for technology clusters
const TECH_CLUSTERS = [
  {
    id: "TC-001",
    name: "Frontend Monolith",
    technologies: ["React", "Next.js", "Tailwind", "TypeScript"],
    hostCount: 12,
    riskLevel: "medium",
    icon: Globe,
  },
  {
    id: "TC-002",
    name: "Data Lake Infrastructure",
    technologies: ["PostgreSQL", "Redis", "Elasticsearch", "Kafka"],
    hostCount: 8,
    riskLevel: "high",
    icon: Database,
  },
  {
    id: "TC-003",
    name: "Authentication Layer",
    technologies: ["Keycloak", "OAuth2", "LDAP", "SAML"],
    hostCount: 4,
    riskLevel: "critical",
    icon: Lock,
  },
  {
    id: "TC-004",
    name: "Cloud Infrastructure",
    technologies: ["AWS", "Terraform", "Docker", "Kubernetes"],
    hostCount: 15,
    riskLevel: "medium",
    icon: Cloud,
  },
  {
    id: "TC-005",
    name: "API Gateway Layer",
    technologies: ["Kong", "Nginx", "Express", "GraphQL"],
    hostCount: 6,
    riskLevel: "high",
    icon: Layers,
  },
  {
    id: "TC-006",
    name: "CI/CD Pipeline",
    technologies: ["GitHub Actions", "Jenkins", "ArgoCD"],
    hostCount: 3,
    riskLevel: "low",
    icon: GitBranch,
  },
]

const categoryColors: Record<string, string> = {
  Evasion: "bg-primary/10 text-primary",
  Auth: "bg-high/10 text-high",
  Injection: "bg-critical/10 text-critical",
  Config: "bg-medium/10 text-medium",
}

const riskColors: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: "bg-critical/10", text: "text-critical", dot: "bg-critical" },
  high: { bg: "bg-high/10", text: "text-high", dot: "bg-high" },
  medium: { bg: "bg-medium/10", text: "text-medium", dot: "bg-medium" },
  low: { bg: "bg-low/10", text: "text-low", dot: "bg-low" },
}

export default function IntelligencePage() {
  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Intelligence" />

        <main className="p-6">
          {/* Header */}
          <div className="mb-6">
            <h1 className="text-2xl font-semibold text-foreground">AI Intelligence</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Machine learning insights and attack pattern analysis
            </p>
          </div>

          {/* Stats Row */}
          <div className="mb-6 grid grid-cols-4 gap-4">
            {[
              { icon: Brain, label: "Patterns Learned", value: "2,847", color: "text-primary" },
              { icon: Zap, label: "Active Optimizations", value: "156", color: "text-high" },
              { icon: TrendingUp, label: "Success Rate", value: "94.2%", color: "text-low" },
              { icon: Shield, label: "Bypasses Found", value: "423", color: "text-medium" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-lg border border-border bg-card p-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                    <stat.icon className={cn("h-5 w-5", stat.color)} />
                  </div>
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      {stat.label}
                    </p>
                    <p className={cn("text-xl font-semibold", stat.color)}>{stat.value}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Two Column Layout */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Learned Patterns Card */}
            <div className="rounded-lg border border-border bg-card">
              <div className="flex items-center justify-between border-b border-border px-5 py-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                    <Brain className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Learned Patterns</h2>
                    <p className="text-xs text-muted-foreground">AI-optimized attack vectors</p>
                  </div>
                </div>
                <span className="rounded-full bg-elevated px-3 py-1 text-xs font-medium text-muted-foreground">
                  {LEARNED_PATTERNS.length} patterns
                </span>
              </div>
              
              <div className="divide-y divide-border">
                {LEARNED_PATTERNS.map((pattern) => (
                  <div
                    key={pattern.id}
                    className="group flex items-center justify-between px-5 py-4 transition-colors hover:bg-elevated/50"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-foreground group-hover:text-primary transition-colors">
                          {pattern.name}
                        </span>
                        <span className={cn(
                          "rounded-md px-2 py-0.5 text-xs font-medium",
                          categoryColors[pattern.category]
                        )}>
                          {pattern.category}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground truncate">
                        {pattern.description}
                      </p>
                    </div>
                    <div className="ml-4 flex items-center gap-6 shrink-0">
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Usage</p>
                        <p className="font-mono text-sm font-medium text-foreground">
                          {pattern.usageCount.toLocaleString()}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Confidence</p>
                        <p className="font-mono text-sm font-semibold text-primary">
                          {pattern.confidence}%
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Technology Clusters Card */}
            <div className="rounded-lg border border-border bg-card">
              <div className="flex items-center justify-between border-b border-border px-5 py-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-high/10">
                    <Activity className="h-5 w-5 text-high" />
                  </div>
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Technology Clusters</h2>
                    <p className="text-xs text-muted-foreground">Inferred infrastructure groups</p>
                  </div>
                </div>
                <span className="rounded-full bg-elevated px-3 py-1 text-xs font-medium text-muted-foreground">
                  {TECH_CLUSTERS.length} clusters
                </span>
              </div>
              
              <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-2">
                {TECH_CLUSTERS.map((cluster) => {
                  const risk = riskColors[cluster.riskLevel]
                  return (
                    <div
                      key={cluster.id}
                      className="group rounded-lg border border-border p-4 transition-all hover:border-muted-foreground hover:bg-elevated/30"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2.5">
                          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-elevated">
                            <cluster.icon className="h-4 w-4 text-muted-foreground" />
                          </div>
                          <div>
                            <h3 className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">
                              {cluster.name}
                            </h3>
                            <p className="text-xs text-muted-foreground">
                              {cluster.hostCount} hosts
                            </p>
                          </div>
                        </div>
                        <span className={cn(
                          "flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium",
                          risk.bg, risk.text
                        )}>
                          <span className={cn("h-1.5 w-1.5 rounded-full", risk.dot)} />
                          {cluster.riskLevel}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {cluster.technologies.map((tech) => (
                          <span
                            key={tech}
                            className="rounded-md border border-border bg-background px-2 py-0.5 text-xs text-muted-foreground"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
