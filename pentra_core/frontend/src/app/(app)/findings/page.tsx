"use client"

import React from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { SeverityBadge } from "@/components/ui/severity-badge"
import { Search, Filter, ShieldAlert, AlertTriangle, ArrowRight, Download } from "lucide-react"

const MOCK_FINDINGS = [
    { id: "VULN-0982Y", title: "Remote Code Execution via Log4Shell", severity: "critical", cvss: 10.0, target: "order-queue.prod.local", status: "confirmed", discovered: "2024-03-24T14:22:00Z" },
    { id: "VULN-1827X", title: "Blind SQL Injection (Boolean-Based)", severity: "high", cvss: 8.5, target: "api.finance.local", status: "confirmed", discovered: "2024-03-24T11:05:00Z" },
    { id: "VULN-8712A", title: "Authentication Bypass via Misconfigured JWT", severity: "critical", cvss: 9.1, target: "sso.corp.internal", status: "triaging", discovered: "2024-03-23T09:12:00Z" },
    { id: "VULN-3381C", title: "Exposed AWS Access Keys in Git Repo", severity: "high", cvss: 7.8, target: "git.dev.local", status: "confirmed", discovered: "2024-03-22T16:44:00Z" },
    { id: "VULN-9182Z", title: "Reflected Cross-Site Scripting (XSS)", severity: "medium", cvss: 5.4, target: "support.company.com", status: "new", discovered: "2024-03-21T08:30:00Z" },
    { id: "VULN-4419B", title: "Outdated OpenSSL Version", severity: "medium", cvss: 4.3, target: "vpn.corp.internal", status: "ignored", discovered: "2024-03-20T10:11:00Z" },
    { id: "VULN-1102D", title: "Missing HTTP Strict Transport Security", severity: "low", cvss: 3.1, target: "marketing.site.com", status: "new", discovered: "2024-03-19T14:45:00Z" },
]

export default function FindingsPage() {
    return (
        <div className="space-y-6">

            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-display font-bold tracking-widest text-white mb-1 uppercase">Global Findings</h1>
                    <p className="text-pentra-text-muted font-mono text-xs uppercase tracking-wider">THREAT MATRIX & VULNERABILITY INTELLIGENCE</p>
                </div>
                <div className="flex gap-4">
                    <div className="flex flex-col items-end">
                        <span className="text-[10px] font-mono text-pentra-text-muted uppercase">Total Critical</span>
                        <span className="font-display font-bold text-pentra-critical text-2xl">14</span>
                    </div>
                    <div className="flex flex-col items-end">
                        <span className="text-[10px] font-mono text-pentra-text-muted uppercase">Total High</span>
                        <span className="font-display font-bold text-pentra-high text-2xl">48</span>
                    </div>
                </div>
            </div>

            {/* Toolbar */}
            <div className="flex items-center justify-between gap-4 p-4 bg-pentra-panel border border-pentra-border">
                <div className="flex items-center gap-4 flex-1">
                    <div className="relative flex-1 max-w-sm">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-pentra-text-muted" size={14} />
                        <Input placeholder="Filter findings (e.g. severity:critical)..." className="pl-9 h-8 text-xs rounded-none border-pentra-border-strong bg-pentra-black font-mono w-[400px]" />
                    </div>
                    <Button variant="outline" size="sm" className="gap-2">
                        <Filter size={14} /> FILTERS
                    </Button>
                </div>

                <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" className="text-pentra-cyan border border-pentra-cyan/30 hover:bg-pentra-cyan/10">
                        KANBAN BOARD
                    </Button>
                    <Button variant="ghost" size="sm" className="text-white bg-pentra-surface border border-pentra-border-strong">
                        TABLE VIEW
                    </Button>
                    <div className="w-px h-6 bg-pentra-border mx-2" />
                    <Button variant="ghost" size="sm" className="text-pentra-text-dim hover:text-white" title="Export CSV/JSON">
                        <Download size={14} />
                    </Button>
                </div>
            </div>

            {/* Main Table */}
            <Card className="bg-pentra-surface border-pentra-border">
                <CardContent className="p-0">
                    <table className="w-full text-sm text-left">
                        <thead className="text-[10px] text-pentra-text-muted uppercase font-mono bg-pentra-panel border-b border-pentra-border tracking-widest">
                            <tr>
                                <th className="px-6 py-4 font-bold w-12">SEV</th>
                                <th className="px-4 py-4 font-bold">Vulnerability Signature</th>
                                <th className="px-4 py-4 font-bold w-24">CVSS Base</th>
                                <th className="px-4 py-4 font-bold w-64">Target Asset</th>
                                <th className="px-4 py-4 font-bold w-32">Status</th>
                                <th className="px-4 py-4 font-bold text-right w-24">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-pentra-border font-mono text-xs">
                            {MOCK_FINDINGS.map((finding) => (
                                <tr key={finding.id} className="hover:bg-pentra-panel/50 transition-colors group">
                                    <td className="px-4 py-3 pl-6">
                                        <SeverityBadge severity={finding.severity as any} />
                                    </td>
                                    <td className="px-4 py-3">
                                        <div className="font-bold text-white group-hover:text-pentra-primary transition-colors cursor-pointer">
                                            {finding.title}
                                        </div>
                                        <div className="text-[10px] text-pentra-text-dim mt-1">{finding.id} • {new Date(finding.discovered).toLocaleDateString()}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                        <span className={`px-2 py-0.5 border ${finding.cvss >= 9 ? "border-pentra-critical text-pentra-critical bg-pentra-critical/10" :
                                                finding.cvss >= 7 ? "border-pentra-high text-pentra-high bg-pentra-high/10" :
                                                    finding.cvss >= 4 ? "border-pentra-medium text-pentra-medium bg-pentra-medium/10" :
                                                        "border-pentra-low text-pentra-low bg-pentra-low/10"
                                            } font-bold`}>
                                            {finding.cvss.toFixed(1)}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-pentra-text-muted">{finding.target}</td>
                                    <td className="px-4 py-3 uppercase tracking-wider text-[10px]">
                                        <span className={`flex items-center gap-2 ${finding.status === 'confirmed' ? 'text-pentra-low' : finding.status === 'new' ? 'text-pentra-cyan' : 'text-pentra-text-dim'}`}>
                                            {finding.status === 'confirmed' && <ShieldAlert size={12} />}
                                            {finding.status}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <Button variant="outline" size="sm" className="h-6 px-2 gap-1 border-transparent group-hover:border-pentra-border-strong hover:border-pentra-cyan hover:text-pentra-cyan opacity-0 group-hover:opacity-100 transition-all">
                                            INSPECT <ArrowRight size={12} />
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>

                    <div className="p-4 border-t border-pentra-border flex justify-between items-center text-xs font-mono text-pentra-text-muted">
                        <div>Showing 1-7 of 1,204 Findings</div>
                        <div className="flex gap-2">
                            <Button variant="outline" size="sm" className="h-6 px-3" disabled>PREV</Button>
                            <Button variant="outline" size="sm" className="h-6 px-3 border-pentra-border-strong text-white hover:text-pentra-primary hover:border-pentra-primary">NEXT</Button>
                        </div>
                    </div>
                </CardContent>
            </Card>

        </div>
    )
}
