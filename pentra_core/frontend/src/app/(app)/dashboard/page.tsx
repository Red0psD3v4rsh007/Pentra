"use client"

import React from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ProgressRing } from "@/components/ui/progress-ring"
import { SeverityBadge } from "@/components/ui/severity-badge"
import { StatusBadge } from "@/components/ui/status-badge"
import { Shield, Radar, Target, Skull, ArrowRight } from "lucide-react"

export default function DashboardPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-3xl font-display font-bold tracking-tight text-white mb-2">Command Center</h1>
                    <p className="text-pentra-text-muted font-mono text-sm">SYSTEM STATUS: <span className="text-pentra-primary">ONLINE</span></p>
                </div>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Card glowOnHover className="bg-pentra-dark border-pentra-border-strong relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-pentra-info/5 rounded-bl-[100px] pointer-events-none" />
                    <CardContent className="p-6 flex items-center gap-6">
                        <ProgressRing progress={100} size={70} color="var(--color-pentra-info)" trackColor="var(--color-pentra-border-strong)" />
                        <div>
                            <p className="text-sm font-mono text-pentra-text-muted uppercase mb-1">Active Scans</p>
                            <div className="text-3xl font-display font-bold text-white group-hover:text-pentra-info transition-colors">12</div>
                        </div>
                    </CardContent>
                </Card>

                <Card glowOnHover className="bg-pentra-dark border-pentra-border-strong relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-pentra-critical/5 rounded-bl-[100px] pointer-events-none" />
                    <CardContent className="p-6 flex items-center gap-6">
                        <ProgressRing progress={85} size={70} color="var(--color-pentra-critical)" trackColor="var(--color-pentra-border-strong)" />
                        <div>
                            <p className="text-sm font-mono text-pentra-text-muted uppercase mb-1">Total Findings</p>
                            <div className="text-3xl font-display font-bold text-white group-hover:text-pentra-critical transition-colors">483</div>
                        </div>
                    </CardContent>
                </Card>

                <Card glowOnHover className="bg-pentra-dark border-pentra-border-strong relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-pentra-exploit/5 rounded-bl-[100px] pointer-events-none" />
                    <CardContent className="p-6 flex items-center gap-6">
                        <ProgressRing progress={32} size={70} color="var(--color-pentra-exploit)" trackColor="var(--color-pentra-border-strong)" />
                        <div>
                            <p className="text-sm font-mono text-pentra-text-muted uppercase mb-1">Exploits Verified</p>
                            <div className="text-3xl font-display font-bold text-white group-hover:text-pentra-exploit transition-colors">64</div>
                        </div>
                    </CardContent>
                </Card>

                <Card glowOnHover className="bg-pentra-dark border-pentra-border-strong relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-pentra-primary/5 rounded-bl-[100px] pointer-events-none" />
                    <CardContent className="p-6 flex items-center gap-6">
                        <ProgressRing progress={92} size={70} color="var(--color-pentra-primary)" trackColor="var(--color-pentra-border-strong)" />
                        <div>
                            <p className="text-sm font-mono text-pentra-text-muted uppercase mb-1">Attack Paths</p>
                            <div className="text-3xl font-display font-bold text-white group-hover:text-pentra-primary transition-colors">218</div>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

                {/* Live Activity Feed */}
                <Card className="lg:col-span-3 bg-pentra-black/50 border-pentra-border-strong max-h-[500px] flex flex-col">
                    <CardHeader className="pb-4 border-b border-pentra-border-strong bg-pentra-dark/50">
                        <div className="flex items-center justify-between">
                            <CardTitle className="flex items-center gap-2">
                                <Radar className="text-pentra-primary animate-pulse" size={20} />
                                LIVE ACTIVITY
                            </CardTitle>
                            <div className="text-xs font-mono text-pentra-info bg-pentra-info/10 px-2 py-1 rounded">STREAM CONNECTED</div>
                        </div>
                    </CardHeader>
                    <CardContent className="p-0 overflow-y-auto font-mono text-sm">
                        <div className="divide-y divide-pentra-border-strong">

                            {/* Mock Feed Items */}
                            <div className="p-4 hover:bg-pentra-surface transition-colors flex items-start gap-4">
                                <span className="text-pentra-text-dim text-xs whitespace-nowrap pt-0.5">14:02:11</span>
                                <span className="text-pentra-exploit">EXPLOIT</span>
                                <div className="flex-1">
                                    <p className="text-white">Successful reverse shell via Ghostscript CVE-2024-29510</p>
                                    <p className="text-pentra-text-muted mt-1 text-xs">Target: 10.0.4.52</p>
                                </div>
                                <div className="shrink-0"><SeverityBadge severity="critical" /></div>
                            </div>

                            <div className="p-4 hover:bg-pentra-surface transition-colors flex items-start gap-4">
                                <span className="text-pentra-text-dim text-xs whitespace-nowrap pt-0.5">14:00:45</span>
                                <span className="text-pentra-primary">VULN</span>
                                <div className="flex-1">
                                    <p className="text-white">Differential Analysis: Authentication Bypass</p>
                                    <p className="text-pentra-text-muted mt-1 text-xs">Target: https://api.prod.local/v1/users/admin</p>
                                </div>
                                <div className="shrink-0"><SeverityBadge severity="high" /></div>
                            </div>

                            <div className="p-4 hover:bg-pentra-surface transition-colors flex items-start gap-4">
                                <span className="text-pentra-text-dim text-xs whitespace-nowrap pt-0.5">13:58:22</span>
                                <span className="text-pentra-info">RECON</span>
                                <div className="flex-1">
                                    <p className="text-white">Path brute-force discovered 42 new endpoints</p>
                                    <p className="text-pentra-text-muted mt-1 text-xs">Target: example.com</p>
                                </div>
                            </div>

                            <div className="p-4 hover:bg-pentra-surface transition-colors flex items-start gap-4">
                                <span className="text-pentra-text-dim text-xs whitespace-nowrap pt-0.5">13:55:01</span>
                                <span className="text-pentra-credential">CREDENTIAL</span>
                                <div className="flex-1">
                                    <p className="text-white">Found exposed AWS keys in .git/config</p>
                                    <p className="text-pentra-text-muted mt-1 text-xs">Target: git.dev.local</p>
                                </div>
                                <div className="shrink-0"><SeverityBadge severity="critical" /></div>
                            </div>

                        </div>
                    </CardContent>
                </Card>

                {/* Top Vulnerabilities */}
                <Card className="lg:col-span-2 bg-pentra-dark border-pentra-border-strong">
                    <CardHeader className="pb-4 border-b border-pentra-border-strong">
                        <CardTitle className="flex items-center gap-2">
                            <Skull className="text-pentra-critical" size={20} />
                            CRITICAL VULNERABILITIES
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 space-y-4">

                        <div className="group border border-pentra-border bg-pentra-black p-4 rounded-lg hover:border-pentra-primary transition-colors cursor-pointer">
                            <div className="flex justify-between items-start mb-2">
                                <h4 className="font-semibold text-white group-hover:text-pentra-primary transition-colors">Remote Code Execution via Log4Shell</h4>
                                <div className="bg-pentra-critical/20 text-pentra-critical border border-pentra-critical/30 px-2 py-0.5 rounded font-mono text-xs font-bold">10.0</div>
                            </div>
                            <p className="text-sm text-pentra-text-muted mb-3">CVE-2021-44228 affecting order-processing service.</p>
                            <div className="flex items-center gap-2">
                                <SeverityBadge severity="critical" variant="default" />
                                <span className="text-xs font-mono text-pentra-text-dim bg-pentra-border px-1.5 py-0.5 rounded">OWASP-A06</span>
                            </div>
                        </div>

                        <div className="group border border-pentra-border bg-pentra-black p-4 rounded-lg hover:border-pentra-primary transition-colors cursor-pointer">
                            <div className="flex justify-between items-start mb-2">
                                <h4 className="font-semibold text-white group-hover:text-pentra-primary transition-colors">SQL Injection</h4>
                                <div className="bg-pentra-high/20 text-pentra-high border border-pentra-high/30 px-2 py-0.5 rounded font-mono text-xs font-bold">8.5</div>
                            </div>
                            <p className="text-sm text-pentra-text-muted mb-3">Blind boolean-based SQLi discovered in /api/search.</p>
                            <div className="flex items-center gap-2">
                                <SeverityBadge severity="high" variant="default" />
                                <span className="text-xs font-mono text-pentra-text-dim bg-pentra-border px-1.5 py-0.5 rounded">OWASP-A03</span>
                            </div>
                        </div>

                        <button className="w-full text-center py-2 text-sm font-mono text-pentra-primary hover:text-white transition-colors flex items-center justify-center gap-2">
                            VIEW ALL FINDINGS <ArrowRight size={14} />
                        </button>

                    </CardContent>
                </Card>

            </div>

            {/* Recent Scans */}
            <Card className="bg-pentra-dark border-pentra-border-strong">
                <CardHeader className="pb-4 border-b border-pentra-border-strong">
                    <CardTitle>RECENT OPERATIONS</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                    <table className="w-full text-sm text-left">
                        <thead className="text-xs text-pentra-text-muted uppercase font-mono bg-pentra-black">
                            <tr>
                                <th className="px-6 py-3 font-medium">Operation Name</th>
                                <th className="px-6 py-3 font-medium">Target</th>
                                <th className="px-6 py-3 font-medium">Status</th>
                                <th className="px-6 py-3 font-medium text-right">Findings</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-pentra-border-strong font-mono">
                            <tr className="hover:bg-pentra-surface/50 transition-colors">
                                <td className="px-6 py-4 font-medium text-white">OP-DELTA-X9</td>
                                <td className="px-6 py-4 text-pentra-text-muted">banking-api.prod.local</td>
                                <td className="px-6 py-4"><StatusBadge status="running" /></td>
                                <td className="px-6 py-4 text-right">
                                    <div className="flex gap-1 justify-end">
                                        <span className="inline-block w-6 bg-pentra-critical text-pentra-black text-center text-[10px] rounded">2</span>
                                        <span className="inline-block w-6 bg-pentra-high text-pentra-black text-center text-[10px] rounded">14</span>
                                    </div>
                                </td>
                            </tr>
                            <tr className="hover:bg-pentra-surface/50 transition-colors">
                                <td className="px-6 py-4 font-medium text-white">OP-ECHO-T2</td>
                                <td className="px-6 py-4 text-pentra-text-muted">crm.dev.local</td>
                                <td className="px-6 py-4"><StatusBadge status="completed" /></td>
                                <td className="px-6 py-4 text-right">
                                    <div className="flex gap-1 justify-end">
                                        <span className="inline-block w-6 bg-pentra-medium text-pentra-black text-center text-[10px] rounded">4</span>
                                        <span className="inline-block w-6 bg-pentra-low text-pentra-black text-center text-[10px] rounded">31</span>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </CardContent>
            </Card>

        </div>
    )
}
