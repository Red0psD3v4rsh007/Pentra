"use client"

import React from "react"
import Link from "next/link"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { StatusBadge } from "@/components/ui/status-badge"
import { Input } from "@/components/ui/input"
import { Radar, Plus, Search, Filter, Play, Square, Download, ChevronRight } from "lucide-react"

// Mock Data
const MOCK_SCANS = [
    { id: "OP-DELTA-X9", target: "banking-api.prod.local", status: "running", findings: { critical: 2, high: 14, medium: 21 }, duration: "02:14:05" },
    { id: "OP-ECHO-T2", target: "crm.dev.local", status: "completed", findings: { critical: 0, high: 4, medium: 31 }, duration: "00:45:12" },
    { id: "OP-NOVA-M1", target: "10.0.5.0/24", status: "queued", findings: { critical: 0, high: 0, medium: 0 }, duration: "--:--:--" },
    { id: "OP-ZETA-L8", target: "auth.corp.internal", status: "failed", findings: { critical: 1, high: 2, medium: 0 }, duration: "00:05:33" },
]

export default function ScansPage() {
    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-display font-bold tracking-widest text-white mb-1 uppercase">Operations</h1>
                    <p className="text-pentra-text-muted font-mono text-xs uppercase tracking-wider">ACTIVE & HISTORICAL SCANS</p>
                </div>
                <Link href="/scans/new">
                    <Button variant="default" glow className="gap-2">
                        <Plus size={14} /> NEW OPERATION
                    </Button>
                </Link>
            </div>

            {/* Toolbar */}
            <div className="flex items-center justify-between gap-4 p-4 bg-pentra-panel border border-pentra-border">
                <div className="flex items-center gap-4 flex-1">
                    <div className="relative flex-1 max-w-sm">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-pentra-text-muted" size={14} />
                        <Input placeholder="Filter operations by target or ID..." className="pl-9 h-8 text-xs rounded-none border-pentra-border-strong bg-pentra-black" />
                    </div>
                    <Button variant="outline" size="sm" className="gap-2">
                        <Filter size={14} /> FILTERS
                    </Button>
                </div>

                <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" className="text-pentra-text-dim hover:text-white" title="Stop All">
                        <Square size={14} />
                    </Button>
                    <Button variant="ghost" size="sm" className="text-pentra-text-dim hover:text-white" title="Export">
                        <Download size={14} />
                    </Button>
                </div>
            </div>

            {/* Operations Table */}
            <Card className="bg-pentra-surface border-pentra-border">
                <CardContent className="p-0">
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="text-[10px] text-pentra-text-muted uppercase font-mono bg-pentra-panel border-b border-pentra-border tracking-wider">
                                <tr>
                                    <th className="px-4 py-3 font-medium">Operation ID</th>
                                    <th className="px-4 py-3 font-medium">Target Scope</th>
                                    <th className="px-4 py-3 font-medium">Status</th>
                                    <th className="px-4 py-3 font-medium">Duration</th>
                                    <th className="px-4 py-3 font-medium text-right">Findings Matrix</th>
                                    <th className="px-4 py-3 font-medium text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-pentra-border font-mono text-xs">
                                {MOCK_SCANS.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-pentra-panel/50 transition-colors group">
                                        <td className="px-4 py-3">
                                            <Link href={`/scans/${scan.id}`} className="font-bold text-pentra-cyan hover:text-white transition-colors flex items-center gap-2">
                                                {scan.id}
                                            </Link>
                                        </td>
                                        <td className="px-4 py-3 text-pentra-text">{scan.target}</td>
                                        <td className="px-4 py-3"><StatusBadge status={scan.status as any} /></td>
                                        <td className="px-4 py-3 text-pentra-text-dim">{scan.duration}</td>
                                        <td className="px-4 py-3 text-right">
                                            <div className="flex gap-1 justify-end">
                                                <span className="inline-block w-6 bg-pentra-critical text-black text-center text-[10px]">{scan.findings.critical}</span>
                                                <span className="inline-block w-6 bg-pentra-high text-black text-center text-[10px]">{scan.findings.high}</span>
                                                <span className="inline-block w-6 bg-pentra-medium text-black text-center text-[10px]">{scan.findings.medium}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <Button variant="ghost" size="sm" className="h-6 px-2 text-pentra-primary hover:text-pentra-primary hover:bg-pentra-primary/10">HALT</Button>
                                                <Link href={`/scans/${scan.id}`}>
                                                    <Button variant="outline" size="sm" className="h-6 px-2 gap-1 border-pentra-border-strong hover:border-pentra-cyan hover:text-pentra-cyan">
                                                        VIEW <ChevronRight size={12} />
                                                    </Button>
                                                </Link>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}
