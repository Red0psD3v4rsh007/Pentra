"use client"

import React, { useState } from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { StatusBadge } from "@/components/ui/status-badge"
import { ProgressRing } from "@/components/ui/progress-ring"
import { ChevronLeft, Terminal, FileText, AlertTriangle, Play, FastForward, CheckCircle, Network, Clock, ShieldAlert } from "lucide-react"

import AttackGraph from "@/components/graph/AttackGraph"

const TABS = ["OVERVIEW", "ATTACK GRAPH", "FINDINGS", "EVIDENCE", "TIMELINE", "REPORT"]

export default function ScanDetailPage() {
    const params = useParams()
    const scanId = params.id as string
    const [activeTab, setActiveTab] = useState("OVERVIEW")

    return (
        <div className="space-y-6">

            {/* Header */}
            <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                    <Link href="/scans">
                        <Button variant="outline" size="icon" className="h-10 w-10 border-pentra-border-strong">
                            <ChevronLeft size={16} />
                        </Button>
                    </Link>
                    <div>
                        <div className="flex items-center gap-3 mb-1">
                            <h1 className="text-2xl font-display font-bold tracking-widest text-white uppercase">{scanId}</h1>
                            <StatusBadge status="running" pulse />
                        </div>
                        <p className="text-pentra-text-muted font-mono text-sm uppercase tracking-wider">TARGET: banking-api.prod.local // FULL OFFENSIVE</p>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    <div className="text-right mr-4 font-mono">
                        <div className="text-xs text-pentra-text-muted mb-1">DURATION</div>
                        <div className="text-sm text-white">02:14:05</div>
                    </div>
                    <Button variant="outline" size="sm" className="gap-2 border-pentra-border-strong">
                        <Terminal size={14} /> CONSOLE
                    </Button>
                    <Button variant="destructive" size="sm" className="gap-2" glow>
                        <AlertTriangle size={14} /> HALT ALARM
                    </Button>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-pentra-border">
                {TABS.map(tab => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`px-6 py-3 font-mono text-xs font-bold tracking-widest transition-colors relative
              ${activeTab === tab ? "text-pentra-primary" : "text-pentra-text-muted hover:text-white hover:bg-pentra-surface"}
            `}
                    >
                        {tab}
                        {activeTab === tab && (
                            <div className="absolute bottom-0 left-0 w-full h-[2px] bg-pentra-primary box-glow" />
                        )}
                    </button>
                ))}
            </div>

            {/* Content Area */}
            <div className="mt-6">
                {activeTab === "OVERVIEW" && <OverviewTab />}
                {activeTab === "ATTACK GRAPH" && <AttackGraph />}
                {activeTab === "FINDINGS" && <PlaceholderTab name="Vulnerability Matrix & Filters" icon={<ShieldAlert size={32} className="text-pentra-critical mb-4" />} />}
                {activeTab === "EVIDENCE" && <PlaceholderTab name="Raw HTTP Request/Response Data" icon={<FileText size={32} className="text-pentra-text-muted mb-4" />} />}
                {activeTab === "TIMELINE" && <PlaceholderTab name="Chronological Event Stream" icon={<Clock size={32} className="text-pentra-info mb-4" />} />}
                {activeTab === "REPORT" && <PlaceholderTab name="Executive & Technical Markdown Reports" icon={<FileText size={32} className="text-pentra-text-muted mb-4" />} />}
            </div>
        </div>
    )
}

function OverviewTab() {
    return (
        <div className="space-y-6">

            {/* Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <MetricCard label="Total Discovered Assets" value="24" color="cyan" />
                <MetricCard label="Critical Vulns" value="2" color="critical" />
                <MetricCard label="Exploits Sent" value="843" color="exploit" />
                <MetricCard label="WAF Bypasses" value="7" color="medium" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Pipeline Graph (DAG) */}
                <Card className="lg:col-span-2">
                    <CardHeader>
                        <CardTitle>Execution Pipeline</CardTitle>
                    </CardHeader>
                    <CardContent className="pt-6">
                        <div className="flex flex-col space-y-8 relative before:absolute before:inset-0 before:ml-[1.15rem] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-pentra-border before:to-transparent">

                            <PipelineNode
                                title="Intelligence Gathering"
                                status="completed"
                                detail="412 endpoints discovered, 24 subdomains"
                                time="00:12:05"
                            />

                            <PipelineNode
                                title="Vulnerability Discovery"
                                status="completed"
                                detail="Heuristic engine identified 42 potential flaws"
                                time="00:45:22"
                            />

                            <PipelineNode
                                title="Attack Graph Expansion"
                                status="running"
                                detail="Mapping lateral movement paths"
                                time="LIVE"
                            />

                            <PipelineNode
                                title="Exploit Verification"
                                status="evaluating"
                                detail="Attempting 3 RCE payloads on identified targets"
                                time="PENDING"
                            />

                        </div>
                    </CardContent>
                </Card>

                {/* Live Terminal Log */}
                <Card className="flex flex-col h-[500px]">
                    <CardHeader className="bg-black border-b border-pentra-border-strong rounded-none">
                        <CardTitle className="text-pentra-primary">EXPLOIT CONSOLE</CardTitle>
                    </CardHeader>
                    <CardContent className="bg-black p-4 flex-1 overflow-y-auto font-mono text-xs leading-relaxed scanlines relative">
                        <div className="text-pentra-info mb-2 text-[10px] uppercase">Connecting to worker stream... ESTABLISHED</div>
                        <LogLine time="14:02:11" type="INFO">Initializing Ghostscript payload mutator...</LogLine>
                        <LogLine time="14:02:12" type="WARN" isYellow>WAF detected blocking signature #4021</LogLine>
                        <LogLine time="14:02:18" type="INFO">Applying obfuscation strategy: Unicode Escape</LogLine>
                        <LogLine time="14:02:22" type="INFO">Sending mutated payload batch (10 ops)</LogLine>
                        <LogLine time="14:02:25" type="SUCCESS" isRed>REVERSE SHELL CAUGHT [10.0.4.52]</LogLine>
                        <LogLine time="14:02:26" type="INFO">Agent established. Elevating privileges...</LogLine>
                        {/* Blinking cursor */}
                        <div className="mt-2 text-pentra-primary animate-pulse">_</div>
                    </CardContent>
                </Card>

            </div>
        </div>
    )
}

function MetricCard({ label, value, color }: { label: string, value: string, color: string }) {
    const colorMap: any = {
        cyan: "text-pentra-cyan",
        critical: "text-pentra-critical",
        exploit: "text-pentra-exploit",
        medium: "text-pentra-medium"
    }
    return (
        <div className="border border-pentra-border bg-pentra-panel p-4 hover:border-pentra-border-strong transition-colors group">
            <div className="text-[10px] font-mono text-pentra-text-muted uppercase tracking-widest mb-2">{label}</div>
            <div className={`text-4xl font-display font-bold ${colorMap[color]} group-hover:scale-105 transition-transform origin-left`}>{value}</div>
        </div>
    )
}

function PipelineNode({ title, status, detail, time }: { title: string, status: string, detail: string, time: string }) {
    const getIcon = () => {
        if (status === "completed") return <CheckCircle size={14} className="text-pentra-low" />
        if (status === "running") return <Play size={14} className="text-pentra-cyan" fill="currentColor" />
        return <FastForward size={14} className="text-pentra-text-muted" />
    }

    return (
        <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
            {/* Icon Node */}
            <div className={`flex items-center justify-center w-8 h-8 rounded-full border-2 
        ${status === "running" ? "bg-black border-pentra-cyan shadow-[0_0_15px_rgba(0,234,255,0.4)]" :
                    status === "completed" ? "bg-black border-pentra-low shadow-[0_0_10px_rgba(0,230,118,0.2)]" :
                        "bg-pentra-surface border-pentra-border"} 
        text-white absolute left-1/2 -translate-y-4 sm:translate-y-0 transform -translate-x-1/2 z-10 transition-all`}
            >
                {getIcon()}
            </div>

            {/* Card */}
            <div className="w-[calc(50%-2rem)] md:w-[calc(50%-2.5rem)] p-4 border border-pentra-border bg-pentra-panel hover:border-pentra-border-strong transition-colors">
                <div className="flex justify-between items-start mb-2">
                    <h4 className={`text-sm font-bold font-sans uppercase tracking-wider ${status === "running" ? "text-pentra-cyan" : "text-white"}`}>{title}</h4>
                    <span className="text-[10px] font-mono text-pentra-text-dim">{time}</span>
                </div>
                <p className="text-xs text-pentra-text-muted">{detail}</p>
            </div>
        </div>
    )
}

function LogLine({ time, type, children, isYellow, isRed }: { time: string, type: string, children: React.ReactNode, isYellow?: boolean, isRed?: boolean }) {
    return (
        <div className={`flex gap-3 mb-1 ${isYellow ? "text-pentra-medium" : isRed ? "text-pentra-critical font-bold" : "text-pentra-text"}`}>
            <span className="text-pentra-text-dim shrink-0">{time}</span>
            <span className="shrink-0 w-12 text-pentra-text-muted">[{type}]</span>
            <span className="break-all">{children}</span>
        </div>
    )
}

function PlaceholderTab({ name, icon }: { name: string, icon: React.ReactNode }) {
    return (
        <div className="border border-pentra-border border-dashed bg-pentra-black/50 rounded-none h-64 flex flex-col items-center justify-center text-pentra-text-muted">
            {icon}
            <p className="font-mono text-xs uppercase tracking-widest">{name}</p>
            <p className="text-xs mt-2 opacity-50">Future Implementation Phase</p>
        </div>
    )
}
