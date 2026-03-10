"use client"

import React from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ProgressRing } from "@/components/ui/progress-ring"
import { Shield, BrainCircuit, Target, Network, Zap } from "lucide-react"

export default function IntelligencePage() {
    return (
        <div className="space-y-6">

            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-2xl font-display font-bold tracking-widest text-white mb-1 uppercase">Offensive Intelligence</h1>
                    <p className="text-pentra-text-muted font-mono text-xs uppercase tracking-wider">AI LEARNING & ATTACK SURFACE TELEMETRY</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" size="sm" className="gap-2 border-pentra-cyan text-pentra-cyan">
                        <BrainCircuit size={14} /> EXPORT MODEL WEIGHTS
                    </Button>
                </div>
            </div>

            {/* Global Telemetry */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <TelemetryCard label="Global Assets Discovered" value="1,492" icon={<Network size={16} />} color="text-pentra-cyan" border="border-pentra-cyan/30" />
                <TelemetryCard label="Total Payload Mutations" value="84,201" icon={<Zap size={16} />} color="text-pentra-exploit" border="border-pentra-exploit/30" />
                <TelemetryCard label="Successful Attack Paths" value="318" icon={<Target size={16} />} color="text-pentra-primary" border="border-pentra-primary/30" />
                <TelemetryCard label="WAF Bypasses Learned" value="84" icon={<Shield size={16} />} color="text-pentra-medium" border="border-pentra-medium/30" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Learning Model Effectiveness */}
                <Card className="lg:col-span-2 bg-pentra-surface border-pentra-border">
                    <CardHeader className="border-b border-pentra-border/50">
                        <div className="flex justify-between items-center">
                            <CardTitle>AI Exploitation Efficacy Over Time</CardTitle>
                            <span className="text-[10px] font-mono bg-pentra-exploit/10 text-pentra-exploit px-2 py-1">MODEL: V-1.4.2_OFFENSIVE</span>
                        </div>
                    </CardHeader>
                    <CardContent className="p-6">
                        <div className="h-64 relative w-full border-l border-b border-pentra-border-strong flex items-end justify-between px-4 pb-2 pt-8">
                            {/* Mock Bar Chart - representing AI learning improvement */}
                            {[32, 45, 41, 58, 62, 79, 84, 86, 91, 94].map((h, i) => (
                                <div key={i} className="w-12 group relative flex justify-center">
                                    <div className="absolute -top-8 opacity-0 group-hover:opacity-100 transition-opacity text-[10px] font-mono text-pentra-cyan">{h}%</div>
                                    <div
                                        className="w-full bg-pentra-border-strong group-hover:bg-pentra-cyan transition-colors relative overflow-hidden"
                                        style={{ height: `${h}%` }}
                                    >
                                        <div className="absolute top-0 w-full h-[1px] bg-pentra-cyan box-glow" />
                                    </div>
                                    <div className="absolute -bottom-6 text-[10px] font-mono text-pentra-text-dim">WEEK {i + 1}</div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>

                {/* Payload Success Rates */}
                <Card className="bg-pentra-surface border-pentra-border">
                    <CardHeader className="border-b border-pentra-border/50">
                        <CardTitle>Top Mutation Strategies</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                        <div className="divide-y divide-pentra-border font-mono text-xs">
                            <MutationRow strategy="Unicode Escape Injection" successRate={82} count="4.2k" color="pentra-primary" />
                            <MutationRow strategy="Chunked Transfer Ev" successRate={76} count="3.8k" color="pentra-medium" />
                            <MutationRow strategy="Polyglot XSS (SVG)" successRate={68} count="2.1k" color="pentra-cyan" />
                            <MutationRow strategy="SQLi Time-Delay Var" successRate={54} count="8k" color="pentra-info" />
                            <MutationRow strategy="Zero-Byte Truncation" successRate={41} count="1.2k" color="pentra-text-dim" />
                        </div>
                    </CardContent>
                </Card>

            </div>

            {/* Target Clustering Analysis */}
            <h2 className="text-sm font-sans font-semibold tracking-widest text-white uppercase mt-8 border-b border-pentra-border pb-2">Target Cluster Typology</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

                <ClusterCard
                    name="CLUSTER ALPHA: Legacy Core"
                    tech="Java, WebSphere, Oracle DB"
                    vulns={142}
                    predictability={94}
                    color="var(--color-pentra-critical)"
                />

                <ClusterCard
                    name="CLUSTER BETA: Modern Cloud"
                    tech="AWS IAM, Kubernetes, Node.js"
                    vulns={38}
                    predictability={41}
                    color="var(--color-pentra-cyan)"
                />

                <ClusterCard
                    name="CLUSTER GAMMA: Shadow IT"
                    tech="WordPress, PHP 5.6, OpenSSH"
                    vulns={301}
                    predictability={88}
                    color="var(--color-pentra-exploit)"
                />

            </div>

        </div>
    )
}

function TelemetryCard({ label, value, icon, color, border }: { label: string, value: string, icon: React.ReactNode, color: string, border: string }) {
    return (
        <div className={`border bg-pentra-panel p-4 flex flex-col justify-between h-28 ${border}`}>
            <div className={`flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest ${color}`}>
                {icon} {label}
            </div>
            <div className={`text-3xl font-display font-bold text-white`}>{value}</div>
        </div>
    )
}

function MutationRow({ strategy, successRate, count, color }: { strategy: string, successRate: number, count: string, color: string }) {
    return (
        <div className="p-4 hover:bg-pentra-panel/50 transition-colors flex items-center justify-between">
            <div>
                <div className="text-white font-bold mb-1">{strategy}</div>
                <div className="text-[10px] text-pentra-text-muted">EXECUTED: {count} TIMES</div>
            </div>
            <div className="flex items-center gap-3">
                <div className="w-16 h-1 bg-pentra-black border border-pentra-border-strong relative">
                    <div className={`absolute top-0 left-0 h-full bg-${color}`} style={{ width: `${successRate}%` }} />
                </div>
                <span className={`text-${color} font-bold w-8 text-right`}>{successRate}%</span>
            </div>
        </div>
    )
}

function ClusterCard({ name, tech, vulns, predictability, color }: { name: string, tech: string, vulns: number, predictability: number, color: string }) {
    return (
        <Card className="bg-pentra-black border-pentra-border-strong hover:border-pentra-border transition-colors">
            <CardHeader className="bg-pentra-surface/50 border-none pb-2">
                <CardTitle className="text-white normal-case tracking-normal text-sm">{name}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                <div>
                    <div className="text-[10px] font-mono text-pentra-text-dim uppercase tracking-widest mb-1">TECHNOLOGY FINGERPRINT</div>
                    <div className="text-xs text-pentra-text-muted font-mono">{tech}</div>
                </div>
                <div className="flex items-end justify-between pt-2 border-t border-pentra-border-strong">
                    <div>
                        <div className="text-[10px] font-mono text-pentra-text-dim uppercase tracking-widest mb-1">KNOWN VULNS</div>
                        <div className="text-xl font-display font-bold text-white">{vulns}</div>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="text-[10px] font-mono text-pentra-text-dim uppercase tracking-widest text-right">MODEL<br />CONFIDENCE</div>
                        <ProgressRing progress={predictability} size={40} strokeWidth={3} color={color} />
                    </div>
                </div>
            </CardContent>
        </Card>
    )
}
