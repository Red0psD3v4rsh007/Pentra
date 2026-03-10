"use client"

import React, { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ChevronLeft, Radar, Shield, Target, Zap } from "lucide-react"

export default function NewScanPage() {
    const router = useRouter()
    const [target, setTarget] = useState("")

    const handleLaunch = (e: React.FormEvent) => {
        e.preventDefault()
        // Simulated scan creation
        router.push("/scans/OP-NEW-1")
    }

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            <div className="flex items-center gap-4 mb-8">
                <Link href="/scans">
                    <Button variant="outline" size="icon" className="h-8 w-8 border-pentra-border-strong">
                        <ChevronLeft size={16} />
                    </Button>
                </Link>
                <div>
                    <h1 className="text-2xl font-display font-bold tracking-widest text-white mb-1 uppercase">Initialize Operation</h1>
                    <p className="text-pentra-text-muted font-mono text-xs uppercase tracking-wider">CONFIGURE OFFENSIVE PARAMETERS</p>
                </div>
            </div>

            <form onSubmit={handleLaunch} className="space-y-8">

                {/* Step 1: Target Definition */}
                <div className="space-y-4">
                    <div className="flex items-center gap-2 border-b border-pentra-border pb-2">
                        <span className="text-pentra-primary font-mono font-bold">01 //</span>
                        <h2 className="text-sm font-sans font-semibold tracking-widest text-white uppercase">Target Definition</h2>
                    </div>

                    <Card className="bg-pentra-panel">
                        <CardContent className="p-6 space-y-4">
                            <div className="space-y-2">
                                <label className="text-xs font-mono text-pentra-text-muted uppercase tracking-wider">Primary Target (IP, CIDR, Domain)</label>
                                <Input
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    placeholder="e.g. 10.0.0.0/24 or api.production.internal"
                                    className="font-mono text-sm max-w-xl"
                                    required
                                />
                            </div>
                        </CardContent>
                    </Card>
                </div>

                {/* Step 2: Operational Profile */}
                <div className="space-y-4">
                    <div className="flex items-center gap-2 border-b border-pentra-border pb-2">
                        <span className="text-pentra-primary font-mono font-bold">02 //</span>
                        <h2 className="text-sm font-sans font-semibold tracking-widest text-white uppercase">Operational Profile</h2>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

                        <label className="cursor-pointer">
                            <input type="radio" name="profile" className="peer sr-only" defaultChecked />
                            <Card className="h-full bg-pentra-black border-pentra-border-strong peer-checked:border-pentra-primary peer-checked:shadow-[0_0_15px_rgba(255,0,60,0.15)] transition-all">
                                <CardHeader className="pb-2 border-none">
                                    <Radar className="text-pentra-primary mb-2" size={24} />
                                    <CardTitle className="text-white text-base">Recon & Logic</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-xs text-pentra-text-muted mb-4">Deep asset discovery, logic mapping, and zero-day hypothesis generation.</p>
                                    <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">SubdomainBrute</span>
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">DiffAnalysis</span>
                                    </div>
                                </CardContent>
                            </Card>
                        </label>

                        <label className="cursor-pointer">
                            <input type="radio" name="profile" className="peer sr-only" />
                            <Card className="h-full bg-pentra-black border-pentra-border-strong peer-checked:border-pentra-primary peer-checked:shadow-[0_0_15px_rgba(255,0,60,0.15)] transition-all">
                                <CardHeader className="pb-2 border-none">
                                    <Zap className="text-pentra-critical mb-2" size={24} />
                                    <CardTitle className="text-white text-base">Full Offensive</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-xs text-pentra-text-muted mb-4">Autonomous end-to-end exploitation. Attempts to achieve RCE and lateral movement.</p>
                                    <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">SafeExploit</span>
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">PayloadForge</span>
                                    </div>
                                </CardContent>
                            </Card>
                        </label>

                        <label className="cursor-pointer">
                            <input type="radio" name="profile" className="peer sr-only" />
                            <Card className="h-full bg-pentra-black border-pentra-border-strong peer-checked:border-pentra-primary peer-checked:shadow-[0_0_15px_rgba(255,0,60,0.15)] transition-all">
                                <CardHeader className="pb-2 border-none">
                                    <Shield className="text-pentra-cyan mb-2" size={24} />
                                    <CardTitle className="text-white text-base">Stealth Ops</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-xs text-pentra-text-muted mb-4">Low-noise execution designed to evade WAFs and IPS/IDS detection.</p>
                                    <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">WAFBypass</span>
                                        <span className="bg-pentra-surface px-2 py-0.5 text-pentra-text border border-pentra-border">SlowLoris</span>
                                    </div>
                                </CardContent>
                            </Card>
                        </label>

                    </div>
                </div>

                {/* Action Bar */}
                <div className="pt-6 border-t border-pentra-border flex justify-end gap-4">
                    <Link href="/scans">
                        <Button type="button" variant="ghost">CANCEL</Button>
                    </Link>
                    <Button type="submit" size="lg" glow disabled={!target}>
                        LAUNCH OPERATION
                    </Button>
                </div>

            </form>
        </div>
    )
}
