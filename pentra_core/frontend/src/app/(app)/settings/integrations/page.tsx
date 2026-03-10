"use client"

import React from "react"
import { Button } from "@/components/ui/button"
import { CheckCircle2, XCircle, RefreshCw } from "lucide-react"

export default function IntegrationsPage() {
    return (
        <div className="max-w-4xl space-y-8 animate-in fade-in duration-300">

            <div>
                <h2 className="text-lg font-display font-bold text-white uppercase tracking-widest mb-1">External Integrations</h2>
                <p className="font-mono text-xs text-pentra-text-muted uppercase tracking-wider">Connect SIEMs, Ticketing, and Communications</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                {/* Active Integration */}
                <div className="border border-pentra-border-strong bg-pentra-black p-6 hover:border-pentra-primary transition-colors group relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-pentra-low shadow-[0_0_15px_rgba(0,230,118,0.5)]" />
                    <div className="flex items-start justify-between mb-4">
                        <div>
                            <h3 className="text-white font-bold tracking-widest uppercase">Slack Operations</h3>
                            <p className="text-[10px] font-mono text-pentra-text-dim mt-1">ChatOps & Alerting</p>
                        </div>
                        <span className="flex items-center gap-1 text-[10px] font-mono text-pentra-low uppercase border border-pentra-low/30 bg-pentra-low/10 px-2 py-1">
                            <CheckCircle2 size={12} /> SYNCED
                        </span>
                    </div>
                    <p className="text-xs text-pentra-text-muted mb-6">Routes critical vulnerability discoveries directly to #sec-ops channel.</p>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="w-full border-pentra-border-strong">CONFIGURE</Button>
                        <Button variant="ghost" size="icon" className="shrink-0 text-pentra-text-dim hover:text-white" title="Sync Now"><RefreshCw size={14} /></Button>
                    </div>
                </div>

                {/* Inactive Integration */}
                <div className="border border-pentra-border-strong bg-pentra-black p-6 hover:border-pentra-border transition-colors group relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-pentra-border" />
                    <div className="flex items-start justify-between mb-4">
                        <div>
                            <h3 className="text-white font-bold tracking-widest uppercase">Jira Software</h3>
                            <p className="text-[10px] font-mono text-pentra-text-dim mt-1">Issue Tracking</p>
                        </div>
                        <span className="flex items-center gap-1 text-[10px] font-mono text-pentra-text-dim uppercase border border-pentra-border-strong px-2 py-1">
                            <XCircle size={12} /> DISCONNECTED
                        </span>
                    </div>
                    <p className="text-xs text-pentra-text-muted mb-6">Automatically generate tickets when High/Critical findings are confirmed by AI.</p>
                    <Button variant="default" size="sm" className="w-full bg-pentra-surface border border-pentra-border hover:bg-pentra-surface text-white">CONNECT OAUTH</Button>
                </div>

                {/* Webhook */}
                <div className="border border-pentra-border-strong bg-pentra-black p-6 hover:border-pentra-border transition-colors group relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-pentra-primary shadow-[0_0_15px_rgba(255,0,60,0.5)]" />
                    <div className="flex items-start justify-between mb-4">
                        <div>
                            <h3 className="text-white font-bold tracking-widest uppercase">Custom Webhook</h3>
                            <p className="text-[10px] font-mono text-pentra-text-dim mt-1">Global Event Firehose</p>
                        </div>
                        <span className="flex items-center gap-1 text-[10px] font-mono text-pentra-primary uppercase border border-pentra-primary/30 bg-pentra-primary/10 px-2 py-1">
                            <CheckCircle2 size={12} /> ACTIVE
                        </span>
                    </div>
                    <p className="text-xs text-pentra-text-muted mb-6">Streaming all pipeline events to splunk.internal.corp:8443</p>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="w-full border-pentra-border-strong">EDIT PAYLOAD</Button>
                        <Button variant="ghost" size="icon" className="shrink-0 text-pentra-text-dim hover:text-white" title="Test Fire"><Play size={14} /></Button>
                    </div>
                </div>

            </div>

        </div>
    )
}

// Ensure Play icon is imported for the Webhook card
import { Play } from "lucide-react"
