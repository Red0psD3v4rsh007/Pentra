"use client"

import React from "react"
import { Button } from "@/components/ui/button"
import { Trash2, Copy, Eye, Plus } from "lucide-react"

export default function ApiKeysPage() {
    const MOCK_KEYS = [
        { name: "CI/CD Deployment Token", keyId: "ptk_live_a8x...", lastUsed: "2 mins ago", created: "2024-01-15" },
        { name: "Grafana Telemetry Sync", keyId: "ptk_live_9b4...", lastUsed: "1 hour ago", created: "2024-02-02" },
        { name: "Legacy Script (Deprecated)", keyId: "ptk_test_1c2...", lastUsed: "4 months ago", created: "2023-11-20" },
    ]

    return (
        <div className="max-w-4xl space-y-8 animate-in fade-in duration-300">

            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-lg font-display font-bold text-white uppercase tracking-widest mb-1">API Key Management</h2>
                    <p className="font-mono text-xs text-pentra-text-muted uppercase tracking-wider">Programmatic Access Tokens</p>
                </div>
                <Button variant="default" glow className="gap-2">
                    <Plus size={14} /> GENERATE NEW KEY
                </Button>
            </div>

            <div className="bg-pentra-black border border-pentra-border">
                <table className="w-full text-sm text-left">
                    <thead className="text-[10px] text-pentra-text-muted uppercase font-mono bg-pentra-panel border-b border-pentra-border tracking-wider">
                        <tr>
                            <th className="px-4 py-3 font-medium">Identifier mapping</th>
                            <th className="px-4 py-3 font-medium">Token ID</th>
                            <th className="px-4 py-3 font-medium">Last Active</th>
                            <th className="px-4 py-3 font-medium">Created On</th>
                            <th className="px-4 py-3 font-medium text-right">Controls</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-pentra-border font-mono text-xs">
                        {MOCK_KEYS.map((key, i) => (
                            <tr key={i} className="hover:bg-pentra-panel/50 transition-colors group">
                                <td className="px-4 py-4">
                                    <span className="font-bold text-white">{key.name}</span>
                                </td>
                                <td className="px-4 py-4 text-pentra-cyan">{key.keyId}</td>
                                <td className="px-4 py-4 text-pentra-text-dim">{key.lastUsed}</td>
                                <td className="px-4 py-4 text-pentra-text-dim">{key.created}</td>
                                <td className="px-4 py-4 text-right">
                                    <div className="flex items-center justify-end gap-2 text-pentra-text-muted">
                                        <button className="p-1 hover:text-white transition-colors" title="View"><Eye size={14} /></button>
                                        <button className="p-1 hover:text-white transition-colors" title="Copy"><Copy size={14} /></button>
                                        <button className="p-1 hover:text-pentra-critical text-pentra-critical/70 transition-colors" title="Revoke"><Trash2 size={14} /></button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="p-4 border border-pentra-border-strong bg-pentra-panel/50 border-l-2 border-l-pentra-medium">
                <h4 className="text-[10px] font-mono uppercase font-bold text-pentra-medium mb-1">SECURITY WARNING</h4>
                <p className="text-xs text-pentra-text-muted font-mono leading-relaxed">
                    API keys carry the same operational privileges as the user who generates them. Do not embed keys directly in source code.
                    PENTRA systems periodically scan public repositories for leaked tokens.
                </p>
            </div>
        </div>
    )
}
