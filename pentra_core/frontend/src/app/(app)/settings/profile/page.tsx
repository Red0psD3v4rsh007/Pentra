"use client"

import React from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export default function ProfileSettingsPage() {
    return (
        <div className="max-w-2xl space-y-8 animate-in fade-in duration-300">

            <div>
                <h2 className="text-lg font-display font-bold text-white uppercase tracking-widest mb-1">Operator Profile</h2>
                <p className="font-mono text-xs text-pentra-text-muted uppercase tracking-wider">Manage your identity and authentication</p>
            </div>

            <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4 border-b border-pentra-border-strong pb-6">
                    <div className="space-y-2">
                        <label className="text-[10px] font-mono font-bold tracking-widest text-pentra-text-muted uppercase">Callsign / Operator Name</label>
                        <Input defaultValue="Admin Operator" className="font-mono text-sm max-w-md bg-pentra-black" />
                    </div>

                    <div className="space-y-2">
                        <label className="text-[10px] font-mono font-bold tracking-widest text-pentra-text-muted uppercase">Registered Communication Link (Email)</label>
                        <Input defaultValue="admin@pentra.local" disabled className="font-mono text-sm max-w-md bg-pentra-black/50 text-pentra-text-dim border-pentra-border-strong" />
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-4 border-b border-pentra-border-strong pb-6">
                    <h3 className="text-sm font-sans font-bold text-white uppercase tracking-widest">Authentication Security</h3>

                    <div className="flex items-center justify-between p-4 bg-pentra-black border border-pentra-border-strong">
                        <div>
                            <div className="text-xs font-bold text-white tracking-widest uppercase mb-1">Password Change</div>
                            <div className="text-[10px] font-mono text-pentra-text-muted">Last changed 42 days ago</div>
                        </div>
                        <Button variant="outline" size="sm" className="border-pentra-border-strong">UPDATE TOKEN</Button>
                    </div>

                    <div className="flex items-center justify-between p-4 bg-pentra-cyan/5 border border-pentra-cyan/30">
                        <div>
                            <div className="text-xs font-bold text-pentra-cyan tracking-widest uppercase mb-1">Multi-Factor Authentication (ACTIVE)</div>
                            <div className="text-[10px] font-mono text-pentra-text-muted">Hardware Key / TOTP enforced via policy</div>
                        </div>
                        <Button variant="default" size="sm" className="bg-pentra-cyan text-black hover:bg-pentra-cyan/80">CONFIGURE MFA</Button>
                    </div>
                </div>

                <div className="flex justify-end pt-4">
                    <Button variant="default" glow className="gap-2">
                        COMMIT SYSTEM CHANGES
                    </Button>
                </div>

            </div>
        </div>
    )
}
