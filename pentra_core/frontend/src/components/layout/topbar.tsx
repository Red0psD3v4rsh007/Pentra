"use client"

import React from "react"
import { Search, Bell, UserIcon } from "lucide-react"
import { Input } from "@/components/ui/input"

export function Topbar() {
    return (
        <header className="h-16 border-b border-pentra-border bg-pentra-black/80 backdrop-blur-md flex items-center justify-between px-6 z-10 sticky top-0">

            {/* Search / Command Palette Trigger */}
            <div className="flex-1 max-w-md">
                <div className="relative group">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-pentra-text-muted group-focus-within:text-pentra-primary transition-colors" size={18} />
                    <Input
                        placeholder="Search targets, findings, scans... (⌘K)"
                        className="pl-10 bg-pentra-surface border-pentra-border-strong hover:border-pentra-primary/50 transition-colors h-9"
                    />
                </div>
            </div>

            {/* Right Actions */}
            <div className="flex items-center gap-4">
                <button className="relative p-2 text-pentra-text-muted hover:text-white transition-colors rounded-full hover:bg-pentra-surface">
                    <Bell size={20} />
                    {/* Notification Badge - Pulse Red */}
                    <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-pentra-critical rounded-full border border-pentra-black animate-pulse" />
                </button>

                <div className="h-8 w-px bg-pentra-border mx-1" />

                <button className="flex items-center gap-2 hover:bg-pentra-surface p-1.5 pr-3 rounded-full border border-transparent hover:border-pentra-border transition-all">
                    <div className="w-8 h-8 rounded-full bg-pentra-dark border border-pentra-border-strong flex items-center justify-center text-pentra-primary font-mono text-sm shadow-[0_0_10px_rgba(255,0,60,0.2)]">
                        OP
                    </div>
                    <span className="text-sm text-pentra-text font-medium">Operator</span>
                </button>
            </div>
        </header>
    )
}
