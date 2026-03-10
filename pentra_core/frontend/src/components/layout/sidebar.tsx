"use client"

import React, { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import {
    Terminal,
    LayoutDashboard,
    Radar,
    Layers,
    ShieldAlert,
    FileText,
    BrainCircuit,
    Settings,
    ChevronLeft,
    ChevronRight
} from "lucide-react"

const NAV_ITEMS = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "Scans", href: "/scans", icon: Radar },
    { name: "Assets", href: "/assets", icon: Layers },
    { name: "Findings", href: "/findings", icon: ShieldAlert },
    { name: "Reports", href: "/reports", icon: FileText },
    { name: "Intelligence", href: "/intelligence", icon: BrainCircuit },
]

interface SidebarProps {
    collapsed: boolean;
    onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
    const pathname = usePathname()

    return (
        <aside
            className={cn(
                "relative flex flex-col h-screen border-r border-pentra-border bg-pentra-black transition-all duration-300 z-20",
                collapsed ? "w-[72px]" : "w-[280px]"
            )}
        >
            <div className="flex items-center h-16 px-4 border-b border-pentra-border">
                <div className="flex items-center gap-3 overflow-hidden">
                    <div className="flex-shrink-0 flex items-center justify-center w-10 h-10 rounded-md bg-pentra-primary/10 border border-pentra-primary/20 text-pentra-primary shadow-[0_0_15px_rgba(255,0,60,0.2)]">
                        <Terminal size={20} />
                    </div>
                    {!collapsed && (
                        <span className="font-display font-bold tracking-wider text-xl text-white">
                            PENTRA
                        </span>
                    )}
                </div>
            </div>

            <button
                onClick={onToggle}
                className="absolute -right-3 top-20 flex items-center justify-center w-6 h-6 rounded-full bg-pentra-surface border border-pentra-border text-pentra-text-muted hover:text-pentra-primary hover:border-pentra-primary transition-colors z-30"
            >
                {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
            </button>

            <div className="flex-1 py-6 px-3 space-y-1 overflow-y-auto">
                {NAV_ITEMS.map((item) => {
                    const isActive = pathname.startsWith(item.href)
                    const Icon = item.icon

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 px-3 py-2.5 rounded-md transition-all group relative",
                                isActive
                                    ? "bg-pentra-primary/10 text-pentra-primary font-medium"
                                    : "text-pentra-text-muted hover:bg-pentra-surface-hover hover:text-white"
                            )}
                        >
                            {isActive && (
                                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-pentra-primary rounded-r-md shadow-[0_0_10px_rgba(255,0,60,0.8)]" />
                            )}
                            <Icon size={20} className={cn("flex-shrink-0", isActive && "drop-shadow-[0_0_8px_rgba(255,0,60,0.5)]")} />

                            {!collapsed && (
                                <span className="truncate">{item.name}</span>
                            )}
                        </Link>
                    )
                })}
            </div>

            <div className="p-3 border-t border-pentra-border space-y-1">
                <Link
                    href="/settings"
                    className={cn(
                        "flex items-center gap-3 px-3 py-2.5 rounded-md transition-all group relative text-pentra-text-muted hover:bg-pentra-surface-hover hover:text-white",
                        pathname.startsWith("/settings") && "bg-pentra-primary/10 text-pentra-primary font-medium"
                    )}
                >
                    {pathname.startsWith("/settings") && (
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-pentra-primary rounded-r-md shadow-[0_0_10px_rgba(255,0,60,0.8)]" />
                    )}
                    <Settings size={20} className={cn("flex-shrink-0", pathname.startsWith("/settings") && "drop-shadow-[0_0_8px_rgba(255,0,60,0.5)]")} />
                    {!collapsed && <span>Settings</span>}
                </Link>
            </div>
        </aside>
    )
}
