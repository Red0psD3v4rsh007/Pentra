"use client"

import React from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { User, Building2, Key, Blocks, CreditCard, Bell } from "lucide-react"

const SETTINGS_TABS = [
    { id: "profile", label: "OPERATOR PROFILE", icon: <User size={16} /> },
    { id: "organization", label: "ORGANIZATION", icon: <Building2 size={16} /> },
    { id: "api-keys", label: "API KEYS", icon: <Key size={16} /> },
    { id: "integrations", label: "INTEGRATIONS", icon: <Blocks size={16} /> },
    { id: "billing", label: "BILLING", icon: <CreditCard size={16} /> },
    { id: "notifications", label: "NOTIFICATIONS", icon: <Bell size={16} /> },
]

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
    const pathname = usePathname()

    return (
        <div className="flex flex-col h-full space-y-6 max-w-7xl mx-auto">

            {/* Settings Header */}
            <div>
                <h1 className="text-2xl font-display font-bold tracking-widest text-white mb-1 uppercase">System Configuration</h1>
                <p className="text-pentra-text-muted font-mono text-xs uppercase tracking-wider">MANAGE PLATFORM PARAMETERS AND ACCESS</p>
            </div>

            <div className="flex flex-col md:flex-row gap-8 h-full">

                {/* Navigation Sidebar */}
                <div className="w-full md:w-64 shrink-0">
                    <nav className="flex flex-col space-y-1">
                        {SETTINGS_TABS.map((tab) => {
                            const isActive = pathname.includes(`/settings/${tab.id}`)
                            return (
                                <Link
                                    key={tab.id}
                                    href={`/settings/${tab.id}`}
                                    className={`flex items-center gap-3 px-4 py-3 text-xs font-mono tracking-widest uppercase transition-colors border-l-2
                    ${isActive
                                            ? "border-pentra-primary bg-pentra-primary/10 text-white font-bold"
                                            : "border-transparent text-pentra-text-muted hover:bg-pentra-panel hover:text-white"
                                        }
                  `}
                                >
                                    <span className={isActive ? "text-pentra-primary" : "text-pentra-text-dim"}>{tab.icon}</span>
                                    {tab.label}
                                </Link>
                            )
                        })}
                    </nav>
                </div>

                {/* Setting Content Area */}
                <div className="flex-1 bg-pentra-panel border border-pentra-border p-6 min-h-[500px]">
                    {children}
                </div>

            </div>
        </div>
    )
}
