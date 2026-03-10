import React, { useState } from "react"
import { Sidebar } from "./sidebar"
import { Topbar } from "./topbar"
import { CommandPalette } from "./command-palette"

export function MainLayout({ children }: { children: React.ReactNode }) {
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

    return (
        <div className="flex h-screen bg-pentra-black text-pentra-text overflow-hidden">
            <CommandPalette />
            <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />

            <div className="flex-1 flex flex-col min-w-0">
                <Topbar />

                <main className="flex-1 overflow-auto bg-pentra-black p-6 relative">
                    <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-pentra-surface/20 via-pentra-black to-pentra-black opacity-50" />
                    <div className="max-w-7xl mx-auto relative z-10 w-full h-full">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    )
}
