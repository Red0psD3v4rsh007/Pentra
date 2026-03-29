"use client"

import { useState, type ReactNode } from "react"
import { cn } from "@/lib/utils"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { RightPanel } from "@/components/layout/right-panel"
import { GridBackground } from "@/components/ui/grid-background"
import { useCurrentOperator } from "@/hooks/use-scans"

interface CommandLayoutProps {
  children: ReactNode
  title: string
  showRightPanel?: boolean
  rightPanelContent?: ReactNode
}

export function CommandLayout({
  children,
  title,
  showRightPanel = false,
  rightPanelContent,
}: CommandLayoutProps) {
  const [rightPanelOpen, setRightPanelOpen] = useState(showRightPanel)
  const operator = useCurrentOperator()

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Background Ambient Effects (Stitch Obsidian Blur) */}
      <div className="fixed top-1/4 -right-1/4 w-[600px] h-[600px] bg-primary-container/5 rounded-full blur-[120px] pointer-events-none z-0"></div>
      <div className="fixed -bottom-1/4 -left-1/4 w-[600px] h-[600px] bg-primary/5 rounded-full blur-[120px] pointer-events-none z-0"></div>

      {/* Left Sidebar */}
      <DashboardSidebar operator={operator} />

      {/* Main Area */}
      <div className="flex flex-1 flex-col min-w-0 md:ml-64 transition-all duration-200 z-10">
        {/* Command Bar */}
        <TopBar
          title={title}
          onToggleRightPanel={() => setRightPanelOpen(!rightPanelOpen)}
          rightPanelOpen={rightPanelOpen}
          operator={operator}
        />

        {/* Content + Optional Right Panel */}
        <div className="flex flex-1 overflow-hidden relative pt-16">
          {/* Atmospheric Grid Background */}
          <GridBackground />

          {/* Main Workspace */}
          <main className="flex-1 overflow-y-auto relative z-10 pb-8 px-4 md:px-8 custom-scrollbar">
            {children}
          </main>

          {/* Right Panel — AI + Events */}
          {rightPanelOpen && (
            <RightPanel onClose={() => setRightPanelOpen(false)}>
              {rightPanelContent}
            </RightPanel>
          )}
        </div>
      </div>
    </div>
  )
}
