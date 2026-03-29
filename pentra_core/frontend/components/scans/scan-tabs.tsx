"use client"

import { motion } from "framer-motion"
import { cn } from "@/lib/utils"
import {
  Bot,
  LayoutDashboard,
  AlertTriangle,
  GitBranch,
  FileSearch,
  Clock,
  FileText,
  Target,
  ListTree,
  TerminalSquare,
} from "lucide-react"

interface ScanTabsProps {
  tabs: readonly string[]
  activeTab: string
  onTabChange: (tab: string) => void
  badges?: Record<string, string | null | undefined>
}

const tabIcons: Record<string, React.ElementType> = {
  Overview: LayoutDashboard,
  "Target Model": Target,
  Planner: Bot,
  Findings: AlertTriangle,
  "Attack Graph": GitBranch,
  Evidence: FileSearch,
  Timeline: Clock,
  Jobs: ListTree,
  "Command Console": TerminalSquare,
  Report: FileText,
}

export function ScanTabs({ tabs, activeTab, onTabChange, badges }: ScanTabsProps) {
  return (
    <div className="sticky top-20 z-20 border-b border-border bg-background/95 backdrop-blur-sm">
      <div className="flex px-6">
        {tabs.map((tab) => {
          const Icon = tabIcons[tab]
          const badge = badges?.[tab]
          return (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={cn(
                "relative flex items-center gap-2 px-4 py-3.5 text-sm font-medium transition-all duration-200",
                activeTab === tab
                  ? "text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {Icon && (
                <Icon
                  className={cn(
                    "h-4 w-4 transition-colors",
                    activeTab === tab ? "text-primary" : "text-muted-foreground"
                  )}
                />
              )}
              {tab}
              {badge ? (
                <span
                  className={cn(
                    "rounded-full border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                    activeTab === tab
                      ? "border-primary/30 bg-primary/10 text-primary"
                      : "border-border bg-background text-muted-foreground"
                  )}
                >
                  {badge}
                </span>
              ) : null}
              {activeTab === tab && (
                <motion.div
                  layoutId="activeTabIndicator"
                  className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"
                  transition={{
                    type: "spring",
                    stiffness: 500,
                    damping: 35,
                  }}
                />
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}
