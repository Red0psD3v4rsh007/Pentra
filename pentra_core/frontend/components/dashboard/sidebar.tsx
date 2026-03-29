"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Spinner } from "@/components/ui/spinner"
import {
  LayoutDashboard,
  Crosshair,
  Swords,
  Brain,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  Zap,
} from "lucide-react"
import type { ApiAuthRuntime, ApiCurrentUser } from "@/lib/scans-store"

interface NavItem {
  icon: React.ElementType
  label: string
  href: string
  badge?: string
}

interface NavSection {
  title: string
  items: NavItem[]
}

interface OperatorState {
  user: ApiCurrentUser | null
  authRuntime: ApiAuthRuntime | null
  isLoading: boolean
  error: string | null
  isDevBypass: boolean
  refresh: () => void
  signOut: () => void
}

const navSections: NavSection[] = [
  {
    title: "COMMAND",
    items: [
      { icon: LayoutDashboard, label: "Dashboard", href: "/dashboard" },
      { icon: Crosshair, label: "Targets", href: "/assets" },
      { icon: Swords, label: "Attacks", href: "/scans" },
    ],
  },
  {
    title: "INTELLIGENCE",
    items: [
      { icon: Brain, label: "AI Ops", href: "/intelligence" },
      { icon: Activity, label: "Attack Graphs", href: "/attack-graphs" },
    ],
  },
  {
    title: "OUTPUT",
    items: [
      { icon: Shield, label: "Findings", href: "/findings" },
      { icon: FileText, label: "Reports", href: "/reports" },
    ],
  },
]

export function DashboardSidebar({ operator }: { operator: OperatorState }) {
  const [collapsed, setCollapsed] = useState(false)
  const pathname = usePathname()
  const operatorName = operator.user?.full_name?.trim() || operator.user?.email || "Unknown operator"
  const operatorRole = operator.user?.roles?.[0]?.replaceAll("_", " ") || "unassigned"
  const operatorStatus = operator.isDevBypass ? "DEV BYPASS" : "SESSION ACTIVE"

  return (
    <aside
      className={cn(
        "fixed left-0 top-16 z-40 flex h-[calc(100vh-64px)] flex-col border-r border-[#FF525C]/10 transition-all duration-200",
        "bg-[rgba(0,0,0,0.4)] backdrop-blur-2xl shadow-[4px_0_24px_rgba(0,0,0,0.8)]",
        collapsed ? "w-[52px]" : "w-64"
      )}
    >
      {/* Operator Status */}
      <div
        className={cn(
          "flex h-16 items-center border-b border-[#5F3E3E]/10 bg-surface-container-low/50",
          collapsed ? "justify-center px-2" : "justify-between px-6"
        )}
      >
        {!collapsed ? (
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_#FF525C] animate-pulse"></div>
            <div>
              <h3 className="font-heading text-xs tracking-widest uppercase font-bold text-on-surface">
                {operator.isLoading ? "RESTORING_OPERATOR" : operatorName}
              </h3>
              <p className="font-mono text-[10px] text-primary/60 uppercase">
                {operator.isLoading ? "AUTH: CHECKING" : `${operatorStatus} · ${operatorRole}`}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex h-4 w-4 items-center justify-center">
            {operator.isLoading ? (
              <Spinner className="size-3 text-primary" />
            ) : (
              <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_#FF525C] animate-pulse"></div>
            )}
          </div>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors",
            collapsed && "hidden"
          )}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 custom-scrollbar">
        {navSections.map((section) => (
          <div key={section.title} className="mb-4">
            {!collapsed && (
              <div className="px-6 mb-1.5">
                <span className="text-[10px] font-semibold tracking-[0.2em] text-[#E9BCBA]/50 font-heading">
                  {section.title}
                </span>
              </div>
            )}
            <div className="space-y-0.5 px-2">
              {section.items.map((item) => {
                const isActive = pathname === item.href || pathname?.startsWith(`${item.href}/`)
                const Icon = item.icon

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "group flex items-center gap-4 rounded px-4 py-3 text-sm transition-all duration-300",
                      collapsed && "justify-center px-0",
                      isActive
                        ? "bg-[#FF525C]/10 text-primary border-l-4 border-primary"
                        : "text-[#E9BCBA]/40 hover:bg-[#2A2A2A] hover:text-[#FFB3B2] border-l-4 border-transparent"
                    )}
                  >
                    <Icon
                      className={cn(
                        "h-[18px] w-[18px] shrink-0 transition-colors",
                        isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                      )}
                    />
                    {!collapsed && (
                      <span className="font-heading text-xs tracking-widest uppercase truncate">{item.label}</span>
                    )}
                    {!collapsed && item.badge && (
                      <span className="ml-auto rounded bg-primary/15 px-1.5 py-0.5 text-[10px] font-mono text-neon">
                        {item.badge}
                      </span>
                    )}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* System Status Footer */}
      <div className={cn(
        "border-t border-[#5F3E3E]/10 p-4",
      )}>
        {!collapsed ? (
          <div className="space-y-4 bg-surface-container-low/20 p-2 rounded">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.2em] text-[#E9BCBA]/50 font-heading">
                SYSTEM
              </span>
              <span className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse shadow-[0_0_5px_#FF525C]" />
                <span className="text-[10px] text-primary font-mono tracking-widest">ONLINE</span>
              </span>
            </div>
            {!operator.isLoading && operator.user ? (
              <div className="rounded border border-[#5F3E3E]/20 bg-black/20 px-2 py-2">
                <p className="truncate text-[10px] font-heading uppercase tracking-[0.2em] text-[#E9BCBA]/60">
                  {operator.user.email}
                </p>
                <p className="mt-1 text-[10px] font-mono uppercase text-primary/60">
                  {operator.isDevBypass ? "local development identity" : "backend-authenticated operator"}
                </p>
              </div>
            ) : null}
            <Link
              href="/settings"
              className={cn(
                "flex items-center gap-4 rounded px-2 py-2 text-sm transition-all duration-300",
                pathname === "/settings"
                  ? "bg-[#FF525C]/10 text-primary"
                  : "text-[#E9BCBA]/40 hover:text-foreground hover:bg-[#2A2A2A]"
              )}
            >
              <Settings className="h-4 w-4" />
              <span className="font-heading text-xs tracking-widest uppercase">Settings</span>
            </Link>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-4">
            <span className="h-1.5 w-1.5 rounded-full bg-primary shadow-[0_0_5px_#FF525C] animate-pulse" />
            <Link
              href="/settings"
              className="flex h-8 w-8 items-center justify-center rounded text-[#E9BCBA]/40 hover:text-foreground hover:bg-[#2A2A2A]"
            >
              <Settings className="h-4 w-4" />
            </Link>
          </div>
        )}
      </div>

      {/* Expand button when collapsed */}
      {collapsed && (
        <button
          onClick={() => setCollapsed(false)}
          className="absolute -right-3 top-12 flex h-6 w-6 items-center justify-center rounded-full bg-[#1C1B1B] border border-[#5F3E3E]/30 text-muted-foreground hover:text-primary transition-colors z-50"
        >
          <ChevronRight className="h-3 w-3" />
        </button>
      )}
    </aside>
  )
}
