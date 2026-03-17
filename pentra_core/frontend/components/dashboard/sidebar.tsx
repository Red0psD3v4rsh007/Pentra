"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { SystemStatusBar } from "@/components/system-status-bar"
import {
  LayoutDashboard,
  PlayCircle,
  Server,
  ShieldAlert,
  GitBranch,
  Brain,
  FileText,
  Settings,
  ChevronLeft,
} from "lucide-react"

interface NavItem {
  icon: React.ElementType
  label: string
  href: string
}

interface NavSection {
  title: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    title: "OVERVIEW",
    items: [
      { icon: LayoutDashboard, label: "Dashboard", href: "/dashboard" },
      { icon: PlayCircle, label: "Scans", href: "/scans" },
    ],
  },
  {
    title: "DISCOVERY",
    items: [
      { icon: Server, label: "Assets", href: "/assets" },
      { icon: ShieldAlert, label: "Findings", href: "/findings" },
    ],
  },
  {
    title: "ANALYSIS",
    items: [
      { icon: GitBranch, label: "Attack Graphs", href: "/attack-graphs" },
      { icon: Brain, label: "Intelligence", href: "/intelligence" },
    ],
  },
  {
    title: "OUTPUT",
    items: [
      { icon: FileText, label: "Reports", href: "/reports" },
    ],
  },
]

export function DashboardSidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const pathname = usePathname()

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 flex h-screen flex-col bg-card border-r border-border transition-all duration-200",
        collapsed ? "w-16" : "w-60"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center justify-between border-b border-border px-4">
        {!collapsed && (
          <span className="text-base font-semibold tracking-tight text-foreground">
            PENTRA
          </span>
        )}
        {collapsed && (
          <span className="mx-auto text-base font-semibold text-foreground">
            P
          </span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
            collapsed && "mx-auto"
          )}
        >
          <ChevronLeft className={cn("h-4 w-4 transition-transform", collapsed && "rotate-180")} />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3">
        <div className="flex flex-col gap-6">
          {navSections.map((section) => (
            <div key={section.title}>
              {!collapsed && (
                <span className="mb-2 block px-3 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {section.title}
                </span>
              )}
              <ul className="flex flex-col gap-1">
                {section.items.map((item) => {
                  const isActive = pathname === item.href
                  return (
                    <li key={item.label}>
                      <Link
                        href={item.href}
                        className={cn(
                          "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                          isActive
                            ? "bg-[rgba(59,130,246,0.15)] text-primary"
                            : "text-muted-foreground hover:bg-elevated hover:text-foreground",
                          collapsed && "justify-center px-0"
                        )}
                      >
                        {isActive && (
                          <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary" />
                        )}
                        <item.icon className="h-4 w-4 shrink-0" />
                        {!collapsed && <span>{item.label}</span>}
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>
      </nav>

      {/* Bottom */}
      <div className="border-t border-border p-3 space-y-2">
        <SystemStatusBar collapsed={collapsed} />
        <Link
          href="/settings"
          className={cn(
            "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground",
            collapsed && "justify-center px-0"
          )}
        >
          <Settings className="h-4 w-4 shrink-0" />
          {!collapsed && <span>Settings</span>}
        </Link>
        
        {!collapsed && (
          <div className="mt-1 flex items-center gap-3 rounded-md bg-elevated px-3 py-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
              JD
            </div>
            <div className="flex-1 min-w-0">
              <p className="truncate text-sm font-medium text-foreground">John Doe</p>
              <p className="truncate text-xs text-muted-foreground">Admin</p>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="mt-1 flex justify-center">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
              JD
            </div>
          </div>
        )}
      </div>
    </aside>
  )
}
