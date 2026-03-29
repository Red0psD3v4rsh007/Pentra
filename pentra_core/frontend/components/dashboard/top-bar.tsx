"use client"

import { useState, useRef, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Search, Bell, PanelRight, PanelRightClose, Terminal, LogOut } from "lucide-react"

import { CommandPalette, useCommandPalette } from "@/components/command-palette"
import { useNotificationStore, type Notification } from "@/lib/notification-store"
import { cn } from "@/lib/utils"
import Link from "next/link"
import type { ApiAuthRuntime, ApiCurrentUser } from "@/lib/scans-store"

interface TopBarProps {
  title: string
  onToggleRightPanel?: () => void
  rightPanelOpen?: boolean
  operator: {
    user: ApiCurrentUser | null
    authRuntime: ApiAuthRuntime | null
    isLoading: boolean
    error: string | null
    isDevBypass: boolean
    refresh: () => void
    signOut: () => void
  }
}

function timeAgo(ts: number): string {
  const seconds = Math.floor((Date.now() - ts) / 1000)
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

const typeConfig: Record<Notification["type"], { dot: string; label: string }> = {
  scan_completed: { dot: "bg-primary", label: "Scan" },
  scan_failed: { dot: "bg-destructive", label: "Scan" },
  finding: { dot: "bg-warning", label: "Finding" },
  info: { dot: "bg-cyan", label: "Info" },
}

function operatorInitials(user: ApiCurrentUser | null): string {
  const source = user?.full_name?.trim() || user?.email?.trim() || "Pentra"
  const parts = source.split(/\s+/).filter(Boolean)
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase()
  }
  return `${parts[0][0] ?? ""}${parts[1][0] ?? ""}`.toUpperCase()
}

export function TopBar({ title, onToggleRightPanel, rightPanelOpen, operator }: TopBarProps) {
  const router = useRouter()
  const { open: paletteOpen, setOpen: setPaletteOpen } = useCommandPalette()
  const { items, unreadCount, markRead, markAllRead } = useNotificationStore()
  const [showNotifications, setShowNotifications] = useState(false)
  const [showOperatorMenu, setShowOperatorMenu] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)
  const operatorRef = useRef<HTMLDivElement>(null)

  const operatorName = operator.user?.full_name?.trim() || operator.user?.email || "Unknown operator"
  const operatorSubline = operator.isDevBypass
    ? "Development bypass session"
    : operator.user?.email || "Backend-authenticated session"

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false)
      }
      if (operatorRef.current && !operatorRef.current.contains(e.target as Node)) {
        setShowOperatorMenu(false)
      }
    }
    if (showNotifications) {
      document.addEventListener("mousedown", handleClick)
      return () => document.removeEventListener("mousedown", handleClick)
    }
    if (showOperatorMenu) {
      document.addEventListener("mousedown", handleClick)
      return () => document.removeEventListener("mousedown", handleClick)
    }
  }, [showNotifications, showOperatorMenu])

  return (
    <>
      <header className="fixed top-0 w-full z-50 flex justify-between items-center px-6 h-16 bg-[rgba(0,0,0,0.6)] backdrop-blur-2xl border-b border-[#FF525C]/15 shadow-[0_4px_30px_rgba(0,0,0,0.8)]">
        {/* Left — Logo & Nav */}
        <div className="flex items-center gap-8">
          <Link href="/dashboard" className="text-2xl font-black tracking-widest text-[#FF525C] drop-shadow-[0_0_8px_rgba(255,82,92,0.4)] font-heading uppercase">
            PENTRA_CMD
          </Link>
          <nav className="hidden md:flex gap-6 mt-1">
            <Link className="text-[#E9BCBA]/60 font-heading tracking-tighter uppercase text-sm hover:text-[#FFB3B2] transition-colors" href="/intelligence">INTEL</Link>
            <Link className="text-[#FFB3B2] border-b-2 border-[#FF525C] pb-1 font-heading tracking-tighter uppercase text-sm" href="/dashboard">COMMAND</Link>
            <Link className="text-[#E9BCBA]/60 font-heading tracking-tighter uppercase text-sm hover:text-[#FFB3B2] transition-colors" href="/attack-graphs">NETWORK</Link>
          </nav>
        </div>

        {/* Right — Actions */}
        <div className="flex items-center gap-4 pr-64 md:pr-0">
          {/* Search / Command Palette */}
          <div className="relative hidden sm:block group">
            <input 
              onClick={() => setPaletteOpen(true)}
              className="bg-surface-container-lowest border border-transparent text-xs font-mono text-on-surface-variant w-64 h-8 px-4 rounded-sm focus:outline-none focus:ring-1 focus:ring-primary-container cursor-pointer transition-colors hover:border-primary/30" 
              placeholder="SEARCH_SYSTEM..." 
              readOnly 
            />
            <Search className="absolute right-2 top-2 h-4 w-4 text-primary-container" />
            <kbd className="absolute right-8 top-1.5 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono text-dim pointer-events-none">
              ⌘K
            </kbd>
          </div>

          {/* Notifications */}
          <div ref={notifRef} className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="text-[#E9BCBA]/60 hover:text-[#FF525C] transition-colors relative flex h-7 w-7 items-center justify-center p-1"
            >
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-[9px] font-bold text-primary-foreground shadow-[0_0_8px_#ff525c]">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </button>

            {/* Notification Dropdown */}
            {showNotifications && (
              <div className="absolute right-0 top-full mt-4 w-80 rounded-sm border border-[#5F3E3E]/30 bg-[#1C1B1B]/95 backdrop-blur-2xl shadow-[0_10px_40px_rgba(0,0,0,0.8)] z-50">
                <div className="flex items-center justify-between border-b border-[#5F3E3E]/20 px-4 py-3">
                  <span className="text-xs font-semibold text-foreground font-heading uppercase tracking-widest">
                    SYSTEM_ALERTS
                  </span>
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllRead}
                      className="text-[10px] text-primary hover:text-primary-dim transition-colors uppercase font-mono"
                    >
                      ACKNOWLEDGE_ALL
                    </button>
                  )}
                </div>

                <div className="max-h-72 overflow-y-auto custom-scrollbar">
                  {items.length === 0 ? (
                    <div className="px-4 py-8 text-center text-xs text-[#E9BCBA]/40 font-mono">
                      [NO_ACTIVE_ALERTS]
                    </div>
                  ) : (
                    items.slice(0, 10).map((notif) => {
                      const config = typeConfig[notif.type] ?? { dot: "bg-muted-foreground", label: "Event" }
                      return (
                        <button
                          key={notif.id}
                          onClick={() => { markRead(notif.id); setShowNotifications(false) }}
                          className={cn(
                            "flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-2",
                            !notif.read && "bg-primary/5 border-l-2 border-primary"
                          )}
                        >
                          <span className={cn("mt-1.5 h-2 w-2 rounded-full shrink-0 shadow-[0_0_5px_currentColor]", config.dot)} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs text-foreground/90 font-medium break-words leading-relaxed">{notif.title}</p>
                            <p className="text-[10px] text-primary/60 font-mono mt-1 uppercase">T-MINUS {timeAgo(notif.timestamp)}</p>
                          </div>
                        </button>
                      )
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Terminal / Right Panel Toggle */}
          {onToggleRightPanel && (
            <button
              onClick={onToggleRightPanel}
              className={cn(
                "flex h-8 w-8 items-center justify-center rounded transition-colors ml-2",
                rightPanelOpen
                  ? "text-[#FF525C] bg-primary/10 shadow-[0_0_15px_rgba(255,82,92,0.2)]"
                  : "text-[#E9BCBA]/60 hover:text-foreground hover:bg-[#2A2A2A]"
              )}
              title={rightPanelOpen ? "Close Tactical Panel" : "Open Tactical Panel"}
            >
              {rightPanelOpen ? (
                <PanelRightClose className="h-4 w-4" />
              ) : (
                <Terminal className="h-4 w-4" />
              )}
            </button>
          )}

          <div ref={operatorRef} className="relative ml-2">
            <button
              type="button"
              onClick={() => setShowOperatorMenu((current) => !current)}
              className="flex items-center gap-3 rounded-full border border-primary/20 bg-black/20 pl-2 pr-1.5 py-1 transition-colors hover:border-primary/40 hover:bg-black/30"
            >
              <div className="hidden text-right md:block">
                <p className="max-w-[180px] truncate text-[11px] font-semibold uppercase tracking-[0.16em] text-[#FFB3B2]">
                  {operator.isLoading ? "Restoring operator" : operatorName}
                </p>
                <p className="max-w-[180px] truncate text-[10px] font-mono text-[#E9BCBA]/50">
                  {operator.isLoading ? "AUTH CHECK IN PROGRESS" : operatorSubline}
                </p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-primary/30 bg-primary/10 text-xs font-bold text-primary shadow-[0_0_10px_rgba(255,82,92,0.2)]">
                {operatorInitials(operator.user)}
              </div>
            </button>

            {showOperatorMenu && (
              <div className="absolute right-0 top-full mt-3 w-72 rounded-sm border border-[#5F3E3E]/30 bg-[#1C1B1B]/95 p-4 backdrop-blur-2xl shadow-[0_10px_40px_rgba(0,0,0,0.8)] z-50">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#E9BCBA]/60">
                  Operator Session
                </p>
                <p className="mt-3 text-sm font-semibold text-foreground">{operatorName}</p>
                <p className="mt-1 text-xs text-muted-foreground">{operatorSubline}</p>
                <div className="mt-3 rounded border border-[#5F3E3E]/20 bg-black/20 p-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[#E9BCBA]/60">Roles</span>
                    <span className="text-foreground">
                      {operator.user?.roles?.join(", ") || "unassigned"}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center justify-between">
                    <span className="text-[#E9BCBA]/60">Mode</span>
                    <span className="text-foreground">
                      {operator.isDevBypass ? "dev_bypass" : "browser_session"}
                    </span>
                  </div>
                </div>
                <div className="mt-4 flex justify-end">
                  {operator.isDevBypass ? (
                    <button
                      type="button"
                      onClick={() => {
                        setShowOperatorMenu(false)
                        router.push("/settings")
                      }}
                      className="rounded border border-border/60 px-3 py-2 text-xs text-foreground transition-colors hover:bg-background/70"
                    >
                      Manage runtime auth
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        operator.signOut()
                        setShowOperatorMenu(false)
                        router.push("/")
                      }}
                      className="inline-flex items-center gap-2 rounded border border-[#ff525c]/20 bg-[#ff525c]/10 px-3 py-2 text-xs text-[#ffb3b2] transition-colors hover:bg-[#ff525c]/15"
                    >
                      <LogOut className="h-3.5 w-3.5" />
                      Sign out
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Command Palette Portal */}
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </>
  )
}
