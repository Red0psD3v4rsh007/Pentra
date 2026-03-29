"use client"

import Link from "next/link"
import { useMemo } from "react"
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Crosshair,
  Radar,
  Shield,
  ShieldCheck,
  Swords,
  TrendingUp,
  Zap,
} from "lucide-react"
import { motion } from "framer-motion"

import { CommandLayout } from "@/components/layout/command-layout"
import { CyberCard } from "@/components/ui/cyber-card"
import { GlowButton } from "@/components/ui/glow-button"
import { StatDisplay } from "@/components/ui/stat-display"
import { StatusBadge } from "@/components/ui/status-badge"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useRuntimeDiagnostics, useScans } from "@/hooks/use-scans"
import {
  extractExecutionSummary,
  extractVerificationCounts,
  type Scan,
  type ScanAsset,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

type AssetRollup = {
  asset: ScanAsset
  totalFindings: number
  verifiedFindings: number
  latestScanId: string
  highestSeverity: "critical" | "high" | "medium" | "low" | "info"
  riskScore: number
}

function totalFindings(scan: Scan) {
  return scan.findings.critical + scan.findings.high + scan.findings.medium + scan.findings.low
}

function severityScore(scan: Scan) {
  return (
    scan.findings.critical * 25 +
    scan.findings.high * 15 +
    scan.findings.medium * 8 +
    scan.findings.low * 3
  )
}

function highestSeverity(scan: Scan): AssetRollup["highestSeverity"] {
  if (scan.findings.critical > 0) return "critical"
  if (scan.findings.high > 0) return "high"
  if (scan.findings.medium > 0) return "medium"
  if (scan.findings.low > 0) return "low"
  return "info"
}

function timeAgo(timestamp: string) {
  if (!timestamp) return "-"
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.1 },
  },
}

const itemVariants = {
  hidden: { opacity: 0, y: 30 },
  show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 350, damping: 25 } },
}

const runtimeServiceOrder = [
  "api",
  "orchestrator",
  "worker",
  "redis",
  "ai",
  "external_target_scanning",
] as const

const runtimeServiceLabels: Record<string, string> = {
  api: "API",
  orchestrator: "Orchestrator",
  worker: "Worker",
  redis: "Redis",
  ai: "AI",
  external_target_scanning: "External Targets",
}

export default function DashboardPage() {
  const {
    scans,
    isLoading: scansLoading,
    error: scansError,
  } = useScans({ pageSize: 100, pollIntervalMs: 5000 })
  const {
    assets,
    isLoading: assetsLoading,
    error: assetsError,
  } = useAssetCatalog()
  const { systemStatus, aiDiagnostics } = useRuntimeDiagnostics()

  const dashboard = useMemo(() => {
    const openFindings = scans.reduce((sum, scan) => sum + totalFindings(scan), 0)
    const verification = scans.reduce(
      (acc, scan) => {
        const counts = extractVerificationCounts(scan.resultSummary)
        acc.verified += counts.verified
        acc.suspected += counts.suspected
        acc.detected += counts.detected
        return acc
      },
      { verified: 0, suspected: 0, detected: 0 }
    )
    const execution = scans.reduce(
      (acc, scan) => {
        const summary = extractExecutionSummary(scan.resultSummary)
        acc.live += summary.live
        acc.simulated += summary.simulated
        acc.derived += summary.derived
        acc.blocked += summary.blocked
        acc.inferred += summary.inferred
        return acc
      },
      { live: 0, simulated: 0, derived: 0, blocked: 0, inferred: 0 }
    )
    const severity = scans.reduce(
      (acc, scan) => {
        acc.critical += scan.findings.critical
        acc.high += scan.findings.high
        acc.medium += scan.findings.medium
        acc.low += scan.findings.low
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    )

    const assetMap = new Map(assets.map((asset) => [asset.id, asset]))
    const rollups = new Map<string, AssetRollup>()
    for (const scan of scans) {
      const asset = assetMap.get(scan.assetId)
      if (!asset) continue
      const existing = rollups.get(asset.id)
      const verified = extractVerificationCounts(scan.resultSummary).verified
      const next: AssetRollup = existing
        ? {
            ...existing,
            totalFindings: existing.totalFindings + totalFindings(scan),
            verifiedFindings: existing.verifiedFindings + verified,
            latestScanId: scan.id,
            highestSeverity:
              ["critical", "high", "medium", "low", "info"].indexOf(highestSeverity(scan)) <
              ["critical", "high", "medium", "low", "info"].indexOf(existing.highestSeverity)
                ? highestSeverity(scan)
                : existing.highestSeverity,
            riskScore: Math.min(99, existing.riskScore + severityScore(scan) + verified * 8),
          }
        : {
            asset,
            totalFindings: totalFindings(scan),
            verifiedFindings: verified,
            latestScanId: scan.id,
            highestSeverity: highestSeverity(scan),
            riskScore: Math.min(99, severityScore(scan) + verified * 8),
          }
      rollups.set(asset.id, next)
    }

    return {
      totalScans: scans.length,
      activeScans: scans.filter((s) => s.status === "running" || s.status === "queued").length,
      assetsMonitored: assets.length,
      openFindings,
      verification,
      execution,
      severity,
      recentScans: scans.slice(0, 8),
      topAssets: Array.from(rollups.values())
        .filter((item) => item.totalFindings > 0)
        .sort((left, right) => right.riskScore - left.riskScore)
        .slice(0, 5),
    }
  }, [assets, scans])

  const isLoading = scansLoading || assetsLoading
  const error = scansError ?? assetsError
  const severityTotal =
    dashboard.severity.critical +
    dashboard.severity.high +
    dashboard.severity.medium +
    dashboard.severity.low

  return (
    <CommandLayout title="Dashboard" showRightPanel={false}>
      <motion.div variants={containerVariants} initial="hidden" animate="show" className="p-5 space-y-5">
        {/* Hero Header */}
        <motion.div variants={itemVariants} className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="flex h-9 w-9 items-center justify-center rounded bg-[#00ff9f]/10">
                <Shield className="h-4.5 w-4.5 text-[#00ff9f] drop-shadow-[0_0_8px_rgba(0,255,159,0.5)]" />
              </div>
              {dashboard.activeScans > 0 && (
                <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-[#00ff9f] neon-pulse" />
              )}
            </div>
            <div>
              <h2 className="text-lg font-semibold text-foreground font-heading tracking-tight">
                Command Dashboard
              </h2>
              <p className="text-[11px] text-muted-foreground font-mono">
                {dashboard.activeScans > 0
                  ? `${dashboard.activeScans} active operations • Real-time monitoring`
                  : "Attack surface overview • Standing by"}
              </p>
            </div>
          </div>
          <Link href="/scans/new">
            <GlowButton size="md">
              <Swords className="h-3.5 w-3.5" />
              New Attack
            </GlowButton>
          </Link>
        </motion.div>

        <motion.div variants={itemVariants} className="grid grid-cols-2 gap-3 xl:grid-cols-6">
          {runtimeServiceOrder.map((serviceKey) => {
            const serviceState =
              serviceKey === "ai"
                ? aiDiagnostics?.operator_state ?? systemStatus?.services?.[serviceKey] ?? "unavailable"
                : systemStatus?.services?.[serviceKey] ?? "unavailable"
            return (
              <CyberCard key={serviceKey} className="p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                      {runtimeServiceLabels[serviceKey]}
                    </p>
                    <p className="mt-1 text-xs text-foreground">
                      {serviceKey === "external_target_scanning"
                        ? "Permission Gate"
                        : serviceKey === "ai"
                          ? "Advisor Runtime"
                          : "Service Health"}
                    </p>
                  </div>
                  <StatusBadge status={serviceState} label={serviceState} />
                </div>
              </CyberCard>
            )
          })}
        </motion.div>

        {isLoading ? (
          <CyberCard className="flex min-h-[40vh] items-center justify-center p-8">
            <div className="flex flex-col items-center gap-3">
              <Spinner className="h-6 w-6" />
              <span className="text-sm text-muted-foreground font-mono">Connecting to systems...</span>
            </div>
          </CyberCard>
        ) : error ? (
          <CyberCard accentColor="red" className="p-5">
            <div className="flex items-center gap-3 text-[#ff3b3b]">
              <AlertTriangle className="h-5 w-5" />
              <div>
                <p className="text-sm font-semibold">System Error</p>
                <p className="text-xs font-mono opacity-80">{error}</p>
              </div>
            </div>
          </CyberCard>
        ) : (
          <>
            {/* ─── Stats Grid ─── */}
            <motion.div variants={itemVariants} className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
              <StatDisplay
                label="Active Attacks"
                value={dashboard.activeScans}
                icon={<Radar className="h-5 w-5" />}
                accentColor="#00ff9f"
                sublabel={
                  <span className="flex items-center gap-2">
                    <span className="tabular-nums">{dashboard.totalScans}</span> total
                    {dashboard.activeScans > 0 && (
                      <span className="ml-auto flex items-center gap-1 text-[#00ff9f]">
                        <span className="h-1.5 w-1.5 rounded-full bg-[#00ff9f] neon-pulse" />
                        LIVE
                      </span>
                    )}
                  </span>
                }
              />
              <StatDisplay
                label="Open Findings"
                value={dashboard.openFindings}
                icon={<AlertTriangle className="h-5 w-5" />}
                accentColor="#ff3b3b"
                sublabel={
                  <span className="flex items-center gap-2.5">
                    {(["critical", "high", "medium", "low"] as const).map((sev) => {
                      const colors = { critical: "#ff3b3b", high: "#ff6b35", medium: "#ffaa00", low: "#00ff9f" }
                      return (
                        <span key={sev} className="flex items-center gap-1">
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: colors[sev] }} />
                          <span className="tabular-nums" style={{ color: colors[sev] }}>{dashboard.severity[sev]}</span>
                        </span>
                      )
                    })}
                  </span>
                }
              />
              <StatDisplay
                label="Targets"
                value={dashboard.assetsMonitored}
                icon={<Crosshair className="h-5 w-5" />}
                accentColor="#ff6b35"
                sublabel="Active target inventory"
              />
              <StatDisplay
                label="Verified"
                value={dashboard.verification.verified}
                icon={<ShieldCheck className="h-5 w-5" />}
                accentColor="#00ff9f"
                sublabel={
                  <span className="flex items-center gap-2">
                    <span className="tabular-nums">{dashboard.execution.live}</span> live
                    <span className="text-[#1a1a1e]">|</span>
                    <span className="tabular-nums">{dashboard.execution.derived}</span> derived
                    <span className="text-[#1a1a1e]">|</span>
                    <span className="tabular-nums">{dashboard.execution.blocked}</span> blocked
                    <span className="text-[#1a1a1e]">|</span>
                    <span className="tabular-nums">{dashboard.execution.inferred}</span> inferred
                  </span>
                }
              />
            </motion.div>

            {/* ─── Severity + Targets ─── */}
            <motion.div variants={itemVariants} className="grid grid-cols-1 gap-3 xl:grid-cols-5">
              {/* Severity Distribution */}
              <CyberCard accentColor="green" className="xl:col-span-3 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2.5">
                    <TrendingUp className="h-4 w-4 text-[#00ff9f]" />
                    <h3 className="text-sm font-semibold text-foreground font-heading">
                      Severity Distribution
                    </h3>
                  </div>
                  <Link
                    href="/findings"
                    className="flex items-center gap-1 text-[11px] font-medium text-[#00ff9f] transition-colors hover:text-[#00cc7f]"
                  >
                    View all <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                {/* Animated Severity Bar */}
                <div className="overflow-hidden rounded-sm bg-surface-2 relative">
                  <div className="flex h-2.5 w-full">
                    {(["critical", "high", "medium", "low"] as const).map((sev) => {
                      const value = dashboard.severity[sev]
                      const width = severityTotal > 0 ? `${(value / severityTotal) * 100}%` : "0%"
                      const colors = { critical: "#ff3b3b", high: "#ff6b35", medium: "#ffaa00", low: "#00ff9f" }
                      return (
                        <div
                          key={sev}
                          className="h-full transition-all duration-500"
                          style={{
                            width,
                            background: `linear-gradient(90deg, ${colors[sev]}, ${colors[sev]}cc)`,
                            boxShadow: `0 0 8px ${colors[sev]}40`,
                          }}
                          title={`${sev}: ${value}`}
                        />
                      )
                    })}
                  </div>
                </div>

                {/* Severity Cards */}
                <div className="mt-3 grid grid-cols-2 gap-2 md:grid-cols-4">
                  {(["critical", "high", "medium", "low"] as const).map((sev) => {
                    const colors = { critical: "#ff3b3b", high: "#ff6b35", medium: "#ffaa00", low: "#00ff9f" }
                    return (
                      <div
                        key={sev}
                        className="group relative overflow-hidden rounded border border-border-subtle bg-surface-0 p-2.5 transition-all hover:border-[rgba(255,255,255,0.06)]"
                      >
                        <div
                          className="absolute top-0 left-0 right-0 h-[1px] opacity-40"
                          style={{ background: `linear-gradient(90deg, transparent, ${colors[sev]}, transparent)` }}
                        />
                        <p
                          className="text-[9px] font-semibold uppercase tracking-[0.2em] font-heading"
                          style={{ color: colors[sev] }}
                        >
                          {sev}
                        </p>
                        <p className="mt-1 text-xl font-bold tabular-nums text-foreground font-mono">
                          {dashboard.severity[sev]}
                        </p>
                      </div>
                    )
                  })}
                </div>
              </CyberCard>

              {/* High-Risk Targets */}
              <CyberCard accentColor="orange" className="xl:col-span-2 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2.5">
                    <Zap className="h-4 w-4 text-[#ff6b35]" />
                    <h3 className="text-sm font-semibold text-foreground font-heading">
                      High-Risk Targets
                    </h3>
                  </div>
                  <Link
                    href="/assets"
                    className="flex items-center gap-1 text-[11px] font-medium text-[#00ff9f] transition-colors hover:text-[#00cc7f]"
                  >
                    All <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                <div className="space-y-1.5">
                  {dashboard.topAssets.length === 0 ? (
                    <div className="flex flex-col items-center justify-center rounded border border-dashed border-border-subtle py-8 text-center">
                      <Crosshair className="mb-2 h-6 w-6 text-[#555555]" />
                      <p className="text-xs text-muted-foreground">No targets scanned</p>
                    </div>
                  ) : (
                    dashboard.topAssets.map((item) => (
                      <Link
                        key={item.asset.id}
                        href={`/assets/${item.asset.id}`}
                        className="group/item flex items-center gap-3 rounded border border-border-subtle bg-surface-0 p-2.5 transition-all duration-150 hover:border-[rgba(255,255,255,0.06)] hover:bg-surface-1"
                      >
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium text-foreground group-hover/item:text-[#00ff9f] transition-colors">
                            {item.asset.name}
                          </p>
                          <p className="mt-0.5 flex items-center gap-2 text-[10px] text-muted-foreground font-mono">
                            <span className="tabular-nums">{item.totalFindings} findings</span>
                            <span className="text-[#141417]">|</span>
                            <span className="tabular-nums">{item.verifiedFindings} verified</span>
                          </p>
                        </div>
                        <span
                          className="rounded px-2 py-0.5 text-xs font-bold tabular-nums font-mono"
                          style={{
                            background: item.highestSeverity === "critical" ? "rgba(255,59,59,0.1)" :
                              item.highestSeverity === "high" ? "rgba(255,107,53,0.1)" :
                              item.highestSeverity === "medium" ? "rgba(255,170,0,0.1)" :
                              "rgba(0,255,159,0.1)",
                            color: item.highestSeverity === "critical" ? "#ff3b3b" :
                              item.highestSeverity === "high" ? "#ff6b35" :
                              item.highestSeverity === "medium" ? "#ffaa00" :
                              "#00ff9f",
                          }}
                        >
                          {item.riskScore}
                        </span>
                      </Link>
                    ))
                  )}
                </div>
              </CyberCard>
            </motion.div>

            {/* ─── Recent Attacks ─── */}
            <motion.div variants={itemVariants}><CyberCard accentColor="cyan" className="overflow-hidden">
              <div className="flex items-center justify-between border-b border-border-subtle px-5 py-3">
                <div className="flex items-center gap-2.5">
                  <Activity className="h-4 w-4 text-[#00cfff]" />
                  <h3 className="text-sm font-semibold text-foreground font-heading">
                    Recent Attacks
                  </h3>
                  <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                    {dashboard.recentScans.length}
                  </span>
                </div>
                <Link
                  href="/scans"
                  className="flex items-center gap-1 text-[11px] font-medium text-[#00ff9f] transition-colors hover:text-[#00cc7f]"
                >
                  View all <ArrowRight className="h-3 w-3" />
                </Link>
              </div>

              {dashboard.recentScans.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <Radar className="mb-3 h-8 w-8 text-[#555555]" />
                  <p className="text-sm text-muted-foreground">No attacks launched</p>
                  <Link href="/scans/new" className="mt-3">
                    <GlowButton size="md">
                      <Swords className="h-3.5 w-3.5" />
                      Launch first attack
                    </GlowButton>
                  </Link>
                </div>
              ) : (
                <div className="divide-y divide-border-subtle">
                  {dashboard.recentScans.map((scan) => (
                    <Link
                      key={scan.id}
                      href={`/scans/${scan.id}`}
                      className="group flex items-center justify-between gap-4 px-5 py-3 transition-colors duration-150 hover:bg-surface-1/50"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={cn(
                          "flex h-1.5 w-1.5 shrink-0 rounded-full",
                          scan.status === "running" ? "bg-[#00ff9f] neon-pulse" :
                          scan.status === "completed" ? "bg-[#00ff9f]" :
                          scan.status === "failed" ? "bg-[#ff3b3b]" : "bg-[#888888]"
                        )} />
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-foreground group-hover:text-[#00ff9f] transition-colors">
                            {scan.name}
                          </p>
                          <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                            {scan.target}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <div className="text-right hidden sm:block">
                          <p className="text-[11px] tabular-nums text-foreground font-mono">
                            {totalFindings(scan)} findings
                          </p>
                          <p className="mt-0.5 text-[10px] text-[#555555] font-mono">
                            {timeAgo(scan.updatedAt)}
                          </p>
                        </div>
                        <StatusBadge status={scan.status} label={scan.statusLabel} />
                        <ArrowRight className="h-3 w-3 text-[#555555] group-hover:text-[#00ff9f] transition-colors" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CyberCard></motion.div>
          </>
        )}
      </motion.div>
    </CommandLayout>
  )
}
