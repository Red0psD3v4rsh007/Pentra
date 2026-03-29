"use client"

import type { ElementType, KeyboardEvent } from "react"
import { useEffect, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { AnimatePresence, motion } from "framer-motion"
import {
  AlertCircle,
  ArrowRight,
  Check,
  ChevronLeft,
  Code2,
  Eye,
  EyeOff,
  GitBranch,
  Globe,
  Plus,
  Radar,
  Search,
  Shield,
  Sparkles,
  Swords,
} from "lucide-react"

import { AssetIntakeForm } from "@/components/assets/asset-intake-form"
import { CommandLayout } from "@/components/layout/command-layout"
import { ModeSelector, type ScanMode } from "@/components/scans/mode-selector"
import { MethodologyPicker, type Methodology } from "@/components/scans/methodology-picker"
import { ScopeEditor, defaultScope, type ScopeConfig } from "@/components/scans/scope-editor"
import { CredentialForm, defaultCredentials, type CredentialConfig } from "@/components/scans/credential-form"
import { CyberCard } from "@/components/ui/cyber-card"
import { GlowButton } from "@/components/ui/glow-button"
import { StatusBadge } from "@/components/ui/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useCreateScan, useScanPreflight, useScanProfiles } from "@/hooks/use-scans"
import {
  formatAssetType,
  formatPriority,
  isDevAuthBypassEnabled,
  type ApiScanProfileContract,
  type ApiScanProfilePreflightResponse,
  type ScanAsset,
  type ScanType,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

/* ═══════════════════════════════════════════════════════════════
   STEP DEFINITIONS
   ═══════════════════════════════════════════════════════════════ */

const allSteps = [
  { id: 1, label: "Mode" },
  { id: 2, label: "Methodology" },
  { id: 3, label: "Target" },
  { id: 4, label: "Profile" },
  { id: 5, label: "Preflight" },
  { id: 6, label: "Confirm" },
] as const

type Step = 1 | 2 | 3 | 4 | 5 | 6

const profileIcons: Record<ScanType, ElementType> = {
  recon: Radar,
  vuln: Shield,
  full: Sparkles,
  exploit_verify: Shield,
}

const methodIcons: Record<Methodology, ElementType> = {
  black_box: EyeOff,
  grey_box: Eye,
  white_box: Code2,
}

const methodLabels: Record<Methodology, string> = {
  black_box: "Black Box",
  grey_box: "Grey Box",
  white_box: "White Box",
}

/* ═══════════════════════════════════════════════════════════════
   PAGE COMPONENT
   ═══════════════════════════════════════════════════════════════ */

export default function NewScanPage() {
  const router = useRouter()
  const { assets, projects, isLoading, error, refresh } = useAssetCatalog()
  const { createScan, isSubmitting, error: submitError } = useCreateScan()
  const {
    preflight,
    isLoading: isPreflightLoading,
    error: preflightError,
    clear: clearPreflight,
    runPreflight,
  } = useScanPreflight()

  // Wizard state
  const [currentStep, setCurrentStep] = useState<Step>(1)
  const [scanMode, setScanMode] = useState<ScanMode | null>(null)
  const [methodology, setMethodology] = useState<Methodology | null>(null)
  const [assetQuery, setAssetQuery] = useState("")
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null)
  const [selectedProfileContractId, setSelectedProfileContractId] = useState<string | null>(null)
  const [showCreateAsset, setShowCreateAsset] = useState(false)
  const [scopeConfig, setScopeConfig] = useState<ScopeConfig>(defaultScope)
  const [credentials, setCredentials] = useState<CredentialConfig>(defaultCredentials)
  const [repoUrl, setRepoUrl] = useState("")
  const [repoBranch, setRepoBranch] = useState("main")
  const [repoToken, setRepoToken] = useState("")
  const [authorizationAcknowledged, setAuthorizationAcknowledged] = useState(false)
  const [approvedLiveTools, setApprovedLiveTools] = useState<string[]>([])

  // URL-based asset pre-selection
  useEffect(() => {
    if (typeof window === "undefined") return
    const assetIdFromQuery = new URLSearchParams(window.location.search).get("assetId")
    if (assetIdFromQuery) setSelectedAssetId(assetIdFromQuery)
  }, [])

  // Computed
  const query = assetQuery.trim().toLowerCase()
  const filteredAssets = !query
    ? assets
    : assets.filter(
        (asset) =>
          asset.name.toLowerCase().includes(query) ||
          asset.target.toLowerCase().includes(query) ||
          asset.project?.name.toLowerCase().includes(query)
      )

  const selectedAsset = assets.find((a) => a.id === selectedAssetId)
  const {
    profiles,
    isLoading: isProfilesLoading,
    error: profilesError,
    refresh: refreshProfiles,
  } = useScanProfiles(selectedAsset?.asset_type, selectedAsset?.target)
  const selectedProfileData =
    profiles.find((p) => p.contract_id === selectedProfileContractId) ?? null

  useEffect(() => {
    if (!profiles.length) return
    if (
      !selectedProfileContractId ||
      !profiles.some((p) => p.contract_id === selectedProfileContractId)
    ) {
      setSelectedProfileContractId(profiles[0].contract_id)
    }
  }, [profiles, selectedProfileContractId])

  useEffect(() => {
    if (!selectedProfileData) {
      setApprovedLiveTools([])
      return
    }
    const allowed = new Set(selectedProfileData.approval_required_tools)
    setApprovedLiveTools((current) => current.filter((tool) => allowed.has(tool)))
  }, [selectedProfileData])

  useEffect(() => {
    clearPreflight()
  }, [
    selectedAssetId,
    selectedProfileContractId,
    scanMode,
    methodology,
    scopeConfig,
    credentials,
    repoUrl,
    repoBranch,
    repoToken,
    authorizationAcknowledged,
    approvedLiveTools,
    clearPreflight,
  ])

  useEffect(() => {
    if (
      currentStep !== 5 ||
      !selectedAsset ||
      !selectedProfileData ||
      !scanMode
    ) {
      return
    }

    void runPreflight({
      assetType: selectedAsset.asset_type,
      target: selectedAsset.target,
      contractId: selectedProfileData.contract_id,
      scanMode,
      methodology,
      authorizationAcknowledged,
      approvedLiveTools,
      credentials: buildCredentialPayload(credentials),
      repository: buildRepositoryPayload({
        methodology,
        repoUrl,
        repoBranch,
        repoToken,
      }),
      scope: buildScopePayload(scopeConfig),
    }).catch(() => {
      // Hook stores error for inline display
    })
  }, [
    authorizationAcknowledged,
    credentials,
    currentStep,
    methodology,
    repoBranch,
    repoToken,
    repoUrl,
    runPreflight,
    scanMode,
    scopeConfig,
    selectedAsset,
    selectedProfileData,
    approvedLiveTools,
  ])

  // For autonomous mode, skip methodology step
  const isAutonomous = scanMode === "autonomous"
  const visibleSteps = isAutonomous
    ? allSteps.filter((s) => s.id !== 2)
    : allSteps

  // Map visible step index to actual step id
  function getActualStep(visibleIndex: number): Step {
    return visibleSteps[visibleIndex - 1]?.id as Step ?? 1
  }

  function getVisibleIndex(actual: Step): number {
    const idx = visibleSteps.findIndex((s) => s.id === actual)
    return idx >= 0 ? idx + 1 : 1
  }

  const visibleIndex = getVisibleIndex(currentStep)
  const maxVisibleIndex = visibleSteps.length

  function canContinue(): boolean {
    if (currentStep === 1) return Boolean(scanMode)
    if (currentStep === 2) return Boolean(methodology)
    if (currentStep === 3) return Boolean(selectedAssetId)
    if (currentStep === 4) return Boolean(selectedProfileData)
    if (currentStep === 5) return Boolean(preflight?.can_launch)
    return Boolean(selectedAssetId && selectedProfileData && preflight?.can_launch)
  }

  function goNext() {
    const nextIdx = Math.min(visibleIndex + 1, maxVisibleIndex)
    setCurrentStep(getActualStep(nextIdx))
  }

  function goBack() {
    const prevIdx = Math.max(1, visibleIndex - 1)
    setCurrentStep(getActualStep(prevIdx))
  }

  function handleSearchKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter" && filteredAssets.length === 1) {
      event.preventDefault()
      setSelectedAssetId(filteredAssets[0].id)
    }
  }

  async function handleSubmit() {
    if (!selectedAssetId || !selectedProfileData) return

    try {
      const config: Record<string, unknown> = {
        source: "frontend-v2",
        requested_scan_profile: selectedProfileData.scan_type,
        requested_scan_profile_contract_id: selectedProfileData.contract_id,
        testing_mode: scanMode,
        profile_id: selectedProfileData.profile_id,
        profile: {
          id: selectedProfileData.profile_id,
          variant: selectedProfileData.profile_variant,
          contract_id: selectedProfileData.contract_id,
        },
        authorization_acknowledged: authorizationAcknowledged,
      }

      const approvedApprovalTools = approvedLiveTools.filter((tool) =>
        selectedProfileData.approval_required_tools.includes(tool)
      )
      config.execution = {
        allowed_live_tools: Array.from(
          new Set([
            ...selectedProfileData.live_tools,
            ...selectedProfileData.conditional_live_tools,
            ...approvedApprovalTools,
          ])
        ),
        approval_required_tools: selectedProfileData.approval_required_tools,
        approved_live_tools: approvedApprovalTools,
      }

      if (scanMode === "manual") {
        config.methodology = methodology
        config.scope_custom = {
          in_scope: scopeConfig.inScope,
          out_scope: scopeConfig.outScope,
          attack_depth: scopeConfig.attackDepth,
          rate_limit: scopeConfig.rateLimit,
          max_duration_minutes: scopeConfig.maxDuration,
        }
        if (credentials.authType !== "none") {
          config.credentials = buildCredentialPayload(credentials)
        }
        if ((methodology === "grey_box" || methodology === "white_box") && repoUrl) {
          config.repository = buildRepositoryPayload({
            methodology,
            repoUrl,
            repoBranch,
            repoToken,
          })
        }
      }

      const created = await createScan({
        assetId: selectedAssetId,
        scanType: selectedProfileData.scan_type,
        priority: selectedProfileData.priority,
        config,
      })
      router.push(`/scans/${created.id}`)
    } catch {
      // Hook stores error for inline display
    }
  }

  return (
    <CommandLayout title="New Attack">
      {/* ─── Header ─── */}
      <header className="sticky top-0 z-30 border-b border-border-subtle bg-surface-0/80 backdrop-blur-xl">
        <div className="flex h-14 items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <Link
              href="/scans"
              className="flex h-8 w-8 items-center justify-center rounded border border-border-subtle text-muted-foreground transition-all hover:bg-surface-1 hover:text-[#00ff9f]"
            >
              <ChevronLeft className="h-4 w-4" />
            </Link>
            <div>
              <h1 className="text-base font-semibold text-foreground font-heading">
                New Attack
              </h1>
              <p className="text-[10px] text-muted-foreground font-mono">
                Configure and launch a penetration test
              </p>
            </div>
          </div>
          {isDevAuthBypassEnabled() && (
            <StatusBadge status="running" label="Dev Bypass" />
          )}
        </div>
      </header>

      {/* ─── Step Indicator ─── */}
      <div className="border-b border-border-subtle bg-surface-0/60 px-5 py-4">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center justify-between">
            {visibleSteps.map((step, index) => {
              const actualIdx = getVisibleIndex(step.id)
              const isCurrent = currentStep === step.id
              const isPast = visibleIndex > actualIdx
              return (
                <div key={step.id} className="flex items-center">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={cn(
                        "flex h-8 w-8 items-center justify-center rounded text-xs font-bold transition-all duration-300 font-mono",
                        isPast
                          ? "bg-[#00ff9f] text-[#050505] shadow-[0_0_12px_rgba(0,255,159,0.3)]"
                          : isCurrent
                            ? "bg-[#00ff9f]/15 text-[#00ff9f] border border-[#00ff9f]/30"
                            : "bg-surface-1 text-[#555] border border-border-subtle"
                      )}
                    >
                      {isPast ? <Check className="h-3.5 w-3.5" /> : actualIdx}
                    </div>
                    <span
                      className={cn(
                        "text-xs font-semibold font-heading transition-colors",
                        isCurrent ? "text-foreground" : "text-[#555]"
                      )}
                    >
                      {step.label}
                    </span>
                  </div>
                  {index < visibleSteps.length - 1 && (
                    <div className="mx-4 flex items-center">
                      <div
                        className={cn(
                          "h-px w-12 sm:w-16 transition-all duration-500",
                          isPast ? "bg-[#00ff9f]/40" : "bg-border-subtle"
                        )}
                      />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* ─── Step Content ─── */}
      <main className="p-5">
        <div className="mx-auto max-w-4xl">
          {/* Errors */}
          {error && (
            <CyberCard accentColor="red" className="mb-5 p-4">
              <div className="flex items-center gap-3 text-[#ff3b3b]">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <div>
                  <p className="text-xs font-semibold">Could not load assets</p>
                  <p className="text-[10px] font-mono opacity-80">{error}</p>
                  <button type="button" onClick={refresh} className="mt-1 text-[10px] underline">
                    Retry
                  </button>
                </div>
              </div>
            </CyberCard>
          )}
          {submitError && (
            <CyberCard accentColor="red" className="mb-5 p-4">
              <div className="flex items-center gap-3 text-[#ff3b3b]">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <div>
                  <p className="text-xs font-semibold">Could not create scan</p>
                  <p className="text-[10px] font-mono opacity-80">{submitError}</p>
                </div>
              </div>
            </CyberCard>
          )}

          <AnimatePresence mode="wait">
            {/* ═══ STEP 1: MODE ═══ */}
            {currentStep === 1 && (
              <motion.div
                key="step1"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
              >
                <ModeSelector
                  selected={scanMode}
                  onSelect={(mode) => {
                    setScanMode(mode)
                    if (mode === "autonomous") setMethodology(null)
                  }}
                />
              </motion.div>
            )}

            {/* ═══ STEP 2: METHODOLOGY (Manual only) ═══ */}
            {currentStep === 2 && (
              <motion.div
                key="step2"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
              >
                <MethodologyPicker
                  selected={methodology}
                  onSelect={setMethodology}
                />
              </motion.div>
            )}

            {/* ═══ STEP 3: TARGET + SCOPE + CREDS ═══ */}
            {currentStep === 3 && (
              <motion.div
                key="step3"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-5"
              >
                <div className="text-center">
                  <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
                    Select Target
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground font-mono">
                    Choose an existing asset or create a new one
                  </p>
                </div>

                {/* Create asset inline */}
                <CyberCard accentColor="cyan" className="p-4">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold text-foreground font-heading">
                        Need a new target?
                      </p>
                      <p className="text-[10px] text-muted-foreground font-mono mt-0.5">
                        Create a project and asset here without leaving this flow
                      </p>
                    </div>
                    <GlowButton
                      variant="outline"
                      size="sm"
                      onClick={() => setShowCreateAsset((c) => !c)}
                    >
                      <Plus className="h-3 w-3" />
                      {showCreateAsset ? "Hide" : "Create asset"}
                    </GlowButton>
                  </div>
                  {showCreateAsset && (
                    <div className="mt-4 pt-4 border-t border-border-subtle">
                      <AssetIntakeForm
                        projects={projects}
                        submitLabel="Create and select"
                        title="Create asset target"
                        description="Creates a real project/asset through the API, then selects it."
                        onCancel={() => setShowCreateAsset(false)}
                        onCreated={({ asset }) => {
                          refresh()
                          setSelectedAssetId(asset.id)
                          setAssetQuery("")
                          setShowCreateAsset(false)
                        }}
                      />
                    </div>
                  )}
                </CyberCard>

                {/* Asset search */}
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#555]" />
                  <input
                    type="text"
                    value={assetQuery}
                    onChange={(e) => setAssetQuery(e.target.value)}
                    onKeyDown={handleSearchKeyDown}
                    placeholder="Search by name, target, or project"
                    className="w-full rounded border border-border-subtle bg-surface-0 py-2.5 pl-9 pr-4 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,255,159,0.3)] focus:outline-none"
                  />
                </div>

                {/* Asset list */}
                {isLoading ? (
                  <div className="flex min-h-[200px] items-center justify-center rounded border border-border-subtle bg-surface-0">
                    <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                      <Spinner className="h-4 w-4" />
                      Loading assets...
                    </div>
                  </div>
                ) : filteredAssets.length === 0 ? (
                  <div className="flex min-h-[200px] flex-col items-center justify-center rounded border border-dashed border-border-subtle bg-surface-0 text-center">
                    <Globe className="mb-2 h-6 w-6 text-[#555]" />
                    <p className="text-xs text-muted-foreground">
                      {assets.length === 0 ? "No assets - create one above" : "No match"}
                    </p>
                  </div>
                ) : (
                  <div className="grid gap-2 md:grid-cols-2">
                    {filteredAssets.map((asset) => {
                      const isSelected = asset.id === selectedAssetId
                      return (
                        <button
                          key={asset.id}
                          type="button"
                          onClick={() => setSelectedAssetId(asset.id)}
                          className={cn(
                            "group/asset relative overflow-hidden rounded border p-4 text-left transition-all duration-200",
                            isSelected
                              ? "border-[rgba(0,255,159,0.3)] bg-surface-1"
                              : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)] hover:bg-surface-1/50"
                          )}
                        >
                          {isSelected && (
                            <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#00ff9f] to-transparent" />
                          )}
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <h3 className={cn("text-sm font-semibold font-heading truncate", isSelected ? "text-[#00ff9f]" : "text-foreground")}>
                                {asset.name}
                              </h3>
                              <p className="mt-0.5 text-[10px] text-muted-foreground font-mono truncate">
                                {asset.target}
                              </p>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground">
                                {formatAssetType(asset.asset_type)}
                              </span>
                              {isSelected && (
                                <div className="flex h-4 w-4 items-center justify-center rounded-full bg-[#00ff9f]">
                                  <Check className="h-2.5 w-2.5 text-[#050505]" />
                                </div>
                              )}
                            </div>
                          </div>
                          <div className="mt-2 flex items-center gap-3 text-[10px] text-muted-foreground font-mono">
                            <span>{asset.project?.name ?? "Unassigned"}</span>
                            <span className="text-[#1a1a1e]">|</span>
                            <span className={asset.is_verified ? "text-[#00ff9f]" : "text-[#ffaa00]"}>
                              {asset.is_verified ? "Verified" : "Pending"}
                            </span>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                )}

                {/* Manual-mode: Scope + Credentials */}
                {scanMode === "manual" && selectedAssetId && (
                  <>
                    <div className="border-t border-border-subtle pt-5">
                      <ScopeEditor scope={scopeConfig} onChange={setScopeConfig} />
                    </div>

                    <div className="border-t border-border-subtle pt-5">
                      <CredentialForm credentials={credentials} onChange={setCredentials} />
                    </div>

                    {/* GitHub repo (Grey/White box) */}
                    {(methodology === "grey_box" || methodology === "white_box") && (
                      <div className="border-t border-border-subtle pt-5">
                        <CyberCard accentColor="cyan" className="p-4">
                          <div className="flex items-center gap-2 mb-3">
                            <GitBranch className="h-3.5 w-3.5 text-[#00cfff]" />
                            <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em]">
                              Source Code Repository
                            </h4>
                            <StatusBadge status={methodology === "white_box" ? "critical" : "medium"} label={methodology === "white_box" ? "Required" : "Optional"} size="sm" />
                          </div>
                          <div className="space-y-3">
                            <label className="block">
                              <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Repository URL</span>
                              <input
                                type="url"
                                value={repoUrl}
                                onChange={(e) => setRepoUrl(e.target.value)}
                                placeholder="https://github.com/org/repo"
                                className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
                              />
                            </label>
                            <div className="grid grid-cols-2 gap-3">
                              <label className="block">
                                <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Branch</span>
                                <input
                                  type="text"
                                  value={repoBranch}
                                  onChange={(e) => setRepoBranch(e.target.value)}
                                  placeholder="main"
                                  className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
                                />
                              </label>
                              <label className="block">
                                <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Access Token (private repos)</span>
                                <input
                                  type="password"
                                  value={repoToken}
                                  onChange={(e) => setRepoToken(e.target.value)}
                                  placeholder="ghp_..."
                                  className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
                                />
                              </label>
                            </div>
                            <p className="text-[9px] text-[#555] font-mono">
                              Pentra will clone into an ephemeral volume and run: Semgrep, Bandit, ESLint security, CodeQL
                            </p>
                          </div>
                        </CyberCard>
                      </div>
                    )}
                  </>
                )}
              </motion.div>
            )}

            {/* ═══ STEP 4: PROFILE ═══ */}
            {currentStep === 4 && (
              <motion.div
                key="step4"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-5"
              >
                <div className="text-center">
                  <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
                    Choose Attack Profile
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground font-mono">
                    Profiles define which tools run live against the target
                  </p>
                </div>

                {profilesError ? (
                  <CyberCard accentColor="red" className="p-4">
                    <div className="flex items-center gap-3 text-[#ff3b3b]">
                      <AlertCircle className="h-4 w-4" />
                      <div>
                        <p className="text-xs font-semibold">Could not load profiles</p>
                        <p className="text-[10px] font-mono opacity-80">{profilesError}</p>
                        <button type="button" onClick={refreshProfiles} className="mt-1 text-[10px] underline">
                          Retry
                        </button>
                      </div>
                    </div>
                  </CyberCard>
                ) : isProfilesLoading ? (
                  <div className="flex min-h-[200px] items-center justify-center rounded border border-border-subtle bg-surface-0">
                    <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                      <Spinner className="h-4 w-4" />
                      Loading profiles...
                    </div>
                  </div>
                ) : profiles.length === 0 ? (
                  <div className="flex min-h-[200px] flex-col items-center justify-center rounded border border-dashed border-border-subtle bg-surface-0">
                    <Shield className="mb-2 h-6 w-6 text-[#555]" />
                    <p className="text-xs text-muted-foreground">No profiles for this asset type</p>
                  </div>
                ) : (
                  <div className="grid gap-3 lg:grid-cols-3">
                    {profiles.map((profile) => {
                      const Icon = profileIcons[profile.scan_type]
                      const isSelected = selectedProfileContractId === profile.contract_id
                      return (
                        <button
                          key={profile.contract_id}
                          type="button"
                          onClick={() => setSelectedProfileContractId(profile.contract_id)}
                          className={cn(
                            "group relative overflow-hidden rounded border p-4 text-left transition-all duration-200",
                            isSelected
                              ? "border-[rgba(0,255,159,0.3)] bg-surface-1"
                              : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)] hover:bg-surface-1/50"
                          )}
                        >
                          {isSelected && (
                            <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#00ff9f] to-transparent" />
                          )}
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-2.5">
                              <div className={cn(
                                "flex h-8 w-8 items-center justify-center rounded",
                                isSelected ? "bg-[#00ff9f]/15 text-[#00ff9f]" : "bg-surface-2 text-[#555]"
                              )}>
                                <Icon className="h-4 w-4" />
                              </div>
                              <div>
                                <h3 className={cn("text-sm font-semibold font-heading", isSelected ? "text-[#00ff9f]" : "text-foreground")}>
                                  {profile.name}
                                </h3>
                                <p className="text-[9px] uppercase tracking-[0.15em] text-muted-foreground font-mono">
                                  {profile.duration} | {formatPriority(profile.priority)}
                                </p>
                              </div>
                            </div>
                            {isSelected && (
                              <div className="flex h-4 w-4 items-center justify-center rounded-full bg-[#00ff9f]">
                                <Check className="h-2.5 w-2.5 text-[#050505]" />
                              </div>
                            )}
                          </div>
                          <p className="text-[10px] text-muted-foreground font-mono leading-relaxed mb-3">
                            {profile.description}
                          </p>
                          <div className="mb-3 flex flex-wrap gap-1.5">
                            <StatusBadge status="verified" label={profile.profile_variant} size="sm" />
                            <StatusBadge
                              status={profile.requires_preflight ? "validating" : "completed"}
                              label={profile.requires_preflight ? "Preflight" : "Direct Launch"}
                              size="sm"
                            />
                            <StatusBadge
                              status={profile.benchmark_inputs_enabled ? "medium" : "low"}
                              label={
                                profile.benchmark_inputs_enabled
                                  ? "Benchmark Inputs On"
                                  : "Benchmark Inputs Off"
                              }
                              size="sm"
                            />
                          </div>
                          <div className="space-y-2">
                            <ProfileToolSection label="Live tools" tools={profile.live_tools} tone="live" />
                            {profile.approval_required_tools.length > 0 && (
                              <ProfileToolSection
                                label="Approval Required"
                                tools={profile.approval_required_tools}
                                tone="approval"
                              />
                            )}
                            {profile.conditional_live_tools.length > 0 && (
                              <ProfileToolSection label="Conditional" tools={profile.conditional_live_tools} tone="conditional" />
                            )}
                            {profile.derived_tools.length > 0 && (
                              <ProfileToolSection label="Derived" tools={profile.derived_tools} tone="derived" />
                            )}
                            {profile.unsupported_tools.length > 0 && (
                              <ProfileToolSection label="Unsupported" tools={profile.unsupported_tools} tone="unsupported" />
                            )}
                          </div>
                        </button>
                      )
                    })}
                  </div>
                )}
              </motion.div>
            )}

            {/* ═══ STEP 5: PREFLIGHT ═══ */}
            {currentStep === 5 && (
              <motion.div
                key="step5"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-5"
              >
                <div className="text-center">
                  <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
                    Real-Target Preflight
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground font-mono">
                    Validate authorization, runtime readiness, and bounded live execution before launch
                  </p>
                </div>

                {preflightError ? (
                  <CyberCard accentColor="red" className="p-4">
                    <div className="flex items-center gap-3 text-[#ff3b3b]">
                      <AlertCircle className="h-4 w-4" />
                      <div>
                        <p className="text-xs font-semibold">Preflight failed</p>
                        <p className="text-[10px] font-mono opacity-80">{preflightError}</p>
                      </div>
                    </div>
                  </CyberCard>
                ) : null}

                {isPreflightLoading && !preflight ? (
                  <div className="flex min-h-[220px] items-center justify-center rounded border border-border-subtle bg-surface-0">
                    <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
                      <Spinner className="h-4 w-4" />
                      Running launch preflight...
                    </div>
                  </div>
                ) : preflight ? (
                  <>
                    <PreflightSummary
                      preflight={preflight}
                      authorizationAcknowledged={authorizationAcknowledged}
                      onToggleAuthorization={setAuthorizationAcknowledged}
                      approvedLiveTools={approvedLiveTools}
                      onToggleApprovedTool={(tool, enabled) =>
                        setApprovedLiveTools((current) =>
                          enabled ? Array.from(new Set([...current, tool])) : current.filter((item) => item !== tool)
                        )
                      }
                      onRerun={() =>
                        runPreflight({
                          assetType: selectedAsset?.asset_type ?? "web_app",
                          target: selectedAsset?.target ?? "",
                          contractId: selectedProfileData?.contract_id ?? "",
                          scanMode: scanMode ?? "manual",
                          methodology,
                          authorizationAcknowledged,
                          approvedLiveTools,
                          credentials: buildCredentialPayload(credentials),
                          repository: buildRepositoryPayload({
                            methodology,
                            repoUrl,
                            repoBranch,
                            repoToken,
                          }),
                          scope: buildScopePayload(scopeConfig),
                        })
                      }
                      isRefreshing={isPreflightLoading}
                    />
                  </>
                ) : null}
              </motion.div>
            )}

            {/* ═══ STEP 6: CONFIRM ═══ */}
            {currentStep === 6 && (
              <motion.div
                key="step6"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.15 }}
                className="space-y-5"
              >
                <div className="text-center">
                  <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
                    Confirm & Launch
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground font-mono">
                    Review the launch contract now that preflight has passed
                  </p>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  {/* Config Summary */}
                  <CyberCard accentColor="green" className="p-4">
                    <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
                      Configuration
                    </h3>
                    <div className="space-y-2 text-xs">
                      <ConfirmRow label="Mode" value={scanMode === "autonomous" ? "Autonomous" : "Manual"} />
                      {methodology && (
                        <ConfirmRow label="Methodology" value={methodLabels[methodology]} />
                      )}
                      {selectedProfileData && (
                        <>
                          <ConfirmRow label="Profile" value={selectedProfileData.name} />
                          <ConfirmRow label="Variant" value={selectedProfileData.profile_variant} />
                          <ConfirmRow label="Duration" value={selectedProfileData.duration} />
                          <ConfirmRow label="Priority" value={formatPriority(selectedProfileData.priority)} />
                        </>
                      )}
                      {scanMode === "manual" && (
                        <>
                          <ConfirmRow label="Attack Depth" value={scopeConfig.attackDepth.replace(/_/g, " ")} />
                          <ConfirmRow label="Rate Limit" value={`${scopeConfig.rateLimit} req/min`} />
                          <ConfirmRow label="Auth" value={credentials.authType === "none" ? "None" : credentials.authType} />
                        </>
                      )}
                      {preflight && (
                        <>
                          <ConfirmRow
                            label="Target Profile"
                            value={
                              preflight.target_profile_hypotheses[0]
                                ? formatTargetProfileKey(preflight.target_profile_hypotheses[0].key)
                                : "Unclassified"
                            }
                          />
                          <ConfirmRow
                            label="Launch Gate"
                            value={preflight.can_launch ? "Passed" : "Blocked"}
                          />
                          <ConfirmRow
                            label="Approved Tools"
                            value={approvedLiveTools.length ? approvedLiveTools.join(", ") : "None"}
                          />
                        </>
                      )}
                    </div>
                  </CyberCard>

                  {/* Target Summary */}
                  <CyberCard accentColor="cyan" className="p-4">
                    <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
                      Target
                    </h3>
                    {selectedAsset && (
                      <div className="space-y-2 text-xs">
                        <ConfirmRow label="Asset" value={selectedAsset.name} />
                        <ConfirmRow label="Target" value={selectedAsset.target} mono />
                        <ConfirmRow label="Type" value={formatAssetType(selectedAsset.asset_type)} />
                        <ConfirmRow label="Project" value={selectedAsset.project?.name ?? "Unassigned"} />
                        {scopeConfig.inScope.length > 0 && (
                          <ConfirmRow label="In-scope" value={scopeConfig.inScope.join(", ")} mono />
                        )}
                        {scopeConfig.outScope.length > 0 && (
                          <ConfirmRow label="Exclusions" value={scopeConfig.outScope.join(", ")} mono />
                        )}
                        {repoUrl && (
                          <ConfirmRow label="Repository" value={repoUrl} mono />
                        )}
                        {preflight && (
                          <ConfirmRow
                            label="Authorization"
                            value={String(preflight.scope_authorization["status"] || "unknown")}
                          />
                        )}
                      </div>
                    )}
                  </CyberCard>
                </div>

                {/* Tools that will run */}
                {selectedProfileData && (
                  <CyberCard accentColor="none" className="p-4">
                    <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
                      Tools to Execute
                    </h3>
                    <div className="space-y-2">
                      <ProfileToolSection label="Live" tools={selectedProfileData.live_tools} tone="live" />
                      {selectedProfileData.approval_required_tools.length > 0 && (
                        <ProfileToolSection
                          label="Approval Required"
                          tools={selectedProfileData.approval_required_tools}
                          tone="approval"
                        />
                      )}
                      {selectedProfileData.conditional_live_tools.length > 0 && (
                        <ProfileToolSection label="Conditional" tools={selectedProfileData.conditional_live_tools} tone="conditional" />
                      )}
                      {selectedProfileData.derived_tools.length > 0 && (
                        <ProfileToolSection label="Derived" tools={selectedProfileData.derived_tools} tone="derived" />
                      )}
                      {selectedProfileData.unsupported_tools.length > 0 && (
                        <ProfileToolSection label="Unsupported" tools={selectedProfileData.unsupported_tools} tone="unsupported" />
                      )}
                    </div>
                    {preflight ? (
                      <div className="mt-4 flex flex-wrap gap-2">
                        <StatusBadge
                          status={preflight.benchmark_inputs_enabled ? "medium" : "low"}
                          label={
                            preflight.benchmark_inputs_enabled
                              ? "Benchmark Inputs Enabled"
                              : "Benchmark Inputs Disabled"
                          }
                        />
                        <StatusBadge
                          status={preflight.can_launch ? "configured_and_healthy" : "provider_unreachable"}
                          label={preflight.can_launch ? "Ready To Launch" : "Launch Blocked"}
                        />
                      </div>
                    ) : null}
                    {approvedLiveTools.length > 0 ? (
                      <div className="mt-4 rounded border border-[#00cfff]/20 bg-[#00cfff]/8 px-3 py-3 text-xs text-[#00cfff]">
                        Approved for this run: {approvedLiveTools.join(", ")}
                      </div>
                    ) : null}
                  </CyberCard>
                )}

                {/* Launch button */}
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={
                    isSubmitting ||
                    !selectedAssetId ||
                    !selectedProfileData ||
                    !preflight?.can_launch
                  }
                  className={cn(
                    "w-full rounded py-3 text-sm font-bold font-heading transition-all duration-200",
                    "bg-[#00ff9f] text-[#050505]",
                    "hover:bg-[#00cc7f] hover:shadow-[0_0_30px_rgba(0,255,159,0.3),0_0_60px_rgba(0,255,159,0.1)]",
                    "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:shadow-none disabled:hover:bg-[#00ff9f]"
                  )}
                >
                  {isSubmitting ? (
                    <span className="flex items-center justify-center gap-2">
                      <Spinner className="h-4 w-4" />
                      Launching attack...
                    </span>
                  ) : (
                    <span className="flex items-center justify-center gap-2">
                      <Swords className="h-4 w-4" />
                      Launch Attack
                    </span>
                  )}
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* ─── Navigation ─── */}
          {currentStep < 6 && (
            <div className="mt-6 flex items-center justify-between">
              <button
                type="button"
                onClick={goBack}
                disabled={visibleIndex === 1}
                className={cn(
                  "flex items-center gap-2 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  visibleIndex === 1
                    ? "cursor-not-allowed text-[#555]"
                    : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
                )}
              >
                <ChevronLeft className="h-3 w-3" />
                Back
              </button>
              <GlowButton
                size="md"
                onClick={goNext}
                disabled={!canContinue() || (currentStep === 5 && isPreflightLoading)}
              >
                {currentStep === 5 ? "Continue to confirm" : "Continue"}
                <ArrowRight className="h-3.5 w-3.5" />
              </GlowButton>
            </div>
          )}
          {currentStep === 6 && (
            <div className="mt-4">
              <button
                type="button"
                onClick={goBack}
                className="flex items-center gap-2 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
              >
                <ChevronLeft className="h-3 w-3" />
                Back to preflight
              </button>
            </div>
          )}
        </div>
      </main>
    </CommandLayout>
  )
}

/* ═══════════════════════════════════════════════════════════════
   HELPER COMPONENTS
   ═══════════════════════════════════════════════════════════════ */

function ConfirmRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={cn("text-foreground text-right", mono && "font-mono")}>{value}</span>
    </div>
  )
}

function buildCredentialPayload(credentials: CredentialConfig): Record<string, unknown> {
  if (credentials.authType === "none") {
    return {}
  }
  return {
    type: credentials.authType,
    cookie: credentials.cookie,
    username: credentials.username,
    password: credentials.password,
    bearer_token: credentials.bearerToken,
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
    token_url: credentials.tokenUrl,
  }
}

function buildRepositoryPayload(input: {
  methodology: Methodology | null
  repoUrl: string
  repoBranch: string
  repoToken: string
}): Record<string, unknown> {
  if ((input.methodology !== "grey_box" && input.methodology !== "white_box") || !input.repoUrl) {
    return {}
  }
  return {
    url: input.repoUrl,
    branch: input.repoBranch,
    token: input.repoToken || undefined,
  }
}

function buildScopePayload(scope: ScopeConfig): Record<string, unknown> {
  return {
    in_scope: scope.inScope,
    out_scope: scope.outScope,
    attack_depth: scope.attackDepth,
    rate_limit: scope.rateLimit,
    max_duration_minutes: scope.maxDuration,
  }
}

function formatTargetProfileKey(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}

function readStringRecordValue(record: Record<string, unknown>, key: string): string {
  const value = record[key]
  if (typeof value === "string" && value.trim()) {
    return value
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value)
  }
  return "-"
}

function readNumberRecordValue(record: Record<string, unknown>, key: string): number | null {
  const value = record[key]
  return typeof value === "number" ? value : null
}

function readStringArrayRecordValue(record: Record<string, unknown>, key: string): string[] {
  const value = record[key]
  return Array.isArray(value)
    ? value
        .map((item) => (typeof item === "string" ? item.trim() : ""))
        .filter(Boolean)
    : []
}

function PreflightSummary({
  preflight,
  authorizationAcknowledged,
  onToggleAuthorization,
  approvedLiveTools,
  onToggleApprovedTool,
  onRerun,
  isRefreshing,
}: {
  preflight: ApiScanProfilePreflightResponse
  authorizationAcknowledged: boolean
  onToggleAuthorization: (value: boolean) => void
  approvedLiveTools: string[]
  onToggleApprovedTool: (tool: string, enabled: boolean) => void
  onRerun: () => Promise<unknown>
  isRefreshing: boolean
}) {
  const targetContext = preflight.target_context
  const scopeAuthorization = preflight.scope_authorization
  const authMaterial = preflight.auth_material
  const rateLimitPolicy = preflight.rate_limit_policy
  const safeReplayPolicy = preflight.safe_replay_policy
  const aiReadiness = preflight.ai_provider_readiness
  const executionContract = preflight.execution_contract
  const autoLiveTools = readStringArrayRecordValue(executionContract, "live_tools")
  const approvalRequiredTools = readStringArrayRecordValue(executionContract, "approval_required_tools")
  const derivedTools = readStringArrayRecordValue(executionContract, "derived_tools")
  const unsupportedTools = readStringArrayRecordValue(executionContract, "unsupported_tools")

  return (
    <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-3">
        <CyberCard accentColor="cyan" className="p-4">
          <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
            Target Classification
          </h3>
          <div className="space-y-2 text-xs">
            <ConfirmRow label="Host" value={readStringRecordValue(targetContext, "host")} mono />
            <ConfirmRow
              label="External"
              value={readStringRecordValue(targetContext, "is_external_target")}
            />
            <ConfirmRow
              label="Top Profile"
              value={
                preflight.target_profile_hypotheses[0]
                  ? formatTargetProfileKey(preflight.target_profile_hypotheses[0].key)
                  : "Unclassified"
              }
            />
          </div>
        </CyberCard>

        <CyberCard accentColor="green" className="p-4">
          <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
            Runtime Contract
          </h3>
          <div className="space-y-2 text-xs">
            <ConfirmRow
              label="Live Tools"
              value={String(autoLiveTools.length)}
            />
            <ConfirmRow
              label="Approval Required"
              value={String(approvalRequiredTools.length)}
            />
            <ConfirmRow
              label="Replay Mode"
              value={readStringRecordValue(safeReplayPolicy, "verification_mode")}
            />
            <ConfirmRow
              label="Benchmark Inputs"
              value={preflight.benchmark_inputs_enabled ? "Enabled" : "Disabled"}
            />
          </div>
        </CyberCard>

        <CyberCard accentColor="none" className="p-4">
          <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
            Launch Status
          </h3>
          <div className="space-y-2">
            <StatusBadge
              status={preflight.can_launch ? "configured_and_healthy" : "provider_unreachable"}
              label={preflight.can_launch ? "Ready To Launch" : "Blocked"}
            />
            <StatusBadge
              status={readStringRecordValue(aiReadiness, "operator_state")}
              label={readStringRecordValue(aiReadiness, "operator_state")}
            />
          </div>
        </CyberCard>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <CyberCard accentColor="none" className="p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
                Authorization & Scope
              </h3>
              <p className="text-xs text-muted-foreground">{readStringRecordValue(scopeAuthorization, "message")}</p>
            </div>
            <StatusBadge
              status={readStringRecordValue(scopeAuthorization, "status")}
              label={readStringRecordValue(scopeAuthorization, "status")}
            />
          </div>
          <label className="mt-4 flex items-start gap-3 rounded border border-border-subtle bg-surface-1 p-3">
            <input
              type="checkbox"
              checked={authorizationAcknowledged}
              onChange={(event) => onToggleAuthorization(event.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-border-subtle bg-surface-0 text-[#00ff9f] focus:ring-[#00ff9f]/30"
            />
            <span className="text-xs text-muted-foreground">
              I confirm this target is owned or explicitly authorized in scope for the techniques and rate limits selected here.
            </span>
          </label>
        </CyberCard>

        <CyberCard accentColor="none" className="p-4">
          <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
            Auth, Rate Limits, and AI
          </h3>
          <div className="space-y-2 text-xs">
            <ConfirmRow label="Auth Material" value={readStringRecordValue(authMaterial, "status")} />
            <ConfirmRow
              label="HTTP Rate"
              value={`${readNumberRecordValue(rateLimitPolicy, "http_requests_per_minute") ?? 0}/min`}
            />
            <ConfirmRow
              label="Max Verification / Type"
              value={String(readNumberRecordValue(safeReplayPolicy, "max_verifications_per_type") ?? 0)}
            />
            <ConfirmRow
              label="AI State"
              value={readStringRecordValue(aiReadiness, "operator_state")}
            />
          </div>
        </CyberCard>
      </div>

      <CyberCard accentColor="none" className="p-4">
        <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
          Execution Policy
        </h3>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-3">
            <ProfileToolSection label="Auto Live" tools={autoLiveTools} tone="live" />
            <ProfileToolSection label="Approval Required" tools={approvalRequiredTools} tone="approval" />
            {derivedTools.length > 0 ? (
              <ProfileToolSection label="Derived" tools={derivedTools} tone="derived" />
            ) : null}
            {unsupportedTools.length > 0 ? (
              <ProfileToolSection label="Unsupported" tools={unsupportedTools} tone="unsupported" />
            ) : null}
          </div>

          <div className="rounded border border-border-subtle bg-surface-1 p-4">
            <p className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading">
              Operator Approval
            </p>
            <p className="mt-2 text-xs text-muted-foreground">
              Approval-required tools stay visible and blocked until you explicitly opt into them for this run.
            </p>
            <div className="mt-4 space-y-2">
              {approvalRequiredTools.length === 0 ? (
                <div className="rounded border border-border-subtle bg-surface-0 px-3 py-2 text-xs text-muted-foreground">
                  No extra approvals are required for this profile.
                </div>
              ) : (
                approvalRequiredTools.map((tool) => {
                  const enabled = approvedLiveTools.includes(tool)
                  return (
                    <label
                      key={tool}
                      className="flex items-start gap-3 rounded border border-border-subtle bg-surface-0 px-3 py-2"
                    >
                      <input
                        type="checkbox"
                        checked={enabled}
                        onChange={(event) => onToggleApprovedTool(tool, event.target.checked)}
                        className="mt-0.5 h-4 w-4 rounded border-border-subtle bg-surface-0 text-[#00cfff] focus:ring-[#00cfff]/30"
                      />
                      <div>
                        <p className="text-xs font-medium text-foreground font-mono">{tool}</p>
                        <p className="text-[11px] text-muted-foreground">
                          {enabled ? "Approved for this launch" : "Pending approval"}
                        </p>
                      </div>
                    </label>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </CyberCard>

      {(preflight.blocking_issues.length > 0 || preflight.warnings.length > 0) && (
        <div className="grid gap-3 lg:grid-cols-2">
          <CyberCard accentColor="red" className="p-4">
            <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
              Blocking Issues
            </h3>
            <div className="space-y-2 text-xs text-[#ff8a8a]">
              {preflight.blocking_issues.length ? (
                preflight.blocking_issues.map((issue) => (
                  <div key={issue} className="rounded border border-[#ff3b3b]/20 bg-[#ff3b3b]/8 px-3 py-2">
                    {issue}
                  </div>
                ))
              ) : (
                <div className="rounded border border-border-subtle bg-surface-1 px-3 py-2 text-muted-foreground">
                  No blocking issues detected.
                </div>
              )}
            </div>
          </CyberCard>

          <CyberCard accentColor="yellow" className="p-4">
            <h3 className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-3">
              Warnings
            </h3>
            <div className="space-y-2 text-xs text-[#ffd27a]">
              {preflight.warnings.length ? (
                preflight.warnings.map((warning) => (
                  <div key={warning} className="rounded border border-[#ffaa00]/20 bg-[#ffaa00]/8 px-3 py-2">
                    {warning}
                  </div>
                ))
              ) : (
                <div className="rounded border border-border-subtle bg-surface-1 px-3 py-2 text-muted-foreground">
                  No warnings detected.
                </div>
              )}
            </div>
          </CyberCard>
        </div>
      )}

      <div className="flex justify-end">
        <GlowButton
          size="md"
          onClick={() => void onRerun()}
          disabled={isRefreshing}
        >
          {isRefreshing ? "Refreshing..." : "Rerun Preflight"}
          <ArrowRight className="h-3.5 w-3.5" />
        </GlowButton>
      </div>
    </div>
  )
}

function toolToneClasses(
  tone: "live" | "approval" | "conditional" | "derived" | "unsupported"
): string {
  switch (tone) {
    case "live":
      return "border-[#00ff9f]/20 bg-[#00ff9f]/8 text-[#00ff9f]"
    case "approval":
      return "border-[#00cfff]/20 bg-[#00cfff]/8 text-[#00cfff]"
    case "conditional":
      return "border-[#00cfff]/20 bg-[#00cfff]/8 text-[#00cfff]"
    case "derived":
      return "border-border-subtle bg-surface-2 text-muted-foreground"
    case "unsupported":
      return "border-[#ff3b3b]/20 bg-[#ff3b3b]/8 text-[#ff3b3b]"
    default:
      return "border-border-subtle bg-surface-2 text-muted-foreground"
  }
}

function ProfileToolSection({
  label,
  tools,
  tone,
}: {
  label: string
  tools: string[]
  tone: "live" | "approval" | "conditional" | "derived" | "unsupported"
}) {
  return (
    <div>
      <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-[#555] font-heading">
        {label}
      </p>
      {tools.length > 0 ? (
        <div className="mt-1 flex flex-wrap gap-1">
          {tools.map((tool) => (
            <span
              key={`${label}:${tool}`}
              className={cn(
                "rounded border px-1.5 py-0.5 text-[9px] font-mono font-medium",
                toolToneClasses(tone)
              )}
            >
              {tool}
            </span>
          ))}
        </div>
      ) : (
        <div className="mt-1 rounded border border-border-subtle bg-surface-2 px-2 py-1 text-[9px] font-mono text-muted-foreground">
          none
        </div>
      )}
    </div>
  )
}
