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
  Globe,
  Plus,
  Radar,
  Search,
  Shield,
  Sparkles,
} from "lucide-react"

import { AssetIntakeForm } from "@/components/assets/asset-intake-form"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useCreateScan } from "@/hooks/use-scans"
import {
  formatAssetType,
  formatPriority,
  isDevAuthBypassEnabled,
  scanProfiles,
  type ScanAsset,
  type ScanType,
} from "@/lib/scans-store"
import { cn } from "@/lib/utils"

const steps = [
  { id: 1, label: "Asset" },
  { id: 2, label: "Profile" },
  { id: 3, label: "Confirm" },
] as const

type Step = 1 | 2 | 3

const profileIcons: Record<ScanType, ElementType> = {
  recon: Radar,
  vuln: Shield,
  full: Sparkles,
  exploit_verify: Shield,
}

export default function NewScanPage() {
  const router = useRouter()
  const { assets, projects, isLoading, error, refresh } = useAssetCatalog()
  const { createScan, isSubmitting, error: submitError } = useCreateScan()
  const [currentStep, setCurrentStep] = useState<Step>(1)
  const [assetQuery, setAssetQuery] = useState("")
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null)
  const [selectedProfile, setSelectedProfile] = useState<ScanType | null>("recon")
  const [showCreateAsset, setShowCreateAsset] = useState(false)

  useEffect(() => {
    if (typeof window === "undefined") {
      return
    }

    const assetIdFromQuery = new URLSearchParams(window.location.search).get("assetId")
    if (assetIdFromQuery) {
      setSelectedAssetId(assetIdFromQuery)
    }
  }, [])

  const query = assetQuery.trim().toLowerCase()
  const filteredAssets = !query
    ? assets
    : assets.filter((asset) => {
        return (
          asset.name.toLowerCase().includes(query) ||
          asset.target.toLowerCase().includes(query) ||
          asset.project?.name.toLowerCase().includes(query)
        )
      })

  const selectedAsset = assets.find((asset) => asset.id === selectedAssetId)
  const selectedProfileData = scanProfiles.find((profile) => profile.id === selectedProfile)

  function handleSearchKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter" && filteredAssets.length === 1) {
      event.preventDefault()
      setSelectedAssetId(filteredAssets[0].id)
    }
  }

  function canContinue() {
    if (currentStep === 1) {
      return Boolean(selectedAssetId)
    }

    if (currentStep === 2) {
      return Boolean(selectedProfile)
    }

    return Boolean(selectedAssetId && selectedProfile)
  }

  async function handleSubmit() {
    if (!selectedAssetId || !selectedProfileData) {
      return
    }

    try {
      const created = await createScan({
        assetId: selectedAssetId,
        scanType: selectedProfileData.id,
        priority: selectedProfileData.priority,
        config: {
          source: "frontend-phase1",
          profile: selectedProfileData.id,
          ...selectedProfileData.config,
        },
      })

      router.push(`/scans/${created.id}`)
    } catch {
      // The hook already stores the error for inline display.
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <header className="sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur-md">
          <div className="flex h-16 items-center justify-between px-6">
            <div className="flex items-center gap-4">
              <Link
                href="/scans"
                className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground"
              >
                <ChevronLeft className="h-4 w-4" />
              </Link>
              <div>
                <h1 className="text-lg font-semibold text-foreground">New Scan</h1>
                <p className="text-xs text-muted-foreground">
                  Select a real asset and launch a live scan through the Pentra API.
                </p>
              </div>
            </div>

            {isDevAuthBypassEnabled() ? (
              <div className="rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
                Dev auth bypass enabled
              </div>
            ) : null}
          </div>
        </header>

        <div className="border-b border-border bg-card px-6 py-4">
          <div className="mx-auto max-w-4xl">
            <div className="flex items-center justify-between">
              {steps.map((step, index) => (
                <div key={step.id} className="flex items-center">
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        "flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold transition-all",
                        currentStep > step.id
                          ? "bg-low text-white"
                          : currentStep === step.id
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted text-muted-foreground"
                      )}
                    >
                      {currentStep > step.id ? <Check className="h-4 w-4" /> : step.id}
                    </div>
                    <span
                      className={cn(
                        "text-sm font-medium transition-colors",
                        currentStep === step.id ? "text-foreground" : "text-muted-foreground"
                      )}
                    >
                      {step.label}
                    </span>
                  </div>

                  {index < steps.length - 1 ? (
                    <div
                      className={cn(
                        "mx-4 h-px w-24 transition-colors",
                        currentStep > step.id ? "bg-low" : "bg-border"
                      )}
                    />
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        </div>

        <main className="p-6">
          <div className="mx-auto max-w-4xl">
            {error ? (
              <Alert variant="destructive" className="mb-6 border border-critical/40">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Could not load assets</AlertTitle>
                <AlertDescription>
                  <p>{error}</p>
                  <button
                    type="button"
                    onClick={refresh}
                    className="mt-2 text-sm font-medium underline underline-offset-4"
                  >
                    Retry asset lookup
                  </button>
                </AlertDescription>
              </Alert>
            ) : null}

            {submitError ? (
              <Alert variant="destructive" className="mb-6 border border-critical/40">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Could not create scan</AlertTitle>
                <AlertDescription>{submitError}</AlertDescription>
              </Alert>
            ) : null}

            <AnimatePresence mode="wait">
              {currentStep === 1 ? (
                <motion.div
                  key="step1"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-6"
                >
                  <div>
                    <h2 className="text-xl font-semibold text-foreground">Choose an asset</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Pick an existing target or create a new project-backed asset inline.
                    </p>
                  </div>

                  <div className="rounded-xl border border-border bg-card p-5">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                      <div className="max-w-2xl">
                        <p className="text-sm font-semibold text-foreground">
                          Need a new target?
                        </p>
                        <p className="mt-1 text-sm text-muted-foreground">
                          Create a project and asset here, then continue the real scan flow
                          without leaving this page.
                        </p>
                      </div>

                      <button
                        type="button"
                        onClick={() => setShowCreateAsset((current) => !current)}
                        className="inline-flex items-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                      >
                        <Plus className="h-4 w-4" />
                        {showCreateAsset ? "Hide intake" : "Create asset target"}
                      </button>
                    </div>

                    {showCreateAsset ? (
                      <div className="mt-5">
                        <AssetIntakeForm
                          projects={projects}
                          submitLabel="Create asset and continue"
                          title="Create asset and keep scanning"
                          description="This creates a real project/asset through the API, then selects it here so you can immediately launch a scan."
                          onCancel={() => setShowCreateAsset(false)}
                          onCreated={({ asset }) => {
                            refresh()
                            setSelectedAssetId(asset.id)
                            setAssetQuery("")
                            setShowCreateAsset(false)
                          }}
                        />
                      </div>
                    ) : null}
                  </div>

                  <div className="relative">
                    <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="text"
                      value={assetQuery}
                      onChange={(event) => setAssetQuery(event.target.value)}
                      onKeyDown={handleSearchKeyDown}
                      placeholder="Search by asset name, target, or project"
                      className="w-full rounded-lg border border-border bg-card py-3 pl-11 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                    />
                  </div>

                  {isLoading ? (
                    <div className="flex min-h-[280px] items-center justify-center rounded-xl border border-border bg-card">
                      <div className="flex items-center gap-3 text-sm text-muted-foreground">
                        <Spinner className="h-5 w-5" />
                        Loading assets from the API...
                      </div>
                    </div>
                  ) : filteredAssets.length === 0 ? (
                    <Empty className="min-h-[280px] rounded-xl border border-border bg-card">
                      <EmptyHeader>
                        <EmptyMedia variant="icon">
                          <Globe className="h-6 w-6" />
                        </EmptyMedia>
                        <EmptyTitle>
                          {assets.length === 0 ? "No assets available yet" : "No assets match this search"}
                        </EmptyTitle>
                        <EmptyDescription>
                          {assets.length === 0
                            ? "Create your first real asset above, then Pentra can launch a scan against it."
                            : "Clear the search query or create a new asset target above."}
                        </EmptyDescription>
                      </EmptyHeader>
                    </Empty>
                  ) : (
                    <div className="grid gap-4 md:grid-cols-2">
                      {filteredAssets.map((asset) => {
                        const isSelected = asset.id === selectedAssetId

                        return (
                          <button
                            key={asset.id}
                            type="button"
                            onClick={() => setSelectedAssetId(asset.id)}
                            className={cn(
                              "rounded-xl border p-5 text-left transition-all",
                              isSelected
                                ? "border-primary bg-primary/10 shadow-lg shadow-primary/10"
                                : "border-border bg-card hover:border-border/80 hover:bg-elevated"
                            )}
                          >
                            <div className="mb-4 flex items-start justify-between gap-4">
                              <div>
                                <h3 className="text-base font-semibold text-foreground">
                                  {asset.name}
                                </h3>
                                <p className="mt-1 font-mono text-xs text-muted-foreground">
                                  {asset.target}
                                </p>
                              </div>

                              <div
                                className={cn(
                                  "rounded-full px-2.5 py-1 text-xs font-medium",
                                  isSelected
                                    ? "bg-primary text-primary-foreground"
                                    : "bg-muted text-muted-foreground"
                                )}
                              >
                                {formatAssetType(asset.asset_type)}
                              </div>
                            </div>

                            <div className="grid gap-3 text-sm text-muted-foreground">
                              <div className="flex items-center justify-between gap-2">
                                <span>Project</span>
                                <span className="font-medium text-foreground">
                                  {asset.project?.name ?? "Unassigned"}
                                </span>
                              </div>
                              <div className="flex items-center justify-between gap-2">
                                <span>Verification</span>
                                <span
                                  className={cn(
                                    "font-medium",
                                    asset.is_verified ? "text-low" : "text-medium"
                                  )}
                                >
                                  {asset.is_verified ? "Verified" : "Pending verification"}
                                </span>
                              </div>
                              <div className="flex items-center justify-between gap-2">
                                <span>Asset ID</span>
                                <span className="font-mono text-xs text-foreground">
                                  {asset.id.slice(0, 8)}
                                </span>
                              </div>
                            </div>
                          </button>
                        )
                      })}
                    </div>
                  )}
                </motion.div>
              ) : null}

              {currentStep === 2 ? (
                <motion.div
                  key="step2"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-6"
                >
                  <div>
                    <h2 className="text-xl font-semibold text-foreground">Choose a profile</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Profiles map directly to real backend scan types and priorities.
                    </p>
                  </div>

                  <div className="grid gap-4 md:grid-cols-3">
                    {scanProfiles.map((profile) => {
                      const Icon = profileIcons[profile.id]
                      const isSelected = selectedProfile === profile.id

                      return (
                        <button
                          key={profile.id}
                          type="button"
                          onClick={() => setSelectedProfile(profile.id)}
                          className={cn(
                            "flex flex-col items-start gap-4 rounded-xl border p-6 text-left transition-all",
                            isSelected
                              ? "border-primary bg-primary/10 shadow-lg shadow-primary/10"
                              : "border-border bg-card hover:border-border/80 hover:bg-elevated"
                          )}
                        >
                          <div
                            className={cn(
                              "flex h-12 w-12 items-center justify-center rounded-xl",
                              isSelected ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Icon className="h-6 w-6" />
                          </div>

                          <div>
                            <h3
                              className={cn(
                                "text-base font-semibold",
                                isSelected ? "text-primary" : "text-foreground"
                              )}
                            >
                              {profile.name}
                            </h3>
                            <p className="mt-1 text-sm text-muted-foreground">
                              {profile.description}
                            </p>
                          </div>

                          <div className="space-y-2 text-sm">
                            <div className="flex items-center justify-between gap-4">
                              <span className="text-muted-foreground">Expected duration</span>
                              <span className="font-medium text-foreground">{profile.duration}</span>
                            </div>
                            <div className="flex items-center justify-between gap-4">
                              <span className="text-muted-foreground">Priority</span>
                              <span className="font-medium text-foreground">
                                {formatPriority(profile.priority)}
                              </span>
                            </div>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </motion.div>
              ) : null}

              {currentStep === 3 ? (
                <motion.div
                  key="step3"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-6"
                >
                  <div>
                    <h2 className="text-xl font-semibold text-foreground">Review and confirm</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      This will call the live scan API and redirect to the real scan detail page.
                    </p>
                  </div>

                  <div className="grid gap-6 md:grid-cols-2">
                    <div className="rounded-xl border border-border bg-card p-6">
                      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                        Selected Asset
                      </h3>
                      {selectedAsset ? <AssetSummary asset={selectedAsset} /> : null}
                    </div>

                    <div className="rounded-xl border border-border bg-card p-6">
                      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                        Selected Profile
                      </h3>
                      {selectedProfileData ? (
                        <div className="space-y-4">
                          <div>
                            <p className="text-base font-semibold text-foreground">
                              {selectedProfileData.name}
                            </p>
                            <p className="mt-1 text-sm text-muted-foreground">
                              {selectedProfileData.description}
                            </p>
                          </div>
                          <div className="space-y-2 text-sm">
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Scan type</span>
                              <span className="font-medium text-foreground">
                                {selectedProfileData.id}
                              </span>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Priority</span>
                              <span className="font-medium text-foreground">
                                {formatPriority(selectedProfileData.priority)}
                              </span>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Expected duration</span>
                              <span className="font-medium text-foreground">
                                {selectedProfileData.duration}
                              </span>
                            </div>
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleSubmit}
                    disabled={isSubmitting || !selectedAssetId || !selectedProfile}
                    className="w-full rounded-lg bg-primary py-3.5 text-base font-semibold text-primary-foreground shadow-lg shadow-primary/20 transition-all hover:bg-primary/90 hover:shadow-xl hover:shadow-primary/25 disabled:cursor-not-allowed disabled:opacity-70"
                  >
                    {isSubmitting ? (
                      <span className="flex items-center justify-center gap-2">
                        <Spinner className="h-4 w-4" />
                        Starting scan...
                      </span>
                    ) : (
                      "Start Scan"
                    )}
                  </button>
                </motion.div>
              ) : null}
            </AnimatePresence>

            {currentStep < 3 ? (
              <div className="mt-8 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() =>
                    setCurrentStep((previous) => Math.max(1, previous - 1) as Step)
                  }
                  disabled={currentStep === 1}
                  className={cn(
                    "flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors",
                    currentStep === 1
                      ? "cursor-not-allowed text-muted-foreground"
                      : "text-foreground hover:bg-elevated"
                  )}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Back
                </button>

                <button
                  type="button"
                  onClick={() =>
                    setCurrentStep((previous) => Math.min(3, previous + 1) as Step)
                  }
                  disabled={!canContinue()}
                  className={cn(
                    "flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground transition-all",
                    canContinue() ? "hover:bg-primary/90" : "cursor-not-allowed opacity-50"
                  )}
                >
                  Continue
                  <ArrowRight className="h-4 w-4" />
                </button>
              </div>
            ) : (
              <div className="mt-4">
                <button
                  type="button"
                  onClick={() => setCurrentStep(2)}
                  className="flex items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
                >
                  <ChevronLeft className="h-4 w-4" />
                  Back to profile selection
                </button>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}

function AssetSummary({ asset }: { asset: ScanAsset }) {
  return (
    <div className="space-y-3 text-sm">
      <div>
        <p className="text-base font-semibold text-foreground">{asset.name}</p>
        <p className="mt-1 font-mono text-xs text-muted-foreground">{asset.target}</p>
      </div>

      <div className="space-y-2 text-muted-foreground">
        <div className="flex items-center justify-between gap-4">
          <span>Project</span>
          <span className="font-medium text-foreground">{asset.project?.name ?? "Unassigned"}</span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span>Asset type</span>
          <span className="font-medium text-foreground">{formatAssetType(asset.asset_type)}</span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span>Verification</span>
          <span className={cn("font-medium", asset.is_verified ? "text-low" : "text-medium")}>
            {asset.is_verified ? "Verified" : "Pending verification"}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span>Asset ID</span>
          <span className="font-mono text-xs text-foreground">{asset.id}</span>
        </div>
      </div>
    </div>
  )
}
