"use client"

import Link from "next/link"
import { AlertTriangle, CheckCircle2, Lock, Radar, Settings2, Shield, Wrench } from "lucide-react"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog, useScans } from "@/hooks/use-scans"

export default function SettingsPage() {
  const { scans, isLoading: scansLoading, error: scansError } = useScans({ pageSize: 100 })
  const {
    projects,
    assets,
    isLoading: assetsLoading,
    error: assetsError,
  } = useAssetCatalog()

  const isLoading = scansLoading || assetsLoading
  const error = scansError ?? assetsError

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Settings" />

        <main className="p-6">
          <div className="mb-6">
            <h1 className="text-2xl font-semibold text-foreground">Operator Settings</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              This page is intentionally simplified until real account, webhook, API key, and notification APIs exist.
            </p>
          </div>

          {isLoading ? (
            <div className="flex min-h-[32vh] items-center justify-center gap-3 rounded-lg border border-border bg-card">
              <Spinner className="h-5 w-5" />
              <span className="text-sm text-muted-foreground">Loading current runtime state...</span>
            </div>
          ) : error ? (
            <div className="rounded-lg border border-critical/20 bg-critical/5 p-4 text-sm text-critical">
              {error}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Shield className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Projects
                      </p>
                      <p className="text-2xl font-semibold text-foreground">{projects.length}</p>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-high/10">
                      <Radar className="h-5 w-5 text-high" />
                    </div>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Assets
                      </p>
                      <p className="text-2xl font-semibold text-foreground">{assets.length}</p>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-low/10">
                      <Settings2 className="h-5 w-5 text-low" />
                    </div>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        Scans Observed
                      </p>
                      <p className="text-2xl font-semibold text-foreground">{scans.length}</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <section className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="h-5 w-5 text-low" />
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Available Now</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        These are real product capabilities, not placeholder toggles.
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 space-y-3 text-sm text-muted-foreground">
                    <div className="rounded-lg border border-border bg-background p-4">
                      Scan launch, reports, and retest are backed by real APIs and persisted scan data.
                    </div>
                    <div className="rounded-lg border border-border bg-background p-4">
                      Execution truth is surfaced in scan detail as live, blocked, simulated, or inferred.
                    </div>
                    <div className="rounded-lg border border-border bg-background p-4">
                      AI advisory is wired with Anthropic primary and OpenAI optional fallback.
                    </div>
                  </div>
                </section>

                <section className="rounded-lg border border-border bg-card p-6">
                  <div className="flex items-center gap-3">
                    <Wrench className="h-5 w-5 text-high" />
                    <div>
                      <h2 className="text-base font-semibold text-foreground">Intentionally Deferred</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        These settings are hidden as editable controls until there are real APIs behind them.
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 space-y-3 text-sm text-muted-foreground">
                    <div className="rounded-lg border border-dashed border-border p-4">
                      Profile editing, organization editing, API key lifecycle, webhook delivery, and notifications are not API-backed yet.
                    </div>
                    <div className="rounded-lg border border-dashed border-border p-4">
                      When those APIs exist, this page can become a real configuration surface instead of a fake form.
                    </div>
                  </div>
                </section>
              </div>

              <section className="mt-6 rounded-lg border border-border bg-card p-6">
                <div className="flex items-center gap-3">
                  <Lock className="h-5 w-5 text-primary" />
                  <div>
                    <h2 className="text-base font-semibold text-foreground">Where To Operate Right Now</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      Use the real product surfaces below while settings APIs are still being built.
                    </p>
                  </div>
                </div>

                <div className="mt-5 flex flex-wrap gap-3">
                  <Link
                    href="/assets"
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                  >
                    Open Assets
                  </Link>
                  <Link
                    href="/scans/new"
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                  >
                    Launch Scan
                  </Link>
                  <Link
                    href="/reports"
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
                  >
                    Open Reports
                  </Link>
                </div>
              </section>

              <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
                <AlertTriangle className="h-3.5 w-3.5" />
                Reset 2 keeps this page honest by removing fake editable settings until the backend exists.
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  )
}
