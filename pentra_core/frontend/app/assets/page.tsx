"use client"

import Link from "next/link"
import { useMemo, useState } from "react"
import {
  Activity,
  AlertCircle,
  ArrowUpRight,
  FolderKanban,
  Globe,
  Plus,
  Search,
  ShieldCheck,
  Target,
} from "lucide-react"

import { AssetIntakeForm } from "@/components/assets/asset-intake-form"
import { CommandLayout } from "@/components/layout/command-layout"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { useAssetCatalog } from "@/hooks/use-scans"
import { formatAssetType, formatRelativeTime } from "@/lib/scans-store"
import { cn } from "@/lib/utils"

export default function AssetsPage() {
  const { projects, assets, isLoading, error, refresh } = useAssetCatalog()
  const [searchQuery, setSearchQuery] = useState("")
  const [showCreatePanel, setShowCreatePanel] = useState(false)

  const filteredAssets = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    const nextAssets = [...assets]
      .filter((asset) => {
        if (!query) {
          return true
        }

        return (
          asset.name.toLowerCase().includes(query) ||
          asset.target.toLowerCase().includes(query) ||
          asset.project?.name.toLowerCase().includes(query) ||
          formatAssetType(asset.asset_type).toLowerCase().includes(query)
        )
      })
      .sort((left, right) => {
        return new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime()
      })

    return nextAssets
  }, [assets, searchQuery])

  const stats = [
    {
      label: "Total Assets",
      value: assets.length,
      accent: "text-foreground",
      icon: Target,
    },
    {
      label: "Projects",
      value: projects.filter((project) => project.is_active).length,
      accent: "text-primary",
      icon: FolderKanban,
    },
    {
      label: "Verified",
      value: assets.filter((asset) => asset.is_verified).length,
      accent: "text-low",
      icon: ShieldCheck,
    },
    {
      label: "Pending Verification",
      value: assets.filter((asset) => !asset.is_verified).length,
      accent: "text-medium",
      icon: Activity,
    },
  ] as const

  return (
    <CommandLayout title="Targets">
        <main className="space-y-5 p-5">
          <section className="flex flex-col gap-4 cyber-card p-5 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-primary/25 bg-primary/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.18em] text-primary">
                Real Target Intake
              </div>
              <h1 className="text-2xl font-semibold text-foreground">Asset Inventory</h1>
              <p className="mt-2 text-sm text-muted-foreground">
                Manage the real projects and targets Pentra can scan. This page now reads the
                project and asset APIs directly, so what you create here becomes the source of
                truth for scans, findings, and reports.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Link
                href="/scans/new"
                className="rounded-xl border border-border px-4 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-elevated"
              >
                Launch Scan
              </Link>
              <button
                type="button"
                onClick={() => setShowCreatePanel((current) => !current)}
                className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Plus className="h-4 w-4" />
                {showCreatePanel ? "Hide Intake" : "Add Asset Scope"}
              </button>
            </div>
          </section>

          {showCreatePanel ? (
            <AssetIntakeForm
              projects={projects}
              submitLabel="Create asset"
              onCancel={() => setShowCreatePanel(false)}
              onCreated={() => {
                refresh()
                setShowCreatePanel(false)
              }}
            />
          ) : null}

          {error ? (
            <Alert variant="destructive" className="border border-critical/40">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Could not load assets</AlertTitle>
              <AlertDescription>
                <p>{error}</p>
                <button
                  type="button"
                  onClick={refresh}
                  className="mt-2 text-sm font-medium underline underline-offset-4"
                >
                  Retry
                </button>
              </AlertDescription>
            </Alert>
          ) : null}

          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label} className="rounded-2xl border border-border bg-card p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                      {stat.label}
                    </p>
                    <p className={cn("mt-2 text-3xl font-semibold", stat.accent)}>
                      {stat.value}
                    </p>
                  </div>
                  <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-elevated text-muted-foreground">
                    <stat.icon className="h-5 w-5" />
                  </div>
                </div>
              </div>
            ))}
          </section>

          <section className="rounded-3xl border border-border bg-card p-6">
            <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Real inventory</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Search real project-backed targets and jump straight into scan launch or asset
                  review.
                </p>
              </div>

              <label className="relative block w-full max-w-md">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search by asset, target, project, or type"
                  className="w-full rounded-xl border border-border bg-background py-3 pl-11 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                />
              </label>
            </div>

            {isLoading ? (
              <div className="flex min-h-[260px] items-center justify-center rounded-2xl border border-border bg-background">
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <Spinner className="h-5 w-5" />
                  Loading real assets from the API...
                </div>
              </div>
            ) : filteredAssets.length === 0 ? (
              <Empty className="min-h-[260px] rounded-2xl border border-dashed border-border bg-background">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <Globe className="h-6 w-6" />
                  </EmptyMedia>
                  <EmptyTitle>
                    {assets.length === 0 ? "No real assets yet" : "No assets match this search"}
                  </EmptyTitle>
                  <EmptyDescription>
                    {assets.length === 0
                      ? "Create your first project and target so Pentra can launch scans against a real asset."
                      : "Try a different search or create a new target directly from this page."}
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <div className="overflow-hidden rounded-2xl border border-border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-elevated/60">
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Asset
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Project
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Type
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Verification
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Updated
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id} className="bg-card transition-colors hover:bg-elevated/40">
                        <td className="px-4 py-4 align-top">
                          <div>
                            <Link
                              href={`/assets/${asset.id}`}
                              className="inline-flex items-center gap-2 text-sm font-semibold text-foreground transition-colors hover:text-primary"
                            >
                              {asset.name}
                              <ArrowUpRight className="h-4 w-4" />
                            </Link>
                            <p className="mt-1 font-mono text-xs text-muted-foreground">
                              {asset.target}
                            </p>
                            {asset.description ? (
                              <p className="mt-2 max-w-lg text-sm text-muted-foreground">
                                {asset.description}
                              </p>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-4 align-top">
                          <div className="space-y-1">
                            <p className="text-sm font-medium text-foreground">
                              {asset.project?.name ?? "Unassigned"}
                            </p>
                            {asset.project ? (
                              <p className="text-xs text-muted-foreground">
                                {asset.project.asset_count} assets in project
                              </p>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-4 align-top">
                          <span className="inline-flex rounded-full border border-border bg-background px-3 py-1 text-xs font-medium text-foreground">
                            {formatAssetType(asset.asset_type)}
                          </span>
                        </td>
                        <td className="px-4 py-4 align-top">
                          <span
                            className={cn(
                              "inline-flex rounded-full px-3 py-1 text-xs font-medium",
                              asset.is_verified
                                ? "bg-low/10 text-low"
                                : "bg-medium/10 text-medium"
                            )}
                          >
                            {asset.is_verified ? "Verified" : "Pending"}
                          </span>
                        </td>
                        <td className="px-4 py-4 align-top text-sm text-muted-foreground">
                          {formatRelativeTime(asset.updated_at)}
                        </td>
                        <td className="px-4 py-4 align-top">
                          <div className="flex justify-end gap-2">
                            <Link
                              href={`/assets/${asset.id}`}
                              className="rounded-xl border border-border px-3 py-2 text-xs font-medium text-foreground transition-colors hover:bg-elevated"
                            >
                              View
                            </Link>
                            <Link
                              href={`/scans/new?assetId=${asset.id}`}
                              className="rounded-xl bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
                            >
                              Scan
                            </Link>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </main>
    </CommandLayout>
  )
}
