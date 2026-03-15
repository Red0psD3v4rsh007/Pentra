"use client"

import type { FormEvent } from "react"
import { useMemo, useState } from "react"
import { AlertCircle, FolderPlus, Target } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Spinner } from "@/components/ui/spinner"
import {
  formatAssetType,
  type ApiAsset,
  type ApiProject,
} from "@/lib/scans-store"
import { useCreateAsset, useCreateProject } from "@/hooks/use-scans"
import { cn } from "@/lib/utils"

const assetTypeOptions: Array<ApiAsset["asset_type"]> = [
  "web_app",
  "api",
  "network",
  "repository",
  "cloud",
]

interface AssetIntakeFormProps {
  projects: ApiProject[]
  initialProjectId?: string | null
  title?: string
  description?: string
  submitLabel?: string
  onCreated?: (payload: { asset: ApiAsset; project: ApiProject }) => void
  onCancel?: () => void
  className?: string
}

type ProjectMode = "existing" | "new"

export function AssetIntakeForm({
  projects,
  initialProjectId,
  title = "Create a real target",
  description = "Add a project and asset so Pentra can scan a target you choose, not only seeded demo data.",
  submitLabel = "Create asset",
  onCreated,
  onCancel,
  className,
}: AssetIntakeFormProps) {
  const defaultProjectId = initialProjectId ?? projects[0]?.id ?? ""
  const [projectMode, setProjectMode] = useState<ProjectMode>(
    projects.length > 0 ? "existing" : "new"
  )
  const [selectedProjectId, setSelectedProjectId] = useState(defaultProjectId)
  const [projectName, setProjectName] = useState("")
  const [projectDescription, setProjectDescription] = useState("")
  const [assetName, setAssetName] = useState("")
  const [assetType, setAssetType] = useState<ApiAsset["asset_type"]>("web_app")
  const [target, setTarget] = useState("")
  const [assetDescription, setAssetDescription] = useState("")
  const [scopeTags, setScopeTags] = useState("")
  const [localError, setLocalError] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  const {
    createProject,
    isSubmitting: isCreatingProject,
    error: projectError,
  } = useCreateProject()
  const {
    createAsset,
    isSubmitting: isCreatingAsset,
    error: assetError,
  } = useCreateAsset()

  const isSubmitting = isCreatingProject || isCreatingAsset
  const errorMessage = localError ?? projectError ?? assetError

  const selectedProject = useMemo(() => {
    return projects.find((project) => project.id === selectedProjectId) ?? null
  }, [projects, selectedProjectId])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLocalError(null)
    setSuccessMessage(null)

    if (!assetName.trim()) {
      setLocalError("Asset name is required.")
      return
    }
    if (!target.trim()) {
      setLocalError("Target is required.")
      return
    }
    if (projectMode === "existing" && !selectedProjectId) {
      setLocalError("Choose an existing project or create a new one.")
      return
    }
    if (projectMode === "new" && !projectName.trim()) {
      setLocalError("Project name is required when creating a new project.")
      return
    }

    try {
      let project = selectedProject

      if (projectMode === "new" || !project) {
        project = await createProject({
          name: projectName.trim(),
          description: projectDescription.trim() || undefined,
        })
        setSelectedProjectId(project.id)
      }

      const asset = await createAsset({
        projectId: project.id,
        name: assetName.trim(),
        assetType,
        target: target.trim(),
        description: assetDescription.trim() || undefined,
        tags: parseTags(scopeTags),
      })

      setSuccessMessage(`Created ${asset.name} under ${project.name}.`)
      setAssetName("")
      setTarget("")
      setAssetDescription("")
      setScopeTags("")
      if (projectMode === "new") {
        setProjectMode("existing")
        setProjectName("")
        setProjectDescription("")
      }

      onCreated?.({ asset, project })
    } catch {
      // Hook state already captures the error.
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className={cn("rounded-2xl border border-border bg-card p-6", className)}
    >
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-foreground">{title}</h3>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
        </div>
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/10 text-primary">
          <Target className="h-5 w-5" />
        </div>
      </div>

      {errorMessage ? (
        <Alert variant="destructive" className="mb-5 border border-critical/40">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Could not save target</AlertTitle>
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      ) : null}

      {successMessage ? (
        <Alert className="mb-5 border border-low/30 bg-low/10">
          <FolderPlus className="h-4 w-4 text-low" />
          <AlertTitle className="text-low">Target ready</AlertTitle>
          <AlertDescription>{successMessage}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-6">
        <section className="space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                Project
              </h4>
              <p className="mt-1 text-sm text-muted-foreground">
                Use an existing project or create a new engagement scope.
              </p>
            </div>

            <div className="flex rounded-full border border-border bg-background p-1">
              <button
                type="button"
                onClick={() => setProjectMode("existing")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  projectMode === "existing"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                Existing
              </button>
              <button
                type="button"
                onClick={() => setProjectMode("new")}
                className={cn(
                  "rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                  projectMode === "new"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                New Project
              </button>
            </div>
          </div>

          {projectMode === "existing" ? (
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-foreground">Project</span>
              <select
                value={selectedProjectId}
                onChange={(event) => setSelectedProjectId(event.target.value)}
                className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              >
                <option value="">Choose a project</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name} ({project.asset_count} assets)
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <label className="block">
                <span className="mb-2 block text-sm font-medium text-foreground">
                  Project name
                </span>
                <input
                  value={projectName}
                  onChange={(event) => setProjectName(event.target.value)}
                  placeholder="Customer Portal"
                  className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                />
              </label>

              <label className="block md:col-span-2">
                <span className="mb-2 block text-sm font-medium text-foreground">
                  Project description
                </span>
                <textarea
                  value={projectDescription}
                  onChange={(event) => setProjectDescription(event.target.value)}
                  placeholder="Production customer-facing surface for the B2B app."
                  rows={3}
                  className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                />
              </label>
            </div>
          )}
        </section>

        <section className="grid gap-4 md:grid-cols-2">
          <label className="block">
            <span className="mb-2 block text-sm font-medium text-foreground">Asset name</span>
            <input
              value={assetName}
              onChange={(event) => setAssetName(event.target.value)}
              placeholder="Checkout API"
              className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </label>

          <label className="block">
            <span className="mb-2 block text-sm font-medium text-foreground">Asset type</span>
            <select
              value={assetType}
              onChange={(event) => setAssetType(event.target.value as ApiAsset["asset_type"])}
              className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            >
              {assetTypeOptions.map((option) => (
                <option key={option} value={option}>
                  {formatAssetType(option)}
                </option>
              ))}
            </select>
          </label>

          <label className="block md:col-span-2">
            <span className="mb-2 block text-sm font-medium text-foreground">Target</span>
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="https://api.example.com or 10.10.10.0/24"
              className="w-full rounded-xl border border-border bg-background px-4 py-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </label>

          <label className="block md:col-span-2">
            <span className="mb-2 block text-sm font-medium text-foreground">
              Asset description
            </span>
            <textarea
              value={assetDescription}
              onChange={(event) => setAssetDescription(event.target.value)}
              placeholder="Public-facing API used by the customer portal login and account flows."
              rows={3}
              className="w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </label>

          <label className="block md:col-span-2">
            <span className="mb-2 block text-sm font-medium text-foreground">
              Scope tags
            </span>
            <textarea
              value={scopeTags}
              onChange={(event) => setScopeTags(event.target.value)}
              placeholder={"env=production\nteam=platform"}
              rows={3}
              className="w-full rounded-xl border border-border bg-background px-4 py-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
            <p className="mt-2 text-xs text-muted-foreground">
              Optional. Enter one <code>key=value</code> pair per line.
            </p>
          </label>
        </section>
      </div>

      <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          Pentra will use this asset as the source of truth for later scans, findings, and reports.
        </p>

        <div className="flex items-center gap-3">
          {onCancel ? (
            <button
              type="button"
              onClick={onCancel}
              className="rounded-xl border border-border px-4 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground"
            >
              Cancel
            </button>
          ) : null}
          <button
            type="submit"
            disabled={isSubmitting}
            className="rounded-xl bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {isSubmitting ? (
              <span className="flex items-center gap-2">
                <Spinner className="h-4 w-4" />
                Saving target...
              </span>
            ) : (
              submitLabel
            )}
          </button>
        </div>
      </div>
    </form>
  )
}

function parseTags(input: string): Record<string, string> | undefined {
  const entries = input
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separatorIndex = line.indexOf("=")
      if (separatorIndex === -1) {
        return null
      }

      const key = line.slice(0, separatorIndex).trim()
      const value = line.slice(separatorIndex + 1).trim()
      if (!key || !value) {
        return null
      }
      return [key, value] as const
    })
    .filter((entry): entry is readonly [string, string] => entry !== null)

  if (entries.length === 0) {
    return undefined
  }

  return Object.fromEntries(entries)
}
