"use client"

import { useEffect, useState } from "react"

import {
  createAsset as createAssetRequest,
  createProject as createProjectRequest,
  createRetestScan as createRetestScanRequest,
  DEFAULT_AI_ADVISORY_MODE,
  createScan as createScanRequest,
  getAsset,
  getProject,
  getScanDetail,
  getScanAiReasoning,
  isActiveScanStatus,
  listProjectAssets,
  listScanProfiles,
  listProjects,
  listScans,
  type AiAdvisoryMode,
  type ApiAsset,
  type ApiProject,
  type ApiScanProfileContract,
  type CreateAssetInput,
  type CreateProjectInput,
  type CreateScanInput,
  type Scan,
  type ScanAsset,
  type ScanDetail,
} from "@/lib/scans-store"

const DEFAULT_POLL_INTERVAL_MS = 5000

export function useScanProfiles(
  assetType: ApiAsset["asset_type"] | undefined,
  target: string | undefined
) {
  const [profiles, setProfiles] = useState<ApiScanProfileContract[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    const normalizedTarget = target?.trim() ?? ""
    if (!assetType || !normalizedTarget) {
      setProfiles([])
      setIsLoading(false)
      setError(null)
      return
    }
    const currentAssetType: ApiAsset["asset_type"] = assetType

    let cancelled = false

    async function load() {
      setIsLoading(true)
      setError(null)
      try {
        const nextProfiles = await listScanProfiles({
          assetType: currentAssetType,
          target: normalizedTarget,
        })
        if (!cancelled) {
          setProfiles(nextProfiles)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scan profiles.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [assetType, target, reloadToken])

  return {
    profiles,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useScans(options?: {
  page?: number
  pageSize?: number
  pollIntervalMs?: number
  assetId?: string
}) {
  const [scans, setScans] = useState<Scan[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(options?.page ?? 1)
  const [pageSize, setPageSize] = useState(options?.pageSize ?? 20)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    setPage(options?.page ?? 1)
  }, [options?.page])

  useEffect(() => {
    setPageSize(options?.pageSize ?? 20)
  }, [options?.pageSize])

  useEffect(() => {
    let cancelled = false

    async function load() {
      const showFullLoader = scans.length === 0 && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const response = await listScans({ page, pageSize, assetId: options?.assetId })
        if (cancelled) {
          return
        }

        setScans(response.items)
        setTotal(response.total)
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scans.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [options?.assetId, page, pageSize, reloadToken])

  const hasActiveScans = scans.some((scan) => isActiveScanStatus(scan.rawStatus))

  useEffect(() => {
    if (!hasActiveScans) {
      return
    }

    const timer = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
    }, options?.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS)

    return () => {
      window.clearTimeout(timer)
    }
  }, [hasActiveScans, options?.pollIntervalMs, reloadToken, scans])

  return {
    scans,
    total,
    page,
    pageSize,
    isLoading,
    isRefreshing,
    error,
    refresh: () => setReloadToken((current) => current + 1),
    setPage,
    setPageSize,
  }
}

export function useScan(id: string | undefined, pollIntervalMs: number = DEFAULT_POLL_INTERVAL_MS) {
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [advisoryMode, setAdvisoryMode] = useState<AiAdvisoryMode>(DEFAULT_AI_ADVISORY_MODE)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isRefreshingAiReasoning, setIsRefreshingAiReasoning] = useState(false)
  const [isLaunchingRetest, setIsLaunchingRetest] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    setAdvisoryMode(DEFAULT_AI_ADVISORY_MODE)
  }, [id])

  useEffect(() => {
    if (!id) {
      setDetail(null)
      setIsLoading(false)
      setError("Invalid scan id.")
      return
    }

    const scanId = id
    let cancelled = false

    async function load() {
      const showFullLoader = detail === null && reloadToken === 0
      setError(null)
      setIsLoading(showFullLoader)
      setIsRefreshing(!showFullLoader)

      try {
        const nextDetail = await getScanDetail(scanId, { advisoryMode })
        if (!cancelled) {
          setDetail(nextDetail)
          if (nextDetail.aiReasoning?.advisory_mode) {
            setAdvisoryMode(nextDetail.aiReasoning.advisory_mode)
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scan detail.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
          setIsRefreshing(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [id, reloadToken])

  async function loadAiReasoning(nextMode: AiAdvisoryMode, refresh: boolean) {
    if (!id || !detail?.isTerminal) {
      setAdvisoryMode(nextMode)
      return
    }

    setIsRefreshingAiReasoning(true)
    setError(null)
    try {
      const nextAdvisory = await getScanAiReasoning(id, {
        refresh,
        advisoryMode: nextMode,
      })
      setAdvisoryMode(nextMode)
      setDetail((current) =>
        current
          ? {
              ...current,
              aiReasoning: nextAdvisory,
            }
          : current
      )
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : refresh
            ? "Failed to regenerate AI advisory."
            : "Failed to load advisory mode."
      )
    } finally {
      setIsRefreshingAiReasoning(false)
    }
  }

  async function launchRetest() {
    if (!id) {
      throw new Error("Invalid scan id.")
    }

    setIsLaunchingRetest(true)
    setError(null)
    try {
      return await createRetestScanRequest(id)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to launch retest.")
      throw err
    } finally {
      setIsLaunchingRetest(false)
    }
  }

  const shouldPoll = detail ? isActiveScanStatus(detail.scan.rawStatus) : false

  useEffect(() => {
    if (!shouldPoll) {
      return
    }

    const timer = window.setTimeout(() => {
      setReloadToken((current) => current + 1)
    }, pollIntervalMs)

    return () => {
      window.clearTimeout(timer)
    }
  }, [pollIntervalMs, reloadToken, shouldPoll])

  return {
    scan: detail?.scan,
    asset: detail?.asset,
    jobs: detail?.jobs ?? [],
    findings: detail?.findings ?? [],
    artifacts: detail?.artifacts ?? [],
    attackGraph: detail?.attackGraph ?? null,
    timeline: detail?.timeline ?? [],
    evidence: detail?.evidence ?? [],
    report: detail?.report ?? null,
    aiReasoning: detail?.aiReasoning ?? null,
    advisoryMode,
    isTerminal: detail?.isTerminal ?? false,
    isLoading,
    isRefreshing,
    isRefreshingAiReasoning,
    isLaunchingRetest,
    error,
    selectAdvisoryMode: async (nextMode: AiAdvisoryMode) => {
      if (nextMode === advisoryMode) {
        return
      }
      await loadAiReasoning(nextMode, false)
    },
    refreshAiReasoning: async (nextMode: AiAdvisoryMode = advisoryMode) => {
      await loadAiReasoning(nextMode, true)
    },
    launchRetest,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useScanCatalog() {
  const catalog = useAssetCatalog()

  return {
    assets: catalog.assets,
    isLoading: catalog.isLoading,
    error: catalog.error,
    refresh: catalog.refresh,
  }
}

export function useAssetCatalog() {
  const [projects, setProjects] = useState<ApiProject[]>([])
  const [assets, setAssets] = useState<ScanAsset[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setError(null)
      setIsLoading(true)

      try {
        const projectList = await listProjects()
        const assetGroups = await Promise.all(
          projectList
            .filter((project) => project.is_active)
            .map(async (project) => {
              const projectAssets = await listProjectAssets(project.id)
              return projectAssets
                .filter((asset) => asset.is_active)
                .map((asset) => ({
                  ...asset,
                  project,
                }))
            })
        )
        if (!cancelled) {
          setProjects(projectList)
          setAssets(
            assetGroups.flat().sort((left, right) => left.name.localeCompare(right.name))
          )
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load assets.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [reloadToken])

  return {
    projects,
    assets,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useAsset(id: string | undefined) {
  const [asset, setAsset] = useState<ScanAsset | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    if (!id) {
      setAsset(null)
      setIsLoading(false)
      setError("Invalid asset id.")
      return
    }

    const assetId = id
    let cancelled = false

    async function load() {
      setError(null)
      setIsLoading(true)

      try {
        const baseAsset = await getAsset(assetId)
        const project = await getProject(baseAsset.project_id)
        if (!cancelled) {
          setAsset({
            ...baseAsset,
            project,
          })
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load asset.")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()

    return () => {
      cancelled = true
    }
  }, [id, reloadToken])

  return {
    asset,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useCreateProject() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createProject(input: CreateProjectInput): Promise<ApiProject> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createProjectRequest(input)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create project."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createProject,
    isSubmitting,
    error,
  }
}

export function useCreateAsset() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createAsset(input: CreateAssetInput): Promise<ApiAsset> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createAssetRequest(input)
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create asset."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createAsset,
    isSubmitting,
    error,
  }
}

export function useCreateScan() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function createScan(input: CreateScanInput): Promise<Scan> {
    setIsSubmitting(true)
    setError(null)

    try {
      return await createScanRequest(input)
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to create scan."
      setError(message)
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }

  return {
    createScan,
    isSubmitting,
    error,
  }
}
