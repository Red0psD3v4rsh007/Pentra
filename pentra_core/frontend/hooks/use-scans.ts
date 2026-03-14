"use client"

import { useEffect, useState } from "react"

import {
  createScan as createScanRequest,
  getScanDetail,
  isActiveScanStatus,
  listAvailableAssets,
  listScans,
  type CreateScanInput,
  type Scan,
  type ScanAsset,
  type ScanDetail,
} from "@/lib/scans-store"

const DEFAULT_POLL_INTERVAL_MS = 5000

export function useScans(options?: {
  page?: number
  pageSize?: number
  pollIntervalMs?: number
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
        const response = await listScans({ page, pageSize })
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
  }, [page, pageSize, reloadToken])

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
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

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
        const nextDetail = await getScanDetail(scanId)
        if (!cancelled) {
          setDetail(nextDetail)
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
    isTerminal: detail?.isTerminal ?? false,
    isLoading,
    isRefreshing,
    error,
    refresh: () => setReloadToken((current) => current + 1),
  }
}

export function useScanCatalog() {
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
        const response = await listAvailableAssets()
        if (!cancelled) {
          setAssets(response)
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
    assets,
    isLoading,
    error,
    refresh: () => setReloadToken((current) => current + 1),
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
