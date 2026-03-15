"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter, useSearchParams } from "next/navigation"
import { AnimatePresence, motion } from "framer-motion"
import { AlertCircle, RefreshCw } from "lucide-react"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { ScanHeader } from "@/components/scans/scan-header"
import { ScanTabs } from "@/components/scans/scan-tabs"
import { AttackGraphTab } from "@/components/scans/tabs/attack-graph-tab"
import { EvidenceTab } from "@/components/scans/tabs/evidence-tab"
import { FindingsTab } from "@/components/scans/tabs/findings-tab"
import { OverviewTab } from "@/components/scans/tabs/overview-tab"
import { ReportTab } from "@/components/scans/tabs/report-tab"
import { TimelineTab } from "@/components/scans/tabs/timeline-tab"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Spinner } from "@/components/ui/spinner"
import { useScan } from "@/hooks/use-scans"
import { formatPriority, formatScanType } from "@/lib/scans-store"

const tabs = ["Overview", "Findings", "Attack Graph", "Evidence", "Timeline", "Report"] as const
type TabType = (typeof tabs)[number]

function tabFromQuery(value: string | null): TabType {
  switch (value) {
    case "findings":
      return "Findings"
    case "attack-graph":
      return "Attack Graph"
    case "evidence":
      return "Evidence"
    case "timeline":
      return "Timeline"
    case "report":
      return "Report"
    default:
      return "Overview"
  }
}

export default function ScanDetailPage() {
  const params = useParams()
  const searchParams = useSearchParams()
  const scanId = typeof params.id === "string" ? params.id : undefined
  const {
    scan,
    asset,
    jobs,
    findings,
    attackGraph,
    timeline,
    evidence,
    report,
    aiReasoning,
    advisoryMode,
    isLoading,
    isRefreshing,
    isRefreshingAiReasoning,
    isLaunchingRetest,
    error,
    refresh,
    selectAdvisoryMode,
    refreshAiReasoning,
    launchRetest,
  } = useScan(scanId)
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<TabType>(tabFromQuery(searchParams.get("tab")))

  useEffect(() => {
    setActiveTab(tabFromQuery(searchParams.get("tab")))
  }, [searchParams])

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardSidebar />
        <div className="flex min-h-screen items-center justify-center pl-60">
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Spinner className="h-5 w-5" />
            Loading real scan detail from the API...
          </div>
        </div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardSidebar />
        <div className="pl-60">
          <main className="p-6">
            <Alert variant="destructive" className="border border-critical/40">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Scan detail unavailable</AlertTitle>
              <AlertDescription>
                <p>{error ?? "The requested scan could not be found."}</p>
                <button
                  type="button"
                  onClick={refresh}
                  className="mt-2 inline-flex items-center gap-2 text-sm font-medium underline underline-offset-4"
                >
                  <RefreshCw className="h-4 w-4" />
                  Retry
                </button>
              </AlertDescription>
            </Alert>
          </main>
        </div>
      </div>
    )
  }

  const currentScan = scan
  const scanHeaderData = {
    id: currentScan.id,
    name: currentScan.name,
    target: currentScan.target,
    status: currentScan.status,
    statusLabel: currentScan.statusLabel,
    duration: currentScan.duration,
    progress: currentScan.progress,
    scanTypeLabel: formatScanType(currentScan.scanType),
    priorityLabel: formatPriority(currentScan.priority),
    severity: currentScan.findings,
  }

  function renderTabContent() {
    switch (activeTab) {
      case "Overview":
        return (
          <OverviewTab
            scan={{
              scanType: currentScan.scanType,
              progress: currentScan.progress,
              status: currentScan.status,
              statusLabel: currentScan.statusLabel,
              priority: currentScan.priority,
              startedAt: currentScan.startedAt,
              completedAt: currentScan.completedAt,
              createdAt: currentScan.createdAt,
              target: currentScan.target,
              errorMessage: currentScan.errorMessage,
              severity: currentScan.findings,
            }}
            asset={asset}
            jobs={jobs}
            findings={findings}
          />
        )
      case "Findings":
        return <FindingsTab findings={findings} advisory={aiReasoning} />
      case "Attack Graph":
        return (
          <AttackGraphTab
            graph={attackGraph}
            advisory={aiReasoning}
            advisoryMode={advisoryMode}
            onChangeAdvisoryMode={selectAdvisoryMode}
            onRegenerateAdvisory={refreshAiReasoning}
            isRegeneratingAdvisory={isRefreshingAiReasoning}
          />
        )
      case "Evidence":
        return <EvidenceTab evidence={evidence} />
      case "Timeline":
        return <TimelineTab events={timeline} />
      case "Report":
        return (
          <ReportTab
            scanId={currentScan.id}
            report={report}
            advisory={aiReasoning}
            advisoryMode={advisoryMode}
            onChangeAdvisoryMode={selectAdvisoryMode}
            onRegenerateAdvisory={refreshAiReasoning}
            isRegeneratingAdvisory={isRefreshingAiReasoning}
            isLaunchingRetest={isLaunchingRetest}
            onLaunchRetest={async () => {
              try {
                const nextScan = await launchRetest()
                router.push(`/scans/${nextScan.id}`)
              } catch {}
            }}
          />
        )
      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <ScanHeader scan={scanHeaderData} isRefreshing={isRefreshing} onRefresh={refresh} />

        <ScanTabs
          tabs={tabs}
          activeTab={activeTab}
          onTabChange={(tab) => setActiveTab(tab as TabType)}
        />

        <AnimatePresence mode="wait">
          <motion.main
            key={activeTab}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.15 }}
            className={activeTab === "Attack Graph" ? "" : "p-6"}
          >
            {renderTabContent()}
          </motion.main>
        </AnimatePresence>
      </div>
    </div>
  )
}
