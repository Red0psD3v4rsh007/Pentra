"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter, useSearchParams } from "next/navigation"
import { AnimatePresence, motion } from "framer-motion"
import { AlertCircle, RefreshCw } from "lucide-react"

import { CommandLayout } from "@/components/layout/command-layout"
import { ScanHeader } from "@/components/scans/scan-header"
import { ScanTabs } from "@/components/scans/scan-tabs"
import { AttackGraphTab } from "@/components/scans/tabs/attack-graph-tab"
import { EvidenceTab } from "@/components/scans/tabs/evidence-tab"
import { FindingsTab } from "@/components/scans/tabs/findings-tab"
import { JobsTab } from "@/components/scans/tabs/jobs-tab"
import { OverviewTab } from "@/components/scans/tabs/overview-tab"
import { PlannerTab } from "@/components/scans/tabs/planner-tab"
import { ReportTab } from "@/components/scans/tabs/report-tab"
import { TargetModelTab } from "@/components/scans/tabs/target-model-tab"
import { TimelineTab } from "@/components/scans/tabs/timeline-tab"
import { TerminalPanel } from "@/components/scans/terminal-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Spinner } from "@/components/ui/spinner"
import { useScan, useCancelScan } from "@/hooks/use-scans"
import { formatPriority, formatScanType, isActiveScanStatus, isLiveRuntimeStage } from "@/lib/scans-store"

const tabs = [
  "Overview",
  "Target Model",
  "Planner",
  "Findings",
  "Attack Graph",
  "Evidence",
  "Timeline",
  "Jobs",
  "Command Console",
  "Report",
] as const
type TabType = (typeof tabs)[number]

function tabFromQuery(value: string | null): TabType {
  switch (value) {
    case "findings":
      return "Findings"
    case "target-model":
      return "Target Model"
    case "planner":
      return "Planner"
    case "attack-graph":
      return "Attack Graph"
    case "evidence":
      return "Evidence"
    case "timeline":
      return "Timeline"
    case "jobs":
      return "Jobs"
    case "terminal":
    case "command-console":
      return "Command Console"
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
    targetModel,
    plannerContext,
    fieldValidation,
    toolLogs,
    liveJobSessions,
    agentTranscript,
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
    isApprovingTools,
    streamConnectionState,
    isUsingPollingFallback,
    toolApprovalError,
    error,
    refresh,
    selectAdvisoryMode,
    refreshAiReasoning,
    launchRetest,
    approveTools,
  } = useScan(scanId)
  const { cancelScan, isCancelling } = useCancelScan()
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<TabType>(tabFromQuery(searchParams.get("tab")))

  useEffect(() => {
    setActiveTab(tabFromQuery(searchParams.get("tab")))
  }, [searchParams])

  if (isLoading) {
    return (
      <CommandLayout title="Attacks">
        <div className="flex min-h-[60vh] items-center justify-center">
          <div className="flex items-center gap-3 text-sm text-muted-foreground font-mono">
            <Spinner className="h-5 w-5" />
            Loading scan detail...
          </div>
        </div>
      </CommandLayout>
    )
  }

  if (error || !scan) {
    return (
      <CommandLayout title="Attacks">
        <main className="p-5">
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
      </CommandLayout>
    )
  }

  const currentScan = scan
  const hasLiveCommandActivity = toolLogs.some((entry) =>
    isLiveRuntimeStage(
      entry.runtime_stage ??
        (entry.status === "running"
          ? entry.stdout_preview.trim() || entry.stderr_preview.trim()
            ? "streaming"
            : entry.display_command.trim() || entry.command.length
              ? "command_resolved"
              : "container_starting"
          : null)
    )
  )
  const scanHeaderData = {
    id: currentScan.id,
    name: currentScan.name,
    target: currentScan.target,
    status: currentScan.status,
    statusLabel: currentScan.statusLabel,
    duration: currentScan.duration,
    progress: currentScan.progress,
    scanTypeLabel: currentScan.executionContract?.name?.trim() || formatScanType(currentScan.scanType),
    priorityLabel: formatPriority(currentScan.priority),
    severity: currentScan.findings,
    errorMessage: currentScan.errorMessage,
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
              executionContract: currentScan.executionContract,
              severity: currentScan.findings,
            }}
            asset={asset}
            jobs={jobs}
            findings={findings}
            targetModel={targetModel}
            fieldValidation={fieldValidation}
            onApproveTools={approveTools}
            isApprovingTools={isApprovingTools}
            toolApprovalError={toolApprovalError}
          />
        )
      case "Target Model":
        return <TargetModelTab targetModel={targetModel} />
      case "Planner":
        return (
          <PlannerTab
            plannerContext={plannerContext}
            transcript={agentTranscript}
            fieldValidation={fieldValidation}
          />
        )
      case "Findings":
        return <FindingsTab findings={findings} advisory={aiReasoning} />
      case "Attack Graph":
        return (
          <AttackGraphTab
            graph={attackGraph}
            report={report}
            evidence={evidence}
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
      case "Jobs":
        return (
          <JobsTab
            jobs={jobs}
            toolLogs={toolLogs}
            onApproveTools={approveTools}
            isApprovingTools={isApprovingTools}
            toolApprovalError={toolApprovalError}
          />
        )
      case "Command Console":
        return (
          <TerminalPanel
            scanId={currentScan.id}
            executionLogs={toolLogs}
            liveJobSessions={liveJobSessions}
            isActive={isActiveScanStatus(currentScan.rawStatus)}
            streamConnectionState={streamConnectionState}
            isUsingPollingFallback={isUsingPollingFallback}
          />
        )
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
    <CommandLayout title="Attacks">
      <ScanHeader
        scan={scanHeaderData}
        isRefreshing={isRefreshing}
        isCancelling={isCancelling}
        onRefresh={refresh}
        onCancel={() => scanId && cancelScan(scanId, refresh)}
      />

      <ScanTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab as TabType)}
        badges={{
          "Command Console": hasLiveCommandActivity ? "Live" : null,
        }}
      />

      <AnimatePresence mode="wait">
        <motion.main
          key={activeTab}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.15 }}
          className={activeTab === "Attack Graph" ? "" : "p-5"}
        >
          {renderTabContent()}
        </motion.main>
      </AnimatePresence>
    </CommandLayout>
  )
}
