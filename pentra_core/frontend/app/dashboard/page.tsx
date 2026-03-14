"use client"

import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { MetricCards } from "@/components/dashboard/metric-cards"
import { RecentScans } from "@/components/dashboard/recent-scans"
import { SeverityBreakdown } from "@/components/dashboard/severity-breakdown"

export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Sidebar */}
      <DashboardSidebar />

      {/* Main Content Area */}
      <div className="pl-60 transition-all duration-200">
        {/* Top Bar */}
        <TopBar title="Dashboard" />

        {/* Main Content */}
        <main className="p-6">
          {/* Key Metrics */}
          <section>
            <MetricCards />
          </section>

          {/* Recent Scans */}
          <section className="mt-6">
            <RecentScans />
          </section>

          {/* Severity Breakdown */}
          <section className="mt-6">
            <SeverityBreakdown />
          </section>
        </main>
      </div>
    </div>
  )
}
