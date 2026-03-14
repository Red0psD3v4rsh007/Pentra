"use client"

import { useState } from "react"
import { DashboardSidebar } from "@/components/dashboard/sidebar"
import { TopBar } from "@/components/dashboard/top-bar"
import { 
  User,
  Building,
  Shield,
  Key,
  Webhook,
  Bell,
  Save,
  Plus,
  Copy,
  Eye,
  EyeOff,
  Trash2,
  ExternalLink
} from "lucide-react"
import { cn } from "@/lib/utils"

const settingsTabs = [
  { id: "profile", label: "Profile", icon: User },
  { id: "organization", label: "Organization", icon: Building },
  { id: "authentication", label: "Authentication", icon: Shield },
  { id: "api-keys", label: "API Keys", icon: Key },
  { id: "webhooks", label: "Webhooks", icon: Webhook },
  { id: "notifications", label: "Notifications", icon: Bell },
]

// Mock API keys
const API_KEYS = [
  {
    id: "key-001",
    name: "Production API Key",
    prefix: "pk_live_",
    lastUsed: "2 hours ago",
    created: "Dec 1, 2024",
    status: "active",
  },
  {
    id: "key-002",
    name: "Development API Key",
    prefix: "pk_test_",
    lastUsed: "5 days ago",
    created: "Nov 15, 2024",
    status: "active",
  },
]

// Mock Webhooks
const WEBHOOKS = [
  {
    id: "wh-001",
    url: "https://api.acmecorp.com/webhooks/pentra",
    events: ["scan.completed", "finding.created"],
    status: "active",
    lastTriggered: "1 hour ago",
  },
  {
    id: "wh-002",
    url: "https://slack.com/api/webhooks/T0001",
    events: ["finding.critical"],
    status: "active",
    lastTriggered: "3 days ago",
  },
]

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("profile")
  const [showApiKey, setShowApiKey] = useState<string | null>(null)

  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />

      <div className="pl-60 transition-all duration-200">
        <TopBar title="Settings" />

        <main className="p-6">
          {/* Header */}
          <div className="mb-6">
            <h1 className="text-2xl font-semibold text-foreground">Settings</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Manage your account, organization, and integrations
            </p>
          </div>

          {/* Settings Layout */}
          <div className="flex gap-8">
            {/* Left Sub-nav */}
            <div className="w-64 shrink-0">
              <nav className="sticky top-6 space-y-1">
                {settingsTabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-all",
                      activeTab === tab.id
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-elevated hover:text-foreground"
                    )}
                  >
                    <tab.icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Right Form Panels */}
            <div className="flex-1 max-w-3xl">
              {/* Profile Tab */}
              {activeTab === "profile" && (
                <div className="rounded-lg border border-border bg-card">
                  <div className="border-b border-border px-6 py-4">
                    <h2 className="text-lg font-semibold text-foreground">Profile Settings</h2>
                    <p className="text-sm text-muted-foreground">
                      Manage your personal information
                    </p>
                  </div>
                  <div className="p-6">
                    <div className="mb-6 flex items-center gap-4">
                      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-primary text-2xl font-semibold text-primary-foreground">
                        JD
                      </div>
                      <div>
                        <button className="rounded-md bg-elevated px-3 py-1.5 text-sm font-medium text-foreground hover:bg-muted transition-colors">
                          Change Avatar
                        </button>
                        <p className="mt-1 text-xs text-muted-foreground">
                          JPG, PNG or GIF. Max 2MB.
                        </p>
                      </div>
                    </div>

                    <div className="grid gap-6">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="mb-2 block text-sm font-medium text-foreground">
                            First Name
                          </label>
                          <input
                            type="text"
                            defaultValue="John"
                            className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                          />
                        </div>
                        <div>
                          <label className="mb-2 block text-sm font-medium text-foreground">
                            Last Name
                          </label>
                          <input
                            type="text"
                            defaultValue="Doe"
                            className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Email Address
                        </label>
                        <input
                          type="email"
                          defaultValue="john.doe@acmecorp.com"
                          className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                        />
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Timezone
                        </label>
                        <select className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all">
                          <option>UTC (Coordinated Universal Time)</option>
                          <option>America/New_York (EST)</option>
                          <option>America/Los_Angeles (PST)</option>
                          <option>Europe/London (GMT)</option>
                        </select>
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Role
                        </label>
                        <input
                          type="text"
                          defaultValue="Security Engineer"
                          className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                        />
                      </div>
                    </div>

                    <div className="mt-6 flex justify-end">
                      <button className="flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90">
                        <Save className="h-4 w-4" />
                        Save Changes
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Organization Tab */}
              {activeTab === "organization" && (
                <div className="rounded-lg border border-border bg-card">
                  <div className="border-b border-border px-6 py-4">
                    <h2 className="text-lg font-semibold text-foreground">Organization Settings</h2>
                    <p className="text-sm text-muted-foreground">
                      Manage your organization details and team
                    </p>
                  </div>
                  <div className="p-6">
                    <div className="grid gap-6">
                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Organization Name
                        </label>
                        <input
                          type="text"
                          defaultValue="Acme Corporation"
                          className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                        />
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Organization Slug
                        </label>
                        <div className="flex">
                          <span className="flex items-center rounded-l-md border border-r-0 border-border bg-elevated px-3 text-sm text-muted-foreground">
                            pentra.io/
                          </span>
                          <input
                            type="text"
                            defaultValue="acmecorp"
                            className="h-10 flex-1 rounded-r-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Industry
                        </label>
                        <select className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all">
                          <option>Technology</option>
                          <option>Finance</option>
                          <option>Healthcare</option>
                          <option>Retail</option>
                        </select>
                      </div>

                      <div>
                        <label className="mb-2 block text-sm font-medium text-foreground">
                          Company Size
                        </label>
                        <select className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all">
                          <option>1-50 employees</option>
                          <option>51-200 employees</option>
                          <option>201-1000 employees</option>
                          <option>1000+ employees</option>
                        </select>
                      </div>
                    </div>

                    <div className="mt-6 flex justify-end">
                      <button className="flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90">
                        <Save className="h-4 w-4" />
                        Save Changes
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* API Keys Tab */}
              {activeTab === "api-keys" && (
                <div className="space-y-6">
                  <div className="rounded-lg border border-border bg-card">
                    <div className="flex items-center justify-between border-b border-border px-6 py-4">
                      <div>
                        <h2 className="text-lg font-semibold text-foreground">API Keys</h2>
                        <p className="text-sm text-muted-foreground">
                          Manage API keys for programmatic access
                        </p>
                      </div>
                      <button className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90">
                        <Plus className="h-4 w-4" />
                        Create Key
                      </button>
                    </div>
                    <div className="divide-y divide-border">
                      {API_KEYS.map((key) => (
                        <div key={key.id} className="flex items-center justify-between px-6 py-4">
                          <div className="flex items-center gap-4">
                            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                              <Key className="h-5 w-5 text-muted-foreground" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-medium text-foreground">{key.name}</span>
                                <span className="rounded-full bg-low/10 px-2 py-0.5 text-xs font-medium text-low">
                                  Active
                                </span>
                              </div>
                              <div className="mt-1 flex items-center gap-2">
                                <code className="font-mono text-xs text-muted-foreground">
                                  {key.prefix}
                                  {showApiKey === key.id ? "sk_xxxxxxxxxxxxxxxx" : "••••••••••••"}
                                </code>
                                <button
                                  onClick={() => setShowApiKey(showApiKey === key.id ? null : key.id)}
                                  className="text-muted-foreground hover:text-foreground transition-colors"
                                >
                                  {showApiKey === key.id ? (
                                    <EyeOff className="h-3.5 w-3.5" />
                                  ) : (
                                    <Eye className="h-3.5 w-3.5" />
                                  )}
                                </button>
                                <button className="text-muted-foreground hover:text-foreground transition-colors">
                                  <Copy className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-6">
                            <div className="text-right">
                              <p className="text-xs text-muted-foreground">Last used</p>
                              <p className="text-sm text-foreground">{key.lastUsed}</p>
                            </div>
                            <button className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors">
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Webhooks Tab */}
              {activeTab === "webhooks" && (
                <div className="space-y-6">
                  <div className="rounded-lg border border-border bg-card">
                    <div className="flex items-center justify-between border-b border-border px-6 py-4">
                      <div>
                        <h2 className="text-lg font-semibold text-foreground">Webhooks</h2>
                        <p className="text-sm text-muted-foreground">
                          Configure webhook endpoints for real-time notifications
                        </p>
                      </div>
                      <button className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition-all hover:bg-primary/90">
                        <Plus className="h-4 w-4" />
                        Add Webhook
                      </button>
                    </div>
                    <div className="divide-y divide-border">
                      {WEBHOOKS.map((webhook) => (
                        <div key={webhook.id} className="px-6 py-4">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-4">
                              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                                <Webhook className="h-5 w-5 text-muted-foreground" />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <code className="font-mono text-sm text-foreground">
                                    {webhook.url}
                                  </code>
                                  <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                                </div>
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                  {webhook.events.map((event) => (
                                    <span
                                      key={event}
                                      className="rounded-md border border-border bg-elevated px-2 py-0.5 text-xs text-muted-foreground"
                                    >
                                      {event}
                                    </span>
                                  ))}
                                </div>
                                <p className="mt-2 text-xs text-muted-foreground">
                                  Last triggered: {webhook.lastTriggered}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="rounded-full bg-low/10 px-2 py-0.5 text-xs font-medium text-low">
                                Active
                              </span>
                              <button className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors">
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Authentication Tab */}
              {activeTab === "authentication" && (
                <div className="rounded-lg border border-border bg-card">
                  <div className="border-b border-border px-6 py-4">
                    <h2 className="text-lg font-semibold text-foreground">Authentication</h2>
                    <p className="text-sm text-muted-foreground">
                      Manage your security and authentication settings
                    </p>
                  </div>
                  <div className="p-6">
                    <div className="grid gap-6">
                      <div className="flex items-center justify-between rounded-lg border border-border p-4">
                        <div className="flex items-center gap-4">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                            <Shield className="h-5 w-5 text-muted-foreground" />
                          </div>
                          <div>
                            <h3 className="font-medium text-foreground">Two-Factor Authentication</h3>
                            <p className="text-sm text-muted-foreground">
                              Add an extra layer of security to your account
                            </p>
                          </div>
                        </div>
                        <button className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
                          Enable
                        </button>
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border p-4">
                        <div className="flex items-center gap-4">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                            <Key className="h-5 w-5 text-muted-foreground" />
                          </div>
                          <div>
                            <h3 className="font-medium text-foreground">Change Password</h3>
                            <p className="text-sm text-muted-foreground">
                              Last changed 30 days ago
                            </p>
                          </div>
                        </div>
                        <button className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-muted-foreground hover:bg-elevated hover:text-foreground transition-colors">
                          Update
                        </button>
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border p-4">
                        <div className="flex items-center gap-4">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-elevated">
                            <Bell className="h-5 w-5 text-muted-foreground" />
                          </div>
                          <div>
                            <h3 className="font-medium text-foreground">Login Notifications</h3>
                            <p className="text-sm text-muted-foreground">
                              Get notified when a new device logs in
                            </p>
                          </div>
                        </div>
                        <button className="relative h-6 w-11 rounded-full bg-primary transition-colors">
                          <span className="absolute right-1 top-1 h-4 w-4 rounded-full bg-white transition-transform" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Notifications Tab */}
              {activeTab === "notifications" && (
                <div className="rounded-lg border border-border bg-card">
                  <div className="border-b border-border px-6 py-4">
                    <h2 className="text-lg font-semibold text-foreground">Notification Preferences</h2>
                    <p className="text-sm text-muted-foreground">
                      Control when and how you receive notifications
                    </p>
                  </div>
                  <div className="p-6">
                    <div className="space-y-6">
                      {[
                        { title: "Scan Completed", description: "Get notified when a scan finishes", enabled: true },
                        { title: "Critical Findings", description: "Immediate alerts for critical vulnerabilities", enabled: true },
                        { title: "Weekly Digest", description: "Summary of security activity", enabled: true },
                        { title: "New Team Members", description: "When someone joins your organization", enabled: false },
                        { title: "API Usage Alerts", description: "When approaching rate limits", enabled: false },
                      ].map((notification) => (
                        <div key={notification.title} className="flex items-center justify-between">
                          <div>
                            <h3 className="font-medium text-foreground">{notification.title}</h3>
                            <p className="text-sm text-muted-foreground">{notification.description}</p>
                          </div>
                          <button
                            className={cn(
                              "relative h-6 w-11 rounded-full transition-colors",
                              notification.enabled ? "bg-primary" : "bg-muted"
                            )}
                          >
                            <span
                              className={cn(
                                "absolute top-1 h-4 w-4 rounded-full bg-white transition-transform",
                                notification.enabled ? "right-1" : "left-1"
                              )}
                            />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
