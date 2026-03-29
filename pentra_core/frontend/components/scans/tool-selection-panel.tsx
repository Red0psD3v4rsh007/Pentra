"use client"

import { useState, useEffect, useCallback } from "react"
import { cn } from "@/lib/utils"
import {
  Search,
  ChevronDown,
  ChevronRight,
  Check,
  Sparkles,
  Shield,
  Radar,
  Globe,
  Zap,
  FileSearch,
  AlertTriangle,
  Info,
  GripVertical,
  ToggleLeft,
  ToggleRight,
} from "lucide-react"

interface ToolSubcommand {
  flag: string
  description: string
  default?: any
  required?: boolean
  category?: string
  value_type?: string
}

interface ToolPhase {
  name: string
  description: string
  command_preview: string
  timeout_seconds: number
  conditional: boolean
  condition: string | null
}

interface Tool {
  tool_id: string
  name: string
  description: string
  category: string
  image: string
  is_internal: boolean
  attack_vectors: string[]
  phases: ToolPhase[]
  phase_count: number
  subcommands?: ToolSubcommand[]
  subcommand_count?: number
}

interface ToolSelectionPanelProps {
  selectedTools: string[]
  onSelectionChange: (tools: string[]) => void
  toolOverrides?: Record<string, Record<string, any>>
  onOverridesChange?: (overrides: Record<string, Record<string, any>>) => void
  targetContext?: {
    base_url?: string
    target_host?: string
  }
  className?: string
}

const categoryConfig: Record<string, { label: string; icon: typeof Radar; color: string }> = {
  scope_validation: { label: "Scope", icon: Shield, color: "text-zinc-400" },
  recon: { label: "Recon", icon: Radar, color: "text-blue-400" },
  enum: { label: "Enumeration", icon: FileSearch, color: "text-cyan-400" },
  vuln_scan: { label: "Vulnerability Scanning", icon: AlertTriangle, color: "text-amber-400" },
  verification: { label: "Verification", icon: Check, color: "text-emerald-400" },
  ai_analysis: { label: "AI Analysis", icon: Sparkles, color: "text-purple-400" },
  report_gen: { label: "Reporting", icon: Globe, color: "text-indigo-400" },
}

export function ToolSelectionPanel({
  selectedTools,
  onSelectionChange,
  toolOverrides = {},
  onOverridesChange,
  targetContext,
  className,
}: ToolSelectionPanelProps) {
  const [tools, setTools] = useState<Tool[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [expandedTool, setExpandedTool] = useState<string | null>(null)
  const [expandedSubcommands, setExpandedSubcommands] = useState<Record<string, boolean>>({})

  // Fetch tools from API
  useEffect(() => {
    const fetchTools = async () => {
      try {
        const res = await fetch("/api/v1/tools")
        if (res.ok) {
          const data = await res.json()
          setTools(data.tools || [])
        }
      } catch {
        // Fallback — hardcoded tool data for offline mode
        console.warn("Could not fetch tools from API, using offline data")
      } finally {
        setLoading(false)
      }
    }
    fetchTools()
  }, [])

  const toggleTool = useCallback(
    (toolId: string) => {
      if (selectedTools.includes(toolId)) {
        onSelectionChange(selectedTools.filter((t) => t !== toolId))
      } else {
        onSelectionChange([...selectedTools, toolId])
      }
    },
    [selectedTools, onSelectionChange]
  )

  const selectAll = () => {
    onSelectionChange(tools.map((t) => t.tool_id))
  }

  const selectRecommended = () => {
    const recommended = [
      "scope_check", "subfinder", "nmap_discovery", "httpx_probe",
      "ffuf", "nuclei", "nikto", "sqlmap", "dalfox",
      "ai_triage", "report_gen",
    ]
    onSelectionChange(recommended.filter((r) => tools.some((t) => t.tool_id === r)))
  }

  const selectNone = () => {
    onSelectionChange([])
  }

  const loadSubcommands = async (toolId: string) => {
    if (expandedTool === toolId) {
      setExpandedTool(null)
      return
    }

    // Fetch subcommands if not already loaded
    const tool = tools.find((t) => t.tool_id === toolId)
    if (tool && !tool.subcommands) {
      try {
        const res = await fetch(`/api/v1/tools/${toolId}`)
        if (res.ok) {
          const data = await res.json()
          setTools((prev) =>
            prev.map((t) =>
              t.tool_id === toolId
                ? { ...t, subcommands: data.subcommands, subcommand_count: data.subcommand_count }
                : t
            )
          )
        }
      } catch {
        console.warn("Could not fetch tool details")
      }
    }

    setExpandedTool(toolId)
  }

  // Group tools by category
  const toolsByCategory = tools.reduce<Record<string, Tool[]>>((acc, tool) => {
    const cat = tool.category
    acc[cat] = acc[cat] || []
    acc[cat].push(tool)
    return acc
  }, {})

  const categoryOrder = [
    "scope_validation", "recon", "enum", "vuln_scan",
    "verification", "ai_analysis", "report_gen",
  ]

  const filteredQuery = searchQuery.trim().toLowerCase()

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        <span className="ml-3 text-sm">Loading tool catalog...</span>
      </div>
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Header with search and presets */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search tools, attack vectors..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-border bg-background pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/20 transition-all"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={selectRecommended}
            className="flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Recommended
          </button>
          <button
            onClick={selectAll}
            className="rounded-lg border border-border px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-elevated transition-colors"
          >
            All
          </button>
          <button
            onClick={selectNone}
            className="rounded-lg border border-border px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-elevated transition-colors"
          >
            None
          </button>
        </div>
      </div>

      {/* Selection count */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          <span className="text-primary font-semibold">{selectedTools.length}</span> of{" "}
          {tools.length} tools selected
        </span>
        <span className="flex items-center gap-1">
          <Zap className="h-3 w-3" />
          {tools
            .filter((t) => selectedTools.includes(t.tool_id))
            .reduce((acc, t) => acc + t.attack_vectors.length, 0)}{" "}
          attack vectors covered
        </span>
      </div>

      {/* Tool list by category */}
      <div className="space-y-3">
        {categoryOrder.map((cat) => {
          const catTools = toolsByCategory[cat]
          if (!catTools) return null

          const config = categoryConfig[cat] || {
            label: cat,
            icon: Info,
            color: "text-zinc-400",
          }
          const CatIcon = config.icon

          const filtered = filteredQuery
            ? catTools.filter(
                (t) =>
                  t.name.toLowerCase().includes(filteredQuery) ||
                  t.description.toLowerCase().includes(filteredQuery) ||
                  t.attack_vectors.some((v) => v.toLowerCase().includes(filteredQuery))
              )
            : catTools

          if (filtered.length === 0) return null

          return (
            <div
              key={cat}
              className="rounded-lg border border-border/50 bg-card/50 overflow-hidden"
            >
              {/* Category header */}
              <div className="flex items-center gap-2 border-b border-border/30 px-4 py-2.5 bg-card/80">
                <CatIcon className={cn("h-4 w-4", config.color)} />
                <span className="text-sm font-medium text-foreground">
                  {config.label}
                </span>
                <span className="text-xs text-muted-foreground">
                  ({filtered.length} tool{filtered.length > 1 ? "s" : ""})
                </span>
              </div>

              {/* Tools in category */}
              <div className="divide-y divide-border/20">
                {filtered.map((tool) => {
                  const isSelected = selectedTools.includes(tool.tool_id)
                  const isExpanded = expandedTool === tool.tool_id

                  return (
                    <div key={tool.tool_id}>
                      {/* Tool row */}
                      <div
                        className={cn(
                          "flex items-center gap-3 px-4 py-3 transition-colors cursor-pointer",
                          isSelected
                            ? "bg-primary/5 hover:bg-primary/10"
                            : "hover:bg-elevated/50"
                        )}
                        onClick={() => toggleTool(tool.tool_id)}
                      >
                        {/* Drag handle */}
                        <GripVertical className="h-3.5 w-3.5 text-muted-foreground/30 shrink-0 cursor-grab" />

                        {/* Toggle */}
                        <button
                          className="shrink-0"
                          onClick={(e) => {
                            e.stopPropagation()
                            toggleTool(tool.tool_id)
                          }}
                        >
                          {isSelected ? (
                            <ToggleRight className="h-5 w-5 text-primary" />
                          ) : (
                            <ToggleLeft className="h-5 w-5 text-muted-foreground/50" />
                          )}
                        </button>

                        {/* Tool info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-foreground">
                              {tool.name}
                            </span>
                            <span className="rounded bg-muted/50 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                              {tool.tool_id}
                            </span>
                            {tool.phase_count > 1 && (
                              <span className="text-[10px] text-muted-foreground">
                                {tool.phase_count} phases
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs text-muted-foreground truncate">
                            {tool.description}
                          </p>
                        </div>

                        {/* Attack vector count */}
                        <span className="shrink-0 rounded-full bg-muted/30 px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                          {tool.attack_vectors.length} vectors
                        </span>

                        {/* Expand for subcommands */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            loadSubcommands(tool.tool_id)
                          }}
                          className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-elevated hover:text-foreground transition-colors shrink-0"
                          title="Show subcommands"
                        >
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </div>

                      {/* Expanded subcommands */}
                      {isExpanded && tool.subcommands && (
                        <div className="border-t border-border/20 bg-background/50 px-4 py-3">
                          <div className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Subcommands & Flags
                          </div>
                          <div className="space-y-1.5">
                            {tool.subcommands.map((sc, idx) => (
                              <div
                                key={idx}
                                className="flex items-start gap-3 rounded-lg px-3 py-2 hover:bg-elevated/30 transition-colors"
                              >
                                <code className="shrink-0 rounded bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary">
                                  {sc.flag}
                                </code>
                                <div className="flex-1 min-w-0">
                                  <span className="text-xs text-foreground/80">
                                    {sc.description}
                                  </span>
                                  {sc.default !== undefined && sc.default !== true && sc.default !== false && (
                                    <span className="ml-2 text-[10px] text-muted-foreground">
                                      default: {String(sc.default)}
                                    </span>
                                  )}
                                </div>
                                {sc.required && (
                                  <span className="shrink-0 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-400">
                                    required
                                  </span>
                                )}
                                {sc.category && (
                                  <span className="shrink-0 rounded bg-muted/30 px-1.5 py-0.5 text-[10px] text-muted-foreground">
                                    {sc.category}
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>

                          {/* Phases */}
                          <div className="mt-4 mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Execution Phases
                          </div>
                          <div className="space-y-1">
                            {tool.phases.map((phase, idx) => (
                              <div
                                key={idx}
                                className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs"
                              >
                                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/10 text-[10px] font-bold text-primary">
                                  {idx + 1}
                                </span>
                                <span className="font-medium text-foreground/80">
                                  {phase.name}
                                </span>
                                <span className="text-muted-foreground">—</span>
                                <span className="text-muted-foreground">
                                  {phase.description}
                                </span>
                                {phase.conditional && (
                                  <span className="ml-auto rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400">
                                    conditional
                                  </span>
                                )}
                                <span className="text-[10px] text-muted-foreground">
                                  {phase.timeout_seconds}s
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
