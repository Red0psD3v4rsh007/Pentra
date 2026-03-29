"use client"

import { cn } from "@/lib/utils"
import { Sparkles, Settings2, Zap, Shield, Terminal, Eye } from "lucide-react"

type ScanMode = "customizable" | "autonomous"

interface ScanModeSelectorProps {
  selectedMode: ScanMode
  onModeChange: (mode: ScanMode) => void
  className?: string
}

const modes = [
  {
    id: "autonomous" as const,
    label: "Autonomous",
    icon: Zap,
    color: "from-purple-500 to-blue-500",
    borderColor: "border-purple-500/40",
    bgColor: "bg-purple-500/5",
    features: [
      { icon: Sparkles, text: "AI selects optimal tools automatically" },
      { icon: Shield, text: "Full pipeline: recon → exploit → report" },
      { icon: Eye, text: "Summary progress & findings" },
    ],
    description: "AI drives the entire assessment end-to-end with no manual decisions needed.",
  },
  {
    id: "customizable" as const,
    label: "Customizable",
    icon: Settings2,
    color: "from-emerald-500 to-cyan-500",
    borderColor: "border-emerald-500/40",
    bgColor: "bg-emerald-500/5",
    features: [
      { icon: Settings2, text: "Pick tools & subcommands yourself" },
      { icon: Terminal, text: "Interactive terminal with real shell access" },
      { icon: Sparkles, text: "AI suggests next tools, you approve" },
    ],
    description: "Full control over every tool, command, and execution step.",
  },
]

export function ScanModeSelector({
  selectedMode,
  onModeChange,
  className,
}: ScanModeSelectorProps) {
  return (
    <div className={cn("grid grid-cols-2 gap-4", className)}>
      {modes.map((mode) => {
        const isSelected = selectedMode === mode.id
        const ModeIcon = mode.icon

        return (
          <button
            key={mode.id}
            type="button"
            onClick={() => onModeChange(mode.id)}
            className={cn(
              "group relative rounded-xl border-2 p-5 text-left transition-all duration-200",
              isSelected
                ? cn(mode.borderColor, mode.bgColor, "shadow-lg")
                : "border-border/50 bg-card hover:border-border hover:bg-elevated/50"
            )}
          >
            {/* Selected indicator */}
            {isSelected && (
              <div
                className={cn(
                  "absolute -top-px -right-px rounded-bl-lg rounded-tr-xl bg-gradient-to-r px-3 py-1 text-[10px] font-bold text-white",
                  mode.color
                )}
              >
                SELECTED
              </div>
            )}

            {/* Header */}
            <div className="flex items-center gap-3 mb-3">
              <div
                className={cn(
                  "flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br",
                  mode.color
                )}
              >
                <ModeIcon className="h-5 w-5 text-white" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-foreground">
                  {mode.label}
                </h3>
              </div>
            </div>

            {/* Description */}
            <p className="text-xs text-muted-foreground leading-relaxed mb-4">
              {mode.description}
            </p>

            {/* Features */}
            <div className="space-y-2">
              {mode.features.map((feature, idx) => {
                const FIcon = feature.icon
                return (
                  <div key={idx} className="flex items-center gap-2">
                    <FIcon
                      className={cn(
                        "h-3.5 w-3.5 shrink-0",
                        isSelected ? "text-foreground/80" : "text-muted-foreground"
                      )}
                    />
                    <span
                      className={cn(
                        "text-xs",
                        isSelected ? "text-foreground/80" : "text-muted-foreground"
                      )}
                    >
                      {feature.text}
                    </span>
                  </div>
                )
              })}
            </div>
          </button>
        )
      })}
    </div>
  )
}
