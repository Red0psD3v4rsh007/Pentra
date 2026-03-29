"use client"

import { motion } from "framer-motion"
import { Bot, Crosshair, Sparkles, Wrench } from "lucide-react"
import { cn } from "@/lib/utils"

export type ScanMode = "autonomous" | "manual"

interface ModeSelectorProps {
  selected: ScanMode | null
  onSelect: (mode: ScanMode) => void
}

const modes = [
  {
    id: "autonomous" as ScanMode,
    title: "Autonomous",
    subtitle: "AI-Driven Pipeline",
    description: "Pentra automatically selects tools, techniques, and tactics based on the target profile. Best for standard assessments.",
    icon: Bot,
    accentColor: "#00ff9f",
    features: [
      "Pre-configured attack profiles",
      "AI selects optimal tools per target",
      "Automatic phase transitions",
      "Full report generation",
    ],
  },
  {
    id: "manual" as ScanMode,
    title: "Manual",
    subtitle: "Full Operator Control",
    description: "Choose your testing methodology, select individual tools, define scope boundaries, and control each phase of the kill chain.",
    icon: Wrench,
    accentColor: "#00cfff",
    features: [
      "Black / Grey / White box modes",
      "Custom tool selection & configuration",
      "Phase-gate approval at each step",
      "Live terminal access during exploit",
    ],
  },
]

export function ModeSelector({ selected, onSelect }: ModeSelectorProps) {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
          Select Operation Mode
        </h2>
        <p className="mt-1 text-sm text-muted-foreground font-mono">
          How do you want to run this engagement?
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 max-w-3xl mx-auto">
        {modes.map((mode) => {
          const isSelected = selected === mode.id
          const Icon = mode.icon
          return (
            <motion.button
              key={mode.id}
              type="button"
              onClick={() => onSelect(mode.id)}
              whileHover={{ y: -2 }}
              whileTap={{ scale: 0.99 }}
              className={cn(
                "group relative overflow-hidden rounded border text-left p-5 transition-all duration-200",
                isSelected
                  ? "border-transparent bg-surface-1"
                  : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)] hover:bg-surface-1/50"
              )}
            >
              {/* Animated border when selected */}
              {isSelected && (
                <div
                  className="absolute -inset-px rounded z-0"
                  style={{
                    background: `conic-gradient(from var(--border-angle, 0deg), ${mode.accentColor}, ${mode.accentColor}33, ${mode.accentColor})`,
                    animation: "border-rotate 3s linear infinite",
                    padding: "1px",
                    mask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
                    maskComposite: "exclude",
                    WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
                    WebkitMaskComposite: "xor",
                  }}
                />
              )}

              {/* Top accent line */}
              <div
                className={cn(
                  "absolute top-0 left-0 right-0 h-[1px] transition-opacity duration-200",
                  isSelected ? "opacity-100" : "opacity-40 group-hover:opacity-70"
                )}
                style={{
                  background: `linear-gradient(90deg, transparent, ${mode.accentColor}, transparent)`,
                }}
              />

              {/* Inner glow */}
              {isSelected && (
                <div
                  className="absolute top-0 left-0 right-0 h-32 opacity-100 transition-opacity"
                  style={{
                    background: `linear-gradient(to bottom, ${mode.accentColor}08, transparent)`,
                  }}
                />
              )}

              <div className="relative z-10">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="flex h-10 w-10 items-center justify-center rounded transition-shadow"
                      style={{
                        background: `${mode.accentColor}12`,
                        boxShadow: isSelected ? `0 0 16px ${mode.accentColor}20` : "none",
                      }}
                    >
                      <Icon
                        className="h-5 w-5 transition-all"
                        style={{ color: mode.accentColor }}
                      />
                    </div>
                    <div>
                      <h3 className="text-base font-semibold text-foreground font-heading">
                        {mode.title}
                      </h3>
                      <p className="text-[10px] uppercase tracking-[0.2em] font-mono" style={{ color: mode.accentColor }}>
                        {mode.subtitle}
                      </p>
                    </div>
                  </div>

                  {/* Selection indicator */}
                  <div
                    className={cn(
                      "flex h-5 w-5 items-center justify-center rounded-full border-2 transition-all",
                      isSelected ? "border-transparent" : "border-[#333]"
                    )}
                    style={isSelected ? { background: mode.accentColor, boxShadow: `0 0 8px ${mode.accentColor}60` } : {}}
                  >
                    {isSelected && (
                      <Sparkles className="h-3 w-3 text-[#050505]" />
                    )}
                  </div>
                </div>

                {/* Description */}
                <p className="text-xs text-muted-foreground leading-relaxed mb-4">
                  {mode.description}
                </p>

                {/* Features */}
                <div className="space-y-1.5">
                  {mode.features.map((feature) => (
                    <div key={feature} className="flex items-center gap-2 text-[11px]">
                      <Crosshair
                        className="h-3 w-3 shrink-0"
                        style={{ color: isSelected ? mode.accentColor : "#555" }}
                      />
                      <span className={cn("font-mono", isSelected ? "text-foreground" : "text-muted-foreground")}>
                        {feature}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}
