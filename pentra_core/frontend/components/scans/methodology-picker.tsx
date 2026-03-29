"use client"

import { motion } from "framer-motion"
import { Check, Code2, Eye, EyeOff, GitBranch, Lock, Server, Shield } from "lucide-react"
import { cn } from "@/lib/utils"

export type Methodology = "black_box" | "grey_box" | "white_box"

interface MethodologyPickerProps {
  selected: Methodology | null
  onSelect: (method: Methodology) => void
}

const methodologies = [
  {
    id: "black_box" as Methodology,
    title: "Black Box",
    subtitle: "Zero Knowledge",
    description: "External-only attack simulation. No access to source code or internal documentation. Simulates a real-world attacker perspective.",
    icon: EyeOff,
    accentColor: "#ff3b3b",
    inputs: ["Target host", "Auth credentials", "Scope definition"],
    includes: [
      { label: "Active Recon", included: true },
      { label: "Passive OSINT", included: true },
      { label: "Vulnerability Scan", included: true },
      { label: "Exploitation", included: true },
      { label: "Source Code Analysis", included: false },
      { label: "API Spec Review", included: false },
    ],
  },
  {
    id: "grey_box" as Methodology,
    title: "Grey Box",
    subtitle: "Partial Knowledge",
    description: "Combines external testing with partial source code analysis. Clone a repo for static analysis while running dynamic scans.",
    icon: Eye,
    accentColor: "#ffaa00",
    inputs: ["Target host", "Auth credentials", "Scope", "GitHub repo (partial)"],
    includes: [
      { label: "Active Recon", included: true },
      { label: "Passive OSINT", included: true },
      { label: "Vulnerability Scan", included: true },
      { label: "Exploitation", included: true },
      { label: "Source Code Analysis", included: true },
      { label: "API Spec Review", included: false },
    ],
  },
  {
    id: "white_box" as Methodology,
    title: "White Box",
    subtitle: "Full Knowledge",
    description: "Complete access to source code, API specs, and documentation. Combines SAST, DAST, and AI-assisted code review for maximum coverage.",
    icon: Code2,
    accentColor: "#00ff9f",
    inputs: ["Target host", "Auth credentials", "Scope", "GitHub repo (full)", "API specs"],
    includes: [
      { label: "Active Recon", included: true },
      { label: "Passive OSINT", included: true },
      { label: "Vulnerability Scan", included: true },
      { label: "Exploitation", included: true },
      { label: "Source Code Analysis", included: true },
      { label: "API Spec Review", included: true },
    ],
  },
]

export function MethodologyPicker({ selected, onSelect }: MethodologyPickerProps) {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-foreground font-heading tracking-tight">
          Select Testing Methodology
        </h2>
        <p className="mt-1 text-sm text-muted-foreground font-mono">
          How much access do you have to the target?
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3 max-w-4xl mx-auto">
        {methodologies.map((method) => {
          const isSelected = selected === method.id
          const Icon = method.icon
          return (
            <motion.button
              key={method.id}
              type="button"
              onClick={() => onSelect(method.id)}
              whileHover={{ y: -2 }}
              whileTap={{ scale: 0.99 }}
              className={cn(
                "group relative overflow-hidden rounded border text-left transition-all duration-200",
                isSelected
                  ? "border-transparent bg-surface-1"
                  : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)] hover:bg-surface-1/50"
              )}
            >
              {/* Animated border */}
              {isSelected && (
                <div
                  className="absolute -inset-px rounded z-0"
                  style={{
                    background: `conic-gradient(from var(--border-angle, 0deg), ${method.accentColor}, ${method.accentColor}33, ${method.accentColor})`,
                    animation: "border-rotate 3s linear infinite",
                    padding: "1px",
                    mask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
                    maskComposite: "exclude",
                    WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
                    WebkitMaskComposite: "xor",
                  }}
                />
              )}

              {/* Top accent */}
              <div
                className={cn(
                  "absolute top-0 left-0 right-0 h-[1px] transition-opacity",
                  isSelected ? "opacity-100" : "opacity-30 group-hover:opacity-60"
                )}
                style={{
                  background: `linear-gradient(90deg, transparent, ${method.accentColor}, transparent)`,
                }}
              />

              <div className="relative z-10 p-4">
                {/* Header */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2.5">
                    <div
                      className="flex h-8 w-8 items-center justify-center rounded"
                      style={{ background: `${method.accentColor}12` }}
                    >
                      <Icon className="h-4 w-4" style={{ color: method.accentColor }} />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-foreground font-heading">
                        {method.title}
                      </h3>
                      <p className="text-[9px] uppercase tracking-[0.2em] font-mono" style={{ color: method.accentColor }}>
                        {method.subtitle}
                      </p>
                    </div>
                  </div>
                  <div
                    className={cn(
                      "flex h-4 w-4 items-center justify-center rounded-full border transition-all",
                      isSelected ? "border-transparent" : "border-[#333]"
                    )}
                    style={isSelected ? { background: method.accentColor } : {}}
                  >
                    {isSelected && <Check className="h-2.5 w-2.5 text-[#050505]" />}
                  </div>
                </div>

                <p className="text-[11px] text-muted-foreground leading-relaxed mb-4">
                  {method.description}
                </p>

                {/* Coverage checklist */}
                <div className="space-y-1.5 border-t border-border-subtle pt-3">
                  <p className="text-[9px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-2">
                    Coverage
                  </p>
                  {method.includes.map((item) => (
                    <div key={item.label} className="flex items-center gap-2 text-[10px]">
                      <div
                        className={cn(
                          "flex h-3.5 w-3.5 items-center justify-center rounded-sm",
                          item.included ? "bg-[rgba(0,255,159,0.1)]" : "bg-surface-2"
                        )}
                      >
                        {item.included ? (
                          <Check className="h-2.5 w-2.5 text-[#00ff9f]" />
                        ) : (
                          <Lock className="h-2 w-2 text-[#555]" />
                        )}
                      </div>
                      <span className={cn(
                        "font-mono",
                        item.included ? "text-foreground" : "text-[#555]"
                      )}>
                        {item.label}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Required inputs */}
                <div className="mt-3 border-t border-border-subtle pt-3">
                  <p className="text-[9px] uppercase tracking-[0.2em] text-muted-foreground font-heading mb-2">
                    Required Inputs
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {method.inputs.map((input) => (
                      <span
                        key={input}
                        className="rounded border border-border-subtle bg-surface-0 px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground"
                      >
                        {input}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}
