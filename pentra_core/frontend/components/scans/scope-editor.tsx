"use client"

import { useState } from "react"
import { Globe, Minus, Plus, Shield, X } from "lucide-react"
import { cn } from "@/lib/utils"

export type AttackDepth = "recon_only" | "recon_enum" | "full_exploit" | "full_post_exploit"

export interface ScopeConfig {
  inScope: string[]
  outScope: string[]
  attackDepth: AttackDepth
  rateLimit: number // requests per minute
  maxDuration: number // minutes
}

interface ScopeEditorProps {
  scope: ScopeConfig
  onChange: (scope: ScopeConfig) => void
}

const depthLevels: { id: AttackDepth; label: string; description: string; color: string }[] = [
  { id: "recon_only", label: "Recon Only", description: "Reconnaissance and OSINT only. No active exploitation.", color: "#00cfff" },
  { id: "recon_enum", label: "Recon + Enum", description: "Add directory brute-forcing, parameter fuzzing, vuln scanning.", color: "#ffaa00" },
  { id: "full_exploit", label: "Full Exploit", description: "Include exploitation attempts. SQLi, RCE, file upload bypass.", color: "#ff6b35" },
  { id: "full_post_exploit", label: "Full + Post-Exploit", description: "Privilege escalation, lateral movement, persistence checks.", color: "#ff3b3b" },
]

export const defaultScope: ScopeConfig = {
  inScope: [],
  outScope: [],
  attackDepth: "full_exploit",
  rateLimit: 120,
  maxDuration: 60,
}

export function ScopeEditor({ scope, onChange }: ScopeEditorProps) {
  const [inScopeInput, setInScopeInput] = useState("")
  const [outScopeInput, setOutScopeInput] = useState("")

  function addInScope() {
    const val = inScopeInput.trim()
    if (val && !scope.inScope.includes(val)) {
      onChange({ ...scope, inScope: [...scope.inScope, val] })
      setInScopeInput("")
    }
  }

  function removeInScope(item: string) {
    onChange({ ...scope, inScope: scope.inScope.filter((i) => i !== item) })
  }

  function addOutScope() {
    const val = outScopeInput.trim()
    if (val && !scope.outScope.includes(val)) {
      onChange({ ...scope, outScope: [...scope.outScope, val] })
      setOutScopeInput("")
    }
  }

  function removeOutScope(item: string) {
    onChange({ ...scope, outScope: scope.outScope.filter((i) => i !== item) })
  }

  return (
    <div className="space-y-5">
      {/* In-Scope */}
      <div className="rounded border border-border-subtle bg-surface-0 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Globe className="h-3.5 w-3.5 text-[#00ff9f]" />
          <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em]">
            In-Scope Targets
          </h4>
        </div>
        <p className="text-[10px] text-muted-foreground font-mono mb-3">
          Domains, IPs, or CIDR ranges to include. Wildcards supported (*.example.com)
        </p>

        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={inScopeInput}
            onChange={(e) => setInScopeInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addInScope())}
            placeholder="example.com, 10.0.0.0/24, *.api.example.com"
            className="flex-1 rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,255,159,0.3)] focus:outline-none"
          />
          <button
            type="button"
            onClick={addInScope}
            className="rounded border border-[#00ff9f]/30 bg-[#00ff9f]/8 px-2.5 py-1.5 text-[10px] font-semibold text-[#00ff9f] hover:bg-[#00ff9f]/15 transition-colors"
          >
            <Plus className="h-3 w-3" />
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {scope.inScope.map((item) => (
            <span
              key={item}
              className="inline-flex items-center gap-1.5 rounded border border-[#00ff9f]/20 bg-[#00ff9f]/6 px-2 py-0.5 text-[10px] font-mono text-[#00ff9f]"
            >
              {item}
              <button type="button" onClick={() => removeInScope(item)} className="hover:text-white">
                <X className="h-2.5 w-2.5" />
              </button>
            </span>
          ))}
          {scope.inScope.length === 0 && (
            <span className="text-[10px] text-[#555] font-mono italic">
              Auto-populated from target asset
            </span>
          )}
        </div>
      </div>

      {/* Out-of-Scope */}
      <div className="rounded border border-border-subtle bg-surface-0 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="h-3.5 w-3.5 text-[#ff3b3b]" />
          <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em]">
            Exclusions (Out-of-Scope)
          </h4>
        </div>
        <p className="text-[10px] text-muted-foreground font-mono mb-3">
          Targets that must NOT be touched. These are enforced at the tool execution layer.
        </p>

        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={outScopeInput}
            onChange={(e) => setOutScopeInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addOutScope())}
            placeholder="production.example.com, 10.0.1.0/24"
            className="flex-1 rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(255,59,59,0.3)] focus:outline-none"
          />
          <button
            type="button"
            onClick={addOutScope}
            className="rounded border border-[#ff3b3b]/30 bg-[#ff3b3b]/8 px-2.5 py-1.5 text-[10px] font-semibold text-[#ff3b3b] hover:bg-[#ff3b3b]/15 transition-colors"
          >
            <Plus className="h-3 w-3" />
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {scope.outScope.map((item) => (
            <span
              key={item}
              className="inline-flex items-center gap-1.5 rounded border border-[#ff3b3b]/20 bg-[#ff3b3b]/6 px-2 py-0.5 text-[10px] font-mono text-[#ff3b3b]"
            >
              {item}
              <button type="button" onClick={() => removeOutScope(item)} className="hover:text-white">
                <X className="h-2.5 w-2.5" />
              </button>
            </span>
          ))}
        </div>
      </div>

      {/* Attack Depth */}
      <div className="rounded border border-border-subtle bg-surface-0 p-4">
        <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em] mb-3">
          Attack Depth
        </h4>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {depthLevels.map((level) => {
            const isActive = scope.attackDepth === level.id
            return (
              <button
                key={level.id}
                type="button"
                onClick={() => onChange({ ...scope, attackDepth: level.id })}
                className={cn(
                  "relative overflow-hidden rounded border p-3 text-left transition-all duration-200",
                  isActive
                    ? "border-transparent bg-surface-1"
                    : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)]"
                )}
              >
                {isActive && (
                  <div
                    className="absolute top-0 left-0 right-0 h-[1px]"
                    style={{ background: `linear-gradient(90deg, transparent, ${level.color}, transparent)` }}
                  />
                )}
                <div className="flex items-center gap-2 mb-1">
                  <div
                    className="h-2 w-2 rounded-full"
                    style={{ background: level.color, boxShadow: isActive ? `0 0 8px ${level.color}60` : "none" }}
                  />
                  <span className={cn("text-xs font-semibold font-heading", isActive ? "text-foreground" : "text-muted-foreground")}>
                    {level.label}
                  </span>
                </div>
                <p className="text-[10px] text-muted-foreground font-mono leading-relaxed">
                  {level.description}
                </p>
              </button>
            )
          })}
        </div>
      </div>

      {/* Rate Limit + Duration */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded border border-border-subtle bg-surface-0 p-4">
          <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em] mb-2">
            Rate Limit
          </h4>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => onChange({ ...scope, rateLimit: Math.max(10, scope.rateLimit - 10) })}
              className="rounded border border-border-subtle bg-surface-1 p-1 hover:bg-surface-2 transition-colors"
            >
              <Minus className="h-3 w-3 text-muted-foreground" />
            </button>
            <div className="text-center">
              <span className="text-lg font-bold tabular-nums text-foreground font-mono">{scope.rateLimit}</span>
              <p className="text-[9px] text-muted-foreground font-mono">req/min</p>
            </div>
            <button
              type="button"
              onClick={() => onChange({ ...scope, rateLimit: Math.min(1000, scope.rateLimit + 10) })}
              className="rounded border border-border-subtle bg-surface-1 p-1 hover:bg-surface-2 transition-colors"
            >
              <Plus className="h-3 w-3 text-muted-foreground" />
            </button>
          </div>
        </div>

        <div className="rounded border border-border-subtle bg-surface-0 p-4">
          <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em] mb-2">
            Max Duration
          </h4>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => onChange({ ...scope, maxDuration: Math.max(5, scope.maxDuration - 5) })}
              className="rounded border border-border-subtle bg-surface-1 p-1 hover:bg-surface-2 transition-colors"
            >
              <Minus className="h-3 w-3 text-muted-foreground" />
            </button>
            <div className="text-center">
              <span className="text-lg font-bold tabular-nums text-foreground font-mono">{scope.maxDuration}</span>
              <p className="text-[9px] text-muted-foreground font-mono">minutes</p>
            </div>
            <button
              type="button"
              onClick={() => onChange({ ...scope, maxDuration: Math.min(480, scope.maxDuration + 5) })}
              className="rounded border border-border-subtle bg-surface-1 p-1 hover:bg-surface-2 transition-colors"
            >
              <Plus className="h-3 w-3 text-muted-foreground" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
