"use client"

interface ReasoningStep {
  step: number
  text: string
}

const reasoningSteps: ReasoningStep[] = [
  { step: 1, text: "Detected SQL injection on /api/auth endpoint" },
  { step: 2, text: "WAF bypass successful via double URL encoding" },
  { step: 3, text: "Extracted JWT token with admin privileges" },
  { step: 4, text: "Pivoting to internal metadata service" },
  { step: 5, text: "Lateral movement to database server initiated" },
]

export function AIReasoning() {
  const confidence = 94

  return (
    <div className="flex h-full flex-col rounded-[2px] border border-border bg-[#0f0f0f]">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold tracking-wide text-foreground">
          AI REASONING
        </span>
        <span className="text-[10px] font-mono text-accent">
          CHAIN: {reasoningSteps.length} steps
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3">
        <div className="flex flex-col gap-2">
          {reasoningSteps.map((step) => (
            <div key={step.step} className="flex gap-2">
              <span className="shrink-0 flex h-4 w-4 items-center justify-center rounded-full bg-accent/20 text-[10px] font-bold text-accent">
                {step.step}
              </span>
              <span className="text-[11px] text-foreground leading-relaxed">
                {step.text}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t border-border p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] text-muted-foreground">CONFIDENCE</span>
          <span className="font-mono text-sm font-bold text-accent">{confidence}%</span>
        </div>
        <div className="h-1.5 w-full rounded-full bg-border overflow-hidden mb-3">
          <div
            className="h-full bg-accent transition-all"
            style={{ width: `${confidence}%` }}
          />
        </div>

        <div className="rounded-[2px] border border-primary/50 bg-primary/10 px-2 py-1.5">
          <span className="text-[10px] text-muted-foreground">DECISION:</span>
          <span className="ml-1 text-[11px] font-semibold text-primary">
            ESCALATE TO LATERAL MOVEMENT
          </span>
        </div>
      </div>
    </div>
  )
}
