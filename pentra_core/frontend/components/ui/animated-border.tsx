"use client"

import { type ReactNode } from "react"
import { cn } from "@/lib/utils"

/**
 * Animated gradient border wrapper using CSS conic-gradient.
 * Creates a rotating neon border effect around any content.
 */
interface AnimatedBorderProps {
  children: ReactNode
  className?: string
  containerClassName?: string
  duration?: string
  colors?: string[]
  borderWidth?: number
  active?: boolean
}

export function AnimatedBorder({
  children,
  className,
  containerClassName,
  duration = "3s",
  colors = ["#00ff9f", "#00cfff", "#00ff9f"],
  borderWidth = 1,
  active = true,
}: AnimatedBorderProps) {
  return (
    <div className={cn("relative rounded", containerClassName)}>
      {active && (
        <div
          className="absolute -inset-px rounded z-0"
          style={{
            background: `conic-gradient(from var(--border-angle, 0deg), ${colors.join(", ")})`,
            animation: `border-rotate ${duration} linear infinite`,
            opacity: 0.6,
            padding: `${borderWidth}px`,
            mask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
            maskComposite: "exclude",
            WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
            WebkitMaskComposite: "xor",
          }}
        />
      )}
      <div className={cn("relative z-10 rounded bg-surface-1", className)}>
        {children}
      </div>
    </div>
  )
}
