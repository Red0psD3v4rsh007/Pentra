"use client"

import { forwardRef, type ButtonHTMLAttributes } from "react"
import { cn } from "@/lib/utils"

/**
 * Premium button with neon glow effect on hover.
 * Used for primary actions in the command center.
 */
interface GlowButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "danger" | "cyan" | "ghost" | "outline"
  size?: "sm" | "md" | "lg"
}

const variants = {
  primary: cn(
    "bg-[#00ff9f] text-[#050505] font-semibold",
    "hover:bg-[#00cc7f] hover:shadow-[0_0_20px_rgba(0,255,159,0.3),0_0_60px_rgba(0,255,159,0.1)]",
    "active:bg-[#00b36f]",
  ),
  danger: cn(
    "bg-[#ff3b3b] text-white font-semibold",
    "hover:bg-[#cc2f2f] hover:shadow-[0_0_20px_rgba(255,59,59,0.3),0_0_60px_rgba(255,59,59,0.1)]",
    "active:bg-[#b32828]",
  ),
  cyan: cn(
    "bg-[#00cfff] text-[#050505] font-semibold",
    "hover:bg-[#00a3cc] hover:shadow-[0_0_20px_rgba(0,207,255,0.3),0_0_60px_rgba(0,207,255,0.1)]",
    "active:bg-[#0090b3]",
  ),
  ghost: cn(
    "bg-transparent text-[#e5e5e5]",
    "hover:bg-[#111114] hover:text-[#00ff9f]",
    "active:bg-[#1a1a1e]",
  ),
  outline: cn(
    "bg-transparent text-[#e5e5e5] border border-[#1a1a1e]",
    "hover:border-[rgba(0,255,159,0.3)] hover:text-[#00ff9f] hover:shadow-[0_0_12px_rgba(0,255,159,0.08)]",
    "active:bg-[#111114]",
  ),
}

const sizes = {
  sm: "px-2.5 py-1 text-xs gap-1.5",
  md: "px-4 py-2 text-sm gap-2",
  lg: "px-6 py-2.5 text-sm gap-2.5",
}

export const GlowButton = forwardRef<HTMLButtonElement, GlowButtonProps>(
  ({ className, variant = "primary", size = "md", children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center rounded font-heading",
          "transition-all duration-200 ease-out",
          "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#00ff9f]/40",
          "disabled:opacity-50 disabled:pointer-events-none",
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      >
        {children}
      </button>
    )
  }
)

GlowButton.displayName = "GlowButton"
