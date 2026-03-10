import * as React from "react"
import { cn } from "@/lib/utils"

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: "default" | "outline" | "ghost" | "glass"
    color?: "primary" | "critical" | "high" | "medium" | "low" | "info" | "exploit" | "recon" | "credential"
}

function Badge({ className, variant = "default", color = "primary", ...props }: BadgeProps) {
    return (
        <div
            className={cn(
                "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-pentra-primary focus:ring-offset-2",
                {
                    "border-transparent": variant === "default" || variant === "glass",
                    "border-pentra-border": variant === "outline",
                    "bg-transparent border-transparent": variant === "ghost",

                    /* Colors for default variant */
                    "bg-pentra-primary text-black": variant === "default" && color === "primary",
                    "bg-pentra-critical text-white": variant === "default" && color === "critical",
                    "bg-pentra-high text-white": variant === "default" && color === "high",
                    "bg-pentra-medium text-black": variant === "default" && color === "medium",
                    "bg-pentra-low text-black": variant === "default" && color === "low",
                    "bg-pentra-info text-black": variant === "default" && color === "info",
                    "bg-pentra-exploit text-white": variant === "default" && color === "exploit",
                    "bg-pentra-recon text-white": variant === "default" && color === "recon",
                    "bg-pentra-credential text-black": variant === "default" && color === "credential",

                    /* Colors for glass variant */
                    "bg-pentra-primary/10 text-pentra-primary border-pentra-primary/20": variant === "glass" && color === "primary",
                    "bg-pentra-critical/10 text-pentra-critical border-pentra-critical/20": variant === "glass" && color === "critical",
                    "bg-pentra-high/10 text-pentra-high border-pentra-high/20": variant === "glass" && color === "high",
                    "bg-pentra-medium/10 text-pentra-medium border-pentra-medium/20": variant === "glass" && color === "medium",
                    "bg-pentra-low/10 text-pentra-low border-pentra-low/20": variant === "glass" && color === "low",
                    "bg-pentra-info/10 text-pentra-info border-pentra-info/20": variant === "glass" && color === "info",
                    "bg-pentra-exploit/10 text-pentra-exploit border-pentra-exploit/20": variant === "glass" && color === "exploit",
                    "bg-pentra-recon/10 text-pentra-recon border-pentra-recon/20": variant === "glass" && color === "recon",
                    "bg-pentra-credential/10 text-pentra-credential border-pentra-credential/20": variant === "glass" && color === "credential",
                },
                className
            )}
            {...props}
        />
    )
}

export { Badge }
