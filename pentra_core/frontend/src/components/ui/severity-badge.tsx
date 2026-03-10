import React from "react"
import { Badge } from "./badge"
import { cn } from "@/lib/utils"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

interface SeverityBadgeProps extends React.HTMLAttributes<HTMLDivElement> {
    severity: Severity
    variant?: "default" | "glass"
}

export function SeverityBadge({ severity, className, variant = "glass", ...props }: SeverityBadgeProps) {
    return (
        <Badge color={severity} variant={variant} className={cn("uppercase tracking-widest font-mono text-[10px] rounded-none py-1 px-2", className)} {...props}>
            <span className={cn("mr-2 h-1.5 w-1.5 rounded-none inline-block animate-pulse", {
                "bg-pentra-critical": severity === "critical" && variant === "glass",
                "bg-black": severity === "critical" && variant === "default",
                "bg-pentra-high": severity === "high" && variant === "glass",
                "bg-black": severity === "high" && variant === "default",
                "bg-pentra-medium": severity === "medium" && variant === "glass",
                "bg-black": severity === "medium" && variant === "default",
                "bg-pentra-low": severity === "low" && variant === "glass",
                "bg-black": severity === "low" && variant === "default",
                "bg-pentra-info": severity === "info" && variant === "glass",
                "bg-black": severity === "info" && variant === "default",
            })} />
            {severity}
        </Badge>
    )
}
