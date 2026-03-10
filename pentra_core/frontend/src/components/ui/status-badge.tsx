import React from "react"
import { Badge } from "./badge"
import { cn } from "@/lib/utils"

export type Status = "queued" | "running" | "completed" | "failed"

interface StatusBadgeProps extends React.HTMLAttributes<HTMLDivElement> {
    status: Status
    pulse?: boolean
}

export function StatusBadge({ status, className, pulse = false, ...props }: StatusBadgeProps) {
    let color: any = "info"
    if (status === "queued") color = "info"
    if (status === "running") color = "primary"
    if (status === "completed") color = "low"
    if (status === "failed") color = "critical"

    return (
        <Badge color={color} variant="glass" className={cn("uppercase tracking-wider font-mono text-[10px]", className)} {...props}>
            {status === "running" && (
                <svg className="animate-spin -ml-1 mr-2 h-3 w-3 text-pentra-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            )}
            {status !== "running" && pulse && (
                <span className={cn("mr-1.5 h-1.5 w-1.5 rounded-full inline-block animate-pulse", `bg-pentra-${color}`)} />
            )}
            {status}
        </Badge>
    )
}
