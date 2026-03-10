import React from "react"
import { cn } from "@/lib/utils"

interface ProgressRingProps {
    progress: number // 0 to 100
    size?: number
    strokeWidth?: number
    color?: string
    className?: string
    trackColor?: string
}

export function ProgressRing({
    progress,
    size = 60,
    strokeWidth = 4,
    color = "currentColor",
    trackColor = "var(--color-pentra-border)",
    className
}: ProgressRingProps) {
    const radius = (size - strokeWidth) / 2
    const circumference = radius * 2 * Math.PI
    const offset = circumference - (progress / 100) * circumference

    return (
        <div className={cn("relative inline-flex items-center justify-center", className)} style={{ width: size, height: size }}>
            <svg width={size} height={size} className="transform -rotate-90">
                {/* Track */}
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke={trackColor}
                    strokeWidth={strokeWidth}
                    fill="transparent"
                />
                {/* Progress */}
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke={color}
                    strokeWidth={strokeWidth}
                    fill="transparent"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    className="transition-all duration-500 ease-in-out"
                />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xs font-mono font-bold text-pentra-text">{Math.round(progress)}%</span>
            </div>
        </div>
    )
}
