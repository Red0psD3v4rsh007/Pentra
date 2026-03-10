import * as React from "react"
import { cn } from "@/lib/utils"

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: "default" | "destructive" | "outline" | "ghost" | "glass"
    size?: "default" | "sm" | "lg" | "icon"
    glow?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
    ({ className, variant = "default", size = "default", glow = false, ...props }, ref) => {
        return (
            <button
                ref={ref}
                className={cn(
                    "inline-flex items-center justify-center whitespace-nowrap rounded-none text-xs font-mono font-medium tracking-wider uppercase ring-offset-pentra-black transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-pentra-primary focus-visible:ring-offset-1 disabled:pointer-events-none disabled:opacity-50",
                    {
                        "bg-pentra-primary text-black hover:bg-pentra-secondary box-glow": variant === "default",
                        "bg-pentra-critical text-white hover:bg-red-600": variant === "destructive",
                        "border border-pentra-border bg-transparent hover:bg-pentra-surface hover:border-pentra-primary text-pentra-text": variant === "outline",
                        "hover:bg-pentra-surface hover:text-pentra-primary text-pentra-text": variant === "ghost",
                        "glass-panel text-pentra-text hover:border-pentra-primary": variant === "glass",
                        "h-8 px-4 py-2": size === "default",
                        "h-6 px-3 text-[10px]": size === "sm",
                        "h-10 px-8 text-sm": size === "lg",
                        "h-8 w-8": size === "icon",
                        "box-glow-hover": glow && variant !== "ghost",
                    },
                    className
                )}
                {...props}
            />
        )
    }
)
Button.displayName = "Button"

export { Button }
