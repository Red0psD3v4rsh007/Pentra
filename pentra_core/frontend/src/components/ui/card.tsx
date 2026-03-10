import * as React from "react"
import { cn } from "@/lib/utils"

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement> & { glowOnHover?: boolean, glass?: boolean, active?: boolean }>(
    ({ className, glowOnHover, glass, active, ...props }, ref) => (
        <div
            ref={ref}
            className={cn(
                "border text-pentra-text shadow-sm transition-all duration-300 relative",
                "rounded-none", // Angular tactical corners
                glass ? "glass-panel" : "bg-pentra-surface border-pentra-border",
                active && "border-t-2 border-t-pentra-primary border-x-pentra-border border-b-pentra-border",
                glowOnHover && "hover:border-pentra-primary hover:shadow-[0_0_15px_rgba(255,0,60,0.15)]",
                className
            )}
            {...props}
        />
    )
)
Card.displayName = "Card"

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <div
            ref={ref}
            className={cn("flex flex-col space-y-1.5 p-4 border-b border-pentra-border/50 bg-pentra-panel/50", className)}
            {...props}
        />
    )
)
CardHeader.displayName = "CardHeader"

const CardTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(
    ({ className, ...props }, ref) => (
        <h3
            ref={ref}
            className={cn("text-sm font-semibold leading-none tracking-widest font-sans uppercase text-pentra-text-muted", className)}
            {...props}
        />
    )
)
CardTitle.displayName = "CardTitle"

const CardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
    ({ className, ...props }, ref) => (
        <p
            ref={ref}
            className={cn("text-xs font-mono text-pentra-text-dim", className)}
            {...props}
        />
    )
)
CardDescription.displayName = "CardDescription"

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <div ref={ref} className={cn("p-4", className)} {...props} />
    )
)
CardContent.displayName = "CardContent"

const CardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => (
        <div
            ref={ref}
            className={cn("flex items-center p-4 pt-0", className)}
            {...props}
        />
    )
)
CardFooter.displayName = "CardFooter"

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent }
