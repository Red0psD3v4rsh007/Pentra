"use client"

import { useState } from "react"
import { Eye, EyeOff, Loader2, ArrowRight } from "lucide-react"

interface LoginFormProps {
  onSubmit: (email: string, password: string) => Promise<void>
  isLoading?: boolean
  submitLabel?: string
  disabled?: boolean
  helperText?: string | null
}

export function LoginForm({
  onSubmit,
  isLoading = false,
  submitLabel = "Sign in",
  disabled = false,
  helperText = null,
}: LoginFormProps) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [focused, setFocused] = useState<string | null>(null)
  const isFormDisabled = isLoading || disabled

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (isFormDisabled) {
      return
    }
    await onSubmit(email, password)
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-6">
      {/* Email Input */}
      <div className="flex flex-col gap-2">
        <label 
          htmlFor="email" 
          className={`text-xs font-medium transition-colors duration-200 ${
            focused === 'email' ? 'text-primary' : 'text-muted-foreground'
          }`}
        >
          Email address
        </label>
        <div className="relative group">
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onFocus={() => setFocused('email')}
            onBlur={() => setFocused(null)}
            placeholder="you@company.com"
            required
            disabled={isFormDisabled}
            className="h-12 w-full bg-background/50 border border-border/50 rounded-lg px-4 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 focus:bg-background/80 focus:ring-2 focus:ring-primary/10 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
          />
          <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
        </div>
      </div>

      {/* Password Input */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <label 
            htmlFor="password" 
            className={`text-xs font-medium transition-colors duration-200 ${
              focused === 'password' ? 'text-primary' : 'text-muted-foreground'
            }`}
          >
            Password
          </label>
          <button
            type="button"
            className="text-xs text-muted-foreground hover:text-primary transition-colors duration-200"
          >
            Forgot password?
          </button>
        </div>
        <div className="relative group">
          <input
            id="password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onFocus={() => setFocused('password')}
            onBlur={() => setFocused(null)}
            placeholder="Enter your password"
            required
            disabled={isFormDisabled}
            className="h-12 w-full bg-background/50 border border-border/50 rounded-lg px-4 pr-12 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 focus:bg-background/80 focus:ring-2 focus:ring-primary/10 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            disabled={isFormDisabled}
            className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors duration-200 disabled:opacity-50"
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
          <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
        </div>
      </div>

      {/* Submit Button */}
      <button
        type="submit"
        disabled={isFormDisabled}
        className="group relative h-12 w-full mt-2 bg-primary text-primary-foreground font-medium text-sm rounded-lg overflow-hidden transition-all duration-300 hover:shadow-lg hover:shadow-primary/25 disabled:opacity-80 disabled:cursor-not-allowed"
      >
        {/* Shimmer effect on hover */}
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
        
        <span className="relative flex items-center justify-center gap-2">
          {isLoading ? (
            <>
              <Loader2 size={18} className="animate-spin" />
              <span>Authenticating...</span>
            </>
          ) : (
            <>
              <span>{submitLabel}</span>
              <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform duration-200" />
            </>
          )}
        </span>
      </button>

      {helperText ? <p className="text-xs leading-relaxed text-muted-foreground">{helperText}</p> : null}
    </form>
  )
}
