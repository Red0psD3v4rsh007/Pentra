"use client"

import { useEffect, useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import { LoginForm } from "@/components/login-form"
import { SSOButtons } from "@/components/sso-buttons"
import { CyberGrid } from "@/components/cyber-grid"
import { Spinner } from "@/components/ui/spinner"
import { StatusBadge } from "@/components/ui/status-badge"
import {
  getAuthRuntime,
  getCurrentUser,
  getGoogleLoginUrl,
  isDevAuthBypassEnabled,
  type ApiAuthRuntime,
} from "@/lib/scans-store"
import { Shield, Zap, Lock, ArrowRight } from "lucide-react"

export default function LoginPage() {
  const router = useRouter()
  const [isBootstrapping, setIsBootstrapping] = useState(true)
  const [authRuntime, setAuthRuntime] = useState<ApiAuthRuntime | null>(null)

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
      try {
        const [runtimeResult, userResult] = await Promise.allSettled([
          getAuthRuntime(),
          getCurrentUser(),
        ])

        if (cancelled) {
          return
        }

        if (runtimeResult.status === "fulfilled") {
          setAuthRuntime(runtimeResult.value)
        }

        if (userResult.status === "fulfilled") {
          router.replace("/dashboard")
          return
        }
      } finally {
        if (!cancelled) {
          setIsBootstrapping(false)
        }
      }
    }

    void bootstrap()

    return () => {
      cancelled = true
    }
  }, [router])

  const authGuidance = useMemo(() => {
    if (authRuntime?.dev_auth_bypass_enabled || isDevAuthBypassEnabled()) {
      return {
        title: "Development Auth Bypass Detected",
        description:
          "This local deployment accepts the configured development operator identity. If a session is active, Pentra will route you straight into command.",
        status: "configured_and_healthy",
      }
    }

    if (authRuntime?.google_oauth_configured) {
      return {
        title: "Google OAuth Available",
        description:
          "Use Google to establish a real browser session. Email/password sign-in is not configured in this deployment.",
        status: "configured_and_healthy",
      }
    }

    return {
      title: "Interactive Login Not Configured",
      description:
        "This deployment does not currently expose a browser login method. Enable Google OAuth or development auth bypass before using the web console.",
      status: "configured_but_fallback",
    }
  }, [authRuntime])

  const handleLogin = async (email: string, password: string) => {
    void email
    void password
  }

  return (
    <main className="relative min-h-screen w-full flex">
      {/* LEFT HALF - Visual / Branding */}
      <div className="hidden lg:flex lg:w-1/2 relative items-center justify-center overflow-hidden">
        {/* Cyber Grid Background */}
        <CyberGrid />
        
        {/* Content Container */}
        <div className="relative z-10 flex flex-col items-center max-w-md px-8">
          {/* Floating Logo */}
          <div className="animate-float mb-10">
            <div className="relative">
              {/* Glow effect behind logo */}
              <div className="absolute inset-0 bg-primary/20 rounded-2xl blur-xl scale-150" />
              
              {/* Logo container */}
              <div className="relative w-20 h-20 rounded-2xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-2xl shadow-primary/30">
                <span className="text-4xl font-bold text-white tracking-tight">P</span>
              </div>
            </div>
          </div>
          
          {/* Brand Name */}
          <h1 className="text-4xl font-bold text-foreground tracking-tight mb-3 animate-fade-in-up">
            PENTRA
          </h1>
          
          {/* Tagline */}
          <p className="text-lg text-muted-foreground text-center mb-12 animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
            Autonomous Offensive Security
          </p>

          {/* Feature Pills */}
          <div className="flex flex-col gap-4 w-full animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            <FeaturePill 
              icon={<Shield size={18} />}
              title="AI-Powered Pentesting"
              description="Autonomous vulnerability discovery"
            />
            <FeaturePill 
              icon={<Zap size={18} />}
              title="Real-time Analysis"
              description="Continuous attack surface monitoring"
            />
            <FeaturePill 
              icon={<Lock size={18} />}
              title="Enterprise Security"
              description="SOC 2 Type II compliant platform"
            />
          </div>

          {/* Trust indicators */}
          <div className="mt-12 flex items-center gap-6 text-xs text-muted-foreground/60 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-low" />
              256-bit encryption
            </span>
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-low" />
              99.9% uptime
            </span>
          </div>
        </div>
      </div>

      {/* RIGHT HALF - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center bg-card relative">
        {/* Subtle gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-br from-card via-card to-background/50 pointer-events-none" />
        
        {/* Border line on desktop */}
        <div className="hidden lg:block absolute left-0 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-border to-transparent" />
        
        <div className="relative w-full max-w-[400px] px-8 lg:px-0">
          {/* Mobile Logo - Only shows on mobile */}
          <div className="lg:hidden flex flex-col items-center mb-12">
            <div className="relative mb-4">
              <div className="absolute inset-0 bg-primary/20 rounded-xl blur-lg scale-125" />
              <div className="relative w-14 h-14 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                <span className="text-2xl font-bold text-white">P</span>
              </div>
            </div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight">PENTRA</h1>
            <p className="text-sm text-muted-foreground mt-1">Autonomous Offensive Security</p>
          </div>

          {/* Form Header */}
          <div className="mb-8">
            <h2 className="text-2xl font-semibold text-foreground tracking-tight">
              {isBootstrapping ? "Restoring session" : "Access command"}
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">
              {isBootstrapping
                ? "Checking runtime auth state before opening the workspace"
                : "Use a real runtime-backed sign-in path to continue"}
            </p>
          </div>

          <div className="mb-6 rounded-xl border border-border/60 bg-background/40 p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-foreground">{authGuidance.title}</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  {authGuidance.description}
                </p>
              </div>
              <StatusBadge status={authGuidance.status} label={authGuidance.status.replaceAll("_", " ")} />
            </div>
          </div>

          {isBootstrapping ? (
            <div className="flex min-h-[200px] flex-col items-center justify-center gap-3 rounded-xl border border-border/50 bg-background/40">
              <Spinner className="size-5 text-primary" />
              <p className="text-sm font-medium text-foreground">Checking authentication runtime</p>
              <p className="text-xs text-muted-foreground">
                Verifying current session, provider availability, and development bypass state.
              </p>
            </div>
          ) : (
            <>
              {/* Login Form */}
              <LoginForm
                onSubmit={handleLogin}
                submitLabel="Password Sign-In Unavailable"
                disabled
                helperText="Direct email/password login is not backed by the current Pentra API. Use Google OAuth when configured, or rely on the development auth bypass in local environments."
              />

              {/* SSO Buttons */}
              <SSOButtons
                disabled={false}
                googleAvailable={Boolean(authRuntime?.google_oauth_configured)}
                googleHref={authRuntime?.google_oauth_configured ? getGoogleLoginUrl() : null}
              />
            </>
          )}

          {/* Footer */}
          <div className="mt-10 pt-6 border-t border-border/50">
            <p className="text-center text-sm text-muted-foreground">
              {"Don't have an account? "}
              <button className="text-primary hover:text-primary/80 font-medium transition-colors inline-flex items-center gap-1 group">
                Request access
                <ArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
              </button>
            </p>
          </div>

          {/* Legal links */}
          <div className="mt-6 flex items-center justify-center gap-4 text-xs text-muted-foreground/50">
            <button className="hover:text-muted-foreground transition-colors">Terms</button>
            <span>·</span>
            <button className="hover:text-muted-foreground transition-colors">Privacy</button>
            <span>·</span>
            <button className="hover:text-muted-foreground transition-colors">Security</button>
          </div>
        </div>
      </div>
    </main>
  )
}

// Feature Pill Component
function FeaturePill({ 
  icon, 
  title, 
  description 
}: { 
  icon: React.ReactNode
  title: string
  description: string 
}) {
  return (
    <div className="group flex items-center gap-4 p-4 rounded-xl glass-subtle hover:bg-white/[0.03] transition-all duration-300 cursor-default">
      <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary group-hover:bg-primary/15 group-hover:border-primary/30 transition-colors duration-300">
        {icon}
      </div>
      <div className="flex flex-col">
        <span className="text-sm font-medium text-foreground">{title}</span>
        <span className="text-xs text-muted-foreground">{description}</span>
      </div>
    </div>
  )
}
