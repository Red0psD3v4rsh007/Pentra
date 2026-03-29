"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"

import { Spinner } from "@/components/ui/spinner"
import { StatusBadge } from "@/components/ui/status-badge"
import {
  clearStoredAuthTokens,
  completeFrontendGoogleAuthFromHash,
  getCurrentUser,
} from "@/lib/scans-store"

type CallbackState = "processing" | "failed"

export default function GoogleAuthCallbackPage() {
  const router = useRouter()
  const [state, setState] = useState<CallbackState>("processing")
  const [message, setMessage] = useState("Completing Google sign-in with the Pentra API.")

  useEffect(() => {
    let cancelled = false

    async function completeAuth() {
      const stored = completeFrontendGoogleAuthFromHash(window.location.hash)
      if (!stored) {
        if (!cancelled) {
          setState("failed")
          setMessage("No browser auth token was returned from the backend callback.")
        }
        return
      }

      try {
        await getCurrentUser()
        if (!cancelled) {
          router.replace("/dashboard")
        }
      } catch (error) {
        clearStoredAuthTokens()
        if (!cancelled) {
          setState("failed")
          setMessage(
            error instanceof Error
              ? error.message
              : "Pentra could not validate the returned Google session."
          )
        }
      }
    }

    void completeAuth()

    return () => {
      cancelled = true
    }
  }, [router])

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-6">
      <div className="w-full max-w-lg rounded-2xl border border-border/50 bg-card/80 p-8 shadow-2xl">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-foreground">Pentra Browser Authentication</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Completing a real browser session and handing control back to the command console.
            </p>
          </div>
          <StatusBadge
            status={state === "processing" ? "validating" : "failed"}
            label={state === "processing" ? "processing" : "failed"}
          />
        </div>

        <div className="mt-8 flex items-center gap-3 rounded-xl border border-border/50 bg-background/50 p-4">
          {state === "processing" ? <Spinner className="size-5 text-primary" /> : null}
          <p className="text-sm text-foreground">{message}</p>
        </div>

        {state === "failed" ? (
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              onClick={() => router.replace("/")}
              className="rounded-lg border border-border/60 px-4 py-2 text-sm text-foreground transition-colors hover:bg-background/70"
            >
              Return to login
            </button>
          </div>
        ) : null}
      </div>
    </main>
  )
}
