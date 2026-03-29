"use client"

import { useState } from "react"
import { Cookie, FileUp, Key, Lock, User } from "lucide-react"
import { cn } from "@/lib/utils"

export type AuthType = "none" | "cookie" | "basic" | "bearer" | "oauth2" | "session_file"

export interface CredentialConfig {
  authType: AuthType
  cookie?: string
  username?: string
  password?: string
  bearerToken?: string
  apiKey?: string
  clientId?: string
  clientSecret?: string
  tokenUrl?: string
  sessionFile?: File | null
}

interface CredentialFormProps {
  credentials: CredentialConfig
  onChange: (creds: CredentialConfig) => void
}

const authOptions: { id: AuthType; label: string; description: string; icon: typeof Cookie }[] = [
  { id: "none", label: "No Auth", description: "Unauthenticated scanning only", icon: Lock },
  { id: "cookie", label: "Cookie", description: "Raw cookie string for session-based auth", icon: Cookie },
  { id: "basic", label: "Username & Password", description: "HTTP Basic or form-based login credentials", icon: User },
  { id: "bearer", label: "Bearer Token / API Key", description: "JWT, API key, or bearer token", icon: Key },
  { id: "oauth2", label: "OAuth2 Client", description: "Client credentials grant flow", icon: Lock },
  { id: "session_file", label: "Session File", description: "Upload a Burp/ZAP session or cookie file", icon: FileUp },
]

export const defaultCredentials: CredentialConfig = {
  authType: "none",
}

export function CredentialForm({ credentials, onChange }: CredentialFormProps) {
  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-xs font-semibold text-foreground font-heading uppercase tracking-[0.15em] mb-1">
          Authentication
        </h4>
        <p className="text-[10px] text-muted-foreground font-mono">
          Credentials are injected into every tool that supports authenticated scanning
        </p>
      </div>

      {/* Auth type selector */}
      <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
        {authOptions.map((opt) => {
          const isActive = credentials.authType === opt.id
          const Icon = opt.icon
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => onChange({ ...credentials, authType: opt.id })}
              className={cn(
                "group relative overflow-hidden rounded border p-2.5 text-left transition-all duration-200",
                isActive
                  ? "border-[rgba(0,207,255,0.3)] bg-surface-1"
                  : "border-border-subtle bg-surface-0 hover:border-[rgba(255,255,255,0.06)]"
              )}
            >
              {isActive && (
                <div
                  className="absolute top-0 left-0 right-0 h-[1px]"
                  style={{ background: "linear-gradient(90deg, transparent, #00cfff, transparent)" }}
                />
              )}
              <div className="flex items-center gap-2 mb-1">
                <Icon className={cn("h-3.5 w-3.5", isActive ? "text-[#00cfff]" : "text-[#555]")} />
                <span className={cn("text-[11px] font-semibold font-heading", isActive ? "text-foreground" : "text-muted-foreground")}>
                  {opt.label}
                </span>
              </div>
              <p className="text-[9px] text-[#555] font-mono leading-relaxed">
                {opt.description}
              </p>
            </button>
          )
        })}
      </div>

      {/* Dynamic form fields */}
      {credentials.authType === "cookie" && (
        <div className="rounded border border-border-subtle bg-surface-0 p-4 space-y-3">
          <label className="block">
            <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Cookie Value</span>
            <textarea
              value={credentials.cookie ?? ""}
              onChange={(e) => onChange({ ...credentials, cookie: e.target.value })}
              placeholder="session=abc123; csrf_token=xyz789; user_id=..."
              rows={3}
              className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-2 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none resize-none"
            />
          </label>
          <p className="text-[9px] text-[#555] font-mono">
            Injected via: sqlmap --cookie, nuclei -H &quot;Cookie:...&quot;, ffuf -H, nikto -cookie
          </p>
        </div>
      )}

      {credentials.authType === "basic" && (
        <div className="rounded border border-border-subtle bg-surface-0 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Username</span>
              <input
                type="text"
                value={credentials.username ?? ""}
                onChange={(e) => onChange({ ...credentials, username: e.target.value })}
                placeholder="admin"
                className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Password</span>
              <input
                type="password"
                value={credentials.password ?? ""}
                onChange={(e) => onChange({ ...credentials, password: e.target.value })}
                placeholder="••••••••"
                className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
              />
            </label>
          </div>
          <p className="text-[9px] text-[#555] font-mono">
            Injected via: hydra -l/-p, nikto -id, sqlmap --auth-type=basic, nuclei -H Authorization
          </p>
        </div>
      )}

      {credentials.authType === "bearer" && (
        <div className="rounded border border-border-subtle bg-surface-0 p-4 space-y-3">
          <label className="block">
            <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Bearer Token / API Key</span>
            <input
              type="password"
              value={credentials.bearerToken ?? ""}
              onChange={(e) => onChange({ ...credentials, bearerToken: e.target.value })}
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
            />
          </label>
          <p className="text-[9px] text-[#555] font-mono">
            Injected via: -H &quot;Authorization: Bearer ...&quot; across all HTTP-based tools
          </p>
        </div>
      )}

      {credentials.authType === "oauth2" && (
        <div className="rounded border border-border-subtle bg-surface-0 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Client ID</span>
              <input
                type="text"
                value={credentials.clientId ?? ""}
                onChange={(e) => onChange({ ...credentials, clientId: e.target.value })}
                className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Client Secret</span>
              <input
                type="password"
                value={credentials.clientSecret ?? ""}
                onChange={(e) => onChange({ ...credentials, clientSecret: e.target.value })}
                className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
              />
            </label>
          </div>
          <label className="block">
            <span className="text-[10px] uppercase tracking-[0.15em] text-muted-foreground font-heading">Token URL</span>
            <input
              type="url"
              value={credentials.tokenUrl ?? ""}
              onChange={(e) => onChange({ ...credentials, tokenUrl: e.target.value })}
              placeholder="https://auth.example.com/oauth/token"
              className="mt-1 w-full rounded border border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-foreground font-mono placeholder:text-[#555] focus:border-[rgba(0,207,255,0.3)] focus:outline-none"
            />
          </label>
          <p className="text-[9px] text-[#555] font-mono">
            Pentra will acquire a bearer token via client_credentials grant before scanning
          </p>
        </div>
      )}

      {credentials.authType === "session_file" && (
        <div className="rounded border border-border-subtle bg-surface-0 p-4 space-y-3">
          <label className="flex flex-col items-center justify-center gap-2 rounded border-2 border-dashed border-border-subtle p-8 cursor-pointer hover:border-[rgba(0,207,255,0.3)] transition-colors">
            <FileUp className="h-6 w-6 text-[#555]" />
            <span className="text-xs text-muted-foreground font-mono">
              {credentials.sessionFile ? credentials.sessionFile.name : "Drop or click to upload session file"}
            </span>
            <span className="text-[9px] text-[#555] font-mono">
              Supports: Burp XML, ZAP session, JSON cookie export
            </span>
            <input
              type="file"
              accept=".xml,.json,.txt,.har"
              onChange={(e) => {
                const file = e.target.files?.[0] ?? null
                onChange({ ...credentials, sessionFile: file })
              }}
              className="hidden"
            />
          </label>
        </div>
      )}
    </div>
  )
}
