"use client"

import React, { useState } from "react"
import { useRouter } from "next/navigation"
import { Terminal, Shield, Lock } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export default function LoginPage() {
    const router = useRouter()
    const [isLoading, setIsLoading] = useState(false)

    const handleLogin = (e: React.FormEvent) => {
        e.preventDefault()
        setIsLoading(true)
        setTimeout(() => {
            router.push("/dashboard")
        }, 1500)
    }

    return (
        <div className="min-h-screen bg-pentra-black flex flex-col items-center justify-center relative overflow-hidden">

            {/* Background Grid & Particles matching global theme */}
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,0,60,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,0,60,0.03)_1px,transparent_1px)] bg-[size:30px_30px] opacity-50" />

            {/* Glow Orbs */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-pentra-primary/10 rounded-full blur-[120px] pointer-events-none" />

            <div className="relative z-10 w-full max-w-md">

                {/* Logo Header */}
                <div className="flex flex-col items-center mb-8">
                    <div className="w-16 h-16 rounded-xl bg-pentra-black border-2 border-pentra-primary flex items-center justify-center text-pentra-primary mb-4 shadow-[0_0_30px_rgba(255,0,60,0.6)]">
                        <Terminal size={32} />
                    </div>
                    <h1 className="text-4xl font-display font-bold tracking-[0.2em] text-white text-glow">PENTRA</h1>
                    <p className="text-pentra-primary mt-2 font-mono text-sm tracking-widest uppercase opacity-80">Autonomous Security Engine</p>
                </div>

                {/* Auth Card */}
                <div className="glass-panel rounded-xl p-8 shadow-[0_0_50px_rgba(0,0,0,0.8)] relative border border-pentra-border-strong before:absolute before:inset-0 before:border before:border-pentra-primary/20 before:rounded-xl">

                    <form onSubmit={handleLogin} className="space-y-6 relative z-10">
                        <div className="space-y-2">
                            <label className="text-xs font-mono text-pentra-text-muted uppercase tracking-wider">Operator Identity</label>
                            <div className="relative">
                                <Shield className="absolute left-3 top-1/2 -translate-y-1/2 text-pentra-text-muted" size={16} />
                                <Input
                                    type="email"
                                    defaultValue="operator@pentra.local"
                                    placeholder="admin@domain.com"
                                    className="pl-10"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-xs font-mono text-pentra-text-muted uppercase tracking-wider">Passphrase</label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-pentra-text-muted" size={16} />
                                <Input
                                    type="password"
                                    defaultValue="hunter2"
                                    placeholder="••••••••••••"
                                    className="pl-10"
                                />
                            </div>
                        </div>

                        <Button
                            type="submit"
                            className="w-full h-12 text-lg font-mono tracking-widest uppercase mt-4"
                            glow
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <div className="flex items-center gap-2 text-pentra-primary">
                                    <Terminal size={18} className="animate-pulse" />
                                    <span>Authenticating...</span>
                                </div>
                            ) : (
                                "Initialize Session"
                            )}
                        </Button>
                    </form>

                    {/* CLI Style decorative footer */}
                    <div className="mt-8 pt-4 border-t border-pentra-border-strong text-center">
                        <p className="text-[10px] font-mono text-pentra-text-dim">
                            SYSTEM: AUTHORIZED PERSONNEL ONLY
                            <br />
                            <span className="text-pentra-primary/50">V: 1.0.4-STABLE</span>
                        </p>
                    </div>
                </div>

            </div>
        </div>
    )
}
