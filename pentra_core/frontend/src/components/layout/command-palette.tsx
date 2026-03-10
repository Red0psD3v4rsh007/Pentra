"use client"

import React, { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Command } from "cmdk"
import { Search, Radar, ShieldAlert, Settings, BrainCircuit, Terminal, Server, FileText } from "lucide-react"

export function CommandPalette() {
    const [open, setOpen] = useState(false)
    const router = useRouter()

    // Toggle the menu when ⌘K is pressed
    useEffect(() => {
        const down = (e: KeyboardEvent) => {
            if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault()
                setOpen((open) => !open)
            }
        }

        document.addEventListener("keydown", down)
        return () => document.removeEventListener("keydown", down)
    }, [])

    const runCommand = (command: () => void) => {
        setOpen(false)
        command()
    }

    if (!open) return null

    return (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-pentra-black/80 backdrop-blur-sm">
            <div className="fixed inset-0" onClick={() => setOpen(false)} />

            <div className="relative w-full max-w-2xl bg-pentra-panel border border-pentra-border shadow-2xl overflow-hidden glass-panel animate-in fade-in zoom-in-95 duration-200">

                {/* Scanlines overlay effect for terminal feel */}
                <div className="scanlines pointer-events-none absolute inset-0 z-10 opacity-20" />

                <Command
                    className="relative z-20 flex flex-col w-full h-full text-pentra-text"
                    label="Global Command Menu"
                >
                    <div className="flex items-center px-4 border-b border-pentra-border-strong bg-pentra-black/50">
                        <Search className="w-4 h-4 text-pentra-cyan mr-2" />
                        <Command.Input
                            autoFocus
                            placeholder="Type a command or search Operations..."
                            className="flex-1 h-14 bg-transparent border-none outline-none text-white font-mono placeholder:text-pentra-text-dim text-sm"
                        />
                        <div className="text-[10px] font-mono text-pentra-text-dim border border-pentra-border-strong px-2 py-1 rounded bg-pentra-black">ESC TO CANCEL</div>
                    </div>

                    <Command.List className="max-h-[300px] overflow-y-auto p-2 scrollbar-thin scrollbar-thumb-pentra-border">
                        <Command.Empty className="py-6 text-center text-sm font-mono text-pentra-text-muted">
                            No results found. The system does not recognize this parameter.
                        </Command.Empty>

                        <Command.Group heading="OPERATIONS" className="text-[10px] font-mono uppercase tracking-widest text-pentra-text-muted px-2 py-3 [&_[cmdk-item]]:px-4 [&_[cmdk-item]]:py-2 [&_[cmdk-item]]:rounded-none [&_[cmdk-item]]:flex [&_[cmdk-item]]:items-center [&_[cmdk-item]]:gap-3 [&_[cmdk-item]]:cursor-pointer [&_[cmdk-item]]:text-sm [&_[cmdk-item]]:text-pentra-text [&_[cmdk-item][data-selected]]:bg-pentra-cyan/10 [&_[cmdk-item][data-selected]]:text-white [&_[cmdk-item][data-selected]]:border-l-2 [&_[cmdk-item][data-selected]]:border-pentra-cyan">
                            <Command.Item onSelect={() => runCommand(() => router.push('/scans/new'))}>
                                <Radar className="w-4 h-4 text-pentra-cyan" />
                                Initialize New Operation
                            </Command.Item>
                            <Command.Item onSelect={() => runCommand(() => router.push('/scans/OP-DELTA-X9'))}>
                                <Terminal className="w-4 h-4 text-pentra-info" />
                                View Active: OP-DELTA-X9
                            </Command.Item>
                            <Command.Item onSelect={() => runCommand(() => router.push('/scans'))}>
                                <FileText className="w-4 h-4 text-pentra-text-dim" />
                                All Operations Matrix
                            </Command.Item>
                        </Command.Group>

                        <div className="h-px bg-pentra-border-strong my-1 mx-2" />

                        <Command.Group heading="INTELLIGENCE" className="text-[10px] font-mono uppercase tracking-widest text-pentra-text-muted px-2 py-3 [&_[cmdk-item]]:px-4 [&_[cmdk-item]]:py-2 [&_[cmdk-item]]:rounded-none [&_[cmdk-item]]:flex [&_[cmdk-item]]:items-center [&_[cmdk-item]]:gap-3 [&_[cmdk-item]]:cursor-pointer [&_[cmdk-item]]:text-sm [&_[cmdk-item]]:text-pentra-text [&_[cmdk-item][data-selected]]:bg-pentra-critical/10 [&_[cmdk-item][data-selected]]:text-white [&_[cmdk-item][data-selected]]:border-l-2 [&_[cmdk-item][data-selected]]:border-pentra-critical">
                            <Command.Item onSelect={() => runCommand(() => router.push('/findings'))}>
                                <ShieldAlert className="w-4 h-4 text-pentra-critical" />
                                Global Findings Ledger
                            </Command.Item>
                            <Command.Item onSelect={() => runCommand(() => router.push('/intelligence'))}>
                                <BrainCircuit className="w-4 h-4 text-pentra-exploit" />
                                AI Learning Telemetry
                            </Command.Item>
                            <Command.Item onSelect={() => runCommand(() => router.push('/assets'))}>
                                <Server className="w-4 h-4 text-pentra-medium" />
                                Discovered Asset Topology
                            </Command.Item>
                        </Command.Group>

                        <div className="h-px bg-pentra-border-strong my-1 mx-2" />

                        <Command.Group heading="SYSTEM" className="text-[10px] font-mono uppercase tracking-widest text-pentra-text-muted px-2 py-3 [&_[cmdk-item]]:px-4 [&_[cmdk-item]]:py-2 [&_[cmdk-item]]:rounded-none [&_[cmdk-item]]:flex [&_[cmdk-item]]:items-center [&_[cmdk-item]]:gap-3 [&_[cmdk-item]]:cursor-pointer [&_[cmdk-item]]:text-sm [&_[cmdk-item]]:text-pentra-text [&_[cmdk-item][data-selected]]:bg-pentra-text-dim/30 [&_[cmdk-item][data-selected]]:text-white [&_[cmdk-item][data-selected]]:border-l-2 [&_[cmdk-item][data-selected]]:border-pentra-text-dim">
                            <Command.Item onSelect={() => runCommand(() => router.push('/settings/profile'))}>
                                <Settings className="w-4 h-4 text-pentra-text-muted" />
                                Operator Configuration
                            </Command.Item>
                        </Command.Group>

                    </Command.List>
                </Command>

            </div>
        </div>
    )
}
