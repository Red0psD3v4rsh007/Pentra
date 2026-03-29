"use client"

import { useEffect, useRef, useState, useCallback, type KeyboardEvent } from "react"
import { createPortal } from "react-dom"
import { buildApiHeaders, getDevAuthToken } from "@/lib/scans-store"
import { cn } from "@/lib/utils"
import {
  Terminal as TerminalIcon,
  Maximize2,
  Minimize2,
  X,
  Play,
  Square,
  Copy,
  Check,
} from "lucide-react"

interface InteractiveTerminalProps {
  scanId: string
  toolImage?: string
  className?: string
  onClose?: () => void
}

interface TerminalLine {
  type: "input" | "output" | "error" | "system"
  content: string
  timestamp: string
}

async function readErrorDetail(response: Response): Promise<string> {
  const raw = await response.text()
  if (!raw.trim()) {
    return `HTTP ${response.status}`
  }
  try {
    const parsed = JSON.parse(raw) as { detail?: string }
    if (parsed.detail?.trim()) {
      return parsed.detail.trim()
    }
  } catch {
    // Fall back to the raw body below.
  }
  return raw.trim()
}

export function InteractiveTerminal({
  scanId,
  toolImage = "instrumentisto/nmap:latest",
  className,
  onClose,
}: InteractiveTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [isMaximized, setIsMaximized] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [connectionStatus, setConnectionStatus] = useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected")
  const [lines, setLines] = useState<TerminalLine[]>([])
  const [currentInput, setCurrentInput] = useState("")
  const [commandHistory, setCommandHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [copied, setCopied] = useState(false)
  const [lastError, setLastError] = useState<string | null>(null)

  const addLine = useCallback((type: TerminalLine["type"], content: string) => {
    setLines((prev) => [
      ...prev,
      { type, content, timestamp: new Date().toLocaleTimeString() },
    ])
  }, [])

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      if (scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight
      }
    })
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [lines, scrollToBottom])

  // Initial welcome
  useEffect(() => {
    setLines([
      { type: "system", content: "╔══════════════════════════════════════════════════════════╗", timestamp: "" },
      { type: "system", content: "║  Pentra Interactive Terminal                             ║", timestamp: "" },
      { type: "system", content: "║  Real-time shell access to security tool containers      ║", timestamp: "" },
      { type: "system", content: "╚══════════════════════════════════════════════════════════╝", timestamp: "" },
      { type: "system", content: "", timestamp: "" },
      { type: "system", content: `Image: ${toolImage}`, timestamp: "" },
      { type: "system", content: "Click 'Connect' to start a container shell session.", timestamp: "" },
      { type: "system", content: "", timestamp: "" },
    ])
  }, [toolImage])

  const startSession = useCallback(async () => {
    setConnectionStatus("connecting")
    setLastError(null)
    addLine("system", "Starting container session...")

    try {
      const res = await fetch("/api/v1/terminal/sessions", {
        method: "POST",
        headers: buildApiHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ tool_image: toolImage, scan_id: scanId }),
      })

      if (!res.ok) {
        throw new Error(await readErrorDetail(res))
      }

      const data = await res.json()
      const sid = data.session_id
      setSessionId(sid)
      addLine("system", `Container started: ${data.container_name}`)

      // Connect WebSocket
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:"
      const wsUrl = new URL(`${wsProtocol}//${window.location.host}/api/v1/terminal/ws/${sid}`)
      const devAuthToken = getDevAuthToken()
      if (devAuthToken) {
        wsUrl.searchParams.set("token", devAuthToken)
      }

      const ws = new WebSocket(wsUrl.toString())
      wsRef.current = ws

      ws.onopen = () => {
        setConnectionStatus("connected")
        setLastError(null)
        addLine("system", "Connected. Type commands below.")
        inputRef.current?.focus()
      }

      ws.onmessage = (event) => {
        // Parse terminal output, split by newlines
        const text = event.data as string
        const outputLines = text.split(/\r?\n/)
        for (const line of outputLines) {
          if (line.trim()) {
            addLine("output", line)
          }
        }
      }

      ws.onclose = () => {
        setConnectionStatus("disconnected")
        addLine("system", "Session disconnected.")
      }

      ws.onerror = () => {
        setConnectionStatus("error")
        setLastError("WebSocket connection error. Check Docker, API terminal routing, and scan auth.")
        addLine("error", "WebSocket connection error.")
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error"
      addLine("error", `Failed to start session: ${message}`)
      setConnectionStatus("error")
      setLastError(message)
    }
  }, [scanId, toolImage, addLine])

  const stopSession = useCallback(async () => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    if (sessionId) {
      try {
        await fetch(`/api/v1/terminal/sessions/${sessionId}`, {
          method: "DELETE",
          headers: buildApiHeaders(),
        })
      } catch {
        // Best effort cleanup
      }
      setSessionId(null)
    }

    setConnectionStatus("disconnected")
    setLastError(null)
    addLine("system", "Session ended.")
  }, [sessionId, addLine])

  const sendCommand = useCallback(
    (cmd: string) => {
      if (!cmd.trim()) return

      addLine("input", `$ ${cmd}`)
      setCommandHistory((prev) => [cmd, ...prev].slice(0, 50))
      setHistoryIndex(-1)
      setCurrentInput("")

      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        // Send as input to container
        wsRef.current.send(cmd + "\n")
      } else {
        // Fallback: exec via REST
        if (sessionId) {
          fetch("/api/v1/terminal/exec", {
            method: "POST",
            headers: buildApiHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ session_id: sessionId, command: cmd }),
          })
            .then((res) => res.json())
            .then((data) => {
              if (data.stdout) {
                data.stdout.split("\n").forEach((line: string) => {
                  if (line.trim()) addLine("output", line)
                })
              }
              if (data.stderr) {
                data.stderr.split("\n").forEach((line: string) => {
                  if (line.trim()) addLine("error", line)
                })
              }
              if (data.exit_code !== 0) {
                addLine("system", `Exit code: ${data.exit_code}`)
              }
            })
            .catch((err) => {
              addLine("error", `Exec failed: ${err.message}`)
            })
        } else {
          addLine("error", "Not connected. Click 'Connect' first.")
        }
      }
    },
    [sessionId, addLine]
  )

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      sendCommand(currentInput)
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      if (historyIndex < commandHistory.length - 1) {
        const newIdx = historyIndex + 1
        setHistoryIndex(newIdx)
        setCurrentInput(commandHistory[newIdx])
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault()
      if (historyIndex > 0) {
        const newIdx = historyIndex - 1
        setHistoryIndex(newIdx)
        setCurrentInput(commandHistory[newIdx])
      } else {
        setHistoryIndex(-1)
        setCurrentInput("")
      }
    } else if (e.key === "c" && e.ctrlKey) {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send("\x03") // Send Ctrl+C
      }
      addLine("system", "^C")
      setCurrentInput("")
    }
  }

  const copyAllOutput = () => {
    const text = lines
      .filter((l) => l.type !== "system")
      .map((l) => (l.type === "input" ? l.content : `  ${l.content}`))
      .join("\n")
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const statusColors = {
    disconnected: "bg-zinc-500",
    connecting: "bg-amber-500 animate-pulse",
    connected: "bg-emerald-400",
    error: "bg-red-500",
  }

  const statusLabels = {
    disconnected: "Disconnected",
    connecting: "Connecting...",
    connected: "Connected",
    error: "Error",
  }

  const lineColors = {
    input: "text-emerald-400",
    output: "text-zinc-300",
    error: "text-red-400",
    system: "text-cyan-500/70",
  }

  const terminalBody = (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-lg border border-border bg-[#0a0a0f]",
        isMaximized && "h-full shadow-2xl",
        className
      )}
    >
      {/* Terminal Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/90 px-4 py-2">
        <div className="flex items-center gap-3">
          {/* Mac-style dots */}
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full bg-red-500/80" />
            <span className="h-3 w-3 rounded-full bg-amber-500/80" />
            <span className="h-3 w-3 rounded-full bg-emerald-500/80" />
          </div>
          <TerminalIcon className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium text-foreground">
            Operator Shell
          </span>
          <div className="flex items-center gap-1.5">
            <span className={cn("h-2 w-2 rounded-full", statusColors[connectionStatus])} />
            <span className="text-xs text-muted-foreground">
              {statusLabels[connectionStatus]}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {connectionStatus === "disconnected" || connectionStatus === "error" ? (
            <button
              onClick={startSession}
              className="flex items-center gap-1.5 rounded-md bg-primary/20 px-3 py-1 text-xs font-medium text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
            >
              <Play className="h-3 w-3" />
              Connect
            </button>
          ) : connectionStatus === "connected" ? (
            <button
              onClick={stopSession}
              className="flex items-center gap-1.5 rounded-md bg-red-500/20 px-3 py-1 text-xs font-medium text-red-400 hover:bg-red-500/30 transition-colors"
            >
              <Square className="h-3 w-3" />
              Disconnect
            </button>
          ) : null}

          <button
            onClick={copyAllOutput}
            className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-zinc-800 hover:text-foreground transition-colors"
            title="Copy output"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>

          <button
            onClick={() => setIsMaximized(!isMaximized)}
            className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-zinc-800 hover:text-foreground transition-colors"
          >
            {isMaximized ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>

          {onClose && (
            <button
              onClick={() => { stopSession(); onClose() }}
              className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-zinc-800 hover:text-foreground transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {lastError ? (
        <div className="border-b border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-300">
          {lastError}
        </div>
      ) : null}

      {/* Terminal Output */}
      <div
        ref={scrollRef}
        className={cn(
          "flex-1 overflow-y-auto p-4 font-mono text-[13px] leading-relaxed",
          isMaximized ? "min-h-0" : "min-h-[300px] max-h-[500px]"
        )}
        onClick={() => inputRef.current?.focus()}
      >
        {lines.map((line, idx) => (
          <div key={idx} className={cn("whitespace-pre-wrap break-all", lineColors[line.type])}>
            {line.content}
          </div>
        ))}
      </div>

      {/* Input Line */}
      <div className="flex items-center gap-2 border-t border-zinc-800 bg-zinc-900/50 px-4 py-2">
        <span className="text-emerald-400 font-mono text-sm font-bold select-none">
          {connectionStatus === "connected" ? "pentra$" : "#"}
        </span>
        <input
          ref={inputRef}
          type="text"
          value={currentInput}
          onChange={(e) => setCurrentInput(e.target.value)}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-transparent font-mono text-sm text-zinc-200 outline-none placeholder:text-zinc-600 caret-primary"
          placeholder={
            connectionStatus === "connected"
              ? "Type a command and press Enter..."
              : "Connect to start typing..."
          }
          disabled={connectionStatus !== "connected" && connectionStatus !== "disconnected"}
          autoComplete="off"
          spellCheck={false}
        />
      </div>
    </div>
  )

  if (isMaximized && typeof document !== "undefined") {
    return createPortal(
      <div className="fixed inset-0 z-[120] bg-black/75 p-4 sm:p-6">
        <div className="mx-auto flex h-full w-full max-w-7xl flex-col">
          {terminalBody}
        </div>
      </div>,
      document.body
    )
  }

  return terminalBody
}
