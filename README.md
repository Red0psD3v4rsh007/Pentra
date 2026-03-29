<div align="center">
  <h1>PENTRA</h1>
  <p><b>Autonomous Offensive Security Platform</b></p>
  <p>AI-driven penetration testing engine with a real-time command center UI.</p>

  <br/>

  <img src="https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi" />
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript" />
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-v4-06B6D4?style=flat-square&logo=tailwindcss" />
  <img src="https://img.shields.io/badge/Redis-Streams-DC382D?style=flat-square&logo=redis" />
  <img src="https://img.shields.io/badge/PostgreSQL-14+-336791?style=flat-square&logo=postgresql" />
</div>

---

## What is Pentra?

Pentra is a Pentesting-as-a-Service (PTaaS) platform that automates offensive security operations end-to-end. It coordinates reconnaissance, vulnerability scanning, exploitation, and AI-powered analysis through a distributed microservices architecture — then surfaces every result through a high-density dark-mode command center built for security operators.

**This is not a wrapper around Nmap.** Pentra's orchestrator dynamically mutates attack plans mid-scan based on intermediate findings, applies credential pivoting, and uses AI strategy advisors to prioritize exploit chains — similar to how a human red team operator would adapt during an engagement.

---

## Project Structure

```
pentra/
├── run_pentra_local.sh            # One-command local stack launcher
├── docker-compose.local.yml       # PostgreSQL + Redis containers
│
├── pentra_core/
│   ├── frontend/                  # Next.js 16 command center (TypeScript)
│   │   ├── src/app/(app)/         # Dashboard, Scans, Assets, Findings, etc.
│   │   ├── src/app/login/         # Authentication page
│   │   └── src/components/        # Sidebar, Topbar, MainLayout shell
│   │
│   ├── services/
│   │   ├── api-gateway/           # FastAPI REST + WebSocket API
│   │   ├── orchestrator-svc/      # Scan lifecycle, AI planner, phase execution
│   │   └── worker-svc/            # Tool execution, capability modules, artifact storage
│   │
│   ├── packages/
│   │   └── pentra-common/         # Shared models, auth, config
│   │
│   ├── migrations/                # Alembic database migrations
│   ├── knowledge/                 # OWASP corpus, ontologies, cheatsheets
│   └── scripts/local/             # Individual service run scripts
```

---

## Frontend — Obsidian Command Center

The UI follows a custom **Obsidian Design System** — premium enterprise dark mode built on a Zinc palette with Electric Blue accents. No neon glow, no fake terminals, no radar charts. Just clean data density.

| Page | What it does |
|---|---|
| **Login** | 50/50 split layout with gradient mesh branding |
| **Dashboard** | Metric cards, scan status table, Recharts severity breakdown |
| **Scans → New** | 3-step wizard: target → profile → confirmation |
| **Scans → Detail** | Sticky header, Framer Motion tabs, pipeline progress tracker |
| **Attack Graph** | Interactive `@xyflow/react` kill-chain visualization |
| **Evidence Viewer** | Split-pane HTTP request/response inspector |
| **Assets** | Dense inventory table with risk scores and tech tags |
| **Findings** | Filterable table with expandable remediation rows |
| **Intelligence** | AI-learned patterns + inferred technology clusters |
| **Reports** | Generated report cards with format badges |
| **Settings** | Left sub-nav with profile/org/API key configuration |

---

## Backend Services

### API Gateway (`api-gateway/`)
FastAPI-based REST API and WebSocket server. Handles authentication (JWT), scan lifecycle CRUD, asset management, and real-time event streaming to the frontend.

### Scan Orchestrator (`orchestrator-svc/`)
The brain. Manages the full scan lifecycle through a phased execution engine:
- **Strategic Planner** — Generates initial attack plans from target profiles
- **AI Strategy Advisor** — Adapts plans based on intermediate findings
- **Phase Controller** — Coordinates Recon → Enumeration → Exploitation → Analysis
- **Plan Mutator** — Dynamically injects new attack paths mid-execution

### Worker Service (`worker-svc/`)
Executes discrete security capabilities as isolated jobs:
- Injection analysis (SQLi, XSS, SSRF)
- Authentication & access control testing
- Credential extraction and pivoting
- File parser abuse chains
- Browser-based XSS verification

Each capability is defined by a YAML manifest and produces structured findings with full HTTP evidence.

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 18+ and `pnpm`

### Run the Full Stack

```bash
# Clone
git clone https://github.com/Red0psD3v4rsh007/Pentra.git
cd Pentra

# Start everything (Postgres, Redis, API, Orchestrator, Workers, Frontend)
./run_pentra_local.sh start

# Check status
./run_pentra_local.sh status

# Stop
./run_pentra_local.sh stop
```

The launcher handles database migrations, container health checks, port conflict detection, and coordinated service startup automatically.

| Service | Default Port |
|---|---|
| Frontend | `http://localhost:3000` |
| API Gateway | `http://localhost:8000` |
| Orchestrator | `http://localhost:8001` |

### Frontend Only

```bash
cd pentra_core/frontend
npm install
npm run dev
# → http://localhost:3000
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16, TypeScript, Tailwind CSS v4, Framer Motion, Recharts, React Flow |
| API | FastAPI, Pydantic, JWT Auth, WebSockets |
| Orchestration | Python 3.10+, Redis Streams, Celery |
| Database | PostgreSQL 14+, Alembic migrations |
| Infrastructure | Docker Compose, health-checked containers |
| Security Tools | Nmap, Nuclei, SQLMap, Dalfox, Semgrep, TruffleHog, and more |

---

## Security Notice

**Pentra is built for authorized security testing only.**

The offensive capabilities in this platform can disrupt production systems and trigger security alerts. Never target infrastructure without explicit written authorization. The default configuration restricts live tool execution to local-only targets.

---

<div align="center">
  <sub>Built by <a href="https://github.com/Red0psD3v4rsh007">@Red0psD3v4rsh007</a></sub>
</div>
