<div align="center">
  <img src="docs/logo.png" alt="Pentra Logo" width="120" height="auto" />
  <h1>Pentra.</h1>
  <p><strong>Autonomous Offensive Security Operations Center</strong></p>
  <p>
    An enterprise-grade Pentesting-as-a-Service (PTaaS) platform designed for modern security teams. Pentra automates complex vulnerability discovery, coordinates AI-driven exploitation engines, and delivers real-time granular threat intelligence through a high-performance "Obsidian" command center interface.
  </p>
</div>

---

## 🌪 Architecture & Tech Stack

Pentra is built to scale to thousands of concurrent operations, separated into a robust Python orchestration backend and a Next.js frontend shell optimized for extreme data density.

### **Frontend Command Center (V3 Obsidian System)**
- **Framework:** Next.js 16 (App Router)
- **Language:** TypeScript
- **Styling:** Tailwind CSS v4 (Zinc & Electric Blue palette)
- **Visualizations:** `@xyflow/react` (Attack Pathing), `recharts`
- **State Integration:** `zustand`, Framer Motion physics

### **Backend Core Services**
- **API Gateway:** FastAPI, Auth Middleware, Routing
- **Scan Orchestrator (MOD-04):** Distributed Task Queue (Celery/Redis Streams)
- **Worker Engines:** Python 3.10+, executing discrete modular vulnerability capabilities (SQLi, SSRF, Bypasses, etc.)
- **Knowledge Base:** AI Strategy Models, Target Ontologies, Cheatsheet Registries

---

## 🧠 Core Features

1. **Strategic AI Orchestration:** Pentra doesn't just run static tools. Its backend dynamically mutates attack plans based on intermediate discoveries, similar to a human Red Team operator.
2. **Interactive Attack Graphs:** Visualizes the full kill-chain, mapping assets to detected vulnerabilities, compromised credentials, and resulting access levels dynamically via React Flow.
3. **HTTP Evidence Inspection:** Deeply integrated split-pane HTTP Request/Response viewer (`VS Code` style) for every identified vulnerability directly within the browser dashboard.
4. **Threat Intelligence Clustering:** AI-inferred architectural groupings (Tech Clusters) and optimized payload extraction rules learned continuously across operations.
5. **Progressive Disclosure Analysis:** High-density inventory and finding tables (up to 10k rows) cleanly collapsing detailed remediations and PoC data to maintain operator focus.

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18.17.0 or greater
- Python 3.10+
- Redis (for Task Queues/Orchestration)
- PostgreSQL

### Frontend Installation
1. Navigate to the frontend directory:
   \`\`\`bash
   cd pentra_core/frontend
   \`\`\`
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`
3. Start the development server:
   \`\`\`bash
   npm run dev
   \`\`\`
4. Visit `http://localhost:3000` to view the V3 Command Center.

*(See the `backend/` documentation for instructions on standing up the multi-module Microservices and PostgreSQL schemas).*

---

## 🔒 Security Notice

**Pentra is designed strictly for authorized Red Teaming, internal security auditing, and continuous vulnerability assessment.** 
The offensive capabilities integrated within the engine can cause disruption to production networks and trigger highly escalated alerts in enterprise SOCs. Never target infrastructure you do not have explicit, written authorization to test.

---

<div align="center">
  <p>Engineered for <a href="https://github.com/Red0psD3v4rsh007">@Red0psD3v4rsh007</a></p>
</div>
