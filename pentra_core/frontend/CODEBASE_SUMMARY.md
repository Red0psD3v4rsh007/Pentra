# Pentra UI - Complete Codebase Summary

## Overview

**Pentra** is an autonomous offensive security / AI-driven penetration testing platform. This is the frontend UI built with Next.js 16, React 19, TailwindCSS 4, and shadcn/ui components.

---

## Tech Stack

| Category         | Technology                             |
| ---------------- | -------------------------------------- |
| Framework        | Next.js 16.1.6 (App Router)            |
| React            | React 19.2.4                           |
| Styling          | TailwindCSS 4.2.0                      |
| UI Components    | shadcn/ui (Radix primitives)           |
| Animations       | Framer Motion 11.18.0                  |
| Charts           | Recharts 2.15.0                        |
| Flow Diagrams    | @xyflow/react 12.6.0                   |
| Icons            | Lucide React                           |
| Forms            | React Hook Form + Zod                  |
| State Management | Custom store with useSyncExternalStore |

---

## Design System: "Obsidian"

A premium enterprise dark mode theme defined in `app/globals.css`.

### Color Palette

```css
/* Base */
--background: #09090b; /* Near black */
--foreground: #fafafa; /* Off-white */
--card: #18181b; /* Elevated surface */
--border: #27272a; /* Borders */

/* Primary Accent */
--primary: #3b82f6; /* Blue */

/* Severity Colors */
--critical: #ef4444; /* Red */
--high: #f97316; /* Orange */
--medium: #eab308; /* Yellow */
--low: #22c55e; /* Green */
--info: #71717a; /* Gray */

/* Radius */
--radius: 6px;
```

### Typography

- **Sans**: Inter (variable font)
- **Mono**: JetBrains Mono (for code, IDs, targets)

### Custom Utilities

```css
/* Glassmorphism */
.glass {
  backdrop-filter: blur(20px);
}
.glass-subtle {
  backdrop-filter: blur(12px);
}

/* Text gradient */
.text-gradient {
  background: linear-gradient(135deg, #fafafa, #a1a1aa);
}

/* Animations */
.animate-float {
  /* Floating effect */
}
.animate-fade-in-up {
  /* Entrance animation */
}
.animate-grid-pulse {
  /* Background grid pulse */
}
.animate-scan-line {
  /* Scanning line effect */
}
.animate-glow-pulse {
  /* Glow pulsing */
}
.animate-shimmer {
  /* Button shimmer on hover */
}
```

---

## Project Structure

```
/app
├── page.tsx                    # Login page (/)
├── layout.tsx                  # Root layout with fonts
├── globals.css                 # Design system + Tailwind config
├── dashboard/
│   └── page.tsx                # Main dashboard (/dashboard)
├── scans/
│   ├── page.tsx                # Scans list (/scans)
│   ├── new/
│   │   └── page.tsx            # New scan wizard (/scans/new)
│   └── [id]/
│       └── page.tsx            # Scan detail (/scans/:id)
├── assets/
│   └── page.tsx                # Assets inventory (/assets)
├── findings/
│   └── page.tsx                # Findings table (/findings)
├── attack-graphs/
│   └── page.tsx                # Attack graphs hub (/attack-graphs)
├── intelligence/
│   └── page.tsx                # AI intelligence (/intelligence)
├── reports/
│   └── page.tsx                # Reports management (/reports)
└── settings/
    └── page.tsx                # Settings with tabs (/settings)

/components
├── login-form.tsx              # Email/password form
├── sso-buttons.tsx             # SSO auth buttons
├── cyber-grid.tsx              # Animated grid background
├── gradient-mesh.tsx           # Gradient mesh background
├── theme-provider.tsx          # Theme context
├── dashboard/
│   ├── sidebar.tsx             # Main navigation sidebar
│   ├── top-bar.tsx             # Page header with search
│   ├── metric-cards.tsx        # Animated stat cards
│   ├── recent-scans.tsx        # Recent scans widget
│   ├── severity-breakdown.tsx  # Donut chart
│   ├── attack-graph.tsx        # React Flow graph
│   └── ...                     # Other dashboard widgets
├── scans/
│   ├── scan-header.tsx         # Scan detail header
│   ├── scan-tabs.tsx           # Tab navigation
│   └── tabs/
│       ├── overview-tab.tsx    # Scan overview
│       ├── findings-tab.tsx    # Findings list
│       ├── attack-graph-tab.tsx # Interactive attack graph
│       ├── evidence-tab.tsx    # Evidence/screenshots
│       ├── timeline-tab.tsx    # Scan timeline
│       └── report-tab.tsx      # Report generation
└── ui/                         # shadcn/ui components (80+ files)
    ├── button.tsx
    ├── card.tsx
    ├── table.tsx
    ├── tabs.tsx
    ├── badge.tsx
    └── ...

/hooks
├── use-scans.ts                # Scans state hook
├── use-toast.ts                # Toast notifications
└── use-mobile.ts               # Mobile detection

/lib
├── scans-store.ts              # Scans state management
└── utils.ts                    # cn() utility
```

---

## Page Specifications

### 1. Login Page (`/`)

Split-screen layout:

- **Left**: Animated cyber grid background, floating logo, brand tagline, feature pills
- **Right**: Login form with email/password, SSO buttons (Google, Microsoft, SAML)

Key components: `CyberGrid`, `LoginForm`, `SSOButtons`

### 2. Dashboard (`/dashboard`)

Main monitoring view with sidebar + topbar layout:

- **MetricCards**: 4 animated stat cards (Active Scans, Open Findings, Assets, Exploit Rate)
- **RecentScans**: Table of recent scans with status badges
- **SeverityBreakdown**: Donut chart of findings by severity

### 3. Scans List (`/scans`)

Table listing all scans:

- Columns: Name, Target, Status, Duration, Findings (severity badges)
- Status indicators: Running (animated pulse), Completed, Failed, Queued
- "New Scan" CTA button

### 4. New Scan Wizard (`/scans/new`)

3-step wizard flow:

1. **Target**: Add URLs/IPs/CIDR ranges as tags
2. **Profile**: Choose Quick/Full/Stealth scan
3. **Confirm**: Review and start scan

Uses Framer Motion for step transitions.

### 5. Scan Detail (`/scans/[id]`)

Tabbed interface with 6 tabs:

- **Overview**: Progress, severity breakdown, config, targets
- **Findings**: Expandable findings table with severity badges
- **Attack Graph**: Interactive React Flow diagram showing attack paths
- **Evidence**: Screenshots and raw output evidence
- **Timeline**: Step-by-step scan timeline
- **Report**: Export options (PDF, JSON, CSV)

### 6. Assets (`/assets`)

Asset inventory table:

- Columns: Type icon, Hostname, IP, Risk Score (color-coded), Technologies (tags), Status, Last Scanned, Findings
- Stat cards: Total Assets, Critical Risk, Online, Open Findings
- Search and filters

### 7. Findings (`/findings`)

Expandable findings table:

- Columns: Severity (with pulse indicator), Title, CVSS, Target, Status, OWASP
- Expandable rows showing: Description, Remediation, Proof of Concept
- Stat cards: Total, Critical, High, Medium

### 8. Attack Graphs (`/attack-graphs`)

Hub page showing all scans with attack graph previews:

- Card grid with mini graph visualization
- Status badges (Ready, Generating, Pending)
- Stats: Nodes, Attack Paths
- Links to individual scan attack graphs

### 9. Intelligence (`/intelligence`)

Two-column layout:

- **Learned Patterns**: AI-optimized attack patterns with confidence scores
- **Technology Clusters**: Grouped tech stacks with risk levels

Stat cards: Patterns Learned, Active Optimizations, Success Rate, Bypasses Found

### 10. Reports (`/reports`)

Reports management table:

- Columns: Report Name, Scan, Format (PDF/JSON/CSV badges), Findings breakdown, Generated date, Size
- Filter by format
- Download buttons on hover
- "Generate Report" CTA

### 11. Settings (`/settings`)

Tabbed settings interface:

- **Profile**: Name, email, avatar
- **Organization**: Org name, billing email
- **Authentication**: 2FA, session timeout
- **API Keys**: Key management table
- **Webhooks**: URL configuration
- **Notifications**: Toggle switches for notifications

---

## State Management

### Scans Store (`lib/scans-store.ts`)

In-memory store using pub/sub pattern:

```typescript
interface Scan {
  id: string; // "SC-2847"
  name: string; // "internal-network-sweep"
  target: string; // "api.acmecorp.com"
  status: "running" | "completed" | "failed" | "queued";
  startedAt: string; // ISO date
  duration: string; // "18m 32s"
  profile: string; // "quick" | "full" | "stealth"
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}
```

### useScans Hook (`hooks/use-scans.ts`)

```typescript
const { scans, addScan, updateScan, getScan } = useScans();
```

Uses `useSyncExternalStore` for reactive updates across components.

---

## Layout Components

### Sidebar (`components/dashboard/sidebar.tsx`)

Collapsible sidebar with navigation sections:

- **OVERVIEW**: Dashboard, Scans
- **DISCOVERY**: Assets, Findings
- **ANALYSIS**: Attack Graphs, Intelligence
- **OUTPUT**: Reports
- **Settings** (bottom)
- User profile section

### TopBar (`components/dashboard/top-bar.tsx`)

- Page title
- Search button with Cmd+K shortcut
- Notifications bell with badge
- User avatar

---

## Common UI Patterns

### Severity Badges

```tsx
<span className="bg-critical/15 text-critical">Critical</span>
<span className="bg-high/15 text-high">High</span>
<span className="bg-medium/15 text-medium">Medium</span>
<span className="bg-low/15 text-low">Low</span>
```

### Status Indicators

```tsx
// Running - animated pulse
<span className="bg-primary animate-pulse h-2 w-2 rounded-full" />

// Completed - green
<span className="bg-low h-2 w-2 rounded-full" />

// Failed - red
<span className="bg-critical h-2 w-2 rounded-full" />
```

### Cards

```tsx
<div className="rounded-lg border border-border bg-card p-6">
  {/* Content */}
</div>
```

### Tables

```tsx
<table className="w-full">
  <thead>
    <tr className="border-b border-border text-xs uppercase text-muted-foreground">
      <th className="px-4 py-3">Column</th>
    </tr>
  </thead>
  <tbody className="divide-y divide-border">
    <tr className="hover:bg-elevated">{/* Row */}</tr>
  </tbody>
</table>
```

---

## Animation Patterns

### Page Transitions (Framer Motion)

```tsx
<AnimatePresence mode="wait">
  <motion.div
    key={activeTab}
    initial={{ opacity: 0, y: 4 }}
    animate={{ opacity: 1, y: 0 }}
    exit={{ opacity: 0, y: -4 }}
    transition={{ duration: 0.15 }}
  >
    {content}
  </motion.div>
</AnimatePresence>
```

### Animated Counters

Used in MetricCards with `useCountUp` hook for number animations.

### Hover Effects

```tsx
className = "transition-colors hover:bg-elevated hover:text-foreground";
```

---

## Key Dependencies

```json
{
  "next": "16.1.6",
  "react": "19.2.4",
  "tailwindcss": "^4.2.0",
  "@xyflow/react": "^12.6.0",
  "framer-motion": "^11.18.0",
  "lucide-react": "^0.564.0",
  "recharts": "2.15.0",
  "react-hook-form": "^7.54.1",
  "zod": "^3.24.1"
}
```

---

## Navigation Flow

```
Login (/)
  → Dashboard (/dashboard)
      → Scans List (/scans)
          → New Scan (/scans/new)
          → Scan Detail (/scans/[id])
              → Attack Graph tab links to full attack graph
      → Assets (/assets)
      → Findings (/findings)
      → Attack Graphs (/attack-graphs)
          → Links to scan attack graphs
      → Intelligence (/intelligence)
      → Reports (/reports)
      → Settings (/settings)
```

---

## File Naming Conventions

- Pages: `page.tsx` in route directories
- Components: kebab-case (`metric-cards.tsx`)
- Hooks: `use-*.ts` prefix
- Stores: `*-store.ts` suffix

---

## Notes for AI Models

1. **All pages use the same layout**: `DashboardSidebar` + `TopBar` + main content
2. **State is client-side only**: Using custom store, not connected to backend yet
3. **Mock data is hardcoded**: Scans, findings, assets all use mock data
4. **Dark theme only**: No light mode, "Obsidian" design system
5. **TailwindCSS v4**: Uses `@theme inline` syntax, no `tailwind.config.js`
6. **React 19**: Uses latest React features
7. **Framer Motion**: Used for page transitions and micro-interactions
8. **Attack graphs use @xyflow/react**: Interactive node-edge diagrams

---

## Example: Adding a New Page

```tsx
"use client";

import { DashboardSidebar } from "@/components/dashboard/sidebar";
import { TopBar } from "@/components/dashboard/top-bar";

export default function NewPage() {
  return (
    <div className="min-h-screen bg-background">
      <DashboardSidebar />
      <div className="pl-60 transition-all duration-200">
        <TopBar title="Page Title" />
        <main className="p-6">{/* Content */}</main>
      </div>
    </div>
  );
}
```

---

## Styling Quick Reference

| Element           | Classes                                                                       |
| ----------------- | ----------------------------------------------------------------------------- |
| Page background   | `bg-background`                                                               |
| Card              | `rounded-lg border border-border bg-card p-6`                                 |
| Section title     | `text-xs font-medium uppercase tracking-wider text-muted-foreground`          |
| Primary button    | `rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground` |
| Muted text        | `text-muted-foreground`                                                       |
| Mono text         | `font-mono text-sm`                                                           |
| Severity critical | `text-critical` or `bg-critical/15 text-critical`                             |
| Hover state       | `hover:bg-elevated`                                                           |
| Transition        | `transition-colors` or `transition-all duration-200`                          |
