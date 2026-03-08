# Pentra – MASTER INDEX

This document defines the official module roadmap for the Pentra platform.

This file is the Single Source of Truth (SSoT) for the project structure.

Rules:

* Module IDs must never change.
* Modules must be executed sequentially.
* Submodules may be added using decimal notation (example: MOD-04.1).
* Previous modules cannot be redesigned without explicit justification.

---

## Module Roadmap

MOD-01
Core Architecture
Goal: Define the complete system architecture and service decomposition.

MOD-01.5
Architecture Stress Test
Goal: Validate scalability, security boundaries, and multi-tenant isolation for 10,000 scans/day.

MOD-02
Monorepo & Base Infrastructure
Goal: Create repository structure, base Docker images, and Kubernetes foundation.

MOD-03
API Core
Goal: FastAPI backend with OAuth authentication and PostgreSQL models.

MOD-04
Scan Orchestrator
Goal: Distributed scan orchestration, job scheduling, and pipeline execution.

MOD-04.5
Scan Pipeline Engine
Goal: DAG-based execution engine for pentest workflows.

MOD-05
Worker System
Goal: Containerized scanning workers executing offensive security tools.

MOD-06
Exploit Engine
Goal: Controlled exploit verification and proof-of-concept generation.

MOD-07
AI Analysis
Goal: AI-based vulnerability triage, correlation, and remediation generation.

MOD-08
Reporting
Goal: Pentest report generation and compliance mapping.

MOD-09
Frontend UI
Goal: Next.js dashboard and visualization interface.

MOD-10
Cloud Infrastructure
Goal: AWS infrastructure using Terraform.

MOD-11
CI/CD
Goal: Automated testing, build pipelines, and deployment automation.
