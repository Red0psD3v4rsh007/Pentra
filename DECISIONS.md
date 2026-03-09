# Pentra – Architecture Decisions Log

This document records major architectural decisions to prevent design drift.

---

## Decision 001

Worker orchestration will use Kubernetes Jobs inside AWS EKS.

Reason:
Allows horizontal scaling and isolation of scanning environments.

---

## Decision 002

Scan tasks will be distributed using Redis queue.

Reason:
Simple distributed task orchestration compatible with Celery workers.

---

## Decision 003

Primary database will be PostgreSQL.

Reason:
Strong relational structure required for vulnerabilities, assets, and scan history.

---

## Decision 004

AI analysis will use Anthropic models.

Reason:
High reasoning capability for vulnerability triage and report generation.

---

## Decision 005

Pentra is an Autonomous Offensive Security Platform, not a traditional vulnerability scanner.

Reason:
The architecture must support the full offensive kill chain: reconnaissance → exploitation → post-exploitation → attack graph construction → AI reasoning. All design decisions must accommodate future attack graph generation, exploit chain reasoning, and privilege escalation discovery.

---

## Decision 006

All scan phases produce structured, typed artifacts that feed downstream phases and future attack graph construction.

Reason:
Artifact continuity across phases enables the Attack Graph Engine to reconstruct exploitation paths from raw scan data. Artifact types include: subdomains, hosts, services, endpoints, vulnerabilities, credentials, and access_levels.

---

## Decision 007

The Scan Orchestrator (MOD-04) is designed as the integration point for the future Attack Graph Engine (MOD-04.5).

Reason:
The orchestrator's DAG structure and artifact tracking provide the data backbone for attack graph construction. Keeping orchestration and graph construction in adjacent modules ensures clean data flow without cross-service dependencies.

---

## Decision 008

Exploit verification is bounded by proof-of-concept scope — no destructive exploitation, no persistent access, no data exfiltration beyond what is necessary to prove vulnerability impact.

Reason:
Offensive automation requires strict ethical and legal boundaries. All exploit verification runs in sandboxed, network-isolated containers with enforced time limits and egress controls.
