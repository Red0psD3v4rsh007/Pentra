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
