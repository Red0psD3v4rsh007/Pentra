# Pentra – Environment Assumptions

This document defines the runtime environment for Pentra.

---

## Infrastructure

Cloud Provider: AWS

Container Orchestration: Kubernetes (EKS)

Primary Database: PostgreSQL

Object Storage: AWS S3

Queue System: Redis

Secrets Storage: AWS Secrets Manager

---

## Backend

Language: Python

Framework: FastAPI

Async Workers: Celery

---

## Frontend

Framework: Next.js

UI Framework: React

---

## Security Tools

Workers will execute the following tools:

Nmap
Nuclei
sqlmap
OWASP ZAP
Subfinder
Amass
ffuf
Metasploit
