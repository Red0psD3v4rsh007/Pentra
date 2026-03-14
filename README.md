# Pentra

Pentra is a Pentesting-as-a-Service (PaaS) platform designed to automate offensive security testing.

Core capabilities:

- asset discovery
- vulnerability scanning
- exploit verification
- attack graph modeling
- AI-driven vulnerability triage
- pentest report generation

Architecture supports distributed scanning and is designed for 10,000 scans/day.

Current repo reality:

- Active backend services live in `pentra_core/services/api-gateway`, `pentra_core/services/orchestrator-svc`, and `pentra_core/services/worker-svc`.
- The active frontend workspace is `pentra_core/frontend/`.
- All active UI work should remain in `pentra_core/frontend/`.
- Official module progression is currently aligned to `MOD-14` as the active module and `MOD-15` as pending cloud infrastructure.
- Local Phase 0 bring-up is documented in `docs/runbooks/local-phase0-stack.md`.

Documentation:

docs/
