"""DAG builder — constructs execution graphs from scan type and asset type.

Maps (scan_type, asset_type) → a template of phases, tools, and data
dependencies.  Persists the graph as ScanDAG, ScanPhase, ScanNode, and
ScanEdge rows in PostgreSQL.

Each tool node specifies:
  - tool name (e.g. subfinder, nmap, nuclei)
  - worker_family for routing (recon, network, web, vuln, exploit)
  - phase assignment
  - timeout, max_retries
  - data dependencies (edges from upstream nodes)
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.profiles import DEFAULT_EXTERNAL_WEB_API_PROFILE_ID

logger = logging.getLogger(__name__)


# ── Tool / Phase Template Definitions ────────────────────────────────


@dataclass(frozen=True)
class ToolSpec:
    """Specification for a single tool node in the DAG."""

    name: str
    worker_family: str  # recon | network | web | vuln | exploit
    phase: int
    timeout_seconds: int = 600
    max_retries: int = 2
    depends_on: tuple[str, ...] = ()  # tool names this tool depends on
    data_keys: tuple[str, ...] = ()   # data keys consumed from deps
    output_artifact_type: str = "tool_output"


# ── Phase metadata ───────────────────────────────────────────────────

@dataclass(frozen=True)
class PhaseSpec:
    """Specification for a DAG phase."""

    number: int
    name: str
    min_success_ratio: float = 1.0


# ── Scan type templates ──────────────────────────────────────────────

_PHASES: dict[str, list[PhaseSpec]] = {
    "recon": [
        PhaseSpec(0, "scope_validation", 1.0),
        PhaseSpec(1, "recon", 0.33),
    ],
    "vuln": [
        PhaseSpec(0, "scope_validation", 1.0),
        PhaseSpec(1, "recon", 0.33),
        PhaseSpec(2, "enum", 0.50),
        PhaseSpec(3, "vuln_scan", 0.66),
    ],
    "full": [
        PhaseSpec(0, "scope_validation", 1.0),
        PhaseSpec(1, "recon", 0.33),
        PhaseSpec(2, "enum", 0.50),
        PhaseSpec(3, "vuln_scan", 0.66),
        PhaseSpec(4, "exploit_verify", 1.0),
        PhaseSpec(5, "ai_analysis", 1.0),
        PhaseSpec(6, "report_gen", 1.0),
    ],
    "exploit_verify": [
        PhaseSpec(0, "scope_validation", 1.0),
        PhaseSpec(4, "exploit_verify", 1.0),
    ],
}

_TOOLS: dict[str, list[ToolSpec]] = {
    "recon": [
        # Phase 0 — scope validation
        ToolSpec("scope_check", "recon", phase=0, timeout_seconds=30, max_retries=0,
                 output_artifact_type="scope"),
        # Phase 1 — recon
        ToolSpec("subfinder", "recon", phase=1, timeout_seconds=600, max_retries=2,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="subdomains"),
        ToolSpec("amass", "recon", phase=1, timeout_seconds=600, max_retries=2,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="subdomains"),
        ToolSpec("nmap_discovery", "network", phase=1, timeout_seconds=600, max_retries=2,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="hosts"),
    ],
    "vuln": [],   # extended below
    "full": [],   # extended below
    "exploit_verify": [
        ToolSpec("scope_check", "recon", phase=0, timeout_seconds=30, max_retries=0,
                 output_artifact_type="scope"),
        ToolSpec("metasploit", "exploit", phase=4, timeout_seconds=1200, max_retries=0,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="access_levels"),
    ],
}


def _build_vuln_tools() -> list[ToolSpec]:
    """Build vuln scan type tool list (recon + enum + vuln phases)."""
    recon = list(_TOOLS["recon"])
    enum = [
        ToolSpec("nmap_svc", "network", phase=2, timeout_seconds=900, max_retries=2,
                 depends_on=("nmap_discovery",), data_keys=("hosts",),
                 output_artifact_type="services"),
        ToolSpec("ffuf", "web", phase=2, timeout_seconds=900, max_retries=2,
                 depends_on=("subfinder",), data_keys=("subdomains",),
                 output_artifact_type="endpoints"),
    ]
    vuln = [
        ToolSpec("nuclei", "vuln", phase=3, timeout_seconds=1800, max_retries=1,
                 depends_on=("nmap_svc", "ffuf"), data_keys=("services", "endpoints"),
                 output_artifact_type="vulnerabilities"),
        ToolSpec("zap", "web", phase=3, timeout_seconds=1800, max_retries=1,
                 depends_on=("ffuf",), data_keys=("endpoints",),
                 output_artifact_type="vulnerabilities"),
        ToolSpec("sqlmap", "vuln", phase=3, timeout_seconds=1800, max_retries=1,
                 depends_on=("ffuf",), data_keys=("endpoints",),
                 output_artifact_type="vulnerabilities"),
    ]
    return recon + enum + vuln


def _build_full_tools(config: dict[str, Any] | None = None) -> list[ToolSpec]:
    """Build full scan type tool list (all 7 phases)."""
    vuln_tools = _build_vuln_tools()
    exploit: list[ToolSpec] = []
    if _include_static_metasploit(config):
        exploit = [
            ToolSpec("metasploit", "exploit", phase=4, timeout_seconds=1200, max_retries=0,
                     depends_on=("nuclei",), data_keys=("vulnerabilities",),
                     output_artifact_type="access_levels"),
        ]
    ai = [
        ToolSpec("ai_triage", "recon", phase=5, timeout_seconds=300, max_retries=1,
                 depends_on=("nuclei", "zap", "sqlmap"),
                 data_keys=("vulnerabilities",),
                 output_artifact_type="findings_scored"),
    ]
    report = [
        ToolSpec("report_gen", "recon", phase=6, timeout_seconds=300, max_retries=1,
                 depends_on=("ai_triage",), data_keys=("findings_scored",),
                 output_artifact_type="report"),
    ]
    return vuln_tools + exploit + ai + report


def _build_external_web_api_recon_tools() -> list[ToolSpec]:
    """Recon template for the External Web + API v1 profile."""
    return [
        ToolSpec("scope_check", "recon", phase=0, timeout_seconds=30, max_retries=0,
                 output_artifact_type="scope"),
        ToolSpec("subfinder", "recon", phase=1, timeout_seconds=600, max_retries=1,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="subdomains"),
        ToolSpec("amass", "recon", phase=1, timeout_seconds=900, max_retries=1,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="subdomains"),
        ToolSpec("nmap_discovery", "network", phase=1, timeout_seconds=600, max_retries=1,
                 depends_on=("scope_check",), data_keys=("scope",),
                 output_artifact_type="hosts"),
        ToolSpec("httpx_probe", "web", phase=1, timeout_seconds=600, max_retries=1,
                 depends_on=("subfinder", "amass"), data_keys=("subdomains", "subdomains"),
                 output_artifact_type="endpoints"),
    ]


def _build_external_web_api_vuln_tools() -> list[ToolSpec]:
    """Full pre-exploit profile for external web apps and APIs."""
    recon = _build_external_web_api_recon_tools()
    enum = [
        ToolSpec("nmap_svc", "network", phase=2, timeout_seconds=900, max_retries=1,
                 depends_on=("nmap_discovery",), data_keys=("hosts",),
                 output_artifact_type="services"),
        ToolSpec("web_interact", "web", phase=2, timeout_seconds=900, max_retries=1,
                 depends_on=("httpx_probe",), data_keys=("endpoints",),
                 output_artifact_type="endpoints"),
        ToolSpec("ffuf", "web", phase=2, timeout_seconds=900, max_retries=1,
                 depends_on=("httpx_probe",), data_keys=("endpoints",),
                 output_artifact_type="endpoints"),
    ]
    vuln = [
        ToolSpec("nuclei", "vuln", phase=3, timeout_seconds=1800, max_retries=1,
                 depends_on=("httpx_probe", "ffuf", "nmap_svc"),
                 data_keys=("endpoints", "endpoints", "services"),
                 output_artifact_type="vulnerabilities"),
        ToolSpec("zap", "web", phase=3, timeout_seconds=1200, max_retries=1,
                 depends_on=("httpx_probe",), data_keys=("endpoints",),
                 output_artifact_type="vulnerabilities"),
        ToolSpec("sqlmap", "vuln", phase=3, timeout_seconds=1200, max_retries=0,
                 depends_on=("ffuf",), data_keys=("endpoints",),
                 output_artifact_type="vulnerabilities"),
    ]
    return recon + enum + vuln


def _build_external_web_api_full_tools(config: dict[str, Any] | None = None) -> list[ToolSpec]:
    vuln_tools = _build_external_web_api_vuln_tools()
    exploit: list[ToolSpec] = []
    if _include_static_metasploit(config):
        exploit = [
            ToolSpec("metasploit", "exploit", phase=4, timeout_seconds=1200, max_retries=0,
                     depends_on=("nuclei",), data_keys=("vulnerabilities",),
                     output_artifact_type="access_levels"),
        ]
    ai = [
        ToolSpec("ai_triage", "recon", phase=5, timeout_seconds=300, max_retries=1,
                 depends_on=("nuclei", "zap", "sqlmap"),
                 data_keys=("vulnerabilities", "vulnerabilities", "vulnerabilities"),
                 output_artifact_type="findings_scored"),
    ]
    report = [
        ToolSpec("report_gen", "recon", phase=6, timeout_seconds=300, max_retries=1,
                 depends_on=("ai_triage",), data_keys=("findings_scored",),
                 output_artifact_type="report"),
    ]
    return vuln_tools + exploit + ai + report


def _select_tools(scan_type: str, asset_type: str, config: dict[str, Any] | None) -> list[ToolSpec] | None:
    """Choose either the generic template or the profile-specific toolchain."""
    profile_id = str((config or {}).get("profile_id") or (config or {}).get("profile", {}).get("id") or "")
    if asset_type in {"web_app", "api"} and profile_id == DEFAULT_EXTERNAL_WEB_API_PROFILE_ID:
        if scan_type == "recon":
            return _build_external_web_api_recon_tools()
        if scan_type == "vuln":
            return _build_external_web_api_vuln_tools()
        if scan_type == "full":
            return _build_external_web_api_full_tools(config)

    if scan_type == "full":
        return _build_full_tools(config)
    return _TOOLS.get(scan_type)


def _include_static_metasploit(config: dict[str, Any] | None) -> bool:
    verification_policy = (config or {}).get("verification_policy", {})
    if not isinstance(verification_policy, dict):
        return True

    if not verification_policy.get("enabled", False):
        return True

    mode = str(verification_policy.get("mode") or "").strip().lower()
    allowed_tools = {
        str(tool).strip().lower()
        for tool in verification_policy.get("allowed_tools", [])
        if str(tool).strip()
    }
    if mode == "safe_first" and "metasploit" not in allowed_tools and "msf_verify" not in allowed_tools:
        return False
    return True


# Initialize composite templates
_TOOLS["vuln"] = _build_vuln_tools()
_TOOLS["full"] = _build_full_tools()


# ── DAGBuilder ───────────────────────────────────────────────────────


class DAGBuilder:
    """Constructs a scan execution DAG and persists it to PostgreSQL.

    Usage::

        builder = DAGBuilder(session)
        dag_id = await builder.build_dag(
            scan_id=scan_id,
            tenant_id=tenant_id,
            scan_type="full",
            asset_type="web_app",
            config={},
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build_dag(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        scan_type: str,
        asset_type: str,
        config: dict | None = None,
    ) -> uuid.UUID:
        """Build and persist the execution DAG for a scan.

        Returns the ``dag_id`` of the created ScanDAG.
        """
        phases = _PHASES.get(scan_type)
        tools = _select_tools(scan_type, asset_type, config)

        if phases is None or tools is None:
            raise ValueError(f"Unknown scan_type: {scan_type}")

        # 1 — Create ScanDAG
        dag_id = uuid.uuid4()
        await self._session.execute(text("""
            INSERT INTO scan_dags (id, scan_id, tenant_id, scan_type, asset_type,
                                   total_phases, current_phase, status)
            VALUES (:id, :scan_id, :tid, :scan_type, :asset_type,
                    :total, 0, 'building')
        """), {
            "id": str(dag_id), "scan_id": str(scan_id), "tid": str(tenant_id),
            "scan_type": scan_type, "asset_type": asset_type,
            "total": len(phases),
        })

        # 2 — Create ScanPhases
        phase_ids: dict[int, uuid.UUID] = {}
        for ps in phases:
            pid = uuid.uuid4()
            phase_ids[ps.number] = pid
            await self._session.execute(text("""
                INSERT INTO scan_phases (id, dag_id, tenant_id, phase_number, name,
                                         status, min_success_ratio)
                VALUES (:id, :did, :tid, :num, :name, 'pending', :ratio)
            """), {
                "id": str(pid), "did": str(dag_id), "tid": str(tenant_id),
                "num": ps.number, "name": ps.name, "ratio": ps.min_success_ratio,
            })

        # 3 — Create ScanNodes
        node_ids: dict[str, uuid.UUID] = {}  # tool_name → node_id
        for tool in tools:
            nid = uuid.uuid4()
            node_ids[tool.name] = nid
            await self._session.execute(text("""
                INSERT INTO scan_nodes (id, dag_id, phase_id, tenant_id,
                                        tool, worker_family, status, config)
                VALUES (:id, :did, :pid, :tid,
                        :tool, :family, 'pending',
                        CAST(:config AS jsonb))
            """), {
                "id": str(nid), "did": str(dag_id),
                "pid": str(phase_ids[tool.phase]), "tid": str(tenant_id),
                "tool": tool.name, "family": tool.worker_family,
                "config": json.dumps({
                    "max_retries": tool.max_retries,
                    "timeout_seconds": tool.timeout_seconds,
                }),
            })

        # 4 — Create ScanEdges (data dependencies)
        for tool in tools:
            target_id = node_ids[tool.name]
            for i, dep_name in enumerate(tool.depends_on):
                source_id = node_ids.get(dep_name)
                if source_id is None:
                    continue
                data_key = tool.data_keys[i] if i < len(tool.data_keys) else dep_name
                await self._session.execute(text("""
                    INSERT INTO scan_edges (dag_id, source_node_id, target_node_id, data_key)
                    VALUES (:did, :src, :tgt, :key)
                """), {
                    "did": str(dag_id), "src": str(source_id),
                    "tgt": str(target_id), "key": data_key,
                })

        # 5 — Mark DAG as ready
        await self._session.execute(text("""
            UPDATE scan_dags SET status = 'pending' WHERE id = :id
        """), {"id": str(dag_id)})

        await self._session.flush()

        logger.info(
            "DAG built: dag_id=%s scan_id=%s type=%s phases=%d nodes=%d",
            dag_id, scan_id, scan_type, len(phases), len(tools),
        )
        return dag_id
