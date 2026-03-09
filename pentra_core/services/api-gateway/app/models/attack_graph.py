"""Attack graph SQLAlchemy models — scan DAG execution tracking.

These tables are created by the orchestrator migration but are also
readable (read-only) by the API gateway for scan detail endpoints.

Tables:
    scan_dags          Top-level attack graph per scan
    scan_phases        Phase-level progress tracking
    scan_nodes         Tool execution nodes in the graph
    scan_edges         Data dependencies between nodes
    job_dependencies   Job-level dependencies (derived from edges)
    scan_artifacts     Output artifacts from tool executions
"""

from __future__ import annotations
from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, TenantMixin, TimestampMixin


class ScanDAG(Base, TenantMixin, TimestampMixin):
    """Top-level attack graph for a scan.

    One-to-one with ``scans`` — stores DAG metadata, current progress,
    and execution status.
    """

    __tablename__ = "scan_dags"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    # tenant_id inherited from TenantMixin
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)
    total_phases: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    current_phase: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, server_default=text("'pending'"), index=True,
        comment="pending | building | executing | completed | failed",
    )
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    # Relationships
    scan = relationship("Scan", back_populates="dag", uselist=False)
    phases: Mapped[list[ScanPhase]] = relationship(
        "ScanPhase", back_populates="dag", cascade="all, delete-orphan",
        order_by="ScanPhase.phase_number", lazy="select",
    )
    nodes: Mapped[list[ScanNode]] = relationship(
        "ScanNode", back_populates="dag", cascade="all, delete-orphan", lazy="select",
    )
    edges: Mapped[list[ScanEdge]] = relationship(
        "ScanEdge", back_populates="dag", cascade="all, delete-orphan", lazy="select",
    )


class ScanPhase(Base, TenantMixin):
    """Phase-level progress within an attack graph.

    Tracks job counts, partial-success evaluation, and output references
    for the phase.
    """

    __tablename__ = "scan_phases"
    __table_args__ = (
        UniqueConstraint("dag_id", "phase_number", name="uq_phase_per_dag"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    dag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_dags.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # tenant_id inherited from TenantMixin
    phase_number: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    name: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="scope_validation | recon | enum | vuln_scan | exploit_verify | ai_analysis | report_gen",
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default=text("'pending'"),
        comment="pending | running | completed | partial_success | failed | skipped",
    )
    min_success_ratio: Mapped[float] = mapped_column(
        Numeric(3, 2), nullable=False, server_default=text("1.00")
    )
    jobs_total: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    jobs_completed: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    jobs_failed: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    outputs: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"),
        comment="{tool_name: output_ref, ...}",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    # Relationships
    dag: Mapped[ScanDAG] = relationship("ScanDAG", back_populates="phases")
    nodes: Mapped[list[ScanNode]] = relationship(
        "ScanNode", back_populates="phase", lazy="select",
    )



class ScanNode(Base, TenantMixin, TimestampMixin):
    """Tool execution node in the attack graph.

    Each node represents a single tool invocation.  Nodes may be
    statically defined (from template) or dynamically created at
    runtime by the ``dynamic_planner`` based on prior tool outputs.
    """

    __tablename__ = "scan_nodes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    dag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_dags.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    phase_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_phases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id"),
        nullable=True,
        index=True,
        comment="Linked ScanJob — NULL until job is created by orchestrator",
    )
    # tenant_id inherited from TenantMixin
    tool: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="subfinder | amass | nmap | httpx | ffuf | nuclei | zap | sqlmap | metasploit | ai_triage | report_gen",
    )
    worker_family: Mapped[str] = mapped_column(
        String(30), nullable=False,
        comment="recon | network | web | vuln | exploit",
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default=text("'pending'"),
        comment="pending | scheduled | running | completed | failed | skipped",
    )
    is_dynamic: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"),
        comment="True if created at runtime by dynamic_planner",
    )
    input_refs: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"),
        comment="{data_key: ref, ...}",
    )
    output_ref: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="S3 key for tool output",
    )
    output_summary: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="{hosts_found: 12, ports_open: 47, ...}",
    )
    config: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"),
        comment="Tool-specific config overrides",
    )

    # Relationships
    dag: Mapped[ScanDAG] = relationship("ScanDAG", back_populates="nodes")
    phase: Mapped[ScanPhase] = relationship("ScanPhase", back_populates="nodes")
    job = relationship("ScanJob", foreign_keys=[job_id], uselist=False)
    source_edges: Mapped[list[ScanEdge]] = relationship(
        "ScanEdge", foreign_keys="ScanEdge.source_node_id",
        back_populates="source_node", lazy="select",
    )
    target_edges: Mapped[list[ScanEdge]] = relationship(
        "ScanEdge", foreign_keys="ScanEdge.target_node_id",
        back_populates="target_node", lazy="select",
    )
    artifacts: Mapped[list[ScanArtifact]] = relationship(
        "ScanArtifact", back_populates="node", cascade="all, delete-orphan", lazy="select",
    )


class ScanEdge(Base):
    """Data dependency between two nodes in the attack graph.

    Defines the DAG topology: ``source_node`` produces data identified by
    ``data_key``, which is consumed by ``target_node``.
    """

    __tablename__ = "scan_edges"
    __table_args__ = (
        UniqueConstraint(
            "source_node_id", "target_node_id", "data_key",
            name="uq_edge_src_tgt_key",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    dag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_dags.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    data_key: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="subdomains | hosts | services | directories | live_hosts | vulns | findings | exploits",
    )
    data_ref: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Populated when source completes: S3 key or Redis stream ID",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    # Relationships
    dag: Mapped[ScanDAG] = relationship("ScanDAG", back_populates="edges")
    source_node: Mapped[ScanNode] = relationship(
        "ScanNode", foreign_keys=[source_node_id], back_populates="source_edges",
    )
    target_node: Mapped[ScanNode] = relationship(
        "ScanNode", foreign_keys=[target_node_id], back_populates="target_edges",
    )


class JobDependency(Base):
    """Job-level dependency tracking.

    Derived from :class:`ScanEdge` at scheduling time.  A job is "ready"
    when all its dependencies have ``status = 'satisfied'``.
    """

    __tablename__ = "job_dependencies"
    __table_args__ = (
        UniqueConstraint("job_id", "depends_on_id", name="uq_job_dep"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    depends_on_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default=text("'pending'"),
        comment="pending | satisfied | broken",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class ScanArtifact(Base, TenantMixin):
    """Output artifact produced by a tool execution.

    Stores references to S3 objects, file metadata, and type
    classification.  Enables report generation and audit trail.
    """

    __tablename__ = "scan_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_nodes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # tenant_id inherited from TenantMixin
    artifact_type: Mapped[str] = mapped_column(
        String(30), nullable=False,
        comment="tool_output | findings_raw | findings_scored | report_pdf | report_html | scope",
    )
    storage_ref: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="S3 key: s3://pentra-artifacts/scans/{scan_id}/...",
    )
    content_type: Mapped[str] = mapped_column(
        String(100), nullable=False, server_default=text("'application/json'")
    )
    size_bytes: Mapped[int | None] = mapped_column(nullable=True)
    checksum: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="SHA-256 hash",
    )
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    # Relationships
    scan = relationship("Scan", back_populates="artifacts")
    node: Mapped[ScanNode | None] = relationship(
        "ScanNode", back_populates="artifacts",
    )
