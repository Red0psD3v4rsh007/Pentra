"""002 — Attack graph schema: DAG execution tracking tables for MOD-04.

Tables:
    scan_dags          Top-level attack graph per scan
    scan_phases        Phase-level progress tracking
    scan_nodes         Tool execution nodes in the graph
    scan_edges         Data dependencies between nodes
    job_dependencies   Job-level dependencies (derived from edges)
    scan_artifacts     Output artifacts from tool executions

Revision ID: 002_attack_graph_schema
Create Date: 2026-03-09
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = "002_attack_graph_schema"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ======================================================================
    # TABLE: scan_dags
    # ======================================================================
    op.create_table(
        "scan_dags",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_type", sa.String(30), nullable=False),
        sa.Column("asset_type", sa.String(30), nullable=False),
        sa.Column("total_phases", sa.SmallInteger(), nullable=False),
        sa.Column("current_phase", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("status", sa.String(30), nullable=False, server_default=sa.text("'pending'"), index=True,
                  comment="pending | building | executing | completed | failed"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: scan_phases
    # ======================================================================
    op.create_table(
        "scan_phases",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("dag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_dags.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("phase_number", sa.SmallInteger(), nullable=False),
        sa.Column("name", sa.String(50), nullable=False,
                  comment="scope_validation | recon | enum | vuln_scan | exploit_verify | ai_analysis | report_gen"),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'pending'"),
                  comment="pending | running | completed | partial_success | failed | skipped"),
        sa.Column("min_success_ratio", sa.Numeric(3, 2), nullable=False, server_default=sa.text("1.00")),
        sa.Column("jobs_total", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("jobs_completed", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("jobs_failed", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("outputs", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
                  comment="{tool_name: output_ref, ...}"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("dag_id", "phase_number", name="uq_phase_per_dag"),
    )

    # ======================================================================
    # TABLE: scan_nodes
    # ======================================================================
    op.create_table(
        "scan_nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("dag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_dags.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("phase_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_phases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True, index=True,
                  comment="Linked ScanJob — NULL until job is created by orchestrator"),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("tool", sa.String(50), nullable=False,
                  comment="subfinder | amass | nmap | httpx | ffuf | nuclei | zap | sqlmap | metasploit | ai_triage | report_gen"),
        sa.Column("worker_family", sa.String(30), nullable=False,
                  comment="recon | network | web | vuln | exploit"),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'pending'"),
                  comment="pending | scheduled | running | completed | failed | skipped"),
        sa.Column("is_dynamic", sa.Boolean(), nullable=False, server_default=sa.text("false"),
                  comment="True if created at runtime by dynamic_planner"),
        sa.Column("input_refs", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
                  comment="{data_key: ref, ...}"),
        sa.Column("output_ref", sa.Text(), nullable=True,
                  comment="S3 key for tool output"),
        sa.Column("output_summary", postgresql.JSONB(), nullable=True,
                  comment="{hosts_found: 12, ports_open: 47, ...}"),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
                  comment="Tool-specific config overrides"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: scan_edges
    # ======================================================================
    op.create_table(
        "scan_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("dag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_dags.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_node_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_nodes.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target_node_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_nodes.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("data_key", sa.String(100), nullable=False,
                  comment="subdomains | hosts | services | directories | live_hosts | vulns | findings | exploits"),
        sa.Column("data_ref", sa.Text(), nullable=True,
                  comment="Populated when source completes: S3 key or Redis stream ID"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("source_node_id", "target_node_id", "data_key", name="uq_edge_src_tgt_key"),
    )

    # ======================================================================
    # TABLE: job_dependencies
    # ======================================================================
    op.create_table(
        "job_dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("depends_on_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'pending'"),
                  comment="pending | satisfied | broken"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("job_id", "depends_on_id", name="uq_job_dep"),
    )

    # ======================================================================
    # TABLE: scan_artifacts
    # ======================================================================
    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("node_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_nodes.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("artifact_type", sa.String(30), nullable=False,
                  comment="tool_output | findings_raw | findings_scored | report_pdf | report_html | scope"),
        sa.Column("storage_ref", sa.Text(), nullable=False,
                  comment="S3 key: s3://pentra-artifacts/scans/{scan_id}/..."),
        sa.Column("content_type", sa.String(100), nullable=False, server_default=sa.text("'application/json'")),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("checksum", sa.String(64), nullable=True, comment="SHA-256 hash"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # ROW-LEVEL SECURITY for tenant-scoped attack graph tables
    # ======================================================================
    rls_tables = ["scan_dags", "scan_phases", "scan_nodes", "scan_artifacts"]
    for table in rls_tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.tenant_id')::uuid) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid)"
        )

    # ======================================================================
    # updated_at TRIGGERS for timestamped attack graph tables
    # ======================================================================
    timestamped_tables = ["scan_dags", "scan_nodes"]
    for table in timestamped_tables:
        op.execute(
            f"CREATE TRIGGER set_updated_at "
            f"BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()"
        )


def downgrade() -> None:
    # Drop tables in reverse dependency order
    tables = [
        "scan_artifacts",
        "job_dependencies",
        "scan_edges",
        "scan_nodes",
        "scan_phases",
        "scan_dags",
    ]
    for table in tables:
        op.drop_table(table)
