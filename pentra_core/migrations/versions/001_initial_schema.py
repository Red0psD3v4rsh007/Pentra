"""001 — Initial schema: all MOD-03 tables + RLS + role seed data.

Revision ID: 001_initial_schema
Create Date: 2026-03-08
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ======================================================================
    # ENUM TYPES
    # ======================================================================
    tenant_tier = postgresql.ENUM("free", "pro", "enterprise", name="tenant_tier", create_type=False)
    asset_type = postgresql.ENUM("web_app", "api", "network", "repository", "cloud", name="asset_type", create_type=False)
    scan_type = postgresql.ENUM("recon", "vuln", "full", "exploit_verify", name="scan_type", create_type=False)
    scan_priority = postgresql.ENUM("critical", "high", "normal", "low", name="scan_priority", create_type=False)
    finding_severity = postgresql.ENUM("critical", "high", "medium", "low", "info", name="finding_severity", create_type=False)
    finding_source = postgresql.ENUM("scanner", "exploit_verify", "ai_analysis", name="finding_source_type", create_type=False)

    tenant_tier.create(op.get_bind(), checkfirst=True)
    asset_type.create(op.get_bind(), checkfirst=True)
    scan_type.create(op.get_bind(), checkfirst=True)
    scan_priority.create(op.get_bind(), checkfirst=True)
    finding_severity.create(op.get_bind(), checkfirst=True)
    finding_source.create(op.get_bind(), checkfirst=True)

    # ======================================================================
    # TABLE: tenants
    # ======================================================================
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("tier", tenant_tier, nullable=False, server_default=sa.text("'free'")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: tenant_quotas
    # ======================================================================
    op.create_table(
        "tenant_quotas",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("max_concurrent_scans", sa.Integer(), nullable=False),
        sa.Column("max_daily_scans", sa.Integer(), nullable=False),
        sa.Column("max_assets", sa.Integer(), nullable=False),
        sa.Column("max_projects", sa.Integer(), nullable=False),
        sa.Column("scans_today", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("active_scans", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: roles (non-tenant-scoped — global definitions)
    # ======================================================================
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("name", sa.String(50), unique=True, nullable=False),
        sa.Column("permissions", postgresql.JSONB(), nullable=False),
    )

    # ======================================================================
    # TABLE: users
    # ======================================================================
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column("google_id", sa.String(255), unique=True, nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: user_roles
    # ======================================================================
    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
    )

    # ======================================================================
    # TABLE: projects
    # ======================================================================
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_project_tenant_slug"),
    )

    # ======================================================================
    # TABLE: assets
    # ======================================================================
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: asset_tags
    # ======================================================================
    op.create_table(
        "asset_tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),
    )

    # ======================================================================
    # TABLE: scans
    # ======================================================================
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scan_type", scan_type, nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default=sa.text("'queued'"), index=True),
        sa.Column("priority", scan_priority, nullable=False, server_default=sa.text("'normal'")),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("progress", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("result_summary", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ======================================================================
    # TABLE: scan_jobs
    # ======================================================================
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("phase", sa.SmallInteger(), nullable=False),
        sa.Column("tool", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'pending'"), index=True),
        sa.Column("priority", scan_priority, nullable=False),
        sa.Column("worker_id", sa.String(100), nullable=True),
        sa.Column("input_ref", sa.Text(), nullable=True),
        sa.Column("output_ref", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("max_retries", sa.SmallInteger(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("checkpoint_ref", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_scan_jobs_scan_phase", "scan_jobs", ["scan_id", "phase"])
    op.create_index("ix_scan_jobs_status_priority", "scan_jobs", ["status", "priority"])

    # ======================================================================
    # TABLE: findings
    # ======================================================================
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("source_type", finding_source, nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", finding_severity, nullable=False, index=True),
        sa.Column("confidence", sa.SmallInteger(), nullable=False),
        sa.Column("cve_id", sa.String(20), nullable=True),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("tool_source", sa.String(50), nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("fp_probability", sa.SmallInteger(), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_findings_tenant_scan", "findings", ["tenant_id", "scan_id"])

    # ======================================================================
    # TABLE: audit_logs
    # ======================================================================
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("action", sa.String(100), nullable=False, index=True),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()"), index=True),
    )

    # ======================================================================
    # ROW-LEVEL SECURITY POLICIES
    # ======================================================================
    # Tables requiring RLS (all tenant-scoped tables)
    rls_tables = [
        "users",
        "user_roles",
        "projects",
        "assets",
        "scans",
        "scan_jobs",
        "findings",
        "audit_logs",
    ]

    for table in rls_tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.tenant_id')::uuid) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid)"
        )

    # Audit logs: append-only — block UPDATE and DELETE even for the app user
    op.execute(
        "CREATE POLICY audit_no_update ON audit_logs "
        "FOR UPDATE USING (false)"
    )
    op.execute(
        "CREATE POLICY audit_no_delete ON audit_logs "
        "FOR DELETE USING (false)"
    )

    # ======================================================================
    # SEED DATA: roles
    # ======================================================================
    op.execute("""
        INSERT INTO roles (id, name, permissions) VALUES
        (gen_random_uuid(), 'owner',  '{"*": true}'::jsonb),
        (gen_random_uuid(), 'admin',  '{"scans": "*", "assets": "*", "reports": "*", "users": "manage", "settings": "*"}'::jsonb),
        (gen_random_uuid(), 'member', '{"scans": ["create", "read"], "assets": "*", "reports": "read"}'::jsonb),
        (gen_random_uuid(), 'viewer', '{"scans": "read", "assets": "read", "reports": "read"}'::jsonb)
    """)

    # ======================================================================
    # updated_at TRIGGER (auto-set on UPDATE for all timestamped tables)
    # ======================================================================
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ language 'plpgsql'
    """)

    timestamped_tables = [
        "tenants", "tenant_quotas", "users", "projects",
        "assets", "scans", "scan_jobs",
    ]
    for table in timestamped_tables:
        op.execute(
            f"CREATE TRIGGER set_updated_at "
            f"BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()"
        )


def downgrade() -> None:
    # Drop tables in reverse dependency order
    tables = [
        "audit_logs", "findings", "scan_jobs", "scans",
        "asset_tags", "assets", "projects",
        "user_roles", "users", "roles",
        "tenant_quotas", "tenants",
    ]
    for table in tables:
        op.drop_table(table)

    # Drop enum types
    for enum_name in [
        "finding_source_type", "finding_severity", "scan_priority",
        "scan_type", "asset_type", "tenant_tier",
    ]:
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")

    # Drop trigger function
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")
