"""Import all models so Alembic auto-detect can discover them.

This module also serves as a convenience import for the rest of
the application::

    from app.models import Tenant, User, Scan, Finding  # etc.
"""

from app.models.audit_log import AuditLog
from app.models.asset import Asset, AssetTag
from app.models.asset_group import AssetGroup, AssetGroupMember
from app.models.attack_graph import (
    JobDependency,
    ScanArtifact,
    ScanDAG,
    ScanEdge,
    ScanNode,
    ScanPhase,
)
from app.models.finding import Finding
from app.models.historical_finding import HistoricalFinding, HistoricalFindingOccurrence
from app.models.project import Project
from app.models.scan import Scan, ScanJob
from app.models.tenant import Tenant, TenantQuota
from app.models.user import Role, User, UserRole

__all__ = [
    "AuditLog",
    "Asset",
    "AssetGroup",
    "AssetGroupMember",
    "AssetTag",
    "Finding",
    "HistoricalFinding",
    "HistoricalFindingOccurrence",
    "JobDependency",
    "Project",
    "Scan",
    "ScanArtifact",
    "ScanDAG",
    "ScanEdge",
    "ScanJob",
    "ScanNode",
    "ScanPhase",
    "Tenant",
    "TenantQuota",
    "Role",
    "User",
    "UserRole",
]
