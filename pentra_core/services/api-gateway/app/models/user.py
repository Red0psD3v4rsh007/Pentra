"""User, Role, and UserRole SQLAlchemy models."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, TenantMixin, TimestampMixin


class User(Base, TenantMixin, TimestampMixin):
    """Platform user — belongs to one tenant, authenticated via Google OAuth."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    # tenant_id inherited from TenantMixin
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str | None] = mapped_column(
        String(255), nullable=True, comment="Null for OAuth-only users"
    )
    google_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, comment="Google OAuth subject ID"
    )
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    user_roles: Mapped[list[UserRole]] = relationship(
        "UserRole", back_populates="user", lazy="joined"
    )

    @property
    def roles(self) -> list[str]:
        """Return role names as a flat list — used by Pydantic serialisation."""
        return [ur.role.name for ur in self.user_roles if ur.role]


# Import datetime for the type annotation above
from datetime import datetime  # noqa: E402


class Role(Base):
    """RBAC role definition — pre-seeded: owner, admin, member, viewer."""

    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False)


class UserRole(Base):
    """Many-to-many association between users and roles, scoped per tenant."""

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="user_roles")
    role: Mapped[Role] = relationship("Role", lazy="joined")
