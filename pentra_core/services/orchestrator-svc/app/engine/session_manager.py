"""Session manager — manages multiple session contexts for stateful testing.

MOD-11.6: Maintains authenticated/unauthenticated session contexts with
cookies, tokens, and headers for multi-step interaction workflows.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    """A single session context with authentication state."""

    session_id: str
    session_type: str        # unauthenticated | user_session | admin_session
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)   # jwt, csrf, api_key, etc.
    auth_state: str = "none"  # none | authenticated | elevated
    user_context: dict[str, Any] = field(default_factory=dict)  # username, role, etc.

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "auth_state": self.auth_state,
            "has_cookies": len(self.cookies) > 0,
            "has_tokens": len(self.tokens) > 0,
            "user_context": self.user_context,
        }


class SessionManager:
    """Manages multiple session contexts for stateful vulnerability testing.

    Usage::

        mgr = SessionManager()
        s1 = mgr.create_session("user_session")
        s2 = mgr.create_session("admin_session")
        mgr.set_token(s1.session_id, "jwt", "eyJ...")
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionContext] = {}
        # Always create a default unauthenticated session
        self._default = self.create_session("unauthenticated")

    @property
    def sessions(self) -> list[SessionContext]:
        return list(self._sessions.values())

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    def create_session(
        self,
        session_type: str,
        *,
        user_context: dict[str, Any] | None = None,
    ) -> SessionContext:
        """Create a new session context."""
        ctx = SessionContext(
            session_id=f"sess:{uuid.uuid4().hex[:12]}",
            session_type=session_type,
            user_context=user_context or {},
        )
        self._sessions[ctx.session_id] = ctx
        logger.info("Created session %s (%s)", ctx.session_id, session_type)
        return ctx

    def get_session(self, session_id: str) -> SessionContext | None:
        return self._sessions.get(session_id)

    def get_sessions_by_type(self, session_type: str) -> list[SessionContext]:
        return [s for s in self._sessions.values() if s.session_type == session_type]

    def get_default(self) -> SessionContext:
        return self._default

    def set_cookie(self, session_id: str, name: str, value: str) -> None:
        ctx = self._sessions.get(session_id)
        if ctx:
            ctx.cookies[name] = value

    def set_token(self, session_id: str, token_type: str, value: str) -> None:
        ctx = self._sessions.get(session_id)
        if ctx:
            ctx.tokens[token_type] = value
            if token_type in ("jwt", "session", "bearer"):
                ctx.auth_state = "authenticated"

    def set_header(self, session_id: str, name: str, value: str) -> None:
        ctx = self._sessions.get(session_id)
        if ctx:
            ctx.headers[name] = value

    def elevate_session(self, session_id: str) -> None:
        """Mark session as having elevated privileges."""
        ctx = self._sessions.get(session_id)
        if ctx:
            ctx.auth_state = "elevated"
            ctx.session_type = "admin_session"

    def get_auth_headers(self, session_id: str) -> dict[str, str]:
        """Build full auth headers for a session."""
        ctx = self._sessions.get(session_id)
        if not ctx:
            return {}
        headers = dict(ctx.headers)
        for name, value in ctx.cookies.items():
            headers.setdefault("Cookie", "")
            headers["Cookie"] += f"{name}={value}; "
        if "jwt" in ctx.tokens:
            headers["Authorization"] = f"Bearer {ctx.tokens['jwt']}"
        elif "bearer" in ctx.tokens:
            headers["Authorization"] = f"Bearer {ctx.tokens['bearer']}"
        if "csrf" in ctx.tokens:
            headers["X-CSRF-Token"] = ctx.tokens["csrf"]
        return headers

    def summary(self) -> dict[str, Any]:
        return {
            "total_sessions": len(self._sessions),
            "by_type": {
                t: len(self.get_sessions_by_type(t))
                for t in {"unauthenticated", "user_session", "admin_session"}
            },
            "authenticated": sum(
                1 for s in self._sessions.values() if s.auth_state != "none"
            ),
        }
