"""Impact verifier — classifies exploit output into verified impact artifacts.

MOD-06: Takes exploit tool output and determines:
  - Was the exploit successful?
  - What type of impact was achieved?
  - What evidence proves the impact?

Impact types:
  database_access        — confirmed SQL queries, table enumeration
  shell_access           — confirmed command execution, whoami output
  credential_leak        — harvested credentials, auth tokens
  privilege_escalation   — confirmed elevated access

Stores verified impact as scan_artifact with artifact_type = 'verified_impact'.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.storage.retention import apply_artifact_retention_metadata

logger = logging.getLogger(__name__)


# Impact classification indicators
_IMPACT_INDICATORS: dict[str, list[str]] = {
    "database_access": [
        "table", "column", "database", "schema", "dump", "row",
        "sql", "query", "injection", "dbms", "entries",
    ],
    "shell_access": [
        "whoami", "uid=", "root", "shell", "command", "exec",
        "bash", "/bin/", "meterpreter", "session",
    ],
    "credential_leak": [
        "password", "credential", "token", "api_key", "secret",
        "auth", "login", "bypass", "session", "cookie",
    ],
    "privilege_escalation": [
        "escalat", "privesc", "sudo", "admin", "root",
        "internal", "ssrf", "chain", "pivot",
    ],
}


class ImpactVerifier:
    """Classifies exploit results into verified impact artifacts.

    Usage::

        verifier = ImpactVerifier(session)
        count = await verifier.verify_impact(
            scan_id=scan_id, node_id=node_id, tenant_id=tenant_id,
            tool="sqlmap", output_ref="artifacts/...",
            expected_impact_type="database_access",
            exploit_items=[...],
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def verify_impact(
        self,
        *,
        scan_id: uuid.UUID,
        node_id: uuid.UUID,
        tenant_id: uuid.UUID,
        tool: str,
        output_ref: str,
        expected_impact_type: str,
        exploit_items: list[dict[str, Any]],
    ) -> int:
        """Analyze exploit output and store verified impact artifacts.

        Returns the number of impact artifacts created.
        """
        if not exploit_items:
            return 0

        # Classify the impact
        verified_impact = self._classify_impact(
            items=exploit_items,
            expected_type=expected_impact_type,
            tool=tool,
        )

        if verified_impact is None:
            logger.info("No verified impact from %s output", tool)
            return 0

        # Build the impact artifact
        impact_artifact = apply_artifact_retention_metadata(
            {
                "impact_type": verified_impact["impact_type"],
                "confidence": verified_impact["confidence"],
                "tool": tool,
                "evidence_summary": verified_impact["evidence"],
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "source_ref": output_ref,
            },
            policy="verified_impact",
        )

        # Store as scan_artifact
        artifact_id = uuid.uuid4()
        await self._session.execute(text("""
            INSERT INTO scan_artifacts (
                id, scan_id, node_id, tenant_id,
                artifact_type, storage_ref, metadata
            ) VALUES (
                :id, :sid, :nid, :tid,
                'verified_impact', :ref,
                CAST(:meta AS jsonb)
            )
        """), {
            "id": str(artifact_id),
            "sid": str(scan_id),
            "nid": str(node_id),
            "tid": str(tenant_id),
            "ref": output_ref,
            "meta": json.dumps(impact_artifact, default=str),
        })

        await self._session.flush()

        logger.info(
            "Verified impact: type=%s confidence=%d%% tool=%s artifact=%s",
            verified_impact["impact_type"],
            verified_impact["confidence"],
            tool,
            artifact_id,
        )
        return 1

    def _classify_impact(
        self,
        *,
        items: list[dict],
        expected_type: str,
        tool: str,
    ) -> dict[str, Any] | None:
        """Classify exploit output into an impact type with confidence.

        Returns None if no verified impact detected.
        """
        # Flatten all text content for indicator matching
        text_blob = self._flatten_items(items).lower()

        if not text_blob:
            return None

        # Score each impact type
        scores: dict[str, int] = {}
        for impact_type, indicators in _IMPACT_INDICATORS.items():
            score = sum(1 for ind in indicators if ind in text_blob)
            if score > 0:
                scores[impact_type] = score

        if not scores:
            return None

        # Pick the best matching impact type (prefer expected_type on tie)
        best_type = expected_type if expected_type in scores else max(scores, key=scores.get)
        best_score = scores.get(best_type, 0)

        # Confidence: 0-100 based on indicator matches
        max_possible = len(_IMPACT_INDICATORS.get(best_type, []))
        confidence = min(100, int(best_score / max(max_possible, 1) * 100))

        # Minimum threshold: need at least 2 indicators
        if best_score < 2:
            return None

        # Extract evidence snippets
        evidence = self._extract_evidence(items, best_type)

        return {
            "impact_type": best_type,
            "confidence": confidence,
            "indicator_matches": best_score,
            "evidence": evidence,
        }

    def _flatten_items(self, items: list[dict]) -> str:
        """Flatten all item content into a single text blob."""
        parts = []
        for item in items:
            parts.append(json.dumps(item, default=str))
        return " ".join(parts)

    def _extract_evidence(self, items: list[dict], impact_type: str) -> list[str]:
        """Extract evidence snippets relevant to the impact type."""
        evidence = []
        indicators = _IMPACT_INDICATORS.get(impact_type, [])

        for item in items[:10]:  # cap at 10 items
            text_repr = json.dumps(item, default=str).lower()
            for ind in indicators:
                if ind in text_repr:
                    # Get a short evidence snippet
                    snippet = str(item.get("content", item.get("name", item.get("matched-at", ""))))
                    if snippet and len(snippet) > 200:
                        snippet = snippet[:200] + "..."
                    if snippet:
                        evidence.append(snippet)
                    break

        return evidence[:5]  # max 5 evidence items
