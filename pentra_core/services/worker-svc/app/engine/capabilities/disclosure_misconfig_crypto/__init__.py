"""Disclosure, misconfiguration, crypto, and components capability pack."""

from .analysis import (
    build_disclosure_misconfig_crypto_pack,
    load_disclosure_misconfig_crypto_capability_manifest,
)


def build_capability_pack(**kwargs):
    return build_disclosure_misconfig_crypto_pack(
        base_url=kwargs["base_url"],
        scan_config=kwargs["scan_config"],
        pages=kwargs.get("pages") or [],
        forms=kwargs.get("forms") or [],
        sessions=kwargs.get("sessions") or [],
        replays=kwargs.get("replays") or [],
        probe_findings=kwargs.get("probe_findings") or [],
        capability_results=kwargs.get("capability_results") or {},
    )


__all__ = [
    "build_capability_pack",
    "build_disclosure_misconfig_crypto_pack",
    "load_disclosure_misconfig_crypto_capability_manifest",
]
