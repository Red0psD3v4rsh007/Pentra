"""Safe browser-aware XSS capability pack."""

from .analysis import (
    build_browser_xss_pack,
    extract_dom_xss_markers,
    load_browser_xss_capability_manifest,
    summarize_browser_xss_verification_feedback,
)
from .payloads import (
    build_browser_xss_payload_plan,
    instantiate_browser_xss_canary_plan,
    load_browser_xss_payload_registry,
    select_browser_xss_payload_archetype,
)
from .verifier import summarize_canary_observations, verify_browser_xss_canary


def build_capability_pack(**kwargs):
    return build_browser_xss_pack(
        base_url=kwargs["base_url"],
        scan_config=kwargs["scan_config"],
        pages=kwargs.get("pages") or [],
        forms=kwargs.get("forms") or [],
    )


__all__ = [
    "build_capability_pack",
    "build_browser_xss_pack",
    "build_browser_xss_payload_plan",
    "extract_dom_xss_markers",
    "instantiate_browser_xss_canary_plan",
    "load_browser_xss_capability_manifest",
    "load_browser_xss_payload_registry",
    "select_browser_xss_payload_archetype",
    "summarize_browser_xss_verification_feedback",
    "summarize_canary_observations",
    "verify_browser_xss_canary",
]
