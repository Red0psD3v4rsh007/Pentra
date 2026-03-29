"""Multi-role stateful auth capability pack."""

from .analysis import (
    build_multi_role_stateful_auth_pack,
    load_multi_role_stateful_auth_capability_manifest,
)


def build_capability_pack(**kwargs):
    return build_multi_role_stateful_auth_pack(
        base_url=kwargs["base_url"],
        scan_config=kwargs["scan_config"],
        pages=kwargs.get("pages") or [],
        forms=kwargs.get("forms") or [],
        sessions=kwargs.get("sessions") or [],
        workflows=kwargs.get("workflows") or [],
        replays=kwargs.get("replays") or [],
        probe_findings=kwargs.get("probe_findings") or [],
    )


__all__ = [
    "build_capability_pack",
    "build_multi_role_stateful_auth_pack",
    "load_multi_role_stateful_auth_capability_manifest",
]
