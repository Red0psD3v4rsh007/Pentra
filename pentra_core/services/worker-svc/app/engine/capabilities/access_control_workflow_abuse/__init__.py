"""Access-control and workflow-abuse capability pack."""

from .analysis import (
    build_access_control_workflow_abuse_pack,
    load_access_control_workflow_abuse_capability_manifest,
)


def build_capability_pack(**kwargs):
    return build_access_control_workflow_abuse_pack(
        base_url=kwargs["base_url"],
        scan_config=kwargs["scan_config"],
        pages=kwargs.get("pages") or [],
        forms=kwargs.get("forms") or [],
        sessions=kwargs.get("sessions") or [],
        workflows=kwargs.get("workflows") or [],
        replays=kwargs.get("replays") or [],
        probe_findings=kwargs.get("probe_findings") or [],
        capability_results=kwargs.get("capability_results") or {},
    )


__all__ = [
    "build_access_control_workflow_abuse_pack",
    "build_capability_pack",
    "load_access_control_workflow_abuse_capability_manifest",
]
