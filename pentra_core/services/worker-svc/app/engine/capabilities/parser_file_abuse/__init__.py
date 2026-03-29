"""Parser, file, and upload abuse capability pack."""

from .analysis import (
    build_parser_file_abuse_pack,
    load_parser_file_abuse_capability_manifest,
)


def build_capability_pack(**kwargs):
    return build_parser_file_abuse_pack(
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
    "build_parser_file_abuse_pack",
    "load_parser_file_abuse_capability_manifest",
]
