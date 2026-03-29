from __future__ import annotations


def test_recon_phase_template_has_no_orphan_report_phase() -> None:
    from app.engine.dag_builder import _PHASES

    recon_phase_numbers = [phase.number for phase in _PHASES["recon"]]
    recon_phase_names = [phase.name for phase in _PHASES["recon"]]

    assert recon_phase_numbers == [0, 1]
    assert recon_phase_names == ["scope_validation", "recon"]


def test_external_web_api_recon_profile_tools_fit_recon_phases() -> None:
    from pentra_common.profiles import prepare_scan_config
    from app.engine.dag_builder import _select_tools

    config = prepare_scan_config(
        scan_type="recon",
        asset_type="api",
        asset_target="http://127.0.0.1:8088",
        config={"profile_id": "external_web_api_v1"},
    )

    tools = _select_tools("recon", "api", config)
    assert tools is not None

    tool_names = [tool.name for tool in tools]
    assert tool_names == ["scope_check", "httpx_probe"]
    assert max(tool.phase for tool in tools) == 1


def test_external_web_api_vuln_profile_includes_ai_and_report_phases() -> None:
    from pentra_common.profiles import prepare_scan_config
    from app.engine.dag_builder import _select_tools

    config = prepare_scan_config(
        scan_type="vuln",
        asset_type="api",
        asset_target="http://127.0.0.1:8088",
        config={"profile_id": "external_web_api_v1"},
    )

    tools = _select_tools("vuln", "api", config)
    assert tools is not None

    tool_names = [tool.name for tool in tools]
    assert "ai_triage" in tool_names
    assert "report_gen" in tool_names
    assert "tech_detect" not in tool_names
    assert "cors_check" not in tool_names
    assert "header_audit" not in tool_names


def test_external_web_api_full_profile_has_unique_derived_tools() -> None:
    from pentra_common.profiles import prepare_scan_config
    from app.engine.dag_builder import _select_tools

    config = prepare_scan_config(
        scan_type="full",
        asset_type="api",
        asset_target="http://127.0.0.1:8088",
        config={"profile_id": "external_web_api_v1"},
    )

    tools = _select_tools("full", "api", config)
    assert tools is not None

    tool_names = [tool.name for tool in tools]
    assert tool_names.count("ai_triage") == 1
    assert tool_names.count("report_gen") == 1
