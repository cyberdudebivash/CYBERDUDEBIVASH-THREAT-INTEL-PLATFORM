"""v201 is the only release customers should see on the live dashboard and in Actions.

Section banners (NEXUS, GENESIS, Bug Hunter, TIP/SOAR) and the threat-map HUD
were outside customer_release_label.py, which ignores non-JSON-LD scripts and
only matches SENTINEL APEX labels. Workflow display names are the Actions tab.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_dashboard_sections_and_map_hud_are_v201():
    src = (REPO / "index.html").read_text(encoding="utf-8")
    for label in (
        "NEXUS INTELLIGENCE v201.0",
        "Full-Stack AI Cybersecurity Ecosystem v201.0",
        "GENESIS v201.0",
        "BUG HUNTER v201.0",
        "TIP + SOAR COMMAND CENTER v201.0",
        "label     : 'CDB-SENTINEL v201'",
        "version   : '201.0.0'",
    ):
        assert label in src, label
    for stale in (
        "NEXUS INTELLIGENCE v134.0",
        "Ecosystem v134.0",
        "GENESIS v134.0",
        "BUG HUNTER v134.0",
        "COMMAND CENTER v63.0",
        "CDB-SENTINEL v173",
        "2026.05.20-V173",
    ):
        assert stale not in src, stale


def test_feed_panels_accept_a_raw_array_and_do_not_require_cdb_normalize():
    src = (REPO / "index.html").read_text(encoding="utf-8")
    assert "function eiccItems(" in src
    assert "eiccItems(result.data)" in src
    assert "eiccItems(data)" in src
    assert "eiccNewestMs(" in src
    assert "var _norm = window.CDB_NORMALIZE" in src
    assert "cdb-darkweb-live" in src
    assert "eicc-heatmap-sub" in src
    assert "API ● CHECKING" in src


def test_every_workflow_display_name_is_v201():
    missing = []
    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("name:"):
                if "v201.0" not in line:
                    missing.append(f"{path.name}: {line}")
                break
        else:
            missing.append(f"{path.name}: no workflow name")
    assert missing == []
