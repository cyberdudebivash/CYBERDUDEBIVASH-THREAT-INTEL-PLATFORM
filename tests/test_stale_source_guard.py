"""
Stale source articles are not new intelligence.

Production /api/v1/intel/latest.json (2026-09-26T06:28Z, 42 items): 12 items
were articles their sources published 2026-01-14 .. 2026-08-07, ingested by
the 06:00Z run, leading the newest-first feed, each "intelligence_age_days: 0",
10 with no source link. See scripts/source_publication_age.py.
"""
import ast
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import source_publication_age as spa  # noqa: E402
import stale_source_guard as ssg  # noqa: E402

NOW = datetime(2026, 9, 26, 7, 0, tzinfo=timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- parsing ---------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("2026-01-14T10:00:00-08:00", datetime(2026, 1, 14, 18, 0, tzinfo=timezone.utc)),
    ("2026-09-25T21:38:15Z", datetime(2026, 9, 25, 21, 38, 15, tzinfo=timezone.utc)),
    ("Tue, 22 Jul 2026 01:10:38 +0000", datetime(2026, 7, 22, 1, 10, 38, tzinfo=timezone.utc)),
    ("2026-09-25", datetime(2026, 9, 25, tzinfo=timezone.utc)),
])
def test_parses_source_dates(value, expected):
    assert spa.parse_source_datetime(value) == expected


@pytest.mark.parametrize("value", [None, "", True, False, "True", "not a date"])
def test_unreadable_dates_are_none(value):
    assert spa.parse_source_datetime(value) is None


def test_pipeline_clocks_are_never_read_as_source_date():
    item = {"timestamp": _iso(0), "processed_at": _iso(0), "created": _iso(0)}
    assert spa.source_age_days(item, now=NOW) is None


# --- the rule --------------------------------------------------------------

def test_live_january_article_is_stale():
    item = {"title": "A 0-click exploit chain for the Pixel 9 Part 2",
            "published_at": "2026-01-14T10:00:00-08:00", "processed_at": _iso(0)}
    assert spa.is_stale_source(item, now=NOW)


def test_window_boundary():
    assert not spa.is_stale_source({"published_at": _iso(13.9)}, max_age_days=14, now=NOW)
    assert spa.is_stale_source({"published_at": _iso(14.1)}, max_age_days=14, now=NOW)


def test_undated_item_is_kept():
    assert not spa.is_stale_source({"title": "No date"}, now=NOW)


def test_rss_entry_published_string_is_read():
    entry = {"title": "LG to Ban Residential Proxies", "published": "Wed, 22 Jul 2026 01:10:38 +0000"}
    assert spa.is_stale_source(entry, now=NOW)


def test_kev_confirmed_is_exempt_but_kev_no_is_not():
    old = _iso(120)
    assert not spa.is_stale_source({"published_at": old, "kev_present": True}, now=NOW)
    assert not spa.is_stale_source({"published_at": old, "kev": "YES"}, now=NOW)
    assert spa.is_stale_source({"published_at": old, "kev": "NO"}, now=NOW)


def test_active_exploitation_title_is_exempt():
    item = {"published_at": _iso(90), "title": "Old Fortinet flaw exploited in the wild"}
    assert not spa.is_stale_source(item, now=NOW)


def test_future_date_is_not_stale():
    assert not spa.is_stale_source({"published_at": _iso(-2)}, now=NOW)


def test_env_window(monkeypatch):
    assert spa._env_days("X_UNSET_DAYS", 14) == 14
    monkeypatch.setenv("X_DAYS", "30")
    assert spa._env_days("X_DAYS", 14) == 30
    for bad in ("0", "-3", "abc"):
        monkeypatch.setenv("X_DAYS", bad)
        assert spa._env_days("X_DAYS", 14) == 14


# --- the guard -------------------------------------------------------------

def _feed(n_fresh, n_stale):
    fresh = [{"id": f"intel--f{i}", "title": f"fresh {i}", "published_at": _iso(1)} for i in range(n_fresh)]
    stale = [{"id": f"intel--s{i}", "title": f"stale {i}", "published_at": _iso(60)} for i in range(n_stale)]
    return stale + fresh


def _write(tmp, name, data):
    p = Path(tmp) / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_guard_prunes_list_feed():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, "feed.json", _feed(30, 12))
        res = ssg.guard_file(p, NOW)
        assert res["status"] == "PRUNED" and res["before"] == 42 and res["after"] == 30
        assert {r["id"] for r in res["removed"]} == {f"intel--s{i}" for i in range(12)}
        out = json.loads(p.read_text())
        assert len(out) == 30 and all(i["id"].startswith("intel--f") for i in out)


def test_guard_prunes_dict_manifest_and_count():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, "m.json", {"count": 42, "advisories": _feed(30, 12)})
        assert ssg.guard_file(p, NOW)["status"] == "PRUNED"
        out = json.loads(p.read_text())
        assert out["count"] == 30 and len(out["advisories"]) == 30


def test_guard_never_leaves_fewer_than_floor():
    with tempfile.TemporaryDirectory() as tmp:
        data = _feed(5, 20)
        p = _write(tmp, "feed.json", data)
        res = ssg.guard_file(p, NOW)
        assert res["status"] == "HELD" and res["would_remove"] == 20
        assert json.loads(p.read_text()) == data  # untouched


def test_guard_clean_and_missing():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, "feed.json", _feed(12, 0))
        before = p.read_text()
        assert ssg.guard_file(p, NOW)["status"] == "CLEAN"
        assert p.read_text() == before
        assert ssg.guard_file(Path(tmp) / "absent.json", NOW)["status"] == "SKIPPED"


def test_guard_on_live_snapshot_shape():
    """The 12 live stale items (ids, dates, titles as served) are removed; the
    30 items published 2026-09-23 .. 09-26 are kept."""
    stale = [
        ("intel--1790403273", "2026-01-14T10:00:00-08:00", "A 0-click exploit chain for the Pixel 9 Part 2"),
        ("intel--1790403250_CVE-2025-54957", "2026-05-13T00:00:00-07:00", "Medium: A 0-click exploit chain for the Pixel 10"),
        ("intel--1790402979", "2026-08-07T13:00:57Z", "The Good, the Bad and the Ugly in Cybersecurity  Week 32 (2026)"),
        ("intel--1790402548", "2026-07-22T01:10:38Z", "LG to Ban Residential Proxies from Smart TV Apps"),
    ]
    items = [{"id": i, "published_at": d, "title": t, "kev": "NO"} for i, d, t in stale]
    items += [{"id": f"intel--live{i}", "published_at": "2026-09-25T21:38:15Z", "title": "GHSA"} for i in range(30)]
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, "feed.json", items)
        res = ssg.guard_file(p, NOW)
        assert res["after"] == 30 and {r["id"] for r in res["removed"]} == {s[0] for s in stale}


# --- wiring ----------------------------------------------------------------

def _function_source(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(f"{name} not found in {path}")


def test_ingest_gate_rejects_stale_entry():
    """Runs the real is_temporally_relevant() / _stale_source_check() from
    agent/sentinel_blogger.py (extracted, so the heavy agent imports are not
    needed)."""
    import logging
    import os
    import re as _re
    path = REPO / "agent" / "sentinel_blogger.py"
    ns = {"os": os, "sys": sys, "re": _re, "logger": logging.getLogger("t"),
          "datetime": datetime, "_tz": timezone,
          "CVE_MAX_AGE_YEARS": 2, "CVE_EPSS_EXCEPTION": 70.0,
          "__file__": str(path)}
    exec(_function_source(path, "_stale_source_check"), ns)
    exec(_function_source(path, "is_temporally_relevant"), ns)
    fresh_pub = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    assert ns["is_temporally_relevant"]({"title": "Week 30 recap", "published": "Fri, 24 Jul 2026 13:00:12 +0000"}) is False
    assert ns["is_temporally_relevant"]({"title": "New campaign", "published": fresh_pub}) is True
    assert ns["is_temporally_relevant"]({"title": "No date at all"}) is True


def test_stix_reconstruction_filters_on_source_date():
    src = _function_source(REPO / "scripts" / "run_pipeline.py", "stage_sync_root_feed_json")
    assert "_is_stale_source({\"published_at\": _cdb_pub_at" in src


def test_quality_scorer_ages_from_source_date():
    import intelligence_quality_scorer as iqs
    item = {"published_at": "2026-01-14T10:00:00-08:00",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert iqs._compute_age_days(item) > 200


def test_stix_bundle_carries_source_url():
    from agent.export_stix import STIXExporter
    with tempfile.TemporaryDirectory() as tmp:
        STIXExporter(output_dir=tmp).create_bundle(
            title="Source attribution survives the STIX round-trip",
            iocs={}, risk_score=5.0,
            metadata={"source_url": "https://example.com/article"},
            published_at="2026-09-25T10:00:00Z",
        )
        bundle = json.loads(sorted(Path(tmp).glob("CDB-APEX-*.json"))[-1].read_text())
    intset = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
    ext = intset["extensions"]["x-cdb-apex-1"]
    assert ext["x_cdb_source_url"] == "https://example.com/article"
    assert ext["x_cdb_published_at"] == "2026-09-25T10:00:00Z"


def test_workflow_runs_guard_before_enrichment_and_before_manifests():
    wf = (REPO / ".github" / "workflows" / "sentinel-blogger.yml").read_text(encoding="utf-8")
    i_orch = wf.index('name: "STAGE 1-3 - Master Pipeline Orchestrator"')
    i_g1 = wf.index("scripts/stale_source_guard.py post-ingest")
    i_enrich = wf.index('name: "STAGE 3.1 - APEX AI Feed Enrichment')
    i_reports = wf.index('name: "STAGE 3.2 - Generate Internal HTML Reports')
    i_g2 = wf.index("scripts/stale_source_guard.py pre-manifest")
    i_manifest = wf.index('name: "STAGE 3.93.19 - Re-generate Immutable API Manifests')
    assert i_orch < i_g1 < i_enrich < i_reports
    assert i_g2 < i_manifest
