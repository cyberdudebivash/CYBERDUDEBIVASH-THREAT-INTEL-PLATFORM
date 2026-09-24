"""
apex_feed schema drift (P0 Phase 3C) -- producer/consumer contract.

ROOT CAUSE: two producers wrote the same public object, api/v1/intel/apex.json,
with incompatible schemas:
  - scripts/generate_api_manifests.py (sentinel-blogger STAGE 3.93): the FEED
    {schema_version, generated_at, generator, version, apex_enriched_count,
     count, items, sha256}
  - scripts/generate_dashboard_feeds.py (dashboard-feeds-sync.yml, 4x/day):
    a SUMMARY {defcon, global_threat_level, *_count, top_advisories, ...}
The public schema flipped with whichever workflow ran last. The canary's
baseline was recorded from the SUMMARY (2026-08-26) while its own contract
requires the FEED, and the canary overwrote its baseline on every run, so a
breaking change was reported once and then silently adopted.

Canonical authority: the FEED, produced only by generate_api_manifests.py
(documented in api-reference-card.html as the "Full APEX enriched feed", used
by welcome.html's paid quickstart, required by the canary contract).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import canary_contract_validator as ccv  # noqa: E402

APEX_EP = next(e for e in ccv.CANARY_ENDPOINTS if e["id"] == "apex_feed")
SYNC_WF = REPO / ".github" / "workflows" / "dashboard-feeds-sync.yml"

FEED_BODY = {
    "schema_version": "1.0", "generated_at": "2026-09-24T07:49:38Z", "generator": "generate_api_manifests.py",
    "version": "v200.0", "apex_enriched_count": 2, "count": 2, "sha256": "0" * 64,
    "items": [{"id": "intel--1", "title": "A", "risk_score": 8.1}, {"id": "intel--2", "title": "B", "risk_score": 6.0}],
}
SUMMARY_BODY = {  # the retired generate_dashboard_feeds.py shape
    "schema_version": "2.0", "generated_at": "2026-09-24T03:30:00Z", "generator": "generate_dashboard_feeds.py",
    "total_advisories": 53, "critical_count": 12, "defcon": {"level": 2}, "top_advisories": [],
}


# --- producer side -----------------------------------------------------------

def _apex_payload_keys() -> set[str]:
    src = (REPO / "scripts" / "generate_api_manifests.py").read_text(encoding="utf-8")
    block = re.search(r"apex_payload\s*=\s*\{(.*?)\n\}", src, re.DOTALL).group(1)
    keys = set(re.findall(r"'([a-z_0-9]+)'\s*:", block))
    if re.search(r"apex_payload\['sha256'\]\s*=", src):
        keys.add("sha256")
    return keys


def test_canonical_producer_satisfies_the_consumer_contract():
    keys = _apex_payload_keys()
    missing = set(APEX_EP["required_fields"]) - keys
    assert not missing, f"generate_api_manifests.py apex_payload lacks contract fields {missing}"
    assert "generator" in keys, "the producer must declare itself for the producer pin"


def test_dashboard_generator_no_longer_writes_apex_json(tmp_path):
    env = dict(os.environ, API_OUT_DIR=str(tmp_path), PIPELINE_VERSION="200.0")
    r = subprocess.run([sys.executable, "scripts/generate_dashboard_feeds.py"], cwd=REPO, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    written = sorted(p.name for p in tmp_path.iterdir())
    assert "apex.json" not in written, written
    assert "stats.json" in written  # the summary's counts/threat level live here
    stats = json.loads((tmp_path / "stats.json").read_text())
    assert stats["total"] > 0 and "global_threat_level" in stats


def test_dashboard_sync_workflow_never_publishes_apex_json():
    src = SYNC_WF.read_text(encoding="utf-8")
    upload = src[src.index('name: "Upload dashboard generation to Cloudflare R2"'):src.index('name: "Purge Cloudflare cache"')]
    assert "apex.json" not in upload
    purge = src[src.index('name: "Purge Cloudflare cache"'):src.index('name: "Production semantic canary"')]
    assert "apex.json" not in purge
    # Its empty-publication guard must not depend on apex.json's old SUMMARY fields.
    assert "total_advisories" not in src


def test_only_one_script_writes_apex_json():
    writers = []
    for py in sorted((REPO / "scripts").glob("*.py")):
        src = py.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"""(atomic_write|write_json|open)\([^)\n]*['"]apex\.json['"]""", src) or \
           re.search(r"""f?["']\{OUT_DIR\}/apex\.json["']\s*:""", src):
            writers.append(py.name)
    assert writers == ["generate_api_manifests.py"], writers


# --- consumer side (canary) -------------------------------------------------

def test_canary_accepts_the_canonical_feed():
    verdict, errors, _ = ccv.validate_endpoint(APEX_EP, FEED_BODY, 200, 100)
    assert verdict == "PASS", errors


def test_canary_rejects_the_retired_summary_shape_as_a_foreign_producer():
    verdict, errors, _ = ccv.validate_endpoint(APEX_EP, SUMMARY_BODY, 200, 100)
    assert verdict == "FAIL"
    assert any("Foreign producer" in e for e in errors), errors


def test_committed_baseline_matches_the_canonical_feed_shape():
    base = json.loads((REPO / "data" / "governance" / "api_baseline.json").read_text())
    fp = base["apex_feed"]["schema_fingerprint"]
    assert fp.get("items") == "list" and "count" in fp and "generator" in fp
    for summary_only in ("defcon", "top_advisories", "total_advisories", "global_threat_level"):
        assert summary_only not in fp


def _run_canary(monkeypatch, tmp_path, baseline_fp, body):
    monkeypatch.setattr(ccv, "CANARY_ENDPOINTS", [APEX_EP])
    monkeypatch.setattr(ccv, "BASELINE_PATH", tmp_path / "api_baseline.json")
    monkeypatch.setattr(ccv, "REPORT_PATH", tmp_path / "canary_contract.json")
    monkeypatch.setattr(ccv, "GOV_DIR", tmp_path)
    (tmp_path / "api_baseline.json").write_text(json.dumps(
        {"apex_feed": {"schema_fingerprint": baseline_fp, "last_checked": "x", "item_count": 2}}))
    monkeypatch.setattr(ccv, "fetch_endpoint", lambda url: (body, 200, 50.0, None))
    ccv.main()
    return json.loads((tmp_path / "api_baseline.json").read_text())["apex_feed"]["schema_fingerprint"]


def test_breaking_drift_does_not_overwrite_the_baseline(monkeypatch, tmp_path):
    feed_fp = ccv.compute_schema_fingerprint(FEED_BODY)
    after = _run_canary(monkeypatch, tmp_path, feed_fp, SUMMARY_BODY)
    assert after == feed_fp, "a breaking change must not be adopted as the new baseline"


def test_compatible_run_still_refreshes_the_baseline(monkeypatch, tmp_path):
    feed_fp = ccv.compute_schema_fingerprint(FEED_BODY)
    older = {k: v for k, v in feed_fp.items() if k != "sha256"}  # additive change only
    after = _run_canary(monkeypatch, tmp_path, older, FEED_BODY)
    assert after == feed_fp


def test_internal_manifest_registry_is_not_probed_as_a_public_route(monkeypatch, tmp_path):
    # /api/v1/intel/manifest.json is not routed by the gateway (404 on every
    # run); it is validated in-pipeline by validate_api_manifests.py.
    src = (REPO / "workers" / "intel-gateway" / "src" / "index.js").read_text(encoding="utf-8")
    assert '"/api/v1/intel/manifest.json"' not in src, "if it becomes a public route, re-enable the probe"
    ep = next(e for e in ccv.CANARY_ENDPOINTS if e["id"] == "manifest_registry")
    assert ep["public"] is False
    fetched = []
    monkeypatch.setattr(ccv, "CANARY_ENDPOINTS", [ep])
    monkeypatch.setattr(ccv, "BASELINE_PATH", tmp_path / "b.json")
    monkeypatch.setattr(ccv, "REPORT_PATH", tmp_path / "r.json")
    monkeypatch.setattr(ccv, "GOV_DIR", tmp_path)
    monkeypatch.setattr(ccv, "fetch_endpoint", lambda url: fetched.append(url) or (None, 404, 1.0, "HTTP 404"))
    assert ccv.main() == 0
    assert fetched == []
