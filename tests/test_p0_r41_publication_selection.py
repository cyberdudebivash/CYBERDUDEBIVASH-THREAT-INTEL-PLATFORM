"""P0 R41: a poisoned historical batch cannot starve eligible source evidence."""
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import p0_r35_feed_prewrite_guard as guard
from agent.p0_r39_evidence import capture_rss_evidence
from agent.v70_apex_upgrade.core.models import Manifest, advisory_from_legacy
from agent.v70_apex_upgrade.core.manifest_manager import ManifestManager
from agent.v70_apex_upgrade.orchestrator import _convert_real_advisory


def valid_record(i="valid"):
    now = datetime.now(timezone.utc)
    source_time = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": i, "stix_id": i, "title": "Publisher reported security incident " + i,
        "description": "Source investigation with observed supporting evidence.",
        "source": "Publisher", "source_name": "publisher.example",
        "source_url": "https://publisher.example/security/" + i,
        "publication_timestamp": source_time, "published_at": source_time,
        "retrieval_timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp": source_time, "content_hash": "a" * 64,
        "content_hash_scope": "rss_entry_fields_sha256", "trust_score": 8.2,
        "evidence_count": 1, "evidence_basis": ["captured_rss_entry"],
        "severity": "MEDIUM", "risk_score": 5.0, "tlp": "TLP:CLEAR",
        "actors": [], "tags": [], "report_url": "/reports/2026/10/" + i + ".html",
        "sources": [{"tlp": "TLP:CLEAR", "capture": {"id": "original"}}],
    }


def test_select_before_cap_keeps_valid_minority_without_mutating_inventory():
    rows = [{"id": f"old-{i}", "title": "Historical record"} for i in range(510)]
    rows += [valid_record(str(i)) for i in range(3)]
    original = copy.deepcopy(rows)
    selected, held = guard.select_publishable(rows, limit=2)
    assert [r["id"] for r in selected] == ["0", "1"]
    assert len(held) == 510
    assert rows == original
    assert all(set(r) == {"id", "reason_code", "reason"} for r in held)
    guard.assert_publishable(selected)


@pytest.mark.parametrize("change,reason", [
    ({"tlp": "TLP:AMBER"}, "RESTRICTED_LABEL"),
    ({"sources": [{"tlp": "TLP:RED"}]}, "RESTRICTED_UPSTREAM_LABEL"),
    ({"tlp": None}, "MISSING_LABEL"),
    ({"source": "SENTINEL-APEX"}, "PREWRITE_DENIED"),
    ({"publication_timestamp": "2020-01-01T00:00:00Z"}, "PREWRITE_DENIED"),
    ({"content_hash": ""}, "PREWRITE_DENIED"),
    ({"actor_tag": "UNC-CDB"}, "PREWRITE_DENIED"),
])
def test_denial_rules_are_preserved(change, reason):
    denied = {**valid_record("denied"), **change}
    selected, held = guard.select_publishable([denied, valid_record()])
    assert [r["id"] for r in selected] == ["valid"]
    assert held[0]["reason_code"] == reason



@pytest.mark.parametrize("rejected_fields", [
    {"title": "CVE-2026-97028 - Rejected reason: Maintainers determined it is not a vulnerability",
     "cve_id": "CVE-2026-97028"},
    {"title": "CVE-2026-109111: Rejected reason: This CVE ID has been rejected",
     "cve_id": "CVE-2026-109111"},
    {"cve_id": "CVE-2026-111326", "vuln_status": "Rejected"},
    {"cve_id": "CVE-2026-108537", "cve_status": "WITHDRAWN"},
    {"cve_id": "CVE-2026-108793", "cve_lifecycle": "REJECTED"},
])
def test_rejected_cve_lifecycle_is_withheld_without_modifying_source(rejected_fields):
    rejected = {**valid_record("rejected"), **rejected_fields}
    eligible = valid_record("eligible")
    original = copy.deepcopy([rejected, eligible])
    selected, held = guard.select_publishable([rejected, eligible])
    assert [r["id"] for r in selected] == ["eligible"]
    assert held == [{
        "id": "rejected", "reason_code": "CVE_LIFECYCLE_REJECTED",
        "reason": "Explicitly rejected or withdrawn CVE; historical record only",
    }]
    assert [rejected, eligible] == original
    with pytest.raises(ValueError, match="P0_FEED_PREWRITE_BLOCKED: CVE_LIFECYCLE_REJECTED"):
        guard.assert_publishable([rejected])


@pytest.mark.parametrize("fields", [
    {"title": "Research discussion about rejected CVE IDs", "cve_id": "CVE-2026-97028"},
    {"title": "CVE-2026-97028 - Security patch released", "cve_id": "CVE-2026-97028"},
    {"title": "CVE-2026-97028 - Rejected reason appears in a quoted source",
     "cve_id": "CVE-2026-97028", "cve_status": "PUBLISHED"},
])
def test_rejected_cve_filter_is_conservative(fields):
    row = {**valid_record("article"), **fields}
    selected, held = guard.select_publishable([row])
    # A title explicitly identifying a rejected CVE cannot be overridden by
    # an inconsistent PUBLISHED status supplied by another source.
    if row["title"].startswith("CVE-2026-97028 - Rejected reason"):
        assert not selected and held[0]["reason_code"] == "CVE_LIFECYCLE_REJECTED"
    else:
        assert selected == [row] and held == []



def test_empty_selection_still_blocks_and_does_not_invent_evidence():
    original = [{"id": "unproven", "title": "A source report"}, None]
    rows = copy.deepcopy(original)
    selected, held = guard.select_publishable(rows)
    assert selected == [] and len(held) == 2
    assert rows == original
    with pytest.raises(ValueError, match="P0_FEED_PREWRITE_BLOCKED"):
        guard.assert_publishable(selected)


def test_validator_crash_never_turns_into_publication(monkeypatch):
    def crash(_):
        raise RuntimeError("validation dependency failed")
    monkeypatch.setattr(guard, "check_mandate_3", crash)
    with pytest.raises(RuntimeError, match="validation dependency failed"):
        guard.select_publishable([valid_record()])


@pytest.mark.parametrize("factory", [_convert_real_advisory, advisory_from_legacy])
def test_enrichment_preserves_source_evidence_clocks_and_nested_restrictions(factory):
    item = valid_record()
    item["sources"].append({"tlp": "TLP:AMBER", "capture": {"id": "restricted"}})
    original = copy.deepcopy(item)
    advisory = factory(item)
    for output in (advisory.to_dict(), advisory.to_legacy_dict()):
        for key in ("id", "source_name", "source_url", "publication_timestamp",
                    "retrieval_timestamp", "content_hash", "content_hash_scope",
                    "trust_score", "evidence_count", "evidence_basis", "tlp", "sources"):
            assert output[key] == original[key], key
        assert advisory.published_date == original["publication_timestamp"]
        selected, held = guard.select_publishable([output])
        assert not selected
        assert held[0]["reason_code"] == "RESTRICTED_UPSTREAM_LABEL"
        output["sources"][0]["capture"]["id"] = "changed"
    assert item == original
    assert advisory.to_legacy_dict()["sources"] == original["sources"]


def test_actual_observation_survives_versioned_manifest_publication(tmp_path):
    now = datetime.now(timezone.utc)
    reg = tmp_path / "trust.json"
    reg.write_text(json.dumps({"trust_scores": {"publisher.example": {"trust_score": 0.82}}}))
    entry = {"title": "Publisher security investigation", "summary": "Observed RSS fields",
             "link": "https://publisher.example/security/report",
             "published": (now - timedelta(hours=1)).isoformat()}
    observed = capture_rss_evidence(entry, "https://publisher.example/rss", now.isoformat(), reg)
    item = {**valid_record(), **observed, "title": entry["title"]}
    mgr = ManifestManager(str(tmp_path / "data"))
    success, message = mgr.publish(Manifest(), [_convert_real_advisory(item)])
    assert success, message
    published = json.loads(Path(mgr.latest_path).read_text())["advisories"]
    selected, held = guard.select_publishable(published)
    assert len(selected) == 1 and not held
    for key, value in observed.items():
        assert selected[0][key] == value
    assert list(Path(mgr.versioned_dir).glob("manifest_v*.json"))


def test_missing_provenance_stays_missing_after_enrichment():
    item = {"title": "A report without evidence", "source": "Publisher"}
    out = _convert_real_advisory(item).to_legacy_dict()
    for key in ("retrieval_timestamp", "publication_timestamp", "content_hash", "trust_score"):
        assert key not in out
    assert not guard.select_publishable([out])[0]


def test_dedup_cannot_launder_restricted_components_into_clear_primary():
    from agent.v70_apex_upgrade.engines.dedup_engine import DedupEngine
    clear = valid_record("clear")
    restricted = {**valid_record("restricted"), "source_url": clear["source_url"],
                  "sources": [{"tlp": "TLP:AMBER", "capture": {"id": "partner"}}]}
    original = copy.deepcopy(restricted)
    result = DedupEngine().deduplicate([_convert_real_advisory(clear), _convert_real_advisory(restricted)])
    assert len(result) == 1
    selected, held = guard.select_publishable([result[0].to_legacy_dict()])
    assert selected == [] and held[0]["reason_code"] == "RESTRICTED_UPSTREAM_LABEL"
    assert restricted == original


@pytest.mark.parametrize("has_valid", [True, False])
@pytest.mark.parametrize("broken_quality_output", [True, False])
def test_real_feed_writer_withholds_history_and_preserves_both_previous_files(tmp_path, monkeypatch, has_valid, broken_quality_output):
    import run_pipeline
    import intel_quality_engine
    monkeypatch.setattr(run_pipeline, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(intel_quality_engine, "apply_quality_pipeline", lambda rows: None if broken_quality_output else rows)
    rows = [{"id": f"old-{i}", "title": f"Historical source record {i}",
             "timestamp": "2026-10-10T00:00:00Z"} for i in range(510)]
    if has_valid:
        rows.append(valid_record())
    manifest = tmp_path / "data/stix/feed_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(rows))
    targets = [tmp_path / "feed.json", tmp_path / "api/feed.json"]
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('[{"id":"previous-authoritative"}]')
    if not has_valid:
        with pytest.raises(ValueError, match="P0_FEED_PREWRITE_BLOCKED"):
            run_pipeline.stage_sync_root_feed_json()
        assert all(target.read_text() == '[{"id":"previous-authoritative"}]' for target in targets)
    else:
        run_pipeline.stage_sync_root_feed_json()
        for target in targets:
            assert [r["id"] for r in json.loads(target.read_text())] == ["valid"]
        history = json.loads(manifest.read_text())["advisories"]
        assert len(history) == 511, "internal history must not be silently lost"
    audit = json.loads((tmp_path / "data/quality/p0_r41_publication_selection.json").read_text())
    assert audit["withheld_count"] == 510


def test_ingestion_audit_cannot_manufacture_provenance():
    source = (ROOT / "scripts/run_pipeline.py").read_text()
    stage = source[source.index("# ---- Stage 1.91:"):source.index("    stage_run_intel_engine()", source.index("# ---- Stage 1.91:"))]
    assert '"--report"' in stage
    assert '"--fix"' not in stage


def test_unproven_inventory_cannot_consume_source_balance_slots(tmp_path, monkeypatch):
    import run_pipeline
    monkeypatch.setattr(run_pipeline, "REPO_ROOT", tmp_path)
    old = [{"id": f"old-{i}", "stix_id": f"old-{i}",
            "title": f"Historical vulnerability notice {i}",
            "feed_source": "rss_cvefeed_io_rssfeed_latest_xml", "source": "cvefeed.io",
            "source_url": f"https://cvefeed.io/old/{i}",
            "published_at": "2026-10-09T08:00:00Z", "timestamp": "2026-10-09T08:00:00Z",
            "risk_score": 8.0, "cvss_score": 8.0, "severity": "HIGH"} for i in range(510)]
    new_low = [{**valid_record(f"low-{i}"), "risk_score": 2.0,
                "feed_source": "rss_cvefeed_io_rssfeed_latest_xml"} for i in range(21)]
    new_high = [{**valid_record(f"high-{i}"),
                 "feed_source": "rss_cybersecuritynews_com_feed_"} for i in range(3)]
    manifest = tmp_path / "data/stix/feed_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(old + new_low + new_high))
    run_pipeline.stage_sync_root_feed_json()
    published = json.loads((tmp_path / "api/feed.json").read_text())
    # Existing source cap remains 45% of the eligible 24 candidates: 10
    # lower-quality-source records plus the 3 higher-quality-source records.
    assert len(published) == 13
    assert sum(r["id"].startswith("low-") for r in published) == 10
    assert sum(r["id"].startswith("high-") for r in published) == 3
    assert all(not r["id"].startswith("old-") for r in published)
    assert len(json.loads(manifest.read_text())["advisories"]) == 534
    audit = json.loads((tmp_path / "data/quality/p0_r41_publication_selection.json").read_text())
    assert audit["candidate_count"] == 534 and audit["withheld_count"] == 510
    assert audit["quality_or_cap_filtered_count"] == 11
    guard.assert_publishable(published)


def test_legacy_hardener_cannot_replace_ingestion_host_trust_registry(tmp_path, monkeypatch):
    import v149_intelligence_hardening as hardener
    monkeypatch.setattr(hardener, "REPO", tmp_path)
    registry = tmp_path / "data/quality/source_trust_scores.json"
    registry.parent.mkdir(parents=True)
    original = (ROOT / "data/quality/source_trust_scores.json").read_bytes()
    registry.write_bytes(original)
    hardener.write_source_trust_registry()
    assert registry.read_bytes() == original
    legacy = json.loads(registry.with_name("source_trust_scores_v149.json").read_text())
    assert legacy["trust_scores"]["cvefeed.io"] == hardener.SOURCE_TRUST_MAP["cvefeed.io"]


def test_real_ingestion_hardening_handoff_preserves_eligible_evidence(tmp_path, monkeypatch):
    import run_pipeline
    import clean_feed_manifest
    import v149_intelligence_hardening as hardener
    from agent.export_stix import STIXExporter
    from agent.p0_r39_evidence import append_fetched_article_evidence

    monkeypatch.setattr(hardener, "REPO", tmp_path)
    monkeypatch.setattr(run_pipeline, "REPO_ROOT", tmp_path)
    registry = tmp_path / "data/quality/source_trust_scores.json"
    registry.parent.mkdir(parents=True)
    registry.write_bytes((ROOT / "data/quality/source_trust_scores.json").read_bytes())
    expected_trust = json.loads(registry.read_text())["trust_scores"]["cvefeed.io"]["trust_score"] * 10
    # Execute the real production predecessor, rather than injecting capture
    # metadata after the legacy hardener has already overwritten the registry.
    hardener.write_source_trust_registry()
    now = datetime.now(timezone.utc)
    source_time = (now - timedelta(hours=1)).isoformat()
    exporter = STIXExporter(output_dir=str(tmp_path / "data/stix"))
    observed_records = []
    for i in range(12):
        entry = {"title": f"Security publisher vulnerability investigation {i}",
                 "content": "Original captured RSS content",
                 "link": f"https://cvefeed.io/vuln/detail/observed-{i}", "published": source_time}
        observed = capture_rss_evidence(entry, "https://cvefeed.io/rssfeed/latest.xml", now.isoformat(), registry)
        assert observed["trust_score"] == round(expected_trust, 2)
        observed = append_fetched_article_evidence(observed, {
            "fetch_status": "success", "full_text": "Separately fetched original source article content",
        })
        observed_records.append(observed)
        exporter.create_bundle(title=entry["title"], iocs={}, risk_score=5.0,
                               metadata={"source_url": entry["link"], **observed},
                               published_at=observed["publication_timestamp"],
                               feed_source=observed["source_name"], actor_tag="UNATTRIBUTED",
                               severity="MEDIUM", mitre_tactics=["T1190"])
    manifest = tmp_path / "data/stix/feed_manifest.json"
    monkeypatch.setattr(clean_feed_manifest, "MANIFEST_PATH", manifest)
    assert clean_feed_manifest.main() == 0
    run_pipeline.stage_dedup_and_enrich()
    # The actual final writer includes the production quality pipeline and
    # unchanged mandate/TLP eligibility gate; no mocked eligibility shortcut.
    run_pipeline.stage_sync_root_feed_json()
    for target in (tmp_path / "feed.json", tmp_path / "api/feed.json"):
        published = json.loads(target.read_text())
        assert len(published) == 12
        guard.assert_publishable(published)
        for item in published:
            source = next(r for r in observed_records if r["source_url"] == item["source_url"])
            for key in ("source_name", "publication_timestamp", "retrieval_timestamp",
                        "content_hash", "content_hash_scope", "evidence_count", "trust_score"):
                assert item[key] == source[key], key
