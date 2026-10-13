"""Later collectors cannot bypass eligibility at public upload/bundle writes."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
from agent.p0_r39_evidence import capture_rss_evidence
from multi_source_collector import _make_item
from p0_r44_publication_boundary import finalize_public_feed


def candidates(root):
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    trust = root / "trust.json"
    trust.write_text(json.dumps({"trust_scores": {"publisher.example": {"trust_score": 0.82}}}))
    observed = []
    for n in range(12):
        entry = {"title": f"Publisher security investigation {n}", "summary": "Captured RSS source report",
                 "link": f"https://publisher.example/report/{n}", "published": stamp, "tlp": "TLP:CLEAR"}
        evidence = capture_rss_evidence(entry, "https://publisher.example/rss", now.isoformat(), trust)
        observed.append({**evidence, "id": f"observed-{n}", "stix_id": f"observed-{n}",
                         "title": entry["title"], "description": entry["summary"], "source": "Publisher",
                         "published_at": stamp, "timestamp": stamp, "risk_score": 5.0,
                         "severity": "MEDIUM", "tlp": entry["tlp"], "actors": [], "tags": [], "iocs": [], "ioc_count": 0})
    # This is the production supplemental collector's actual constructor,
    # which supplies no captured provenance and cannot pass the mandates.
    unproven = _make_item("Supplemental publisher investigation", "Source report", "MEDIUM",
                         "CyberSecurityNews", cve_ids=[], ts=stamp, url="https://cybersecuritynews.com/supplemental/")
    return observed, unproven


def write_source(root, records):
    source = root / "api/feed.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps(records))
    (root / "feed.json").write_text('[{"id":"previous-root"}]')
    return source


def test_supplemental_inventory_is_preserved_and_excluded_from_both_public_files(tmp_path):
    observed, unproven = candidates(tmp_path)
    restricted = {**copy.deepcopy(observed[0]), "id": "restricted", "stix_id": "restricted",
                  "sources": [{"tlp": "TLP:RED"}]}
    rows = observed + [unproven, restricted]
    write_source(tmp_path, rows)
    manifest = tmp_path / "data/stix/feed_manifest.json"
    manifest.parent.mkdir(parents=True)
    historical = {"id": "old-history", "title": "Original history", "source_url": "https://publisher.example/old"}
    manifest.write_text(json.dumps({"advisories": [historical], "original_metadata": "preserved"}))
    result = finalize_public_feed(tmp_path)
    expected_public = [{k: v for k, v in record.items() if k != "stix_id"} for record in observed]
    for name in ("api/feed.json", "feed.json"):
        assert json.loads((tmp_path / name).read_text()) == expected_public
    history = json.loads(manifest.read_text())
    assert history["original_metadata"] == "preserved" and history["advisories"][0] == historical
    archived = {r["id"]: r for r in history["advisories"]}
    for row in rows:
        for key, value in row.items():
            assert archived[row["id"]][key] == value
    assert result["candidate_count"] == 14 and result["published_count"] == 12
    assert result["withheld_count"] == 2
    assert result["reason_counts"] == {"PREWRITE_DENIED": 1, "RESTRICTED_UPSTREAM_LABEL": 1}


@pytest.mark.parametrize("mode", ["unproven", "malformed", "empty", "restricted"])
def test_invalid_final_batch_cannot_overwrite_either_feed(tmp_path, mode):
    observed, unproven = candidates(tmp_path)
    rows = {"unproven": [unproven], "malformed": [None], "empty": [],
            "restricted": [{**observed[0], "tlp": "TLP:AMBER"}]}[mode]
    source = write_source(tmp_path, rows)
    before = {p: p.read_bytes() for p in (source, tmp_path / "feed.json")}
    if mode == "restricted":
        assert finalize_public_feed(tmp_path)["tlp_tombstone_boundary_required"] is True
    else:
        with pytest.raises(ValueError, match="P0_.*BLOCKED"):
            finalize_public_feed(tmp_path)
    assert all(p.read_bytes() == content for p, content in before.items())


def test_r2_main_filters_after_collectors_before_any_credentials_or_network(tmp_path, monkeypatch):
    import r2_upload
    observed, unproven = candidates(tmp_path)
    source = write_source(tmp_path, observed + [unproven])
    monkeypatch.setattr(r2_upload, "REPO_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    class StopBeforeNetwork(Exception):
        pass
    def stop():
        expected_public = [{k: v for k, v in record.items() if k != "stix_id"} for record in observed]
        assert json.loads(source.read_text()) == expected_public
        raise StopBeforeNetwork()
    monkeypatch.setattr(r2_upload, "get_credentials", stop)
    with pytest.raises(StopBeforeNetwork):
        r2_upload.main()
    archive = json.loads((tmp_path / "data/stix/feed_manifest.json").read_text())
    assert len(archive) == 13 and any(r["id"] == unproven["id"] for r in archive)


def test_real_public_bundle_generator_publishes_only_qualified_candidates(tmp_path):
    observed, unproven = candidates(tmp_path)
    write_source(tmp_path, observed + [unproven])
    run = subprocess.run([sys.executable, str(ROOT / "scripts/generate_api_manifests.py")],
                         cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    latest = json.loads((tmp_path / "api/v1/intel/latest.json").read_text())
    assert latest["count"] == 12
    assert {r["id"] for r in latest["items"]} == {r["id"] for r in observed}
    assert all(r["id"] != unproven["id"] for r in latest["items"])
    expected_public = [{k: v for k, v in record.items() if k != "stix_id"} for record in observed]
    assert json.loads((tmp_path / "api/feed.json").read_text()) == expected_public


def test_empty_qualified_bundle_cannot_advance_previous_public_generation(tmp_path):
    _, unproven = candidates(tmp_path)
    write_source(tmp_path, [unproven])
    target = tmp_path / "api/v1/intel/latest.json"
    target.parent.mkdir(parents=True)
    previous = b'{"generated_at":"2026-10-09T05:38:01Z","items":[{"id":"previous"}]}'
    target.write_bytes(previous)
    run = subprocess.run([sys.executable, str(ROOT / "scripts/generate_api_manifests.py")],
                         cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert run.returncode != 0
    assert target.read_bytes() == previous
    assert "P0_FEED_PREWRITE_BLOCKED" in run.stdout + run.stderr


def test_all_tlp_denied_inventory_still_replaces_restricted_public_bundles(tmp_path):
    observed, _ = candidates(tmp_path)
    write_source(tmp_path, [{**observed[0], "tlp": "TLP:AMBER"}])
    target = tmp_path / "api/v1/intel/latest.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"items":[{"id":"previous-restricted"}]}')
    run = subprocess.run([sys.executable, str(ROOT / "scripts/generate_api_manifests.py")],
                         cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert run.returncode != 0
    assert json.loads(target.read_text())["items"] == []
    assert "every feed item was withheld by the TLP publication policy" in run.stdout + run.stderr


def test_valid_stix_kept_internal_alias_removed_without_changing_history(tmp_path):
    observed, _ = candidates(tmp_path)
    valid = "indicator--123e4567-e89b-42d3-a456-426614174000"
    observed[0]["stix_id"] = valid
    write_source(tmp_path, observed)
    result = finalize_public_feed(tmp_path)
    assert result["published_count"] == 12
    for path in ("api/feed.json", "feed.json"):
        published = json.loads((tmp_path / path).read_text())
        assert published[0]["id"] == observed[0]["id"]
        assert published[0]["stix_id"] == valid
        assert all("stix_id" not in record for record in published[1:])
    archive = json.loads((tmp_path / "data/stix/feed_manifest.json").read_text())
    archive_rows = archive["advisories"] if isinstance(archive, dict) else archive
    archived = {record["id"]: record for record in archive_rows}
    assert archived[observed[0]["id"]]["stix_id"] == valid
    assert archived[observed[1]["id"]]["stix_id"] == observed[1]["stix_id"]


def test_public_r2_upload_copy_sanitizes_aliases_without_modifying_source(tmp_path):
    import r2_upload
    observed, _ = candidates(tmp_path)
    valid = "indicator--123e4567-e89b-42d3-a456-426614174000"
    observed[0]["stix_id"] = valid
    source = write_source(tmp_path, observed)
    before = source.read_bytes()
    safe_path = r2_upload.tlp_safe_public_feed_source(source, tmp_path / "scratch")
    uploaded = json.loads(safe_path.read_text())
    assert len(uploaded) == len(observed)
    assert uploaded[0]["stix_id"] == valid
    assert all("stix_id" not in r for r in uploaded[1:])
    assert source.read_bytes() == before
