"""Zero-network negative controls for P0 report certification coverage."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from certification_source_coverage import audit_coverage, SOURCES


def doc(ids, key="items"):
    return {key: [{"id": id} for id in ids]}


def ids(count):
    return ["intel--" + f"{x:024x}" for x in range(1, count + 1)]


def source_set():
    return {key: doc([ids(4)[i]]) for i, key in enumerate(SOURCES)}


def test_reports_outside_feed_are_not_marked_approved():
    catalog = doc(ids(5), "reports")
    sources = source_set()
    result = audit_coverage(catalog, sources)
    assert result["catalog_candidates"] == 5
    assert result["resolved_from_feed_windows"] == 4
    assert result["outside_feed_windows"] == 1
    assert result["verdict"] == "COVERAGE_INCOMPLETE"
    assert result["persisted_certification_verified"] is False
    assert result["publication_gate_reasons_verified"] is False
    assert result["customer_release_certified"] is False
    assert result["cloudflare_requests"] == 0


def test_fully_resolved_feed_is_only_precheck():
    one = ids(1)[0]
    sources = {key: doc([one]) for key in SOURCES}
    result = audit_coverage(doc([one], "reports"), sources)
    assert result["verdict"] == "COVERAGE_PRECHECK_ONLY"
    assert result["customer_release_certified"] is False
    assert result["first_source_counts"]["latest_pro"] == 1
    assert result["first_source_counts"]["latest"] == 0


def test_first_source_wins_as_in_worker():
    one = ids(1)[0]
    sources = {key: doc([one]) for key in SOURCES}
    assert audit_coverage(doc([one], "reports"), sources)["first_source_counts"] == {
        "latest_pro": 1, "latest": 0, "top10": 0, "apex": 0,
    }


def test_missing_feed_cannot_be_counted_as_zero_mismatch():
    one = ids(1)[0]
    sources = source_set()
    del sources["apex"]
    with pytest.raises(ValueError, match="four source"):
        audit_coverage(doc([one], "reports"), sources)


def test_duplicate_catalog_identifier_blocks():
    one = ids(1)[0]
    with pytest.raises(ValueError, match="Duplicate"):
        audit_coverage(doc([one, one], "reports"), source_set())


@pytest.mark.parametrize("broken", [{}, [], {"reports": []},
                                      {"reports": [42]}, {"reports": [{"id": "bad"}]}])
def test_malformed_catalog_rejected(broken):
    with pytest.raises(ValueError):
        audit_coverage(broken, source_set())


def test_source_stix_id_precedence_matches_worker():
    original = ids(2)
    sources = source_set()
    sources["latest_pro"] = {"items": [{"id": original[1], "stix_id": original[0]}]}
    result = audit_coverage(doc([original[0], original[1]], "reports"), sources)
    assert result["first_source_counts"]["latest_pro"] == 1
    # A separate source can still resolve id[1], but the PRO alias does not.
    assert result["resolved_from_feed_windows"] <= 2


def test_offline_cli_malformed_source_fails_closed(tmp_path):
    files = {}
    for name in ("catalog", *SOURCES):
        f = tmp_path / (name + ".json")
        f.write_text(json.dumps(doc(ids(1), "reports" if name == "catalog" else "items")))
        files[name] = f
    files["top10"].write_text("{}")
    cmd = [sys.executable, str(ROOT / "scripts" / "certification_source_coverage.py")]
    for name, path in files.items():
        cmd += ["--" + name.replace("_", "-"), str(path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    assert result.returncode == 2
    verdict = json.loads(result.stdout)
    assert verdict["verdict"] == "BLOCKED_INVALID_OFFLINE_EVIDENCE"
    assert verdict["customer_release_certified"] is False


def test_late_catalog_r2_upload_requires_prior_offline_utc_chronology_guard():
    """Release contract: R2 PUT cannot precede strict UTC catalogue validation."""
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    stage = workflow.split('name: "STAGE 5.4.0d - Refresh Customer Reports Catalog"', 1)
    assert len(stage) == 2, "Late catalogue stage is missing"
    body = stage[1].split("# STAGE 5.4.1:", 1)[0]
    guard = "if ! python3 scripts/report_chronology_integrity.py --catalog api/reports/index.json; then"
    assert guard in body
    assert 'echo "::warning::STAGE 5.4.0d: strict UTC chronology rejected' in body
    assert "exit 0" in body.split(guard, 1)[1].split("\n          fi", 1)[0]
    assert body.index(guard) < body.index("scripts/r2_upload.py --reports-index-only")
    assert "scripts/r2_reports_integrity.py" in body


def test_late_catalog_chronology_cli_rejects_naive_utc_without_network(tmp_path):
    """Exercise the exact CLI invoked by the upload guard, including exit code."""
    path = "/reports/2026/10/intel--aaaaaaaaaaaaaaaa.html"
    row = {
        "id": "intel--aaaaaaaaaaaaaaaa",
        "path": path,
        "url": "https://intel.cyberdudebivash.com" + path,
        "timestamp": "2026-10-24T19:00:00",
    }
    catalog = tmp_path / "index.json"
    catalog.write_text(json.dumps({"reports": [row]}), encoding="utf-8")
    cmd = [sys.executable, str(ROOT / "scripts/report_chronology_integrity.py"),
           "--catalog", str(catalog)]
    rejected = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    assert rejected.returncode == 2
    verdict = json.loads(rejected.stdout)
    assert verdict["verdict"] == "BLOCKED"
    assert verdict["delivery_certified"] is False
    assert verdict["latest"] == []
    row["timestamp"] += "Z"
    catalog.write_text(json.dumps({"reports": [row]}), encoding="utf-8")
    accepted = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    assert accepted.returncode == 0
    accepted_verdict = json.loads(accepted.stdout)
    assert accepted_verdict["verdict"] == "CHRONOLOGY_PRECHECK_ONLY"
    assert accepted_verdict["delivery_certified"] is False


@pytest.mark.parametrize(
    ("timestamp", "allowed"),
    [
        ("2026-10-24T19:00:00", False),  # ambiguous timezone
        ("2026-10-24T19:00:00Z", True),  # canonical UTC
        (None, False),                   # missing index
    ],
)
def test_stage35_report_catalog_is_all_or_none_without_r2(tmp_path, monkeypatch, timestamp, allowed):
    """Stage 3.5 withholds the entire catalog trio while retaining intel feeds."""
    import r2_upload

    monkeypatch.setattr(r2_upload, "REPO_ROOT", tmp_path)
    report_dir = tmp_path / "api/reports"
    report_dir.mkdir(parents=True)
    (tmp_path / "api/feed.json").write_text('{"items":[]}', encoding="utf-8")
    for name in ("latest.json", "stats.json"):
        (report_dir / name).write_text("{}", encoding="utf-8")
    if timestamp is not None:
        path = "/reports/2026/10/intel--aaaaaaaaaaaaaaaa.html"
        catalog = {"reports": [{
            "id": "intel--aaaaaaaaaaaaaaaa",
            "path": path,
            "url": "https://intel.cyberdudebivash.com" + path,
            "timestamp": timestamp,
        }]}
        (report_dir / "index.json").write_text(json.dumps(catalog), encoding="utf-8")

    pairs = r2_upload.build_upload_plan()  # local filesystem only; no R2 calls
    keys = {dst for _src, dst in pairs}
    report_keys = {dst for _src, dst in r2_upload.REPORTS_INDEX_FILES}
    assert ("api/feed.json" in keys)
    assert report_keys.issubset(keys) is allowed
    assert report_keys.isdisjoint(keys) is (not allowed)
    assert r2_upload.report_catalog_chronology_precheck() is allowed
