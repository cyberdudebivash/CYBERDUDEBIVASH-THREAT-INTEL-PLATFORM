"""P0: Python last-mile TLP sanitation must match the genuine Worker boundary.

Synthetic fixtures only; no network, R2, customer data or publication.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import r2_upload  # noqa: E402

DIAGNOSTIC = ROOT / "scripts/p0_r2_public_feed_diagnostic.mjs"


def sample():
    return {
        "id": "intel--public-test",
        "title": "Documented sample advisory",
        "tlp": "TLP:CLEAR",
        "related_advisories": [
            {"id": "intel--unclassified", "title": "UNVERIFIED_PRIVATE_CANARY"},
            {"id": "intel--clear-child", "title": "Child CLEAR", "tlp": "TLP:CLEAR"},
        ],
    }


def test_last_mile_array_removes_worker_rejected_nested_advisory(tmp_path):
    src = tmp_path / "api/feed.json"
    src.parent.mkdir(parents=True)
    payload = [sample()]
    src.write_text(json.dumps(payload), encoding="utf-8")
    before = src.read_bytes()
    safe = r2_upload.tlp_safe_public_feed_source(src, tmp_path / "scratch")
    result = json.loads(safe.read_text(encoding="utf-8"))
    assert len(result) == 1
    assert result[0]["id"] == payload[0]["id"]
    assert result[0]["related_advisories"] == [
        {"id": "intel--clear-child", "title": "Child CLEAR", "tlp": "TLP:CLEAR"}
    ]
    assert "UNVERIFIED_PRIVATE_CANARY" not in safe.read_text()
    assert src.read_bytes() == before


def test_last_mile_object_accepted_by_real_worker_gate(tmp_path):
    latest = tmp_path / "api/v1/intel/latest.json"
    latest.parent.mkdir(parents=True)
    original = {"generated_at": datetime.now(timezone.utc).isoformat(),
                "count": 1, "items": [sample()]}
    latest.write_text(json.dumps(original), encoding="utf-8")
    source_bytes = latest.read_bytes()
    safe = r2_upload.tlp_safe_public_json_source(
        latest, tmp_path / "scratch", "api/v1/intel/latest.json"
    )
    assert safe is not None
    result = subprocess.run(["node", str(DIAGNOSTIC), str(safe)], cwd=ROOT,
                            capture_output=True, text=True, check=False, timeout=20)
    assert result.returncode == 0, "sanitized document rejected by actual Worker"
    decision = json.loads(result.stdout)
    assert decision["verdict"] == "DELIVERABLE"
    assert decision["worker_public_tlp_gate"] == "PASS"
    assert "UNVERIFIED_PRIVATE_CANARY" not in safe.read_text()
    assert latest.read_bytes() == source_bytes


def test_top_level_unclassified_advisory_never_promoted_to_clear(tmp_path):
    src = tmp_path / "api/feed.json"
    src.parent.mkdir()
    src.write_text(json.dumps([
        {"id": "intel--unknown", "title": "Unknown without TLP"},
        {"id": "intel--clear", "title": "Known public", "tlp": "TLP:CLEAR"}
    ]), encoding="utf-8")
    safe = r2_upload.tlp_safe_public_feed_source(src, tmp_path / "scratch")
    records = json.loads(safe.read_text())
    assert [x["id"] for x in records] == ["intel--clear"]
