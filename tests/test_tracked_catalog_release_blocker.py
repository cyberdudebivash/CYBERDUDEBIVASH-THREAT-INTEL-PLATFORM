"""P0 negative controls for the tracked catalog. No network or storage calls."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from report_chronology_integrity import audit_catalog


def test_tracked_catalog_cannot_be_mistaken_for_fresh_production_evidence():
    """Historical repository fixture must not authorize strict production activation."""
    catalog = json.loads((ROOT / "api/reports/index.json").read_text(encoding="utf-8"))
    result = audit_catalog(
        catalog, maximum_age_hours=24, at=datetime(2026, 10, 19, tzinfo=timezone.utc)
    )
    assert result["verdict"] == "BLOCKED"
    assert result["delivery_certified"] is False
    assert not result["latest"] and not result["historical"]
    assert any("older" in reason or "UTC" in reason or "timestamp" in reason
               for reason in result["defects"])


def test_provenance_preserving_canonical_catalog_is_chronology_only():
    record_id = "intel--" + "a" * 24
    path = "/reports/2026/10/" + record_id + ".html"
    catalog = {
        "generated_at": "2026-10-19T08:00:00Z",
        "reports": [{
            "id": record_id, "path": path,
            "url": "https://intel.cyberdudebivash.com" + path,
            "timestamp": "2026-10-18T12:00:00Z",
        }],
    }
    result = audit_catalog(
        catalog, maximum_age_hours=24,
        at=datetime(2026, 10, 19, 9, tzinfo=timezone.utc)
    )
    assert result["verdict"] == "CHRONOLOGY_PRECHECK_ONLY"
    assert result["delivery_certified"] is False
