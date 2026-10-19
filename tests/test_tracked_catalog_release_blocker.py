"""P0 offline negative controls for catalog release provenance.

Never pin a repository's catalog to a historical release date: that would
incorrectly fail once the catalog has been legitimately regenerated.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from report_chronology_integrity import audit_catalog

AT = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
BASE = "https://intel.cyberdudebivash.com"
RID = "intel--" + "a" * 24
PATH = "/reports/2026/10/" + RID + ".html"


def _catalog(*, generated_at="2026-10-19T09:00:00Z",
             timestamp="2026-10-18T12:00:00Z"):
    return {
        "generated_at": generated_at,
        "reports": [{
            "id": RID, "path": PATH, "url": BASE + PATH,
            "timestamp": timestamp,
        }],
    }


def test_stale_catalog_is_blocked_without_guessing_its_origin():
    result = audit_catalog(
        _catalog(generated_at="2026-10-16T09:00:00Z"),
        maximum_age_hours=24, at=AT,
    )
    assert result["verdict"] == "BLOCKED"
    assert result["delivery_certified"] is False
    assert result["latest"] == [] and result["historical"] == []
    assert any("older than" in defect for defect in result["defects"])


def test_ambiguous_report_time_blocks_even_when_catalog_is_fresh():
    result = audit_catalog(
        _catalog(timestamp="2026-10-18T12:00:00"),
        maximum_age_hours=24, at=AT,
    )
    assert result["verdict"] == "BLOCKED"
    assert result["delivery_certified"] is False
    assert any("explicit-UTC" in defect for defect in result["defects"])


def test_fresh_canonical_catalog_is_only_chronology_not_delivery():
    result = audit_catalog(_catalog(), maximum_age_hours=24, at=AT)
    assert result["verdict"] == "CHRONOLOGY_PRECHECK_ONLY"
    assert result["latest"] == [BASE + PATH]
    assert result["historical"] == []
    assert result["delivery_certified"] is False
