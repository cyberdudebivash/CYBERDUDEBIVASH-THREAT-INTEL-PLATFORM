"""Customer-truth contract for publicly sold SENTINEL APEX Weekly Threat Brief."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import weekly_threat_brief as brief  # noqa: E402


def _entry(hours_ago=1, **extra):
    row = {
        "id": "intel--test", "title": "Evidence-backed bulletin",
        "severity": "MEDIUM", "risk_score": 4.0, "tlp": "TLP:CLEAR",
        "published_at": (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat(),
        "report_url": "https://intel.cyberdudebivash.com/reports/2026/10/intel--test.html",
    }
    return {**row, **extra}


@pytest.mark.parametrize("raw,expected", [
    ("/reports/2026/10/intel--a.html", "https://intel.cyberdudebivash.com/reports/2026/10/intel--a.html"),
    ("https://intel.cyberdudebivash.com/reports/2026/10/intel--a.html", "https://intel.cyberdudebivash.com/reports/2026/10/intel--a.html"),
    ("https://intel.cyberdudebivash.comhttps://intel.cyberdudebivash.com/reports/2026/10/intel--a.html", "https://intel.cyberdudebivash.com/reports/2026/10/intel--a.html"),
    ("https://example.org/reports/external.html", ""),
    ("javascript:alert(1)", ""),
    ("//example.org/reports/x.html", ""),
    ("", ""),
    ("/reports/../../admin", ""),
])
def test_report_url_normalization(raw, expected):
    assert brief._canonical_report_url(raw) == expected


def test_only_real_current_week_entries_are_published():
    output = brief._build_brief([_entry(), _entry(hours_ago=240, id="intel--stale")])
    assert output["stats"]["total_advisories"] == 1
    assert output["top_threats"][0]["report_url"].startswith(brief.PLATFORM_URL + "/reports/")
    assert "15,000" not in json.dumps(output)
    contract = json.loads((ROOT / "config/commercial-contract.json").read_text())
    for tier, label in (("pro", "PRO"), ("enterprise", "ENTERPRISE"), ("mssp", "MSSP")):
        assert any(label in plan and f"₹{contract['tiers'][tier]['inr_monthly']:,}" in plan for plan in output["upgrade_cta"]["plans"])


def test_html_escapes_untrusted_title_and_actor_and_never_links_unknown_origin():
    row = _entry(title='"><script>window.evaded=1</script>', actor='"><svg/onload=alert(1)>',
                 report_url="javascript:alert(1)")
    output = brief._build_brief([row])
    html = brief._render_html(output)
    assert "<script>window.evaded=1</script>" not in html
    assert "<svg/onload=alert(1)>" not in html
    assert 'href="javascript:' not in html


def test_no_stale_weekly_publish_when_source_only_has_historical_entries(tmp_path, monkeypatch):
    old = _entry(hours_ago=240)
    target = tmp_path / "weekly-brief.html"
    target.write_text("existing_verified_release")
    dest = tmp_path / "weekly_brief.json"
    dest.write_text('{"existing":true}')
    monkeypatch.setattr(brief, "_load_feed", lambda: [old])
    monkeypatch.setattr(brief, "BRIEF_HTML_PATH", target)
    monkeypatch.setattr(brief, "BRIEF_JSON_PATH", dest)
    assert brief.main() == 1
    assert target.read_text() == "existing_verified_release"
    assert dest.read_text() == '{"existing":true}'


def test_public_source_filters_restricted_records(tmp_path, monkeypatch):
    manifest = tmp_path / "data/stix/feed_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps([_entry(), _entry(id="intel--denied", tlp="TLP:RED")]))
    monkeypatch.setattr(brief, "MANIFEST_PATH", manifest)
    monkeypatch.setattr(brief, "FEED_PATH", tmp_path / "missing-feed.json")
    selected = brief._load_feed()
    assert len(selected) == 1
    assert selected[0]["tlp"] == "TLP:CLEAR"
