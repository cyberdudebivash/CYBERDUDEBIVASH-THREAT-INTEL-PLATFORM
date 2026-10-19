"""Customer-truth contract for publicly sold SENTINEL APEX Weekly Threat Brief."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import weekly_threat_brief as brief  # noqa: E402


def _entry(hours_ago=None, **extra):
    row = {
        "id": "intel--test", "title": "Evidence-backed bulletin",
        "severity": "MEDIUM", "risk_score": 4.0, "tlp": "TLP:CLEAR",
        "published_at": ((brief._report_window()[0] + timedelta(days=3, hours=12))
                         if hours_ago is None else
                         (datetime.now(timezone.utc) - timedelta(hours=hours_ago))).isoformat(),
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


def test_no_false_kev_confirmation_from_string_no_or_unverified_stix_alias():
    row = _entry(kev="NO", cisa_kev=False, stix_id="intel--bad-uuid")
    result = brief._build_brief([row])
    assert result["stats"]["kev_additions"] == 0
    assert result["top_threats"][0]["kev"] is False
    assert result["stats"]["stix_bundles"] == 0
    known = _entry(id="intel--known", kev="YES", stix_bundle_verified=True,
                   stix_bundle_url="/data/stix/verified.json")
    positive = brief._build_brief([known])
    assert positive["stats"]["kev_additions"] == 1
    assert positive["stats"]["stix_bundles"] == 1


def test_monday_report_is_previous_completed_iso_week():
    monday = datetime(2026, 10, 19, 2, 30, tzinfo=timezone.utc)
    start, end = brief._report_window(monday)
    assert (start.isoformat(), end.isoformat()) == (
        "2026-10-12T00:00:00+00:00", "2026-10-19T00:00:00+00:00"
    )
    assert start.isocalendar()[:2] == (2026, 42)


def test_weekly_brief_without_any_feed_fails_instead_of_returning_success(tmp_path, monkeypatch):
    old_html = tmp_path / "weekly-brief.html"
    old_json = tmp_path / "weekly_brief.json"
    old_html.write_text("old August HTML")
    old_json.write_text('{"week":"Week 35 2026"}')
    monkeypatch.setattr(brief, "_load_feed", lambda: [])
    monkeypatch.setattr(brief, "BRIEF_HTML_PATH", old_html)
    monkeypatch.setattr(brief, "BRIEF_JSON_PATH", old_json)
    assert brief.main() == 1
    assert old_html.read_text() == "old August HTML"
    assert "Week 35" in old_json.read_text()


def test_only_completed_week_included_not_new_monday_entries():
    start, end = brief._report_window()
    eligible = _entry(id="intel--eligible", published_at=(start + timedelta(days=2)).isoformat())
    new_week = _entry(id="intel--new-week", published_at=(end + timedelta(minutes=2)).isoformat())
    result = brief._build_brief([eligible, new_week])
    assert result["week"] == f"Week {start.isocalendar().week} {start.isocalendar().year}"
    assert result["stats"]["total_advisories"] == 1
    assert result["top_threats"][0]["title"] == eligible["title"]


def test_r2_source_fetch_is_required_and_never_falls_back_to_git(tmp_path, monkeypatch):
    import weekly_brief_source as source
    destination = tmp_path / "feed_manifest.json"
    monkeypatch.setattr(source, "get_credentials", lambda: ("test-account", "key", "secret"))
    monkeypatch.setattr(source, "install_awscli", lambda: None)
    calls = []
    def failed_get(path, bucket, key, endpoint):
        calls.append((bucket, key))
        return "ERROR"
    monkeypatch.setattr(source, "s3_get", failed_get)
    assert source.fetch_source(destination) == 1
    assert not destination.exists()
    assert calls[0][1] == "intel/feed_manifest.json"

    def success_get(path, bucket, key, endpoint):
        Path(path).write_text(json.dumps([_entry()]), encoding="utf-8")
        return "OK"
    monkeypatch.setattr(source, "s3_get", success_get)
    assert source.fetch_source(destination) == 0
    assert json.loads(destination.read_text())[0]["id"] == "intel--test"
