"""Fetched supplemental RSS records must carry real provenance through release."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import multi_source_collector as collector
from p0_r35_feed_prewrite_guard import select_publishable
from p0_r44_publication_boundary import finalize_public_feed

READERS = [(collector.collect_securityaffairs, "securityaffairs.com", 0.604),
           (collector.collect_cybersecuritynews, "cybersecuritynews.com", 0.561)]


def prepare(root, monkeypatch, host, score, *, publication=None, entry_tlp="", channel_tlp=""):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    original = now - timedelta(hours=1)
    date = publication if publication is not None else format_datetime(original.astimezone(timezone(timedelta(hours=5, minutes=30))))
    cve = "CVE-2026-12345" if host == "securityaffairs.com" else "CVE-2026-12346"
    raw = f'''<rss><channel>{channel_tlp}<item><title>Publisher vulnerability investigation {cve}</title>
    <link>https://{host}/security/report</link><description>Actual RSS source report with {cve}</description>
    <pubDate>{date}</pubDate>{entry_tlp}</item></channel></rss>'''
    registry = root / "data/quality/source_trust_scores.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    trust = json.loads(registry.read_text()) if registry.exists() else {"trust_scores": {}}
    trust["trust_scores"][host] = {"trust_score": score}
    registry.write_text(json.dumps(trust))
    monkeypatch.setattr(collector, "REPO_ROOT", root)
    monkeypatch.setattr(collector, "_now", lambda: stamp)
    calls = []
    monkeypatch.setattr(collector, "_get", lambda url, **kwargs: calls.append(url) or raw)
    return stamp, original.strftime("%Y-%m-%dT%H:%M:%SZ"), registry, calls


@pytest.mark.parametrize("reader,host,score", READERS)
def test_actual_rss_reader_preserves_observation_and_original_utc_publication(tmp_path, monkeypatch, reader, host, score):
    fetched, published, registry, calls = prepare(tmp_path, monkeypatch, host, score)
    before = registry.read_bytes()
    rows = reader()
    assert len(rows) == 1 and len(calls) == 1, "reuse the response; no additional fetches"
    row = rows[0]
    assert row["source_name"] == host
    assert row["retrieval_timestamp"] == row["processed_at"] == fetched
    assert row["publication_timestamp"] == row["timestamp"] == row["published_at"] == published
    assert row["trust_score"] == pytest.approx(score * 10)
    assert len(row["content_hash"]) == 64 and row["content_hash_scope"] == "rss_entry_fields_sha256"
    assert row["evidence_count"] == 1 and row["evidence_basis"] == ["captured_rss_entry"]
    assert registry.read_bytes() == before
    assert select_publishable(rows)[0] == rows
    source = tmp_path / "api/feed.json"
    source.parent.mkdir()
    source.write_text(json.dumps(rows))
    finalize_public_feed(tmp_path)
    # Public feed preserves collected evidence and internal id but must not
    # publish legacy intel-- identifiers as STIX object identities.
    expected_public = [{k: v for k, v in record.items() if k != "stix_id"} for record in rows]
    assert json.loads(source.read_text()) == expected_public
    archived = json.loads((tmp_path / "data/stix/feed_manifest.json").read_text())
    archive_rows = archived["advisories"] if isinstance(archived, dict) else archived
    assert any(r["id"] == row["id"] and r.get("stix_id") == row.get("stix_id") for r in archive_rows)


@pytest.mark.parametrize("publication", ["", "unparseable", "2099-01-01T00:00:00Z"])
def test_missing_invalid_or_future_source_date_is_never_processing_time(tmp_path, monkeypatch, publication):
    prepare(tmp_path, monkeypatch, "securityaffairs.com", 0.604, publication=publication)
    row = collector.collect_securityaffairs()[0]
    assert "publication_timestamp" not in row
    assert not select_publishable([row])[0]


def test_unapproved_trust_format_is_not_invented_or_scaled(tmp_path, monkeypatch):
    _, _, registry, _ = prepare(tmp_path, monkeypatch, "securityaffairs.com", 0.604)
    registry.write_text('{"trust_scores":{"securityaffairs.com":80}}')
    row = collector.collect_securityaffairs()[0]
    assert "trust_score" not in row and not select_publishable([row])[0]


@pytest.mark.parametrize("where", ["entry", "channel"])
def test_upstream_restrictions_survive_public_collector_default(tmp_path, monkeypatch, where):
    label = '<classification tlp="TLP:RED" />'
    prepare(tmp_path, monkeypatch, "cybersecuritynews.com", 0.561,
            entry_tlp=label if where == "entry" else "", channel_tlp=label if where == "channel" else "")
    row = collector.collect_cybersecuritynews()[0]
    assert row["sources"][0]["tlp"] == "TLP:RED"
    selected, held = select_publishable([row])
    assert not selected and held[0]["reason_code"] == "RESTRICTED_UPSTREAM_LABEL"


def test_supplemental_sources_remain_diverse_after_final_qualified_publication(tmp_path, monkeypatch):
    rows = []
    for reader, host, score in READERS:
        prepare(tmp_path, monkeypatch, host, score)
        rows.extend(reader())
    source = tmp_path / "api/feed.json"
    source.parent.mkdir()
    source.write_text(json.dumps(rows))
    finalize_public_feed(tmp_path)
    published = json.loads(source.read_text())
    assert {r["source_name"] for r in published} == {host for _, host, _ in READERS}
    assert len(published) == 2
