"""
OpenPhish items never link customers to the phishing site.

Production 2026-09-26T08:04Z: 47 of 50 OpenPhish items had the phishing URL
itself as source_url (3 were blanked by a blogspot filter). The source is the
OpenPhish feed; the phishing URL is the IOC.
"""
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import true_intel_ingestor as tii  # noqa: E402
import openphish_source_link_guard as guard  # noqa: E402
from intel_dedup_engine import enforce_manifest_uniqueness  # noqa: E402

PHISH = [
    "https://www.roblox.com.do/games/102919673732823/X5-New-word-The-Best-Game?privateServerLinkCode=7456",
    "https://www.facebookkerls.blogspot.com/login",
]


def _legacy(phish, **extra):
    title = f"[OpenPhish] Phishing URL: {phish[:100]}"
    item = {
        "id": f"intel--{hashlib.sha256((phish + title).encode()).hexdigest()[:16]}",
        "title": title, "source": "openphish", "feed_source": "openphish",
        "source_url": phish, "iocs": [],
        "description": f"URL flagged by OpenPhish community feed as active phishing: {phish}",
        "evidence_chain": {"source_url": phish},
    }
    item.update(extra)
    return item


def test_ingest_links_openphish_not_the_phish():
    with patch.object(tii, "_get_text", return_value="\n".join(PHISH) + "\n"):
        items = tii.ingest_openphish(None)
    assert len(items) == 2
    for item, phish in zip(items, PHISH):
        assert item["source_url"].startswith("https://openphish.com/feed.txt?entry=")
        assert phish not in item["source_url"]
        assert item["iocs"] == [{"type": "url", "value": phish}]
        # ids unchanged: still the hash of phishing URL + title
        assert item["id"] == f"intel--{hashlib.sha256((phish + item['title']).encode()).hexdigest()[:16]}"


def test_links_are_unique_so_the_uniqueness_guard_keeps_every_entry():
    with patch.object(tii, "_get_text", return_value="\n".join(PHISH)):
        items = tii.ingest_openphish(None)
    assert items[0]["source_url"] != items[1]["source_url"]
    unique, removed = enforce_manifest_uniqueness(items)
    assert removed == 0 and len(unique) == 2


def test_repair_legacy_blank_and_ioc_forms():
    phish_src = _legacy(PHISH[0])
    blank = _legacy(PHISH[1], source_url="")
    ioc_only = _legacy(PHISH[1], source_url="", description="", iocs=[{"type": "url", "value": PHISH[1]}])
    assert tii.repair_openphish_source_links([phish_src, blank, ioc_only]) == 3
    assert phish_src["source_url"] == tii.openphish_source_link(PHISH[0])
    assert blank["source_url"] == ioc_only["source_url"] == tii.openphish_source_link(PHISH[1])
    assert "evidence_chain" not in phish_src  # rebuilt from item data by P20.1


def test_repair_leaves_other_feeds_and_repaired_items_alone():
    urlhaus = {"source": "urlhaus", "title": "[URLhaus] MALWARE: http://x",
               "source_url": "https://urlhaus.abuse.ch/url/123/"}
    done = _legacy(PHISH[0], source_url=tii.openphish_source_link(PHISH[0]))
    before = json.dumps([urlhaus, done], sort_keys=True)
    assert tii.repair_openphish_source_links([urlhaus, done, "junk", None]) == 0
    assert json.dumps([urlhaus, done], sort_keys=True) == before


def test_merge_repairs_items_already_in_the_manifest():
    existing = [_legacy(PHISH[0])]
    saved = {}

    class NoDedup:
        def is_duplicate(self, item):
            return False

        def mark_seen(self, item):
            pass

    with patch.object(tii, "_load_manifest", return_value=existing), \
         patch.object(tii, "_save_manifest", side_effect=lambda e: saved.setdefault("e", e)):
        tii._merge_into_manifest([], NoDedup())
    assert saved["e"][0]["source_url"] == tii.openphish_source_link(PHISH[0])


def test_publisher_guard_repairs_feed_files():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "feed.json"
        p.write_text(json.dumps([_legacy(PHISH[0]), {"id": "x", "source_url": "https://a.example/1"}]))
        assert guard.guard_file(p) == 1
        out = json.loads(p.read_text())
        assert out[0]["source_url"] == tii.openphish_source_link(PHISH[0])
        assert out[1]["source_url"] == "https://a.example/1"
        m = Path(tmp) / "m.json"
        m.write_text(json.dumps({"advisories": [_legacy(PHISH[1])]}))
        assert guard.guard_file(m) == 1
        assert guard.guard_file(p) == 0  # idempotent


def test_workflow_runs_guard_after_ingest_before_enrichment():
    wf = (REPO / ".github" / "workflows" / "sentinel-blogger.yml").read_text(encoding="utf-8")
    i_orch = wf.index('name: "STAGE 1-3 - Master Pipeline Orchestrator"')
    i_guard = wf.index("python3 scripts/openphish_source_link_guard.py")
    i_enrich = wf.index('name: "STAGE 3.1 - APEX AI Feed Enrichment')
    i_chain = wf.index('name: "STAGE 3.93.15b - P20.1 Evidence Chain Enricher"')
    assert i_orch < i_guard < i_enrich < i_chain
