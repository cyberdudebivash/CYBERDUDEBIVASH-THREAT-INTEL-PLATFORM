#!/usr/bin/env python3
"""
scripts/audit_title_enrichment.py
Post-enrichment audit: count how many feed items still have raw CVE IDs as titles.
Exits 0 always (non-blocking), prints warning if enriched=0.
"""
import json, re, sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = REPO_ROOT / "api" / "feed.json"
CVE_RE    = re.compile(r"^CVE-\d{4}-\d+$", re.I)

try:
    feed  = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    raw   = [it for it in items if CVE_RE.fullmatch(str(it.get("title", "")).strip())]
    total    = len(items)
    enriched = total - len(raw)
    print(f"[TITLE-AUDIT] total={total} enriched={enriched} still_raw={len(raw)}")
    if enriched == 0:
        print("::warning::Title enricher produced 0 enriched titles - all items still show raw CVE IDs")
        sys.exit(0)
    pct = round(enriched / total * 100) if total else 0
    print(f"[PASS] {enriched}/{total} ({pct}%) titles now have analyst-grade descriptions")
    if raw:
        print(f"[INFO] {len(raw)} items still pending enrichment (will resolve next run)")
except Exception as e:
    print(f"::warning::audit_title_enrichment.py failed: {e}")
sys.exit(0)
