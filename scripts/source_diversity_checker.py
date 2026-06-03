#!/usr/bin/env python3
"""
scripts/source_diversity_checker.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Source Diversity Governance (Phase 9)
Tests live RSS/API availability and checks source distribution.
"""
from __future__ import annotations
import json, logging, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

log = logging.getLogger("sentinel.source_diversity")
REPO_ROOT = Path(__file__).resolve().parent.parent

LIVE_SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "api"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
    {"name": "SecurityAffairs", "url": "https://securityaffairs.com/feed", "type": "rss"},
    {"name": "CyberSecurityNews", "url": "https://cybersecuritynews.com/feed/", "type": "rss"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
]

def _test_source(source):
    result = {"name": source["name"], "url": source["url"], "type": source["type"], "reachable": False, "status_code": None, "response_bytes": 0, "error": None}
    try:
        req = urllib.request.Request(source["url"], headers={"User-Agent": "SENTINEL-APEX/171 CTI-Monitor"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            result["status_code"] = resp.status
            result["reachable"] = resp.status == 200
            result["response_bytes"] = len(resp.read(2048))
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:100]
    return result

def run_source_diversity_check():
    now = datetime.now(timezone.utc)

    # Load data/feed.json source breakdown
    data_path = REPO_ROOT / "data" / "feed.json"
    items = []
    if data_path.exists():
        raw = json.loads(data_path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("items", raw.get("advisories", []))

    src_dist = defaultdict(int)
    for i in items:
        s = i.get("source") or i.get("source_name","Unknown")
        src_dist[s] += 1

    total = len(items)
    hhi = sum((v/total)**2 for v in src_dist.values()) if total else 1.0
    diversity_score = round((1 - hhi) * 100, 1)  # 0=monopoly, 100=perfect diversity

    # Test live sources
    live_results = []
    reachable_count = 0
    for source in LIVE_SOURCES:
        r = _test_source(source)
        live_results.append(r)
        if r["reachable"]: reachable_count += 1

    # Check api/feed.json sources
    api_path = REPO_ROOT / "api" / "feed.json"
    api_items = []
    if api_path.exists():
        raw2 = json.loads(api_path.read_text(encoding="utf-8"))
        api_items = raw2 if isinstance(raw2, list) else raw2.get("items",[])
    api_sources = defaultdict(int)
    for i in api_items:
        s = i.get("source") or "Unknown"
        api_sources[s] += 1

    issues = []
    if len(src_dist) < 5:
        issues.append({"severity":"HIGH","issue":f"Only {len(src_dist)} distinct sources — need >= 5"})
    if api_sources.get("SENTINEL-APEX",0) == len(api_items) and len(api_items) > 0:
        issues.append({"severity":"HIGH","issue":"api/feed.json 100% source=SENTINEL-APEX — no real source attribution"})
    if reachable_count < 3:
        issues.append({"severity":"MEDIUM","issue":f"Only {reachable_count}/{len(LIVE_SOURCES)} live sources reachable"})

    report = {
        "validator": "SourceDiversityChecker",
        "run_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_feed_sources": {
            "total_items": total,
            "distinct_sources": len(src_dist),
            "distribution": dict(sorted(src_dist.items(), key=lambda x:-x[1])),
            "herfindahl_index": round(hhi,4),
            "diversity_score": diversity_score,
        },
        "api_feed_sources": {
            "total_items": len(api_items),
            "distinct_sources": len(api_sources),
            "distribution": dict(api_sources),
        },
        "live_source_tests": live_results,
        "live_reachable": reachable_count,
        "live_total": len(LIVE_SOURCES),
        "issues": issues,
        "status": "PASS" if not issues else "WARN"
    }

    rp = REPO_ROOT / "reports" / "source_diversity_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_source_diversity_check()
    print(json.dumps({k:v for k,v in r.items() if k!="live_source_tests"}, indent=2))
    for s in r["live_source_tests"]:
        print(f"  {s['name']}: {'OK' if s['reachable'] else 'FAIL'} {s.get('error','')}")
