#!/usr/bin/env python3
"""
scripts/attribution_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Source Attribution Validator
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("sentinel.attribution_validator")
REPO_ROOT = Path(__file__).resolve().parent.parent

TRUST_SCORES = {
    "CISA": 98, "US-CERT": 95, "NVD": 95, "CVE Feed": 90,
    "Google Project Zero": 92, "Microsoft Security": 88, "Mandiant": 87,
    "CrowdStrike": 86, "Palo Alto Unit 42": 85, "Rapid7": 84,
    "SentinelOne": 83, "Check Point Research": 83, "Zero Day Initiative": 82,
    "Kaspersky SecureList": 80, "The Hacker News": 78, "BleepingComputer": 77,
    "Security Affairs": 76, "CyberSecurity News": 74, "CyberScoop": 74,
    "KrebsOnSecurity": 79, "Vulners": 72, "AWS Security Blog": 75,
    "NCSC Netherlands": 85, "Recorded Future": 83, "SENTINEL-APEX": 50,
    "Unknown": 30,
}

SOURCE_URLS = {
    "CISA": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "US-CERT": "https://www.us-cert.gov/ncas/alerts",
    "NVD": "https://nvd.nist.gov/vuln/detail/",
    "CVE Feed": "https://cve.mitre.org/cgi-bin/cvename.cgi",
    "Google Project Zero": "https://googleprojectzero.blogspot.com",
    "Microsoft Security": "https://msrc.microsoft.com/update-guide",
    "Mandiant": "https://www.mandiant.com/resources/blog",
    "CrowdStrike": "https://www.crowdstrike.com/blog",
    "Palo Alto Unit 42": "https://unit42.paloaltonetworks.com",
    "Rapid7": "https://www.rapid7.com/blog",
    "SentinelOne": "https://www.sentinelone.com/blog",
    "Check Point Research": "https://research.checkpoint.com",
    "Zero Day Initiative": "https://www.zerodayinitiative.com/advisories",
    "Kaspersky SecureList": "https://securelist.com",
    "The Hacker News": "https://thehackernews.com",
    "BleepingComputer": "https://www.bleepingcomputer.com",
    "Security Affairs": "https://securityaffairs.com",
    "CyberSecurity News": "https://cybersecuritynews.com",
    "KrebsOnSecurity": "https://krebsonsecurity.com",
    "Vulners": "https://vulners.com",
    "AWS Security Blog": "https://aws.amazon.com/security/security-bulletins",
    "CyberScoop": "https://cyberscoop.com",
    "NCSC Netherlands": "https://www.ncsc.nl/english",
    "SENTINEL-APEX": "https://sentinel.cyberdudebivash.com",
}

def _extract_domain(url):
    if not url: return ""
    try:
        p = urlparse(url)
        return p.netloc.lstrip("www.")
    except Exception:
        return ""

class AttributionValidator:
    def __init__(self):
        self.now_utc = datetime.now(timezone.utc)
        self.enriched = 0
        self.issues = []

    def validate_record(self, item):
        """Check if item has all required attribution fields. Returns list of missing fields."""
        required = ["source_name","source_url","source_domain","publisher","publisher_trust_score","original_article"]
        missing = [f for f in required if not item.get(f)]
        return missing

    def enrich_attribution(self, item):
        item = dict(item)
        # Determine canonical source name
        src = (item.get("source_name") or item.get("source") or
               item.get("feed_source") or "SENTINEL-APEX")
        item["source_name"] = src

        # source_url
        if not item.get("source_url"):
            item["source_url"] = SOURCE_URLS.get(src, SOURCE_URLS.get("SENTINEL-APEX"))
            self.enriched += 1

        # source_domain
        if not item.get("source_domain"):
            item["source_domain"] = _extract_domain(item.get("source_url",""))

        # publisher
        if not item.get("publisher"):
            item["publisher"] = src

        # publisher_trust_score
        if not item.get("publisher_trust_score"):
            item["publisher_trust_score"] = TRUST_SCORES.get(src, TRUST_SCORES.get("Unknown",30))

        # original_article — use report_url or source_url
        if not item.get("original_article"):
            item["original_article"] = (
                item.get("report_url") or
                item.get("source_url") or
                SOURCE_URLS.get(src, "")
            )

        # Ensure source field is consistent
        item["source"] = src

        return item

    def run_validation(self, feed_path):
        feed_path = Path(feed_path)
        if not feed_path.exists():
            return {"error": f"File not found: {feed_path}", "status": "FAIL"}

        raw = json.loads(feed_path.read_text(encoding="utf-8"))
        is_dict = isinstance(raw, dict)
        if is_dict:
            items = raw.get("items", raw.get("advisories", raw.get("data", [])))
        else:
            items = raw

        before_complete = sum(1 for i in items if not self.validate_record(i))
        enriched_items = []
        for item in items:
            item = self.enrich_attribution(item)
            missing = self.validate_record(item)
            if missing:
                self.issues.append({"id": item.get("id","?"), "missing_fields": missing})
            enriched_items.append(item)
        after_complete = sum(1 for i in enriched_items if not self.validate_record(i))

        if is_dict:
            for key in ("items","advisories","data"):
                if key in raw:
                    raw[key] = enriched_items; break
            else:
                raw["items"] = enriched_items
            output = raw
        else:
            output = enriched_items

        feed_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

        # Source distribution
        src_dist = {}
        for i in enriched_items:
            s = i.get("source_name","?")
            src_dist[s] = src_dist.get(s,0)+1

        trust_avg = 0
        if enriched_items:
            scores = [i.get("publisher_trust_score",0) for i in enriched_items if isinstance(i.get("publisher_trust_score"),int)]
            trust_avg = round(sum(scores)/len(scores),1) if scores else 0

        return {
            "validator": "AttributionValidator",
            "feed_path": str(feed_path),
            "run_at": self.now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "before": {"total_items": len(items), "fully_attributed": before_complete},
            "after": {"total_items": len(enriched_items), "fully_attributed": after_complete},
            "enrichments_applied": self.enriched,
            "remaining_issues": len(self.issues),
            "source_distribution": src_dist,
            "average_trust_score": trust_avg,
            "issues_sample": self.issues[:10],
            "status": "PASS" if after_complete == len(enriched_items) else "WARN"
        }


def run_attribution_validation_stage(feed_paths=None):
    if feed_paths is None:
        feed_paths = [REPO_ROOT/"api"/"feed.json", REPO_ROOT/"feed.json"]
    combined = {"stage": "source_attribution", "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {}, "total_enrichments": 0, "overall_status": "PASS"}
    for path in feed_paths:
        v = AttributionValidator()
        r = v.run_validation(path)
        combined["files"][str(path)] = r
        combined["total_enrichments"] += r.get("enrichments_applied",0)
        if r.get("status") == "FAIL":
            combined["overall_status"] = "FAIL"
    rp = REPO_ROOT/"reports"/"source_integrity_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")
    return combined

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    r = run_attribution_validation_stage([path] if path else None)
    print(json.dumps(r, indent=2))
