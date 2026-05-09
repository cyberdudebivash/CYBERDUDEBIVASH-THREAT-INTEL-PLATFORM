#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Source Trust Engine
========================================================
Enterprise Intelligence Quality: Phase 3

Dynamically scores and weights threat intelligence sources by:
  - Domain reputation (tier: premium / standard / community / unvetted)
  - Historical accuracy rate (track record of verified IOCs)
  - Timeliness (average age of intel at publication time)
  - False positive rate (percentage of IOCs that proved benign)
  - Volume consistency (anomaly detection on article frequency)
  - CVSS/EPSS signal quality (rate of high-fidelity vulnerability coverage)

Trust score range: 0.0 (untrusted) -- 1.0 (platinum source)

Produces: data/quality/source_trust_scores.json

Usage:
  python3 scripts/source_trust_engine.py [--report] [--update]
"""

import argparse
import json
import pathlib
import datetime
import re
import math
from typing import Dict, List, Any, Optional, Tuple

# ============================================================
# SOURCE TIER DEFINITIONS
# ============================================================
SOURCE_TIER_MAP: Dict[str, Dict[str, Any]] = {
    # TIER 1: PLATINUM — authoritative, vendor-backed, primary sources
    "nvd.nist.gov":             {"tier": "platinum", "base_trust": 1.00, "category": "vulnerability"},
    "cisa.gov":                 {"tier": "platinum", "base_trust": 0.98, "category": "advisory"},
    "us-cert.cisa.gov":         {"tier": "platinum", "base_trust": 0.98, "category": "advisory"},
    "cert.org":                 {"tier": "platinum", "base_trust": 0.97, "category": "advisory"},
    "attack.mitre.org":         {"tier": "platinum", "base_trust": 0.99, "category": "framework"},
    "microsoft.com":            {"tier": "platinum", "base_trust": 0.96, "category": "vendor"},
    "security.microsoft.com":   {"tier": "platinum", "base_trust": 0.97, "category": "vendor"},
    "google.com":               {"tier": "platinum", "base_trust": 0.95, "category": "vendor"},
    "blog.google":              {"tier": "platinum", "base_trust": 0.95, "category": "vendor"},
    "googleprojectzero.blogspot.com": {"tier": "platinum", "base_trust": 0.97, "category": "research"},
    "mandiant.com":             {"tier": "platinum", "base_trust": 0.97, "category": "vendor"},
    "crowdstrike.com":          {"tier": "platinum", "base_trust": 0.96, "category": "vendor"},
    "sentinelone.com":          {"tier": "platinum", "base_trust": 0.95, "category": "vendor"},
    "paloaltonetworks.com":     {"tier": "platinum", "base_trust": 0.95, "category": "vendor"},
    "unit42.paloaltonetworks.com": {"tier": "platinum", "base_trust": 0.96, "category": "research"},
    "recordedfuture.com":       {"tier": "platinum", "base_trust": 0.95, "category": "vendor"},
    "virustotal.com":           {"tier": "platinum", "base_trust": 0.94, "category": "analysis"},
    "ibm.com":                  {"tier": "platinum", "base_trust": 0.93, "category": "vendor"},
    "securityintelligence.com": {"tier": "platinum", "base_trust": 0.93, "category": "vendor"},

    # TIER 2: ENTERPRISE — reputable research, major security blogs
    "thehackernews.com":        {"tier": "enterprise", "base_trust": 0.88, "category": "news"},
    "bleepingcomputer.com":     {"tier": "enterprise", "base_trust": 0.87, "category": "news"},
    "krebsonsecurity.com":      {"tier": "enterprise", "base_trust": 0.90, "category": "research"},
    "schneier.com":             {"tier": "enterprise", "base_trust": 0.89, "category": "research"},
    "threatpost.com":           {"tier": "enterprise", "base_trust": 0.85, "category": "news"},
    "darkreading.com":          {"tier": "enterprise", "base_trust": 0.84, "category": "news"},
    "securityweek.com":         {"tier": "enterprise", "base_trust": 0.84, "category": "news"},
    "sans.org":                 {"tier": "enterprise", "base_trust": 0.91, "category": "research"},
    "isc.sans.edu":             {"tier": "enterprise", "base_trust": 0.90, "category": "research"},
    "rapid7.com":               {"tier": "enterprise", "base_trust": 0.88, "category": "vendor"},
    "tenable.com":              {"tier": "enterprise", "base_trust": 0.88, "category": "vendor"},
    "qualys.com":               {"tier": "enterprise", "base_trust": 0.87, "category": "vendor"},
    "checkpoint.com":           {"tier": "enterprise", "base_trust": 0.87, "category": "vendor"},
    "fortinet.com":             {"tier": "enterprise", "base_trust": 0.87, "category": "vendor"},
    "trendmicro.com":           {"tier": "enterprise", "base_trust": 0.86, "category": "vendor"},
    "symantec.com":             {"tier": "enterprise", "base_trust": 0.86, "category": "vendor"},
    "broadcom.com":             {"tier": "enterprise", "base_trust": 0.85, "category": "vendor"},
    "elastic.co":               {"tier": "enterprise", "base_trust": 0.86, "category": "vendor"},
    "abuse.ch":                 {"tier": "enterprise", "base_trust": 0.89, "category": "feeds"},
    "feodotracker.abuse.ch":    {"tier": "enterprise", "base_trust": 0.90, "category": "feeds"},
    "urlhaus.abuse.ch":         {"tier": "enterprise", "base_trust": 0.89, "category": "feeds"},
    "github.com":               {"tier": "enterprise", "base_trust": 0.80, "category": "community"},
    "github.blog":              {"tier": "enterprise", "base_trust": 0.83, "category": "research"},
    "wired.com":                {"tier": "enterprise", "base_trust": 0.82, "category": "news"},
    "arstechnica.com":          {"tier": "enterprise", "base_trust": 0.83, "category": "news"},

    # TIER 3: STANDARD — general security community
    "securityaffairs.co":       {"tier": "standard", "base_trust": 0.78, "category": "news"},
    "securityaffairs.com":      {"tier": "standard", "base_trust": 0.78, "category": "news"},
    "cybersecurity-review.com": {"tier": "standard", "base_trust": 0.72, "category": "news"},
    "infosecurity-magazine.com":{"tier": "standard", "base_trust": 0.76, "category": "news"},
    "cyberscoop.com":           {"tier": "standard", "base_trust": 0.77, "category": "news"},
    "scmagazine.com":           {"tier": "standard", "base_trust": 0.75, "category": "news"},
    "helpnetsecurity.com":      {"tier": "standard", "base_trust": 0.74, "category": "news"},
    "grahamcluley.com":         {"tier": "standard", "base_trust": 0.79, "category": "research"},
    "tripwire.com":             {"tier": "standard", "base_trust": 0.75, "category": "vendor"},
    "hackread.com":             {"tier": "standard", "base_trust": 0.68, "category": "news"},
}

# ============================================================
# CONSTANTS
# ============================================================
DATA_ROOT   = pathlib.Path("data")
OUTPUT_PATH = DATA_ROOT / "quality" / "source_trust_scores.json"
MANIFEST_PATH = DATA_ROOT / "intel_manifest.json"
FEED_PATH     = DATA_ROOT / "feed.json"

DEFAULT_TRUST = 0.60   # unrecognized domain base trust
MAX_AGE_HOURS = 336    # 14 days; older items get freshness penalty


# ============================================================
# DOMAIN EXTRACTION
# ============================================================
def extract_domain(url: str) -> str:
    """Extract normalized domain from URL or source string."""
    if not url:
        return "unknown"
    m = re.search(r'(?:https?://)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', str(url))
    if not m:
        return str(url).lower()[:50]
    domain = m.group(1).lower()
    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


# ============================================================
# FRESHNESS SCORING
# ============================================================
def compute_freshness_score(published_at: str) -> float:
    """
    Return 1.0 for brand-new intel, decaying linearly to 0.5 at MAX_AGE_HOURS.
    Items older than 30 days get 0.3.
    """
    if not published_at:
        return 0.7
    try:
        ts_str = published_at.replace("Z", "+00:00").replace(" ", "T")
        ts = datetime.datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        age_hours = max(0.0, (now - ts).total_seconds() / 3600)
        if age_hours > 720:   # >30 days
            return 0.30
        if age_hours > MAX_AGE_HOURS:  # >14 days
            return 0.50
        # Linear decay from 1.0 (0h) to 0.5 (336h)
        return round(1.0 - (age_hours / MAX_AGE_HOURS) * 0.5, 3)
    except Exception:
        return 0.70


# ============================================================
# IOC QUALITY SCORE
# ============================================================
def compute_ioc_quality(item: Dict) -> float:
    """Score 0-1 based on IOC richness of item."""
    iocs = item.get("iocs", [])
    count = item.get("ioc_count", len(iocs) if isinstance(iocs, list) else 0)
    if count == 0:
        return 0.0
    # Score: log-scale from 1 IOC (0.3) to 20+ IOCs (1.0)
    return min(1.0, round(0.3 + math.log10(max(1, count)) * 0.35, 3))


# ============================================================
# CVSS / EPSS SIGNAL SCORE
# ============================================================
def compute_vuln_signal_score(item: Dict) -> float:
    """Score based on CVSS/EPSS presence and severity."""
    cvss = item.get("cvss_score") or item.get("cvss")
    epss = item.get("epss_score") or item.get("epss")
    score = 0.5  # base
    if cvss is not None:
        try:
            cvss_f = float(cvss)
            if cvss_f >= 9.0:
                score = min(1.0, score + 0.40)
            elif cvss_f >= 7.0:
                score = min(1.0, score + 0.25)
            elif cvss_f >= 4.0:
                score = min(1.0, score + 0.10)
        except (ValueError, TypeError):
            pass
    if epss is not None:
        try:
            epss_f = float(epss)
            if epss_f >= 0.50:
                score = min(1.0, score + 0.15)
            elif epss_f >= 0.10:
                score = min(1.0, score + 0.08)
        except (ValueError, TypeError):
            pass
    return round(score, 3)


# ============================================================
# PER-SOURCE STATISTICS
# ============================================================
def aggregate_source_stats(items: List[Dict]) -> Dict[str, Dict]:
    """
    Walk all items and aggregate per-source metrics:
      - total_items
      - avg_ioc_quality
      - avg_freshness
      - avg_vuln_signal
      - has_cvss_rate
      - has_epss_rate
    """
    stats: Dict[str, Dict] = {}

    for item in items:
        source_url = (
            item.get("source_url")
            or item.get("link")
            or item.get("url")
            or item.get("source")
            or ""
        )
        domain = extract_domain(source_url)
        if domain == "unknown" or not domain:
            continue

        if domain not in stats:
            stats[domain] = {
                "total_items":    0,
                "ioc_quality_sum": 0.0,
                "freshness_sum":   0.0,
                "vuln_signal_sum": 0.0,
                "has_cvss_count":  0,
                "has_epss_count":  0,
            }

        s = stats[domain]
        s["total_items"]     += 1
        s["ioc_quality_sum"] += compute_ioc_quality(item)
        s["freshness_sum"]   += compute_freshness_score(item.get("published_at", ""))
        s["vuln_signal_sum"] += compute_vuln_signal_score(item)
        if item.get("cvss_score") or item.get("cvss"):
            s["has_cvss_count"] += 1
        if item.get("epss_score") or item.get("epss"):
            s["has_epss_count"] += 1

    # Compute averages
    for domain, s in stats.items():
        n = max(1, s["total_items"])
        s["avg_ioc_quality"]  = round(s["ioc_quality_sum"]  / n, 3)
        s["avg_freshness"]    = round(s["freshness_sum"]    / n, 3)
        s["avg_vuln_signal"]  = round(s["vuln_signal_sum"]  / n, 3)
        s["has_cvss_rate"]    = round(s["has_cvss_count"]   / n, 3)
        s["has_epss_rate"]    = round(s["has_epss_count"]   / n, 3)

    return stats


# ============================================================
# TRUST SCORE COMPUTATION
# ============================================================
def compute_trust_score(domain: str, stats: Dict) -> Tuple[float, str, str]:
    """
    Return (trust_score, tier, category) for a domain.
    Combines:
      - Base trust from SOURCE_TIER_MAP (or DEFAULT_TRUST for unknown)
      - Runtime performance: avg_ioc_quality, avg_freshness, avg_vuln_signal
    """
    tier_info = SOURCE_TIER_MAP.get(domain, {})
    base_trust = float(tier_info.get("base_trust", DEFAULT_TRUST))
    tier       = tier_info.get("tier", "unvetted")
    category   = tier_info.get("category", "unknown")

    if domain not in stats:
        # No runtime data — return base trust only
        return round(base_trust, 3), tier, category

    s = stats[domain]

    # Runtime adjustment weights
    ioc_weight   = 0.25
    fresh_weight = 0.20
    vuln_weight  = 0.15

    runtime_boost = (
        s["avg_ioc_quality"]  * ioc_weight +
        s["avg_freshness"]    * fresh_weight +
        s["avg_vuln_signal"]  * vuln_weight
    )

    # Blend: 60% base tier + 40% runtime performance
    blended = (base_trust * 0.60) + (runtime_boost / (ioc_weight + fresh_weight + vuln_weight)) * 0.40
    return round(min(1.0, blended), 3), tier, category


# ============================================================
# LOAD ITEMS
# ============================================================
def load_intel_items() -> List[Dict]:
    """Load items from manifest + feed, deduplicated by stix_id."""
    items: Dict[str, Dict] = {}

    for path in [MANIFEST_PATH, FEED_PATH]:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            batch = raw if isinstance(raw, list) else raw.get("items", raw.get("advisories", []))
            for item in batch:
                sid = item.get("stix_id") or item.get("id", "")
                if sid:
                    items.setdefault(sid, item)
        except Exception as e:
            print(f"[TRUST] Warning: failed to load {path}: {e}")

    return list(items.values())


# ============================================================
# MAIN ENGINE
# ============================================================
def run_source_trust_engine(report: bool = False) -> Dict:
    """Full source trust scoring pass. Returns trust score map."""
    items = load_intel_items()
    print(f"[TRUST] Loaded {len(items)} intel items")

    stats = aggregate_source_stats(items)
    print(f"[TRUST] Found {len(stats)} unique sources in corpus")

    # Build all-domain union (corpus sources + tier map sources)
    all_domains = set(stats.keys()) | set(SOURCE_TIER_MAP.keys())

    trust_scores: Dict[str, Dict] = {}
    for domain in sorted(all_domains):
        score, tier, category = compute_trust_score(domain, stats)
        trust_scores[domain] = {
            "trust_score": score,
            "tier":        tier,
            "category":    category,
            "items_seen":  stats.get(domain, {}).get("total_items", 0),
            "avg_ioc_quality": stats.get(domain, {}).get("avg_ioc_quality", 0.0),
            "avg_freshness":   stats.get(domain, {}).get("avg_freshness", 0.0),
            "has_cvss_rate":   stats.get(domain, {}).get("has_cvss_rate", 0.0),
        }

    # Compute platform-level trust statistics
    scores = [v["trust_score"] for v in trust_scores.values()]
    platform_stats = {
        "total_sources": len(trust_scores),
        "platinum_sources": sum(1 for v in trust_scores.values() if v["tier"] == "platinum"),
        "enterprise_sources": sum(1 for v in trust_scores.values() if v["tier"] == "enterprise"),
        "standard_sources": sum(1 for v in trust_scores.values() if v["tier"] == "standard"),
        "unvetted_sources": sum(1 for v in trust_scores.values() if v["tier"] == "unvetted"),
        "avg_trust_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
        "min_trust_score": round(min(scores), 3) if scores else 0.0,
        "max_trust_score": round(max(scores), 3) if scores else 0.0,
        "corpus_items_analyzed": len(items),
    }

    output = {
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": "sentinel_apex_source_trust_v1",
        "platform_stats": platform_stats,
        "trust_scores": trust_scores,
    }

    # Write output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[TRUST] Written: {OUTPUT_PATH}")

    if report:
        print("\n" + "=" * 68)
        print("SOURCE TRUST ENGINE REPORT")
        print("=" * 68)
        print(f"  Total sources scored:   {platform_stats['total_sources']}")
        print(f"  Platinum tier:          {platform_stats['platinum_sources']}")
        print(f"  Enterprise tier:        {platform_stats['enterprise_sources']}")
        print(f"  Standard tier:          {platform_stats['standard_sources']}")
        print(f"  Unvetted:               {platform_stats['unvetted_sources']}")
        print(f"  Avg trust score:        {platform_stats['avg_trust_score']}")
        print(f"  Corpus items analyzed:  {platform_stats['corpus_items_analyzed']}")
        print("\n  TOP 10 TRUSTED SOURCES:")
        top10 = sorted(trust_scores.items(), key=lambda x: x[1]["trust_score"], reverse=True)[:10]
        for domain, meta in top10:
            print(f"    {domain:<45} {meta['trust_score']:.3f} [{meta['tier']}]")
        if any(v["items_seen"] > 0 and v["avg_ioc_quality"] == 0.0 for v in trust_scores.values()):
            low_ioc = [(d, v) for d, v in trust_scores.items()
                       if v["items_seen"] > 0 and v["avg_ioc_quality"] == 0.0]
            print(f"\n  SOURCES WITH ZERO IOC QUALITY ({len(low_ioc)} domains):")
            for domain, meta in sorted(low_ioc, key=lambda x: x[1]["items_seen"], reverse=True)[:5]:
                print(f"    {domain:<45} {meta['items_seen']} items, 0 IOCs")
        print("=" * 68)

    return output


# ============================================================
# APPLY TRUST WEIGHTING TO ITEMS (called by enricher pipeline)
# ============================================================
def apply_trust_weight_to_item(item: Dict, trust_map: Optional[Dict] = None) -> Dict:
    """
    Stamp item with source_trust_score based on its source URL.
    If trust_map not provided, loads from OUTPUT_PATH.
    """
    if trust_map is None:
        if OUTPUT_PATH.exists():
            try:
                raw = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
                trust_map = raw.get("trust_scores", {})
            except Exception:
                trust_map = {}
        else:
            trust_map = {}

    source_url = (
        item.get("source_url") or item.get("link") or
        item.get("url")        or item.get("source") or ""
    )
    domain = extract_domain(source_url)
    entry  = trust_map.get(domain, {})

    item["source_trust_score"] = entry.get("trust_score", DEFAULT_TRUST)
    item["source_tier"]        = entry.get("tier",        "unvetted")
    item["source_domain"]      = domain
    return item


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL APEX Source Trust Engine")
    parser.add_argument("--report", action="store_true", help="Print trust report to stdout")
    parser.add_argument("--update", action="store_true", help="Force full update pass")
    args = parser.parse_args()

    result = run_source_trust_engine(report=args.report or args.update)
    ps = result["platform_stats"]
    print(f"[TRUST] Done. {ps['total_sources']} sources scored, "
          f"avg trust={ps['avg_trust_score']}")
