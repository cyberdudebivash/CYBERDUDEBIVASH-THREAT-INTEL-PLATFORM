#!/usr/bin/env python3
"""
INTELLIGENCE QUALITY GOVERNOR  v1.0  -- SENTINEL APEX
======================================================
Evaluates and scores each intelligence item on a 0-100 IQ scale.

DIMENSIONS (each 0-10, weighted):
  Title Quality       (10%) -- descriptive, non-generic, CVE-aware
  Actor Quality       (10%) -- attributed vs unattributed
  IOC Quality         (15%) -- valid indicators, no artifacts
  MITRE Quality       (15%) -- ATT&CK technique coverage
  Source Quality      (10%) -- credible source, multi-source bonus
  Enrichment Quality  (20%) -- CVSS, EPSS, KEV, apex_ai
  Confidence Quality  (10%) -- confidence score present and reasonable
  Severity Accuracy   (10%) -- severity matches signals (no LOW for active exploits)

TARGET: Average IQ Score > 85

Usage:
  python3 scripts/intelligence_quality_governor.py [--feed api/feed.json] [--report]
"""
import json, os, sys, re, argparse, datetime, pathlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Source credibility ranking
_SOURCE_TIER = {
    "CISA": 10, "CISA KEV": 10, "NVD": 9, "NIST": 9,
    "Mandiant": 9, "CrowdStrike": 9, "Microsoft": 9, "Google": 9,
    "Wordfence": 8, "Qualys": 8, "Tenable": 8, "Rapid7": 8,
    "Recorded Future": 8, "Palo Alto": 8, "Fortinet": 8,
    "CVE Feed": 7, "Vulners": 6, "AlienVault": 7,
    "Threatpost": 7, "BleepingComputer": 7, "SecurityWeek": 7,
    "CyberDudeBivash Intel": 10, "APEX Telemetry": 10,
}

_GENERIC_TITLE_PATTERNS = [
    re.compile(r'^low security vulnerability', re.I),
    re.compile(r'^medium security vulnerability', re.I),
    re.compile(r'^high security vulnerability', re.I),
    re.compile(r'^security advisory$', re.I),
    re.compile(r'^vulnerability advisory$', re.I),
    re.compile(r'^security update$', re.I),
]


def _score_title(item: dict) -> float:
    title = (item.get("title") or "").strip()
    if not title:
        return 0.0
    score = 5.0
    # Length bonus
    if len(title) > 40:
        score += 1.0
    if len(title) > 70:
        score += 1.0
    # CVE with description
    if re.search(r'CVE-\d{4}-\d+\s*-\s*\w', title):
        score += 2.0
    # Generic title penalty
    for pat in _GENERIC_TITLE_PATTERNS:
        if pat.search(title):
            score -= 3.0
            break
    # Verb/action bonus
    if re.search(r'\b(exploit|attack|bypass|injection|execut|escalat|leak)\b', title, re.I):
        score += 1.0
    return max(0.0, min(10.0, score))


def _score_actor(item: dict) -> float:
    actor_id = item.get("actor_id") or ""
    unattr = ("UNATTR", "UNATTRIBUTED")
    if not actor_id or any(u in actor_id.upper() for u in unattr):
        return 3.0  # no attribution
    if item.get("actor_name") or item.get("actor_attribution"):
        return 10.0
    return 7.0


def _score_iocs(item: dict) -> float:
    iocs = item.get("iocs") or []
    count = item.get("ioc_count") or len(iocs)
    if count == 0:
        return 2.0
    if count >= 10:
        score = 8.0
    elif count >= 5:
        score = 7.0
    elif count >= 2:
        score = 6.0
    else:
        score = 5.0
    # Penalise if iocs contain obvious artifacts
    artifacts = [i for i in iocs if re.search(r'\.(normalize|match|compile|decodefrombytes)\b|^js\.|monoglyphrat', i, re.I)]
    if artifacts:
        score -= 3.0 * min(len(artifacts) / max(len(iocs), 1), 1.0)
    return max(0.0, min(10.0, score))


def _score_mitre(item: dict) -> float:
    ttps = item.get("ttps") or item.get("attack_techniques") or item.get("tags") or []
    mitre = [t for t in ttps if re.match(r'^T\d{4}', str(t))]
    if not mitre:
        return 2.0
    if len(mitre) >= 5:
        return 10.0
    if len(mitre) >= 3:
        return 8.0
    if len(mitre) >= 1:
        return 6.0
    return 2.0


def _score_source(item: dict) -> float:
    source = item.get("source") or ""
    base = _SOURCE_TIER.get(source, 5.0)
    score = float(base)
    if item.get("multi_source") or (item.get("source_count") or 0) > 1:
        score = min(10.0, score + 1.5)
    return score


def _score_enrichment(item: dict) -> float:
    score = 0.0
    if item.get("cvss_score") is not None:
        score += 2.0
    if item.get("epss_score") is not None:
        score += 2.0
    if str(item.get("kev") or "").upper() in ("YES", "TRUE", "1"):
        score += 2.0
    if item.get("apex_ai"):
        score += 2.0
    if item.get("actor_attribution"):
        score += 1.0
    if item.get("detection_rules") or item.get("sigma_rules"):
        score += 1.0
    return min(10.0, score)


def _score_confidence(item: dict) -> float:
    conf = item.get("confidence")
    if conf is None:
        return 4.0
    try:
        c = float(conf)
        if c > 1.0:
            c = c / 100.0
        if c >= 0.80:
            return 10.0
        if c >= 0.60:
            return 8.0
        if c >= 0.40:
            return 6.0
        return 4.0
    except (TypeError, ValueError):
        return 4.0


def _score_severity_accuracy(item: dict) -> float:
    """Penalise severity that is too low for the signals present."""
    sev = (item.get("severity") or "LOW").upper()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    rank = sev_rank.get(sev, 1)

    # Check for signals that mandate HIGH
    kev = str(item.get("kev") or "").upper() in ("YES", "TRUE", "1")
    active_exploit = bool(re.search(r'actively exploit|exploited in the wild|under active attack', 
                                     item.get("title", "") + " " + item.get("description", ""), re.I))
    try:
        cvss = float(item.get("cvss_score") or 0)
    except (TypeError, ValueError):
        cvss = 0

    min_rank = 1
    if kev or active_exploit:
        min_rank = 3  # HIGH
    if cvss >= 9.0:
        min_rank = 3

    if rank >= min_rank:
        return 10.0
    # Severity is too low
    gap = min_rank - rank
    return max(0.0, 10.0 - gap * 4.0)


# Dimension weights (must sum to 1.0)
_WEIGHTS = {
    "title":      0.10,
    "actor":      0.10,
    "ioc":        0.15,
    "mitre":      0.15,
    "source":     0.10,
    "enrichment": 0.20,
    "confidence": 0.10,
    "severity":   0.10,
}
assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"


def score_item(item: dict) -> dict:
    """Score a single item. Returns dict with dimension scores and IQ total."""
    dims = {
        "title":      _score_title(item),
        "actor":      _score_actor(item),
        "ioc":        _score_iocs(item),
        "mitre":      _score_mitre(item),
        "source":     _score_source(item),
        "enrichment": _score_enrichment(item),
        "confidence": _score_confidence(item),
        "severity":   _score_severity_accuracy(item),
    }
    iq = sum(dims[d] * _WEIGHTS[d] * 10 for d in dims)  # scale 0-100
    return {"dimensions": dims, "iq_score": round(iq, 1)}


def score_feed(items: list) -> tuple:
    """Score all items. Returns (scored_items, report)."""
    scored = []
    all_scores = []
    low_iq = []

    for item in items:
        result = score_item(item)
        out = dict(item)
        out["_iq_score"] = result["iq_score"]
        out["_iq_dimensions"] = result["dimensions"]
        scored.append(out)
        all_scores.append(result["iq_score"])
        if result["iq_score"] < 50:
            low_iq.append({"title": item.get("title", "")[:60], "iq": result["iq_score"],
                            "dims": result["dimensions"]})

    avg_iq = round(sum(all_scores) / max(len(all_scores), 1), 1)
    report = {
        "report_type": "intelligence_quality_report",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": "v1.0",
        "total_items": len(items),
        "average_iq_score": avg_iq,
        "target_iq": 85,
        "target_met": avg_iq >= 85,
        "min_iq": min(all_scores) if all_scores else 0,
        "max_iq": max(all_scores) if all_scores else 0,
        "low_iq_items": low_iq[:20],
        "VERDICT": "PASS" if avg_iq >= 85 else "FAIL",
    }
    return scored, report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Intelligence Quality Governor v1.0")
    parser.add_argument("--feed",   default=os.path.join(REPO, "api", "feed.json"))
    parser.add_argument("--report", default=os.path.join(REPO, "reports", "intelligence_quality_report.json"))
    args = parser.parse_args()

    feed_path = pathlib.Path(args.feed)
    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", [])

    print("=" * 60)
    print("INTELLIGENCE QUALITY GOVERNOR  v1.0")
    print(f"Feed: {feed_path}  ({len(items)} items)")
    print("=" * 60)

    scored, report = score_feed(items)
    print(f"Average IQ Score : {report['average_iq_score']} / 100  (target >=85)")
    print(f"Min IQ           : {report['min_iq']}")
    print(f"Max IQ           : {report['max_iq']}")
    print(f"Verdict          : {report['VERDICT']}")
    if report["low_iq_items"]:
        print(f"\nLow IQ items (score < 50):")
        for li in report["low_iq_items"][:5]:
            print(f"  [{li['iq']}] {li['title']}")

    rpath = pathlib.Path(args.report)
    rpath.parent.mkdir(parents=True, exist_ok=True)
    rpath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[REPORT] {rpath}")
    sys.exit(0 if report["target_met"] else 1)
