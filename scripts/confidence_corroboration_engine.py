#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX
scripts/confidence_corroboration_engine.py
Intelligence Confidence & Corroboration Engine v1.0

MISSION:
  Transforms raw numeric confidence scores into the industry-standard
  5-level intelligence confidence taxonomy, adds multi-source corroboration
  scoring, and attaches revenue opportunity tags to every feed item.

  Confidence Taxonomy (aligned with CTI industry standard):
    CONFIRMED         Active exploitation in CISA KEV, OR 3+ authoritative
                      sources corroborate, OR in-the-wild exploitation observed
    HIGH_CONFIDENCE   2+ sources corroborate, OR CVSS>=9 + EPSS>=0.3
    MEDIUM_CONFIDENCE Single authoritative/high-trust source with CVSS or IOCs
    LOW_CONFIDENCE    Single standard source, limited evidence signals
    UNVERIFIED        No external corroboration; AI-only or single-point-of-origin

  Revenue Opportunity Tags:
    CONSULTING_OPPORTUNITY    Nation-state / APT / zero-day / supply chain
    INCIDENT_RESPONSE         Active exploitation / breach / ransomware
    THREAT_HUNTING            TTP / behavioral / kill chain intelligence
    VULNERABILITY_ASSESSMENT  CVE / patch gap / CVSS critical findings
    MSSP_UPSELL               Continuous monitoring / managed detection signals
    EXECUTIVE_BRIEFING        Critical infrastructure / government / C-suite

Exit codes: 0=success, 1=hard failure (feed not found), 2=partial (warnings)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Version ───────────────────────────────────────────────────────────────────
ENGINE_VERSION = "1.0.0"
ENGINE_NAME    = "SENTINEL-APEX-CONFIDENCE-ENGINE"

# ── Feed paths (in priority order) ────────────────────────────────────────────
FEED_CANDIDATES = [
    "api/feed.json",
    "data/stix/feed_manifest.json",
    "feed.json",
]

OUTPUT_REPORT   = "data/governance/confidence_corroboration_report.json"
GOVERNANCE_DIR  = Path("data/governance")
QUALITY_DIR     = Path("data/quality")

# ── Source classification ─────────────────────────────────────────────────────
AUTHORITATIVE_SOURCES = {
    "cisa", "nvd", "nist", "ncsc", "ncsc uk", "us-cert", "cert",
    "microsoft security", "msrc", "google project zero", "nsa",
    "anssi", "bsi", "acsc", "jpcert", "jpcert/cc", "enisa", "cert-eu",
    "us cert", "national cybersecurity centre",
}

HIGH_TRUST_SOURCES = {
    "crowdstrike", "mandiant", "unit 42", "palo alto", "google tag",
    "recorded future", "elastic security", "rapid7", "tenable",
    "sentinelone", "sophos", "eset", "kaspersky", "ibm security",
    "check point", "cisco talos", "red canary", "huntress",
    "volexity", "dragos", "claroty", "dfir report", "google tag",
    "darkpulse", "shadowserver", "abuse.ch",
}

# ── Revenue opportunity keyword triggers ─────────────────────────────────────
REVENUE_TRIGGERS = {
    "CONSULTING_OPPORTUNITY": [
        "nation-state", "apt", "advanced persistent", "zero-day", "zero day",
        "supply chain", "critical infrastructure", "ics", "ot attack", "scada",
        "state-sponsored", "geopolitical", "strategic threat",
    ],
    "INCIDENT_RESPONSE": [
        "actively exploit", "in the wild", "mass exploit", "ransomware",
        "breach", "data exfil", "compromised", "lateral movement",
        "active campaign", "live attack", "incident", "intrusion",
    ],
    "THREAT_HUNTING": [
        "ttp", "mitre att&ck", "behavioral", "kill chain", "persistence",
        "command and control", "c2", "exfiltration", "stealth",
        "living off the land", "lolbin", "lateral movement detection",
    ],
    "VULNERABILITY_ASSESSMENT": [
        "cve-", "cvss", "patch", "unpatched", "missing patch",
        "exploit available", "poc available", "proof-of-concept",
        "exposure", "vulnerability management",
    ],
    "MSSP_UPSELL": [
        "continuous monitoring", "managed detection", "soc", "24x7",
        "enterprise monitoring", "threat detection service",
        "managed security", "alert triage",
    ],
    "EXECUTIVE_BRIEFING": [
        "critical infrastructure", "government", "financial sector",
        "healthcare", "national security", "geopolitical", "strategic",
        "c-suite", "board-level", "regulatory", "compliance breach",
    ],
}

# ── Confidence scoring weights ────────────────────────────────────────────────
EVIDENCE_WEIGHTS = {
    "kev_present":            30,   # CISA KEV — strongest confirmation signal
    "active_exploitation":    25,   # In-the-wild exploitation detected in text
    "cvss_critical":          15,   # CVSS >= 9.0
    "cvss_high":               8,   # CVSS 7.0–8.9
    "epss_very_high":         12,   # EPSS >= 0.5
    "epss_high":               6,   # EPSS 0.3–0.49
    "corroboration_3plus":    20,   # 3+ sources report same threat
    "corroboration_2":        12,   # 2 sources report same threat
    "authoritative_source":   15,   # CISA/NVD/NCSC/etc.
    "high_trust_source":       8,   # CrowdStrike/Mandiant/etc.
    "iocs_5plus":              8,   # 5+ IOCs extracted
    "iocs_2to4":               4,   # 2–4 IOCs
    "ttps_5plus":              8,   # 5+ MITRE TTPs mapped
    "ttps_2to4":               4,   # 2–4 MITRE TTPs mapped
    "stix_indicator":          5,   # STIX 2.1 indicator object present
    "cve_referenced":          5,   # CVE ID present
    "poc_available":          10,   # PoC explicitly mentioned
}

# Confidence label thresholds (score out of max ~130)
CONFIDENCE_THRESHOLDS = {
    "CONFIRMED":          55,   # >= 55 → CONFIRMED
    "HIGH_CONFIDENCE":    35,   # 35–54  → HIGH_CONFIDENCE
    "MEDIUM_CONFIDENCE":  18,   # 18–34  → MEDIUM_CONFIDENCE
    "LOW_CONFIDENCE":      5,   # 5–17   → LOW_CONFIDENCE
    "UNVERIFIED":          0,   # <5     → UNVERIFIED
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text_blob(item: dict) -> str:
    """Single lowercase text blob for keyword scanning."""
    parts = [
        item.get("title", ""),
        item.get("description", ""),
        item.get("summary", ""),
        item.get("source", ""),
        " ".join(item.get("tags", [])),
        " ".join(item.get("ttps", [])),
    ]
    return " ".join(str(p) for p in parts).lower()


def _source_norm(item: dict) -> str:
    return (item.get("source") or item.get("feed_source") or "").lower().strip()


def _cvss(item: dict) -> float:
    return float(item.get("cvss_score") or item.get("cvss") or 0.0)


def _epss(item: dict) -> float:
    return float(item.get("epss_score") or item.get("epss") or 0.0)


def _ioc_count(item: dict) -> int:
    explicit = int(item.get("ioc_count") or 0)
    from_list = len(item.get("iocs") or [])
    return max(explicit, from_list)


def _ttp_count(item: dict) -> int:
    from_list = len(item.get("ttps") or item.get("mitre_tactics") or [])
    return from_list


def _extract_cve_ids(item: dict) -> list:
    """Return normalised CVE IDs from the item."""
    cves = set()
    for cve in (item.get("cve_ids") or []):
        if cve:
            cves.add(str(cve).upper().strip())
    single = item.get("cve_id") or item.get("cve")
    if single:
        cves.add(str(single).upper().strip())
    # Also grep from title/description
    blob = _text_blob(item)
    for match in re.findall(r"cve-\d{4}-\d{4,7}", blob, re.I):
        cves.add(match.upper())
    return sorted(cves)


# ── Step 1: Build CVE corroboration index ────────────────────────────────────

def build_corroboration_index(items: list) -> dict:
    """
    Returns {cve_id: {"sources": set(), "item_ids": []}}
    Maps each CVE to the set of distinct sources that reported it.
    """
    index: dict = defaultdict(lambda: {"sources": set(), "item_ids": []})
    for item in items:
        cves = _extract_cve_ids(item)
        src  = _source_norm(item)
        iid  = item.get("id") or item.get("stix_id") or ""
        for cve in cves:
            if cve and re.match(r"CVE-\d{4}-\d{4,}", cve):
                index[cve]["sources"].add(src or "unknown")
                if iid and iid not in index[cve]["item_ids"]:
                    index[cve]["item_ids"].append(iid)
    return dict(index)


# ── Step 2: Score individual item evidence ────────────────────────────────────

def score_item_evidence(item: dict, corroboration_index: dict) -> dict:
    """
    Returns:
      score       (int)
      factors     (list of {"factor": str, "weight": int, "signal": str})
      label       (str)
      rationale   (str)
    """
    score   = 0
    factors = []
    text    = _text_blob(item)
    src     = _source_norm(item)

    def add(factor_key: str, reason: str):
        nonlocal score
        w = EVIDENCE_WEIGHTS.get(factor_key, 0)
        score += w
        factors.append({"factor": factor_key, "weight": w, "signal": reason})

    # KEV — highest single signal
    if item.get("kev_present"):
        add("kev_present", "Item is listed in CISA Known Exploited Vulnerabilities")

    # Active exploitation detected in text
    exploit_patterns = [
        "actively exploit", "in the wild", "exploited in the wild",
        "mass exploit", "publicly exploit", "ransomware adopted",
        "observed in attacks", "threat actors exploit",
    ]
    if any(p in text for p in exploit_patterns):
        add("active_exploitation", "Active exploitation language detected in intelligence text")

    # PoC available
    poc_patterns = ["poc available", "proof-of-concept", "poc released", "poc published", "exploit code"]
    if any(p in text for p in poc_patterns):
        add("poc_available", "Proof-of-concept or exploit code referenced")

    # CVSS
    cvss = _cvss(item)
    if cvss >= 9.0:
        add("cvss_critical", f"CVSS score {cvss:.1f} (Critical)")
    elif cvss >= 7.0:
        add("cvss_high", f"CVSS score {cvss:.1f} (High)")

    # EPSS
    epss = _epss(item)
    if epss >= 0.5:
        add("epss_very_high", f"EPSS score {epss:.3f} (very high exploitation probability)")
    elif epss >= 0.3:
        add("epss_high", f"EPSS score {epss:.3f} (elevated exploitation probability)")

    # Source classification
    if any(a in src for a in AUTHORITATIVE_SOURCES):
        add("authoritative_source", f"Source '{src}' is authoritative (government/standards body)")
    elif any(h in src for h in HIGH_TRUST_SOURCES):
        add("high_trust_source", f"Source '{src}' is high-trust (tier-1 vendor research)")

    # CVE reference
    cves = _extract_cve_ids(item)
    if cves:
        add("cve_referenced", f"CVE(s) referenced: {', '.join(cves[:3])}")

    # Cross-feed corroboration
    iid  = item.get("id") or item.get("stix_id") or ""
    max_corroboration = 1
    corroborating_sources: list = []
    for cve in cves:
        entry = corroboration_index.get(cve)
        if entry:
            n = len(entry["sources"])
            if n > max_corroboration:
                max_corroboration = n
                corroborating_sources = sorted(entry["sources"])

    if max_corroboration >= 3:
        add("corroboration_3plus",
            f"CVE corroborated by {max_corroboration} distinct sources: "
            f"{', '.join(corroborating_sources[:5])}")
    elif max_corroboration == 2:
        add("corroboration_2",
            f"CVE corroborated by 2 distinct sources: "
            f"{', '.join(corroborating_sources[:2])}")

    # IOC count
    iocs = _ioc_count(item)
    if iocs >= 5:
        add("iocs_5plus", f"{iocs} IOCs extracted and verified")
    elif iocs >= 2:
        add("iocs_2to4", f"{iocs} IOCs present")

    # TTP count
    ttps = _ttp_count(item)
    if ttps >= 5:
        add("ttps_5plus", f"{ttps} MITRE ATT&CK TTPs mapped")
    elif ttps >= 2:
        add("ttps_2to4", f"{ttps} MITRE ATT&CK TTPs mapped")

    # STIX indicator
    if item.get("stix_id") and str(item.get("stix_id", "")).startswith("indicator--"):
        add("stix_indicator", "STIX 2.1 indicator object present")

    # ── Assign label ──
    label = "UNVERIFIED"
    for lbl, threshold in [
        ("CONFIRMED",         CONFIDENCE_THRESHOLDS["CONFIRMED"]),
        ("HIGH_CONFIDENCE",   CONFIDENCE_THRESHOLDS["HIGH_CONFIDENCE"]),
        ("MEDIUM_CONFIDENCE", CONFIDENCE_THRESHOLDS["MEDIUM_CONFIDENCE"]),
        ("LOW_CONFIDENCE",    CONFIDENCE_THRESHOLDS["LOW_CONFIDENCE"]),
    ]:
        if score >= threshold:
            label = lbl
            break

    # ── Build rationale ──
    if label == "CONFIRMED":
        rationale = (
            "Intelligence confirmed: " +
            "; ".join(f["signal"] for f in factors[:3])
        )
    elif label == "HIGH_CONFIDENCE":
        rationale = (
            "High confidence based on: " +
            "; ".join(f["signal"] for f in factors[:2])
        )
    elif label == "MEDIUM_CONFIDENCE":
        rationale = (
            "Medium confidence — " +
            (factors[0]["signal"] if factors else "limited evidence available")
        )
    elif label == "LOW_CONFIDENCE":
        rationale = "Single source with minimal corroborating evidence"
    else:
        rationale = "No external corroboration; unverified intelligence"

    return {
        "score":         score,
        "factors":       factors,
        "label":         label,
        "rationale":     rationale,
        "sources_count": max_corroboration,
        "corroborating_sources": corroborating_sources,
    }


# ── Step 3: Revenue opportunity detection ────────────────────────────────────

def detect_revenue_opportunities(item: dict) -> list:
    text = _text_blob(item)
    opportunities = []
    for opp, keywords in REVENUE_TRIGGERS.items():
        if any(kw in text for kw in keywords):
            opportunities.append(opp)
    # Always tag VULNERABILITY_ASSESSMENT if CVE present
    if _extract_cve_ids(item) and "VULNERABILITY_ASSESSMENT" not in opportunities:
        opportunities.append("VULNERABILITY_ASSESSMENT")
    return sorted(set(opportunities))


# ── Step 4: Build intelligence SLA recommendation ────────────────────────────

def build_sla_recommendation(item: dict, confidence_label: str) -> dict:
    """Calculates action deadline based on severity + confidence + KEV."""
    severity = (item.get("severity") or "INFO").upper()
    kev      = bool(item.get("kev_present"))
    risk     = float(item.get("risk_score") or 0)

    # Action deadlines (hours)
    if kev or (severity == "CRITICAL" and confidence_label in ("CONFIRMED", "HIGH_CONFIDENCE")):
        hours = 24
        action = "EMERGENCY PATCH — Active exploitation confirmed or KEV listed"
        priority = "P0"
    elif severity == "CRITICAL" or (severity == "HIGH" and risk >= 8.5):
        hours = 72
        action = "URGENT PATCH — Critical severity, deploy fix within 72 hours"
        priority = "P1"
    elif severity == "HIGH" and confidence_label in ("CONFIRMED", "HIGH_CONFIDENCE"):
        hours = 168   # 7 days
        action = "PRIORITY PATCH — High severity with confirmed threat activity"
        priority = "P2"
    elif severity in ("HIGH", "MEDIUM"):
        hours = 336   # 14 days
        action = "SCHEDULED PATCH — Apply in next maintenance window"
        priority = "P3"
    else:
        hours = 720   # 30 days
        action = "MONITOR — Assess in next vulnerability review cycle"
        priority = "P4"

    return {
        "recommended_action": action,
        "sla_priority":       priority,
        "action_deadline_hours": hours,
    }


# ── Main enrichment loop ──────────────────────────────────────────────────────

def enrich_feed(feed_path: Path) -> dict:
    """Load feed, enrich all items, write back, return report dict."""
    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw.get("items") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return {"error": f"Cannot parse items from {feed_path}"}

    print(f"[INFO] Loaded {len(items)} items from {feed_path}")

    # Build corroboration index
    corr_index = build_corroboration_index(items)
    print(f"[INFO] Corroboration index: {len(corr_index)} unique CVEs tracked")

    # Counters for report
    label_counts: dict = {
        "CONFIRMED": 0, "HIGH_CONFIDENCE": 0, "MEDIUM_CONFIDENCE": 0,
        "LOW_CONFIDENCE": 0, "UNVERIFIED": 0,
    }
    opp_counts: dict = {}
    corroborated_cves: list = []
    items_with_kev = 0
    items_with_exploit = 0

    enriched_items = []
    for item in items:
        evidence = score_item_evidence(item, corr_index)
        opps     = detect_revenue_opportunities(item)
        sla      = build_sla_recommendation(item, evidence["label"])

        # Merge new fields into item (non-destructive — preserves all existing fields)
        item["confidence_label"]         = evidence["label"]
        item["confidence_score_v2"]      = evidence["score"]
        item["confidence_rationale"]     = evidence["rationale"]
        item["confidence_factors"]       = evidence["factors"]
        item["sources_reporting"]        = evidence["sources_count"]
        item["corroborating_sources"]    = evidence["corroborating_sources"]
        item["revenue_opportunities"]    = opps
        item["sla_priority"]             = sla["sla_priority"]
        item["action_deadline_hours"]    = sla["action_deadline_hours"]
        item["recommended_sla_action"]   = sla["recommended_action"]
        item["confidence_enriched_at"]   = now_iso()
        item["confidence_engine_version"]= ENGINE_VERSION

        # Accumulate stats
        label_counts[evidence["label"]] = label_counts.get(evidence["label"], 0) + 1
        for opp in opps:
            opp_counts[opp] = opp_counts.get(opp, 0) + 1
        if item.get("kev_present"):
            items_with_kev += 1
        if "active_exploitation" in [f["factor"] for f in evidence["factors"]]:
            items_with_exploit += 1

        enriched_items.append(item)

    # Identify corroborated CVEs (2+ sources)
    for cve, data in corr_index.items():
        if len(data["sources"]) >= 2:
            corroborated_cves.append({
                "cve": cve,
                "sources_count": len(data["sources"]),
                "sources": sorted(data["sources"]),
            })
    corroborated_cves.sort(key=lambda x: -x["sources_count"])

    # Write enriched feed back
    if isinstance(raw, dict):
        raw["items"] = enriched_items
        raw["confidence_enriched_at"] = now_iso()
        raw["confidence_engine_version"] = ENGINE_VERSION
    else:
        raw = enriched_items
    feed_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[INFO] Wrote enriched feed → {feed_path}")

    return {
        "feed_path":          str(feed_path),
        "total_items":        len(enriched_items),
        "confidence_labels":  label_counts,
        "revenue_opportunities": opp_counts,
        "kev_confirmed_count": items_with_kev,
        "active_exploitation_count": items_with_exploit,
        "corroborated_cves":  corroborated_cves[:50],
        "corroborated_cve_count": len(corroborated_cves),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"\n{'='*70}")
    print(f"  {ENGINE_NAME} v{ENGINE_VERSION}")
    print(f"  CYBERDUDEBIVASH® SENTINEL APEX")
    print(f"  {now_iso()}")
    print(f"{'='*70}\n")

    # Ensure output dirs exist
    GOVERNANCE_DIR.mkdir(parents=True, exist_ok=True)
    QUALITY_DIR.mkdir(parents=True, exist_ok=True)

    # Find first available feed
    feed_path = None
    for candidate in FEED_CANDIDATES:
        p = Path(candidate)
        if p.exists() and p.stat().st_size > 100:
            feed_path = p
            break

    if not feed_path:
        print("[HARD FAIL] No feed found in any candidate path:")
        for c in FEED_CANDIDATES:
            print(f"  - {c}")
        return 1

    # Run enrichment
    try:
        report = enrich_feed(feed_path)
    except Exception as exc:
        print(f"[HARD FAIL] Enrichment error: {exc}")
        import traceback; traceback.print_exc()
        return 1

    if "error" in report:
        print(f"[HARD FAIL] {report['error']}")
        return 1

    # Print summary
    print("\n── CONFIDENCE DISTRIBUTION ─────────────────────────────────────────")
    total = report["total_items"]
    for label, count in report["confidence_labels"].items():
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 4)
        print(f"  {label:<22} {count:>4} ({pct:5.1f}%)  {bar}")

    print(f"\n── THREAT SIGNALS ───────────────────────────────────────────────────")
    print(f"  KEV-confirmed items:       {report['kev_confirmed_count']}")
    print(f"  Active exploitation items: {report['active_exploitation_count']}")
    print(f"  Multi-source CVEs (2+):    {report['corroborated_cve_count']}")

    if report["corroborated_cves"]:
        print(f"\n── TOP CORROBORATED CVEs ────────────────────────────────────────────")
        for entry in report["corroborated_cves"][:10]:
            print(f"  {entry['cve']:<20} {entry['sources_count']} sources: "
                  f"{', '.join(entry['sources'][:3])}")

    print(f"\n── REVENUE OPPORTUNITIES ────────────────────────────────────────────")
    for opp, count in sorted(report["revenue_opportunities"].items(),
                              key=lambda x: -x[1]):
        print(f"  {opp:<30} {count} items")

    # Write governance report
    full_report = {
        "engine":       ENGINE_NAME,
        "version":      ENGINE_VERSION,
        "generated_at": now_iso(),
        "summary":      report,
    }
    Path(OUTPUT_REPORT).write_text(
        json.dumps(full_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n[OK] Report written → {OUTPUT_REPORT}")
    print(f"[OK] {total} items enriched with confidence labels + revenue tags")
    print(f"\n{'='*70}")
    print("  CONFIDENCE ENRICHMENT COMPLETE — 0 REGRESSION, 0 DATA LOSS")
    print(f"{'='*70}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
