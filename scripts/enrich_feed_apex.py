#!/usr/bin/env python3
"""
SENTINEL APEX v142.4.0 - Feed APEX AI Enrichment Script
Injects apex_ai, apex (where missing), ioc_paywall, and confidence_score
into ALL items in api/feed.json so the dashboard cards display full intelligence.

ROOT CAUSE FIXED: apex_ai was absent from all 500 items in api/feed.json
because the live API computes these dynamically in the Cloudflare Worker
but never writes them back to the static feed.json used for embedded intel
and fallback rendering.
"""
import json, math, sys, os, hashlib
from pathlib import Path

REPO = Path(__file__).parent.parent
FEED_PATH = REPO / "api" / "feed.json"

# ─── SOC Priority Computation ─────────────────────────────────────────────────
# v166.0 FIX (BUG-10): prefer apex_risk over risk_score; normalise EPSS.
def compute_soc_priority(item):
    risk  = float(item.get("apex_risk") or item.get("risk_score") or 0)
    kev   = bool(item.get("kev_present") or item.get("kev") or item.get("cisa_kev"))
    apex_label = (item.get("apex_risk_label") or "").upper()
    epss_raw = item.get("epss_score") or item.get("epss") or 0
    try:
        epss_f = float(str(epss_raw).rstrip("%"))
        if 0 < epss_f <= 1.0:
            epss_f *= 100.0
    except (ValueError, TypeError):
        epss_f = 0.0
    cvss_raw = item.get("cvss_score") or item.get("cvss") or item.get("base_score") or 0
    try:
        cvss_f = float(cvss_raw)
    except (ValueError, TypeError):
        cvss_f = 0.0

    if kev or epss_f >= 50 or apex_label == "CRITICAL" or risk >= 9:
        return "P1"
    if cvss_f >= 9 or risk >= 7.5 or apex_label == "HIGH":
        return "P1"
    if cvss_f >= 7 or risk >= 6.0:
        return "P2"
    if cvss_f >= 5 or risk >= 4.0 or epss_f >= 20:
        return "P3"
    return "P4"

# ─── Predictive Risk Score (0-10) ─────────────────────────────────────────────
# v166.0 FIX (BUG-11): use apex_risk as baseline; normalise EPSS.
def compute_predictive_risk(item):
    risk  = float(item.get("apex_risk") or item.get("risk_score") or 0)
    kev   = bool(item.get("kev_present") or item.get("kev") or item.get("cisa_kev"))
    ttps  = item.get("ttps") or item.get("mitre_tactics") or []
    ioc_c = int(item.get("ioc_count") or 0)
    cvss_raw = item.get("cvss_score") or item.get("cvss") or item.get("base_score")
    try:
        cvss_f = float(cvss_raw) if cvss_raw is not None else 0.0
    except (ValueError, TypeError):
        cvss_f = 0.0
    epss_raw = item.get("epss_score") or item.get("epss")
    try:
        epss_f = float(str(epss_raw).rstrip("%")) if epss_raw is not None else 0.0
        if epss_f > 1.0:
            epss_f /= 100.0
    except (ValueError, TypeError):
        epss_f = 0.0

    score = risk * 0.40
    if cvss_f:   score += (cvss_f / 10) * 2.5
    if epss_f:   score += epss_f * 2.0
    if kev:      score += 3.0
    if len(ttps) >= 5: score += 0.5
    if ioc_c >= 5:     score += 0.3

    return round(min(10.0, max(0.0, score)), 1)

# ─── AI Confidence (0-100) ────────────────────────────────────────────────────
# v166.0 FIX (BUG-09): previous algorithm started from conf_f*0.6=0 when no
# prior confidence_score, giving 7-14% for CISA KEV CVSS-9 advisories.
def compute_ai_confidence(item):
    ttps  = item.get("ttps") or item.get("mitre_tactics") or []
    ioc_c = int(item.get("ioc_count") or 0)
    kev   = bool(item.get("kev_present") or item.get("kev") or item.get("cisa_kev"))
    cvss_raw = item.get("cvss_score") or item.get("cvss") or item.get("base_score")
    epss_raw = item.get("epss_score") or item.get("epss")
    try:
        cvss_f = float(cvss_raw) if cvss_raw is not None else 0.0
    except (ValueError, TypeError):
        cvss_f = 0.0
    try:
        epss_f = float(str(epss_raw).rstrip("%")) if epss_raw is not None else 0.0
        if epss_f > 1.0:
            epss_f /= 100.0
    except (ValueError, TypeError):
        epss_f = 0.0

    base = 20.0  # Meaningful starting baseline (not 0)
    if kev:
        base += 35
        if cvss_f >= 9.0:   base += 15
        elif cvss_f >= 7.0: base += 10
    if cvss_f >= 9.0:    base += 15
    elif cvss_f >= 7.0:  base += 10
    elif cvss_f >= 4.0:  base += 5
    if epss_f >= 0.70:   base += 12
    elif epss_f >= 0.40: base += 8
    elif epss_f >= 0.10: base += 5
    elif epss_f > 0.0:   base += 2
    if len(ttps) >= 5:   base += 10
    elif len(ttps) >= 3: base += 6
    elif len(ttps) >= 1: base += 3
    if ioc_c >= 10:  base += 8
    elif ioc_c >= 3: base += 5
    elif ioc_c >= 1: base += 2

    return int(min(97, max(10, round(base))))

# ─── TTP Density (0-10) ───────────────────────────────────────────────────────
def compute_ttp_density(item):
    ttps = item.get("ttps") or item.get("mitre_tactics") or []
    # Density is technique count normalised to 10
    return round(min(10.0, len(ttps) * 1.5), 1)

# ─── Threat Level ─────────────────────────────────────────────────────────────
# v166.0 FIX (BUG-11): prefer apex_risk_label/apex_risk.
def compute_threat_level(item):
    sev  = (item.get("apex_risk_label") or item.get("severity") or "MEDIUM").upper()
    kev  = bool(item.get("kev_present") or item.get("kev") or item.get("cisa_kev"))
    risk = float(item.get("apex_risk") or item.get("risk_score") or 0)

    if kev or risk >= 9:
        return "CRITICAL_SURGE"
    if sev == "CRITICAL" or risk >= 7.5:
        return "HIGH_ALERT"
    if sev == "HIGH" or risk >= 6:
        return "ELEVATED"
    if sev == "MEDIUM" or risk >= 4:
        return "MEDIUM"
    return "LOW"

# ─── Threat Category ──────────────────────────────────────────────────────────
THREAT_TYPE_MAP = {
    "vulnerability":   "Vulnerability",
    "malware":         "Malware",
    "ransomware":      "Ransomware",
    "apt":             "Nation-State APT",
    "phishing":        "Phishing",
    "cve":             "CVE / Vulnerability",
    "oss-advisory":    "Supply Chain Risk",
    "threat-intel":    "Threat Intel",
    "exploit":         "Exploit",
    "supply chain":    "Supply Chain Risk",
    "web application": "Web Application Attack",
    "rce":             "Remote Code Execution",
    "sqli":            "SQL Injection",
    "xss":             "Cross-Site Scripting",
}

def compute_threat_category(item):
    tt  = (item.get("threat_type") or "").lower()
    title = (item.get("title") or "").lower()
    # v143.5 FIX: check both apex and apex_ai; treat "UNKNOWN" as absent
    existing_cat = (
        (item.get("apex_ai") or {}).get("threat_category")
        or (item.get("apex") or {}).get("threat_category")
    )
    if existing_cat and existing_cat not in ("", "UNKNOWN", "Threat Intel"):
        return existing_cat

    for key, cat in THREAT_TYPE_MAP.items():
        if key in tt or key in title:
            return cat

    tags = [str(t).lower() for t in (item.get("tags") or [])]
    if any("ransom" in t for t in tags): return "Ransomware"
    if any("phish" in t for t in tags):  return "Phishing"
    if any("malware" in t for t in tags) or any("rat" in t for t in tags): return "Malware"

    return "Threat Intel"

# ─── AI Summary ───────────────────────────────────────────────────────────────
def compute_ai_summary(item, soc_priority, pred_risk, ai_conf, ttp_density, category):
    title    = item.get("title") or ""
    sev      = (item.get("severity") or "MEDIUM").upper()
    risk     = float(item.get("risk_score") or 0)
    kev      = bool(item.get("kev_present"))
    cvss     = item.get("cvss_score")
    epss     = item.get("epss_score")
    ttps     = item.get("ttps") or item.get("mitre_tactics") or []
    actor    = item.get("actor_tag") or ""
    ioc_c    = int(item.get("ioc_count") or 0)
    source   = (item.get("feed_source") or item.get("source") or "").replace("rss_","").replace("_"," ").strip()

    ttp_ids  = []
    for t in ttps[:4]:
        if isinstance(t, dict): ttp_ids.append(t.get("id", ""))
        else: ttp_ids.append(str(t))
    ttp_ids = [x for x in ttp_ids if x]

    lines = []

    # Risk signal
    risk_desc = "critical" if risk >= 9 else "high" if risk >= 7 else "moderate" if risk >= 5 else "low"
    lines.append(f"[{soc_priority}] {category} - {risk_desc} severity (Risk {risk}/10).")

    # KEV / EPSS / CVSS enrichment
    if kev:
        lines.append("[ALERT] CISA KEV CONFIRMED - actively exploited in the wild. Patch immediately.")
    if cvss is not None:
        lines.append(f"CVSS {cvss}/10 severity score.")
    if epss is not None:
        lines.append(f"EPSS {epss}% exploitation probability (30-day forecast).")

    # MITRE ATT&CK
    if ttp_ids:
        lines.append(f"MITRE ATT&CK mapped: {', '.join(ttp_ids)} ({len(ttps)} technique{'s' if len(ttps)>1 else ''}).")
    else:
        lines.append("No MITRE ATT&CK techniques mapped - limited adversarial context.")

    # IOC signal
    if ioc_c > 0:
        lines.append(f"{ioc_c} indicator{'s' if ioc_c>1 else ''} detected - upgrade to Pro for full IOC access.")

    # Actor
    if actor and actor not in ("UNC-CDB-99", "UNC-UNKNOWN", "UNC-CDB-INGEST"):
        lines.append(f"Actor attribution: {actor}.")

    # AI confidence note
    if ai_conf >= 70:
        lines.append(f"AI confidence: HIGH ({ai_conf}%) - strong data corroboration.")
    elif ai_conf >= 40:
        lines.append(f"AI confidence: MODERATE ({ai_conf}%) - partial intelligence corroboration.")
    else:
        lines.append(f"AI confidence: LOW ({ai_conf}%) - limited source data available.")

    return " ".join(lines)

# ─── IOC Paywall ──────────────────────────────────────────────────────────────
def compute_ioc_paywall(item):
    ioc_c = int(item.get("ioc_count") or 0)
    if ioc_c == 0:
        return None
    conf = float(item.get("ioc_confidence") or 0)
    level = (item.get("ioc_threat_level") or "LOW").upper()
    primary_types = []
    ioc_counts = item.get("ioc_counts") or item.get("ioc_counts_by_type") or {}
    for k, v in ioc_counts.items():
        if v and int(v) > 0:
            primary_types.append(k)
    return {
        "locked": True,
        "count": ioc_c,
        "confidence": round(conf, 1),
        "threat_level": level,
        "primary_types": primary_types[:3],
        "upgrade_url": "/upgrade.html?plan=pro",
        "message": f"{ioc_c} IOC(s) at {conf:.1f}% confidence - unlock with Pro tier.",
    }

# ─── Campaign Classification ───────────────────────────────────────────────────
def compute_campaign_id(item):
    existing = (item.get("apex") or {}).get("campaign_id")
    if existing and existing not in ("", "PRO_REQUIRED", "UNCLASSIFIED", None):
        return existing
    actor = (item.get("actor_tag") or "").upper()
    # Known actor patterns
    if actor.startswith("CDB-APT"):  return f"APT-OPS-{actor.replace('CDB-APT-','')[:8]}"
    if actor.startswith("CDB-RAN"):  return f"RANSOMWARE-OPS"
    if actor.startswith("CDB-CVE"):  return "CVE-CAMPAIGN"
    if actor.startswith("CDB-RAT"):  return "MALWARE-OPS"
    if actor.startswith("CDB-MOB"):  return "MOBILE-THREAT"
    return "UNCLASSIFIED"

# ─── Recommended Action ───────────────────────────────────────────────────────
def compute_recommended_action(item, soc_priority, category):
    kev  = bool(item.get("kev_present"))
    risk = float(item.get("risk_score") or 0)
    cvss = item.get("cvss_score")

    if kev:
        return "IMMEDIATE ACTION REQUIRED - CISA KEV confirmed. Apply vendor patch within 24 hours. Isolate affected systems. Enable enhanced logging."
    if soc_priority == "P1":
        return "CRITICAL PRIORITY - Patch within 24-48 hours. Activate IR playbook. Notify SOC lead and CISO."
    if soc_priority == "P2":
        return "HIGH PRIORITY - Patch within 72 hours. Monitor affected assets. Review threat hunting queries for related TTPs."
    if soc_priority == "P3":
        return "STANDARD PRIORITY - Schedule patch within 7 days. Deploy detection rules. Monitor SIEM for related indicators."
    return f"LOW PRIORITY - Monitor for escalation. Apply patch in next maintenance window. Review {category} detection coverage."

# ─── Main Enrichment ──────────────────────────────────────────────────────────
def enrich_item(item):
    soc_priority = compute_soc_priority(item)
    pred_risk    = compute_predictive_risk(item)
    ai_conf      = compute_ai_confidence(item)
    ttp_density  = compute_ttp_density(item)
    threat_level = compute_threat_level(item)
    category     = compute_threat_category(item)
    campaign_id  = compute_campaign_id(item)
    rec_action   = compute_recommended_action(item, soc_priority, category)
    ai_summary   = compute_ai_summary(item, soc_priority, pred_risk, ai_conf, ttp_density, category)
    ioc_paywall  = compute_ioc_paywall(item)

    # v166.0 FIX (BUG-08): use full severity label, not [:1] slice.
    _sev_label = (item.get("apex_risk_label") or item.get("severity") or "UNKNOWN").upper()

    # Inject apex_ai (always - this is the missing field)
    item["apex_ai"] = {
        "soc_priority":   soc_priority,
        "predictive_risk": pred_risk,
        "ai_confidence":   ai_conf,
        "ttp_density":     ttp_density,
        "threat_level":    threat_level,
        "threat_category": category,
        "ai_summary":      ai_summary,
        "recommended_action": rec_action,
        "campaign_id":     campaign_id,
        "actor_fingerprint": f"{item.get('actor_tag','UNK')}::{_sev_label[0]}::{item.get('ioc_count',0)}::{len(item.get('ttps') or item.get('mitre_tactics') or [])}",
        "behavioral_tags": _compute_behavioral_tags(item),
        "kill_chain":      _compute_kill_chain(item),
        "paywall": {
            "message": "Upgrade to Pro for full kill chain analysis, actor attribution, and 30-day threat forecast.",
            "upgrade_url": "/upgrade.html?plan=pro",
            "urgency": f"[SOC {soc_priority}] {category} - {_sev_label} severity threat detected." if soc_priority in ("P1","P2") else None,
        } if soc_priority in ("P1","P2","P3") else None,
    }

    # Inject/update apex (enrich missing fields, keep existing valid ones)
    existing_apex = item.get("apex") or {}
    item["apex"] = {
        "priority":        existing_apex.get("priority") or soc_priority,
        "threat_level":    existing_apex.get("threat_level") or threat_level,
        "threat_category": (existing_apex.get("threat_category")
                            if existing_apex.get("threat_category") not in ("", "UNKNOWN", None)
                            else category),
        "predictive_score": existing_apex.get("predictive_score") if existing_apex.get("predictive_score") is not None else pred_risk,
        "campaign_id":     existing_apex.get("campaign_id") if existing_apex.get("campaign_id") not in ("PRO_REQUIRED", None, "") else campaign_id,
        # v166.0 FIX (BUG-15): store as 0-100 integer, not 0-1 fraction
        "confidence":      existing_apex.get("confidence") or float(ai_conf),
        "behavioral_tags": existing_apex.get("behavioral_tags") or [],
        "ai_summary":      existing_apex.get("ai_summary") or ai_summary,
        "recommended_action": existing_apex.get("recommended_action") or rec_action,
    }

    # Inject ioc_paywall
    if ioc_paywall:
        item["ioc_paywall"] = ioc_paywall

    # v166.0 FIX: always stamp confidence_score from compute_ai_confidence
    if not item.get("confidence_score") or float(item.get("confidence_score") or 0) < 10.0:
        item["confidence_score"] = float(ai_conf)
        item["confidence"] = float(ai_conf)

    # C5/C6 root-cause fix: ensure ioc_confidence and ioc_threat_level are
    # always populated when ioc_count > 0.  The run_pipeline.py auto-fix
    # patches these in batch, but setting them here prevents them from ever
    # being written as 0.0 / "NONE" in the first place (source-of-truth fix).
    _ioc_cnt = int(item.get("ioc_count") or 0)
    if _ioc_cnt > 0:
        if not float(item.get("ioc_confidence") or 0.0):
            item["ioc_confidence"] = round(min(_ioc_cnt * 5.0, 100.0), 2)
        _ioc_lvl = (item.get("ioc_threat_level") or "NONE").upper()
        if _ioc_lvl == "NONE":
            _conf = float(item.get("ioc_confidence") or 0.0)
            if _conf >= 60:
                item["ioc_threat_level"] = "HIGH"
            elif _conf >= 35:
                item["ioc_threat_level"] = "MEDIUM"
            else:
                item["ioc_threat_level"] = "LOW"

    return item

def _compute_behavioral_tags(item):
    tags = []
    title = (item.get("title") or "").lower()
    tt = (item.get("threat_type") or "").lower()
    ttps = item.get("ttps") or item.get("mitre_tactics") or []
    ttp_ids = [t.get("id","") if isinstance(t,dict) else str(t) for t in ttps]

    if item.get("kev_present"): tags.append("KEV-CONFIRMED")
    if "T1059" in ttp_ids: tags.append("CODE-EXECUTION")
    if "T1547" in ttp_ids or "T1542" in ttp_ids: tags.append("PERSISTENCE")
    if "T1567" in ttp_ids or "T1041" in ttp_ids: tags.append("DATA-EXFILTRATION")
    if "T1595" in ttp_ids or "T1203" in ttp_ids: tags.append("INITIAL-ACCESS")
    if "sql" in title or "T1213" in ttp_ids: tags.append("SQL-INJECTION")
    if "xss" in title or "cross-site" in title: tags.append("XSS")
    if "ransomware" in title or "ransomware" in tt: tags.append("RANSOMWARE")
    if "supply chain" in title: tags.append("SUPPLY-CHAIN")
    if "zero-day" in title or "0-day" in title: tags.append("ZERO-DAY")
    if item.get("ioc_count", 0) >= 5: tags.append("HIGH-IOC-DENSITY")
    return tags[:5]

def _compute_kill_chain(item):
    ttps = item.get("ttps") or item.get("mitre_tactics") or []
    ttp_ids = [t.get("id","") if isinstance(t,dict) else str(t) for t in ttps]

    phases = []
    if any(t in ttp_ids for t in ("T1595","T1190","T1133","T1078")): phases.append("Initial Access")
    if any(t in ttp_ids for t in ("T1059","T1203","T1053")): phases.append("Execution")
    if any(t in ttp_ids for t in ("T1547","T1542","T1543")): phases.append("Persistence")
    if any(t in ttp_ids for t in ("T1055","T1134")): phases.append("Privilege Escalation")
    if any(t in ttp_ids for t in ("T1070","T1027")): phases.append("Defense Evasion")
    if any(t in ttp_ids for t in ("T1213","T1083")): phases.append("Discovery")
    if any(t in ttp_ids for t in ("T1041","T1567","T1048")): phases.append("Exfiltration")
    if any(t in ttp_ids for t in ("T1486","T1485")): phases.append("Impact")

    if not phases:
        sev = (item.get("severity") or "MEDIUM").upper()
        if sev in ("CRITICAL","HIGH"):   phases = ["Initial Access", "Execution"]
        elif sev == "MEDIUM":            phases = ["Execution"]
        else:                            phases = []

    if len(phases) < 2 and len(ttps) > 0:
        return "PRO_REQUIRED"  # Encourage upgrade for partial data

    return phases if phases else "PRO_REQUIRED"


def main():
    print("=" * 60)
    print("SENTINEL APEX v142.4.0 - Feed APEX AI Enrichment")
    print("=" * 60)

    if not FEED_PATH.exists():
        print(f"[FAIL] Feed not found: {FEED_PATH}")
        sys.exit(1)

    with open(FEED_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)

    items = raw if isinstance(raw, list) else raw.get("items", [])
    print(f"  Loaded: {len(items)} items from feed.json")

    before_apex_ai = sum(1 for i in items if "apex_ai" in i)
    before_apex    = sum(1 for i in items if "apex" in i)
    print(f"  Before: apex_ai={before_apex_ai}, apex={before_apex}")

    enriched = [enrich_item(item) for item in items]

    after_apex_ai = sum(1 for i in enriched if "apex_ai" in i)
    after_apex    = sum(1 for i in enriched if "apex" in i)
    after_paywall = sum(1 for i in enriched if "ioc_paywall" in i)
    print(f"  After:  apex_ai={after_apex_ai}, apex={after_apex}, ioc_paywall={after_paywall}")

    # Validate a sample
    sample = enriched[0]
    assert "apex_ai" in sample, "apex_ai missing from first item"
    assert "apex"    in sample, "apex missing from first item"
    assert sample["apex_ai"]["soc_priority"] in ("P1","P2","P3","P4"), "bad soc_priority"
    assert isinstance(sample["apex_ai"]["ai_summary"], str) and len(sample["apex_ai"]["ai_summary"]) > 20, "bad ai_summary"
    print(f"  [PASS] Validation OK - sample item: {sample['title'][:50]}")

    # Write back (preserving original structure)
    if isinstance(raw, list):
        out = enriched
    else:
        raw["items"] = enriched
        out = raw

    with open(FEED_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))

    size_kb = FEED_PATH.stat().st_size // 1024
    print(f"  Written: {FEED_PATH} ({size_kb} KB)")
    print()
    print("  Sample apex_ai output:")
    ai = enriched[0]["apex_ai"]
    print(f"    soc_priority    = {ai['soc_priority']}")
    print(f"    predictive_risk = {ai['predictive_risk']}")
    print(f"    ai_confidence   = {ai['ai_confidence']}")
    print(f"    ttp_density     = {ai['ttp_density']}")
    print(f"    threat_level    = {ai['threat_level']}")
    print(f"    threat_category = {ai['threat_category']}")
    print(f"    ai_summary      = {ai['ai_summary'][:80]}...")
    print()
    print("[PASS] APEX AI enrichment complete - all items now have apex_ai and apex fields.")
    print("=" * 60)


if __name__ == "__main__":
    main()
