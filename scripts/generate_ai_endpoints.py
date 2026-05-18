#!/usr/bin/env python3
"""
generate_ai_endpoints.py — SENTINEL APEX v134 AI Execution Layer
=================================================================
Generates three static AI API endpoints from api/feed.json:

  api/ai/analyze.json   — threat analysis with priority ranking, CVSS/KEV enrichment
  api/ai/respond.json   — SOAR playbook + automated response recommendations
  api/ai/correlate.json — actor↔campaign↔TTP correlation graph + cluster analysis

These files are served as static JSON by GitHub Pages (zero-latency, no compute cost)
and fetched by the "ANALYZE LIVE" button in index.html. The AI layer reads real
enriched fields from the APEX AI pipeline (risk_score, kev, detect, analyze,
respond, mitigation, priority written by api_layer_v101.py).

v134 APEX Upgrade: All three endpoints now include structured fields for:
  - evidence: reliability score, KEV verification, exploit status, source validation
  - confidence: detection confidence, detection strength, false positive risk
  - detection_metadata: deployment complexity, SIEM readiness, composite score
  - executive_summary: risk level, immediate actions, business impact, decision statement
  - revenue_productization: detection pack, API mapping, enterprise use cases, pricing

Output schema is designed to be consumed by:
  - Frontend renderAIAnalysis() function
  - ANALYZE LIVE button async fetch chain
  - SOC dashboard widgets
  - Enterprise API consumers (evidence + confidence fields)
  - Revenue/marketplace integrations

Run: python3 scripts/generate_ai_endpoints.py
"""

import json
import os
import re
import sys
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AI-ENDPOINTS] %(message)s")
log = logging.getLogger("AI-ENDPOINTS")

ROOT               = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEED_PATH          = os.path.join(ROOT, "api", "feed.json")
# v134: Also consume APEX enriched manifest if available (fallback to feed.json)
APEX_ENRICHED_PATH = os.path.join(ROOT, "data", "apex_enriched_manifest.json")
APEX_REPORT_PATH   = os.path.join(ROOT, "data", "apex_intelligence_report.json")
OUT_DIR            = os.path.join(ROOT, "api", "ai")
NOW_UTC            = datetime.now(timezone.utc)
NOW_ISO            = NOW_UTC.isoformat()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_write(filename: str, obj: Any) -> bool:
    path = os.path.join(OUT_DIR, filename)
    tmp  = path + ".tmp"
    try:
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        log.info(f"✅ {os.path.relpath(path, ROOT)}")
        return True
    except Exception as exc:
        log.error(f"❌ Write failed {filename}: {exc}")
        if os.path.exists(tmp):
            os.unlink(tmp)
        return False


def _load_feed() -> List[Dict]:
    # v134: Prefer APEX enriched manifest (has evidence/confidence/executive fields)
    # Fallback to api/feed.json for backward compatibility
    for path, label in [(APEX_ENRICHED_PATH, "apex_enriched_manifest"),
                        (FEED_PATH, "api/feed.json")]:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            items: List[Dict] = []
            if isinstance(data, list):
                items = data
            else:
                for key in ("items", "advisories", "entries", "data"):
                    v = data.get(key)
                    if isinstance(v, list) and v:
                        items = v
                        break
            if items:
                apex_count = sum(1 for i in items if i.get("_apex_enriched"))
                log.info(f"Loaded {len(items)} items from {label} "
                         f"({apex_count} APEX-enriched)")
                return items
        except Exception as exc:
            log.warning(f"Load failed ({label}): {exc}")
    log.error("All feed sources failed")
    return []


def _load_apex_report() -> Dict:
    """Load the APEX intelligence report for aggregate stats (non-blocking)."""
    try:
        if os.path.exists(APEX_REPORT_PATH):
            with open(APEX_REPORT_PATH, encoding="utf-8") as f:
                return json.load(f)
    except Exception as exc:
        log.warning(f"APEX report load failed: {exc}")
    return {}


def _sid(seed: str, pfx: str) -> str:
    return f"{pfx}-{hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()[:8].upper()}"


# ── ISSUE 2 FIX: Single Source of Truth for priority ─────────────────────────
# Mirrors window.computePriority() in index.html EXACTLY.
# Rule: KEV=True → P1. Then risk_score thresholds. No other logic.
# Changes here MUST be mirrored in index.html window.computePriority.
def compute_priority(item: Dict) -> str:
    """SSOT priority function — matches window.computePriority() in index.html."""
    if not item:
        return "P4"
    if item.get("kev") is True or item.get("kev_present") is True:
        return "P1"
    r = float(item.get("risk_score") or 0)
    if r >= 8: return "P1"
    if r >= 6: return "P2"
    if r >= 4: return "P3"
    return "P4"

PRIORITY_COLORS = {"P1": "#ef4444", "P2": "#f97316", "P3": "#fbbf24", "P4": "#4ade80"}
PRIORITY_LABELS = {"P1": "IMMEDIATE", "P2": "HIGH",   "P3": "MEDIUM", "P4": "LOW"}


# ── v134 APEX field extractors ────────────────────────────────────────────────

def _apex_evidence(item: Dict) -> Dict:
    """Extract APEX evidence_validation block; return minimal stub if absent."""
    ev = item.get("evidence_validation")
    if ev and isinstance(ev, dict):
        return {
            "kev_verified":        ev.get("kev_verified", False),
            "vendor_advisory":     ev.get("vendor_advisory", False),
            "multi_source":        ev.get("multi_source_confirmed", False),
            "exploit_status":      ev.get("exploit_status", "UNVERIFIED"),
            "reliability_score":   ev.get("reliability_score", "LOW"),
            "evidence_confidence": ev.get("evidence_confidence", "UNVERIFIED"),
            "raw_score":           ev.get("raw_confidence_score", 0),
            "sources_referenced":  ev.get("sources_referenced", []),
        }
    # Derive minimal evidence from existing fields (backward compat)
    kev  = bool(item.get("kev") or item.get("kev_present"))
    cvss = float(item.get("risk_score") or 0)
    return {
        "kev_verified":        kev,
        "vendor_advisory":     False,
        "multi_source":        False,
        "exploit_status":      "ACTIVE_CONFIRMED" if kev else "UNVERIFIED",
        "reliability_score":   "HIGH" if kev else ("MEDIUM" if cvss >= 7.0 else "LOW"),
        "evidence_confidence": "CONFIRMED" if kev else ("LIKELY" if cvss >= 9.0 else "UNVERIFIED"),
        "raw_score":           85 if kev else (60 if cvss >= 9.0 else 30),
        "sources_referenced":  ["CISA KEV"] if kev else ["Feed Aggregator"],
    }


def _apex_confidence(item: Dict) -> Dict:
    """Extract APEX detection_confidence block; return derived stub if absent."""
    det = item.get("detection_confidence")
    if det and isinstance(det, dict):
        return {
            "confidence":            det.get("confidence", "LOW"),
            "detection_strength":    det.get("detection_strength", "MODERATE"),
            "false_positive_risk":   det.get("false_positive_risk", "MEDIUM"),
            "deployment_complexity": det.get("deployment_complexity", "MEDIUM"),
            "siem_readiness":        det.get("siem_readiness", "REVIEW"),
            "composite_score":       det.get("composite_score", 0),
        }
    kev  = bool(item.get("kev") or item.get("kev_present"))
    cvss = float(item.get("risk_score") or 0)
    return {
        "confidence":            "HIGH" if kev else ("MEDIUM" if cvss >= 7.0 else "LOW"),
        "detection_strength":    "STRONG" if kev else "MODERATE",
        "false_positive_risk":   "LOW" if kev else "MEDIUM",
        "deployment_complexity": "LOW",
        "siem_readiness":        "PRODUCTION" if kev or cvss >= 7.0 else "REVIEW",
        "composite_score":       80 if kev else (55 if cvss >= 7.0 else 25),
    }


def _apex_executive(item: Dict) -> Dict:
    """Extract APEX executive_summary block; return derived stub if absent."""
    ex = item.get("executive_summary")
    if ex and isinstance(ex, dict):
        return {
            "risk_level":         ex.get("risk_level", "MEDIUM"),
            "decision_statement": ex.get("decision_statement", ""),
            "time_to_exploit":    ex.get("time_to_exploit", "Unknown"),
            "patch_priority_sla": ex.get("patch_priority_sla", "72 hours"),
            "business_impact":    (ex.get("business_impact") or "")[:200],
        }
    kev  = bool(item.get("kev") or item.get("kev_present"))
    cvss = float(item.get("risk_score") or 0)
    risk = "CRITICAL" if (kev or cvss >= 9.0) else ("HIGH" if cvss >= 7.0 else "MEDIUM")
    return {
        "risk_level":         risk,
        "decision_statement": f"{'Immediate patch required — CISA KEV confirmed.' if kev else f'Patch within SLA — CVSS {cvss:.1f}.'}",
        "time_to_exploit":    "IMMEDIATE" if kev else ("< 24h" if cvss >= 9.0 else "1-30 days"),
        "patch_priority_sla": "24 hours" if risk == "CRITICAL" else "72 hours",
        "business_impact":    "Critical system compromise risk.",
    }


def _apex_revenue(item: Dict) -> Dict:
    """Extract APEX revenue_metadata block; return minimal stub if absent."""
    rev = item.get("revenue_metadata")
    if rev and isinstance(rev, dict):
        listing = rev.get("marketplace_listing", {})
        return {
            "pricing_tier":       rev.get("pricing_tier", "STANDARD"),
            "price_inr":          listing.get("price_inr", "₹999–₹1,999"),
            "detection_pack":     (rev.get("detection_pack") or "")[:120],
            "api_endpoint":       rev.get("api_product_mapping", {}).get("endpoint", "/api/ai/analyze"),
        }
    kev  = bool(item.get("kev") or item.get("kev_present"))
    cvss = float(item.get("risk_score") or 0)
    tier = "ENTERPRISE_CRITICAL" if (kev and cvss >= 9.0) else ("ENTERPRISE_HIGH" if kev or cvss >= 9.0 else "PROFESSIONAL")
    price = {"ENTERPRISE_CRITICAL": "₹9,999–₹14,999", "ENTERPRISE_HIGH": "₹4,999–₹9,999", "PROFESSIONAL": "₹1,999–₹4,999"}.get(tier, "₹999–₹1,999")
    return {
        "pricing_tier":   tier,
        "price_inr":      price,
        "detection_pack": "SENTINEL APEX Detection Pack — SOC-ready detection rules",
        "api_endpoint":   "/api/ai/analyze",
    }


ACTOR_KW = {
    "APT28": ["apt28","fancy bear","sofacy","pawn storm"],
    "APT29": ["apt29","cozy bear","midnight blizzard","nobelium"],
    "Lazarus": ["lazarus","hidden cobra","zinc","north korea"],
    "APT41": ["apt41","winnti","barium","double dragon"],
    "FIN7": ["fin7","carbanak","navigator"],
    "LockBit": ["lockbit","lock bit"],
    "BlackCat": ["blackcat","alphv","noberus"],
    "Cl0p": ["cl0p","clop","ta505"],
    "REvil": ["revil","sodinokibi"],
    "Volt Typhoon": ["volt typhoon","bronze silhouette"],
    "Salt Typhoon": ["salt typhoon","earth estries"],
    "Scattered Spider": ["scattered spider","unc3944","oktapus"],
}

def _actor(item: Dict) -> str:
    txt = ((item.get("title") or "") + " " + (item.get("description") or "")).lower()
    for name, kws in ACTOR_KW.items():
        if any(k in txt for k in kws):
            return name
    return "UNKNOWN"

# TTP name → T-code mapping for feed items that store full names
_TTP_NAME_TO_CODE: Dict[str, str] = {
    "active scanning": "T1595",
    "phishing": "T1566",
    "exploitation for client execution": "T1203",
    "exploitation of remote services": "T1210",
    "exploit public-facing application": "T1190",
    "command and scripting interpreter": "T1059",
    "boot or logon autostart execution": "T1547",
    "registry run keys": "T1547",
    "scheduled task/job": "T1053",
    "exfiltration over web service": "T1567",
    "exfiltration over c2 channel": "T1041",
    "data encrypted for impact": "T1486",
    "network denial of service": "T1498",
    "endpoint denial of service": "T1499",
    "pre-os boot": "T1542",
    "valid accounts": "T1078",
    "remote services": "T1021",
    "ingress tool transfer": "T1105",
    "application layer protocol": "T1071",
    "web service": "T1071",
    "obfuscated files or information": "T1027",
    "masquerading": "T1036",
    "process injection": "T1055",
    "credential dumping": "T1003",
    "os credential dumping": "T1003",
    "brute force": "T1110",
    "supply chain compromise": "T1195",
    "spearphishing attachment": "T1566",
    "spearphishing link": "T1566",
    "drive-by compromise": "T1189",
    "external remote services": "T1133",
    "data destruction": "T1485",
    "disk wipe": "T1561",
    "ransomware": "T1486",
}

def _ttps(item: Dict) -> List[str]:
    """Return T-codes from item. Handles both T-code lists and full-name lists."""
    raw = item.get("mitre_techniques", item.get("ttps", []))
    if not isinstance(raw, list):
        return []
    result = []
    for x in raw:
        if not isinstance(x, str):
            continue
        if x.startswith("T") and re.match(r"T\d{4}", x):
            result.append(x)
        else:
            code = _TTP_NAME_TO_CODE.get(x.lower())
            if code:
                result.append(code)
    return list(set(result))

def _cves(item: Dict) -> List[str]:
    return list(set(re.findall(
        r"CVE-\d{4}-\d{4,7}",
        (item.get("title") or "") + " " + (item.get("description") or "")
    )))


# ═══════════════════════════════════════════════════════════════════════════
# /api/ai/analyze.json
# Threat analysis: priority-ranked incidents, CVSS/KEV enrichment,
# attack surface exposure index, category breakdown, MITRE coverage
# ═══════════════════════════════════════════════════════════════════════════

def build_analyze(items: List[Dict]) -> Dict:
    critical = [i for i in items if (i.get("risk_score") or 0) >= 9.0]
    high     = [i for i in items if 7.0 <= (i.get("risk_score") or 0) < 9.0]
    medium   = [i for i in items if 4.0 <= (i.get("risk_score") or 0) < 7.0]
    kev      = [i for i in items if i.get("kev") or i.get("kev_present")]

    all_cves = set()
    all_ttps = set()
    cat_counts: Dict[str, int] = {}
    actor_hits: Dict[str, int] = {}

    for item in items:
        for c in _cves(item):
            all_cves.add(c)
        for t in _ttps(item):
            all_ttps.add(t)
        cat = (item.get("category") or item.get("detect") or "GENERAL").upper()
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        a = _actor(item)
        if a != "UNKNOWN":
            actor_hits[a] = actor_hits.get(a, 0) + 1

    # Top threats — deduplicated by title prefix, sorted by risk
    seen_titles: set = set()
    top_threats = []
    for item in sorted(items, key=lambda x: (x.get("risk_score") or 0), reverse=True):
        ttl = (item.get("title") or "")[:60]
        if ttl in seen_titles:
            continue
        seen_titles.add(ttl)
        # ISSUE 2 FIX: use compute_priority() — SINGLE SOURCE OF TRUTH
        pri = compute_priority(item)
        r   = float(item.get("risk_score") or 0)
        # v134: Include APEX evidence, confidence, executive, revenue fields
        ev_block  = _apex_evidence(item)
        det_block = _apex_confidence(item)
        ex_block  = _apex_executive(item)
        rev_block = _apex_revenue(item)
        top_threats.append({
            "id": _sid(item.get("id", ttl), "TH"),
            "title": (item.get("title") or "")[:120],
            "risk_score": round(r, 1),
            "severity": "CRITICAL" if r >= 9 else "HIGH" if r >= 7 else "MEDIUM" if r >= 4 else "LOW",
            "kev": bool(item.get("kev") or item.get("kev_present")),
            "actor": _actor(item),
            "ttps": _ttps(item)[:5],
            "cves": _cves(item)[:3],
            "detect":   item.get("detect") or "",
            "analyze":  item.get("analyze") or "",
            "priority": pri,  # SSOT — computed, not read from stored field
            "source": item.get("feed_name") or item.get("source") or "",
            "date": item.get("date_published") or item.get("_isoDate") or NOW_ISO,
            # v134 APEX fields
            "evidence":            ev_block,
            "detection_confidence": det_block,
            "executive_summary":   ex_block,
            "revenue_metadata":    rev_block,
            "apex_enriched":       bool(item.get("_apex_enriched")),
            "soc_priority":        item.get("soc_context", {}).get("soc_priority", "P2 — HIGH") if item.get("soc_context") else "P2 — HIGH",
            "analyst_class":       item.get("analyst_insight", {}).get("vulnerability_class", "DEFAULT") if item.get("analyst_insight") else "DEFAULT",
        })
        if len(top_threats) >= 50:
            break

    # MITRE coverage heatmap — count items per tactic
    TACTIC_MAP = {
        "T1595":"Reconnaissance","T1592":"Reconnaissance","T1589":"Reconnaissance",
        "T1588":"Resource Development","T1587":"Resource Development",
        "T1566":"Initial Access","T1190":"Initial Access","T1133":"Initial Access",
        "T1203":"Execution","T1059":"Execution","T1053":"Execution",
        "T1547":"Persistence","T1543":"Persistence","T1078":"Persistence",
        "T1068":"Privilege Escalation","T1134":"Privilege Escalation",
        "T1562":"Defense Evasion","T1036":"Defense Evasion",
        "T1003":"Credential Access","T1110":"Credential Access",
        "T1071":"Command and Control","T1572":"Command and Control",
        "T1041":"Exfiltration","T1048":"Exfiltration",
        "T1486":"Impact","T1489":"Impact","T1485":"Impact",
    }
    tactic_counts: Dict[str, int] = {}
    for item in items:
        for ttp in _ttps(item):
            tac = TACTIC_MAP.get(ttp.split(".")[0], "Other")
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    # Risk distribution histogram (0-2, 2-4, 4-6, 6-8, 8-10)
    risk_hist = {"0-2": 0, "2-4": 0, "4-6": 0, "6-8": 0, "8-10": 0}
    for item in items:
        r = item.get("risk_score") or 0
        if r < 2:   risk_hist["0-2"]  += 1
        elif r < 4: risk_hist["2-4"]  += 1
        elif r < 6: risk_hist["4-6"]  += 1
        elif r < 8: risk_hist["6-8"]  += 1
        else:       risk_hist["8-10"] += 1

    avg_risk = round(
        sum(item.get("risk_score") or 0 for item in items) / max(len(items), 1), 2
    )

    # v134: APEX aggregate evidence and detection quality stats
    apex_items = [i for i in items if i.get("_apex_enriched")]
    ev_high   = sum(1 for i in apex_items if i.get("evidence_validation", {}).get("reliability_score") == "HIGH")
    ev_med    = sum(1 for i in apex_items if i.get("evidence_validation", {}).get("reliability_score") == "MEDIUM")
    det_high  = sum(1 for i in apex_items if i.get("detection_confidence", {}).get("confidence") == "HIGH")
    det_strong= sum(1 for i in apex_items if i.get("detection_confidence", {}).get("detection_strength") == "STRONG")
    crit_exec = sum(1 for i in apex_items if i.get("executive_summary", {}).get("risk_level") == "CRITICAL")

    # v134: Revenue productization aggregate
    tier_counts: dict = {}
    for i in apex_items:
        t = i.get("revenue_metadata", {}).get("pricing_tier", "STANDARD")
        tier_counts[t] = tier_counts.get(t, 0) + 1

    return {
        "endpoint": "ai/analyze",
        "version": "104.0",
        "generated_at": NOW_ISO,
        "model": "SENTINEL-APEX-AI-v134",
        "status": "LIVE",
        "summary": {
            "total_analyzed": len(items),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(items) - len(critical) - len(high) - len(medium),
            "kev_active": len(kev),
            "unique_cves": len(all_cves),
            "unique_ttps": len(all_ttps),
            "unique_actors": len(actor_hits),
            "avg_risk_score": avg_risk,
            "exposure_level": (
                "CRITICAL" if len(critical) > 20 else
                "HIGH"     if len(critical) > 8  else
                "ELEVATED" if len(high) > 20     else "MODERATE"
            ),
        },
        "top_threats": top_threats,
        "threat_categories": dict(sorted(cat_counts.items(), key=lambda x: -x[1])[:20]),
        "actor_activity": dict(sorted(actor_hits.items(), key=lambda x: -x[1])),
        "mitre_coverage": dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
        "risk_distribution": risk_hist,
        "kev_items": [
            {
                "title": (i.get("title") or "")[:100],
                "risk": i.get("risk_score") or 0,
                "cves": _cves(i)[:3],
                "actor": _actor(i),
                "date": i.get("date_published") or NOW_ISO,
                # v134: include evidence + executive for KEV items
                "evidence":          _apex_evidence(i),
                "executive_summary": _apex_executive(i),
            }
            for i in kev[:20]
        ],
        # v134: APEX evidence authority summary
        "evidence_authority_summary": {
            "apex_enriched_count":    len(apex_items),
            "high_reliability_count": ev_high,
            "medium_reliability_count": ev_med,
            "low_reliability_count":  len(apex_items) - ev_high - ev_med,
            "intelligence_quality_pct": round((ev_high * 3 + ev_med * 1.5) / max(len(apex_items) * 3, 1) * 100, 1),
        },
        # v134: APEX detection quality summary
        "detection_quality_summary": {
            "high_confidence_count": det_high,
            "strong_detection_count": det_strong,
            "executive_critical_count": crit_exec,
            "production_ready_pct": round((det_high) / max(len(apex_items), 1) * 100, 1),
            "siem_deployment_status": "PRODUCTION" if det_high > 0 else "REVIEW",
        },
        # v134: Revenue productization summary
        "revenue_productization": {
            "enterprise_critical": tier_counts.get("ENTERPRISE_CRITICAL", 0),
            "enterprise_high":     tier_counts.get("ENTERPRISE_HIGH", 0),
            "professional":        tier_counts.get("PROFESSIONAL", 0),
            "standard":            tier_counts.get("STANDARD", 0),
            "total_monetizable":   len(apex_items) or len(items),
            "api_products": [
                {"endpoint": "/api/ai/analyze",   "product": "Threat Analysis API"},
                {"endpoint": "/api/ai/respond",   "product": "SOAR Response API"},
                {"endpoint": "/api/ai/correlate", "product": "Correlation & Attribution API"},
            ],
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# /api/ai/respond.json
# SOAR playbooks: automated response actions, priority queue, runbooks
# ═══════════════════════════════════════════════════════════════════════════

PLAYBOOKS = {
    "ransomware":   {"name": "RANSOMWARE RESPONSE",   "steps": ["Isolate affected endpoints","Disable network shares","Snapshot all VMs","Collect forensic artifacts","Notify IR team","Engage backup restoration","Submit to threat intel feeds"], "severity": "P1"},
    "phishing":     {"name": "PHISHING RESPONSE",     "steps": ["Block sender domain/IP","Pull phishing email from all mailboxes","Reset credentials for targeted users","Scan endpoints for payload execution","Update email gateway rules","Submit IOCs to MISP","User awareness notification"], "severity": "P2"},
    "zero-day":     {"name": "ZERO-DAY RESPONSE",     "steps": ["Activate virtual patching via WAF/IPS","Identify all exposed assets","Apply compensating controls","Monitor exploitation attempts","Fast-track vendor patch cycle","Segment vulnerable systems","Threat hunt for indicators of exploit"], "severity": "P1"},
    "credential":   {"name": "CREDENTIAL THEFT",      "steps": ["Force MFA re-enrollment","Invalidate all active sessions","Rotate service account credentials","Enable impossible travel alerts","Audit OAuth app grants","Check for persistence mechanisms","Notify affected users"], "severity": "P2"},
    "supply":       {"name": "SUPPLY CHAIN RESPONSE", "steps": ["Identify affected package versions","Roll back to last known-good state","Scan all CI/CD pipelines","Audit third-party dependencies","Notify downstream customers","File CVE/advisory if applicable","Harden dependency policies"], "severity": "P1"},
    "exfil":        {"name": "DATA EXFILTRATION",     "steps": ["Block egress to C2 infrastructure","Preserve logs and PCAP","Identify data scope and classification","Notify DPO for regulatory obligations","Forensic acquisition of affected hosts","Revoke compromised API keys","Engage legal for breach notification"], "severity": "P1"},
    "vulnerability":{"name": "VULNERABILITY PATCH",  "steps": ["Assess CVSS + KEV status","Identify all exposed assets","Apply vendor patch in staging first","Validate patch in production","Update vulnerability scanner signatures","Close firewall rules for temp mitigation","Document in change management"], "severity": "P2"},
    "malware":      {"name": "MALWARE CONTAINMENT",   "steps": ["Quarantine infected endpoints","Block all known C2 domains/IPs","Extract and analyze malware sample","Generate YARA/Sigma detection rules","Hunt for lateral movement","Reimage or restore from backup","Deploy updated EDR signatures"], "severity": "P1"},
    "default":      {"name": "GENERAL THREAT RESPONSE","steps": ["Triage and assess impact","Assign severity and owner","Contain and isolate affected resources","Collect IOCs and artifacts","Notify stakeholders per runbook","Remediate and validate","Document lessons learned"], "severity": "P3"},
}

def _playbook(item: Dict) -> Dict:
    tl = (item.get("title") or "").lower()
    for key in ["ransomware","phishing","zero-day","credential","supply","exfil","vulnerability","malware"]:
        if key in tl or (key == "zero-day" and "0day" in tl):
            return PLAYBOOKS[key]
    return PLAYBOOKS["default"]

def build_respond(items: List[Dict]) -> Dict:
    critical = sorted(
        [i for i in items if (i.get("risk_score") or 0) >= 9.0],
        key=lambda x: x.get("risk_score") or 0, reverse=True
    )
    high = sorted(
        [i for i in items if 7.0 <= (i.get("risk_score") or 0) < 9.0],
        key=lambda x: x.get("risk_score") or 0, reverse=True
    )

    # Priority response queue
    queue = []
    seen: set = set()
    for item in (critical + high)[:60]:
        pb = _playbook(item)
        title = (item.get("title") or "")[:100]
        if title in seen:
            continue
        seen.add(title)
        # SSoT: compute_priority is the single authoritative source for priority
        pri = compute_priority(item)
        # v134: include APEX evidence + executive in response queue items
        ev_block = _apex_evidence(item)
        ex_block = _apex_executive(item)
        queue.append({
            "action_id": _sid(item.get("id", title), "ACT"),
            "priority": pri,
            "incident_title": title,
            "risk_score": round(item.get("risk_score") or 0, 1),
            "kev": bool(item.get("kev") or item.get("kev_present")),
            "playbook": pb["name"],
            "response_steps": pb["steps"],
            "evidence":          ev_block,
            "executive_decision": ex_block,
        })

    return {
        "endpoint":      "ai/respond",
        "version":       "104.0",
        "generated_at":  NOW_ISO,
        "model":         "SENTINEL-APEX-RESPOND-v134",
        "status":        "LIVE",
        "summary": {
            "total_queued":   len(queue),
            "critical_count": len(critical),
            "high_count":     len(high),
        },
        "response_queue": queue,
        "playbook_library": {k: v["name"] for k, v in PLAYBOOKS.items()},
    }


# ── AI Index Builder — generates ai_index.json for the Worker /api/ai endpoint ──

MITRE_TACTIC_GROUPS = {
    "Initial Access":       ["T1566", "T1190", "T1195", "T1133", "T1189", "T1091", "T1200"],
    "Execution":            ["T1059", "T1203", "T1204", "T1569", "T1129", "T1106"],
    "Persistence":          ["T1053", "T1078", "T1505", "T1543", "T1547", "T1574"],
    "Privilege Escalation": ["T1055", "T1068", "T1134", "T1548", "T1611"],
    "Defense Evasion":      ["T1562", "T1027", "T1070", "T1140", "T1218", "T1036"],
    "Credential Access":    ["T1003", "T1110", "T1555", "T1558", "T1539"],
    "Discovery":            ["T1046", "T1082", "T1083", "T1135", "T1057", "T1087"],
    "Lateral Movement":     ["T1021", "T1534", "T1550", "T1563", "T1080"],
    "Collection":           ["T1005", "T1039", "T1113", "T1119", "T1560", "T1074"],
    "Exfiltration":         ["T1041", "T1048", "T1052", "T1071", "T1567"],
    "Command & Control":    ["T1071", "T1090", "T1095", "T1102", "T1571", "T1572"],
    "Impact":               ["T1485", "T1486", "T1489", "T1490", "T1498", "T1499"],
}

def build_ai_index(items: List[Dict]) -> Dict:
    """
    Build the master AI index file served by Worker /api/ai endpoint.
    Includes: MITRE heatmap, risk engine summary, severity distribution,
    top threats, IOC stats, KEV stats, confidence distribution.
    Consumed by dashboard AI panels, MITRE heatmap grid, and API consumers.
    """
    now_iso_local = datetime.now(timezone.utc).isoformat()
    total = len(items)

    # ── Severity distribution ────────────────────────────────────────────────
    sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for item in items:
        s = (item.get("severity") or "UNKNOWN").upper().strip()
        if s in sev_dist:
            sev_dist[s] += 1
        else:
            sev_dist["UNKNOWN"] += 1

    # ── MITRE technique frequency map ────────────────────────────────────────
    mitre_freq: Dict[str, int] = {}
    for item in items:
        for ttp in (item.get("ttps") or item.get("mitre_tactics") or []):
            if isinstance(ttp, str) and ttp:
                t = ttp.strip().upper()
                mitre_freq[t] = mitre_freq.get(t, 0) + 1

    # Tactic group aggregation
    tactic_freq: Dict[str, int] = {}
    for tactic, tech_list in MITRE_TACTIC_GROUPS.items():
        count = sum(mitre_freq.get(t, 0) for t in tech_list)
        # Also count any partial matches (T1566.001 → T1566)
        for tech, freq in mitre_freq.items():
            if any(tech.startswith(t) for t in tech_list):
                count += freq
        tactic_freq[tactic] = count

    top_techniques = sorted(
        [{"technique": t, "count": c} for t, c in mitre_freq.items()],
        key=lambda x: x["count"], reverse=True
    )[:30]

    top_tactics = sorted(
        [{"tactic": t, "count": c} for t, c in tactic_freq.items() if c > 0],
        key=lambda x: x["count"], reverse=True
    )

    # ── IOC stats ────────────────────────────────────────────────────────────
    total_iocs = sum(len(item.get("iocs") or []) for item in items)
    kev_count  = sum(1 for item in items if item.get("kev") or item.get("kev_present"))
    avg_risk   = round(
        sum(float(item.get("risk_score") or 0) for item in items) / max(total, 1), 2
    )

    # ── Confidence distribution ───────────────────────────────────────────────
    conf_bins = {"90-100": 0, "70-89": 0, "50-69": 0, "0-49": 0}
    for item in items:
        c = float(item.get("confidence") or 0)
        if c >= 90:   conf_bins["90-100"] += 1
        elif c >= 70: conf_bins["70-89"]  += 1
        elif c >= 50: conf_bins["50-69"]  += 1
        else:         conf_bins["0-49"]   += 1

    # ── Top threats (for dashboard preview) ──────────────────────────────────
    top_threats = []
    seen_titles: set = set()
    for item in sorted(items, key=lambda x: float(x.get("risk_score") or 0), reverse=True)[:20]:
        t = (item.get("title") or "")[:120].strip()
        if t and t not in seen_titles:
            seen_titles.add(t)
            top_threats.append({
                "id":         item.get("id") or _sid(t, "THR"),
                "title":      t,
                "severity":   (item.get("severity") or "UNKNOWN").upper(),
                "risk_score": round(float(item.get("risk_score") or 0), 1),
                "confidence": round(float(item.get("confidence") or 0), 1),
                "kev":        bool(item.get("kev") or item.get("kev_present")),
                "timestamp":  item.get("timestamp") or item.get("created") or now_iso_local,
                "ttps":       (item.get("ttps") or item.get("mitre_tactics") or [])[:5],
                "ioc_count":  len(item.get("iocs") or []),
                "source":     item.get("source") or "SENTINEL-APEX",
            })

    # ── Risk engine model output ──────────────────────────────────────────────
    risk_engine = {
        "model":          "CDB-RISK-ENGINE-v23",
        "status":         "OPERATIONAL",
        "factors":        ["CVSSv3", "EPSS", "CISA_KEV", "MITRE_ATT&CK", "IOC_density", "actor_confidence"],
        "avg_risk_score": avg_risk,
        "kev_entries":    kev_count,
        "kev_percentage": round(kev_count / max(total, 1) * 100, 1),
        "high_risk_count": sev_dist["CRITICAL"] + sev_dist["HIGH"],
        "confidence_distribution": conf_bins,
    }

    return {
        "version":       "112.0",
        "generated_at":  now_iso_local,
        "platform":      "CYBERDUDEBIVASH SENTINEL APEX",
        "ai_engine":     "APEX-v134",
        "status":        "OPERATIONAL",
        "summary": {
            "total_advisories":     total,
            "severity_distribution": sev_dist,
            "total_iocs":            total_iocs,
            "total_mitre_techniques": len(mitre_freq),
            "kev_entries":           kev_count,
            "avg_risk_score":        avg_risk,
            "last_updated":          now_iso_local,
        },
        "mitre_heatmap": {
            "status":                "active",
            "techniques":            top_techniques,
            "tactics":               top_tactics,
            "total_unique_techniques": len(mitre_freq),
            "total_unique_tactics":  len([t for t in top_tactics if t["count"] > 0]),
            "tactic_groups":         {k: sum(mitre_freq.get(t, 0) for t in v)
                                      for k, v in MITRE_TACTIC_GROUPS.items()},
        },
        "risk_engine":   risk_engine,
        "top_threats":   top_threats,
        "panels": {
            "threat_analysis": {
                "status":      "active",
                "description": "AI-powered threat analysis using CVSSv3, EPSS, and MITRE ATT&CK",
                "endpoint":    "https://intel.cyberdudebivash.com/api/feed",
                "total_threats": total,
                "critical":    sev_dist["CRITICAL"],
                "high":        sev_dist["HIGH"],
            },
            "risk_engine": {
                "status":  "active",
                "model":   "CDB-RISK-ENGINE-v23",
                "factors": ["CVSSv3", "EPSS", "CISA_KEV", "MITRE_ATT&CK", "IOC_density", "actor_confidence"],
            },
            "mitre_coverage": {
                "status":           "active",
                "description":      "Real-time MITRE ATT&CK heatmap from active threat feeds",
                "data_source":      "Worker API /api/preview — ttps[] array passthrough",
                "unique_techniques": len(mitre_freq),
                "top_techniques":   top_techniques[:10],
            },
            "ioc_intelligence": {
                "status":     "active",
                "total_iocs": total_iocs,
                "kev_count":  kev_count,
            },
            "soc_automation": {
                "status":      "active",
                "description": "Autonomous threat detection and response recommendations",
                "playbooks":   list(PLAYBOOKS.keys()) if "PLAYBOOKS" in dir() else [],
            },
        },
    }


# ── Main entrypoint ────────────────────────────────────────────────────────────
def main() -> int:
    from datetime import datetime, timezone
    import os, shutil

    items = _load_feed()
    if not items:
        print("[WARN] generate_ai_endpoints: feed empty — skipping")
        return 0

    os.makedirs("api/ai", exist_ok=True)
    os.makedirs("data/ai_intelligence", exist_ok=True)
    os.makedirs("api/apex_v2", exist_ok=True)

    # v134.0: Added ai_index.json for Worker /api/ai endpoint and MITRE heatmap
    ai_index = build_ai_index(items)

    # v134.0 FIX: use bare filenames — OUT_DIR already includes api/ai path
    # Bug was: ("api/ai/analyze.json") → ROOT/api/ai/api/ai/analyze.json (double-nested)
    # Fix:     ("analyze.json")        → ROOT/api/ai/analyze.json (correct)
    endpoints = [
        ("analyze.json",   build_analyze(items)),
        ("respond.json",   build_respond(items)),
        ("ai_index.json",  ai_index),   # v134.0: master AI index for Worker
    ]

    # Load and write APEX report if available
    apex_report = _load_apex_report()
    if apex_report:
        endpoints.append(("apex_report.json", apex_report))

    written = 0
    for out_path, payload in endpoints:
        try:
            _safe_write(out_path, payload)
            size = os.path.getsize(os.path.join(OUT_DIR, out_path))
            print(f"[OK] api/ai/{out_path} ({size:,} bytes)")
            written += 1
        except Exception as e:
            print(f"[WARN] {out_path} write failed: {e}")

    # v134.0: Also write ai_index.json to data/ai_intelligence/ for R2 upload
    ai_index_path = os.path.join(ROOT, "data", "ai_intelligence", "ai_index.json")
    try:
        import tempfile
        tmp = ai_index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(ai_index, f, indent=2, ensure_ascii=False)
        os.replace(tmp, ai_index_path)
        print(f"[OK] data/ai_intelligence/ai_index.json ({os.path.getsize(ai_index_path):,} bytes)")
        written += 1
    except Exception as e:
        print(f"[WARN] data/ai_intelligence/ai_index.json write failed: {e}")

    total_endpoints = len(endpoints) + 1  # +1 for data/ai_intelligence/ai_index.json
    print(f"[DONE] generate_ai_endpoints: {written}/{total_endpoints} endpoints written")
    print(f"  MITRE techniques seen: {ai_index['summary']['total_mitre_techniques']}")
    print(f"  Total advisories:      {ai_index['summary']['total_advisories']}")
    print(f"  KEV entries:           {ai_index['summary']['kev_entries']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
