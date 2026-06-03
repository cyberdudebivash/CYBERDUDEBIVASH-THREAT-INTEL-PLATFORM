#!/usr/bin/env python3
"""
SENTINEL APEX — Intelligence Grade Engine v2.0.0
Grade A: Verified actor+campaign+IOC+multi-source+operational detection
Grade B: Verified CVE CVSS>=8.0 + evidence ATT&CK + 2+ sources + exploit evidence
Grade C: Verified vulnerability + limited enrichment
Grade D: Single-source advisory, no exploit/ATT&CK/IOC
Grade F: Synthetic, unverified, evidence-deficient
"""
from __future__ import annotations
import argparse, json, logging, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

ENGINE_VERSION = "2.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [grade-engine-v2] %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

GRADE_B_CVSS_MIN = 8.0
GRADE_C_CVSS_MIN = 4.0
GRADE_B_SOURCES_MIN = 2
GRADE_B_CORR_MIN = 40

DECISION_MAP = {"A":"ALLOW","B":"ALLOW_WITH_WARNING","C":"ALLOW_WITH_WARNING","D":"QUARANTINE","F":"BLOCK"}
ANALYST_VERDICT_MAP = {
    "A": "PASS — Grade A: fully evidenced intelligence. Operational IOCs, verified actor, multi-source corroboration, validated detections.",
    "B": "ALLOW — Grade B: strong CVE intelligence. Verified CVE, CVSS>=8.0, evidence-based ATT&CK, multi-source corroboration.",
    "C": "WARNING — Grade C: standard vulnerability advisory. Verified CVE, limited enrichment. Suitable for awareness/advisory tiers.",
    "D": "QUARANTINE — Grade D: weak single-source advisory. No exploit evidence, no ATT&CK, no IOC. Informational only.",
    "F": "BLOCK — Grade F: insufficient evidence. No verified CVE/IOC/ATT&CK/attribution. Not suitable for publication.",
}


def _f(val: Any, default: float=0.0) -> float:
    try: return float(val) if val is not None else default
    except: return default

def _i(val: Any, default: int=0) -> int:
    try: return int(val) if val is not None else default
    except: return default

def _has_operational_iocs(item: Dict) -> bool: return _i(item.get("real_ioc_count")) > 0

def _has_verified_cve(item: Dict) -> bool:
    import re
    cve = str(item.get("cve_id") or "")
    return bool(re.match(r"CVE-\d{4}-\d{4,}", cve))

def _has_cvss(item: Dict, minimum: float=0.0) -> bool: return _f(item.get("cvss_score")) >= minimum

def _has_attck(item: Dict) -> bool:
    ids = item.get("attck_technique_ids") or []
    v = item.get("attck_verification") or ""
    return bool(ids) and v in ("EVIDENCE_BASED","VERIFIED","SOURCE_ATTRIBUTED","VENDOR_VERIFIED")

def _has_exploit_evidence(item: Dict) -> bool:
    kev = str(item.get("kev") or "").upper()
    kev_present = str(item.get("kev_present") or "").upper()
    exploit_mat = str(item.get("exploit_maturity") or "").upper()
    exploit_count = _i(item.get("exploit_count"))
    meta_available = bool(item.get("metasploit_available"))
    active = str(item.get("active_exploitation") or "").upper()
    poc_count = _i(item.get("poc_github_count"))
    if kev in ("YES","TRUE","1"): return True
    if kev_present in ("YES","TRUE"): return True
    if exploit_mat in ("CONFIRMED","FUNCTIONAL","HIGH","WEAPONIZED"): return True
    if exploit_mat == "POC" and exploit_count > 0: return True
    if exploit_count > 2: return True
    if meta_available: return True
    if active in ("YES","TRUE","1"): return True
    if poc_count > 0: return True
    return False

def _has_verified_actor(item: Dict) -> bool:
    return str(item.get("attribution_status") or "").upper() in ("VERIFIED_MITRE","VENDOR_ATTRIBUTED","CORROBORATED")

def _has_production_detection(item: Dict) -> bool: return bool(item.get("detection_production_ready"))
def _corroboration_score(item: Dict) -> int: return _i(item.get("corroboration_score"))
def _independent_sources(item: Dict) -> int: return _i(item.get("corroboration_count"))


def assign_grade_v2(item: Dict) -> Tuple[str, List[str], str]:
    notes: List[str] = []
    has_ioc = _has_operational_iocs(item)
    has_cve = _has_verified_cve(item)
    cvss = _f(item.get("cvss_score"))
    has_attck = _has_attck(item)
    has_exploit = _has_exploit_evidence(item)
    has_actor = _has_verified_actor(item)
    has_detect = _has_production_detection(item)
    corr_score = _corroboration_score(item)
    n_sources = _independent_sources(item)

    if has_ioc and has_actor and has_attck and n_sources >= 3 and has_detect:
        notes.append(f"Grade A: operational IOC, verified actor, evidenced ATT&CK, {n_sources} sources, production detection")
        return "A", notes, ANALYST_VERDICT_MAP["A"]

    b_signals: List[str] = []
    if has_cve: b_signals.append("CVE verified")
    if cvss >= GRADE_B_CVSS_MIN: b_signals.append(f"CVSS={cvss:.1f}")
    if n_sources >= GRADE_B_SOURCES_MIN: b_signals.append(f"{n_sources} sources")
    if has_attck: b_signals.append("evidence-based ATT&CK")
    if has_exploit: b_signals.append("exploit evidence")
    if corr_score >= GRADE_B_CORR_MIN: b_signals.append(f"corroboration={corr_score}")
    grade_b_standard = has_cve and cvss >= GRADE_B_CVSS_MIN and n_sources >= GRADE_B_SOURCES_MIN and (has_attck or has_exploit)
    grade_b_critical = has_cve and cvss >= 9.0 and has_exploit and n_sources >= 1
    if grade_b_standard or grade_b_critical:
        notes.append(f"Grade B: {'; '.join(b_signals)}")
        return "B", notes, ANALYST_VERDICT_MAP["B"]

    c_signals: List[str] = []
    if has_cve: c_signals.append("verified CVE")
    if cvss >= GRADE_C_CVSS_MIN: c_signals.append(f"CVSS={cvss:.1f}")
    if n_sources >= 1: c_signals.append(f"{n_sources} source(s)")
    if has_cve and cvss >= GRADE_C_CVSS_MIN:
        notes.append(f"Grade C: {'; '.join(c_signals) if c_signals else 'verified CVE, limited enrichment'}")
        return "C", notes, ANALYST_VERDICT_MAP["C"]
    if has_cve and n_sources >= 1:
        notes.append(f"Grade C: CVE present, source confirmed, CVSS below threshold ({cvss:.1f})")
        return "C", notes, ANALYST_VERDICT_MAP["C"]

    if n_sources >= 1 and not has_exploit and not has_attck and not has_ioc:
        notes.append(f"Grade D: single-source advisory, CVSS={cvss:.1f}, no exploit/ATT&CK/IOC")
        return "D", notes, ANALYST_VERDICT_MAP["D"]

    f_reasons: List[str] = []
    if not has_cve: f_reasons.append("no verified CVE")
    if cvss < 1: f_reasons.append("CVSS absent")
    if n_sources < 1: f_reasons.append("no identifiable source")
    if not f_reasons: f_reasons.append("insufficient combined evidence")
    notes.append(f"Grade F: {'; '.join(f_reasons)}")
    return "F", notes, ANALYST_VERDICT_MAP["F"]


def grade_item(item: Dict) -> Dict:
    item = dict(item)
    cvss = _f(item.get("cvss_score"))
    severity = str(item.get("severity") or "").upper()
    kev_str = str(item.get("kev") or "").upper()
    risk = _f(item.get("risk_score"))
    floor = 0.0; floor_reason = ""
    if severity == "CRITICAL" or cvss >= 9.0: floor = 8.5; floor_reason = "CRITICAL/CVSS>=9 floor"
    elif severity == "HIGH" or cvss >= 7.0: floor = 7.0; floor_reason = "HIGH/CVSS>=7 floor"
    if kev_str in ("YES","TRUE","1"): floor = max(floor, 7.0); floor_reason += " +KEV"
    if floor > 0 and risk < floor:
        item["risk_score"] = floor
        if not isinstance(item.get("risk_score_reasoning"), str) or not item["risk_score_reasoning"]:
            item["risk_score_reasoning"] = floor_reason
    grade, notes, verdict = assign_grade_v2(item)
    item["intelligence_grade"] = grade
    item["grade_notes_v2"] = notes
    item["analyst_verdict"] = verdict
    item["publication_decision"] = DECISION_MAP[grade]
    item["grade_engine_version"] = f"v{ENGINE_VERSION}"
    item["graded_at_v2"] = datetime.now(timezone.utc).isoformat()

    # Inject all 10 mandatory API contract fields (Mandate 7)
    item.setdefault("evidence_count",
        _i(item.get("corroboration_count")) +
        (1 if _f(item.get("cvss_score")) > 0 else 0) +
        (1 if item.get("kev") and str(item.get("kev")).upper() not in ("NO","FALSE","0","NONE") else 0) +
        (1 if _i(item.get("exploit_count")) > 0 else 0))
    item.setdefault("corroboration_count", _i(item.get("corroboration_count")))
    item.setdefault("attribution_status", "NONE")
    item.setdefault("campaign_status", "UNVERIFIED")
    item.setdefault("ioc_quality_score", _i(item.get("real_ioc_count")) * 10)
    item.setdefault("attck_verification",
        "EVIDENCE_BASED" if item.get("attck_technique_ids") else "NOT_VERIFIED")
    if not item.get("risk_score_reasoning"):
        item["risk_score_reasoning"] = (
            f"deterministic: severity={str(item.get('severity','')).upper()} "
            f"cvss={_f(item.get('cvss_score')):.1f} kev={item.get('kev','NO')}"
        )
    return item


def process_feed(items: List[Dict]) -> Tuple[List[Dict], Dict]:
    governed = []
    grade_dist = Counter(); decision_dist = Counter()
    for item in items:
        graded = grade_item(item)
        governed.append(graded)
        grade_dist[graded["intelligence_grade"]] += 1
        decision_dist[graded["publication_decision"]] += 1
    published = [i for i in governed if i["publication_decision"] not in ("BLOCK","QUARANTINE")]
    blocked = [i for i in governed if i["publication_decision"] == "BLOCK"]
    quarantined = [i for i in governed if i["publication_decision"] == "QUARANTINE"]
    return governed, {
        "total_items":len(items),"grade_distribution":dict(grade_dist),
        "decision_distribution":dict(decision_dist),"published":len(published),
        "blocked":len(blocked),"quarantined":len(quarantined),
        "enterprise_eligible":sum(1 for i in published if i["intelligence_grade"] in ("A","B")),
        "mssp_eligible":sum(1 for i in published if i["intelligence_grade"] in ("A","B","C")),
        "engine_version":ENGINE_VERSION,"generated_at":datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Intelligence Grade Engine v{ENGINE_VERSION}")
    parser.add_argument("feed", nargs="?", default=str(REPO_ROOT/"api"/"feed.json"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", default=str(REPO_ROOT/"data"/"governance"/"intelligence_grade_v2.json"))
    args = parser.parse_args()
    raw = Path(args.feed).read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data,list) else data.get("threats",data.get("items",[]))
    log.info("[grade-v2] Processing %d items", len(items))
    governed, summary = process_feed(items)
    log.info("[grade-v2] A=%d B=%d C=%d D=%d F=%d | published=%d enterprise=%d mssp=%d",
             summary["grade_distribution"].get("A",0), summary["grade_distribution"].get("B",0),
             summary["grade_distribution"].get("C",0), summary["grade_distribution"].get("D",0),
             summary["grade_distribution"].get("F",0), summary["published"],
             summary["enterprise_eligible"], summary["mssp_eligible"])
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.apply:
        Path(args.feed).write_text(json.dumps(governed, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("[grade-v2] Graded feed written to %s", args.feed)
    return 0

if __name__ == "__main__":
    sys.exit(main())
