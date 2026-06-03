#!/usr/bin/env python3
"""
scripts/cti_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Enterprise CTI Validation (Phase 8)
Checks MITRE ATT&CK mappings, STIX export quality, IOC quality.
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.cti_validator")
REPO_ROOT = Path(__file__).resolve().parent.parent

VALID_MITRE_TACTICS = {
    "reconnaissance","resource-development","initial-access","execution",
    "persistence","privilege-escalation","defense-evasion","credential-access",
    "discovery","lateral-movement","collection","command-and-control","exfiltration","impact"
}

IOC_TYPES = {"ip","domain","url","hash","md5","sha1","sha256","email","filename","registry"}

def _load_items(path):
    path = Path(path)
    if not path.exists(): return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        for key in ("items","advisories","data","objects"):
            if key in raw and isinstance(raw[key],list):
                return raw[key]
    return raw if isinstance(raw, list) else []

def run_cti_validation():
    now = datetime.now(timezone.utc)

    # Check api/feed.json MITRE coverage
    items = _load_items(REPO_ROOT/"api"/"feed.json")
    mitre_mapped = sum(1 for i in items if i.get("mitre_techniques") or i.get("attack_techniques") or i.get("mitre_tactics"))
    tactic_coverage = set()
    for i in items:
        for f in ("mitre_tactics","kill_chain_phases","ttps"):
            v = i.get(f)
            if isinstance(v, list):
                for t in v:
                    t_str = str(t).lower() if isinstance(t,str) else str(t.get("phase_name","")).lower() if isinstance(t,dict) else ""
                    if t_str in VALID_MITRE_TACTICS:
                        tactic_coverage.add(t_str)

    # Check IOC quality
    ioc_items = [i for i in items if i.get("iocs")]
    ioc_total = sum(len(i.get("iocs",[])) for i in items)
    valid_ioc_count = 0
    for i in items:
        iocs = i.get("iocs",[])
        if isinstance(iocs, list):
            for ioc in iocs:
                if isinstance(ioc, dict) and ioc.get("type","").lower() in IOC_TYPES:
                    valid_ioc_count += 1
                elif isinstance(ioc, str) and ioc:
                    valid_ioc_count += 1

    # Check STIX export
    stix_path = REPO_ROOT / "api" / "exports" / "feed.stix.json"
    stix_report = {"exists": False}
    if stix_path.exists():
        stix_data = json.loads(stix_path.read_text(encoding="utf-8"))
        stix_objects = stix_data.get("objects",[])
        stix_types = {}
        for obj in stix_objects:
            t = obj.get("type","?")
            stix_types[t] = stix_types.get(t,0)+1
        stix_report = {
            "exists": True,
            "spec_version": stix_data.get("spec_version","?"),
            "object_count": len(stix_objects),
            "type_distribution": stix_types,
            "has_indicators": stix_types.get("indicator",0) > 0,
            "has_vulnerabilities": stix_types.get("vulnerability",0) > 0,
            "schema_valid": bool(stix_data.get("type")=="bundle" and stix_data.get("id"))
        }

    # Check data/feed.json for MITRE coverage
    data_items = _load_items(REPO_ROOT/"data"/"feed.json")
    data_mitre = sum(1 for i in data_items if i.get("mitre_techniques") or i.get("attack_techniques"))
    data_kev = sum(1 for i in data_items if i.get("kev") or i.get("kev_present"))

    report = {
        "validator": "CTIValidator",
        "run_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mitre_attck": {
            "api_feed_mapped": mitre_mapped,
            "api_feed_total": len(items),
            "api_feed_coverage_pct": round(100*mitre_mapped/len(items),1) if items else 0,
            "tactics_found": sorted(tactic_coverage),
            "tactic_coverage_pct": round(100*len(tactic_coverage)/14,1),
            "data_feed_mapped": data_mitre,
            "data_feed_total": len(data_items),
        },
        "ioc_quality": {
            "items_with_iocs": len(ioc_items),
            "ioc_total": ioc_total,
            "valid_typed_iocs": valid_ioc_count,
            "ioc_coverage_pct": round(100*len(ioc_items)/len(items),1) if items else 0,
        },
        "stix_export": stix_report,
        "kev_coverage": {"data_feed_kev_items": data_kev, "data_feed_kev_pct": round(100*data_kev/len(data_items),1) if data_items else 0},
        "issues": [],
        "status": "PASS"
    }

    if mitre_mapped == 0:
        report["issues"].append({"severity":"HIGH","issue":"Zero MITRE ATT&CK mappings in api/feed.json"})
    if not stix_report.get("schema_valid"):
        report["issues"].append({"severity":"MEDIUM","issue":"STIX export schema invalid or missing"})
    if ioc_total == 0:
        report["issues"].append({"severity":"MEDIUM","issue":"Zero IOCs in api/feed.json"})
    if report["issues"]:
        report["status"] = "WARN"

    rp = REPO_ROOT / "reports" / "cti_validation_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_cti_validation()
    print(json.dumps(r, indent=2))
