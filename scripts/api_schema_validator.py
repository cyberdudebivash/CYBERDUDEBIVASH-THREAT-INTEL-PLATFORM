#!/usr/bin/env python3
"""
scripts/api_schema_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX — API Schema Validator (Phase 10)
"""
from __future__ import annotations
import json, logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.api_schema")
REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_ITEM_FIELDS = ["id","title","severity","risk_score","published_at","source"]
VALID_SEVERITIES = {"LOW","MEDIUM","HIGH","CRITICAL"}

FEED_FILES = {
    "api/feed.json": {"type": "array_or_items_dict", "required_fields": REQUIRED_ITEM_FIELDS},
    "api/latest.json": {"type": "dict_with_data", "required_fields": REQUIRED_ITEM_FIELDS},
    "feed.json": {"type": "array_or_items_dict", "required_fields": ["id","title","severity","published_at","source"]},
}

def _load_items(raw):
    if isinstance(raw, list): return raw
    if isinstance(raw, dict):
        for k in ("items","advisories","data","feed"):
            if k in raw and isinstance(raw[k],list):
                return raw[k]
    return []

def _validate_item(item, required_fields, idx):
    issues = []
    for f in required_fields:
        if not item.get(f):
            issues.append({"item_index":idx,"id":item.get("id","?"),"missing_field":f})
    sev = (item.get("severity") or "").upper()
    if sev and sev not in VALID_SEVERITIES:
        issues.append({"item_index":idx,"id":item.get("id","?"),"invalid_severity":sev})
    return issues

def run_api_validation():
    now = datetime.now(timezone.utc)
    report = {
        "validator": "APISchemaValidator",
        "run_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {},
        "cross_file_consistency": {},
        "overall_status": "PASS"
    }

    all_items_by_file = {}

    for rel_path, spec in FEED_FILES.items():
        full_path = REPO_ROOT / rel_path
        file_report = {"path": rel_path, "exists": full_path.exists(), "item_count": 0, "issues": [], "status": "PASS"}
        if not full_path.exists():
            file_report["status"] = "FILE_NOT_FOUND"
            report["files"][rel_path] = file_report
            report["overall_status"] = "WARN"
            continue
        try:
            raw = json.loads(full_path.read_text(encoding="utf-8"))
            file_report["parse_ok"] = True
        except Exception as e:
            file_report["parse_ok"] = False
            file_report["parse_error"] = str(e)
            file_report["status"] = "PARSE_FAIL"
            report["files"][rel_path] = file_report
            report["overall_status"] = "FAIL"
            continue

        items = _load_items(raw)
        file_report["item_count"] = len(items)
        all_items_by_file[rel_path] = items

        if len(items) == 0:
            file_report["issues"].append({"type":"EMPTY_FEED","description":"No items found"})
            file_report["status"] = "WARN"

        schema_issues = []
        for idx, item in enumerate(items):
            schema_issues.extend(_validate_item(item, spec["required_fields"], idx))
        file_report["schema_issues_count"] = len(schema_issues)
        file_report["schema_issues_sample"] = schema_issues[:5]

        # Field coverage stats
        field_coverage = {}
        for f in spec["required_fields"]:
            pct = round(100*sum(1 for i in items if i.get(f))/len(items),1) if items else 0
            field_coverage[f] = pct
        file_report["field_coverage_pct"] = field_coverage

        # Severity distribution
        sev_dist = {}
        for i in items:
            s = (i.get("severity") or "UNKNOWN").upper()
            sev_dist[s] = sev_dist.get(s,0)+1
        file_report["severity_distribution"] = sev_dist

        if schema_issues:
            file_report["status"] = "WARN"
            report["overall_status"] = "WARN"

        report["files"][rel_path] = file_report

    # Cross-file consistency check
    api_ids = set(i.get("id","") for i in all_items_by_file.get("api/feed.json",[]))
    root_ids = set(i.get("id","") for i in all_items_by_file.get("feed.json",[]))
    overlap = len(api_ids & root_ids)
    report["cross_file_consistency"] = {
        "api_feed_item_count": len(api_ids),
        "root_feed_item_count": len(root_ids),
        "id_overlap": overlap,
        "overlap_pct": round(100*overlap/len(api_ids),1) if api_ids else 0
    }

    # STIX schema check
    stix_path = REPO_ROOT / "api" / "exports" / "feed.stix.json"
    if stix_path.exists():
        try:
            stix = json.loads(stix_path.read_text(encoding="utf-8"))
            stix_valid = stix.get("type")=="bundle" and bool(stix.get("id")) and bool(stix.get("objects"))
            report["stix_schema"] = {"valid": stix_valid, "object_count": len(stix.get("objects",[])), "spec_version": stix.get("spec_version")}
        except Exception as e:
            report["stix_schema"] = {"valid": False, "error": str(e)}
    else:
        report["stix_schema"] = {"valid": False, "error": "file not found"}

    rp = REPO_ROOT / "reports" / "api_validation_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_api_validation()
    print(json.dumps(r, indent=2))
