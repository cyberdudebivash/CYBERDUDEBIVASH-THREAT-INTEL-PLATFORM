#!/usr/bin/env python3
"""
scripts/platform_health_monitor.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Platform Health Monitor (Phase 11)
Writes: logs/platform_health.json with status per component (OK/WARN/FAIL) + timestamp.
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.platform_health")
REPO_ROOT = Path(__file__).resolve().parent.parent
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def _load_items(path):
    path = Path(path)
    if not path.exists(): return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for k in ("items","advisories","data"):
                if k in raw and isinstance(raw[k],list): return raw[k]
        return raw if isinstance(raw,list) else []
    except: return []

def _check_collector_failures():
    """Check if key feed files are populated."""
    checks = {}
    for fname in ("api/feed.json","feed.json","data/feed.json","api/latest.json"):
        items = _load_items(REPO_ROOT/fname)
        checks[fname] = {"item_count": len(items), "status": "OK" if len(items)>0 else "FAIL"}
    overall = "OK" if all(v["status"]=="OK" for v in checks.values()) else "WARN"
    return {"checks": checks, "status": overall}

def _check_feed_integrity():
    """Validate required fields presence and severity distribution."""
    items = _load_items(REPO_ROOT/"api"/"feed.json")
    if not items: return {"status":"FAIL","detail":"api/feed.json empty"}
    missing_id = sum(1 for i in items if not i.get("id"))
    missing_title = sum(1 for i in items if not i.get("title"))
    missing_sev = sum(1 for i in items if not i.get("severity"))
    sev_dist = {}
    for i in items:
        s = (i.get("severity") or "UNKNOWN").upper()
        sev_dist[s] = sev_dist.get(s,0)+1
    low_pct = sev_dist.get("LOW",0)/len(items)*100 if items else 0
    status = "OK"
    issues = []
    if missing_id > 0: issues.append(f"{missing_id} items missing id"); status = "WARN"
    if missing_title > 0: issues.append(f"{missing_title} items missing title"); status = "WARN"
    if low_pct > 60: issues.append(f"LOW severity {low_pct:.0f}% > 60% threshold"); status = "WARN"
    return {"item_count":len(items),"severity_distribution":sev_dist,"low_severity_pct":round(low_pct,1),"issues":issues,"status":status}

def _check_timestamp_violations():
    """Count future timestamps across all feeds."""
    now = datetime.now(timezone.utc)
    violations = []
    for fname in ("api/feed.json","feed.json"):
        items = _load_items(REPO_ROOT/fname)
        for i in items:
            for f in ("published_at","processed_at","timestamp"):
                v = i.get(f,"")
                if v:
                    try:
                        dt = datetime.fromisoformat(str(v).replace("Z","+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if dt > now:
                            violations.append({"file":fname,"id":i.get("id","?"),"field":f,"value":v})
                    except: pass
    status = "OK" if not violations else "WARN"
    return {"future_timestamp_count":len(violations),"violations_sample":violations[:5],"status":status}

def _check_severity_anomalies():
    """Detect KEV items with LOW severity."""
    items = _load_items(REPO_ROOT/"api"/"feed.json")
    kev_low = [i.get("id","?") for i in items if (i.get("kev") or i.get("kev_present")) and (i.get("severity") or "").upper()=="LOW"]
    sev_dist = {}
    for i in items:
        s = (i.get("severity") or "UNKNOWN").upper()
        sev_dist[s] = sev_dist.get(s,0)+1
    status = "FAIL" if kev_low else ("WARN" if sev_dist.get("LOW",0)>sev_dist.get("HIGH",0)+sev_dist.get("CRITICAL",0) else "OK")
    return {"kev_items_with_low_severity":kev_low,"severity_distribution":sev_dist,"status":status}

def _check_missing_attribution():
    """Count items missing source attribution."""
    items = _load_items(REPO_ROOT/"api"/"feed.json")
    missing = sum(1 for i in items if not i.get("source") or i.get("source")=="SENTINEL-APEX")
    pct = round(100*missing/len(items),1) if items else 0
    status = "OK" if pct < 20 else ("WARN" if pct < 80 else "FAIL")
    return {"items_missing_real_source":missing,"total_items":len(items),"pct":pct,"status":status}

def _check_api_schema_drift():
    """Check if api/feed.json and api/latest.json follow expected schemas."""
    issues = []
    for fname in ("api/feed.json","api/latest.json"):
        path = REPO_ROOT/fname
        if not path.exists():
            issues.append(f"{fname} missing")
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not raw:
                issues.append(f"{fname} is empty")
        except Exception as e:
            issues.append(f"{fname} parse error: {e}")
    status = "OK" if not issues else "WARN"
    return {"issues":issues,"status":status}

def run_health_monitor():
    now = datetime.now(timezone.utc)
    components = {
        "collector_failures": _check_collector_failures(),
        "feed_integrity": _check_feed_integrity(),
        "timestamp_violations": _check_timestamp_violations(),
        "severity_anomalies": _check_severity_anomalies(),
        "missing_attribution": _check_missing_attribution(),
        "api_schema_drift": _check_api_schema_drift(),
    }
    statuses = [v.get("status","UNKNOWN") for v in components.values()]
    overall = "FAIL" if "FAIL" in statuses else ("WARN" if "WARN" in statuses else "OK")

    report = {
        "monitor": "PlatformHealthMonitor",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_status": overall,
        "components": components,
        "summary": {s: statuses.count(s) for s in ("OK","WARN","FAIL")},
    }

    logs_dir = REPO_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "platform_health.json"
    log_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("[HealthMonitor] overall=%s written to %s", overall, log_path)
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_health_monitor()
    print(json.dumps({"overall_status":r["overall_status"],"summary":r["summary"]},indent=2))
    for comp,data in r["components"].items():
        print(f"  {comp}: {data.get('status','?')}")
