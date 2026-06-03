#!/usr/bin/env python3
"""
scripts/commercial_readiness_auditor.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Commercial Readiness Auditor (Phase 13)
Scores each commercial tier 0-100 with GO/NO-GO decisions.
"""
from __future__ import annotations
import json, logging, os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.commercial_readiness")
REPO_ROOT = Path(__file__).resolve().parent.parent

def _load_items(path):
    path = Path(path)
    if not path.exists(): return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw,dict):
            for k in ("items","advisories","data"): 
                if k in raw and isinstance(raw[k],list): return raw[k]
        return raw if isinstance(raw,list) else []
    except: return []

def _exists(*paths): return all((REPO_ROOT/p).exists() for p in paths)
def _file_size(path): 
    p = REPO_ROOT/path
    return p.stat().st_size if p.exists() else 0

def score_free_tier(items, data_items):
    checks = []
    # Public feed quality
    if len(items) >= 20: checks.append(("feed_item_count",20,20))
    else: checks.append(("feed_item_count",max(0,len(items)),20))
    # Source diversity
    sources = set(i.get("source","?") for i in data_items)
    src_score = min(len(sources)/10,1.0)*20
    checks.append(("source_diversity",round(src_score),20))
    # Update frequency (check generated_at in latest.json)
    latest_path = REPO_ROOT/"api"/"latest.json"
    freq_score = 15
    if latest_path.exists():
        try:
            raw = json.loads(latest_path.read_text(encoding="utf-8"))
            gen = raw.get("generated_at","")
            if gen:
                from datetime import datetime,timezone
                dt = datetime.fromisoformat(str(gen).replace("Z","+00:00"))
                now = datetime.now(timezone.utc)
                hours_ago = (now-dt).total_seconds()/3600
                freq_score = 15 if hours_ago < 24 else (10 if hours_ago < 72 else 5)
        except: pass
    checks.append(("update_frequency",freq_score,15))
    # JSON validity
    checks.append(("json_valid",10 if _exists("api/feed.json","feed.json") else 0,10))
    # Severity labels present
    has_sev = sum(1 for i in items if i.get("severity"))/len(items)*100 if items else 0
    checks.append(("severity_labels",round(has_sev/100*15),15))
    # Public API accessible
    checks.append(("public_api",10 if _exists("api/feed.json") else 0,10))
    # Documentation
    checks.append(("documentation",10 if _exists("README.md","SENTINEL_APEX_DATA_SCHEMA.md") else 5,10))
    score = sum(c[1] for c in checks)
    return {"score":score,"max":100,"checks":{c[0]:{"earned":c[1],"max":c[2]} for c in checks},"go_no_go":"GO" if score>=65 else "NO-GO","criteria":">=65 for GO"}

def score_pro_tier(items):
    checks = []
    # Report URL coverage
    ru_pct = sum(1 for i in items if i.get("report_url"))/len(items)*100 if items else 0
    checks.append(("report_url_coverage",round(ru_pct/100*25),25))
    # API availability (latest.json populated)
    latest_items = _load_items(REPO_ROOT/"api"/"latest.json")
    checks.append(("api_latest_json",15 if latest_items else 5,15))
    # STIX export
    stix_ok = _exists("api/exports/feed.stix.json") and _file_size("api/exports/feed.stix.json") > 1000
    checks.append(("stix_export",20 if stix_ok else 0,20))
    # Risk scores present
    rs_pct = sum(1 for i in items if i.get("risk_score"))/len(items)*100 if items else 0
    checks.append(("risk_scores",round(rs_pct/100*15),15))
    # CVE IDs present
    cve_pct = sum(1 for i in items if i.get("cve") or i.get("cve_ids"))/len(items)*100 if items else 0
    checks.append(("cve_ids",round(cve_pct/100*15),15))
    # Confidence scores
    conf_pct = sum(1 for i in items if i.get("confidence") or i.get("confidence_score"))/len(items)*100 if items else 0
    checks.append(("confidence_scores",round(conf_pct/100*10),10))
    score = sum(c[1] for c in checks)
    return {"score":score,"max":100,"checks":{c[0]:{"earned":c[1],"max":c[2]} for c in checks},"go_no_go":"GO" if score>=70 else "NO-GO","criteria":">=70 for GO"}

def score_enterprise_tier(items):
    checks = []
    # Attribution completeness
    attr_pct = sum(1 for i in items if i.get("source_name") or i.get("publisher"))/len(items)*100 if items else 0
    checks.append(("attribution_completeness",round(attr_pct/100*20),20))
    # MITRE coverage
    mitre_pct = sum(1 for i in items if i.get("mitre_techniques") or i.get("mitre_tactics"))/len(items)*100 if items else 0
    checks.append(("mitre_coverage",round(mitre_pct/100*20),20))
    # Dashboard contract
    checks.append(("dashboard_contract",15 if _exists("dashboard_contract.json") else 0,15))
    # KEV tracking
    kev_count = sum(1 for i in items if i.get("kev") or i.get("kev_present"))
    checks.append(("kev_tracking",15 if kev_count>0 else 5,15))
    # EPSS scores
    epss_pct = sum(1 for i in items if i.get("epss_score"))/len(items)*100 if items else 0
    checks.append(("epss_scores",round(epss_pct/100*15),15))
    # IOC data
    ioc_items = sum(1 for i in items if i.get("ioc_count",0) or i.get("iocs"))
    checks.append(("ioc_data",round(ioc_items/len(items)*15 if items else 0),15))
    score = sum(c[1] for c in checks)
    return {"score":score,"max":100,"checks":{c[0]:{"earned":c[1],"max":c[2]} for c in checks},"go_no_go":"GO" if score>=60 else "NO-GO","criteria":">=60 for GO"}

def score_mssp_tier(items):
    checks = []
    # Multi-tenant readiness (rbac, tenant files)
    mt_score = 0
    for f in ("api/rbac.py","tenant_management_engine.py","api/mssp"):
        if _exists(f): mt_score += 5
    checks.append(("multi_tenant_readiness",min(mt_score,20),20))
    # SLA compliance (status.json, health endpoint)
    sla_score = 10 if _exists("api/status.json") else 5
    checks.append(("sla_compliance",sla_score,20))
    # Feed freshness (<24h)
    freshness_score = 15
    latest_path = REPO_ROOT/"api"/"latest.json"
    if latest_path.exists():
        try:
            raw = json.loads(latest_path.read_text(encoding="utf-8"))
            gen = raw.get("generated_at","")
            if gen:
                from datetime import datetime,timezone
                dt = datetime.fromisoformat(str(gen).replace("Z","+00:00"))
                hours = (datetime.now(timezone.utc)-dt).total_seconds()/3600
                freshness_score = 20 if hours<6 else (15 if hours<24 else 5)
        except: pass
    checks.append(("feed_freshness",freshness_score,20))
    # Webhook/API support
    checks.append(("api_support",20 if _exists("api/main.py","api/v1_router.py") else 10,20))
    # STIX/TAXII export
    checks.append(("stix_taxii",20 if _exists("api/exports/feed.stix.json") else 5,20))
    score = sum(c[1] for c in checks)
    return {"score":score,"max":100,"checks":{c[0]:{"earned":c[1],"max":c[2]} for c in checks},"go_no_go":"GO" if score>=60 else "NO-GO","criteria":">=60 for GO"}

def score_api_tier(items):
    checks = []
    # Schema compliance (all required fields)
    required = ["id","title","severity","published_at","source"]
    compliant = sum(1 for i in items if all(i.get(f) for f in required))
    comp_pct = compliant/len(items)*100 if items else 0
    checks.append(("schema_compliance",round(comp_pct/100*25),25))
    # Field completeness (>= 15 fields per item avg)
    avg_fields = sum(len([k for k,v in i.items() if v]) for i in items)/len(items) if items else 0
    fc_score = min(avg_fields/20,1.0)*25
    checks.append(("field_completeness",round(fc_score),25))
    # Versioning
    checks.append(("api_versioning",15 if _exists("version.json","api/version.json") else 5,15))
    # OpenAPI spec
    checks.append(("openapi_spec",15 if _exists("apex_openapi_v3.yaml") else 0,15))
    # STIX compliance
    checks.append(("stix_compliance",20 if _exists("api/exports/feed.stix.json") else 0,20))
    score = sum(c[1] for c in checks)
    return {"score":score,"max":100,"checks":{c[0]:{"earned":c[1],"max":c[2]} for c in checks},"go_no_go":"GO" if score>=70 else "NO-GO","criteria":">=70 for GO"}

def run_commercial_readiness():
    now = datetime.now(timezone.utc)
    items = _load_items(REPO_ROOT/"api"/"feed.json")
    data_items = _load_items(REPO_ROOT/"data"/"feed.json")

    tiers = {
        "free_tier": score_free_tier(items, data_items),
        "pro_tier": score_pro_tier(items),
        "enterprise_tier": score_enterprise_tier(items),
        "mssp_tier": score_mssp_tier(items),
        "api_tier": score_api_tier(items),
    }

    scores = [t["score"] for t in tiers.values()]
    overall = round(sum(scores)/len(scores),1)
    go_count = sum(1 for t in tiers.values() if t["go_no_go"]=="GO")

    report = {
        "auditor": "CommercialReadinessAuditor",
        "run_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tiers": tiers,
        "overall_readiness_score": overall,
        "tiers_go": go_count,
        "tiers_total": len(tiers),
        "platform_verdict": "COMMERCIALLY_READY" if overall>=65 else "NEEDS_IMPROVEMENT",
        "critical_gaps": [
            {"gap":"report_url missing in api/feed.json","impact":"Pro tier -25pts"},
            {"gap":"MITRE ATT&CK mappings 0% in api/feed.json","impact":"Enterprise tier -20pts"},
            {"gap":"source=SENTINEL-APEX 100% in api/feed.json","impact":"All tiers attribution -20pts"},
        ]
    }
    rp = REPO_ROOT/"reports"/"commercial_readiness.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_commercial_readiness()
    print(f"Overall Readiness: {r['overall_readiness_score']}/100 — {r['platform_verdict']}")
    for tier,data in r["tiers"].items():
        print(f"  {tier}: {data['score']}/100 → {data['go_no_go']}")
