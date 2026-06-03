#!/usr/bin/env python3
"""
SENTINEL APEX — Source Corroboration Engine v1.0.0
1 source=weak(0-30), 2 sources=moderate(31-65), 3+ independent=strong(66-100)
Tier-1: CISA, NVD, Microsoft, Google, Cisco Talos, CrowdStrike, Mandiant, Palo Alto, etc.
"""
from __future__ import annotations
import argparse, json, logging, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [corroboration] %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

TIER1_SOURCES: Dict[str, str] = {
    "cisa":"CISA","ics-cert":"ICS-CERT/CISA","ics-cert/cisa":"ICS-CERT/CISA",
    "us-cert":"US-CERT","nist":"NIST/NVD","nvd":"NIST/NVD",
    "microsoft":"Microsoft","microsoft msrc":"Microsoft","msrc":"Microsoft",
    "google tag":"Google TAG","google threat":"Google TAG","mandiant":"Mandiant",
    "fireeye":"Mandiant/FireEye","crowdstrike":"CrowdStrike",
    "palo alto":"Palo Alto/Unit42","unit 42":"Palo Alto/Unit42","unit42":"Palo Alto/Unit42",
    "cisco talos":"Cisco Talos","talos":"Cisco Talos","recorded future":"Recorded Future",
    "proofpoint":"Proofpoint","nsa":"NSA","ncsc":"NCSC","bsi":"BSI","anssi":"ANSSI",
}
TIER2_SOURCES: Dict[str, str] = {
    "rapid7":"Rapid7","rapid7/metasploit":"Rapid7/Metasploit","metasploit":"Rapid7/Metasploit",
    "sans":"SANS","vulners":"Vulners","check point":"Check Point","checkpoint":"Check Point",
    "blog.checkpoint":"Check Point","sophos":"Sophos","kaspersky":"Kaspersky",
    "securelist":"Kaspersky SecureList","eset":"ESET","qualys":"Qualys","tenable":"Tenable",
    "github security":"GitHub Advisory","github advisory":"GitHub Advisory","ghsa":"GitHub Advisory",
    "nvd.nist.gov":"NVD","cve.mitre.org":"CVE/MITRE",
}
TIER3_SOURCES: Dict[str, str] = {
    "bleepingcomputer":"BleepingComputer","securityweek":"SecurityWeek",
    "the record":"The Record","krebs":"KrebsOnSecurity",
}
EXPLOIT_DB_PATTERNS = [r"exploit.?db",r"packetstorm",r"metasploit",r"rapid7",r"poc.*github",r"github.*poc"]


def _classify_source(source_text: str) -> Tuple[int, str]:
    s = source_text.lower().strip()
    for key, name in TIER1_SOURCES.items():
        if key in s: return 1, name
    for key, name in TIER2_SOURCES.items():
        if key in s: return 2, name
    for key, name in TIER3_SOURCES.items():
        if key in s: return 3, name
    return 0, source_text[:40]


def _extract_sources_from_item(item: Dict) -> Set[Tuple[int, str]]:
    sources: Set[Tuple[int, str]] = set()
    for field in ("source","feed_source","source_name"):
        v = str(item.get(field) or "").strip()
        if v:
            tier, name = _classify_source(v)
            if name: sources.add((tier, name))
    url = str(item.get("source_url") or "")
    if url:
        tier, name = _classify_source(url)
        if tier > 0: sources.add((tier, name))
    cve = item.get("cve_id")
    if cve and re.match(r"CVE-\d{4}-\d+", str(cve)):
        sources.add((2, "NVD/CVE-Database"))
    kev = item.get("kev")
    if kev and str(kev).upper() not in ("NO","FALSE","0","NONE"):
        sources.add((1, "CISA-KEV"))
    exploit_refs = item.get("exploit_refs") or []
    for ref in (exploit_refs if isinstance(exploit_refs, list) else []):
        ref_str = str(ref).lower()
        for pattern in EXPLOIT_DB_PATTERNS:
            if re.search(pattern, ref_str, re.I):
                sources.add((2, "ExploitDB/Metasploit")); break
    if int(item.get("exploit_count") or 0) > 0:
        sources.add((2, "PublicExploitConfirmed"))
    if item.get("metasploit_available") and str(item.get("metasploit_available")).upper() not in ("FALSE","NO","0","NONE"):
        sources.add((2, "MetasploitModule"))
    if item.get("epss_score") or item.get("epss"):
        sources.add((2, "EPSS/FIRST"))
    return sources


def compute_corroboration(item: Dict) -> Dict:
    sources = _extract_sources_from_item(item)
    tier1 = [(t,n) for t,n in sources if t==1]
    tier2 = [(t,n) for t,n in sources if t==2]
    tier3 = [(t,n) for t,n in sources if t==3]
    total_independent = len(sources)
    if total_independent >= 4:
        score = min(90 + len(tier1)*2, 100); strength = "STRONG"
    elif total_independent == 3:
        score = min(70 + len(tier1)*5, 89); strength = "STRONG"
    elif total_independent == 2:
        score = 40 + len(tier1)*10; strength = "MODERATE"
    elif total_independent == 1:
        score = 30 if tier1 else (20 if tier2 else 10); strength = "WEAK"
    else:
        score = 0; strength = "NONE"
    return {
        "corroboration_score": min(score,100), "corroboration_strength": strength,
        "independent_source_count": total_independent,
        "tier1_sources": [n for _,n in tier1], "tier2_sources": [n for _,n in tier2],
        "tier3_sources": [n for _,n in tier3], "all_sources": [n for _,n in sorted(sources)],
    }


def process_feed(items: List[Dict]) -> Tuple[List[Dict], Dict]:
    governed, scores = [], []
    strength_counts = {"STRONG":0,"MODERATE":0,"WEAK":0,"NONE":0}
    for item in items:
        item = dict(item)
        corr = compute_corroboration(item)
        item["corroboration_score"] = corr["corroboration_score"]
        item["corroboration_strength"] = corr["corroboration_strength"]
        item["corroboration_count"] = corr["independent_source_count"]
        item["corroboration_sources"] = corr["all_sources"]
        governed.append(item)
        scores.append({"id":item.get("id",""), **corr})
        strength_counts[corr["corroboration_strength"]] = strength_counts.get(corr["corroboration_strength"],0)+1
    avg_score = int(sum(s["corroboration_score"] for s in scores)/max(len(scores),1))
    multi_source = sum(1 for s in scores if s["independent_source_count"] >= 2)
    return governed, {
        "total_items":len(items),"avg_corroboration_score":avg_score,
        "multi_source_items":multi_source,"strength_distribution":strength_counts,
        "per_item":scores,"engine_version":ENGINE_VERSION,
        "generated_at":datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Source Corroboration Engine v{ENGINE_VERSION}")
    parser.add_argument("feed", nargs="?", default=str(REPO_ROOT/"api"/"feed.json"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", default=str(REPO_ROOT/"data"/"governance"/"corroboration_report.json"))
    args = parser.parse_args()
    raw = Path(args.feed).read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data,list) else data.get("threats",data.get("items",[]))
    log.info("[corroboration] Processing %d items", len(items))
    governed, summary = process_feed(items)
    log.info("[corroboration] avg_score=%d multi_source=%d strong=%d",
             summary["avg_corroboration_score"],summary["multi_source_items"],
             summary["strength_distribution"]["STRONG"])
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.apply:
        Path(args.feed).write_text(json.dumps(governed, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("[corroboration] Governed feed written to %s", args.feed)
    return 0

if __name__ == "__main__":
    sys.exit(main())
