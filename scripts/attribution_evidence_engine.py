#!/usr/bin/env python3
"""
SENTINEL APEX — Attribution Evidence Engine v1.0.0
Requires: min 2 evidence sources OR verified MITRE group OR Tier-1 vendor attribution.
Otherwise: actor_display_name=UNATTRIBUTED, actor_confidence=LOW, actor_status=EVIDENCE_INSUFFICIENT
Forbidden without evidence: Turla, APT28, APT29, Lazarus, FIN7, LockBit
"""
from __future__ import annotations
import argparse, json, logging, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [attribution-engine] %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

TIER1_ATTRIBUTION_SOURCES = frozenset([
    "mandiant","fireeye","crowdstrike","microsoft","microsoft msrc","recorded future",
    "secureworks","palo alto","unit 42","unit42","cisco talos","talos",
    "google tag","google threat analysis group","nsa","cisa","fbi","ncsc","bsi","anssi",
    "kaspersky","kaspersky securelist","eset",
])
VERIFIED_MITRE_GROUPS = frozenset([
    "G0007","G0016","G0019","G0022","G0032","G0034","G0035","G0037","G0038","G0040",
    "G0041","G0049","G0059","G0065","G0069","G0072","G0074","G0078","G0080","G0082",
    "G0085","G0086","G0087","G0091","G0096","G0099","G0100","G0101","G0102","G0103",
    "G0109","G0112","G0114","G0116","G0117","G0118","G0119","G0120","G0122","G0123",
    "G0124","G0125","G0126","G0127","G0128","G0129","G0130","G0131","G0133","G0134",
    "G0135","G0136","G0138","G0139","G0140","G0141","G0143","G0145","G0146",
])
HIGH_CONFIDENCE_REQUIRED = frozenset([
    "turla","apt28","apt29","lazarus","fin7","lockbit","cozy bear","fancy bear",
    "sandworm","equation group","darkside","revil","conti","hive","alphv","blackcat",
    "cl0p","clop","lapsus",
])
BANNED_SYNTHETIC = frozenset([
    "CDB-UNATTR-CVE","CDB-UNATTR-APT","CDB-UNATTR-RAN","CDB-UNATTR-PHI",
    "CDB-UNATTR-MAL","CDB-UNATTR-INT","UNC-CDB",
])
BANNED_SYNTHETIC_NAMES = frozenset([
    "web application threat cluster","vulnerability exploitation cluster",
    "unknown threat actor","untracked threat cluster","unattributed apt cluster",
    "unattributed threat actor","unknown state-sponsored actor",
])


def score_attribution(item: Dict) -> Dict:
    actor_text = " ".join(filter(None,[
        str(item.get("actor") or ""),str(item.get("actor_name") or ""),
        str(item.get("actor_display_name") or ""),
    ])).lower()
    source_text = " ".join(filter(None,[
        str(item.get("source") or ""),str(item.get("feed_source") or ""),
        str(item.get("source_name") or ""),
    ])).lower()
    actor_tag = str(item.get("actor_tag") or item.get("actor") or "")
    mitre_id = str(item.get("actor_mitre_id") or "")
    signals = item.get("attribution_signals") or []

    if actor_tag in BANNED_SYNTHETIC:
        return {"actor_status":"BANNED_SYNTHETIC","actor_confidence":"NONE","evidence_count":0,
                "verdict":"REJECT — synthetic actor tag","action":"null_actor"}
    for banned_name in BANNED_SYNTHETIC_NAMES:
        if banned_name in actor_text:
            return {"actor_status":"BANNED_SYNTHETIC","actor_confidence":"NONE","evidence_count":0,
                    "verdict":f"REJECT — banned synthetic name: {banned_name}","action":"null_actor"}
    if not actor_text.strip() or actor_text.strip() in ("none","null",""):
        return {"actor_status":"UNATTRIBUTED","actor_confidence":"NONE","evidence_count":0,
                "verdict":"No actor claimed — correct","action":"no_change"}

    evidence_count = len([s for s in signals if s]) if signals else 0
    tier1_source = any(t in source_text for t in TIER1_ATTRIBUTION_SOURCES)
    verified_mitre = bool(mitre_id and mitre_id.upper() in VERIFIED_MITRE_GROUPS)
    if item.get("attribution_method") and item.get("attribution_method") not in ("category_classification",""):
        evidence_count += 1
    if item.get("source_reliability") in ("A","B","high","very_reliable"):
        evidence_count += 1

    requires_strong = any(name in actor_text for name in HIGH_CONFIDENCE_REQUIRED)
    if verified_mitre and evidence_count >= 1:
        status,confidence,verdict,action = "VERIFIED_MITRE","HIGH",f"Accepted — verified MITRE {mitre_id}","no_change"
    elif tier1_source and evidence_count >= 1 and not requires_strong:
        status,confidence,verdict,action = "VENDOR_ATTRIBUTED","MEDIUM",f"Accepted — Tier-1 vendor + {evidence_count} signal(s)","no_change"
    elif evidence_count >= 2:
        status,confidence,verdict,action = "CORROBORATED","MEDIUM",f"Accepted — {evidence_count} evidence sources","no_change"
    elif requires_strong and evidence_count < 2 and not verified_mitre:
        status,confidence,verdict,action = "EVIDENCE_INSUFFICIENT","LOW",f"REJECTED — {actor_text[:40]!r} requires 2+ sources or MITRE; found {evidence_count}","null_actor"
    elif evidence_count == 1 and tier1_source:
        status,confidence,verdict,action = "LOW_CONFIDENCE_VENDOR","LOW","Downgraded — single tier-1 source insufficient","downgrade"
    else:
        status,confidence,verdict,action = "EVIDENCE_INSUFFICIENT","LOW",f"REJECTED — {evidence_count} source(s), minimum 2 required","null_actor"

    return {"actor_claimed":actor_text[:80],"actor_status":status,"actor_confidence":confidence,
            "evidence_count":evidence_count,"tier1_source":tier1_source,"verified_mitre":verified_mitre,
            "verdict":verdict,"action":action}


def apply_attribution(item: Dict, assessment: Dict) -> Dict:
    action = assessment.get("action","no_change")
    if action == "null_actor":
        for f in ("actor","actor_tag","actor_name","actor_display_name","actor_country",
                  "actor_motivation","actor_mitre_id","actor_threat_level"):
            item[f] = None
        item["actor_aliases"] = []; item["actor_sectors"] = []
        item["actor_malware"] = []; item["actor_ttps"] = []
        item["verified_actor"] = False; item["attribution_status"] = "NONE"
        item["actor_confidence_label"] = "NONE"
    elif action == "downgrade":
        item["attribution_status"] = "UNVERIFIED"; item["actor_confidence_label"] = "LOW"
        item["verified_actor"] = False
    else:
        item["attribution_status"] = assessment["actor_status"]
        item["actor_confidence_label"] = assessment["actor_confidence"]
        item["verified_actor"] = assessment["actor_confidence"] in ("HIGH","MEDIUM")
    item["attribution_assessment"] = {
        "status":assessment["actor_status"],"confidence":assessment["actor_confidence"],
        "evidence_count":assessment["evidence_count"],"verdict":assessment["verdict"],
        "engine_version":ENGINE_VERSION,
    }
    return item


def process_feed(items: List[Dict]) -> Tuple[List[Dict], Dict]:
    governed, assessments = [], []
    counts = {"VERIFIED_MITRE":0,"VENDOR_ATTRIBUTED":0,"CORROBORATED":0,
              "EVIDENCE_INSUFFICIENT":0,"BANNED_SYNTHETIC":0,"UNATTRIBUTED":0,"LOW_CONFIDENCE_VENDOR":0}
    for item in items:
        item = dict(item)
        assessment = score_attribution(item)
        item = apply_attribution(item, assessment)
        governed.append(item)
        assessments.append({"id":item.get("id",""), **assessment})
        status = assessment["actor_status"]
        counts[status] = counts.get(status,0) + 1
    verified_total = counts["VERIFIED_MITRE"] + counts["VENDOR_ATTRIBUTED"] + counts["CORROBORATED"]
    summary = {
        "total_items":len(items),"verified_attribution":verified_total,
        "insufficient_evidence":counts["EVIDENCE_INSUFFICIENT"],
        "banned_synthetic":counts["BANNED_SYNTHETIC"],
        "unattributed":counts["UNATTRIBUTED"],"status_breakdown":counts,
        "engine_version":ENGINE_VERSION,"generated_at":datetime.now(timezone.utc).isoformat(),
    }
    return governed, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Attribution Evidence Engine v{ENGINE_VERSION}")
    parser.add_argument("feed", nargs="?", default=str(REPO_ROOT/"api"/"feed.json"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", default=str(REPO_ROOT/"data"/"governance"/"attribution_evidence.json"))
    args = parser.parse_args()
    raw = Path(args.feed).read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data,list) else data.get("threats",data.get("items",[]))
    log.info("[attribution] Processing %d items", len(items))
    governed, summary = process_feed(items)
    log.info("[attribution] verified=%d insufficient=%d banned=%d",
             summary["verified_attribution"],summary["insufficient_evidence"],summary["banned_synthetic"])
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.apply:
        Path(args.feed).write_text(json.dumps(governed, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("[attribution] Governed feed written to %s", args.feed)
    return 0

if __name__ == "__main__":
    sys.exit(main())
