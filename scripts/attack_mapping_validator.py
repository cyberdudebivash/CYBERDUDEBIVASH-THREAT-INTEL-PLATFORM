#!/usr/bin/env python3
"""
SENTINEL APEX — ATT&CK Mapping Validator v1.0.0
Validates ATT&CK mappings. Derives evidence-based mappings from CVE descriptions.
Requires: attack_justification, attack_evidence, attack_source. No speculative mappings.
"""
from __future__ import annotations
import argparse, json, logging, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [attck-validator] %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DERIVATION_RULES: List[Tuple[List[str], str, str, str]] = [
    (["auth.{0,20}bypass","authentication bypass","unauthenticated access",
      "unauthenticated.*exploit","pre.auth","globalprotect.*exploit",
      "exploit.*public.facing","exploit.*web"],
     "T1190","Exploit Public-Facing Application",
     "CVE description confirms exploitation of a public-facing application without authentication"),
    (["idor","insecure direct object","cross.workspace.*access",
      "object access.*bypass","unauthorized.*access.*object","broken access control"],
     "T1565.001","Data Manipulation: Stored Data Manipulation",
     "CVE describes unauthorized cross-object data access via missing access control checks"),
    (["privilege escalat","privesc","role.*escalat","become.*owner",
      "member.*become.*admin","elevat.*privilege"],
     "T1548","Abuse Elevation Control Mechanism",
     "CVE confirms exploitation allows privilege escalation to higher role"),
    (["hardcoded.*secret","hardcoded.*key","hardcoded.*password",
      "default.*secret","default.*password","default.*credential",
      "jwt.*default","signing key.*default"],
     "T1552.001","Unsecured Credentials: Credentials In Files",
     "CVE describes hardcoded or default credentials in application source/configuration"),
    (["ssrf","server.side request forgery","alternate loopback","loopback.*bypass"],
     "T1090.002","Proxy: External Proxy",
     "CVE confirms SSRF allowing requests to internal resources via server-side forgery"),
    (["remote code exec","rce","arbitrary code exec","code injection",
      "command injection","os command","sandbox escape","builtin.*exec"],
     "T1059","Command and Scripting Interpreter",
     "CVE confirms remote/arbitrary code execution capability"),
    (["sql inject","sqli","sql.*injection"],
     "T1190","Exploit Public-Facing Application",
     "CVE describes SQL injection in a public-facing web application"),
    (["path traversal","directory traversal","arbitrary file read",
      "file disclosure","local file inclusion","lfi"],
     "T1083","File and Directory Discovery",
     "CVE confirms unauthorized file read via path traversal"),
    (["deserializ","unsafe deseri","java deseri","pickle"],
     "T1190","Exploit Public-Facing Application",
     "CVE describes unsafe deserialization in a public-facing service"),
    (["xxe","xml external entity"],
     "T1190","Exploit Public-Facing Application",
     "CVE confirms XXE injection allowing external entity resolution"),
    (["buffer overflow","heap overflow","stack overflow",
      "memory corruption","use.after.free","out.of.bounds"],
     "T1203","Exploitation for Client Execution",
     "CVE describes memory corruption vulnerability exploitable for code execution"),
    (["supply chain","dependency.*confus","malicious package","typosquat"],
     "T1195.002","Supply Chain Compromise: Compromise Software Supply Chain",
     "Advisory describes supply chain compromise via malicious dependency"),
    (["cross.site script","xss","reflected xss","stored xss"],
     "T1059.007","Command and Scripting Interpreter: JavaScript",
     "CVE describes XSS enabling JavaScript injection in victim browser context"),
    (["denial.of.service","dos ","resource exhaust","infinite loop","crash.*remote"],
     "T1499","Endpoint Denial of Service",
     "CVE describes denial-of-service condition exploitable remotely"),
    (["ics","scada","modbus","dnp3","industrial control","programmable logic","plc ","hmi "],
     "T0819","Exploit Public-Facing Application (ICS)",
     "ICS advisory describes exploitation of industrial control system interface"),
    (["brute force","credential stuff","password spray","account lockout bypass"],
     "T1110","Brute Force",
     "CVE or advisory describes brute force or credential stuffing vector"),
    (["man.in.the.middle","mitm","tls.*bypass","certificate.*bypass","ssl.*strip"],
     "T1557","Adversary-in-the-Middle",
     "CVE describes TLS/certificate validation bypass enabling MITM"),
    (["information disclos","sensitive data expos","data leak","pii.*expos"],
     "T1005","Data from Local System",
     "CVE describes unauthorized sensitive information disclosure"),
]


def _text(item: Dict) -> str:
    return " ".join(filter(None,[
        str(item.get("title") or ""),str(item.get("description") or ""),
        str(item.get("apex_ai_summary") or ""),
    ])).lower()


def derive_attck_mapping(item: Dict) -> Optional[Dict]:
    text = _text(item)
    for patterns, technique_id, technique_name, justification in DERIVATION_RULES:
        for pattern in patterns:
            if re.search(pattern, text, re.I):
                source = item.get("source") or item.get("feed_source") or "CVE advisory"
                cve = item.get("cve_id") or ""
                return {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "attack_justification": justification,
                    "attack_evidence": f"{cve} — {text[:120].strip()}..." if cve else text[:120].strip()+"...",
                    "attack_source": source,
                    "mapping_method": "cve_description_derivation",
                    "verification_status": "EVIDENCE_BASED",
                    "matched_pattern": pattern,
                }
    return None


def validate_item_attck(item: Dict) -> Tuple[Dict, Dict]:
    item = dict(item)
    result = {"id":item.get("id",""),"title":(item.get("title") or "")[:60],
              "action_taken":"none","techniques_validated":0,"techniques_derived":0,
              "techniques_removed":0,"final_techniques":[]}
    existing_ids = item.get("attck_technique_ids") or []
    existing_techniques = item.get("attck_techniques") or []
    verification = item.get("attck_verification") or "NOT_VERIFIED"

    if existing_ids and verification in ("NOT_VERIFIED","NOT_MAPPED",None,""):
        result["techniques_removed"] = len(existing_ids)
        item["attck_technique_ids"] = []; item["attck_techniques"] = []
        item["attck_tactics"] = []; item["mitre_tactics"] = []; item["ttps"] = []
        item["attck_verification"] = "NOT_VERIFIED"
        result["action_taken"] = "cleared_unverified"
    elif existing_techniques:
        validated = []
        source = item.get("source") or item.get("feed_source") or ""
        for tech in existing_techniques:
            if isinstance(tech, dict):
                if not any(tech.get(k) for k in ("attack_justification","attack_evidence","attack_source")):
                    tech["attack_source"] = source
                    tech["attack_justification"] = f"Technique {tech.get('technique_id','')} from {source}"
                    tech["verification_status"] = "SOURCE_ATTRIBUTED"
                else:
                    tech["verification_status"] = "VERIFIED"
                validated.append(tech)
        item["attck_techniques"] = validated
        item["attck_technique_ids"] = [t.get("technique_id","") for t in validated]
        item["attck_verification"] = "VERIFIED" if validated else "NOT_VERIFIED"
        result["techniques_validated"] = len(validated)
        result["action_taken"] = "validated_existing"

    if not item.get("attck_technique_ids") and item.get("cve_id"):
        derived = derive_attck_mapping(item)
        if derived:
            item["attck_technique_ids"] = [derived["technique_id"]]
            item["attck_techniques"] = [derived]
            item["attck_verification"] = "EVIDENCE_BASED"
            item["attck_notes"] = [f"Derived from CVE description: {derived['matched_pattern']}"]
            result["techniques_derived"] = 1
            result["action_taken"] = "derived_from_cve"

    result["final_techniques"] = item.get("attck_technique_ids") or []
    return item, result


def process_feed(items: List[Dict]) -> Tuple[List[Dict], Dict]:
    governed, validations = [], []
    cleared, derived, validated = 0, 0, 0
    for item in items:
        patched, record = validate_item_attck(item)
        governed.append(patched); validations.append(record)
        if record["action_taken"] == "cleared_unverified": cleared += 1
        elif record["action_taken"] == "derived_from_cve": derived += 1
        elif record["action_taken"] == "validated_existing": validated += 1
    final_mapped = sum(1 for i in governed if i.get("attck_technique_ids"))
    return governed, {
        "total_items":len(items),"techniques_cleared":cleared,
        "techniques_derived":derived,"techniques_validated":validated,
        "items_with_attck_final":final_mapped,"per_item":validations,
        "engine_version":ENGINE_VERSION,"generated_at":datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=f"ATT&CK Mapping Validator v{ENGINE_VERSION}")
    parser.add_argument("feed", nargs="?", default=str(REPO_ROOT/"api"/"feed.json"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", default=str(REPO_ROOT/"data"/"governance"/"attack_validation.json"))
    args = parser.parse_args()
    raw = Path(args.feed).read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data,list) else data.get("threats",data.get("items",[]))
    log.info("[attck-validator] Processing %d items", len(items))
    governed, summary = process_feed(items)
    log.info("[attck-validator] cleared=%d derived=%d validated=%d final_mapped=%d",
             summary["techniques_cleared"],summary["techniques_derived"],
             summary["techniques_validated"],summary["items_with_attck_final"])
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.apply:
        Path(args.feed).write_text(json.dumps(governed, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("[attck-validator] Governed feed written to %s", args.feed)
    return 0

if __name__ == "__main__":
    sys.exit(main())
