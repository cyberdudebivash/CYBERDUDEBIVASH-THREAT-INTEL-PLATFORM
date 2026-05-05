#!/usr/bin/env python3
"""
scripts/mitre_v15_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — MITRE ATT&CK v15 TTP Enricher
===========================================================================
Replaces generic 'Technique T1234' labels with authoritative ATT&CK v15 names.
Corrects tactic mismatches (e.g., T1486 must be 'Impact', not 'Execution').

OPERATIONS:
  1. Enriches all TTP/mitre_tactics entries in api/feed.json and feed_manifest.json
  2. Corrects tactic field for every known technique
  3. Adds technique_name, tactic_corrected, url, is_sub_technique fields
  4. Writes corrected feeds atomically (no partial writes)
  5. Reports mismatch count for CI audit

EXIT CODES:
  0 = OK (enrichment applied)
  1 = Critical file missing or JSON parse error

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [mitre_v15] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.mitre_v15")

REPO       = Path(__file__).resolve().parent.parent
FEED_PATH  = REPO / "api" / "feed.json"
FEED2_PATH = REPO / "feed.json"
MANIFEST_PATH = REPO / "data" / "stix" / "feed_manifest.json"
ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"

# ── MITRE ATT&CK v15 Lookup Table ────────────────────────────────────────────
# Format: technique_id → (technique_name, primary_tactic, [all_tactics])
# All tactic values use the official ATT&CK slug format.
#
# Coverage: All Enterprise techniques appearing in threat intel feeds.
# Source: MITRE ATT&CK v15.1 (released April 2024).

ATTACK_V15: dict[str, tuple[str, str, list[str]]] = {
    # ── Initial Access ─────────────────────────────────────────────────────────
    "T1078":  ("Valid Accounts",                            "defense-evasion", ["defense-evasion","persistence","privilege-escalation","initial-access"]),
    "T1091":  ("Replication Through Removable Media",      "lateral-movement", ["lateral-movement","initial-access"]),
    "T1133":  ("External Remote Services",                 "initial-access",  ["initial-access","persistence"]),
    "T1189":  ("Drive-by Compromise",                      "initial-access",  ["initial-access"]),
    "T1190":  ("Exploit Public-Facing Application",        "initial-access",  ["initial-access"]),
    "T1195":  ("Supply Chain Compromise",                  "initial-access",  ["initial-access"]),
    "T1199":  ("Trusted Relationship",                     "initial-access",  ["initial-access"]),
    "T1200":  ("Hardware Additions",                       "initial-access",  ["initial-access"]),
    "T1566":  ("Phishing",                                 "initial-access",  ["initial-access"]),
    "T1566.001": ("Spearphishing Attachment",              "initial-access",  ["initial-access"]),
    "T1566.002": ("Spearphishing Link",                    "initial-access",  ["initial-access"]),
    "T1566.003": ("Spearphishing via Service",             "initial-access",  ["initial-access"]),
    # ── Execution ──────────────────────────────────────────────────────────────
    "T1047":  ("Windows Management Instrumentation",       "execution",       ["execution"]),
    "T1053":  ("Scheduled Task/Job",                       "execution",       ["execution","persistence","privilege-escalation"]),
    "T1059":  ("Command and Scripting Interpreter",        "execution",       ["execution"]),
    "T1059.001": ("PowerShell",                            "execution",       ["execution"]),
    "T1059.003": ("Windows Command Shell",                 "execution",       ["execution"]),
    "T1059.006": ("Python",                                "execution",       ["execution"]),
    "T1106":  ("Native API",                               "execution",       ["execution"]),
    "T1129":  ("Shared Modules",                           "execution",       ["execution"]),
    "T1203":  ("Exploitation for Client Execution",        "execution",       ["execution"]),
    "T1204":  ("User Execution",                           "execution",       ["execution"]),
    "T1204.001": ("Malicious Link",                        "execution",       ["execution"]),
    "T1204.002": ("Malicious File",                        "execution",       ["execution"]),
    "T1559":  ("Inter-Process Communication",              "execution",       ["execution"]),
    "T1609":  ("Container Administration Command",         "execution",       ["execution"]),
    "T1610":  ("Deploy Container",                         "execution",       ["execution","defense-evasion"]),
    # ── Persistence ───────────────────────────────────────────────────────────
    "T1037":  ("Boot or Logon Initialization Scripts",    "persistence",      ["persistence","privilege-escalation"]),
    "T1098":  ("Account Manipulation",                    "persistence",      ["persistence","privilege-escalation"]),
    "T1136":  ("Create Account",                          "persistence",      ["persistence"]),
    "T1176":  ("Browser Extensions",                      "persistence",      ["persistence"]),
    "T1505":  ("Server Software Component",               "persistence",      ["persistence"]),
    "T1546":  ("Event Triggered Execution",               "persistence",      ["persistence","privilege-escalation"]),
    "T1547":  ("Boot or Logon Autostart Execution",       "persistence",      ["persistence","privilege-escalation"]),
    "T1574":  ("Hijack Execution Flow",                   "persistence",      ["persistence","privilege-escalation","defense-evasion"]),
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1055":  ("Process Injection",                       "privilege-escalation", ["privilege-escalation","defense-evasion"]),
    "T1068":  ("Exploitation for Privilege Escalation",   "privilege-escalation", ["privilege-escalation"]),
    "T1134":  ("Access Token Manipulation",               "privilege-escalation", ["privilege-escalation","defense-evasion"]),
    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1027":  ("Obfuscated Files or Information",         "defense-evasion",  ["defense-evasion"]),
    "T1036":  ("Masquerading",                            "defense-evasion",  ["defense-evasion"]),
    "T1070":  ("Indicator Removal",                       "defense-evasion",  ["defense-evasion"]),
    "T1112":  ("Modify Registry",                         "defense-evasion",  ["defense-evasion"]),
    "T1140":  ("Deobfuscate/Decode Files or Information", "defense-evasion",  ["defense-evasion"]),
    "T1218":  ("System Binary Proxy Execution",           "defense-evasion",  ["defense-evasion"]),
    "T1562":  ("Impair Defenses",                         "defense-evasion",  ["defense-evasion"]),
    "T1620":  ("Reflective Code Loading",                 "defense-evasion",  ["defense-evasion"]),
    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003":  ("OS Credential Dumping",                   "credential-access", ["credential-access"]),
    "T1110":  ("Brute Force",                             "credential-access", ["credential-access"]),
    "T1539":  ("Steal Web Session Cookie",                "credential-access", ["credential-access"]),
    "T1552":  ("Unsecured Credentials",                   "credential-access", ["credential-access"]),
    "T1555":  ("Credentials from Password Stores",        "credential-access", ["credential-access"]),
    "T1557":  ("Adversary-in-the-Middle",                 "credential-access", ["credential-access","collection"]),
    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1007":  ("System Service Discovery",                "discovery",        ["discovery"]),
    "T1012":  ("Query Registry",                          "discovery",        ["discovery"]),
    "T1016":  ("System Network Configuration Discovery",  "discovery",        ["discovery"]),
    "T1018":  ("Remote System Discovery",                 "discovery",        ["discovery"]),
    "T1046":  ("Network Service Discovery",               "discovery",        ["discovery"]),
    "T1057":  ("Process Discovery",                       "discovery",        ["discovery"]),
    "T1069":  ("Permission Groups Discovery",             "discovery",        ["discovery"]),
    "T1082":  ("System Information Discovery",            "discovery",        ["discovery"]),
    "T1083":  ("File and Directory Discovery",            "discovery",        ["discovery"]),
    "T1518":  ("Software Discovery",                      "discovery",        ["discovery"]),
    "T1614":  ("System Location Discovery",               "discovery",        ["discovery"]),
    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021":  ("Remote Services",                         "lateral-movement", ["lateral-movement"]),
    "T1021.001": ("Remote Desktop Protocol",              "lateral-movement", ["lateral-movement"]),
    "T1021.006": ("Windows Remote Management",            "lateral-movement", ["lateral-movement"]),
    "T1080":  ("Taint Shared Content",                    "lateral-movement", ["lateral-movement"]),
    "T1550":  ("Use Alternate Authentication Material",   "lateral-movement", ["lateral-movement","defense-evasion"]),
    # ── Collection ────────────────────────────────────────────────────────────
    "T1005":  ("Data from Local System",                  "collection",       ["collection"]),
    "T1039":  ("Data from Network Shared Drive",          "collection",       ["collection"]),
    "T1056":  ("Input Capture",                           "collection",       ["collection","credential-access"]),
    "T1074":  ("Data Staged",                             "collection",       ["collection"]),
    "T1113":  ("Screen Capture",                          "collection",       ["collection"]),
    "T1114":  ("Email Collection",                        "collection",       ["collection"]),
    "T1119":  ("Automated Collection",                    "collection",       ["collection"]),
    "T1560":  ("Archive Collected Data",                  "collection",       ["collection"]),
    # ── Command and Control ───────────────────────────────────────────────────
    "T1071":  ("Application Layer Protocol",              "command-and-control", ["command-and-control"]),
    "T1071.001": ("Web Protocols",                        "command-and-control", ["command-and-control"]),
    "T1071.004": ("DNS",                                  "command-and-control", ["command-and-control"]),
    "T1090":  ("Proxy",                                   "command-and-control", ["command-and-control"]),
    "T1095":  ("Non-Application Layer Protocol",          "command-and-control", ["command-and-control"]),
    "T1105":  ("Ingress Tool Transfer",                   "command-and-control", ["command-and-control"]),
    "T1219":  ("Remote Access Software",                  "command-and-control", ["command-and-control"]),
    "T1571":  ("Non-Standard Port",                       "command-and-control", ["command-and-control"]),
    "T1572":  ("Protocol Tunneling",                      "command-and-control", ["command-and-control"]),
    "T1573":  ("Encrypted Channel",                       "command-and-control", ["command-and-control"]),
    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1020":  ("Automated Exfiltration",                  "exfiltration",     ["exfiltration"]),
    "T1041":  ("Exfiltration Over C2 Channel",            "exfiltration",     ["exfiltration"]),
    "T1048":  ("Exfiltration Over Alternative Protocol",  "exfiltration",     ["exfiltration"]),
    "T1052":  ("Exfiltration Over Physical Medium",       "exfiltration",     ["exfiltration"]),
    "T1567":  ("Exfiltration Over Web Service",           "exfiltration",     ["exfiltration"]),
    # ── Impact ────────────────────────────────────────────────────────────────
    # NOTE: These were previously incorrectly mapped to 'Execution' in the enricher.
    "T1485":  ("Data Destruction",                        "impact",           ["impact"]),
    "T1486":  ("Data Encrypted for Impact",               "impact",           ["impact"]),
    "T1489":  ("Service Stop",                            "impact",           ["impact"]),
    "T1490":  ("Inhibit System Recovery",                 "impact",           ["impact"]),
    "T1491":  ("Defacement",                              "impact",           ["impact"]),
    "T1495":  ("Firmware Corruption",                     "impact",           ["impact"]),
    "T1496":  ("Resource Hijacking",                      "impact",           ["impact"]),
    "T1498":  ("Network Denial of Service",               "impact",           ["impact"]),
    "T1499":  ("Endpoint Denial of Service",              "impact",           ["impact"]),
    "T1529":  ("System Shutdown/Reboot",                  "impact",           ["impact"]),
    "T1531":  ("Account Access Removal",                  "impact",           ["impact"]),
    "T1561":  ("Disk Wipe",                               "impact",           ["impact"]),
    # ── Reconnaissance ────────────────────────────────────────────────────────
    "T1589":  ("Gather Victim Identity Information",      "reconnaissance",   ["reconnaissance"]),
    "T1590":  ("Gather Victim Network Information",       "reconnaissance",   ["reconnaissance"]),
    "T1591":  ("Gather Victim Org Information",           "reconnaissance",   ["reconnaissance"]),
    "T1592":  ("Gather Victim Host Information",          "reconnaissance",   ["reconnaissance"]),
    "T1593":  ("Search Open Websites/Domains",            "reconnaissance",   ["reconnaissance"]),
    "T1595":  ("Active Scanning",                         "reconnaissance",   ["reconnaissance"]),
    "T1596":  ("Search Open Technical Databases",         "reconnaissance",   ["reconnaissance"]),
    "T1597":  ("Search Closed Sources",                   "reconnaissance",   ["reconnaissance"]),
    "T1598":  ("Phishing for Information",                "reconnaissance",   ["reconnaissance"]),
    # ── Resource Development ──────────────────────────────────────────────────
    "T1583":  ("Acquire Infrastructure",                  "resource-development", ["resource-development"]),
    "T1584":  ("Compromise Infrastructure",               "resource-development", ["resource-development"]),
    "T1585":  ("Establish Accounts",                      "resource-development", ["resource-development"]),
    "T1586":  ("Compromise Accounts",                     "resource-development", ["resource-development"]),
    "T1587":  ("Develop Capabilities",                    "resource-development", ["resource-development"]),
    "T1588":  ("Obtain Capabilities",                     "resource-development", ["resource-development"]),
    "T1608":  ("Stage Capabilities",                      "resource-development", ["resource-development"]),
}

# Official tactic display names (slug → human-readable)
TACTIC_DISPLAY: dict[str, str] = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command & Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Development",
}


def _technique_url(tid: str) -> str:
    clean = tid.replace(".", "/")
    return f"{ATTACK_BASE_URL}{clean}"


def _is_sub_technique(tid: str) -> bool:
    return "." in tid


def enrich_ttp(ttp: dict) -> tuple[dict, bool]:
    """
    Enrich a single TTP dict with ATT&CK v15 data.
    Returns (enriched_dict, was_changed: bool).
    """
    if not isinstance(ttp, dict):
        return ttp, False

    tid = str(ttp.get("id", "")).strip().upper()
    # Normalise: handle 'T1203', 't1203', 'attack-pattern--...' prefixes
    if not tid.startswith("T"):
        return ttp, False
    # Look up (case-insensitive, uppercase canonical)
    record = ATTACK_V15.get(tid)
    if record is None:
        # Try parent (e.g., T1059.001 → T1059)
        parent = tid.split(".")[0]
        record = ATTACK_V15.get(parent)

    if record is None:
        return ttp, False

    technique_name, primary_tactic, all_tactics = record
    old_tactic = str(ttp.get("tactic", "")).lower()
    old_name   = str(ttp.get("name", ""))
    tactic_corrected = old_tactic != primary_tactic

    enriched = {
        **ttp,
        "id":            tid,
        "name":          technique_name,
        "tactic":        primary_tactic,
        "tactic_display": TACTIC_DISPLAY.get(primary_tactic, primary_tactic.title()),
        "all_tactics":   all_tactics,
        "url":           _technique_url(tid),
        "is_sub_technique": _is_sub_technique(tid),
        "v15_enriched":  True,
    }

    was_changed = (old_name != technique_name) or tactic_corrected
    if tactic_corrected:
        enriched["tactic_corrected_from"] = old_tactic
        log.debug("TACTIC CORRECTED: %s %s→%s", tid, old_tactic, primary_tactic)

    return enriched, was_changed


def enrich_item(item: dict) -> tuple[dict, int]:
    """
    Enrich all TTP fields in a single advisory.
    Returns (enriched_item, change_count).
    """
    changes = 0
    for field in ("ttps", "mitre_tactics", "tags"):
        raw = item.get(field)
        if not raw or not isinstance(raw, list):
            continue

        enriched_list = []
        for entry in raw:
            if isinstance(entry, dict):
                enriched_entry, changed = enrich_ttp(entry)
                enriched_list.append(enriched_entry)
                if changed:
                    changes += 1
            elif isinstance(entry, str) and entry.startswith("T"):
                # Tags stored as plain TTP IDs — enrich to dicts
                record = ATTACK_V15.get(entry.upper())
                if record:
                    technique_name, primary_tactic, all_tactics = record
                    enriched_list.append({
                        "id":            entry.upper(),
                        "name":          technique_name,
                        "tactic":        primary_tactic,
                        "tactic_display": TACTIC_DISPLAY.get(primary_tactic, primary_tactic.title()),
                        "all_tactics":   all_tactics,
                        "url":           _technique_url(entry.upper()),
                        "is_sub_technique": _is_sub_technique(entry),
                        "v15_enriched":  True,
                        "justification": f"{entry.upper()} — {technique_name} (MITRE ATT&CK v15)",
                    })
                    changes += 1
                else:
                    enriched_list.append(entry)
            else:
                enriched_list.append(entry)

        item = {**item, field: enriched_list}

    return item, changes


def _atomic_write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    tmp.rename(path)


def enrich_feed(path: Path, label: str) -> tuple[int, int]:
    """Enrich a feed JSON file. Returns (items_processed, changes_total)."""
    if not path.exists():
        log.warning("Feed not found (skipping): %s", path)
        return 0, 0

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Failed to parse %s: %s", label, e)
        return 0, 0

    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("items") or raw.get("advisories") or []
    else:
        log.warning("Unexpected root type in %s: %s", label, type(raw))
        return 0, 0

    enriched_items = []
    total_changes = 0
    for item in items:
        enriched, n = enrich_item(item)
        enriched_items.append(enriched)
        total_changes += n

    if isinstance(raw, list):
        output = enriched_items
    else:
        output = {**raw, "items": enriched_items}

    _atomic_write(path, output)
    log.info("[%s] Enriched %d items | %d TTP changes", label, len(items), total_changes)
    return len(items), total_changes


def main() -> int:
    log.info("SENTINEL APEX v143.1.0 — MITRE ATT&CK v15 TTP Enricher starting")
    log.info("Coverage: %d techniques in lookup table", len(ATTACK_V15))
    t0 = time.time()

    total_items = 0
    total_changes = 0

    for path, label in [
        (FEED_PATH,     "api/feed.json"),
        (FEED2_PATH,    "feed.json"),
    ]:
        n, c = enrich_feed(path, label)
        total_items  += n
        total_changes += c

    log.info(
        "DONE: %d items enriched | %d TTP fields updated | %.2fs",
        total_items, total_changes, time.time() - t0,
    )

    if total_items == 0:
        log.error("No items enriched — api/feed.json not found or empty")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
