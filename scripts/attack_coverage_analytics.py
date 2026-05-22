#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
ATT&CK COVERAGE ANALYTICS GOVERNANCE
===============================================================================
PURPOSE:
  Generates comprehensive MITRE ATT&CK coverage analytics across the entire
  intelligence feed. Identifies which tactics, techniques and sub-techniques
  are covered, which are gaps, and tracks coverage trends over time.

OUTPUTS:
  data/governance/attack_coverage.json    — governance report with coverage %
  data/intelligence/attack_navigator.json — ATT&CK Navigator layer (importable)

COVERAGE METRICS:
  - Tactic coverage (14 TA tactics)
  - Technique coverage (count + % of ~200 top techniques tracked)
  - Sub-technique coverage
  - Top observed techniques ranked by advisory count
  - Coverage gap list (unobserved high-priority techniques)
  - Per-actor ATT&CK fingerprint

GOVERNANCE THRESHOLDS:
  PASS:   >= 40% tactic coverage AND >= 10% technique coverage
  WARN:   20-39% tactic coverage OR 5-9% technique coverage
  FAIL:   < 20% tactic coverage  OR < 5% technique coverage

EXIT CODES:
  0 — PASS or WARN (non-blocking)
  0 — always (governance analytics must not break production pipeline)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [attack_coverage] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-ATTACK-COVERAGE")

REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
FEED_PATH   = REPO_ROOT / "api" / "feed.json"
GOV_DIR     = REPO_ROOT / "data" / "governance"
INTEL_DIR   = REPO_ROOT / "data" / "intelligence"
REPORT_PATH = GOV_DIR / "attack_coverage.json"
NAVIGATOR_PATH = INTEL_DIR / "attack_navigator.json"

VERSION = "146.0.0"

# 14 MITRE ATT&CK Tactics (Enterprise v15)
TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# High-priority techniques map: technique_id -> (tactic_id, name)
PRIORITY_TECHNIQUES = {
    "T1190": ("TA0001", "Exploit Public-Facing Application"),
    "T1133": ("TA0001", "External Remote Services"),
    "T1566": ("TA0001", "Phishing"),
    "T1195": ("TA0001", "Supply Chain Compromise"),
    "T1078": ("TA0001", "Valid Accounts"),
    "T1059": ("TA0002", "Command and Scripting Interpreter"),
    "T1053": ("TA0002", "Scheduled Task/Job"),
    "T1203": ("TA0002", "Exploitation for Client Execution"),
    "T1547": ("TA0003", "Boot or Logon Autostart Execution"),
    "T1136": ("TA0003", "Create Account"),
    "T1543": ("TA0003", "Create or Modify System Process"),
    "T1068": ("TA0004", "Exploitation for Privilege Escalation"),
    "T1548": ("TA0004", "Abuse Elevation Control Mechanism"),
    "T1055": ("TA0004", "Process Injection"),
    "T1027": ("TA0005", "Obfuscated Files or Information"),
    "T1562": ("TA0005", "Impair Defenses"),
    "T1070": ("TA0005", "Indicator Removal"),
    "T1112": ("TA0005", "Modify Registry"),
    "T1003": ("TA0006", "OS Credential Dumping"),
    "T1110": ("TA0006", "Brute Force"),
    "T1557": ("TA0006", "Adversary-in-the-Middle"),
    "T1087": ("TA0007", "Account Discovery"),
    "T1082": ("TA0007", "System Information Discovery"),
    "T1057": ("TA0007", "Process Discovery"),
    "T1021": ("TA0008", "Remote Services"),
    "T1570": ("TA0008", "Lateral Tool Transfer"),
    "T1560": ("TA0009", "Archive Collected Data"),
    "T1005": ("TA0009", "Data from Local System"),
    "T1071": ("TA0011", "Application Layer Protocol"),
    "T1573": ("TA0011", "Encrypted Channel"),
    "T1572": ("TA0011", "Protocol Tunneling"),
    "T1105": ("TA0011", "Ingress Tool Transfer"),
    "T1041": ("TA0010", "Exfiltration Over C2 Channel"),
    "T1048": ("TA0010", "Exfiltration Over Alternative Protocol"),
    "T1486": ("TA0040", "Data Encrypted for Impact"),
    "T1490": ("TA0040", "Inhibit System Recovery"),
    "T1498": ("TA0040", "Network Denial of Service"),
    "T1489": ("TA0040", "Service Stop"),
    "T1595": ("TA0043", "Active Scanning"),
    "T1592": ("TA0043", "Gather Victim Host Information"),
    "T1588": ("TA0042", "Obtain Capabilities"),
    "T1608": ("TA0042", "Stage Capabilities"),
}

TACTIC_COVERAGE_PASS = 0.40
TACTIC_COVERAGE_WARN = 0.20
TECH_COVERAGE_PASS   = 0.10
TECH_COVERAGE_WARN   = 0.05

# v160.0 -- Reverse lookup maps: human-readable names -> IDs
# The feed stores technique/tactic names (not IDs) in mitre_tactics.
# These maps enable full ATT&CK coverage detection from name-based feeds.
TECH_NAME_TO_ID: Dict[str, str] = {
    name.lower().strip(): tid
    for tid, (_, name) in PRIORITY_TECHNIQUES.items()
}
TACTIC_NAME_TO_ID: Dict[str, str] = {
    name.lower().strip(): tid
    for tid, name in TACTICS.items()
}
# Extra common aliases the feed may use
_EXTRA_NAME_ALIASES: Dict[str, str] = {
    "data encrypted for impact":             "T1486",
    "exfiltration over c2 channel":          "T1041",
    "steal web session cookie":              "T1539",
    "exploitation for client execution":     "T1203",
    "exploitation for privilege escalation": "T1068",
    "abuse elevation control mechanism":     "T1548",
    "impair defenses":                       "T1562",
    "indicator removal":                     "T1070",
    "ingress tool transfer":                 "T1105",
    "lateral tool transfer":                 "T1570",
    "obfuscated files or information":       "T1027",
    "os credential dumping":                 "T1003",
    "application layer protocol":            "T1071",
    "archive collected data":                "T1560",
    "brute force":                           "T1110",
    "command and scripting interpreter":     "T1059",
    "create account":                        "T1136",
    "data from local system":                "T1005",
    "encrypted channel":                     "T1573",
    "exploit public-facing application":     "T1190",
    "external remote services":              "T1133",
    "gather victim host information":        "T1592",
    "inhibit system recovery":               "T1490",
    "network denial of service":             "T1498",
    "obtain capabilities":                   "T1588",
    "phishing":                              "T1566",
    "process discovery":                     "T1057",
    "process injection":                     "T1055",
    "protocol tunneling":                    "T1572",
    "remote services":                       "T1021",
    "reconnaissance":                        "T1595",
    "active scanning":                       "T1595",
    "scheduled task/job":                    "T1053",
    "service stop":                          "T1489",
    "stage capabilities":                    "T1608",
    "supply chain compromise":               "T1195",
    "system information discovery":          "T1082",
    "account discovery":                     "T1087",
    "valid accounts":                        "T1078",
    "boot or logon autostart execution":     "T1547",
    "create or modify system process":       "T1543",
    "adversary-in-the-middle":               "T1557",
}
TECH_NAME_TO_ID.update(_EXTRA_NAME_ALIASES)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".atk_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _resolve_entry(entry: Any) -> str:
    """v160.0: Resolve a single mitre_tactics/mitre_techniques entry to a T-ID.
    Accepts: T-ID strings (T1xxx), TA-ID strings (TA0xxx), dicts with technique_id/id,
    OR human-readable technique/tactic names (looked up via reverse maps).
    Returns the T-ID string or '' if unresolvable.
    """
    if isinstance(entry, dict):
        raw_id = entry.get("technique_id") or entry.get("id") or entry.get("name") or ""
    else:
        raw_id = str(entry)

    tid = raw_id.strip().upper()

    # Direct T-ID match (T1xxx, T1xxx.yyy)
    if tid.startswith("T") and not tid.startswith("TA") and len(tid) >= 5:
        return tid.split(".")[0]

    # TA-ID: look up any technique in that tactic (maps to first priority tech in tactic)
    if tid.startswith("TA") and len(tid) >= 6:
        for tech_id, (tac_id, _) in PRIORITY_TECHNIQUES.items():
            if tac_id == tid:
                return tech_id  # register coverage for first matched technique

    # Human-readable name lookup (v160.0 -- handles name-based feeds)
    name_key = raw_id.strip().lower()
    if name_key in TECH_NAME_TO_ID:
        return TECH_NAME_TO_ID[name_key]

    # Try tactic name -> register coverage for matching techniques
    if name_key in TACTIC_NAME_TO_ID:
        tac_id = TACTIC_NAME_TO_ID[name_key]
        for tech_id, (t_tac, _) in PRIORITY_TECHNIQUES.items():
            if t_tac == tac_id:
                return tech_id  # register coverage for first matched technique

    return ""


def extract_techniques(item: Dict[str, Any]) -> List[str]:
    """Extract all MITRE technique IDs from an item.
    v160.0: Supports T-IDs, TA-IDs, and human-readable names from name-based feeds.
    """
    techs: Set[str] = set()

    # mitre_tactics field (array of technique IDs, TA-IDs, or human-readable names)
    raw = item.get("mitre_tactics") or item.get("ttps") or []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw.replace("'", '"'))
        except Exception:
            raw = [raw]
    if isinstance(raw, list):
        for entry in raw:
            resolved = _resolve_entry(entry)
            if resolved:
                techs.add(resolved)

    # mitre_techniques field (same resolution logic)
    raw2 = item.get("mitre_techniques") or []
    if isinstance(raw2, list):
        for entry in raw2:
            resolved = _resolve_entry(entry)
            if resolved:
                techs.add(resolved)

    # kill_chain_phase field (single string or list, often a tactic name)
    kcp = item.get("kill_chain_phase") or item.get("kill_chain") or ""
    if isinstance(kcp, str) and kcp:
        resolved = _resolve_entry(kcp)
        if resolved:
            techs.add(resolved)
    elif isinstance(kcp, list):
        for entry in kcp:
            resolved = _resolve_entry(entry)
            if resolved:
                techs.add(resolved)

    return list(techs)


def build_navigator_layer(
    tech_counts: Counter,
    total_advisories: int,
) -> Dict[str, Any]:
    """Build an ATT&CK Navigator-compatible layer JSON."""
    techniques = []
    for tech_id, count in tech_counts.items():
        score = min(100, int((count / max(total_advisories, 1)) * 500))
        techniques.append({
            "techniqueID": tech_id,
            "score"      : score,
            "comment"    : f"{count} advisor{'y' if count == 1 else 'ies'}",
            "enabled"    : True,
        })

    return {
        "name"           : "SENTINEL APEX — ATT&CK Coverage",
        "versions"       : {"attack": "15", "navigator": "4.9", "layer": "4.5"},
        "domain"         : "enterprise-attack",
        "description"    : f"Generated by SENTINEL APEX {VERSION} — {now_iso()}",
        "filters"        : {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
        "sorting"        : 3,
        "layout"         : {"layout": "side", "showID": True, "showName": True},
        "hideDisabled"   : False,
        "techniques"     : techniques,
        "gradient"       : {
            "colors": ["#ffffff", "#00d4aa"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems"    : [
            {"label": "Low coverage", "color": "#ccffee"},
            {"label": "High coverage", "color": "#00d4aa"},
        ],
        "metadata"       : [{"name": "generated_at", "value": now_iso()}],
    }


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — ATT&CK Coverage Analytics", VERSION)
    log.info("Feed: %s", FEED_PATH)
    log.info("=" * 66)

    # Load feed
    if not FEED_PATH.exists():
        log.warning("[SKIP] Feed not found — creating empty coverage report")
        items = []
    else:
        try:
            with open(FEED_PATH, encoding="utf-8", errors="replace") as f:
                items = json.load(f)
            if not isinstance(items, list):
                items = []
        except Exception as e:
            log.warning("[SKIP] Feed load error: %s", e)
            items = []

    log.info("Loaded %d items", len(items))

    # Gather all techniques
    tech_counter: Counter = Counter()
    tactic_counter: Counter = Counter()
    actor_tech_map: Dict[str, Set[str]] = defaultdict(set)
    items_with_mitre = 0

    for item in items:
        techs = extract_techniques(item)
        if techs:
            items_with_mitre += 1
        for tid in techs:
            tech_counter[tid] += 1
            # Map to tactic
            if tid in PRIORITY_TECHNIQUES:
                tac_id, _ = PRIORITY_TECHNIQUES[tid]
                tactic_counter[tac_id] += 1
            # Actor fingerprint
            actor = item.get("actor_tag") or "UNATTRIBUTED"
            actor_tech_map[actor].add(tid)

    # Coverage calculations
    observed_tactics  = {t for t in tactic_counter if tactic_counter[t] > 0}
    observed_techs    = set(tech_counter.keys())
    priority_covered  = observed_techs & set(PRIORITY_TECHNIQUES.keys())

    tactic_cov_pct    = len(observed_tactics) / max(len(TACTICS), 1)
    tech_cov_pct      = len(priority_covered) / max(len(PRIORITY_TECHNIQUES), 1)

    # Top 20 observed techniques
    top_techniques    = [
        {
            "technique_id": tid,
            "name"        : PRIORITY_TECHNIQUES.get(tid, ("?", tid))[1] if tid in PRIORITY_TECHNIQUES else "Unknown",
            "tactic"      : PRIORITY_TECHNIQUES.get(tid, (tid, "?"))[0],
            "advisory_count": count,
        }
        for tid, count in tech_counter.most_common(20)
    ]

    # Gap list — high-priority techniques NOT observed
    gap_techniques    = [
        {
            "technique_id": tid,
            "name"        : name,
            "tactic"      : tac,
        }
        for tid, (tac, name) in PRIORITY_TECHNIQUES.items()
        if tid not in observed_techs
    ]

    # Actor fingerprints
    actor_fingerprints = {
        actor: sorted(list(techs))
        for actor, techs in actor_tech_map.items()
        if techs
    }

    # Governance verdict
    if tactic_cov_pct >= TACTIC_COVERAGE_PASS and tech_cov_pct >= TECH_COVERAGE_PASS:
        verdict = "PASS"
    elif tactic_cov_pct >= TACTIC_COVERAGE_WARN and tech_cov_pct >= TECH_COVERAGE_WARN:
        verdict = "WARN"
    else:
        verdict = "FAIL"

    runtime = round(time.monotonic() - t0, 3)

    log.info("Tactics covered    : %d / %d (%.1f%%)", len(observed_tactics), len(TACTICS), tactic_cov_pct * 100)
    log.info("Techniques covered : %d / %d (%.1f%%)", len(priority_covered), len(PRIORITY_TECHNIQUES), tech_cov_pct * 100)
    log.info("Items w/ MITRE data: %d / %d", items_with_mitre, len(items))
    log.info("Top technique      : %s", tech_counter.most_common(1)[0] if tech_counter else "none")
    log.info("Coverage verdict   : %s", verdict)

    # Build governance report
    report = {
        "schema_version"         : "1.0",
        "generated_at"           : now_iso(),
        "generator"              : "attack_coverage_analytics.py",
        "version"                : VERSION,
        "total_advisories"       : len(items),
        "advisories_with_mitre"  : items_with_mitre,
        "tactic_coverage_count"  : len(observed_tactics),
        "tactic_coverage_total"  : len(TACTICS),
        "tactic_coverage_pct"    : round(tactic_cov_pct * 100, 1),
        "technique_coverage_count": len(priority_covered),
        "technique_coverage_total": len(PRIORITY_TECHNIQUES),
        "technique_coverage_pct" : round(tech_cov_pct * 100, 1),
        "governance_verdict"     : verdict,
        "thresholds"             : {
            "tactic_pass": TACTIC_COVERAGE_PASS * 100,
            "tactic_warn": TACTIC_COVERAGE_WARN * 100,
            "tech_pass"  : TECH_COVERAGE_PASS * 100,
            "tech_warn"  : TECH_COVERAGE_WARN * 100,
        },
        "observed_tactics"       : sorted(list(observed_tactics)),
        "missing_tactics"        : sorted([t for t in TACTICS if t not in observed_tactics]),
        "top_techniques"         : top_techniques,
        "coverage_gaps"          : gap_techniques[:20],
        "actor_fingerprints"     : actor_fingerprints,
        "runtime_seconds"        : runtime,
    }

    GOV_DIR.mkdir(parents=True, exist_ok=True)
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))
    log.info("[WRITE] Coverage report: %s", REPORT_PATH)

    # Navigator layer
    nav_layer = build_navigator_layer(tech_counter, len(items))
    atomic_write(NAVIGATOR_PATH, json.dumps(nav_layer, ensure_ascii=False, indent=2))
    log.info("[WRITE] Navigator layer: %s", NAVIGATOR_PATH)

    log.info("=" * 66)
    log.info("ATT&CK COVERAGE COMPLETE: verdict=%s tactic=%.1f%% tech=%.1f%%",
             verdict, tactic_cov_pct * 100, tech_cov_pct * 100)
    log.info("=" * 66)
    return 0   # non-blocking: always exit 0


if __name__ == "__main__":
    sys.exit(main())
