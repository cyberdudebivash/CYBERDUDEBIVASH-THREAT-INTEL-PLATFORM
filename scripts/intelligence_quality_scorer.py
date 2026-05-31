#!/usr/bin/env python3
"""
scripts/intelligence_quality_scorer.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Intelligence Quality Scorer v1.0.0
=======================================================================
GAP-011: Confidence scores unreliable (flat 0.2 for most items)
GAP-020: ATT&CK mapping is tag-level only (names not T-IDs)
GAP-021: No intelligence aging/TTL

This script:
  1. Computes multi-factor confidence score from evidence signals
  2. Maps ATT&CK technique names to specific T-IDs (T1190, T1078, etc.)
  3. Applies confidence decay based on item age (half-life model)
  4. Computes a final IntelligenceQuality score (IQ score 0-100)

CONFIDENCE FACTORS:
  Factor A: Source reliability        (0-25 pts)
    - Primary CVE source:         15 pts
    - Vendor advisory:            25 pts
    - Security researcher:        20 pts
    - Generic/unknown:            5 pts

  Factor B: Enrichment completeness   (0-25 pts)
    - Has CVSS score:             5 pts
    - Has EPSS score:             5 pts
    - Has KEV flag:               5 pts
    - Has exploit maturity:       5 pts
    - Has IOCs:                   5 pts

  Factor C: Attribution quality       (0-25 pts)
    - Named actor (non-UNATTR):   15 pts
    - Has MITRE ATT&CK TTPs:      5 pts
    - Has malware association:     5 pts

  Factor D: Corroboration             (0-25 pts)
    - KEV (official govt source): 25 pts
    - High EPSS (>50%):           20 pts
    - Public PoC exists:          15 pts
    - Metasploit module:          25 pts

ATT&CK T-ID MAPPING (most common technique names -> IDs)
Decay: confidence *= 0.95^(days_old/30) -- 5% decay per month
"""
from __future__ import annotations
import json, logging, os, re
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [IQ-SCORE] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("IQ-SCORE")

REPO_ROOT  = Path(__file__).resolve().parent.parent
FEED_PATH  = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
TELEMETRY  = REPO_ROOT / "data" / "telemetry" / "intelligence_quality_report.json"
DRY_RUN    = os.environ.get("DRY_RUN", "").lower() == "true"

# ── ATT&CK Technique Name -> T-ID mapping ───────────────────────────────────
ATTCK_NAME_TO_TID = {
    # Initial Access
    "Exploit Public-Facing Application": "T1190",
    "Valid Accounts": "T1078",
    "Phishing": "T1566",
    "Spearphishing Attachment": "T1566.001",
    "Spearphishing Link": "T1566.002",
    "Supply Chain Compromise": "T1195",
    "Trusted Relationship": "T1199",
    "Drive-by Compromise": "T1189",
    "External Remote Services": "T1133",
    "Hardware Additions": "T1200",
    # Execution
    "Command and Scripting Interpreter": "T1059",
    "PowerShell": "T1059.001",
    "Python": "T1059.006",
    "Unix Shell": "T1059.004",
    "Windows Command Shell": "T1059.003",
    "User Execution": "T1204",
    "Scheduled Task/Job": "T1053",
    "Exploitation for Client Execution": "T1203",
    "Native API": "T1106",
    # Persistence
    "Boot or Logon Autostart Execution": "T1547",
    "Create Account": "T1136",
    "Create or Modify System Process": "T1543",
    "Hijack Execution Flow": "T1574",
    "Scheduled Task": "T1053.005",
    # Privilege Escalation
    "Abuse Elevation Control Mechanism": "T1548",
    "Process Injection": "T1055",
    "Exploitation for Privilege Escalation": "T1068",
    # Defense Evasion
    "Obfuscated Files or Information": "T1027",
    "Masquerading": "T1036",
    "Indicator Removal": "T1070",
    "Modify Registry": "T1112",
    "Disable or Modify Tools": "T1562.001",
    # Credential Access
    "Brute Force": "T1110",
    "OS Credential Dumping": "T1003",
    "Steal Application Access Token": "T1528",
    "Multi-Factor Authentication Request Generation": "T1621",
    # Discovery
    "Network Service Discovery": "T1046",
    "System Information Discovery": "T1082",
    "Account Discovery": "T1087",
    # Lateral Movement
    "Remote Services": "T1021",
    "Lateral Tool Transfer": "T1570",
    # Collection
    "Data from Local System": "T1005",
    "Screen Capture": "T1113",
    "Email Collection": "T1114",
    # C2
    "Application Layer Protocol": "T1071",
    "Web Protocols": "T1071.001",
    "Encrypted Channel": "T1573",
    # Exfiltration
    "Exfiltration Over C2 Channel": "T1041",
    "Data Encrypted for Impact": "T1486",
    # Impact
    "Data Encrypted for Impact": "T1486",
    "Service Stop": "T1489",
    "Inhibit System Recovery": "T1490",
    "Defacement": "T1491",
    "Disk Wipe": "T1561",
}

# Reverse map: TID -> name
TID_TO_NAME = {v: k for k, v in ATTCK_NAME_TO_TID.items()}

# ── Source reliability scores ────────────────────────────────────────────────
SOURCE_SCORES = {
    "SENTINEL-APEX": 15,
    "MSRC": 25,
    "Cisco": 25,
    "Fortinet": 25,
    "VMware": 25,
    "Palo Alto": 25,
    "BleepingComputer": 20,
    "Krebs": 20,
    "Mandiant": 25,
    "CrowdStrike": 25,
    "Microsoft": 25,
    "Vulners": 18,
    "AlienVault": 18,
    "NVD": 22,
    "CISA": 25,
}


def _source_score(item: dict) -> int:
    src = str(item.get("source") or item.get("feed_source") or "SENTINEL-APEX")
    for key, pts in SOURCE_SCORES.items():
        if key.lower() in src.lower():
            return pts
    return 10  # unknown source


def _enrichment_score(item: dict) -> int:
    score = 0
    if item.get("cvss_score") or item.get("cvss"): score += 5
    if item.get("epss_score") or item.get("epss"): score += 5
    if str(item.get("kev", "") or item.get("KEV", "") or "").upper() in ("YES","TRUE","1"): score += 5
    if item.get("exploit_maturity") and item["exploit_maturity"] != "UNPROVEN": score += 5
    if (item.get("ioc_count") or 0) > 0: score += 5
    return min(score, 25)


def _attribution_score(item: dict) -> int:
    score = 0
    actor = str(item.get("actor") or "")
    if actor and not actor.startswith("CDB-UNATTR"): score += 15
    if item.get("actor_mitre_id"): score += 3
    ttps = item.get("actor_ttps") or item.get("tags") or []
    if len(ttps) > 0: score += 5
    if item.get("actor_malware") and len(item.get("actor_malware", [])) > 0: score += 2
    return min(score, 25)


def _corroboration_score(item: dict) -> int:
    score = 0
    kev = str(item.get("kev") or item.get("KEV") or item.get("cisa_kev") or "").upper()
    if kev in ("YES","TRUE","1"): score = max(score, 25)

    msf = item.get("metasploit_available")
    if msf: score = max(score, 25)

    maturity = str(item.get("exploit_maturity") or "UNPROVEN")
    if maturity == "WEAPONIZED": score = max(score, 25)
    elif maturity == "FUNCTIONAL": score = max(score, 20)
    elif maturity == "POC": score = max(score, 15)

    epss = 0.0
    try:
        raw = str(item.get("epss_score") or item.get("epss") or "0").replace("%","")
        epss = float(raw)
        if epss > 1: epss /= 100.0
    except Exception: pass
    if epss >= 0.50: score = max(score, 20)
    elif epss >= 0.10: score = max(score, 10)

    return min(score, 25)


def _compute_age_days(item: dict) -> float:
    ts = item.get("timestamp") or item.get("processed_at") or item.get("published_at") or ""
    if not ts:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0
    except Exception:
        return 0.0


def _apply_age_decay(raw_score: float, age_days: float) -> float:
    """5% confidence decay per 30 days. Never below 20% of original."""
    if age_days <= 0:
        return raw_score
    decay = 0.95 ** (age_days / 30.0)
    return max(raw_score * decay, raw_score * 0.20)


def _map_attck_techniques(item: dict) -> list:
    """Map ATT&CK technique names in tags to T-IDs."""
    tags = item.get("tags") or item.get("labels") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    ttps = list(item.get("actor_ttps") or [])
    tid_set = set(ttps)  # existing T-IDs
    tid_names = []

    for tag in tags:
        tag_stripped = tag.strip()
        # Direct name match
        if tag_stripped in ATTCK_NAME_TO_TID:
            tid = ATTCK_NAME_TO_TID[tag_stripped]
            if tid not in tid_set:
                tid_set.add(tid)
                ttps.append(tid)
            tid_names.append({"id": tid, "name": tag_stripped})
        # Already a T-ID
        elif re.match(r"^T\d{4}(\.\d{3})?$", tag_stripped):
            if tag_stripped not in tid_set:
                tid_set.add(tag_stripped)
                ttps.append(tag_stripped)
            name = TID_TO_NAME.get(tag_stripped, tag_stripped)
            tid_names.append({"id": tag_stripped, "name": name})

    return ttps, tid_names


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run():
    log.info("=" * 60)
    log.info("INTELLIGENCE QUALITY SCORER v1.0.0 -- GAP-011/020/021")
    log.info("Feed: %s | DRY_RUN=%s", FEED_PATH, DRY_RUN)
    log.info("=" * 60)

    try:
        feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Cannot load feed: %s", e)
        return {"status": "ERROR"}

    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    log.info("Loaded %d items", len(items))

    score_sum = 0
    age_decayed = 0
    ttps_mapped = 0

    for it in items:
        # Factor A: Source reliability
        fa = _source_score(it)
        # Factor B: Enrichment completeness
        fb = _enrichment_score(it)
        # Factor C: Attribution quality
        fc = _attribution_score(it)
        # Factor D: Corroboration
        fd = _corroboration_score(it)

        raw_score = (fa + fb + fc + fd) / 100.0  # normalize to 0-1

        # Age decay
        age_days = _compute_age_days(it)
        final_score = _apply_age_decay(raw_score, age_days)
        if age_days > 30:
            age_decayed += 1

        # Update confidence field
        old_conf = it.get("confidence", 0)
        it["confidence"] = round(final_score, 2)
        it["iq_score"] = round((fa + fb + fc + fd), 0)  # raw 0-100
        it["iq_breakdown"] = {"source": fa, "enrichment": fb, "attribution": fc, "corroboration": fd}
        it["intelligence_age_days"] = round(age_days, 1)

        # Map ATT&CK T-IDs
        new_ttps, tid_names = _map_attck_techniques(it)
        if new_ttps:
            it["attck_technique_ids"] = new_ttps
            it["attck_techniques"] = tid_names
            ttps_mapped += 1

        score_sum += final_score

    avg_score = score_sum / len(items) if items else 0
    log.info("=" * 60)
    log.info("COMPLETE: avg_confidence=%.2f age_decayed=%d ttps_mapped=%d",
             avg_score, age_decayed, ttps_mapped)
    log.info("=" * 60)

    if not DRY_RUN:
        out = feed if isinstance(feed, list) else {**feed, "advisories": items}
        _atomic_write(FEED_PATH, out)
        log.info("[WRITE] Feed updated")
        _atomic_write(TELEMETRY, {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "items_scored": len(items),
            "avg_confidence": round(avg_score, 3),
            "age_decayed_items": age_decayed,
            "ttps_mapped": ttps_mapped,
        })

    return {"items_scored": len(items), "avg_confidence": round(avg_score, 3)}


if __name__ == "__main__":
    r = run()
    print(f"[DONE] {r}")
