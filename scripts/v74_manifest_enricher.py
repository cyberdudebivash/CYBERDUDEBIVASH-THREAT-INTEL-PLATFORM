#!/usr/bin/env python3
"""
v74_manifest_enricher.py — SENTINEL APEX v74.0 Post-Pipeline Enricher
=====================================================================
SAFE: Runs AFTER manifest generation. Only ADDS fields. Never removes.
ADDITIVE: If a field already exists and is non-empty, it is preserved.
FALLBACK: If enrichment fails for any item, that item is left unchanged.
ZERO-REGRESSION: Writes back to the same file. If the whole script fails,
                 the manifest is untouched (atomic write with backup).

Adds:
  - threat_type: str  ("Vulnerability", "Ransomware", "APT", "Malware",
                        "Phishing", "Data Breach", "Supply Chain", "General")
  - exploit_probability: str  ("Critical", "High", "Medium", "Low")

Run: python3 scripts/v74_manifest_enricher.py
"""

import json
import os
import re
import shutil
import sys
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [v74-ENRICHER] %(message)s")
log = logging.getLogger("v74")

# ═══════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(REPO_ROOT, "data", "stix", "feed_manifest.json")
BACKUP_PATH = MANIFEST_PATH + ".v74bak"


# ═══════════════════════════════════════════════════════════
# THREAT TYPE CLASSIFIER (keyword-based, zero dependencies)
# ═══════════════════════════════════════════════════════════
def classify_threat_type(title: str, mitre_tactics: list = None) -> str:
    """Classify threat type from title + MITRE tactics."""
    text = (title or "").lower()
    tactics = set(mitre_tactics or [])

    # CVE Lock — any CVE present = Vulnerability
    if re.search(r'cve-\d{4}-\d{4,}', text):
        return "Vulnerability"

    # Ransomware
    if any(k in text for k in [
        "ransomware", "ransom", "encrypted for impact", "data encrypted",
        "lockbit", "blackcat", "alphv", "clop", "conti", "ryuk", "akira",
        "rhysida", "play ransomware", "medusa ransomware", "blackbasta",
    ]):
        return "Ransomware"

    # APT / State-sponsored
    if any(k in text for k in [
        "apt", "lazarus", "sandworm", "fancy bear", "cozy bear", "turla",
        "kimsuky", "charming kitten", "mustang panda", "salt typhoon",
        "volt typhoon", "state-sponsored", "nation-state", "espionage",
        "sidewinder", "gamaredon", "nobelium", "hafnium",
    ]):
        return "APT"

    # Phishing
    if any(k in text for k in [
        "phishing", "spear-phishing", "credential harvest", "fake login",
        "social engineering", "business email compromise", "bec",
    ]):
        return "Phishing"

    # Supply Chain
    if any(k in text for k in [
        "supply chain", "dependency confusion", "typosquatting",
        "backdoored package", "npm malware", "pypi malware",
        "compromised update", "software supply",
    ]):
        return "Supply Chain"

    # Data Breach
    if any(k in text for k in [
        "breach", "data leak", "exposed database", "stolen data",
        "records leaked", "customer data", "data dump", "hackers leak",
    ]):
        return "Data Breach"

    # Malware (generic)
    if any(k in text for k in [
        "malware", "trojan", "botnet", "backdoor", "infostealer",
        "stealer", "rat ", "remote access", "worm", "rootkit",
        "keylogger", "cryptominer", "loader", "dropper",
    ]):
        return "Malware"

    # MITRE tactic-based fallback
    impact_tactics = {"T1486", "T1490", "T1561", "T1489"}
    if tactics & impact_tactics:
        return "Ransomware"

    exfil_tactics = {"T1041", "T1048", "T1567"}
    if tactics & exfil_tactics:
        return "Data Breach"

    phish_tactics = {"T1566"}
    if tactics & phish_tactics:
        return "Phishing"

    exec_tactics = {"T1059", "T1053", "T1203"}
    if tactics & exec_tactics:
        return "Malware"

    return "General"


# ═══════════════════════════════════════════════════════════
# EXPLOIT PROBABILITY CALCULATOR
# ═══════════════════════════════════════════════════════════
def calculate_exploit_probability(
    risk_score: float = 0,
    kev_present: bool = False,
    epss_score: float = None,
    cvss_score: float = None,
    title: str = "",
) -> str:
    """Calculate exploit probability tier from available signals."""
    text = (title or "").lower()

    # CISA KEV = confirmed exploitation
    if kev_present:
        return "Critical"

    # Active exploitation keywords
    if any(k in text for k in [
        "actively exploited", "in the wild", "zero-day", "0-day",
        "proof of concept", "poc released", "exploit available",
        "under attack", "exploitation detected",
    ]):
        return "Critical"

    # EPSS-based
    if epss_score is not None:
        if epss_score >= 0.5:
            return "Critical"
        if epss_score >= 0.15:
            return "High"
        if epss_score >= 0.05:
            return "Medium"

    # CVSS-based
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "High"
        if cvss_score >= 7.0:
            return "Medium"

    # Risk score fallback
    if risk_score >= 9:
        return "High"
    if risk_score >= 7:
        return "Medium"

    return "Low"


# ═══════════════════════════════════════════════════════════
# MAIN ENRICHMENT
# ═══════════════════════════════════════════════════════════
def enrich_manifest():
    """Load manifest, add missing fields, write back atomically."""
    if not os.path.exists(MANIFEST_PATH):
        log.warning(f"Manifest not found: {MANIFEST_PATH}")
        return False

    # Read
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        log.warning("Manifest is not a list — skipping")
        return False

    log.info(f"Loaded: {len(data)} items")

    # Backup
    shutil.copy2(MANIFEST_PATH, BACKUP_PATH)

    # Enrich
    added_tt = 0
    added_ep = 0

    for item in data:
        try:
            # threat_type: only add if missing or empty
            if not item.get("threat_type"):
                item["threat_type"] = classify_threat_type(
                    title=item.get("title", ""),
                    mitre_tactics=item.get("mitre_tactics", []),
                )
                added_tt += 1

            # exploit_probability: only add if missing or empty
            if not item.get("exploit_probability"):
                item["exploit_probability"] = calculate_exploit_probability(
                    risk_score=float(item.get("risk_score", 0) or 0),
                    kev_present=bool(item.get("kev_present")),
                    epss_score=float(item["epss_score"]) if item.get("epss_score") is not None else None,
                    cvss_score=float(item["cvss_score"]) if item.get("cvss_score") is not None else None,
                    title=item.get("title", ""),
                )
                added_ep += 1

        except Exception as e:
            # FAILSAFE: Skip item, don't crash
            log.warning(f"Skipping item: {e}")
            continue

    # Write atomically (write to temp, then rename)
    tmp_path = MANIFEST_PATH + ".v74tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))

    os.replace(tmp_path, MANIFEST_PATH)

    log.info(f"Enriched: threat_type +{added_tt}, exploit_probability +{added_ep}")
    log.info(f"Total: {len(data)} items | Backup: {BACKUP_PATH}")

    # Cleanup backup
    try:
        os.remove(BACKUP_PATH)
    except Exception:
        pass

    return True


# ═══════════════════════════════════════════════════════════
# API LAYER: Generate static /api/feed.json
# ═══════════════════════════════════════════════════════════
def generate_api_layer():
    """Create /api/feed.json from manifest (static file, zero backend)."""
    if not os.path.exists(MANIFEST_PATH):
        return False

    api_dir = os.path.join(REPO_ROOT, "api")
    os.makedirs(api_dir, exist_ok=True)

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # /api/feed.json — full manifest with CORS-friendly wrapper
    api_feed = {
        "version": "v74.0",
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(data),
        "data": data,
    }

    feed_path = os.path.join(api_dir, "feed.json")
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(api_feed, f, ensure_ascii=False, separators=(",", ":"))

    log.info(f"API: {feed_path} ({len(data)} items)")

    # /api/latest.json — last 20 items
    latest = {
        "version": "v74.0",
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": min(20, len(data)),
        "data": data[:20],
    }

    latest_path = os.path.join(api_dir, "latest.json")
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(latest, f, ensure_ascii=False, separators=(",", ":"))

    log.info(f"API: {latest_path} ({latest['count']} items)")

    return True


if __name__ == "__main__":
    log.info("=" * 60)
    log.info("SENTINEL APEX v74.0 — Manifest Enricher")
    log.info("=" * 60)

    ok = enrich_manifest()
    if ok:
        generate_api_layer()
        log.info("v74 enrichment complete ✓")
    else:
        log.warning("Enrichment skipped — manifest issue")
        sys.exit(0)  # Exit 0 to not break pipeline
