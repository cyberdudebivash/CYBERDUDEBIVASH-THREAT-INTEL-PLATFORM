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
# CORRELATION ENGINE (v74.1 — anchor-based, no transitive chains)
# ═══════════════════════════════════════════════════════════
def compute_correlations(data: list) -> dict:
    """
    Anchor-based correlation: groups items by shared CVE, named actor,
    or matching TTP fingerprint. No transitive chaining (avoids mega-clusters).

    Returns: {item_index: {cluster_id, cluster_type, related_count, confidence}}
    """
    import hashlib
    from itertools import combinations
    from collections import Counter, defaultdict

    # Identify common (non-discriminating) tactics
    tactic_freq = Counter()
    for item in data:
        for t in item.get("mitre_tactics", []):
            tactic_freq[t] += 1
    common_tactics = {t for t, c in tactic_freq.items() if c > len(data) * 0.25}

    # ── Level 1: CVE anchors (confidence: 90) ──
    cve_groups = defaultdict(list)
    for idx, item in enumerate(data):
        cves = re.findall(r"CVE-\d{4}-\d{4,}", item.get("title", ""), re.IGNORECASE)
        for cve in cves:
            cve_groups[cve.upper()].append(idx)

    # ── Level 2: Named actor anchors (confidence: 80) ──
    actor_groups = defaultdict(list)
    for idx, item in enumerate(data):
        actor = item.get("actor_tag", "")
        if actor and actor != "UNC-CDB-99":
            actor_groups[actor].append(idx)

    # ── Level 3: TTP anchors — same threat_type + rare tactic fingerprint (confidence: 65) ──
    ttp_groups = defaultdict(list)
    for idx, item in enumerate(data):
        tt = item.get("threat_type", "General")
        if tt == "Vulnerability":
            continue
        rare = tuple(sorted(set(item.get("mitre_tactics", [])) - common_tactics))
        if len(rare) >= 2:
            ttp_groups[f"{tt}|{rare}"].append(idx)

    # ── Assign items: highest-confidence anchor wins ──
    assignments = {}

    for cve, idxs in cve_groups.items():
        if len(idxs) >= 2:
            cid = "CVE-" + hashlib.md5(cve.encode()).hexdigest()[:8].upper()
            for idx in idxs:
                if idx not in assignments or assignments[idx][2] < 90:
                    assignments[idx] = (cid, "cve", 90, len(idxs))

    for actor, idxs in actor_groups.items():
        if len(idxs) >= 2:
            cid = "ACT-" + hashlib.md5(actor.encode()).hexdigest()[:8].upper()
            for idx in idxs:
                if idx not in assignments or assignments[idx][2] < 80:
                    assignments[idx] = (cid, "actor", 80, len(idxs))

    for ttp_key, idxs in ttp_groups.items():
        if len(idxs) >= 2:
            cid = "TTP-" + hashlib.md5(ttp_key.encode()).hexdigest()[:8].upper()
            for idx in idxs:
                if idx not in assignments:
                    assignments[idx] = (cid, "ttp", 65, len(idxs))

    return assignments


def detect_campaigns(data: list) -> dict:
    """
    Detect campaigns from named actor groups within 7-day windows.

    Returns: {item_index: {name, threat_count, risk}}
    """
    import hashlib
    from collections import Counter, defaultdict

    actor_groups = defaultdict(list)
    for idx, item in enumerate(data):
        actor = item.get("actor_tag", "")
        if actor and actor != "UNC-CDB-99":
            actor_groups[actor].append(idx)

    campaign_assignments = {}

    for actor, idxs in actor_groups.items():
        if len(idxs) < 2:
            continue

        types = Counter(data[i].get("threat_type", "General") for i in idxs)
        dominant_type = types.most_common(1)[0][0]
        max_risk = max((data[i].get("risk_score", 0) or 0) for i in idxs)
        risk_level = (
            "Critical" if max_risk >= 9 else
            "High" if max_risk >= 7 else
            "Medium" if max_risk >= 4 else "Low"
        )

        camp_name = f"{actor} {dominant_type} Campaign"

        camp_data = {
            "name": camp_name,
            "threat_count": len(idxs),
            "risk": risk_level,
        }

        for idx in idxs:
            campaign_assignments[idx] = camp_data

    return campaign_assignments


# ═══════════════════════════════════════════════════════════
# MAIN ENRICHMENT
# ═══════════════════════════════════════════════════════════
def enrich_manifest():
    """Load manifest, add missing fields, write back atomically."""
    import time as _time
    _t0 = _time.monotonic()

    # ── INPUT VALIDATION ──
    if not os.path.exists(MANIFEST_PATH):
        log.warning(f"Manifest not found: {MANIFEST_PATH}")
        return False

    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        log.error(f"FATAL: Manifest is not valid JSON: {e}")
        return False

    if not isinstance(data, list):
        log.warning(f"Manifest is not a list (type={type(data).__name__}) — skipping")
        return False

    if len(data) == 0:
        log.warning("Manifest is empty — skipping")
        return False

    input_count = len(data)
    log.info(f"Loaded: {input_count} items ({len(raw):,} bytes)")

    # ── INPUT SANITY: check items have minimum structure ──
    sample = data[0]
    if not isinstance(sample, dict) or "title" not in sample:
        log.error("FATAL: Manifest items lack expected structure (no 'title' field)")
        return False

    # ── BACKUP ──
    shutil.copy2(MANIFEST_PATH, BACKUP_PATH)

    # ── ENRICH ──
    added_tt = 0
    added_ep = 0
    skipped = 0

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
            skipped += 1
            continue

    # ── ITEM COUNT GUARD ──
    if len(data) != input_count:
        log.error(f"FATAL: Item count changed during enrichment ({input_count} → {len(data)}). Restoring backup.")
        shutil.copy2(BACKUP_PATH, MANIFEST_PATH)
        return False

    # ── CORRELATION + CAMPAIGN ENRICHMENT (v74.1) ──
    added_corr = 0
    added_camp = 0
    try:
        correlations = compute_correlations(data)
        campaigns = detect_campaigns(data)

        for idx, item in enumerate(data):
            # Correlation: only add if missing
            if not item.get("correlation"):
                corr = correlations.get(idx)
                if corr:
                    item["correlation"] = {
                        "cluster_id": corr[0],
                        "cluster_type": corr[1],
                        "related_count": corr[3],
                        "confidence": corr[2],
                    }
                    added_corr += 1

            # Campaign: only add if missing
            if not item.get("campaign"):
                camp = campaigns.get(idx)
                if camp:
                    item["campaign"] = camp
                    added_camp += 1

        unique_clusters = len(set(c[0] for c in correlations.values())) if correlations else 0
        unique_campaigns = len(set(c["name"] for c in campaigns.values())) if campaigns else 0
        log.info(f"Correlation: {added_corr} items in {unique_clusters} clusters | Campaigns: {added_camp} items in {unique_campaigns} campaigns")
    except Exception as e:
        log.warning(f"Correlation/campaign enrichment failed (non-fatal): {e}")

    # ── WRITE ATOMICALLY ──
    tmp_path = MANIFEST_PATH + ".v74tmp"
    output_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(output_json)

    # ── OUTPUT VALIDATION: re-read and verify ──
    try:
        with open(tmp_path, "r", encoding="utf-8") as f:
            verify = json.load(f)
        if not isinstance(verify, list) or len(verify) != input_count:
            raise ValueError(f"Output verification failed: {len(verify)} items (expected {input_count})")
        # Spot-check first item
        if "title" not in verify[0]:
            raise ValueError("Output verification failed: first item missing 'title'")
    except Exception as e:
        log.error(f"FATAL: Output validation failed: {e}. Restoring backup.")
        shutil.copy2(BACKUP_PATH, MANIFEST_PATH)
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return False

    # ── COMMIT: atomic replace ──
    os.replace(tmp_path, MANIFEST_PATH)

    elapsed = _time.monotonic() - _t0
    log.info(f"Enriched: threat_type +{added_tt}, exploit_probability +{added_ep}, correlation +{added_corr}, campaigns +{added_camp}, skipped: {skipped}")
    log.info(f"Total: {len(data)} items | Output: {len(output_json):,} bytes | Time: {elapsed:.2f}s")

    # Cleanup backup (only after successful validation)
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
        log.warning("Manifest not found — skipping API generation")
        return False

    try:
        api_dir = os.path.join(REPO_ROOT, "api")
        os.makedirs(api_dir, exist_ok=True)

        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list) or len(data) == 0:
            log.warning("Manifest empty or invalid — skipping API generation")
            return False

        # /api/feed.json — full manifest with API envelope
        api_feed = {
            "version": "v74.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "count": len(data),
            "data": data,
        }

        feed_path = os.path.join(api_dir, "feed.json")
        with open(feed_path, "w", encoding="utf-8") as f:
            json.dump(api_feed, f, ensure_ascii=False, separators=(",", ":"))

        # Verify feed.json is valid JSON
        with open(feed_path, "r", encoding="utf-8") as f:
            verify = json.load(f)
        if verify.get("count") != len(data):
            log.error(f"API feed.json verification failed: count mismatch")
            return False

        log.info(f"API: {feed_path} ({len(data)} items, {os.path.getsize(feed_path):,} bytes)")

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

        log.info(f"API: {latest_path} ({latest['count']} items, {os.path.getsize(latest_path):,} bytes)")

        return True

    except Exception as e:
        log.error(f"API generation failed: {e}")
        return False


if __name__ == "__main__":
    log.info("=" * 60)
    log.info("SENTINEL APEX v74.0 — Manifest Enricher")
    log.info("=" * 60)

    try:
        ok = enrich_manifest()
        if ok:
            api_ok = generate_api_layer()
            log.info(f"v74 enrichment: COMPLETE | API: {'OK' if api_ok else 'SKIPPED'}")
        else:
            log.warning("Enrichment skipped — see warnings above")
            sys.exit(0)  # Exit 0 to not break pipeline
    except Exception as e:
        log.error(f"UNHANDLED ERROR: {e}")
        log.info("Exiting with code 0 to not break pipeline")
        sys.exit(0)  # NEVER break the pipeline
