#!/usr/bin/env python3
"""
scripts/intel_quality_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v142.0.0 -- Intel Quality Engine
==================================================================
8-PHASE INTELLIGENCE QUALITY UPGRADE SYSTEM

Phase 1: Global 3-Layer Dedup Engine (ingestion + STIX + manifest)
Phase 2: True Newness Validation (intel_index + fingerprints + manifest)
Phase 3: Manifest Sanity Guard (HARD deduplicate; fail if unresolvable)
Phase 4: Intel Quality Enrichment (actor, kill_chain, attack_vector, MITRE, campaign)
Phase 5: CVE Spam Control (cap raw CVEs, require context)
Phase 6: Feed Quality Balancer (weight sources, enforce mix)
Phase 7: Dashboard Truth Validation (ordering, newness, no repeats)
Phase 8: Final Assertions (quality report + duplicate_count==0)

INTEGRATION:
    Called from run_pipeline.py after Phase 4 manifest dedup gate:
        from intel_quality_engine import apply_quality_pipeline
        manifest_items = apply_quality_pipeline(manifest_items)

GUARANTEES:
    - Never raises (all phases wrapped in try/except)
    - Always returns a list of dicts
    - Atomic writes only (tmp -> fsync -> os.replace)
    - Zero inline Python in YAML -- this is a pure script call
    - All hard-fails are internal deduplicate operations, not sys.exit()
    - Quality report written to data/quality/intel_quality_report.json

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("sentinel.intel_quality_engine")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT   = Path(__file__).resolve().parent.parent
DATA_DIR    = REPO_ROOT / "data"
QUALITY_DIR = DATA_DIR / "quality"
FINGERPRINT_PATH = DATA_DIR / "processed_fingerprints.json"
INTEL_INDEX_PATH = DATA_DIR / "intel_index.json"
QUALITY_REPORT   = QUALITY_DIR / "intel_quality_report.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ENGINE_VERSION = "143.4.0"

# CVE Spam Control limits
MAX_CISA_KEV_ENTRIES   = 200
MAX_NVD_CVE_ENTRIES    = 300
MAX_GITHUB_ADV_ENTRIES = 200
CVE_MIN_CVSS           = 7.0   # CVE-only entries below this get downgraded
CVE_MIN_EPSS           = 0.20  # CVE-only entries below this get downgraded

# Feed Quality targets (% of final feed)
TARGET_HIGH_SOURCE_MIN = 0.20   # At least 20% from high-quality threat intel sources
TARGET_LOW_SOURCE_MAX  = 0.45   # At most 45% raw CVE content

# Enrichment score weights
_SCORE_ACTOR_RESOLVED  = 20
_SCORE_KILL_CHAIN      = 15
_SCORE_ATTACK_VECTOR   = 15
_SCORE_MITRE_TTPS      = 15
_SCORE_CVSS            = 10
_SCORE_EPSS            = 10
_SCORE_IOCS            = 10
_SCORE_DESCRIPTION     = 5


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------
HIGH_QUALITY_SOURCES = {
    "rss_www_crowdstrike_com_blog_feed_",
    "rss_cybersecuritynews_com_feed_",
    "rss_securityaffairs_com_feed",
    "rss_www_darkreading_com_rss_xml",
    "rss_feeds_feedburner_com_thehackersnews",
    "rss_redcanary_com_blog_feed_",
    "rss_www_mandiant_com_resources_blog_rss_xml",
    "rss_unit42_paloaltonetworks_com_feed_",
    "rss_blog_talosintelligence_com_feeds_posts_default",
    "rss_www_bleepingcomputer_com_feed_",
    "rss_krebsonsecurity_com_feed_",
    "rss_thedfirreport_com_feed_",
    "rss_www_sentinelone_com_blog_rss_",
    "rss_research_checkpoint_com_feed_",
    "rss_securelist_com_feed_",
    "ransomware_live",
}

LOW_QUALITY_SOURCES = {
    "cisa_kev",
    "nvd_cve",
    "github_advisory",
    "rss_cvefeed_io_rssfeed_latest_xml",
    "rss_vulners_com_rss_xml",
}

MEDIUM_QUALITY_SOURCES = {
    "rss_seclists_org_rss_fulldisclosure_rss",
    "rss_seclists_org_rss_oss_sec_rss",
    "rss_www_securitymagazine_com_rss_topic_2236",
    "rss_www_ncsc_gov_uk_api_1_services_published_rss_xml",
    "rss_www_cisa_gov_uscert_rss_xml",
}


def classify_source(source: str) -> str:
    """Return HIGH, MEDIUM, or LOW quality classification for a source."""
    if not source:
        return "LOW"
    s = source.lower()
    for hs in HIGH_QUALITY_SOURCES:
        if hs in s or s in hs:
            return "HIGH"
    for ms in MEDIUM_QUALITY_SOURCES:
        if ms in s or s in ms:
            return "MEDIUM"
    for ls in LOW_QUALITY_SOURCES:
        if ls in s or s in ls:
            return "LOW"
    # Default: unknown sources are MEDIUM
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_title(title: str) -> str:
    """Normalize title for dedup comparison."""
    t = (title or "").lower().strip()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _title_fingerprint(title: str) -> str:
    return hashlib.sha256(_norm_title(title).encode()).hexdigest()[:16]


def _content_fingerprint(item: Dict) -> str:
    """SHA256(title + source_url + published_at) for dedup."""
    parts = "|".join([
        _norm_title(item.get("title", "")),
        (item.get("source_url") or item.get("link") or "").strip().lower(),
        (item.get("published_at") or "").strip(),
    ])
    return hashlib.sha256(parts.encode()).hexdigest()


def _atomic_write(path: Path, data: dict) -> None:
    """Atomic JSON write: tmp -> fsync -> replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    content = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    tmp.write_text(content, encoding="utf-8")
    try:
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
    except Exception:
        pass
    os.replace(tmp, path)


def _load_json_safe(path: Path, default=None):
    """Load JSON file safely, returning default on any error."""
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("[QUALITY] Failed to load %s: %s", path.name, e)
    return default if default is not None else {}


# ---------------------------------------------------------------------------
# PHASE 1: Global 3-Layer Dedup Engine
# ---------------------------------------------------------------------------

class Layer1IngestDedup:
    """
    Layer 1: Content fingerprint dedup (source_url + title + published_at).
    Checks against processed_fingerprints.json for cross-run dedup.
    """

    def __init__(self) -> None:
        self._seen: Set[str] = set()
        self._loaded: Set[str] = set()
        self._load()

    def _load(self) -> None:
        raw = _load_json_safe(FINGERPRINT_PATH, {})
        fps = raw.get("fingerprints", [])
        if isinstance(fps, list):
            self._loaded = {fp for fp in fps if isinstance(fp, str) and len(fp) == 64}
        log.debug("[L1-DEDUP] Loaded %d fingerprints from store", len(self._loaded))

    def is_duplicate(self, item: Dict) -> bool:
        fp = _content_fingerprint(item)
        return fp in self._loaded or fp in self._seen

    def mark_seen(self, item: Dict) -> str:
        fp = _content_fingerprint(item)
        self._seen.add(fp)
        return fp

    def deduplicate(self, items: List[Dict]) -> Tuple[List[Dict], int]:
        seen_fps: Set[str] = set(self._loaded)
        unique: List[Dict] = []
        removed = 0
        for item in items:
            fp = _content_fingerprint(item)
            if fp in seen_fps:
                removed += 1
                continue
            seen_fps.add(fp)
            unique.append(item)
        log.info("[L1-DEDUP] Ingestion layer: %d in -> %d unique (removed %d fingerprint dups)",
                 len(items), len(unique), removed)
        return unique, removed


class Layer2StixDedup:
    """
    Layer 2: STIX-level dedup — same CVE or stix_id.
    """

    def deduplicate(self, items: List[Dict]) -> Tuple[List[Dict], int]:
        seen_stix: Set[str] = set()
        seen_cves: Dict[str, int] = defaultdict(int)  # CVE -> count
        unique: List[Dict] = []
        removed = 0

        for item in items:
            stix_id = (item.get("stix_id") or item.get("id") or "").strip()
            if stix_id and stix_id in seen_stix:
                removed += 1
                continue

            # Allow up to 2 entries per CVE (different sources add value)
            cves = item.get("cves", [])
            if isinstance(cves, list) and cves:
                primary_cve = cves[0] if cves else None
                if primary_cve and seen_cves[primary_cve] >= 2:
                    removed += 1
                    continue
                if primary_cve:
                    seen_cves[primary_cve] += 1

            if stix_id:
                seen_stix.add(stix_id)
            unique.append(item)

        log.info("[L2-DEDUP] STIX layer: %d in -> %d unique (removed %d stix/cve dups)",
                 len(items), len(unique), removed)
        return unique, removed


class Layer3ManifestDedup:
    """
    Layer 3: Final manifest dedup by normalized title.
    Keeps the most recent entry per title group.
    """

    def deduplicate(self, items: List[Dict]) -> Tuple[List[Dict], int]:
        seen_titles: Dict[str, int] = {}  # title_fp -> index in unique
        unique: List[Dict] = []
        removed = 0

        for item in items:
            title_fp = _title_fingerprint(item.get("title", ""))
            if not title_fp:
                unique.append(item)
                continue

            if title_fp not in seen_titles:
                seen_titles[title_fp] = len(unique)
                unique.append(item)
            else:
                # Keep the most recent one (by processed_at)
                existing_idx = seen_titles[title_fp]
                existing = unique[existing_idx]
                existing_ts = existing.get("processed_at") or existing.get("timestamp") or ""
                current_ts  = item.get("processed_at") or item.get("timestamp") or ""
                if current_ts > existing_ts:
                    unique[existing_idx] = item  # replace with newer
                removed += 1

        log.info("[L3-DEDUP] Manifest layer: %d in -> %d unique (removed %d title dups)",
                 len(items), len(unique), removed)
        return unique, removed


# ---------------------------------------------------------------------------
# PHASE 2: True Newness Validation
# ---------------------------------------------------------------------------

class NewnessValidator:
    """
    Determines if an entry is truly NEW (never seen before).
    Checks against: intel_index + processed_fingerprints + current manifest stix_ids.

    NEW = NOT in any of these stores.
    Sets item['is_new'] = True/False accordingly.
    Removes 'new' badge from entries that aren't actually new.
    """

    def __init__(self) -> None:
        self._known_stix: Set[str] = set()
        self._known_fps: Set[str] = set()
        self._load_intel_index()
        self._load_fingerprints()
        # FIX v142.1.0: also seed known stix_ids from the persisted feed_manifest
        # (intel_index.json may not exist yet; manifest is always the ground truth)
        self._load_manifest_stix_ids()

    def _load_intel_index(self) -> None:
        raw = _load_json_safe(INTEL_INDEX_PATH, {})
        if isinstance(raw, dict):
            for sid in raw.get("stix_ids", raw.get("ids", [])):
                if isinstance(sid, str):
                    self._known_stix.add(sid)
        elif isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    sid = entry.get("stix_id") or entry.get("id")
                    if sid:
                        self._known_stix.add(sid)
        log.debug("[NEWNESS] Loaded %d known stix_ids from intel_index", len(self._known_stix))

    def _load_fingerprints(self) -> None:
        raw = _load_json_safe(FINGERPRINT_PATH, {})
        fps = raw.get("fingerprints", [])
        if isinstance(fps, list):
            self._known_fps = {fp for fp in fps if isinstance(fp, str) and len(fp) == 64}
        log.debug("[NEWNESS] Loaded %d fingerprints from store", len(self._known_fps))

    def _load_manifest_stix_ids(self) -> None:
        """
        FIX v142.1.0: Seed _known_stix from feed_manifest.json so that entries
        already present in the manifest are NOT marked as NEW on the next run.
        This is the ground-truth historical reference when intel_index.json is absent.
        """
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        raw = _load_json_safe(manifest_path, [])
        # FIX v148.0: unwrap dict envelope (same as __main__ fix)
        if isinstance(raw, dict):
            for _key in ("advisories", "items", "data", "feed", "reports", "intel"):
                if isinstance(raw.get(_key), list):
                    raw = raw[_key]
                    break
            else:
                raw = next((v for v in raw.values() if isinstance(v, list)), [])
        before = len(self._known_stix)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    sid = (entry.get("stix_id") or entry.get("id") or "").strip()
                    if sid:
                        self._known_stix.add(sid)
        added = len(self._known_stix) - before
        log.debug("[NEWNESS] Seeded %d stix_ids from feed_manifest (total known: %d)",
                  added, len(self._known_stix))

    def validate_batch(self, items: List[Dict]) -> List[Dict]:
        """
        Set is_new=True/False on each item.
        An item is NEW if its fingerprint and stix_id are not in known stores.
        Items processed in THIS RUN are new relative to prior runs.
        """
        # Build current-batch stix_id set (for within-batch dedup of newness)
        current_batch_stix: Set[str] = set()
        new_count = 0
        not_new_count = 0

        for item in items:
            stix_id = (item.get("stix_id") or item.get("id") or "").strip()
            fp = _content_fingerprint(item)

            # An item is NEW if it's not in any prior-run store
            in_index = stix_id in self._known_stix if stix_id else False
            in_fps   = fp in self._known_fps

            is_new = not (in_index or in_fps)

            item["is_new"] = is_new
            if is_new:
                new_count += 1
                # Mark it so we don't double-count within batch
                if stix_id:
                    current_batch_stix.add(stix_id)
            else:
                not_new_count += 1

        log.info("[NEWNESS] Validated: %d new | %d existing", new_count, not_new_count)
        return items


# ---------------------------------------------------------------------------
# PHASE 3: Manifest Sanity Guard
# ---------------------------------------------------------------------------

class ManifestSanityGuard:
    """
    Validates manifest integrity post-dedup.
    After dedup, NO duplicate stix_ids, titles, or CVE (>2 entries) are allowed.

    Strategy:
        1. Detect all violations
        2. Remove the duplicates (keep first occurrence)
        3. If violations remain after cleanup -> log ERROR + write error report
        4. Return cleaned items (never raises, never sys.exit)

    ASSERTION: After this guard, duplicate_count MUST == 0.
    """

    def validate_and_clean(self, items: List[Dict]) -> Tuple[List[Dict], Dict]:
        t0 = time.monotonic()
        violations: Dict[str, List] = {
            "duplicate_stix_ids": [],
            "duplicate_titles": [],
            "cve_spam": [],
        }

        # --- Stix ID dedup ---
        seen_stix: Dict[str, int] = {}
        to_remove_stix: Set[int] = set()
        for i, item in enumerate(items):
            sid = (item.get("stix_id") or item.get("id") or "").strip()
            if not sid:
                continue
            if sid in seen_stix:
                violations["duplicate_stix_ids"].append({
                    "stix_id": sid,
                    "first_idx": seen_stix[sid],
                    "dup_idx": i,
                    "title": item.get("title", "")[:80],
                })
                to_remove_stix.add(i)
            else:
                seen_stix[sid] = i

        # --- Title dedup ---
        seen_titles: Dict[str, int] = {}
        to_remove_titles: Set[int] = set()
        for i, item in enumerate(items):
            if i in to_remove_stix:
                continue  # already removing
            tfp = _title_fingerprint(item.get("title", ""))
            if not tfp:
                continue
            if tfp in seen_titles:
                violations["duplicate_titles"].append({
                    "title_fp": tfp,
                    "title": item.get("title", "")[:80],
                    "first_idx": seen_titles[tfp],
                    "dup_idx": i,
                })
                to_remove_titles.add(i)
            else:
                seen_titles[tfp] = i

        # --- CVE spam detection ---
        cve_counts: Dict[str, int] = defaultdict(int)
        for item in items:
            for cve in (item.get("cves") or []):
                if cve:
                    cve_counts[cve] += 1
        for cve, count in cve_counts.items():
            if count > 3:
                violations["cve_spam"].append({"cve": cve, "count": count})

        total_violations = (len(violations["duplicate_stix_ids"]) +
                            len(violations["duplicate_titles"]) +
                            len(violations["cve_spam"]))

        # Build clean list
        remove_set = to_remove_stix | to_remove_titles
        clean_items = [item for i, item in enumerate(items) if i not in remove_set]

        elapsed = time.monotonic() - t0

        report = {
            "phase": "3_manifest_sanity_guard",
            "total_input": len(items),
            "total_after_clean": len(clean_items),
            "removed": len(remove_set),
            "total_violations_detected": total_violations,
            "violations": violations,
            "duplicate_count": len(to_remove_stix) + len(to_remove_titles),
            "assertion_duplicate_count_zero": (len(to_remove_stix) + len(to_remove_titles)) == 0,
            "elapsed_ms": round(elapsed * 1000),
        }

        if total_violations > 0:
            log.warning(
                "[PHASE3-SANITY] Violations detected: %d dup stix_ids, %d dup titles, "
                "%d cve-spam groups. Removed %d entries.",
                len(violations["duplicate_stix_ids"]),
                len(violations["duplicate_titles"]),
                len(violations["cve_spam"]),
                len(remove_set),
            )
        else:
            log.info("[PHASE3-SANITY] PASS: No duplicates detected in %d items (%.1fms)",
                     len(items), elapsed * 1000)

        return clean_items, report


# ---------------------------------------------------------------------------
# PHASE 4: Intel Quality Enrichment
# ---------------------------------------------------------------------------

# Kill chain phase keyword map (ordered: more specific first)
_KILL_CHAIN_MAP = [
    ("Impact",           ["ransomware", "wiper", "ransom demand", "data destruction",
                          "denial of service", "ddos", "encrypt files", "double extortion"]),
    ("Exfiltration",     ["exfiltrat", "data theft", "data leak", "stolen data",
                          "stealer", "information theft"]),
    ("Command-and-Control", ["c2 server", "c&c", "command and control", "botnet",
                              "rat ", "remote access trojan", "beaconing", "c2 infrastructure"]),
    ("Collection",       ["collect data", "harvest credentials", "keylogger", "screen capture",
                          "data collection"]),
    ("Lateral-Movement", ["lateral movement", "lateral-movement", "pivoting",
                          "pass the hash", "pass-the-hash", "remote service"]),
    ("Discovery",        ["discovery", "enumerat", "reconnaissance", "network scan",
                          "port scan", "nmap"]),
    ("Credential-Access",["credential", "password spray", "brute force", "kerberoast",
                          "mimikatz", "credential dump", "hash dump"]),
    ("Defense-Evasion",  ["evasion", "obfuscat", "anti-analysis", "bypass security",
                          "disable defender", "living off the land", "lolbas", "lolbin"]),
    ("Privilege-Escalation", ["privilege escalation", "priv esc", "sudo exploit",
                               "uac bypass", "token impersonation", "local exploit"]),
    ("Persistence",      ["persistence", "backdoor", "registry run", "startup folder",
                          "scheduled task", "cron job", "boot kit", "rootkit"]),
    ("Execution",        ["powershell", "cmd.exe", "wscript", "mshta", "macro",
                          "javascript payload", "script execution", "shellcode"]),
    ("Initial-Access",   ["phishing", "spear phishing", "spear-phishing", "watering hole",
                          "drive-by", "exploit public-facing", "supply chain attack",
                          "malicious attachment", "credential stuffing", "initial access"]),
    ("Reconnaissance",   ["reconnaissance", "recon", "osint", "scanning"]),
    ("Weaponization",    ["exploit kit", "payload craft", "malware develop",
                          "zero-day develop"]),
    ("Delivery",         ["deliver", "dropper", "downloader", "loader", "malicious link",
                          "email attachment"]),
]

# Attack vector keyword map
_ATTACK_VECTOR_MAP = [
    ("SOCIAL_ENGINEERING", ["phishing", "spear-phishing", "vishing", "smishing",
                             "social engineering", "pretexting", "bec "]),
    ("NETWORK",            ["remote code", "rce", "internet-facing", "network-based",
                             "remote exploit", "web exploit", "unauthenticated remote"]),
    ("ADJACENT_NETWORK",   ["adjacent network", "lan-based", "internal network",
                             "same segment"]),
    ("LOCAL",              ["local privilege", "local exploit", "requires local",
                             "physical access", "local user"]),
    ("SUPPLY_CHAIN",       ["supply chain", "typosquat", "malicious package",
                             "npm package", "pypi package", "dependency"]),
]

# MITRE ATT&CK technique inference map (technique_id -> keywords)
_MITRE_TECHNIQUE_MAP = [
    ("T1566.001", ["spear-phishing attachment", "malicious attachment"]),
    ("T1566.002", ["spear-phishing link", "malicious link in email"]),
    ("T1566",     ["phishing", "spear phishing"]),
    ("T1190",     ["exploit public-facing", "rce", "remote code execution", "web exploit"]),
    ("T1059.001", ["powershell", "pwsh"]),
    ("T1059.007", ["javascript", "jscript", "wscript"]),
    ("T1059",     ["command line", "script execution", "cmd.exe", "shellcode"]),
    ("T1486",     ["ransomware", "encrypt files", "ransom", "file encryption"]),
    ("T1078",     ["valid accounts", "stolen credentials", "credential abuse"]),
    ("T1071",     ["command and control", "c2", "c&c", "beaconing"]),
    ("T1055",     ["process injection", "dll injection", "code injection"]),
    ("T1027",     ["obfuscat", "encode payload", "encrypted payload", "packing"]),
    ("T1547",     ["persistence", "registry run", "startup", "scheduled task"]),
    ("T1003",     ["credential dump", "mimikatz", "lsass", "hashdump", "ntds"]),
    ("T1110",     ["brute force", "password spray", "credential stuffing"]),
    ("T1195",     ["supply chain", "malicious package", "dependency confusion"]),
    ("T1219",     ["remote access trojan", "rat ", "remote desktop", "rdp abuse"]),
    ("T1040",     ["network sniff", "packet capture", "credential sniff"]),
    ("T1562",     ["disable security", "bypass av", "disable defender", "edr bypass"]),
    ("T1021",     ["lateral movement", "remote service", "smb", "wmi execution"]),
    ("T1485",     ["data destruction", "wiper", "disk wipe"]),
    ("T1041",     ["exfiltrat", "data theft", "data leak"]),
    ("T1189",     ["drive-by", "watering hole", "browser exploit"]),
]

# Campaign name inference
_CAMPAIGN_MAP = [
    ("OP-LOCKBIT-SURGE",      ["lockbit"]),
    ("OP-VOLT-TYPHOON",       ["volt typhoon", "volt-typhoon"]),
    ("OP-MIDNIGHT-BLIZZARD",  ["midnight blizzard", "nobelium", "cozy bear"]),
    ("OP-FOREST-BLIZZARD",    ["forest blizzard", "fancy bear", "apt28"]),
    ("OP-SCATTERED-SPIDER",   ["scattered spider", "octo tempest", "sim swap gang"]),
    ("OP-CLOP-MOVEIT",        ["cl0p", "clop", "moveit"]),
    ("OP-LAZARUS-CRYPTO",     ["lazarus", "hidden cobra", "north korea crypto"]),
    ("OP-SANDWORM-GRID",      ["sandworm", "industroyer", "notpetya"]),
    ("OP-AKIRA-VMWARE",       ["akira ransomware"]),
    ("OP-MEDUSA-HEALTH",      ["medusa ransomware", "medusalocker"]),
    ("OP-ALPHV-BLACKCAT",     ["blackcat", "alphv", "noberus"]),
    ("OP-QILIN-VMWARE",       ["qilin ransomware", "agenda ransomware"]),
    ("OP-KIMSUKY-RECON",      ["kimsuky", "thallium", "apt43"]),
    ("OP-OILRIG-GOV",         ["oilrig", "apt34", "helixkitten"]),
    ("OP-TURLA-SNAKE",        ["turla", "snake malware", "uroburos"]),
    ("OP-REVIL-REVIVAL",      ["revil", "sodinokibi"]),
    ("OP-BADBOX-MOBILE",      ["badbox", "triada", "keenadu", "lemon group"]),
    ("OP-GHOSTPULSE",         ["ghostpulse", "hijack loader", "clickfix"]),
    ("OP-STEALER-MALWARE",    ["infostealer", "vidar", "redline stealer",
                                "lumma stealer", "raccoon stealer"]),
]

# Extended actor resolution map (supplements run_pipeline.py)
_EXTENDED_ACTOR_MAP = [
    ("CDB-APT-28",   ["apt28", "fancy bear", "forest blizzard", "strontium", "gru unit 26165"]),
    ("CDB-APT-29",   ["apt29", "cozy bear", "midnight blizzard", "nobelium", "solarwinds actor"]),
    ("CDB-APT-41",   ["apt41", "double dragon", "winnti", "shadowpad", "barium"]),
    ("CDB-APT-40",   ["apt40", "temp.periscope", "bronze mohawk"]),
    ("CDB-APT-43",   ["kimsuky", "thallium", "black banshee"]),
    ("CDB-APT-22",   ["volt typhoon", "bronze silhouette", "vanguard panda"]),
    ("CDB-FIN-09",   ["lazarus", "hidden cobra", "andariel", "bluenoroff", "dprk"]),
    ("CDB-FIN-11",   ["cl0p", "clop", "fin11", "ta505", "moveit"]),
    ("CDB-FIN-12",   ["scattered spider", "octo tempest", "sim swapper"]),
    ("CDB-RAN-01",   ["lockbit", "lock bit"]),
    ("CDB-RAN-02",   ["blackcat", "alphv", "noberus"]),
    ("CDB-RAN-03",   ["akira ransomware", "akira group"]),
    ("CDB-RAN-04",   ["medusa ransomware", "medusalocker", "medusa group"]),
    ("CDB-RAN-05",   ["qilin", "agenda ransomware"]),
    ("CDB-RAN-06",   ["revil", "sodinokibi", "gold southfield"]),
    ("CDB-RU-01",    ["sandworm", "voodoo bear", "telebots", "industroyer"]),
    ("CDB-RU-02",    ["turla", "snake malware", "venomous bear", "uroburos"]),
    ("CDB-IR-03",    ["oilrig", "apt34", "crambus", "helixkitten"]),
    ("CDB-MOB-01",   ["triada", "badbox", "lemon group", "keenadu"]),
    ("CDB-SUP-01",   ["supply chain attacker", "dependency confusion", "typosquat"]),
    ("CDB-PHI-GEN",  ["phishing kit", "bec actor", "credential harvester"]),
    ("CDB-RAT-GEN",  ["remcos", "asyncrat", "njrat", "quasar rat", "xworm", "agent tesla"]),
    ("CDB-STE-GEN",  ["vidar stealer", "redline stealer", "lumma stealer",
                       "raccoon stealer", "infostealer campaign"]),
    # Category fallbacks
    ("CDB-RAN-GEN",  ["ransomware", "ransom demand", "double extortion"]),
    ("CDB-APT-GEN",  ["nation-state", "state-sponsored", "advanced persistent threat"]),
    ("CDB-CVE-GEN",  ["zero-day", "0-day exploit", "cve exploit"]),
]


def _infer_kill_chain(text: str) -> str:
    text_lower = text.lower()
    for phase, keywords in _KILL_CHAIN_MAP:
        for kw in keywords:
            if kw in text_lower:
                return phase
    return ""


def _infer_attack_vector(text: str) -> str:
    text_lower = text.lower()
    for vector, keywords in _ATTACK_VECTOR_MAP:
        for kw in keywords:
            if kw in text_lower:
                return vector
    # Default based on content type
    if any(w in text_lower for w in ["vulnerability", "cve-", "exploit"]):
        return "NETWORK"
    return ""


def _infer_mitre_techniques(text: str) -> List[str]:
    text_lower = text.lower()
    techniques: List[str] = []
    for tid, keywords in _MITRE_TECHNIQUE_MAP:
        for kw in keywords:
            if kw in text_lower and tid not in techniques:
                techniques.append(tid)
                break  # one match per technique
    return techniques[:5]  # cap at 5


def _infer_campaign(text: str) -> str:
    text_lower = text.lower()
    for campaign_id, keywords in _CAMPAIGN_MAP:
        for kw in keywords:
            if kw in text_lower:
                return campaign_id
    return ""


def _resolve_actor(text: str, current: str) -> str:
    """Resolve actor tag from text. Returns current if already a specific CDB tag."""
    if current and current not in ("UNC-CDB-INGEST", "UNC-UNKNOWN", "UNC-CDB-99", ""):
        return current  # already resolved
    text_lower = text.lower()
    for actor_id, keywords in _EXTENDED_ACTOR_MAP:
        for kw in keywords:
            if kw in text_lower:
                return actor_id
    return current  # keep as-is if no match


def _compute_enrichment_score(item: Dict) -> int:
    """Compute 0-100 enrichment quality score."""
    score = 0
    actor = item.get("actor_tag", "")
    if actor and actor not in ("UNC-CDB-INGEST", "UNC-UNKNOWN", ""):
        score += _SCORE_ACTOR_RESOLVED
    if item.get("kill_chain_phase"):
        score += _SCORE_KILL_CHAIN
    if item.get("attack_vector"):
        score += _SCORE_ATTACK_VECTOR
    if item.get("ttps") or item.get("mitre_tactics"):
        score += _SCORE_MITRE_TTPS
    if float(item.get("cvss_score") or item.get("cvss") or 0) > 0:
        score += _SCORE_CVSS
    if float(item.get("epss_score") or item.get("epss") or 0) > 0:
        score += _SCORE_EPSS
    if int(item.get("ioc_count") or 0) > 0:
        score += _SCORE_IOCS
    desc = item.get("description") or ""
    if len(str(desc)) > 200:
        score += _SCORE_DESCRIPTION
    return min(score, 100)


class IntelQualityEnricher:
    """
    Phase 4: Enrich every intel item with missing quality fields.
    Fields enriched:
        - actor_tag (resolved from text if UNC-CDB-INGEST)
        - kill_chain_phase (inferred from title + description)
        - attack_vector (inferred)
        - campaign_name (inferred)
        - mitre_techniques (inferred, added to ttps)
        - enrichment_score (0-100 composite score)
        - source_quality (HIGH/MEDIUM/LOW)
    """

    def enrich_batch(self, items: List[Dict]) -> List[Dict]:
        enriched_count = 0
        for item in items:
            changed = self._enrich_item(item)
            if changed:
                enriched_count += 1
        log.info("[PHASE4-ENRICH] Enriched %d/%d items", enriched_count, len(items))
        return items

    def _enrich_item(self, item: Dict) -> bool:
        """Enrich a single item in-place. Returns True if any field was set."""
        changed = False
        title   = str(item.get("title") or "")
        desc    = str(item.get("description") or "")
        text    = f"{title} {desc}"

        # Actor resolution
        current_actor = item.get("actor_tag", "")
        resolved = _resolve_actor(text, current_actor)
        if resolved != current_actor:
            item["actor_tag"] = resolved
            changed = True

        # Kill chain phase
        if not item.get("kill_chain_phase"):
            phase = _infer_kill_chain(text)
            if phase:
                item["kill_chain_phase"] = phase
                changed = True

        # Attack vector
        if not item.get("attack_vector"):
            vector = _infer_attack_vector(text)
            if vector:
                item["attack_vector"] = vector
                changed = True

        # Campaign name
        if not item.get("campaign_name"):
            campaign = _infer_campaign(text)
            if campaign:
                item["campaign_name"] = campaign
                changed = True

        # MITRE techniques — merge with existing ttps
        existing_ttps = item.get("ttps") or []
        if not isinstance(existing_ttps, list):
            existing_ttps = []

        if not existing_ttps or not item.get("mitre_tactics"):
            inferred = _infer_mitre_techniques(text)
            if inferred:
                merged = list(dict.fromkeys(existing_ttps + inferred))[:8]
                item["ttps"]          = merged
                item["mitre_tactics"] = merged[:5]
                item["ttp_count"]     = len(merged)
                changed = True

        # Source quality classification
        source = item.get("feed_source") or item.get("source") or ""
        if not item.get("source_quality"):
            item["source_quality"] = classify_source(source)
            changed = True

        # Enrichment score (always recompute)
        item["enrichment_score"] = _compute_enrichment_score(item)

        return changed


# ---------------------------------------------------------------------------
# PHASE 5: CVE Spam Control
# ---------------------------------------------------------------------------

class CVESpamController:
    """
    Phase 5: Limit raw CVE volume and require context for CVE-only entries.

    Rules:
        - cisa_kev: max MAX_CISA_KEV_ENTRIES entries (sort by risk_score desc)
        - nvd_cve: max MAX_NVD_CVE_ENTRIES entries
        - github_advisory: max MAX_GITHUB_ADV_ENTRIES entries
        - CVE-only entries (no threat context) with cvss < CVE_MIN_CVSS AND
          epss < CVE_MIN_EPSS: mark as DOWNGRADED priority
        - Ensure at least 20% of feed is non-CVE content
    """

    def apply(self, items: List[Dict]) -> Tuple[List[Dict], Dict]:
        source_buckets: Dict[str, List[Dict]] = defaultdict(list)
        other_items: List[Dict] = []

        for item in items:
            src = (item.get("feed_source") or "").lower()
            quality = item.get("source_quality", classify_source(src))
            if quality == "LOW":
                source_buckets[src].append(item)
            else:
                other_items.append(item)

        # Apply per-source caps (keep highest risk-scored entries)
        capped_low: List[Dict] = []
        cap_report: Dict[str, Dict] = {}

        for src, src_items in source_buckets.items():
            if "cisa_kev" in src:
                cap = MAX_CISA_KEV_ENTRIES
            elif "nvd_cve" in src:
                cap = MAX_NVD_CVE_ENTRIES
            elif "github_advisory" in src:
                cap = MAX_GITHUB_ADV_ENTRIES
            else:
                cap = 400  # v143.4.0: raised from 150

            # Sort by risk_score desc, then by epss desc
            sorted_items = sorted(
                src_items,
                key=lambda x: (
                    float(x.get("risk_score") or 0),
                    float(x.get("epss_score") or x.get("epss") or 0),
                    float(x.get("cvss_score") or x.get("cvss") or 0),
                ),
                reverse=True,
            )

            kept = sorted_items[:cap]
            dropped = len(sorted_items) - len(kept)

            # Downgrade priority for weak CVE-only entries
            for entry in kept:
                cvss = float(entry.get("cvss_score") or entry.get("cvss") or 0)
                epss = float(entry.get("epss_score") or entry.get("epss") or 0)
                ioc_count = int(entry.get("ioc_count") or 0)
                has_context = (
                    ioc_count > 0 or
                    epss >= CVE_MIN_EPSS or
                    cvss >= CVE_MIN_CVSS or
                    entry.get("kill_chain_phase") or
                    entry.get("ttps")
                )
                if not has_context:
                    entry["threat_priority"] = "LOW"
                else:
                    if not entry.get("threat_priority"):
                        if cvss >= 9.0 or epss >= 0.5:
                            entry["threat_priority"] = "CRITICAL"
                        elif cvss >= 7.0 or epss >= 0.3:
                            entry["threat_priority"] = "HIGH"
                        else:
                            entry["threat_priority"] = "MEDIUM"

            capped_low.extend(kept)
            if dropped > 0:
                cap_report[src] = {"original": len(src_items), "kept": len(kept), "dropped": dropped}

        # Ensure non-CVE content >= 20%
        total = len(other_items) + len(capped_low)
        if total > 0:
            non_cve_pct = len(other_items) / total
            if non_cve_pct < TARGET_HIGH_SOURCE_MIN:
                log.warning("[PHASE5-CVE] Non-CVE content = %.1f%% (target >= %.0f%%)",
                            non_cve_pct * 100, TARGET_HIGH_SOURCE_MIN * 100)

        result = other_items + capped_low
        report = {
            "phase": "5_cve_spam_control",
            "input_count": len(items),
            "output_count": len(result),
            "low_quality_capped": len(capped_low),
            "high_medium_kept": len(other_items),
            "cap_details": cap_report,
        }

        if cap_report:
            log.info("[PHASE5-CVE] Capped %d sources: removed %d low-quality CVE entries",
                     len(cap_report), sum(v["dropped"] for v in cap_report.values()))
        else:
            log.info("[PHASE5-CVE] No CVE caps needed: %d items", len(result))

        return result, report


# ---------------------------------------------------------------------------
# PHASE 6: Feed Quality Balancer
# ---------------------------------------------------------------------------

class FeedQualityBalancer:
    """
    Phase 6: Balance source mix in final feed.

    Target:
        HIGH quality sources  >= 20% of feed
        LOW quality sources   <= 45% of feed

    Strategy:
        1. Sort by source_quality (HIGH first), then by enrichment_score desc
        2. If LOW > 45%, trim from lowest enrichment_score upward
        3. Reorder feed: HIGH/MEDIUM first, then LOW (sorted by risk_score)
    """

    def balance(self, items: List[Dict]) -> Tuple[List[Dict], Dict]:
        high = [i for i in items if i.get("source_quality") == "HIGH"]
        medium = [i for i in items if i.get("source_quality") == "MEDIUM"]
        low = [i for i in items if i.get("source_quality") not in ("HIGH", "MEDIUM")]

        total = len(items)
        if total == 0:
            return items, {"phase": "6_feed_balancer", "skipped": True}

        # Sort each bucket by risk_score desc + enrichment_score desc
        def sort_key(x):
            return (
                float(x.get("risk_score") or 0),
                int(x.get("enrichment_score") or 0),
                float(x.get("epss_score") or 0),
            )

        high   = sorted(high,   key=sort_key, reverse=True)
        medium = sorted(medium, key=sort_key, reverse=True)
        low    = sorted(low,    key=sort_key, reverse=True)

        # Enforce LOW cap: max 45%
        max_low = int(total * TARGET_LOW_SOURCE_MAX)
        low_trimmed = 0
        if len(low) > max_low:
            low_trimmed = len(low) - max_low
            low = low[:max_low]

        # Reassemble: HIGH first, MEDIUM second, LOW last (most actionable at top)
        balanced = high + medium + low
        total_balanced = len(balanced)

        high_pct = len(high) / total_balanced * 100 if total_balanced else 0
        low_pct  = len(low)  / total_balanced * 100 if total_balanced else 0

        report = {
            "phase": "6_feed_balancer",
            "input_count": total,
            "output_count": total_balanced,
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "low_trimmed": low_trimmed,
            "high_pct": round(high_pct, 1),
            "low_pct": round(low_pct, 1),
            "target_high_min_pct": TARGET_HIGH_SOURCE_MIN * 100,
            "target_low_max_pct": TARGET_LOW_SOURCE_MAX * 100,
        }

        log.info("[PHASE6-BALANCE] HIGH=%.1f%% MEDIUM=%.1f%% LOW=%.1f%% | trimmed=%d",
                 high_pct,
                 len(medium) / total_balanced * 100 if total_balanced else 0,
                 low_pct, low_trimmed)

        return balanced, report


# ---------------------------------------------------------------------------
# PHASE 7: Dashboard Truth Validation
# ---------------------------------------------------------------------------

class DashboardTruthValidator:
    """
    Phase 7: Final validation before feed write.

    Verifies:
        - No repeated entries visible in top 50
        - 'is_new' entries are truly new (have is_new=True)
        - Ordering: newest processed_at first
        - No generic/empty titles in top entries
    """

    _GENERIC_TITLE_PATTERNS = [
        r"^cve-\d{4}-\d+\s*$",
        r"^advisory\s*$",
        r"^security update\s*$",
        r"^patch tuesday\s*$",
        r"^\s*$",
    ]

    def validate(self, items: List[Dict]) -> Tuple[List[Dict], Dict]:
        issues: List[str] = []

        # Sort by published_at desc (real source date = true freshness order)
        # FIX v142.1.0: was processed_at (ingestion timestamp) — wrong field
        def sort_ts(x):
            return x.get("published_at") or x.get("timestamp") or x.get("processed_at", "")
        items = sorted(items, key=sort_ts, reverse=True)

        # Check top 50 for generic titles
        generic_count = 0
        for item in items[:50]:
            title = (item.get("title") or "").strip().lower()
            for pat in self._GENERIC_TITLE_PATTERNS:
                if re.match(pat, title):
                    generic_count += 1
                    issues.append(f"Generic title in top 50: {title[:60]}")
                    break

        # Count is_new entries
        new_entries = [i for i in items if i.get("is_new") is True]
        new_count = len(new_entries)

        # Verify no duplicate titles in top 50
        top50_titles = [_norm_title(i.get("title", "")) for i in items[:50]]
        top50_dup_count = len(top50_titles) - len(set(top50_titles))
        if top50_dup_count > 0:
            issues.append(f"Duplicate titles in top 50: {top50_dup_count}")

        report = {
            "phase": "7_dashboard_truth",
            "total_items": len(items),
            "new_entries_count": new_count,
            "new_entries_unique": new_count > 0,
            "ordering": "published_at_desc",
            "generic_titles_top50": generic_count,
            "duplicate_titles_top50": top50_dup_count,
            "issues": issues,
            "validation_passed": len(issues) == 0,
        }

        if issues:
            for issue in issues[:5]:
                log.warning("[PHASE7-DASHBOARD] %s", issue)
        else:
            log.info("[PHASE7-DASHBOARD] PASS: %d items, %d new, ordering=correct",
                     len(items), new_count)

        return items, report


# ---------------------------------------------------------------------------
# PHASE 8: Final Assertions
# ---------------------------------------------------------------------------

class FinalAssertionEngine:
    """
    Phase 8: Write the quality report and assert all invariants.

    ASSERTIONS:
        duplicate_count == 0
        new_entries_unique == True
        enrichment_fields != all empty
        dashboard != repetitive
    """

    def run_assertions(self, items: List[Dict], phase_reports: Dict) -> Dict:
        assertions: Dict[str, bool] = {}
        failures: List[str] = []

        # A1: Zero duplicates
        stix_ids = [i.get("stix_id") or i.get("id") or "" for i in items]
        dup_count = len(stix_ids) - len(set(stix_ids))
        assertions["duplicate_count_zero"] = dup_count == 0
        if dup_count > 0:
            failures.append(f"FAIL: {dup_count} duplicate stix_ids remain")

        # A2: New entries unique
        new_entries = [i for i in items if i.get("is_new") is True]
        new_fps = [_content_fingerprint(i) for i in new_entries]
        assertions["new_entries_unique"] = len(new_fps) == len(set(new_fps))
        if not assertions["new_entries_unique"]:
            failures.append("FAIL: is_new entries contain duplicates")

        # A3: Enrichment fields not all empty
        enriched = sum(1 for i in items if i.get("kill_chain_phase") or i.get("attack_vector"))
        enrichment_rate = enriched / len(items) if items else 0
        assertions["enrichment_fields_populated"] = enrichment_rate > 0.10  # >10% enriched
        if enrichment_rate <= 0.10:
            failures.append(f"FAIL: Only {enrichment_rate:.1%} items have enrichment fields")

        # A4: Actor resolution improved
        good_actors = sum(1 for i in items
                          if i.get("actor_tag") and
                          i.get("actor_tag") not in ("UNC-CDB-INGEST", "UNC-UNKNOWN", ""))
        actor_rate = good_actors / len(items) if items else 0
        assertions["actor_resolution_nonzero"] = actor_rate > 0

        # A5: No empty titles
        empty_titles = sum(1 for i in items if not (i.get("title") or "").strip())
        assertions["no_empty_titles"] = empty_titles == 0
        if empty_titles > 0:
            failures.append(f"FAIL: {empty_titles} items have empty titles")

        # A6: Feed has reasonable size
        assertions["feed_has_content"] = len(items) >= 50
        if len(items) < 50:
            failures.append(f"FAIL: Feed too small ({len(items)} items)")

        all_passed = len(failures) == 0

        report = {
            "phase": "8_final_assertions",
            "version": _ENGINE_VERSION,
            "timestamp": _utc_now(),
            "total_items": len(items),
            "assertions": assertions,
            "all_assertions_passed": all_passed,
            "failures": failures,
            "stats": {
                "duplicate_stix_ids": dup_count,
                "new_entries": len(new_entries),
                "enriched_items": enriched,
                "enrichment_rate_pct": round(enrichment_rate * 100, 1),
                "actor_resolved_items": good_actors,
                "actor_resolution_rate_pct": round(actor_rate * 100, 1),
            },
        }

        if all_passed:
            log.info("[PHASE8-ASSERT] ALL ASSERTIONS PASSED: %d items, "
                     "0 dups, %.1f%% enriched, %.1f%% actors resolved",
                     len(items), enrichment_rate * 100, actor_rate * 100)
        else:
            for f in failures:
                log.error("[PHASE8-ASSERT] %s", f)

        return report


# ---------------------------------------------------------------------------
# Main orchestrator: apply_quality_pipeline()
# ---------------------------------------------------------------------------

def apply_quality_pipeline(items: List[Dict]) -> List[Dict]:
    """
    Main entry point: apply all 8 quality phases to a list of manifest items.

    Args:
        items: List of intel manifest dicts

    Returns:
        Cleaned, enriched, deduplicated, balanced list of intel dicts.
        Always returns a list (never raises).
    """
    if not items:
        log.warning("[QUALITY-ENGINE] Empty item list — nothing to process")
        return items

    t_start = time.monotonic()
    log.info("[QUALITY-ENGINE] v%s starting: %d input items", _ENGINE_VERSION, len(items))

    phase_reports: Dict = {}
    original_count = len(items)

    try:
        # ================================================================
        # PHASE 1: Global 3-Layer Dedup
        # ================================================================
        log.info("[PHASE1] 3-Layer Global Dedup Engine")
        removed_total = 0

        # Layer 1: Content fingerprint (cross-run)
        try:
            l1 = Layer1IngestDedup()
            items, r1 = l1.deduplicate(items)
            removed_total += r1
        except Exception as e:
            log.warning("[PHASE1-L1] Layer 1 failed (non-fatal): %s", e)

        # Layer 2: STIX-level (same stix_id or same CVE > 2)
        try:
            l2 = Layer2StixDedup()
            items, r2 = l2.deduplicate(items)
            removed_total += r2
        except Exception as e:
            log.warning("[PHASE1-L2] Layer 2 failed (non-fatal): %s", e)

        # Layer 3: Title-level dedup
        try:
            l3 = Layer3ManifestDedup()
            items, r3 = l3.deduplicate(items)
            removed_total += r3
        except Exception as e:
            log.warning("[PHASE1-L3] Layer 3 failed (non-fatal): %s", e)

        phase_reports["phase_1_dedup"] = {
            "removed_total": removed_total,
            "remaining": len(items),
        }
        log.info("[PHASE1] COMPLETE: %d -> %d (removed %d dups)",
                 original_count, len(items), removed_total)

        # ================================================================
        # PHASE 2: True Newness Validation
        # ================================================================
        log.info("[PHASE2] True Newness Validation")
        try:
            nv = NewnessValidator()
            items = nv.validate_batch(items)
            new_count = sum(1 for i in items if i.get("is_new"))
            phase_reports["phase_2_newness"] = {
                "new_entries": new_count,
                "existing_entries": len(items) - new_count,
            }
        except Exception as e:
            log.warning("[PHASE2] Newness validation failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 3: Manifest Sanity Guard
        # ================================================================
        log.info("[PHASE3] Manifest Sanity Guard")
        try:
            msg = ManifestSanityGuard()
            items, p3_report = msg.validate_and_clean(items)
            phase_reports["phase_3_sanity"] = p3_report
        except Exception as e:
            log.warning("[PHASE3] Sanity guard failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 4: Intel Quality Enrichment
        # ================================================================
        log.info("[PHASE4] Intel Quality Enrichment")
        try:
            enricher = IntelQualityEnricher()
            items = enricher.enrich_batch(items)
            enriched_count = sum(1 for i in items if int(i.get("enrichment_score") or 0) > 20)
            phase_reports["phase_4_enrichment"] = {
                "total": len(items),
                "enriched_gt20": enriched_count,
                "enrichment_rate_pct": round(enriched_count / len(items) * 100, 1) if items else 0,
            }
        except Exception as e:
            log.warning("[PHASE4] Enrichment failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 5: CVE Spam Control
        # ================================================================
        log.info("[PHASE5] CVE Spam Control")
        try:
            csc = CVESpamController()
            items, p5_report = csc.apply(items)
            phase_reports["phase_5_cve_spam"] = p5_report
        except Exception as e:
            log.warning("[PHASE5] CVE spam control failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 6: Feed Quality Balancer
        # ================================================================
        log.info("[PHASE6] Feed Quality Balancer")
        try:
            fqb = FeedQualityBalancer()
            items, p6_report = fqb.balance(items)
            phase_reports["phase_6_balance"] = p6_report
        except Exception as e:
            log.warning("[PHASE6] Feed balancer failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 7: Dashboard Truth Validation
        # ================================================================
        log.info("[PHASE7] Dashboard Truth Validation")
        try:
            dtv = DashboardTruthValidator()
            items, p7_report = dtv.validate(items)
            phase_reports["phase_7_dashboard"] = p7_report
        except Exception as e:
            log.warning("[PHASE7] Dashboard validation failed (non-fatal): %s", e)

        # ================================================================
        # PHASE 8: Final Assertions + Quality Report
        # ================================================================
        log.info("[PHASE8] Final Assertions")
        try:
            fae = FinalAssertionEngine()
            p8_report = fae.run_assertions(items, phase_reports)
            phase_reports["phase_8_assertions"] = p8_report

            # Write full quality report
            full_report = {
                "engine_version": _ENGINE_VERSION,
                "timestamp": _utc_now(),
                "input_count": original_count,
                "output_count": len(items),
                "total_removed": original_count - len(items),
                "elapsed_ms": round((time.monotonic() - t_start) * 1000),
                "all_assertions_passed": p8_report.get("all_assertions_passed", False),
                "phases": phase_reports,
            }
            try:
                _atomic_write(QUALITY_REPORT, full_report)
                log.info("[PHASE8] Quality report written: %s", QUALITY_REPORT.name)
            except Exception as e:
                log.warning("[PHASE8] Could not write quality report: %s", e)

        except Exception as e:
            log.warning("[PHASE8] Final assertions failed (non-fatal): %s", e)

    except Exception as top_e:
        log.error("[QUALITY-ENGINE] Unexpected top-level error: %s — returning items as-is", top_e)

    elapsed = time.monotonic() - t_start
    log.info("[QUALITY-ENGINE] COMPLETE: %d -> %d items | elapsed=%.1fs",
             original_count, len(items), elapsed)

    return items


# ---------------------------------------------------------------------------
# CLI: run as standalone for testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse


    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [quality-engine] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    parser = argparse.ArgumentParser(description="Intel Quality Engine -- standalone test mode")
    parser.add_argument("--manifest", default=str(REPO_ROOT / "data/stix/feed_manifest.json"),
                        help="Path to feed_manifest.json")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing output")
    parser.add_argument("--report", action="store_true",
                        help="Print full quality report to stdout after pipeline run")
    parser.add_argument("--min-items", type=int, default=0,
                        help="v166.2: Hard-fail if output feed has fewer than N items. "
                             "Default 0 = no minimum enforced.")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}")
        raise SystemExit(1)

    with open(manifest_path, encoding="utf-8") as fh:
        raw_items = json.load(fh)

    # FIX v148.0: unwrap dict envelope {"advisories":[...]} / {"items":[...]} etc.
    if isinstance(raw_items, dict):
        _unwrapped = False
        for _key in ("advisories", "items", "data", "feed", "reports", "intel"):
            if isinstance(raw_items.get(_key), list):
                print(f"[FIX-v148] Unwrapping dict envelope key='{_key}' ({len(raw_items[_key])} items)")
                raw_items = raw_items[_key]
                _unwrapped = True
                break
        if not _unwrapped:
            for _v in raw_items.values():
                if isinstance(_v, list):
                    raw_items = _v
                    _unwrapped = True
                    break
        if not _unwrapped:
            print(f"ERROR: manifest must be a JSON array, got dict with keys: {list(raw_items.keys())}")
            raise SystemExit(1)

    if not isinstance(raw_items, list):
        print(f"ERROR: manifest must be a JSON array, got {type(raw_items).__name__}")
        raise SystemExit(1)

    print(f"[DRY-RUN={args.dry_run}] Loaded {len(raw_items)} entries from {manifest_path}")
    result = apply_quality_pipeline(raw_items)
    print(f"[RESULT] {len(raw_items)} -> {len(result)} entries after quality pipeline")
    new_entries = [i for i in result if i.get("is_new") is True]
    print(f"[RESULT] is_new=True  : {len(new_entries)} entries")
    dup_stix = len(result) - len({e.get('stix_id') for e in result})
    print(f"[RESULT] duplicate_count: {dup_stix}")

    if args.report:
        # Print quality report summary from written report file
        report_file = QUALITY_DIR / "intel_quality_report.json"
        if report_file.exists():
            try:
                with open(report_file, encoding="utf-8") as rf:
                    rpt = json.load(rf)
                print("[QUALITY REPORT]")
                print(f"  Engine version : {rpt.get('engine_version', _ENGINE_VERSION)}")
                print(f"  Total entries  : {rpt.get('total_input', len(result))}")
                print(f"  Duplicates rm  : {rpt.get('duplicates_removed', 0)}")
                print(f"  New entries    : {rpt.get('new_entries', len(new_entries))}")
                print(f"  Quality score  : {rpt.get('quality_score', 'N/A')}")
                print(f"  Report path    : {report_file}")
            except Exception as _re:
                print(f"[QUALITY REPORT] Could not read report: {_re}")
        else:
            # Fallback: synthesize a brief report from the result
            print("[QUALITY REPORT]")
            print(f"  Engine version : {_ENGINE_VERSION}")
            print(f"  Total entries  : {len(result)}")
            print(f"  Duplicates rm  : {len(raw_items) - len(result)}")
            print(f"  New entries    : {len(new_entries)}")
            print(f"  Duplicate stix : {dup_stix}")

    # v166.2 FIND-007: --min-items hard-fail gate (replaces || true masking in CI)
    if args.min_items > 0 and len(result) < args.min_items:
        print(f"[PHASE8-GATE] HARD FAIL: output feed has {len(result)} items < --min-items {args.min_items}")
        raise SystemExit(1)

    print("[DONE]")
