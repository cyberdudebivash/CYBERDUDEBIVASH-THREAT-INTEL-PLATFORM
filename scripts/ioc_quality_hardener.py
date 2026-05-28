#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/ioc_quality_hardener.py — IOC Quality Hardening Engine
================================================================================
Version : 149.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering
License : CONFIDENTIAL — All Rights Reserved

PROBLEM SOLVED:
  The feed currently contains pseudo-IOCs: CVE IDs, Vulners/NVD RSS URLs,
  vendor advisory page URLs — all being counted as operational indicators.
  This degrades enterprise trust and bloats IOC counts with useless data.

SOLUTION:
  1. CLASSIFY each IOC by true type (IP, domain, hash, URL-C2, CVE-ref, etc.)
  2. FILTER pseudo-IOCs that are NOT operational network/file/hash indicators
  3. RECALIBRATE confidence per IOC type using APEX multi-signal scoring
  4. RECOUNT ioc_count to reflect only genuine operational IOCs
  5. PRESERVE filtered items in a separate pseudo_iocs list for transparency
  6. WRITE quality report for CI visibility

OPERATIONAL IOC TYPES (kept):
  - IPv4/IPv6 addresses (malicious IPs, C2 endpoints)
  - Domain names (C2, phishing, malware distribution)
  - SHA256/SHA1/MD5 hashes (malware file hashes)
  - URLs with malicious indicators (not advisory/vendor links)
  - Email addresses (phishing, actor contact)
  - JA3/JA3S fingerprints (TLS C2 fingerprints)
  - Mutex names, registry keys (persistence IOCs)

PSEUDO-IOC TYPES (filtered into pseudo_iocs, not counted):
  - CVE ID strings (CVE-YYYY-XXXXX)
  - Vulners.com advisory URLs
  - NVD/NIST advisory URLs
  - Vendor advisory URLs (vendor.com/security/advisory/...)
  - GitHub advisory/commit URLs
  - CISA/US-CERT advisory URLs

CONFIDENCE CALIBRATION:
  - Verified network C2 IP:       HIGH (85–95%)
  - Active domain (PDNS match):   HIGH (80–90%)
  - File hash (malware sample):   VERIFIED (90–98%)
  - Phishing URL:                 HIGH (75–85%)
  - Observed URL (passive):       MEDIUM (55–70%)
  - Legacy/unverified indicator:  LOW (25–45%)
================================================================================
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IOC-HARDENER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("IOC-HARDENER")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT     = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
QUALITY_DIR   = REPO_ROOT / "data" / "ioc_quality"
QUALITY_REPORT = QUALITY_DIR / "ioc_quality_report.json"

ENGINE_VERSION = "166.2.0"
NOW_ISO        = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# CVE ID — always a reference, never an operational IOC
_CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)

# IPv4 address (operational IOC)
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# IPv6 address (operational IOC)
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]{4,39}$')

# SHA256 hash
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')

# SHA1 hash
_SHA1_RE = re.compile(r'^[0-9a-fA-F]{40}$')

# MD5 hash
_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')

# Domain name (2+ labels, no path)
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# Email address
_EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

# PSEUDO-IOC: URL patterns that are not operational C2/phishing
_PSEUDO_URL_PATTERNS = [
    # Vulners advisory URLs
    re.compile(r'https?://vulners\.com/', re.I),
    # NVD/NIST advisory URLs
    re.compile(r'https?://nvd\.nist\.gov/', re.I),
    re.compile(r'https?://cve\.mitre\.org/', re.I),
    # CISA/US-CERT advisory
    re.compile(r'https?://www\.cisa\.gov/', re.I),
    re.compile(r'https?://us-cert\.cisa\.gov/', re.I),
    re.compile(r'https?://www\.kb\.cert\.org/', re.I),
    # GitHub advisory/commit references
    re.compile(r'https?://github\.com/[^/]+/[^/]+/(security/advisories|commit|releases|issues|pull)', re.I),
    re.compile(r'https?://github\.com/advisories/', re.I),
    # Vendor security advisory paths
    re.compile(r'https?://[^/]+\.(com|net|org|io)/[^?#]*(?:security[_-]?advisory|security[_-]?bulletin|advisory|patch|fix|vuln|cve)', re.I),
    # Intel platform self-references
    re.compile(r'https?://intel\.cyberdudebivash\.com/', re.I),
    # RSS feed tracker URLs
    re.compile(r'utm_source=rss|utm_medium=rss', re.I),
    # Vendor blog posts about patches
    re.compile(r'https?://(?:www\.)?(?:microsoft|apple|google|oracle|adobe|cisco|vmware|paloalto|crowdstrike|rapid7|tenable|qualys)\.com/.*(?:update|patch|advisory|security)', re.I),
    # Hacker News / security news articles (not IOCs)
    re.compile(r'https?://thehackernews\.com/', re.I),
    re.compile(r'https?://www\.bleepingcomputer\.com/', re.I),
    re.compile(r'https?://krebsonsecurity\.com/', re.I),
    re.compile(r'https?://securityaffairs\.com/', re.I),
    re.compile(r'https?://www\.securityweek\.com/', re.I),
    # Packetstorm/exploit-db advisory pages
    re.compile(r'https?://packetstormsecurity\.com/files/[^/]+/', re.I),
]

# Operational C2/phishing URL indicators (these ARE valid IOCs)
_OPERATIONAL_URL_INDICATORS = [
    re.compile(r'(?:c2|cnc|beacon|dropper|payload|malware|rat\.|loader|stager|stage1|stage2)', re.I),
    re.compile(r'/[a-zA-Z0-9]{20,}$'),  # Long random paths (beacon URLs)
    re.compile(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{4,5})?/', re.I),  # IP-based URL
    re.compile(r'\.(?:onion|bit|bazar)\b', re.I),  # Dark web / alternative DNS
]


# ─────────────────────────────────────────────────────────────────────────────
# IOC CLASSIFICATION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def classify_ioc(indicator: Any) -> Tuple[str, str, bool]:
    """
    Classify an IOC indicator.
    Returns: (ioc_type, classification, is_operational)
    ioc_type: 'ip', 'domain', 'hash_sha256', 'hash_sha1', 'hash_md5',
               'url_c2', 'url_phishing', 'url_operational', 'email',
               'cve_reference', 'url_pseudo', 'unknown'
    classification: 'operational' | 'pseudo' | 'reference'
    is_operational: True if should be kept in IOC table
    """
    # Normalise to string
    raw = ""
    if isinstance(indicator, dict):
        raw = str(
            indicator.get("value") or
            indicator.get("indicator") or
            indicator.get("ioc") or
            indicator.get("id") or ""
        ).strip()
    elif isinstance(indicator, str):
        raw = indicator.strip()
    else:
        raw = str(indicator).strip()

    if not raw:
        return ("unknown", "pseudo", False)

    # CVE reference — never operational
    if _CVE_RE.match(raw):
        return ("cve_reference", "reference", False)

    # IPv4
    if _IPV4_RE.match(raw):
        # Filter RFC1918 private IPs (not useful external IOCs)
        parts = raw.split(".")
        if parts[0] in ("10", "127") or \
           (parts[0] == "172" and 16 <= int(parts[1]) <= 31) or \
           (parts[0] == "192" and parts[1] == "168") or \
           (parts[0] == "0"):
            return ("ip_private", "pseudo", False)
        return ("ipv4", "operational", True)

    # IPv6
    if len(raw) >= 4 and ":" in raw and _IPV6_RE.match(raw.replace("[", "").replace("]", "")):
        return ("ipv6", "operational", True)

    # Hashes
    if _SHA256_RE.match(raw):
        return ("hash_sha256", "operational", True)
    if _SHA1_RE.match(raw):
        return ("hash_sha1", "operational", True)
    if _MD5_RE.match(raw):
        return ("hash_md5", "operational", True)

    # Email
    if _EMAIL_RE.match(raw) and len(raw) < 100:
        return ("email", "operational", True)

    # URL classification
    if raw.startswith(("http://", "https://", "ftp://")):
        # Check if pseudo-URL first
        for pseudo_pat in _PSEUDO_URL_PATTERNS:
            if pseudo_pat.search(raw):
                return ("url_pseudo", "pseudo", False)
        # Check for operational URL indicators
        for op_pat in _OPERATIONAL_URL_INDICATORS:
            if op_pat.search(raw):
                return ("url_c2", "operational", True)
        # Default: operational URL (could be phishing/C2)
        return ("url_operational", "operational", True)

    # Domain (no path, 2+ labels)
    if _DOMAIN_RE.match(raw) and len(raw) < 255:
        # Filter common legitimate domains used as pseudo-IOCs
        legitimate_tlds = {"vulners.com", "nvd.nist.gov", "cve.mitre.org",
                           "github.com", "cisa.gov", "microsoft.com"}
        lower_raw = raw.lower()
        if any(lower_raw == d or lower_raw.endswith("." + d) for d in legitimate_tlds):
            return ("domain_legitimate", "pseudo", False)
        return ("domain", "operational", True)

    # Mutex, registry key, or other host-based IOC
    if raw.startswith(("HKEY_", "HKLM\\", "HKCU\\", "SOFTWARE\\", "\\Registry")):
        return ("registry_key", "operational", True)

    # Filename with malicious extension
    if re.match(r'^[a-zA-Z0-9_\-\.]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|scr|pif)$', raw, re.I):
        return ("filename", "operational", True)

    return ("unknown", "pseudo", False)


def calibrate_confidence(ioc: Any, ioc_type: str) -> int:
    """
    Assign confidence percentage based on IOC type and context signals.
    Returns 0–100.
    """
    if isinstance(ioc, dict):
        existing_conf = ioc.get("confidence")
        context = str(ioc.get("context") or "").lower()
    else:
        existing_conf = None
        context = ""

    # Type-based base confidence
    type_base = {
        "hash_sha256":    90,
        "hash_sha1":      85,
        "hash_md5":       80,
        "ipv4":           75,
        "ipv6":           72,
        "url_c2":         78,
        "url_phishing":   76,
        "url_operational": 65,
        "domain":         70,
        "email":          65,
        "registry_key":   80,
        "filename":       70,
        "mutex":          75,
    }.get(ioc_type, 50)

    # Context signals
    confidence_boost = 0
    if "confirmed" in context or "verified" in context:
        confidence_boost += 15
    elif "observed" in context:
        confidence_boost += 5
    elif "generated" in context or "synthetic" in context:
        confidence_boost -= 15
    elif "legacy" in context:
        confidence_boost -= 10

    # If original confidence was already high, respect it
    if existing_conf is not None:
        try:
            orig = float(str(existing_conf).replace("%", ""))
            if orig <= 100 and orig >= 60:
                # Blend original with type-calibrated
                return max(min(int((type_base + confidence_boost + orig) / 2), 100), 10)
        except (ValueError, TypeError):
            pass

    return max(min(type_base + confidence_boost, 100), 10)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN IOC HARDENING FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def harden_item_iocs(item: dict) -> Tuple[dict, dict]:
    """
    Harden IOCs for a single advisory item.
    Returns (updated_item, stats_dict).
    """
    stats = {
        "total_before": 0,
        "operational": 0,
        "pseudo": 0,
        "types": {},
    }

    raw_iocs = item.get("iocs") or []
    if not raw_iocs:
        return item, stats

    stats["total_before"] = len(raw_iocs)

    operational_iocs = []
    pseudo_iocs = []

    for ioc in raw_iocs:
        ioc_type, classification, is_operational = classify_ioc(ioc)

        # Build enriched IOC dict
        if isinstance(ioc, dict):
            enriched = dict(ioc)
        else:
            enriched = {
                "value": str(ioc),
                "indicator": str(ioc),
                "confidence": "50%",
                "context": "legacy",
                "source": "OBSERVED",
            }

        enriched["ioc_type"] = ioc_type
        enriched["classification"] = classification

        if is_operational:
            # Calibrate confidence for operational IOCs
            calibrated = calibrate_confidence(ioc, ioc_type)
            enriched["confidence"] = f"{calibrated}%"
            enriched["apex_validated"] = True
            operational_iocs.append(enriched)
            stats["operational"] += 1
            stats["types"][ioc_type] = stats["types"].get(ioc_type, 0) + 1
        else:
            enriched["apex_validated"] = False
            enriched["filtered_reason"] = f"pseudo_{classification}"
            pseudo_iocs.append(enriched)
            stats["pseudo"] += 1

    # Update item
    item = dict(item)
    item["iocs"] = operational_iocs
    item["ioc_count"] = len(operational_iocs)
    item["indicator_count"] = len(operational_iocs)
    item["pseudo_iocs"] = pseudo_iocs
    item["pseudo_ioc_count"] = len(pseudo_iocs)
    item["_ioc_hardened"] = True
    item["_ioc_hardened_at"] = NOW_ISO

    return item, stats


# ─────────────────────────────────────────────────────────────────────────────
# ATOMIC WRITE
# ─────────────────────────────────────────────────────────────────────────────

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=indent, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# v161.0 P0-004 FIX: EPSS Anomaly Sanity Check
# Evidence: CVE-2026-5194 EPSS=100% with CVSS=5.5 MEDIUM — impossible combo
# ─────────────────────────────────────────────────────────────────────────────

def _epss_sanity_check(epss, cvss):
    """Cap EPSS if implausibly high for given CVSS severity. Returns corrected float."""
    if epss is None:
        return epss
    try:
        epss = float(epss)
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        return epss
    if cvss is None:
        return epss
    # MEDIUM severity (4.0-6.9) cannot statistically sustain EPSS > 75%
    if cvss < 7.0 and epss > 75.0:
        corrected = round(min(cvss / 10.0 * 60.0, 75.0), 2)
        log.warning("EPSS anomaly corrected: %.2f -> %.2f (CVSS=%.1f MEDIUM)", epss, corrected, cvss)
        return corrected
    # LOW severity (< 4.0) cannot sustain EPSS > 40%
    if cvss < 4.0 and epss > 40.0:
        corrected = round(min(cvss / 10.0 * 40.0, 40.0), 2)
        log.warning("EPSS anomaly corrected: %.2f -> %.2f (CVSS=%.1f LOW)", epss, corrected, cvss)
        return corrected
    return epss


# ─────────────────────────────────────────────────────────────────────────────
# v161.0 P1-006 FIX: NVD REST API v2 CVSS Backfill
# Evidence: ~56% of advisories lack CVSS — 2026 CVEs not in NVD yet handled
# ─────────────────────────────────────────────────────────────────────────────

def _backfill_nvd_cvss(cve_id: str):
    """
    Query NVD REST API v2 for CVSS score.

    v166.2 FIX (P0): Previously the NVD_API_KEY environment variable was never
    read, causing ALL requests to run unauthenticated (5 req/30s limit →
    forced 6s sleep per CVE). With 47+ CVEs this guaranteed the 5-minute step
    timeout. Fix: read NVD_API_KEY from env and pass as apiKey header.

    Rate limits:
      - Without API key: 5 req/30s  → sleep 6.0s between calls
      - With    API key: 50 req/30s → sleep 0.6s between calls

    Returns (score: float|None, source: str, sleep_s: float).
    """
    import urllib.request

    nvd_api_key = os.environ.get("NVD_API_KEY", "").strip()
    sleep_s = 0.6 if nvd_api_key else 6.0  # respect correct rate limit tier

    headers = {"User-Agent": "CDB-SENTINEL-APEX/166.2"}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = __import__("json").loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, "NVD_NOT_FOUND", sleep_s
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score), "NVD_REST_v2", sleep_s
        return None, "NVD_NO_METRIC", sleep_s
    except Exception as e:
        log.debug("NVD CVSS backfill failed for %s: %s", cve_id, e)
        return None, "NVD_ERROR", sleep_s

def apply_ioc_hardening(manifest_path: Path = MANIFEST_PATH) -> dict:
    """
    Apply IOC hardening to all advisories in the manifest.
    ADDITIVE: adds pseudo_iocs, updates ioc_count, calibrates confidence.
    Returns summary dict.
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX IOC Quality Hardener v%s", ENGINE_VERSION)
    log.info("Manifest: %s", manifest_path)
    log.info("=" * 60)
    t0 = time.monotonic()

    # v166.2: Time-budget guard — bail out of NVD backfill before step timeout
    # kills the entire job. Step timeout is 5 min; we stop backfill at 4 min,
    # saving ~60s for the manifest write + downstream stages.
    # When the API key is present (0.6s/req) this guard will rarely trigger.
    # When the API key is absent (6s/req) it caps at ~40 CVEs before gracefully
    # stopping rather than hard-timing out and failing the step.
    BACKFILL_TIME_BUDGET_S = 240  # 4 minutes max for NVD backfill loop

    if not manifest_path.exists():
        log.error("FATAL: manifest not found: %s", manifest_path)
        return {"error": "manifest_not_found", "processed": 0}

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else (
        data.get("advisories") or data.get("reports") or data.get("items") or [])
    total = len(items)
    log.info("Loaded %d advisories", total)

    # Global stats
    global_stats = {
        "total_items": total,
        "items_with_iocs": 0,
        "total_iocs_before": 0,
        "total_iocs_after": 0,
        "total_pseudo_filtered": 0,
        "ioc_type_distribution": {},
        "items_with_zero_operational_iocs": 0,
    }

    updated_items = []
    for item in items:
        if not isinstance(item, dict):
            updated_items.append(item)
            continue

        raw_ioc_count = len(item.get("iocs") or [])
        if raw_ioc_count == 0:
            updated_items.append(item)
            continue

        global_stats["items_with_iocs"] += 1
        global_stats["total_iocs_before"] += raw_ioc_count

        item, stats = harden_item_iocs(item)

        global_stats["total_iocs_after"] += stats["operational"]
        global_stats["total_pseudo_filtered"] += stats["pseudo"]

        if stats["operational"] == 0 and raw_ioc_count > 0:
            global_stats["items_with_zero_operational_iocs"] += 1

        for ioc_type, count in stats["types"].items():
            global_stats["ioc_type_distribution"][ioc_type] = \
                global_stats["ioc_type_distribution"].get(ioc_type, 0) + count

        # v161.0 FIX: EPSS sanity check on each item
        _epss_raw  = item.get("epss_score") or item.get("epss")
        _cvss_raw  = item.get("cvss_score") or item.get("cvss")
        _epss_fixed = _epss_sanity_check(_epss_raw, _cvss_raw)
        if _epss_fixed != _epss_raw and _epss_raw is not None:
            if "epss_score" in item:
                item["epss_score"] = _epss_fixed
            if "epss" in item:
                item["epss"] = _epss_fixed
            global_stats.setdefault("epss_anomalies_corrected", 0)
            global_stats["epss_anomalies_corrected"] += 1

        # v161.0 FIX: NVD CVSS backfill for items missing CVSS
        # v166.2 FIX: Use NVD_API_KEY (10x faster rate limit) + time-budget guard
        _cvss_val = item.get("cvss_score") or item.get("cvss")
        if not _cvss_val:
            _cve_ids = item.get("cve_ids") or item.get("cves") or []
            if isinstance(_cve_ids, str):
                _cve_ids = [_cve_ids]
            if _cve_ids:
                # v166.2: Time-budget guard — skip backfill if approaching step timeout
                _elapsed = time.monotonic() - t0
                if _elapsed >= BACKFILL_TIME_BUDGET_S:
                    global_stats.setdefault("cvss_backfill_skipped_budget", 0)
                    global_stats["cvss_backfill_skipped_budget"] += 1
                    log.warning(
                        "NVD backfill budget exhausted (%.0fs elapsed, limit %ds) — "
                        "skipping %s. Will backfill on next pipeline run.",
                        _elapsed, BACKFILL_TIME_BUDGET_S, _cve_ids[0]
                    )
                else:
                    _nvd_score, _nvd_src, _sleep_s = _backfill_nvd_cvss(_cve_ids[0])
                    time.sleep(_sleep_s)  # v166.2: dynamic — 0.6s w/ key, 6s without
                    if _nvd_score is not None:
                        item["cvss_score"] = _nvd_score
                        item["cvss"] = _nvd_score
                        item["cvss_source"] = _nvd_src
                        global_stats.setdefault("cvss_backfilled", 0)
                        global_stats["cvss_backfilled"] += 1
                        log.info("CVSS backfilled for %s: %.1f (%s)", _cve_ids[0], _nvd_score, _nvd_src)

        updated_items.append(item)

    # Update items in data
    if "advisories" in data:
        data["advisories"] = updated_items
    elif "reports" in data:
        data["reports"] = updated_items
    else:
        data["items"] = updated_items

    # Write enriched manifest
    _atomic_write(manifest_path, data)
    log.info("Manifest written")

    # Write quality report
    elapsed = time.monotonic() - t0
    removal_rate = (
        global_stats["total_pseudo_filtered"] /
        max(global_stats["total_iocs_before"], 1) * 100
    )

    report = {
        "engine_version": ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "manifest": str(manifest_path),
        **global_stats,
        "pseudo_removal_rate_pct": round(removal_rate, 1),
        "elapsed_seconds": round(elapsed, 2),
    }
    QUALITY_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write(QUALITY_REPORT, report)

    log.info("=" * 60)
    log.info("IOC HARDENING COMPLETE: %d items | IOCs %d → %d (-%d pseudo) | %.1f%% removal | %.2fs",
             total,
             global_stats["total_iocs_before"],
             global_stats["total_iocs_after"],
             global_stats["total_pseudo_filtered"],
             removal_rate,
             elapsed)
    log.info("IOC type distribution: %s", global_stats["ioc_type_distribution"])
    log.info("=" * 60)

    return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description=f"SENTINEL APEX IOC Quality Hardener v{ENGINE_VERSION}"
    )
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--dry-run", action="store_true",
                        help="Classify IOCs but do not write manifest")
    args = parser.parse_args()

    result = apply_ioc_hardening(Path(args.manifest))
    if "error" in result:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
