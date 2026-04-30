#!/usr/bin/env python3
"""
scripts/ioc_reputation_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- IOC Reputation Engine v1.0
==============================================================
Production-grade Indicator of Compromise reputation lookup engine.

Supported IOC types:
  - IP Address     (IPv4 + IPv6)
  - Domain / FQDN
  - URL
  - File Hash      (MD5 / SHA-1 / SHA-256)

Data sources:
  - AbuseIPDB      (IPs only)        env: ABUSEIPDB_API_KEY
  - VirusTotal v3  (IP/domain/URL/hash) env: VT_API_KEY

Paywall enforcement:
  - FREE      : 5 IOC lookups/day, AbuseIPDB score only, no VT detail
  - PRO       : Unlimited lookups, full multi-source, threat context
  - ENTERPRISE: Bulk scan (up to 500), STIX output, full pivot fields
  - MSSP      : Unlimited + white-label metadata

Cache:
  - TTL-based disk cache (1h default) at data/cache/ioc_cache/
  - Keyed by ioc_type:value hash; prevents redundant API calls

Zero-Regression Mandates:
  - NEVER raises unhandled exceptions (all errors returned as structured dicts)
  - NEVER modifies source intel data
  - NEVER writes credentials to disk
  - Atomic cache writes (tmp -> rename)

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] IOC-ENGINE %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-IOC")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = Path(__file__).resolve().parent.parent
CACHE_DIR  = BASE_DIR / "data" / "cache" / "ioc_cache"
QUOTA_FILE = BASE_DIR / "data" / "cache" / "ioc_quota.json"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
QUOTA_FILE.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
VT_API_KEY:        str = os.environ.get("VT_API_KEY", "").strip()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CACHE_TTL_SECONDS: int  = 3600        # 1 hour default
VT_RATE_LIMIT_DELAY: float = 15.1     # 4 req/min free tier → 15s between calls
ABUSEIPDB_BASE     = "https://api.abuseipdb.com/api/v2"
VT_BASE            = "https://www.virustotal.com/api/v3"

# Tier daily quotas for FREE users
FREE_DAILY_QUOTA: int = 5

# Upgrade CTA injected for FREE tier responses
_UPGRADE_CTA = {
    "upgrade_available": True,
    "upgrade_url": "https://intel.cyberdudebivash.com/api",
    "upgrade_plan": "PRO ($49/mo)",
    "upgrade_message": (
        "Unlock unlimited IOC reputation lookups, full VirusTotal multi-engine "
        "analysis, threat context, STIX output, and bulk scanning. "
        "Upgrade to PRO or ENTERPRISE."
    ),
}

# Verdict thresholds
VERDICT_MALICIOUS   = "MALICIOUS"
VERDICT_SUSPICIOUS  = "SUSPICIOUS"
VERDICT_CLEAN       = "CLEAN"
VERDICT_UNKNOWN     = "UNKNOWN"

# IOC type identifiers
IOC_IP     = "ip"
IOC_DOMAIN = "domain"
IOC_URL    = "url"
IOC_HASH   = "hash"

# ---------------------------------------------------------------------------
# IOC Type Detection
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_SHA1_RE   = re.compile(r'^[a-fA-F0-9]{40}$')
_MD5_RE    = re.compile(r'^[a-fA-F0-9]{32}$')
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def detect_ioc_type(value: str) -> str:
    """
    Auto-detect IOC type from value string.
    Returns one of: 'ip', 'domain', 'url', 'hash', 'unknown'
    """
    v = value.strip()

    # URL check first (has scheme)
    if v.startswith(("http://", "https://", "ftp://")):
        return IOC_URL

    # IP address
    try:
        ipaddress.ip_address(v)
        return IOC_IP
    except ValueError:
        pass

    # Hash
    if _SHA256_RE.match(v):
        return IOC_HASH
    if _SHA1_RE.match(v):
        return IOC_HASH
    if _MD5_RE.match(v):
        return IOC_HASH

    # Domain
    if _DOMAIN_RE.match(v):
        return IOC_DOMAIN

    return "unknown"


def _hash_algorithm(value: str) -> str:
    v = value.strip()
    if _SHA256_RE.match(v):
        return "SHA-256"
    if _SHA1_RE.match(v):
        return "SHA-1"
    if _MD5_RE.match(v):
        return "MD5"
    return "unknown"


# ---------------------------------------------------------------------------
# Quota Management (FREE tier daily cap)
# ---------------------------------------------------------------------------

def _load_quota() -> Dict:
    try:
        if QUOTA_FILE.exists() and QUOTA_FILE.stat().st_size > 0:
            return json.loads(QUOTA_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_quota(data: Dict) -> None:
    try:
        tmp = QUOTA_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(QUOTA_FILE)
    except Exception as e:
        logger.warning(f"Quota save failed: {e}")


def check_and_increment_quota(tier: str, key_prefix: str = "default") -> Tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    PRO+ always allowed. FREE enforced against FREE_DAILY_QUOTA.
    """
    if tier in ("PRO", "ENTERPRISE", "MSSP"):
        return True, "ok"

    quota = _load_quota()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    day_key = f"{key_prefix}:{today}"
    used = quota.get(day_key, 0)

    if used >= FREE_DAILY_QUOTA:
        return False, (
            f"FREE tier quota exhausted ({used}/{FREE_DAILY_QUOTA} lookups today). "
            f"Upgrade to PRO for unlimited lookups."
        )

    quota[day_key] = used + 1
    _save_quota(quota)
    return True, f"{used + 1}/{FREE_DAILY_QUOTA} daily lookups used"


# ---------------------------------------------------------------------------
# Disk Cache
# ---------------------------------------------------------------------------

def _cache_key(ioc_type: str, value: str) -> str:
    h = hashlib.sha256(f"{ioc_type}:{value.lower().strip()}".encode()).hexdigest()[:32]
    return h


def _cache_path(cache_key: str) -> Path:
    return CACHE_DIR / f"{cache_key}.json"


def _cache_get(ioc_type: str, value: str, ttl: int = CACHE_TTL_SECONDS) -> Optional[Dict]:
    path = _cache_path(_cache_key(ioc_type, value))
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            cached_at = data.get("_cached_at", 0)
            if (time.time() - cached_at) < ttl:
                logger.debug(f"Cache HIT: {ioc_type}:{value[:30]}")
                return data.get("payload")
    except Exception as e:
        logger.debug(f"Cache read error: {e}")
    return None


def _cache_set(ioc_type: str, value: str, payload: Dict) -> None:
    path = _cache_path(_cache_key(ioc_type, value))
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"_cached_at": time.time(), "payload": payload}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(path)
    except Exception as e:
        logger.debug(f"Cache write error: {e}")


# ---------------------------------------------------------------------------
# HTTP Helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: Dict[str, str], timeout: int = 15) -> Tuple[int, Dict]:
    """
    Minimal HTTP GET using stdlib urllib only (zero external deps).
    Returns (status_code, parsed_json_or_error_dict).
    """
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# AbuseIPDB Source
# ---------------------------------------------------------------------------

def _query_abuseipdb(ip: str) -> Dict:
    """
    Query AbuseIPDB for IP reputation.
    Returns structured result or error dict.
    """
    if not ABUSEIPDB_API_KEY:
        return {
            "source": "AbuseIPDB",
            "available": False,
            "reason": "ABUSEIPDB_API_KEY not configured",
        }

    url = f"{ABUSEIPDB_BASE}/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose=true"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    status, body = _http_get(url, headers)

    if status != 200:
        return {
            "source": "AbuseIPDB",
            "available": False,
            "status_code": status,
            "reason": body.get("errors", [{}])[0].get("detail", str(body)) if "errors" in body else str(body),
        }

    d = body.get("data", {})
    score = d.get("abuseConfidenceScore", 0)

    # Derive verdict
    if score >= 75:
        verdict = VERDICT_MALICIOUS
    elif score >= 25:
        verdict = VERDICT_SUSPICIOUS
    elif score == 0 and d.get("totalReports", 0) == 0:
        verdict = VERDICT_CLEAN
    else:
        verdict = VERDICT_SUSPICIOUS

    # Extract recent reports
    reports = d.get("reports", [])[:5]
    report_categories = []
    for r in reports:
        cats = r.get("categories", [])
        report_categories.extend(cats)

    return {
        "source": "AbuseIPDB",
        "available": True,
        "verdict": verdict,
        "abuse_confidence_score": score,
        "total_reports": d.get("totalReports", 0),
        "distinct_users_reporting": d.get("numDistinctUsers", 0),
        "last_reported_at": d.get("lastReportedAt"),
        "country_code": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"),
        "is_tor": d.get("isTor", False),
        "is_whitelisted": d.get("isWhitelisted", False),
        "report_categories": list(set(report_categories)),
        "recent_reports_sample": [
            {
                "reported_at": r.get("reportedAt"),
                "categories": r.get("categories", []),
                "comment_preview": (r.get("comment") or "")[:100],
            }
            for r in reports
        ],
    }


# ---------------------------------------------------------------------------
# VirusTotal Source
# ---------------------------------------------------------------------------

def _query_vt_ip(ip: str) -> Dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "available": False, "reason": "VT_API_KEY not configured"}

    url = f"{VT_BASE}/ip_addresses/{urllib.parse.quote(ip)}"
    return _parse_vt_response("VirusTotal", url, {"x-apikey": VT_API_KEY})


def _query_vt_domain(domain: str) -> Dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "available": False, "reason": "VT_API_KEY not configured"}

    url = f"{VT_BASE}/domains/{urllib.parse.quote(domain)}"
    return _parse_vt_response("VirusTotal", url, {"x-apikey": VT_API_KEY})


def _query_vt_url(url_ioc: str) -> Dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "available": False, "reason": "VT_API_KEY not configured"}

    # VT URL lookup requires URL-safe base64 encoding of the URL (no padding)
    import base64
    url_id = base64.urlsafe_b64encode(url_ioc.encode()).rstrip(b"=").decode()
    url = f"{VT_BASE}/urls/{url_id}"
    return _parse_vt_response("VirusTotal", url, {"x-apikey": VT_API_KEY})


def _query_vt_hash(file_hash: str) -> Dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "available": False, "reason": "VT_API_KEY not configured"}

    url = f"{VT_BASE}/files/{file_hash.lower()}"
    return _parse_vt_response("VirusTotal", url, {"x-apikey": VT_API_KEY})


def _parse_vt_response(source: str, url: str, headers: Dict) -> Dict:
    """Parse VirusTotal v3 API response into structured format."""
    status, body = _http_get(url, headers)

    if status == 404:
        return {"source": source, "available": True, "verdict": VERDICT_UNKNOWN, "reason": "not_found_in_vt"}
    if status == 429:
        return {"source": source, "available": False, "reason": "rate_limited", "retry_after": 60}
    if status != 200:
        return {
            "source": source,
            "available": False,
            "status_code": status,
            "reason": body.get("error", {}).get("message", str(body)),
        }

    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    # Compute detection ratio
    detection_ratio = f"{malicious}/{total_engines}" if total_engines > 0 else "0/0"

    # Derive verdict
    if malicious >= 5:
        verdict = VERDICT_MALICIOUS
    elif malicious >= 1 or suspicious >= 3:
        verdict = VERDICT_SUSPICIOUS
    elif total_engines > 0 and malicious == 0:
        verdict = VERDICT_CLEAN
    else:
        verdict = VERDICT_UNKNOWN

    # Reputation score (VT provides this for IPs/domains, -100 to 100)
    reputation = attrs.get("reputation")

    # Tags / categories
    categories = attrs.get("categories", {})
    tags = attrs.get("tags", [])

    # Malicious engine names (top 10)
    analysis_results = attrs.get("last_analysis_results", {})
    malicious_engines = [
        engine for engine, result in analysis_results.items()
        if result.get("category") in ("malicious", "suspicious")
    ][:10]

    # WHOIS data (redacted to safe fields)
    whois_date = attrs.get("whois_date")
    creation_date = attrs.get("creation_date")
    last_modification_date = attrs.get("last_modification_date")

    # Network info
    asn = attrs.get("asn")
    as_owner = attrs.get("as_owner")
    country = attrs.get("country")
    network = attrs.get("network")

    # File-specific
    file_type = attrs.get("type_description")
    file_size = attrs.get("size")
    names = attrs.get("names", [])[:5]

    return {
        "source": source,
        "available": True,
        "verdict": verdict,
        "detection_ratio": detection_ratio,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "harmless_engines": harmless,
        "undetected_engines": undetected,
        "total_engines": total_engines,
        "malicious_engine_names": malicious_engines,
        "reputation_score": reputation,
        "categories": categories,
        "tags": tags,
        "asn": asn,
        "as_owner": as_owner,
        "country": country,
        "network": network,
        "file_type": file_type,
        "file_size_bytes": file_size,
        "known_filenames": names,
        "whois_date": whois_date,
        "creation_date": creation_date,
        "last_modification_date": last_modification_date,
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


# ---------------------------------------------------------------------------
# Composite Verdict Engine
# ---------------------------------------------------------------------------

def _compute_composite_verdict(sources: List[Dict]) -> Dict:
    """
    Combine verdicts from multiple sources into a single authoritative verdict.
    Weighted scoring: MALICIOUS=10, SUSPICIOUS=4, UNKNOWN=0, CLEAN=-2
    """
    weight_map = {
        VERDICT_MALICIOUS:  10,
        VERDICT_SUSPICIOUS:  4,
        VERDICT_UNKNOWN:     0,
        VERDICT_CLEAN:      -2,
    }

    total_score = 0
    contributing_sources = 0
    verdict_votes: Dict[str, int] = {}

    for src in sources:
        if not src.get("available"):
            continue
        v = src.get("verdict", VERDICT_UNKNOWN)
        total_score += weight_map.get(v, 0)
        contributing_sources += 1
        verdict_votes[v] = verdict_votes.get(v, 0) + 1

    if contributing_sources == 0:
        return {
            "verdict": VERDICT_UNKNOWN,
            "confidence": "LOW",
            "score": 0,
            "sources_consulted": 0,
        }

    avg_score = total_score / contributing_sources

    if avg_score >= 7:
        verdict = VERDICT_MALICIOUS
        confidence = "HIGH" if contributing_sources >= 2 else "MEDIUM"
    elif avg_score >= 2:
        verdict = VERDICT_SUSPICIOUS
        confidence = "MEDIUM"
    elif avg_score < 0:
        verdict = VERDICT_CLEAN
        confidence = "HIGH" if contributing_sources >= 2 else "MEDIUM"
    else:
        verdict = VERDICT_UNKNOWN
        confidence = "LOW"

    # SOC priority mapping
    soc_priority_map = {
        VERDICT_MALICIOUS:  "P1",
        VERDICT_SUSPICIOUS: "P2",
        VERDICT_UNKNOWN:    "P3",
        VERDICT_CLEAN:      "P4",
    }

    return {
        "verdict": verdict,
        "confidence": confidence,
        "composite_score": round(avg_score, 2),
        "sources_consulted": contributing_sources,
        "verdict_votes": verdict_votes,
        "soc_priority": soc_priority_map.get(verdict, "P3"),
        "action_required": verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS),
    }


# ---------------------------------------------------------------------------
# SOC Recommendations
# ---------------------------------------------------------------------------

_SOC_ACTIONS: Dict[str, List[str]] = {
    VERDICT_MALICIOUS: [
        "BLOCK immediately at perimeter firewall and DNS resolver.",
        "Isolate any endpoints that communicated with this IOC.",
        "Search SIEM/EDR for historical connections (last 90 days).",
        "Open P1 incident ticket — escalate to SOC Lead.",
        "Document in threat intel feed and share with ISAC.",
    ],
    VERDICT_SUSPICIOUS: [
        "Add to watchlist and enable enhanced logging.",
        "Review recent connections from this IOC in your SIEM.",
        "Consider blocking if non-essential business traffic.",
        "Correlate with other IOCs in the same campaign.",
        "Re-check reputation in 24h — verdict may change.",
    ],
    VERDICT_UNKNOWN: [
        "Monitor passively — insufficient data for verdict.",
        "Enable logging for any future connections.",
        "Submit to VirusTotal/AbuseIPDB for community analysis.",
    ],
    VERDICT_CLEAN: [
        "No action required based on current intelligence.",
        "Continue standard monitoring per baseline policy.",
    ],
}


def _get_soc_actions(verdict: str) -> List[str]:
    return _SOC_ACTIONS.get(verdict, _SOC_ACTIONS[VERDICT_UNKNOWN])


# ---------------------------------------------------------------------------
# Main Lookup Functions
# ---------------------------------------------------------------------------

def lookup_ioc(
    value: str,
    tier: str = "FREE",
    ioc_type: Optional[str] = None,
    key_prefix: str = "default",
    force_refresh: bool = False,
) -> Dict:
    """
    Primary IOC reputation lookup.
    Auto-detects IOC type, queries all available sources, returns composite verdict.

    Args:
        value:         IOC value (IP, domain, URL, hash)
        tier:          API key tier (FREE/PRO/ENTERPRISE/MSSP)
        ioc_type:      Override auto-detection ('ip'/'domain'/'url'/'hash')
        key_prefix:    API key prefix for quota tracking
        force_refresh: Bypass cache

    Returns:
        Structured dict with composite verdict, source details, SOC actions.
    """
    value = value.strip()
    if not value:
        return {"error": "empty_ioc_value", "verdict": VERDICT_UNKNOWN}

    # Detect type
    detected_type = ioc_type or detect_ioc_type(value)
    if detected_type == "unknown":
        return {
            "error": "unrecognized_ioc_format",
            "value": value,
            "verdict": VERDICT_UNKNOWN,
            "hint": "Expected: IPv4/IPv6, domain, URL (http/https), or hex hash (32/40/64 chars)",
        }

    # Quota check
    allowed, quota_msg = check_and_increment_quota(tier, key_prefix)
    if not allowed:
        return {
            "error": "quota_exceeded",
            "tier": tier,
            "message": quota_msg,
            "upgrade_cta": _UPGRADE_CTA,
        }

    # Cache check
    if not force_refresh:
        cached = _cache_get(detected_type, value)
        if cached:
            cached["_from_cache"] = True
            return cached

    # --- Query sources ---
    sources_raw: List[Dict] = []
    ts_start = time.time()

    if detected_type == IOC_IP:
        ab_result = _query_abuseipdb(value)
        sources_raw.append(ab_result)

        if tier != "FREE":
            vt_result = _query_vt_ip(value)
            sources_raw.append(vt_result)
        else:
            sources_raw.append({
                "source": "VirusTotal",
                "available": False,
                "reason": "PRO_REQUIRED",
                "upgrade_cta": _UPGRADE_CTA,
            })

    elif detected_type == IOC_DOMAIN:
        if tier != "FREE":
            vt_result = _query_vt_domain(value)
            sources_raw.append(vt_result)
        else:
            sources_raw.append({
                "source": "VirusTotal",
                "available": False,
                "reason": "PRO_REQUIRED",
                "upgrade_cta": _UPGRADE_CTA,
            })

        sources_raw.append({
            "source": "AbuseIPDB",
            "available": False,
            "reason": "AbuseIPDB_IP_ONLY",
            "note": "Resolve domain to IP for AbuseIPDB lookup",
        })

    elif detected_type == IOC_URL:
        if tier != "FREE":
            vt_result = _query_vt_url(value)
            sources_raw.append(vt_result)
        else:
            sources_raw.append({
                "source": "VirusTotal",
                "available": False,
                "reason": "PRO_REQUIRED",
                "upgrade_cta": _UPGRADE_CTA,
            })

    elif detected_type == IOC_HASH:
        if tier != "FREE":
            vt_result = _query_vt_hash(value)
            sources_raw.append(vt_result)
        else:
            sources_raw.append({
                "source": "VirusTotal",
                "available": False,
                "reason": "PRO_REQUIRED",
                "upgrade_cta": _UPGRADE_CTA,
            })

    # Compute composite verdict
    composite = _compute_composite_verdict(sources_raw)
    verdict = composite["verdict"]

    # Build final result
    result: Dict[str, Any] = {
        "ioc_value":    value,
        "ioc_type":     detected_type,
        "lookup_time_iso": datetime.now(timezone.utc).isoformat(),
        "lookup_ms":    round((time.time() - ts_start) * 1000),
        "tier_used":    tier,
        "composite":    composite,
        "sources":      sources_raw,
        "soc_actions":  _get_soc_actions(verdict),
        "_from_cache":  False,
    }

    # Hash algorithm label for hash IOCs
    if detected_type == IOC_HASH:
        result["hash_algorithm"] = _hash_algorithm(value)

    # Inject STIX for ENTERPRISE/MSSP (PRO gated)
    if tier in ("ENTERPRISE", "MSSP") and verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
        result["stix_indicator"] = _build_stix_indicator(value, detected_type, verdict)

    # Inject upgrade CTA for FREE tier
    if tier == "FREE":
        result["upgrade_cta"] = _UPGRADE_CTA

    # Cache the result
    _cache_set(detected_type, value, result)

    return result


# ---------------------------------------------------------------------------
# Bulk Scan (ENTERPRISE/MSSP only)
# ---------------------------------------------------------------------------

def bulk_scan(
    ioc_list: List[str],
    tier: str = "ENTERPRISE",
    key_prefix: str = "default",
    max_iocs: int = 500,
    delay_between: float = VT_RATE_LIMIT_DELAY,
) -> Dict:
    """
    Batch IOC reputation scan. ENTERPRISE/MSSP only.
    Respects VT rate limits with configurable inter-request delay.

    Returns:
        {
          "total": int,
          "malicious": int,
          "suspicious": int,
          "clean": int,
          "unknown": int,
          "results": [lookup_result, ...]
        }
    """
    if tier not in ("ENTERPRISE", "MSSP"):
        return {
            "error": "tier_insufficient",
            "required_tier": "ENTERPRISE",
            "current_tier": tier,
            "upgrade_cta": _UPGRADE_CTA,
        }

    ioc_list = [i.strip() for i in ioc_list if i.strip()][:max_iocs]
    results: List[Dict] = []

    verdict_counts: Dict[str, int] = {
        VERDICT_MALICIOUS: 0,
        VERDICT_SUSPICIOUS: 0,
        VERDICT_CLEAN: 0,
        VERDICT_UNKNOWN: 0,
    }

    for idx, ioc_val in enumerate(ioc_list):
        logger.info(f"Bulk scan [{idx + 1}/{len(ioc_list)}]: {ioc_val[:50]}")
        result = lookup_ioc(ioc_val, tier=tier, key_prefix=key_prefix)
        results.append(result)

        verdict = result.get("composite", {}).get("verdict", VERDICT_UNKNOWN)
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        # Rate limit delay (skip on cache hits)
        if not result.get("_from_cache") and idx < len(ioc_list) - 1:
            time.sleep(delay_between)

    # Sort by severity (malicious first)
    severity_order = {VERDICT_MALICIOUS: 0, VERDICT_SUSPICIOUS: 1, VERDICT_UNKNOWN: 2, VERDICT_CLEAN: 3}
    results.sort(key=lambda r: severity_order.get(
        r.get("composite", {}).get("verdict", VERDICT_UNKNOWN), 2
    ))

    return {
        "scan_type": "bulk",
        "tier_used": tier,
        "total_iocs": len(ioc_list),
        "completed": len(results),
        "verdict_summary": verdict_counts,
        "threat_iocs": [
            r["ioc_value"] for r in results
            if r.get("composite", {}).get("verdict") in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS)
        ],
        "results": results,
        "scan_completed_iso": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# STIX 2.1 Indicator Builder (ENTERPRISE+)
# ---------------------------------------------------------------------------

def _build_stix_indicator(value: str, ioc_type: str, verdict: str) -> Dict:
    """
    Build a STIX 2.1-compatible indicator object for malicious/suspicious IOCs.
    Lightweight representation suitable for SIEM import.
    """
    import uuid

    pattern_map = {
        IOC_IP:     f"[ipv4-addr:value = '{value}']",
        IOC_DOMAIN: f"[domain-name:value = '{value}']",
        IOC_URL:    f"[url:value = '{value}']",
        IOC_HASH:   f"[file:hashes.'SHA-256' = '{value}']",
    }

    confidence_map = {VERDICT_MALICIOUS: 85, VERDICT_SUSPICIOUS: 50}

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{str(uuid.uuid4())}",
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": f"CDB-IOC: {value[:60]}",
        "description": f"IOC flagged as {verdict} by SENTINEL APEX IOC Engine",
        "pattern": pattern_map.get(ioc_type, f"[unknown:value = '{value}']"),
        "pattern_type": "stix",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "labels": ["malicious-activity"] if verdict == VERDICT_MALICIOUS else ["anomalous-activity"],
        "confidence": confidence_map.get(verdict, 50),
        "created_by_ref": "identity--cyberdudebivash-sentinel-apex",
    }


# ---------------------------------------------------------------------------
# Cache Management
# ---------------------------------------------------------------------------

def clear_ioc_cache() -> Dict:
    """Purge all cached IOC lookups."""
    cleared = 0
    errors = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
            cleared += 1
        except Exception:
            errors += 1
    return {"cleared": cleared, "errors": errors}


def get_cache_stats() -> Dict:
    """Return cache statistics."""
    files = list(CACHE_DIR.glob("*.json"))
    stale = 0
    fresh = 0
    now = time.time()
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if (now - data.get("_cached_at", 0)) > CACHE_TTL_SECONDS:
                stale += 1
            else:
                fresh += 1
        except Exception:
            stale += 1
    return {
        "total_cached": len(files),
        "fresh": fresh,
        "stale": stale,
        "cache_dir": str(CACHE_DIR),
        "ttl_seconds": CACHE_TTL_SECONDS,
    }


# ---------------------------------------------------------------------------
# Integration: Feed-level IOC Enrichment
# ---------------------------------------------------------------------------

def enrich_intel_item(item: Dict, tier: str = "PRO", key_prefix: str = "system") -> Dict:
    """
    Enrich a single threat intel item with IOC reputation data.
    Queries reputation for IPs/domains found in item['iocs'] list.
    Returns enriched copy (never mutates source).

    Called by master_p0_fix.py or CI pipeline for PRO+ accounts.
    """
    import copy
    enriched = copy.deepcopy(item)

    iocs = enriched.get("iocs", [])
    if not iocs or tier == "FREE":
        return enriched

    ioc_results: List[Dict] = []
    malicious_count = 0
    suspicious_count = 0

    for ioc_val in iocs[:20]:  # cap at 20 IOCs per item to avoid rate limit
        if not isinstance(ioc_val, str) or len(ioc_val) < 3:
            continue
        res = lookup_ioc(ioc_val, tier=tier, key_prefix=key_prefix)
        ioc_results.append({
            "value":       ioc_val,
            "type":        res.get("ioc_type", "unknown"),
            "verdict":     res.get("composite", {}).get("verdict", VERDICT_UNKNOWN),
            "soc_priority": res.get("composite", {}).get("soc_priority", "P3"),
            "from_cache":  res.get("_from_cache", False),
        })
        v = res.get("composite", {}).get("verdict", VERDICT_UNKNOWN)
        if v == VERDICT_MALICIOUS:
            malicious_count += 1
        elif v == VERDICT_SUSPICIOUS:
            suspicious_count += 1

        # Rate limit courtesy
        if not res.get("_from_cache"):
            time.sleep(1.0)

    enriched["ioc_reputation"] = {
        "enriched": True,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs_checked": len(ioc_results),
        "malicious_confirmed": malicious_count,
        "suspicious_confirmed": suspicious_count,
        "results": ioc_results,
    }

    # Escalate risk_score if confirmed malicious IOCs found
    if malicious_count > 0:
        current_risk = enriched.get("risk_score", 5.0)
        enriched["risk_score"] = min(10.0, current_risk + (malicious_count * 0.5))
        enriched["ioc_escalated"] = True

    return enriched


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_result(result: Dict, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return

    if "error" in result:
        print(f"[ERROR] {result['error']}: {result.get('message', '')}")
        if "upgrade_cta" in result:
            print(f"[UPGRADE] {result['upgrade_cta']['upgrade_message']}")
        return

    composite = result.get("composite", {})
    verdict   = composite.get("verdict", "UNKNOWN")
    priority  = composite.get("soc_priority", "P3")
    confidence = composite.get("confidence", "LOW")
    score     = composite.get("composite_score", 0)

    verdict_colors = {
        "MALICIOUS":  "[!!] MALICIOUS",
        "SUSPICIOUS": "[!]  SUSPICIOUS",
        "CLEAN":      "[OK] CLEAN",
        "UNKNOWN":    "[?]  UNKNOWN",
    }

    print("=" * 70)
    print(f"  IOC Reputation Report — CYBERDUDEBIVASH SENTINEL APEX")
    print("=" * 70)
    print(f"  IOC        : {result.get('ioc_value')}")
    print(f"  Type       : {result.get('ioc_type', '').upper()}")
    print(f"  Verdict    : {verdict_colors.get(verdict, verdict)}")
    print(f"  SOC Priority: {priority}")
    print(f"  Confidence : {confidence}")
    print(f"  Score      : {score}/10")
    print(f"  Sources    : {composite.get('sources_consulted', 0)} consulted")
    print(f"  Cached     : {result.get('_from_cache', False)}")
    print("-" * 70)

    for src in result.get("sources", []):
        name = src.get("source", "?")
        if not src.get("available"):
            reason = src.get("reason", "unavailable")
            print(f"  [{name}] Unavailable — {reason}")
        else:
            sv = src.get("verdict", "?")
            print(f"  [{name}] Verdict: {sv}", end="")
            if "abuse_confidence_score" in src:
                print(f"  | AbuseScore: {src['abuse_confidence_score']}%  Reports: {src.get('total_reports', 0)}", end="")
            if "detection_ratio" in src:
                print(f"  | VT: {src['detection_ratio']} engines detected", end="")
            print()

    print("-" * 70)
    print("  SOC ACTIONS:")
    for i, action in enumerate(result.get("soc_actions", []), 1):
        print(f"  {i}. {action}")
    print("=" * 70)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — IOC Reputation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/ioc_reputation_engine.py --ioc 8.8.8.8
  python scripts/ioc_reputation_engine.py --ioc evil.example.com --tier PRO
  python scripts/ioc_reputation_engine.py --ioc https://malware.site/payload --tier PRO
  python scripts/ioc_reputation_engine.py --ioc d41d8cd98f00b204e9800998ecf8427e --tier ENTERPRISE
  python scripts/ioc_reputation_engine.py --bulk ips.txt --tier ENTERPRISE
  python scripts/ioc_reputation_engine.py --cache-stats
  python scripts/ioc_reputation_engine.py --cache-clear
        """,
    )
    parser.add_argument("--ioc",        type=str, help="Single IOC to check (IP/domain/URL/hash)")
    parser.add_argument("--ioc-type",   type=str, choices=["ip", "domain", "url", "hash"],
                        help="Force IOC type (overrides auto-detect)")
    parser.add_argument("--bulk",       type=str, help="Path to file with one IOC per line (ENTERPRISE+)")
    parser.add_argument("--tier",       type=str, default="FREE",
                        choices=["FREE", "PRO", "ENTERPRISE", "MSSP"],
                        help="API tier (default: FREE)")
    parser.add_argument("--json",       action="store_true", help="Output JSON instead of human-readable")
    parser.add_argument("--force-refresh", action="store_true", help="Bypass cache")
    parser.add_argument("--cache-stats",   action="store_true", help="Show cache statistics")
    parser.add_argument("--cache-clear",   action="store_true", help="Clear IOC reputation cache")
    parser.add_argument("--quota",      action="store_true", help="Show current quota usage")

    args = parser.parse_args()

    # API key status report
    logger.info(f"AbuseIPDB API key: {'configured' if ABUSEIPDB_API_KEY else 'NOT configured'}")
    logger.info(f"VirusTotal API key: {'configured' if VT_API_KEY else 'NOT configured'}")

    if args.cache_stats:
        stats = get_cache_stats()
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return

    if args.cache_clear:
        result = clear_ioc_cache()
        print(f"Cache cleared: {result['cleared']} files removed, {result['errors']} errors")
        return

    if args.quota:
        quota = _load_quota()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_keys = {k: v for k, v in quota.items() if today in k}
        print(json.dumps({"today": today, "usage": today_keys, "free_limit": FREE_DAILY_QUOTA}, indent=2, ensure_ascii=False))
        return

    if args.bulk:
        bulk_file = Path(args.bulk)
        if not bulk_file.exists():
            print(f"[ERROR] File not found: {args.bulk}")
            sys.exit(1)
        ioc_list = [line.strip() for line in bulk_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        result = bulk_scan(ioc_list, tier=args.tier)
        if args.json:
            print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        else:
            print(f"\nBulk Scan Complete: {result['completed']}/{result['total_iocs']} IOCs")
            print(f"Verdict Summary: {result['verdict_summary']}")
            print(f"\nThreat IOCs ({len(result['threat_iocs'])}):")
            for t in result['threat_iocs']:
                print(f"  - {t}")
        return

    if args.ioc:
        result = lookup_ioc(
            value=args.ioc,
            tier=args.tier,
            ioc_type=args.ioc_type,
            force_refresh=args.force_refresh,
        )
        _print_result(result, output_json=args.json)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
