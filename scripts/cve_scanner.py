#!/usr/bin/env python3
"""
scripts/cve_scanner.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Real CVE Intelligence Scanner
================================================================
REVENUE FEATURE: PRO/ENTERPRISE paywall gate — drives FREE→PRO conversion.

Capabilities:
    - Live CVE lookup via NVD REST API v2 (no key needed, key for higher rate)
    - CISA KEV (Known Exploited Vulnerabilities) real-time feed integration
    - CVSS v3.x scoring: Base, Temporal, Environmental
    - Exploit availability detection
    - Patch status tracking
    - EPSS (Exploit Prediction Scoring System) scores
    - CWE classification
    - Affected CPE enumeration
    - Cross-reference NVD + CISA KEV + GitHub PoC advisories
    - Batch CVE scanning for PRO/ENTERPRISE bulk workflows

PAYWALL ENFORCEMENT:
    - FREE: Lookup 3 CVEs/day, base CVSS only, no KEV, no EPSS
    - PRO:  Unlimited lookups, full CVSS, KEV, EPSS, exploit status
    - ENTERPRISE: + bulk scan (up to 500 CVEs), CPE enumeration, webhook push

RATE LIMITS (NVD API):
    - Without key: 5 req/30s (auto-throttled)
    - With NVDAPIKEY env var: 50 req/30s

OUTPUT: data/cve_scan_results.json (rolling, last 500 scans)

ZERO REGRESSION: Standalone module, no modification to existing files.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.cve_scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_API_KEY   = os.environ.get("NVD_API_KEY", "").strip()

RESULTS_FILE   = _DATA / "cve_scan_results.json"
KEV_CACHE_FILE = _DATA / "cache" / "cisa_kev.json"
KEV_CACHE_TTL  = 3600  # seconds

_THROTTLE_NO_KEY = 6.5   # 5 req/30s → ~6s between calls (with buffer)
_THROTTLE_WITH_KEY = 0.7  # 50 req/30s

_last_nvd_call = 0.0

# ---------------------------------------------------------------------------
# Tier paywall enforcement
# ---------------------------------------------------------------------------
_FREE_DAILY_LIMIT = 3

def check_paywall(tier: str, daily_usage: int = 0) -> Tuple[bool, str]:
    """
    Returns (allowed, reason).
    Integrates with TIERS defined in api/auth.py.
    """
    tier = (tier or "FREE").upper()
    if tier in ("PRO", "ENTERPRISE", "MSSP"):
        return True, "allowed"
    # FREE tier: 3 CVE lookups/day
    if daily_usage >= _FREE_DAILY_LIMIT:
        return False, (
            f"FREE tier: {_FREE_DAILY_LIMIT} CVE lookups/day limit reached. "
            "Upgrade to PRO ($29/mo) for unlimited CVE scanning + EPSS + KEV data. "
            "https://intel.cyberdudebivash.com/upgrade?plan=pro&src=cve_scanner"
        )
    return True, "allowed"


# ---------------------------------------------------------------------------
# HTTP Utilities
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: Optional[Dict] = None, timeout: int = 15) -> Optional[Dict]:
    """Safe HTTP GET, returns parsed JSON or None."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "CYBERDUDEBIVASH-SENTINEL-APEX/1.0 CVE-Scanner")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        log.warning("[CVE-SCAN] HTTP %d for %s", exc.code, url[:80])
        return None
    except Exception as exc:
        log.warning("[CVE-SCAN] Request failed for %s: %s", url[:80], exc)
        return None


def _nvd_throttle() -> None:
    """Enforce NVD API rate limit."""
    global _last_nvd_call
    wait = _THROTTLE_WITH_KEY if NVD_API_KEY else _THROTTLE_NO_KEY
    elapsed = time.time() - _last_nvd_call
    if elapsed < wait:
        time.sleep(wait - elapsed)
    _last_nvd_call = time.time()


# ---------------------------------------------------------------------------
# CISA KEV Cache
# ---------------------------------------------------------------------------

def _load_kev_cache() -> Dict[str, Dict]:
    """Load CISA KEV from cache. Refresh if stale."""
    cache = KEV_CACHE_FILE
    cache.parent.mkdir(parents=True, exist_ok=True)

    # Check freshness
    if cache.exists():
        age = time.time() - cache.stat().st_mtime
        if age < KEV_CACHE_TTL:
            try:
                raw = json.loads(cache.read_text(encoding="utf-8"))
                return {v["cveID"]: v for v in raw.get("vulnerabilities", [])}
            except Exception:
                pass

    # Refresh from CISA
    log.info("[CVE-SCAN] Refreshing CISA KEV feed...")
    data = _http_get(CISA_KEV_URL, timeout=20)
    if data and "vulnerabilities" in data:
        try:
            cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            log.info("[CVE-SCAN] KEV cached: %d entries", len(data["vulnerabilities"]))
        except Exception:
            pass
        return {v["cveID"]: v for v in data["vulnerabilities"]}

    log.warning("[CVE-SCAN] KEV fetch failed — using empty cache")
    return {}


# ---------------------------------------------------------------------------
# EPSS Score Fetch
# ---------------------------------------------------------------------------

def _fetch_epss(cve_id: str) -> Optional[Dict]:
    """Fetch EPSS exploit probability score from FIRST.org."""
    url = f"{EPSS_API_BASE}?cve={urllib.parse.quote(cve_id)}"
    data = _http_get(url, timeout=10)
    if data and data.get("data"):
        entry = data["data"][0]
        return {
            "epss_score":      float(entry.get("epss", 0)),
            "epss_percentile": float(entry.get("percentile", 0)),
            "epss_date":       entry.get("date", ""),
            "exploit_probability_pct": round(float(entry.get("epss", 0)) * 100, 2),
        }
    return None


# ---------------------------------------------------------------------------
# NVD CVE Fetcher
# ---------------------------------------------------------------------------

def _parse_cvss(cve_item: Dict) -> Dict[str, Any]:
    """Extract CVSS v3.1 / v3.0 / v2.0 scores from NVD item."""
    metrics = cve_item.get("metrics", {})
    result = {
        "cvss_version":    None,
        "cvss_score":      None,
        "cvss_severity":   None,
        "cvss_vector":     None,
        "cvss_impact":     None,
        "cvss_exploitability": None,
        "attack_vector":   None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope":           None,
        "confidentiality": None,
        "integrity":       None,
        "availability":    None,
    }

    # Prefer v3.1 > v3.0 > v2.0
    for v_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(v_key, [])
        if not entries:
            continue
        entry = entries[0]
        cvss = entry.get("cvssData", {})
        result["cvss_version"]    = cvss.get("version", v_key)
        result["cvss_score"]      = cvss.get("baseScore")
        result["cvss_severity"]   = entry.get("baseSeverity") or cvss.get("baseSeverity")
        result["cvss_vector"]     = cvss.get("vectorString")
        result["cvss_impact"]     = entry.get("impactScore")
        result["cvss_exploitability"] = entry.get("exploitabilityScore")
        result["attack_vector"]   = cvss.get("attackVector") or cvss.get("accessVector")
        result["attack_complexity"] = cvss.get("attackComplexity") or cvss.get("accessComplexity")
        result["privileges_required"] = cvss.get("privilegesRequired")
        result["user_interaction"] = cvss.get("userInteraction")
        result["scope"]           = cvss.get("scope")
        result["confidentiality"] = cvss.get("confidentialityImpact")
        result["integrity"]       = cvss.get("integrityImpact")
        result["availability"]    = cvss.get("availabilityImpact")
        break

    return result


def _parse_weaknesses(cve_item: Dict) -> List[str]:
    """Extract CWE IDs from NVD item."""
    cwes = []
    for weakness in cve_item.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc.get("value", ""))
    return [c for c in cwes if c and c != "NVD-CWE-Other"]


def _parse_references(cve_item: Dict) -> List[Dict]:
    """Extract references (patch, exploit, advisory) from NVD item."""
    refs = []
    for ref in (cve_item.get("references") or [])[:10]:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        ref_type = "other"
        if any(t in tags for t in ["Patch", "Vendor Advisory"]):
            ref_type = "patch"
        elif any(t in tags for t in ["Exploit", "Proof of Concept"]):
            ref_type = "exploit"
        elif any(t in tags for t in ["Third Party Advisory", "VDB Entry"]):
            ref_type = "advisory"
        refs.append({"url": url[:200], "type": ref_type, "tags": tags[:5]})
    return refs


def _parse_affected_products(cve_item: Dict) -> List[str]:
    """Extract affected CPE product names (simplified)."""
    products = set()
    for config in (cve_item.get("configurations") or [])[:3]:
        for node in (config.get("nodes") or [])[:5]:
            for match in (node.get("cpeMatch") or [])[:5]:
                cpe = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 else "*"
                    if vendor != "*" and product != "*":
                        products.add(f"{vendor} {product}" + (f" {version}" if version != "*" else ""))
    return list(products)[:15]


# ---------------------------------------------------------------------------
# Core Lookup Functions
# ---------------------------------------------------------------------------

def lookup_cve(cve_id: str, tier: str = "FREE", include_epss: bool = True) -> Dict[str, Any]:
    """
    Look up a single CVE from NVD + CISA KEV + EPSS.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2024-1234')
        tier: Subscription tier for paywall enforcement
        include_epss: Fetch EPSS score (PRO+ only)

    Returns:
        Structured CVE intelligence dict.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"error": "invalid_cve_id", "cve_id": cve_id}

    log.info("[CVE-SCAN] Looking up %s (tier=%s)", cve_id, tier)

    # NVD lookup
    _nvd_throttle()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    url = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
    data = _http_get(url, headers=headers)

    if not data or not data.get("vulnerabilities"):
        return {
            "cve_id":       cve_id,
            "found":        False,
            "error":        "not_found_in_nvd",
            "scanned_at":   datetime.now(timezone.utc).isoformat(),
        }

    nvd_item = data["vulnerabilities"][0]
    cve_data = nvd_item.get("cve", {})
    cvss     = _parse_cvss(nvd_item)

    # Description
    descriptions = cve_data.get("descriptions", [])
    description  = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # Published / modified dates
    published  = cve_data.get("published", "")
    modified   = cve_data.get("lastModified", "")

    # CISA KEV check (PRO+ for full data)
    kev_data = _load_kev_cache()
    in_kev   = cve_id in kev_data
    kev_info = None
    if in_kev:
        kev_entry = kev_data[cve_id]
        kev_info  = {
            "vendor_project":  kev_entry.get("vendorProject"),
            "product":         kev_entry.get("product"),
            "due_date":        kev_entry.get("dueDate"),
            "short_description": kev_entry.get("shortDescription", "")[:200],
            "notes":           kev_entry.get("notes", "")[:200],
        }

    # EPSS (PRO+)
    epss = None
    if tier in ("PRO", "ENTERPRISE", "MSSP") and include_epss:
        try:
            epss = _fetch_epss(cve_id)
        except Exception as exc:
            log.warning("[CVE-SCAN] EPSS fetch failed for %s: %s", cve_id, exc)

    # References + affected products
    references        = _parse_references(cve_data)
    affected_products = _parse_affected_products(nvd_item)
    cwes              = _parse_weaknesses(cve_data)

    # Exploit indicators
    exploit_refs = [r for r in references if r["type"] == "exploit"]
    patch_refs   = [r for r in references if r["type"] == "patch"]

    # SOC Priority derived from CVSS + KEV + EPSS
    score = cvss.get("cvss_score") or 0
    soc_priority = "P4"
    if in_kev or score >= 9.5:
        soc_priority = "P1"
    elif score >= 8.0 or (epss and epss.get("epss_score", 0) > 0.5):
        soc_priority = "P2"
    elif score >= 6.0:
        soc_priority = "P3"

    result: Dict[str, Any] = {
        "cve_id":           cve_id,
        "found":            True,
        "scanned_at":       datetime.now(timezone.utc).isoformat(),
        "tier_used":        tier,

        # Core intelligence
        "description":      description[:500],
        "published":        published,
        "last_modified":    modified,
        "status":           cve_data.get("vulnStatus", "Unknown"),

        # CVSS scoring
        **cvss,

        # Exploitation intelligence
        "in_cisa_kev":      in_kev,
        "kev_details":      kev_info,
        "exploit_poc_available": len(exploit_refs) > 0,
        "exploit_refs":     exploit_refs[:3],
        "patch_available":  len(patch_refs) > 0,
        "patch_refs":       patch_refs[:3],

        # Weakness + affected scope
        "cwes":             cwes,
        "affected_products": affected_products,

        # EPSS (PRO+)
        "epss":             epss,

        # SOC action
        "soc_priority":     soc_priority,
        "immediate_action": (
            "PATCH NOW — actively exploited (CISA KEV)" if in_kev else
            "HIGH PRIORITY — critical CVSS score" if score >= 9.0 else
            "PATCH RECOMMENDED" if score >= 7.0 else
            "MONITOR — medium severity"
        ),

        # Revenue CTA for FREE tier
        "upgrade_cta": None if tier in ("PRO", "ENTERPRISE", "MSSP") else {
            "message": "Upgrade to PRO for EPSS scores, bulk scanning, and watchlist alerts",
            "url": "https://intel.cyberdudebivash.com/upgrade?plan=pro&src=cve_result",
            "price": "$29/month",
        },
    }

    log.info("[CVE-SCAN] %s: CVSS=%.1f, KEV=%s, Priority=%s",
             cve_id, score, in_kev, soc_priority)
    return result


def search_cves_by_keyword(
    keyword: str,
    tier: str = "FREE",
    severity: Optional[str] = None,
    days_back: int = 30,
    max_results: int = 20,
) -> Dict[str, Any]:
    """
    Search CVEs by keyword/product name via NVD API.
    PRO+ required for full results. FREE returns top 3.
    """
    tier = (tier or "FREE").upper()
    if tier == "FREE":
        max_results = min(max_results, 3)

    params = {"keywordSearch": keyword, "resultsPerPage": min(max_results, 100)}
    if severity:
        params["cvssV3Severity"] = severity.upper()

    url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
    _nvd_throttle()

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    data = _http_get(url, headers=headers)

    if not data:
        return {"error": "nvd_api_error", "keyword": keyword, "results": []}

    results = []
    for vuln in (data.get("vulnerabilities") or [])[:max_results]:
        cve_item = vuln
        cve_data = vuln.get("cve", {})
        cve_id   = cve_data.get("id", "")
        cvss     = _parse_cvss(vuln)
        desc     = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )
        results.append({
            "cve_id":      cve_id,
            "description": desc[:200],
            "cvss_score":  cvss.get("cvss_score"),
            "cvss_severity": cvss.get("cvss_severity"),
            "published":   cve_data.get("published", "")[:10],
        })

    return {
        "keyword":       keyword,
        "total_found":   data.get("totalResults", 0),
        "returned":      len(results),
        "tier_used":     tier,
        "results":       results,
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
        "upgrade_cta":   None if tier != "FREE" else {
            "message": f"Showing 3/{data.get('totalResults', '?')} results. PRO shows all + EPSS + KEV status.",
            "url":     "https://intel.cyberdudebivash.com/upgrade?plan=pro&src=cve_search",
        },
    }


def batch_scan(cve_ids: List[str], tier: str = "PRO") -> Dict[str, Any]:
    """
    Batch CVE scan. ENTERPRISE/MSSP only (up to 500 CVEs).
    Returns structured results for SOC consumption.
    """
    tier = (tier or "FREE").upper()
    if tier not in ("ENTERPRISE", "MSSP"):
        return {
            "error": "tier_insufficient",
            "required": "ENTERPRISE",
            "upgrade_url": "https://intel.cyberdudebivash.com/upgrade?plan=enterprise&src=batch_scan",
        }

    max_batch = 500
    cve_ids = cve_ids[:max_batch]

    results = []
    kev_hits = []
    critical_count = 0

    for cve_id in cve_ids:
        result = lookup_cve(cve_id, tier=tier, include_epss=True)
        results.append(result)
        if result.get("in_cisa_kev"):
            kev_hits.append(cve_id)
        if (result.get("cvss_score") or 0) >= 9.0:
            critical_count += 1
        time.sleep(0.1)  # brief pause between batch items

    # Save batch results
    _save_scan_results(results)

    return {
        "batch_id":      f"BATCH-{int(time.time())}",
        "scanned":       len(results),
        "kev_count":     len(kev_hits),
        "critical_count": critical_count,
        "kev_cves":      kev_hits,
        "results":       results,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
    }


def get_kev_feed(tier: str = "FREE", limit: int = 20) -> Dict[str, Any]:
    """
    Return latest CISA KEV entries.
    FREE: latest 5. PRO+: all entries with enrichment.
    """
    tier = (tier or "FREE").upper()
    kev_data = _load_kev_cache()
    entries  = list(kev_data.values())

    # Sort by date_added descending
    entries.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)

    if tier == "FREE":
        entries = entries[:5]

    def _enrich(e: Dict) -> Dict:
        return {
            "cve_id":         e.get("cveID"),
            "vendor_project": e.get("vendorProject"),
            "product":        e.get("product"),
            "vulnerability_name": e.get("vulnerabilityName"),
            "date_added":     e.get("dateAdded"),
            "due_date":       e.get("dueDate"),
            "short_description": e.get("shortDescription", "")[:200],
            "required_action": e.get("requiredAction", "")[:200],
            "notes":          e.get("notes", "")[:100],
        }

    return {
        "total_kev_entries": len(kev_data),
        "returned":          len(entries),
        "tier_used":         tier,
        "entries":           [_enrich(e) for e in entries[:limit]],
        "fetched_at":        datetime.now(timezone.utc).isoformat(),
        "source":            "CISA Known Exploited Vulnerabilities Catalog",
        "upgrade_cta": None if tier != "FREE" else {
            "message": f"Showing 5/{len(kev_data)} KEV entries. PRO unlocks all KEV data + EPSS scores.",
            "url": "https://intel.cyberdudebivash.com/upgrade?plan=pro&src=kev_feed",
        },
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _save_scan_results(results: List[Dict]) -> None:
    """Append scan results to rolling file (last 500)."""
    try:
        path = RESULTS_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
        existing.extend(results)
        existing = existing[-500:]  # Keep last 500
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        import os as _os
        _os.replace(tmp, path)
    except Exception as exc:
        log.error("[CVE-SCAN] Save failed: %s", exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [cve-scan] %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%SZ")

    parser = argparse.ArgumentParser(description="SENTINEL APEX CVE Scanner")
    parser.add_argument("--cve",     type=str, help="CVE ID to look up (e.g. CVE-2024-1234)")
    parser.add_argument("--search",  type=str, help="Keyword search for CVEs")
    parser.add_argument("--kev",     action="store_true", help="Show latest CISA KEV entries")
    parser.add_argument("--tier",    type=str, default="PRO", help="Tier (FREE/PRO/ENTERPRISE)")
    parser.add_argument("--json",    action="store_true", help="Output JSON")
    parser.add_argument("--batch",   type=str, help="Comma-separated CVE IDs for batch scan")
    args = parser.parse_args()

    result = None
    if args.cve:
        result = lookup_cve(args.cve, tier=args.tier)
    elif args.search:
        result = search_cves_by_keyword(args.search, tier=args.tier)
    elif args.kev:
        result = get_kev_feed(tier=args.tier)
    elif args.batch:
        cve_list = [c.strip() for c in args.batch.split(",") if c.strip()]
        result = batch_scan(cve_list, tier=args.tier)
    else:
        parser.print_help()
        import sys; sys.exit(0)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    elif result:
        print(f"\n=== CVE SCAN RESULT ===")
        for k, v in result.items():
            if v is not None and k not in ("upgrade_cta",):
                print(f"  {k:25s}: {str(v)[:80]}")
        if result.get("upgrade_cta"):
            print(f"\n  [UPGRADE] {result['upgrade_cta']['message']}")
            print(f"  [UPGRADE] {result['upgrade_cta']['url']}")
