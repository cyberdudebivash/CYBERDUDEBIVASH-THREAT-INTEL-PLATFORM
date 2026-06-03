#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/ioc_truth_engine.py — IOC Truth Engine
Pipeline Stage 6.95
================================================================================
Version : 1.0.0
Purpose : Enforce strict operational IOC type classification.
          Eliminate IOC inflation from filenames, code artifacts,
          CVE references, software components, and advisory URLs.

ALLOWED OPERATIONAL IOC TYPES:
  IPV4          IPv4 address (public, routable, validated)
  IPV6          IPv6 address (public, routable, validated)
  DOMAIN        Registered operational domain (not a filename, not a TLD trap)
  FQDN          Fully-qualified domain name with valid structure
  URL           HTTP/S URL pointing to operational infrastructure
  EMAIL         Email address
  MD5           32-char hex hash
  SHA1          40-char hex hash
  SHA256        64-char hex hash
  SHA512        128-char hex hash
  WALLET_BTC    Bitcoin wallet address
  WALLET_ETH    Ethereum wallet address

RECLASSIFIED (excluded from IOC counts):
  artifact_reference     → filesystem.ts, search-manager.ts
  software_component     → worddecoder.decodeheader, Node.js, alf.io
  cve_reference          → CVE-2024-XXXX (vulnerability ID, not indicator)
  contextual_reference   → Vulners/NVD/CVEFeed/advisory URLs
  invalid_indicator      → Malformed, reserved IPs, invalid patterns

OUTPUTS:
  real_ioc_count          Operational IOC count
  ioc_truth_score         0-100 quality score for the IOC set
  ioc_validation_report.json  Full per-record validation with before/after
================================================================================
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID      = "IOC-TRUTH-ENGINE"
ENGINE_VERSION = "1.0.0"
STAGE_ID       = "6.95"

# ── Strict Type Patterns ──────────────────────────────────────────────────────
IPV4_RE   = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IPV6_FULL = re.compile(
    r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^(([0-9a-fA-F]{1,4}:){0,7}:([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4})$"
)
MD5_RE    = re.compile(r"^[0-9a-fA-F]{32}$")
SHA1_RE   = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SHA512_RE = re.compile(r"^[0-9a-fA-F]{128}$")
EMAIL_RE  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
URL_RE    = re.compile(r"^https?://[^\s]{5,}$")
CVE_RE    = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
BTC_RE    = re.compile(r"^(1|3)[a-zA-Z0-9]{25,34}$|^bc1[a-zA-Z0-9]{39,59}$")
ETH_RE    = re.compile(r"^0x[a-fA-F0-9]{40}$")

# DOMAIN: must have proper structure (not a filename disguised as domain)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# ── Source Code / Filename Extensions (NEVER operational IOCs) ───────────────
# These match TLDs but are code files
SOURCE_CODE_EXTENSIONS = {
    ".ts", ".js", ".mjs", ".cjs", ".jsx", ".tsx",
    ".py", ".pyc", ".pyo",
    ".java", ".class", ".jar",
    ".cs", ".vb", ".fs",
    ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
    ".go", ".rs", ".rb", ".php",
    ".kt", ".kts", ".swift", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".lua", ".pl", ".r", ".m", ".jl",
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini",
    ".sql", ".db", ".sqlite",
    ".md", ".rst", ".txt", ".log",
    ".dll", ".exe", ".so", ".dylib",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
}

# ── Method/Class Reference Patterns (NEVER operational IOCs) ─────────────────
# e.g. worddecoder.decodeheader, com.example.Class.method
METHOD_REF_RE = re.compile(
    r"^[a-z][a-z0-9]*\.[a-z][a-z0-9]*$"  # word.word (all lowercase, no hyphen)
)
JAVA_CLASS_RE = re.compile(
    r"^([a-z][a-z0-9]*\.)+[A-Za-z][a-zA-Z0-9]*$"  # com.example.ClassName
)

# ── Advisory / Intelligence Source URL Patterns (contextual_reference) ───────
ADVISORY_URL_RE = re.compile(
    r"(vulners\.com|nvd\.nist\.gov|nist\.gov/nvd|"
    r"cisa\.gov|us-cert\.gov|cert\.org|kb\.cert\.org|"
    r"attack\.mitre\.org|mitre\.org|"
    r"intel\.cyberdudebivash\.com|cyberdudebivash\.in|"
    r"cve\.mitre\.org|cve\.org|"
    r"github\.com/advisories|github\.com/security|"
    r"cvefeed\.io|"
    r"thehackernews\.com|securityaffairs\.co|"
    r"bleepingcomputer\.com|"
    r"rapid7\.com|tenable\.com|qualys\.com|"
    r"microsoft\.com/security|msrc\.microsoft|"
    r"support\.apple\.com|ubuntu\.com/security|"
    r"exploit-db\.com|packetstormsecurity\.com|"
    r"crowdstrike\.com|mandiant\.com|recordedfuture\.com|"
    r"utm_source=rss|utm_medium=rss)",
    re.IGNORECASE,
)

# ── Known Software Product Domains in CVE Context ────────────────────────────
# These are affected-product domains extracted from CVE titles — NOT operational IOCs
KNOWN_PRODUCT_DOMAINS = {
    "alf.io",           # alf.io ticketing platform
    "node.js",          # Node.js runtime (also matched as software_component)
    "dask.org",
    "librechat.ai",
}

# ── Private / Reserved IP Ranges ─────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
]

# ── Valid Operational TLDs (short-list of common benign ccTLDs that are
#    NOT used as source-code extensions in the wild) ─────────────────────────
# Any string whose suffix matches a source code extension is a filename first.
# The .ts / .js TLD trap: Chad (.td is correct, .ts is common suffix for TS files)
# We check extensions BEFORE domain matching.


# =============================================================================
# Classification Core
# =============================================================================

def _has_source_code_extension(value: str) -> Optional[str]:
    """Return extension if value looks like a source code filename."""
    lower = value.lower()
    for ext in SOURCE_CODE_EXTENSIONS:
        if lower.endswith(ext):
            # Must not have a path separator — filenames only
            if "/" not in value and "\\" not in value:
                return ext
    return None


def _is_software_component(value: str) -> bool:
    """Detect method references and framework component names."""
    # e.g. worddecoder.decodeheader
    if METHOD_REF_RE.match(value):
        return True
    # e.g. Node.js (with capital and .js)
    if re.match(r"^[A-Z][a-zA-Z0-9]+\.[a-z]{2,4}$", value):
        return True
    # Java-style fully qualified name
    if JAVA_CLASS_RE.match(value) and value.count(".") >= 2:
        return True
    # Known product names
    if value.lower() in KNOWN_PRODUCT_DOMAINS:
        return True
    return False


def _validate_ipv4(value: str) -> Tuple[bool, Optional[str]]:
    """Strict IPv4 validation: format, octet range, leading zeros, routing."""
    m = IPV4_RE.match(value.strip())
    if not m:
        return False, "does not match IPv4 x.x.x.x pattern"
    parts = value.strip().split(".")
    for p in parts:
        if len(p) > 1 and p.startswith("0"):
            return False, f"leading zero in octet '{p}' — synthetic/malformed"
        try:
            v = int(p)
        except ValueError:
            return False, f"non-integer octet '{p}'"
        if v < 0 or v > 255:
            return False, f"octet {p} out of range 0-255"
    try:
        addr = ipaddress.ip_address(value.strip())
        for net in _PRIVATE_NETS:
            if addr in net:
                return False, f"private/reserved address ({net}) — not operational"
    except ValueError:
        return False, "ipaddress parse failed"
    return True, None


def classify_ioc(value: str) -> Dict[str, Any]:
    """
    Classify a single value into its operational IOC type or
    reclassify it into a non-IOC category.

    Returns dict with:
      ioc_type        : canonical type string
      category        : 'operational_ioc' | 'non_ioc'
      non_ioc_class   : if non_ioc — artifact_reference | software_component |
                        cve_reference | contextual_reference | invalid_indicator
      rejection_reason: explanation if non_ioc
    """
    v = value.strip()
    result: Dict[str, Any] = {
        "value": v,
        "ioc_type": None,
        "category": None,
        "non_ioc_class": None,
        "rejection_reason": None,
    }

    if not v:
        result["category"] = "non_ioc"
        result["non_ioc_class"] = "invalid_indicator"
        result["rejection_reason"] = "empty value"
        return result

    # ── Gate 1: CVE Reference ─────────────────────────────────────────────────
    if CVE_RE.match(v):
        result["category"] = "non_ioc"
        result["non_ioc_class"] = "cve_reference"
        result["rejection_reason"] = "CVE identifier is a vulnerability reference, not an operational indicator"
        return result

    # ── Gate 2: Source Code Filename ──────────────────────────────────────────
    ext = _has_source_code_extension(v)
    if ext:
        result["category"] = "non_ioc"
        result["non_ioc_class"] = "artifact_reference"
        result["rejection_reason"] = f"source code filename with extension '{ext}' — code artifact, not an operational indicator"
        return result

    # ── Gate 3: Software Component ────────────────────────────────────────────
    if _is_software_component(v):
        result["category"] = "non_ioc"
        result["non_ioc_class"] = "software_component"
        result["rejection_reason"] = "software component, method reference, or product name — not an operational indicator"
        return result

    # ── Gate 4: Advisory / Reference URL ─────────────────────────────────────
    if URL_RE.match(v):
        if ADVISORY_URL_RE.search(v):
            result["category"] = "non_ioc"
            result["non_ioc_class"] = "contextual_reference"
            result["rejection_reason"] = "advisory/intelligence source URL — not malicious infrastructure"
            return result
        # Legitimate operational URL (C2, phishing, malware distribution)
        result["ioc_type"] = "URL"
        result["category"] = "operational_ioc"
        return result

    # ── Gate 5: IPv4 ─────────────────────────────────────────────────────────
    if IPV4_RE.match(v):
        valid, reason = _validate_ipv4(v)
        if valid:
            result["ioc_type"] = "IPV4"
            result["category"] = "operational_ioc"
        else:
            result["category"] = "non_ioc"
            result["non_ioc_class"] = "invalid_indicator"
            result["rejection_reason"] = reason
        return result

    # ── Gate 6: IPv6 ─────────────────────────────────────────────────────────
    if IPV6_FULL.match(v):
        try:
            addr = ipaddress.ip_address(v)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                result["category"] = "non_ioc"
                result["non_ioc_class"] = "invalid_indicator"
                result["rejection_reason"] = "private/reserved IPv6 — not operational"
            else:
                result["ioc_type"] = "IPV6"
                result["category"] = "operational_ioc"
        except ValueError:
            result["category"] = "non_ioc"
            result["non_ioc_class"] = "invalid_indicator"
            result["rejection_reason"] = "invalid IPv6 format"
        return result

    # ── Gate 7: Hashes ────────────────────────────────────────────────────────
    if SHA512_RE.match(v):
        result["ioc_type"] = "SHA512"
        result["category"] = "operational_ioc"
        return result
    if SHA256_RE.match(v):
        result["ioc_type"] = "SHA256"
        result["category"] = "operational_ioc"
        return result
    if SHA1_RE.match(v):
        result["ioc_type"] = "SHA1"
        result["category"] = "operational_ioc"
        return result
    if MD5_RE.match(v):
        # MD5 collision risk note but still valid IOC type
        result["ioc_type"] = "MD5"
        result["category"] = "operational_ioc"
        return result

    # ── Gate 8: Email ─────────────────────────────────────────────────────────
    if EMAIL_RE.match(v):
        result["ioc_type"] = "EMAIL"
        result["category"] = "operational_ioc"
        return result

    # ── Gate 9: Wallet Addresses ──────────────────────────────────────────────
    if BTC_RE.match(v):
        result["ioc_type"] = "WALLET_BTC"
        result["category"] = "operational_ioc"
        return result
    if ETH_RE.match(v):
        result["ioc_type"] = "WALLET_ETH"
        result["category"] = "operational_ioc"
        return result

    # ── Gate 10: Domain / FQDN ────────────────────────────────────────────────
    if DOMAIN_RE.match(v):
        # Final check: known software product domains in CVE context
        if v.lower() in KNOWN_PRODUCT_DOMAINS:
            result["category"] = "non_ioc"
            result["non_ioc_class"] = "software_component"
            result["rejection_reason"] = f"'{v}' is the affected product's domain in a CVE advisory — not threat infrastructure"
            return result
        # Check if it matches a source code extension (e.g. filesystem.ts)
        # Already caught in Gate 2 but double-check for TLD trap
        lower = v.lower()
        for ext in SOURCE_CODE_EXTENSIONS:
            # e.g. filesystem.ts — after Gate 2 this shouldn't reach here
            # but if someone passes 'test.ts' without being caught above:
            if lower.endswith(ext) and "." + lower.split(".")[-1] == ext:
                result["category"] = "non_ioc"
                result["non_ioc_class"] = "artifact_reference"
                result["rejection_reason"] = f"'{v}' matches source code extension trap — filename, not domain"
                return result

        # Multi-level: if > 2 labels, classify as FQDN, else DOMAIN
        labels = v.split(".")
        result["ioc_type"] = "FQDN" if len(labels) > 2 else "DOMAIN"
        result["category"] = "operational_ioc"
        return result

    # ── Fallback: Unknown / unclassifiable ────────────────────────────────────
    result["category"] = "non_ioc"
    result["non_ioc_class"] = "invalid_indicator"
    result["rejection_reason"] = f"value '{v}' does not match any operational IOC pattern"
    return result


# =============================================================================
# Per-Record Processing
# =============================================================================

def compute_ioc_truth_score(real_count: int, raw_count: int, ioc_types: List[str]) -> float:
    """
    Compute IOC Truth Score (0–100).
    Measures signal-to-noise ratio and type diversity.
    """
    if raw_count == 0:
        return 100.0  # No IOCs claimed, no inflation

    # Precision ratio: real / raw (0–100)
    precision = (real_count / raw_count) * 100.0

    # Type diversity bonus (max +10 points)
    unique_types = len(set(ioc_types))
    diversity_bonus = min(unique_types * 2.5, 10.0)

    # High-value type bonus (SHA256, SHA512, IPV4, IPV6 = high value)
    high_value = {"SHA256", "SHA512", "IPV4", "IPV6", "DOMAIN", "FQDN"}
    hv_count = sum(1 for t in ioc_types if t in high_value)
    hv_bonus = min(hv_count * 2.0, 10.0)

    # Combine
    score = min(precision + diversity_bonus + hv_bonus, 100.0)
    return round(score, 2)


def process_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run IOC Truth Engine against a single intelligence record.
    Returns enriched record with truth engine results.
    """
    raw_iocs: List[str] = record.get("iocs", [])
    raw_count = record.get("ioc_count", len(raw_iocs))

    # Previous real_ioc_count (for before/after comparison)
    prev_real_count = record.get("real_ioc_count", raw_count)

    operational_iocs: List[Dict[str, Any]] = []
    rejected_iocs: List[Dict[str, Any]] = []

    for ioc_value in raw_iocs:
        classified = classify_ioc(ioc_value)
        if classified["category"] == "operational_ioc":
            operational_iocs.append(classified)
        else:
            rejected_iocs.append(classified)

    # Build type distribution
    ioc_types = [i["ioc_type"] for i in operational_iocs]
    types_by_count: Dict[str, int] = {}
    for t in ioc_types:
        types_by_count[t] = types_by_count.get(t, 0) + 1

    # Build rejection breakdown
    rejection_breakdown: Dict[str, int] = {}
    for r in rejected_iocs:
        cls = r.get("non_ioc_class", "unknown")
        rejection_breakdown[cls] = rejection_breakdown.get(cls, 0) + 1

    real_count = len(operational_iocs)
    truth_score = compute_ioc_truth_score(real_count, raw_count, ioc_types)

    # Compute inflation factor
    inflation_factor = round(raw_count / real_count, 1) if real_count > 0 else float("inf")

    truth_result = {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "stage_id": STAGE_ID,
        "processed_at": datetime.now(timezone.utc).isoformat(),

        # Counts
        "raw_ioc_count_before": raw_count,
        "real_ioc_count_prev": prev_real_count,
        "real_ioc_count": real_count,
        "rejected_count": len(rejected_iocs),
        "inflation_factor": inflation_factor,

        # Truth score
        "ioc_truth_score": truth_score,

        # Type distribution
        "ioc_types_distribution": types_by_count,

        # Rejection breakdown
        "rejection_breakdown": rejection_breakdown,

        # Full lists
        "operational_iocs": operational_iocs,
        "rejected_iocs": rejected_iocs,

        # Governance flags
        "inflation_detected": raw_count > (real_count * 2),
        "zero_real_iocs": real_count == 0,
        "previously_overcounted": prev_real_count > real_count,
    }

    return truth_result


# =============================================================================
# Feed-Level Processing
# =============================================================================

def process_feed(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process entire feed and produce aggregated validation report."""

    record_results = []
    total_raw = 0
    total_real = 0
    total_prev_real = 0
    inflation_violations = []
    zero_ioc_records = []
    previously_overcounted = []

    for record in feed:
        truth = process_record(record)
        record_results.append({
            "id": record.get("id", "unknown"),
            "title": record.get("title", ""),
            **truth,
        })

        total_raw += truth["raw_ioc_count_before"]
        total_real += truth["real_ioc_count"]
        total_prev_real += truth["real_ioc_count_prev"]

        if truth["inflation_detected"]:
            inflation_violations.append({
                "id": record.get("id"),
                "title": record.get("title", ""),
                "raw": truth["raw_ioc_count_before"],
                "real": truth["real_ioc_count"],
                "factor": truth["inflation_factor"],
            })
        if truth["zero_real_iocs"]:
            zero_ioc_records.append(record.get("id"))
        if truth["previously_overcounted"]:
            previously_overcounted.append({
                "id": record.get("id"),
                "prev": truth["real_ioc_count_prev"],
                "corrected": truth["real_ioc_count"],
            })

    # Feed-level truth score
    feed_truth_score = round(
        sum(r["ioc_truth_score"] for r in record_results) / len(record_results), 2
    ) if record_results else 0.0

    # Aggregated type distribution
    agg_types: Dict[str, int] = {}
    for r in record_results:
        for t, c in r["ioc_types_distribution"].items():
            agg_types[t] = agg_types.get(t, 0) + c

    # Aggregated rejection breakdown
    agg_rejections: Dict[str, int] = {}
    for r in record_results:
        for cls, c in r["rejection_breakdown"].items():
            agg_rejections[cls] = agg_rejections.get(cls, 0) + c

    # Before/After metrics
    inflation_removed = total_raw - total_real
    prev_overcounting = total_prev_real - total_real

    report = {
        "report_metadata": {
            "engine_id": ENGINE_ID,
            "engine_version": ENGINE_VERSION,
            "stage_id": STAGE_ID,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records_processed": len(feed),
        },

        "before_metrics": {
            "total_ioc_count_raw": total_raw,
            "total_real_ioc_count_prev": total_prev_real,
            "average_iocs_per_record_raw": round(total_raw / len(feed), 1) if feed else 0,
            "average_real_iocs_prev": round(total_prev_real / len(feed), 1) if feed else 0,
        },

        "after_metrics": {
            "total_real_ioc_count": total_real,
            "total_rejected_iocs": total_raw - total_real,
            "average_real_iocs_per_record": round(total_real / len(feed), 1) if feed else 0,
            "feed_ioc_truth_score": feed_truth_score,
        },

        "delta": {
            "ioc_inflation_removed": inflation_removed,
            "prev_overcounting_corrected": prev_overcounting,
            "inflation_reduction_pct": round((inflation_removed / total_raw * 100), 1) if total_raw > 0 else 0,
        },

        "type_distribution_real": agg_types,
        "rejection_breakdown_feed": agg_rejections,

        "violations": {
            "inflation_violations_count": len(inflation_violations),
            "inflation_violations": inflation_violations,
            "zero_ioc_records_count": len(zero_ioc_records),
            "zero_ioc_record_ids": zero_ioc_records,
            "previously_overcounted_count": len(previously_overcounted),
            "previously_overcounted": previously_overcounted,
        },

        "governance": {
            "dashboard_ioc_total_was": total_raw,
            "dashboard_ioc_total_corrected": total_real,
            "dashboard_update_required": total_raw != total_real,
            "api_ioc_count_field_requires_update": True,
            "block_publication_of_inflated_records": True,
        },

        "records": record_results,
    }

    return report


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX IOC Truth Engine v1.0.0 — Stage 6.95"
    )
    parser.add_argument(
        "--feed",
        default="data/stix/feed_manifest.json",
        help="Path to feed JSON (array of intel records)",
    )
    parser.add_argument(
        "--output",
        default="reports/ioc_validation_report.json",
        help="Output path for validation report",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary to stdout",
    )
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[IOC-TRUTH] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed: List[Dict[str, Any]] = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        # Try wrapping
        feed = [feed]

    print(f"[IOC-TRUTH] Processing {len(feed)} records...")
    report = process_feed(feed)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[IOC-TRUTH] Report written → {out_path}")

    if args.summary:
        b = report["before_metrics"]
        a = report["after_metrics"]
        d = report["delta"]
        v = report["violations"]
        print("\n" + "=" * 60)
        print("IOC TRUTH ENGINE — SUMMARY")
        print("=" * 60)
        print(f"  Records processed    : {report['report_metadata']['total_records_processed']}")
        print(f"  Raw IOC count        : {b['total_ioc_count_raw']}")
        print(f"  Prev real_ioc_count  : {b['total_real_ioc_count_prev']}")
        print(f"  TRUE real_ioc_count  : {a['total_real_ioc_count']}")
        print(f"  IOCs rejected        : {a['total_rejected_iocs']}")
        print(f"  Inflation removed    : {d['inflation_reduction_pct']}%")
        print(f"  Feed truth score     : {a['feed_ioc_truth_score']}/100")
        print(f"  Inflation violations : {v['inflation_violations_count']}")
        print(f"  Zero-IOC records     : {v['zero_ioc_records_count']}")
        print(f"  Rejection breakdown  : {report['rejection_breakdown_feed']}")
        print("=" * 60)

    return report


if __name__ == "__main__":
    main()
