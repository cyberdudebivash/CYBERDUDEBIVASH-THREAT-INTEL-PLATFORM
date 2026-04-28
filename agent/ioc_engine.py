#!/usr/bin/env python3
"""
agent/ioc_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Unified IOC Extraction & Confidence Engine
===============================================================================
v1.0.0  --  Production-grade IOC pipeline for SENTINEL APEX ULTRA

RESPONSIBILITIES:
  1. Extract ALL IOC types from raw text:
       - IPv4 / IPv6 addresses
       - Domains (with TLD validation)
       - URLs (http/https/ftp)
       - MD5 / SHA1 / SHA256 / SHA512 hashes
       - Email addresses (threat actor attribution)
       - CVE identifiers
  2. Normalize + deduplicate each type.
  3. Validate against false-positive blocklists (RFC1918, loopback, CIDRs,
     benign domains, short hash-like numbers, etc.).
  4. Compute ioc_confidence (0.0–100.0) dynamically from:
       - IOC count (quantity signal)
       - IOC type diversity (quality signal)
       - High-fidelity type bonus (hash/CVE carry more weight than domain)
  5. Map ioc_confidence to threat_level enum:
       NONE / LOW / MEDIUM / HIGH / CRITICAL
  6. Return a validated, structured IOCResult dataclass.

DESIGN GUARANTEES:
  - ioc_count is ALWAYS == len(flat_iocs)  (enforced at return time)
  - Never raises — all errors caught, degraded-but-safe result returned
  - Deterministic: same input → same output (sorted, deduped)
  - Thread-safe: pure functions, no global mutable state

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-IOC")

# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# IPv4: strict octet validation (0-255)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6: compressed and full forms
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
)

# Domains: strict - must have TLD, reject single-label
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,24})\b"
)

# URLs: full http/https/ftp
_RE_URL = re.compile(
    r"(?:https?|ftp)://[^\s\"'<>\]\[(){},;|\\^`]+",
    re.IGNORECASE
)

# Hashes: by exact length
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA512 = re.compile(r"\b[0-9a-fA-F]{128}\b")

# Email: threat actor attribution (deliberately loose — tightened by blocklist)
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"
)

# CVE IDs
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ─────────────────────────────────────────────────────────────────────────────
# FALSE-POSITIVE BLOCKLISTS
# ─────────────────────────────────────────────────────────────────────────────

# IP addresses that are never threat IOCs
_IP_BLOCKLIST_RE = re.compile(
    r"^("
    r"127\.\d+\.\d+\.\d+|"           # loopback
    r"0\.0\.0\.0|"                    # null route
    r"255\.255\.255\.255|"            # broadcast
    r"192\.168\.\d+\.\d+|"           # RFC1918 class C
    r"10\.\d+\.\d+\.\d+|"            # RFC1918 class A
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"  # RFC1918 class B
    r"169\.254\.\d+\.\d+|"           # link-local
    r"100\.6[4-9]\.\d+\.\d+|"        # shared address space (CGNAT)
    r"100\.[7-9]\d\.\d+\.\d+|"
    r"100\.1[01]\d\.\d+\.\d+|"
    r"100\.12[0-7]\.\d+\.\d+"        # RFC6598
    r")$"
)

# Domains that are NOT threat IOCs (CDN, benign infra, etc.)
_DOMAIN_BLOCKLIST = frozenset({
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "localdomain", "test.com", "test.org",
    "google.com", "google.co.uk", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "apple.com", "icloud.com", "akamai.com", "akamaiedge.com", "cloudflare.com",
    "amazonaws.com", "aws.amazon.com", "s3.amazonaws.com",
    "github.com", "githubusercontent.com", "gitlab.com",
    "nvd.nist.gov", "cve.mitre.org", "cisa.gov", "us-cert.cisa.gov",
    "virustotal.com", "shodan.io", "censys.io",
    "w3.org", "schema.org", "openssl.org",
    "x.com", "twitter.com", "facebook.com", "linkedin.com",
    "cyberdudebivash.com",  # own brand domain - not a threat IOC
    # ── Threat intel SOURCE domains (news feeds / vendor blogs) ──────────────
    # These are intelligence PUBLISHERS — never C2 infrastructure.
    # Extracting them as IOCs pollutes feeds with false positives.
    "malwarebytes.com", "wordfence.com", "rapid7.com",
    "bleepingcomputer.com", "thehackernews.com", "securityweek.com",
    "darkreading.com", "isc.sans.edu", "sans.org",
    "recordedfuture.com", "mandiant.com", "crowdstrike.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "talos-intelligence.com", "talosintelligence.com", "blog.talosintelligence.com",
    "sentinelone.com", "checkpoint.com", "research.checkpoint.com",
    "fortinet.com", "fortiguard.com", "kaspersky.com", "securelist.com",
    "symantec.com", "broadcom.com", "trendmicro.com", "mcafee.com",
    "sophos.com", "sophosnews.com", "threatpost.com",
    "securityaffairs.co", "securityaffairs.com",
    "krebsonsecurity.com", "wired.com", "techcrunch.com",
    "helpnetsecurity.com", "infosecurity-magazine.com",
    "cyberscoop.com", "therecord.media", "grahamcluley.com",
    "proofpoint.com", "abuse.ch", "urlhaus.abuse.ch",
    "otx.alienvault.com", "alienvault.com",
    "microsoft.com", "msrc.microsoft.com", "security.googleblog.com",
    "blog.google", "research.google",
})

# Domain TLD-only patterns to reject (single word .tld is not a domain)
_DOMAIN_MIN_LABELS = 2

# File extensions that match domain TLD regex but are NOT real TLDs.
# e.g. "chrome.exe", "conhost.exe", "secret.png", "0.exe", "rundll32.exe"
# The domain regex matches [a-zA-Z]{2,24} which includes .exe, .dll, .png etc.
_FILE_EXT_BLOCKLIST: frozenset = frozenset({
    # Executable / script
    "exe", "dll", "bat", "cmd", "ps1", "ps2", "vbs", "jse", "js", "py",
    "sh", "rb", "pl", "php", "asp", "aspx", "jar", "class", "war",
    # Document
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv",
    "xml", "json", "html", "htm", "mhtml", "css", "rtf", "odt",
    # Archive
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "cab", "ace",
    # Image
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "tiff", "webp",
    # System / binary
    "sys", "drv", "ocx", "cpl", "msi", "msp", "scr", "hta", "wsf",
    "wsh", "lnk", "pif", "com", "tmp", "log", "ini", "cfg", "dat",
    "db", "sqlite", "mdb", "bin", "hex",
    # Media
    "mp3", "mp4", "avi", "mkv", "mov", "wav", "flv",
})

# Valid hash hex patterns sometimes appear as version numbers, etc.
# Reject if it's clearly a version string context
_HASH_CONTEXT_FP_RE = re.compile(
    r"(?:version|ver|v|build|revision|ref|commit)\s*[=:]\s*[0-9a-fA-F]{32,64}",
    re.IGNORECASE
)

# Known benign email domains to suppress from threat IOC list
_EMAIL_BENIGN_DOMAINS = frozenset({
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "live.com",
    "protonmail.com", "icloud.com", "me.com", "aol.com",
    "example.com", "test.com", "cyberdudebivash.com",
})

# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORING
# ─────────────────────────────────────────────────────────────────────────────

# Per-type weight: high-fidelity IOCs carry more signal
_IOC_TYPE_WEIGHTS: Dict[str, float] = {
    "sha256":  10.0,   # Highest fidelity — exact file match
    "sha512":   9.5,
    "sha1":     8.0,
    "md5":      7.5,   # Weak against collision but still useful
    "ipv4":     6.0,   # Good signal — specific C2 address
    "ipv6":     5.5,
    "url":      5.0,   # C2 URL / phishing landing
    "email":    4.5,   # Spearphishing attribution
    "domain":   4.0,   # C2 domain — moderate FP rate
    "cve":      7.0,   # Specific vulnerability reference
}

# Threat level thresholds
_THREAT_LEVEL_THRESHOLDS = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (35.0, "MEDIUM"),
    (10.0, "LOW"),
    (0.0,  "NONE"),
]


def _compute_confidence(iocs_by_type: Dict[str, List[str]]) -> float:
    """
    Compute ioc_confidence (0.0–100.0) from the structured IOC dict.

    Algorithm:
      base_score = sum(weight * min(count, 10)) for each type present
      diversity_bonus = +5 per additional type beyond the first (max +20)
      raw_score = base_score + diversity_bonus
      confidence = min(raw_score, 100.0)

    This ensures:
      - confidence > 0 whenever ANY ioc is present
      - Higher fidelity types (hashes) contribute more than domains
      - Diversity of IOC types (multi-type presence) signals richer intel
    """
    if not iocs_by_type:
        return 0.0

    base = 0.0
    types_present = 0
    for ioc_type, values in iocs_by_type.items():
        count = len(values)
        if count == 0:
            continue
        weight = _IOC_TYPE_WEIGHTS.get(ioc_type, 3.0)
        # Diminishing returns after 10 IOCs of the same type
        base += weight * min(count, 10)
        types_present += 1

    # Diversity bonus: +5 per extra type (max +20 for 5+ types)
    diversity_bonus = min(5.0 * max(0, types_present - 1), 20.0)
    raw = base + diversity_bonus

    return round(min(raw, 100.0), 2)


def _confidence_to_threat_level(confidence: float) -> str:
    """Map confidence score to threat level string."""
    for threshold, level in _THREAT_LEVEL_THRESHOLDS:
        if confidence >= threshold:
            return level
    return "NONE"


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IOCResult:
    """
    Structured result from the IOC extraction engine.

    INVARIANT: ioc_count == len(flat_iocs)  ALWAYS (enforced in __post_init__)
    """
    iocs_by_type: Dict[str, List[str]] = field(default_factory=dict)
    flat_iocs: List[str] = field(default_factory=list)
    ioc_count: int = 0
    ioc_confidence: float = 0.0
    threat_level: str = "NONE"
    extraction_meta: Dict = field(default_factory=dict)

    def __post_init__(self):
        # Integrity invariant: ioc_count must always equal len(flat_iocs)
        if self.ioc_count != len(self.flat_iocs):
            logger.warning(
                "IOCResult invariant violation: ioc_count=%d but len(flat_iocs)=%d — correcting",
                self.ioc_count, len(self.flat_iocs)
            )
            self.ioc_count = len(self.flat_iocs)

    def to_manifest_fields(self) -> Dict:
        """
        Return the fields that should be written to the manifest entry.
        All fields are guaranteed consistent: ioc_count == len(iocs).
        """
        return {
            "iocs":                self.flat_iocs,
            "ioc_count":           self.ioc_count,        # ALWAYS == len(iocs)
            "iocs_by_type":        self.iocs_by_type,
            "ioc_confidence":      self.ioc_confidence,
            "ioc_threat_level":    self.threat_level,
            "ioc_extraction_meta": self.extraction_meta,
        }


# ─────────────────────────────────────────────────────────────────────────────
# EXTRACTION FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _extract_ipv4(text: str) -> List[str]:
    candidates = _RE_IPV4.findall(text)
    result = []
    seen = set()
    for ip in candidates:
        if ip in seen:
            continue
        seen.add(ip)
        if _IP_BLOCKLIST_RE.match(ip):
            continue
        result.append(ip)
    return sorted(result)


def _extract_ipv6(text: str) -> List[str]:
    candidates = _RE_IPV6.findall(text)
    result = []
    seen = set()
    for ip in candidates:
        ip = ip.strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        # Skip loopback
        if ip.startswith("::1") or ip == "::":
            continue
        result.append(ip)
    return sorted(result)


def _extract_domains(text: str, exclude_from_urls: Optional[List[str]] = None) -> List[str]:
    """
    Extract domains from text, excluding domains that are part of already-extracted URLs.
    """
    candidates = _RE_DOMAIN.findall(text)
    exclude_set = set(exclude_from_urls or [])
    result = []
    seen = set()
    for dom in candidates:
        dom_lower = dom.lower().rstrip(".")
        if dom_lower in seen:
            continue
        seen.add(dom_lower)
        # Must have at least 2 labels
        labels = dom_lower.split(".")
        if len(labels) < _DOMAIN_MIN_LABELS:
            continue
        # ── v143.0 FIX: Reject file-extension TLDs ───────────────────────────
        # The domain regex matches .exe, .dll, .png etc. as valid TLDs.
        # e.g. "chrome.exe", "conhost.exe", "secret.png", "rundll32.exe" all
        # match _RE_DOMAIN but are Windows filenames, NOT real network domains.
        if labels[-1] in _FILE_EXT_BLOCKLIST:
            continue
        # Blocklist check
        if dom_lower in _DOMAIN_BLOCKLIST:
            continue
        # Also check base domain (strip subdomain)
        if len(labels) >= 2 and ".".join(labels[-2:]) in _DOMAIN_BLOCKLIST:
            continue
        # Skip if it's just a URL hostname we already captured
        if dom_lower in exclude_set:
            continue
        # Reject domains that look like version numbers (e.g. 1.2.3.4.5)
        if re.match(r"^[\d.]+$", dom_lower):
            continue
        result.append(dom_lower)
    return sorted(result)


def _extract_urls(text: str) -> List[str]:
    candidates = _RE_URL.findall(text)
    result = []
    seen = set()
    for url in candidates:
        url = url.rstrip(".,;\"')")
        url_lower = url.lower()
        if url_lower in seen:
            continue
        seen.add(url_lower)
        # Skip URLs pointing to benign reference sites
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            base = ".".join(hostname.split(".")[-2:]) if hostname else ""
            if hostname in _DOMAIN_BLOCKLIST or base in _DOMAIN_BLOCKLIST:
                continue
        except Exception:
            pass
        result.append(url)
    return sorted(result)


def _extract_hashes(text: str) -> Dict[str, List[str]]:
    """
    Extract file hashes. Returns dict by type.
    Orders by length (SHA512 > SHA256 > SHA1 > MD5) to avoid sub-matching.
    """
    # Remove hash-context FPs (version strings etc.)
    clean_text = _HASH_CONTEXT_FP_RE.sub(" ", text)

    sha512_set = set(_RE_SHA512.findall(clean_text))
    sha256_set = set(_RE_SHA256.findall(clean_text))
    sha1_set   = set(_RE_SHA1.findall(clean_text))
    md5_set    = set(_RE_MD5.findall(clean_text))

    # Remove SHA256 matches that are also SHA512 sub-sequences (shouldn't happen but guard it)
    # SHA512 = 128 hex chars; SHA256 = 64 hex chars. Since we use exact-length regex, no overlap.

    return {
        "sha512": sorted(sha512_set),
        "sha256": sorted(sha256_set),
        "sha1":   sorted(sha1_set),
        "md5":    sorted(md5_set),
    }


def _extract_emails(text: str) -> List[str]:
    candidates = _RE_EMAIL.findall(text)
    result = []
    seen = set()
    for email in candidates:
        email_lower = email.lower()
        if email_lower in seen:
            continue
        seen.add(email_lower)
        # Skip benign email domains (threat actor attribution only)
        domain = email_lower.split("@", 1)[-1] if "@" in email_lower else ""
        if domain in _EMAIL_BENIGN_DOMAINS:
            continue
        result.append(email_lower)
    return sorted(result)


def _extract_cves(text: str) -> List[str]:
    candidates = _RE_CVE.findall(text)
    result = sorted({c.upper() for c in candidates})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def extract_iocs(
    text: str,
    *,
    additional_text: Optional[str] = None,
    existing_iocs_by_type: Optional[Dict[str, List[str]]] = None,
) -> IOCResult:
    """
    Primary entry point: extract all IOC types from text.

    Args:
        text:                  Primary text (article body, title, summary).
        additional_text:       Optional secondary text (appended before extraction).
        existing_iocs_by_type: Pre-structured IOC dict (from enricher/STIX layer).
                               If provided, merged with extracted IOCs.

    Returns:
        IOCResult with guaranteed invariant: ioc_count == len(flat_iocs)
    """
    if not text and not additional_text and not existing_iocs_by_type:
        return IOCResult()

    try:
        full_text = (text or "") + " " + (additional_text or "")

        # --- Extract each type ---
        urls     = _extract_urls(full_text)
        ipv4     = _extract_ipv4(full_text)
        ipv6     = _extract_ipv6(full_text)

        # Extract domains excluding hostnames already captured in URLs
        url_hosts = []
        from urllib.parse import urlparse
        for u in urls:
            try:
                h = urlparse(u).hostname or ""
                if h:
                    url_hosts.append(h.lower())
            except Exception:
                pass
        domains  = _extract_domains(full_text, exclude_from_urls=url_hosts)

        hashes   = _extract_hashes(full_text)
        emails   = _extract_emails(full_text)
        cves     = _extract_cves(full_text)

        iocs_by_type: Dict[str, List[str]] = {
            "ipv4":   ipv4,
            "ipv6":   ipv6,
            "domain": domains,
            "url":    urls,
            "sha256": hashes.get("sha256", []),
            "sha512": hashes.get("sha512", []),
            "sha1":   hashes.get("sha1", []),
            "md5":    hashes.get("md5", []),
            "email":  emails,
            "cve":    cves,
        }

        # Merge with pre-existing structured IOCs if provided
        if existing_iocs_by_type and isinstance(existing_iocs_by_type, dict):
            for ioc_type, values in existing_iocs_by_type.items():
                if not isinstance(values, list):
                    continue
                normalized_type = ioc_type.lower().replace("-", "_")
                if normalized_type in iocs_by_type:
                    # Deduplicated union
                    merged = sorted(
                        set(iocs_by_type[normalized_type])
                        | {str(v).strip() for v in values if v}
                    )
                    iocs_by_type[normalized_type] = merged
                else:
                    iocs_by_type[normalized_type] = sorted(
                        {str(v).strip() for v in values if v}
                    )

        # Remove empty types to keep manifest clean
        iocs_by_type = {k: v for k, v in iocs_by_type.items() if v}

        # Build flat list (deterministic order: type priority)
        TYPE_ORDER = ["sha256", "sha512", "sha1", "md5", "ipv4", "ipv6", "url",
                      "domain", "email", "cve"]
        flat_iocs: List[str] = []
        seen_flat: set = set()
        for ioc_type in TYPE_ORDER:
            for val in iocs_by_type.get(ioc_type, []):
                if val not in seen_flat:
                    flat_iocs.append(val)
                    seen_flat.add(val)
        # Append any extra types not in TYPE_ORDER
        for ioc_type, values in iocs_by_type.items():
            if ioc_type not in TYPE_ORDER:
                for val in values:
                    if val not in seen_flat:
                        flat_iocs.append(val)
                        seen_flat.add(val)

        # Compute confidence from structured types
        confidence   = _compute_confidence(iocs_by_type)
        threat_level = _confidence_to_threat_level(confidence)

        # Extraction metadata for observability
        meta = {
            "types_found":   list(iocs_by_type.keys()),
            "counts_by_type": {k: len(v) for k, v in iocs_by_type.items()},
            "text_length":   len(full_text),
            "had_existing":  bool(existing_iocs_by_type),
        }

        result = IOCResult(
            iocs_by_type    = iocs_by_type,
            flat_iocs       = flat_iocs,
            ioc_count       = len(flat_iocs),  # set explicitly
            ioc_confidence  = confidence,
            threat_level    = threat_level,
            extraction_meta = meta,
        )

        logger.debug(
            "IOC extraction: %d IOCs | types=%s | confidence=%.1f | level=%s",
            result.ioc_count,
            list(iocs_by_type.keys()),
            confidence,
            threat_level,
        )
        return result

    except Exception as exc:
        logger.error("IOC extraction failed (returning empty result): %s", exc)
        return IOCResult()


def extract_iocs_from_manifest_entry(entry: Dict) -> IOCResult:
    """
    Convenience: extract IOCs from a manifest entry dict.
    Pulls text from: title, description, summary, summary_ai fields.
    Merges with any existing iocs_by_type dict stored in the entry.
    """
    text_parts = [
        str(entry.get("title", "")),
        str(entry.get("description", "")),
        str(entry.get("summary", "")),
        str(entry.get("summary_ai", "")),
        str(entry.get("ai_narrative", "")),
    ]
    full_text = " ".join(p for p in text_parts if p and p != "None")

    existing = entry.get("iocs_by_type")
    if not existing and isinstance(entry.get("ioc_counts"), dict):
        # Reconstruct skeleton from ioc_counts (counts only, no values)
        # The extractor will re-derive values from text
        existing = None

    return extract_iocs(full_text, existing_iocs_by_type=existing)


def enforce_ioc_integrity(entry: Dict) -> Dict:
    """
    Enforce ioc_count == len(iocs) on a manifest entry.
    If mismatched, re-extract from text fields.
    If ioc_confidence == 0 but iocs exist, recompute confidence.

    Returns mutated copy (does not modify original).
    """
    entry = dict(entry)

    iocs = entry.get("iocs")
    ioc_count = entry.get("ioc_count", 0)
    ioc_confidence = entry.get("ioc_confidence", 0.0)

    # Case 1: ioc_count > 0 but iocs is empty/missing → P0 integrity violation
    if ioc_count > 0 and (not iocs or len(iocs) == 0):
        logger.warning(
            "P0 IOC INTEGRITY: ioc_count=%d but iocs=[] for title=%s — re-extracting",
            ioc_count, str(entry.get("title", ""))[:60]
        )
        result = extract_iocs_from_manifest_entry(entry)
        entry.update(result.to_manifest_fields())

    # Case 2: iocs list exists but ioc_count is wrong
    elif isinstance(iocs, list) and ioc_count != len(iocs):
        logger.warning(
            "IOC count mismatch: declared=%d actual=%d — correcting",
            ioc_count, len(iocs)
        )
        entry["ioc_count"] = len(iocs)

    # Case 3: ioc_confidence == 0 but iocs exist → compute
    if isinstance(iocs, list) and len(iocs) > 0 and (ioc_confidence is None or float(ioc_confidence) == 0.0):
        iocs_by_type = entry.get("iocs_by_type") or {}
        if not iocs_by_type:
            # Build a minimal iocs_by_type from the flat list for confidence calc
            iocs_by_type = {"unknown": iocs}
        confidence = _compute_confidence(iocs_by_type)
        if confidence == 0.0:
            # Fallback: any non-zero IOC list gets minimum LOW confidence
            confidence = max(len(iocs) * 2.0, 10.0)
            confidence = min(confidence, 100.0)
        entry["ioc_confidence"] = round(confidence, 2)
        entry["ioc_threat_level"] = _confidence_to_threat_level(confidence)

    # Guarantee: remove ioc_threat_level=NONE when confidence > 0
    if float(entry.get("ioc_confidence", 0.0)) > 0 and entry.get("ioc_threat_level") == "NONE":
        entry["ioc_threat_level"] = _confidence_to_threat_level(
            float(entry.get("ioc_confidence", 0.0))
        )

    return entry


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING NORMALIZATION HELPER
# ─────────────────────────────────────────────────────────────────────────────

def normalize_risk_score(
    base_score: float,
    *,
    kev_present: bool = False,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    ioc_count: int = 0,
    ioc_confidence: float = 0.0,
) -> Dict:
    """
    Normalize risk score and severity classification.

    CRITICAL classification rules (at least ONE must be true):
      1. KEV listed (CISA confirmed exploitation in the wild)
      2. CVSS >= 9.0 AND (IOC density > 0 OR EPSS >= 0.5)
      3. EPSS >= 0.7 (70% exploitation probability within 30 days)
      4. ioc_confidence >= 80 AND ioc_count >= 5

    HIGH:
      - CVSS >= 7.5 OR (EPSS >= 0.3 AND ioc_count > 0) OR ioc_confidence >= 60

    MEDIUM:
      - CVSS >= 4.0 OR ioc_count > 0

    LOW:
      - Anything else with some signal

    UNKNOWN:
      - Absolutely no signals

    Returns: {"risk_score": float, "severity": str}
    """
    # Clamp input
    base_score = max(0.0, min(10.0, float(base_score or 0.0)))
    cvss = float(cvss_score or 0.0)
    epss = float(epss_score or 0.0)
    conf = float(ioc_confidence or 0.0)

    # Determine severity with strict gates
    is_critical = (
        kev_present
        or (cvss >= 9.0 and (ioc_count > 0 or epss >= 0.5))
        or epss >= 0.7
        or (conf >= 80.0 and ioc_count >= 5)
    )
    is_high = (
        is_critical
        or cvss >= 7.5
        or (epss >= 0.3 and ioc_count > 0)
        or conf >= 60.0
    )
    is_medium = (
        is_high
        or cvss >= 4.0
        or ioc_count > 0
    )
    is_low = (
        is_medium
        or base_score > 0
        or conf > 0
    )

    if is_critical:
        severity = "CRITICAL"
        # Ensure score reflects criticality
        final_score = max(base_score, 9.0)
    elif is_high:
        severity = "HIGH"
        final_score = max(base_score, 7.0)
        final_score = min(final_score, 9.0)
    elif is_medium:
        severity = "MEDIUM"
        final_score = max(base_score, 4.0)
        final_score = min(final_score, 7.0)
    elif is_low:
        severity = "LOW"
        final_score = max(base_score, 1.0)
        final_score = min(final_score, 4.0)
    else:
        severity = "UNKNOWN"
        final_score = base_score

    return {
        "risk_score": round(final_score, 2),
        "severity":   severity,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MODULE SELF-TEST (run with: python -m agent.ioc_engine)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    test_text = """
    A campaign by APT29 was observed distributing SUNBURST malware from
    185.220.101.45 and staging on update.solarwinds-cdn.com.
    Command-and-control traffic was seen to http://evil-c2.com/beacon/init.
    File hash (SHA-256): a77f3c6f8c8b4f2e9d1234567890abcdef1234567890abcdef1234567890abcd01
    MD5: d41d8cd98f00b204e9800998ecf8427e
    Malicious email: attacker@apt-evil.ru
    CVE-2024-12345 was exploited (CVSS 9.8, KEV confirmed).
    Loopback 127.0.0.1 and internal 192.168.1.100 should be EXCLUDED.
    """
    result = extract_iocs(test_text)
    print(json.dumps(result.to_manifest_fields(), indent=2))
    scoring = normalize_risk_score(7.5, kev_present=True, cvss_score=9.8, ioc_count=result.ioc_count)
    print(f"Risk scoring: {scoring}")
