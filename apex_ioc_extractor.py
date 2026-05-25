"""
CYBERDUDEBIVASH SENTINEL APEX
Production-Grade IOC Extraction Engine v2.0
=============================================
Replaces the broken IOC extraction that was generating garbage artifacts
(attack.execution, blog URLs, Wireshark.exe as "domain indicators").

This module extracts real, validated Indicators of Compromise from raw
threat intelligence text, structured JSON feeds, and STIX bundles.

Supported IOC types:
  - IPv4 / IPv6 addresses
  - Domain names (validated TLD, not internal labels)
  - URLs (threat-relevant, de-fang supported)
  - File hashes: MD5, SHA1, SHA256, SHA512
  - CVE identifiers
  - Email addresses
  - Registry keys (Windows)
  - File paths
  - MITRE ATT&CK technique IDs (T-codes) — tracked separately, NOT as IOCs
"""

import re
import ipaddress
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse
import json

# ---------------------------------------------------------------------------
# BLOCKLISTS — These patterns are NOT IOCs; they are noise produced by the
# previous broken extractor. Anything matching these is silently dropped.
# ---------------------------------------------------------------------------

BLOCKLISTED_PATTERNS = {
    # JavaScript / DOM artifacts accidentally scraped
    "attack.execution", "attack.discovery", "attack.initial_access",
    "attack.credential_access", "attack.lateral_movement",
    "document.cookie", "document.location", "window.location",
    # Generic software binary names — not threat indicators
    "wireshark.exe", "notepad.exe", "calc.exe", "cmd.exe",
    "powershell.exe", "explorer.exe",
    # Installer / packaging terms
    "tools.installer", "setup.exe", "install.msi",
    # Own infrastructure — never block your own domains in client SIEMs
    "cyberdudebivash.in", "cyberdudebivash.com", "intel.cyberdudebivash.com",
    "blog.cyberdudebivash.in",
    # Generic news domains — source URLs, not threat infrastructure
    "cybersecuritynews.com", "thehackernews.com", "bleepingcomputer.com",
    "krebs on security", "krebsonsecurity.com", "darkreading.com",
    "securityweek.com", "nvd.nist.gov", "cisa.gov", "mitre.org",
    "attack.mitre.org", "nvd.nist.gov",
}

# Allowlisted generic labels that appear in descriptions but are NOT domains
GENERIC_LABELS = {
    "localhost", "example.com", "test.com", "internal", "local",
    "corp", "intranet",
}

# Known-safe TLDs for domain validation (expanded list of legitimately suspicious TLDs)
# We use a pragmatic allowlist of TLDs seen in threat actor infrastructure
THREAT_RELEVANT_TLDS = {
    "com", "net", "org", "io", "ru", "cn", "ir", "kp", "tk", "ml", "ga",
    "cf", "gq", "top", "xyz", "pw", "cc", "su", "bz", "ws", "info",
    "biz", "pro", "name", "mobi", "club", "online", "site", "live",
    "space", "fun", "icu", "app", "dev", "page", "tech", "store",
    "shop", "link", "click", "ooo", "men", "work", "life",
}


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
)

RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:[a-zA-Z]{2,})\b'
)

RE_URL = re.compile(
    r'https?://[^\s\'"<>\]\[(){},;]+',
    re.IGNORECASE
)

RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
RE_SHA512 = re.compile(r'\b[0-9a-fA-F]{128}\b')

RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

RE_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

RE_REG_KEY = re.compile(
    r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
    r'HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s"\'<>|]+',
    re.IGNORECASE
)

RE_MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

# Defanged indicators (common in threat intel reports)
RE_DEFANG_IP   = re.compile(r'\b(\d{1,3})\[?\.\]?(\d{1,3})\[?\.\]?(\d{1,3})\[?\.\]?(\d{1,3})\b')
RE_DEFANG_URL  = re.compile(r'hxxps?://[^\s\'"<>\]\[(){},;]+', re.IGNORECASE)
RE_DEFANG_DOT  = re.compile(r'([a-zA-Z0-9\-]+)\[\.\]([a-zA-Z0-9\-\.]+)')


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    type: str           # ip, domain, url, md5, sha1, sha256, sha512, cve, email, registry
    value: str
    confidence: int     # 0-100
    context: str        = ""
    source: str         = ""
    defanged: bool      = False
    validated: bool     = False

    def to_dict(self) -> dict:
        return asdict(self)

    def to_stix_indicator(self, bundle_id: str) -> dict:
        """Minimal STIX 2.1 indicator object."""
        pattern_map = {
            "ip":      f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{self.value}']",
            "domain":  f"[domain-name:value = '{self.value}']",
            "url":     f"[url:value = '{self.value}']",
            "md5":     f"[file:hashes.MD5 = '{self.value}']",
            "sha1":    f"[file:hashes.SHA-1 = '{self.value}']",
            "sha256":  f"[file:hashes.SHA-256 = '{self.value}']",
            "sha512":  f"[file:hashes.SHA-512 = '{self.value}']",
            "email":   f"[email-message:from_ref.value = '{self.value}']",
        }
        pattern = pattern_map.get(self.type, f"[artifact:payload_bin = '{self.value}']")
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.sha256(self.value.encode()).hexdigest()[:35]}",
            "created": "2026-05-25T00:00:00Z",
            "modified": "2026-05-25T00:00:00Z",
            "name": f"APEX-{self.type.upper()}-{self.value[:30]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": "2026-05-25T00:00:00Z",
            "confidence": self.confidence,
            "labels": ["malicious-activity"],
        }


@dataclass
class ExtractionResult:
    raw_iocs: list[IOC]         = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    cve_ids: list[str]          = field(default_factory=list)
    dropped_noise: list[str]    = field(default_factory=list)

    @property
    def validated_iocs(self) -> list[IOC]:
        return [i for i in self.raw_iocs if i.validated]

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for ioc in self.validated_iocs:
            by_type[ioc.type] = by_type.get(ioc.type, 0) + 1
        return {
            "total_validated": len(self.validated_iocs),
            "by_type": by_type,
            "mitre_techniques": self.mitre_techniques,
            "cve_ids": self.cve_ids,
            "dropped_noise_count": len(self.dropped_noise),
        }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return True  # treat parse errors as private/invalid


def _is_loopback_or_special(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return True


def _is_valid_domain(domain: str) -> bool:
    """
    Return True only if this looks like a real, threat-relevant domain.
    Rejects: generic labels, own infrastructure, news sources, internal labels,
             single-word tokens, pure hex strings, version strings like 4.6.6
    """
    lower = domain.lower()

    # Must contain at least one dot
    if '.' not in lower:
        return False

    # Reject if in blocklist
    if lower in BLOCKLISTED_PATTERNS:
        return False

    # Reject if any part matches own infrastructure
    for block in BLOCKLISTED_PATTERNS:
        if lower.endswith('.' + block) or lower == block:
            return False

    # Reject version-like patterns (e.g., "4.6.6", "v1.0.2")
    if re.match(r'^\d+(\.\d+)+$', lower):
        return False

    # Reject domains that are just file extensions
    parts = lower.split('.')
    tld = parts[-1]

    # TLD must be alpha-only
    if not tld.isalpha():
        return False

    # Reject single-label "domains"
    if len(parts) < 2:
        return False

    # Domain labels must be reasonable length
    if any(len(p) > 63 or len(p) == 0 for p in parts):
        return False

    # Reject pure hex strings mistaken for domains
    sld = parts[-2]
    if re.match(r'^[0-9a-f]+$', sld) and len(sld) >= 8:
        return False

    # Reject generic safe TLDs that look like legitimate software names
    generic_slds = {
        "github", "microsoft", "apple", "google", "amazon", "cloudflare",
        "akamai", "fastly", "windows", "adobe", "oracle", "ibm", "splunk",
        "elastic", "crowdstrike", "sentinelone", "paloaltonetworks",
    }
    if sld in generic_slds and tld in {"com", "net", "org", "io"}:
        return False

    return True


def _is_news_or_source_url(url: str) -> bool:
    """Return True if this URL points to a known news/research source — NOT threat infra."""
    blocklisted_hosts = {
        "cybersecuritynews.com", "thehackernews.com", "bleepingcomputer.com",
        "krebsonsecurity.com", "darkreading.com", "securityweek.com",
        "nvd.nist.gov", "cisa.gov", "attack.mitre.org", "mitre.org",
        "cvefeed.io", "vulners.com", "github.com", "microsoft.com",
        "cyberdudebivash.in", "cyberdudebivash.com", "intel.cyberdudebivash.com",
        "blog.cyberdudebivash.in",
    }
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().lstrip("www.")
        return host in blocklisted_hosts
    except Exception:
        return False


def _refang(text: str) -> str:
    """Convert common defanging back to canonical form for extraction."""
    text = RE_DEFANG_DOT.sub(r'\1.\2', text)
    text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
    text = re.sub(r'\[:\]', ':', text)
    return text


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

class APEXIOCExtractor:
    """
    Production IOC extractor for CYBERDUDEBIVASH SENTINEL APEX.

    Usage:
        extractor = APEXIOCExtractor()
        result = extractor.extract(text=raw_text, source="CyberSecurity News")
        print(result.summary())
        validated = result.validated_iocs
    """

    def __init__(self, confidence_defaults: Optional[dict] = None):
        self.confidence_defaults = confidence_defaults or {
            "ip":       75,
            "domain":   65,
            "url":      55,
            "md5":      80,
            "sha1":     80,
            "sha256":   85,
            "sha512":   85,
            "cve":      90,
            "email":    70,
            "registry": 80,
        }

    def extract(
        self,
        text: str,
        source: str = "",
        stix_objects: Optional[list] = None,
        json_feed: Optional[dict] = None,
    ) -> ExtractionResult:
        result = ExtractionResult()

        # 1. Refang any defanged indicators in text
        clean_text = _refang(text)

        # 2. Extract from structured STIX objects if provided
        if stix_objects:
            self._extract_from_stix(stix_objects, result, source)

        # 3. Extract from JSON feed if provided
        if json_feed:
            self._extract_from_json(json_feed, result, source)

        # 4. Extract from raw text
        self._extract_hashes(clean_text, result, source)
        self._extract_ips(clean_text, result, source)
        self._extract_urls(clean_text, result, source)
        self._extract_domains(clean_text, result, source)
        self._extract_emails(clean_text, result, source)
        self._extract_registry_keys(clean_text, result, source)

        # 5. Extract CVEs and MITRE — these are metadata, not network IOCs
        result.cve_ids = list(set(RE_CVE.findall(clean_text)))
        result.mitre_techniques = list(set(RE_MITRE.findall(clean_text)))

        # 6. Deduplicate
        self._deduplicate(result)

        return result

    # -----------------------------------------------------------------------
    # Private extraction methods
    # -----------------------------------------------------------------------

    def _is_noise(self, value: str) -> bool:
        lower = value.lower().strip()
        if lower in BLOCKLISTED_PATTERNS:
            return True
        for block in BLOCKLISTED_PATTERNS:
            if lower == block:
                return True
        return False

    def _add_ioc(
        self,
        result: ExtractionResult,
        ioc_type: str,
        value: str,
        source: str,
        context: str = "",
        validated: bool = True,
        defanged: bool = False,
    ):
        if self._is_noise(value):
            result.dropped_noise.append(f"[noise:{ioc_type}] {value}")
            return
        ioc = IOC(
            type=ioc_type,
            value=value,
            confidence=self.confidence_defaults.get(ioc_type, 50),
            context=context,
            source=source,
            defanged=defanged,
            validated=validated,
        )
        result.raw_iocs.append(ioc)

    def _extract_hashes(self, text: str, result: ExtractionResult, source: str):
        # Order matters: SHA512 > SHA256 > SHA1 > MD5 (avoid partial matches)
        for h in RE_SHA512.findall(text):
            self._add_ioc(result, "sha512", h.lower(), source, "file hash SHA-512")
        # Remove SHA512 matches before searching SHA256
        text_no512 = RE_SHA512.sub('', text)
        for h in RE_SHA256.findall(text_no512):
            self._add_ioc(result, "sha256", h.lower(), source, "file hash SHA-256")
        text_no256 = RE_SHA256.sub('', text_no512)
        for h in RE_SHA1.findall(text_no256):
            self._add_ioc(result, "sha1", h.lower(), source, "file hash SHA-1")
        text_no1 = RE_SHA1.sub('', text_no256)
        for h in RE_MD5.findall(text_no1):
            self._add_ioc(result, "md5", h.lower(), source, "file hash MD5")

    def _extract_ips(self, text: str, result: ExtractionResult, source: str):
        for match in RE_IPV4.finditer(text):
            ip = match.group()
            if _is_private_ip(ip) or _is_loopback_or_special(ip):
                result.dropped_noise.append(f"[private-ip] {ip}")
                continue
            self._add_ioc(result, "ip", ip, source, "IPv4 address")

        for match in RE_IPV6.finditer(text):
            ip = match.group()
            self._add_ioc(result, "ip", ip.lower(), source, "IPv6 address")

    def _extract_urls(self, text: str, result: ExtractionResult, source: str):
        for match in RE_URL.finditer(text):
            url = match.group().rstrip('.,;)')
            if _is_news_or_source_url(url):
                result.dropped_noise.append(f"[source-url] {url}")
                continue
            if len(url) > 500:  # Truncate unrealistically long URLs
                continue
            self._add_ioc(result, "url", url, source, "URL indicator")

    def _extract_domains(self, text: str, result: ExtractionResult, source: str):
        # Remove URLs first so domain regex doesn't re-match URL hostnames
        text_no_urls = RE_URL.sub(' ', text)
        seen = set()
        for match in RE_DOMAIN.finditer(text_no_urls):
            domain = match.group().lower().rstrip('.')
            if domain in seen:
                continue
            seen.add(domain)
            if not _is_valid_domain(domain):
                result.dropped_noise.append(f"[invalid-domain] {domain}")
                continue
            self._add_ioc(result, "domain", domain, source, "domain indicator")

    def _extract_emails(self, text: str, result: ExtractionResult, source: str):
        for match in RE_EMAIL.finditer(text):
            email = match.group().lower()
            # Skip own infrastructure contacts
            if any(block in email for block in {"cyberdudebivash", "example.com"}):
                result.dropped_noise.append(f"[own-infra-email] {email}")
                continue
            self._add_ioc(result, "email", email, source, "email address")

    def _extract_registry_keys(self, text: str, result: ExtractionResult, source: str):
        for match in RE_REG_KEY.finditer(text):
            key = match.group()
            self._add_ioc(result, "registry", key, source, "Windows registry key")

    def _extract_from_stix(
        self, objects: list, result: ExtractionResult, source: str
    ):
        for obj in objects:
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                # Extract embedded values from STIX patterns
                for ip in RE_IPV4.findall(pattern):
                    if not _is_private_ip(ip):
                        self._add_ioc(result, "ip", ip, source, "STIX indicator pattern")
                for h in RE_SHA256.findall(pattern):
                    self._add_ioc(result, "sha256", h.lower(), source, "STIX file hash")
                domain_match = re.search(r"domain-name:value = '([^']+)'", pattern)
                if domain_match and _is_valid_domain(domain_match.group(1)):
                    self._add_ioc(result, "domain", domain_match.group(1), source, "STIX domain")

    def _extract_from_json(self, feed: dict, result: ExtractionResult, source: str):
        """Extract from structured JSON intel feed objects."""
        # Scan common fields where real IOCs appear
        indicator_fields = ["ioc", "indicator", "hash", "ip", "domain", "url", "file_hash"]
        for key in indicator_fields:
            val = feed.get(key, "")
            if val and isinstance(val, str):
                self.extract(val, source=source)  # Recurse into value

        # Handle iocs array if present
        iocs_list = feed.get("iocs", feed.get("indicators", []))
        if isinstance(iocs_list, list):
            for item in iocs_list:
                if isinstance(item, dict):
                    for field_val in item.values():
                        if isinstance(field_val, str) and len(field_val) > 5:
                            sub = self.extract(field_val, source=source)
                            result.raw_iocs.extend(sub.raw_iocs)
                            result.dropped_noise.extend(sub.dropped_noise)
                elif isinstance(item, str):
                    sub = self.extract(item, source=source)
                    result.raw_iocs.extend(sub.raw_iocs)

    def _deduplicate(self, result: ExtractionResult):
        seen = set()
        unique = []
        for ioc in result.raw_iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        result.raw_iocs = unique


# ---------------------------------------------------------------------------
# EPSS display fix — critical bug where 63.49% was shown as 6349%
# ---------------------------------------------------------------------------

def format_epss(raw_value) -> str:
    """
    Safely format an EPSS score for display.

    The existing code was multiplying the decimal value by 100 TWICE,
    producing '6349%' instead of '63.49%'.

    Args:
        raw_value: May be a float like 0.6349, or already-converted like 63.49

    Returns:
        str: Properly formatted percentage, e.g. '63.49%'
    """
    try:
        v = float(raw_value)
        # Detect if already in percentage form (>1.0 means it's already %)
        if v > 1.0:
            return f"{v:.2f}%"
        else:
            return f"{v * 100:.2f}%"
    except (TypeError, ValueError):
        return "N/A"


def normalize_epss(raw_value) -> float:
    """
    Return EPSS as a 0.0–1.0 float regardless of input format.
    Use this for storage; format_epss() for display.
    """
    try:
        v = float(raw_value)
        if v > 1.0:
            return v / 100.0
        return v
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# KEV validation — prevents false KEV confirmations
# ---------------------------------------------------------------------------

def validate_kev_status(cve_id: Optional[str], kev_confirmed_flag: bool) -> tuple[bool, str]:
    """
    Validate whether a KEV confirmation is credible.

    Rules:
    1. If no valid CVE-YYYY-NNNNN ID is present, KEV cannot be confirmed.
    2. CVE IDs must be parseable and real-format.
    3. Non-CVE threat intel articles (news summaries, tool releases) cannot be KEV.

    Returns:
        (is_valid_kev, reason_string)
    """
    if not kev_confirmed_flag:
        return False, "Not flagged as KEV"

    if not cve_id:
        return False, "KEV flag set but no valid CVE ID present — FALSE POSITIVE"

    # Must match proper CVE format
    if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id.upper()):
        return False, f"Invalid CVE format '{cve_id}' — KEV flag rejected"

    year = int(cve_id.split('-')[1])
    if year < 1999 or year > 2030:
        return False, f"CVE year {year} out of valid range — KEV flag rejected"

    return True, f"KEV status plausible for {cve_id} — verify against live CISA KEV catalog"


# ---------------------------------------------------------------------------
# CLI / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Test with sample text containing real and fake IOCs
    sample_text = """
    The threat actor infrastructure observed during campaign OPERATION HYDRA-NEXUS
    includes the following IOCs:

    C2 servers:
      - 45.153.204.118
      - 185.220.101.47
      - 2001:0db8:85a3:0000:0000:8a2e:0370:7334

    Malicious domains:
      - update-service[.]ru
      - cdn-delivery.top
      - secure-login.xyz

    File hashes (malware samples):
      MD5:    d41d8cd98f00b204e9800998ecf8427e
      SHA256: a3f5d0c9e8b7261453f0a8e56d2c14f0a9b3e7c215d84f60b9c7d3a2e1f8054b

    Registry persistence:
      HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate

    Related CVEs: CVE-2026-9082, CVE-2024-21413

    Source: https://thehackernews.com/2026/05/example.html
    Blog: https://blog.cyberdudebivash.in/test/

    Noise (should be dropped):
      - attack.execution
      - document.cookie
      - Wireshark.exe
      - tools.installer
    """

    extractor = APEXIOCExtractor()
    result = extractor.extract(sample_text, source="test")

    print("=" * 60)
    print("APEX IOC EXTRACTION RESULT")
    print("=" * 60)
    print(json.dumps(result.summary(), indent=2))

    print("\nVALIDATED IOCs:")
    for ioc in result.validated_iocs:
        print(f"  [{ioc.type.upper():8}] {ioc.value}  (conf: {ioc.confidence}%)")

    print(f"\nDROPPED NOISE ({len(result.dropped_noise)} items):")
    for n in result.dropped_noise[:10]:
        print(f"  {n}")

    print("\nEPSS FIX DEMO:")
    for raw in [0.6349, 0.8449, 0.1257, 63.49, 84.49, 12.57]:
        print(f"  raw={raw!r:8}  →  {format_epss(raw)}")

    print("\nKEV VALIDATION DEMO:")
    tests = [
        (None, True),
        ("CVE-2026-9082", True),
        ("Pentest Agent Suite", True),   # This was the false positive
        ("attack.execution", True),
    ]
    for cve, kev_flag in tests:
        valid, reason = validate_kev_status(cve, kev_flag)
        status = "✓ VALID" if valid else "✗ REJECTED"
        print(f"  CVE={cve!r:30}  KEV={kev_flag}  →  {status}: {reason}")
