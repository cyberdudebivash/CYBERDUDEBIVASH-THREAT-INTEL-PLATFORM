#!/usr/bin/env python3
"""
ioc_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0.0
═══════════════════════════════════════════════════════════════════════
Enterprise-Grade IOC Extraction Engine

Multi-layer extraction strategy:
  Layer 1: Precision regex (IPv4, IPv6, domain, URL, hash, email, CVE)
  Layer 2: Defanged indicator recovery (1[.]2[.]3[.]4, evil[.]com)
  Layer 3: Context-aware NLP extraction (actor refs, malware names, infra)
  Layer 4: Source-specific extraction (NVD CPE, MISP attributes, STIX)
  Layer 5: IOC confidence scoring + false-positive filtering

Functions (public API):
  extract_ips(text)        → List[str]
  extract_domains(text)    → List[str]
  extract_urls(text)       → List[str]
  extract_hashes(text)     → Dict[str, List[str]]
  extract_emails(text)     → List[str]
  extract_cves(text)       → List[str]
  classify_iocs(iocs)      → Dict[str, Any]
  extract_all(text, item)  → Dict[str, Any]   ← primary entry point

Enforcement:
  - MIN_IOC_THRESHOLD: items with 0 IOCs are flagged INTEL-LOW-VALUE
  - IOC confidence score attached per indicator
  - False-positive filters: private IPs, CDN domains, common TLDs

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""

from __future__ import annotations

import re
import ipaddress
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("CDB-IOC-ENGINE")

# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

MIN_IOC_THRESHOLD = 1  # Minimum IOCs for HIGH/CRITICAL report validity

# Confidence weights by evidence type
IOC_CONFIDENCE = {
    "sha256":          0.98,  # Near-certain — 256-bit hash
    "sha1":            0.90,  # High — 160-bit hash
    "md5":             0.82,  # Medium-high — collision risk
    "ipv4_direct":     0.88,  # High — direct IP mention
    "ipv4_defanged":   0.85,  # High — intentionally obfuscated
    "ipv6":            0.90,
    "domain_direct":   0.75,
    "domain_defanged": 0.80,  # Slightly higher — analyst deliberately defanged
    "url":             0.72,
    "email":           0.78,
    "cve":             0.95,  # Near-certain — standardized format
    "btc_address":     0.85,
    "ssdeep":          0.80,
    "imphash":         0.82,
    "yara_rule":       0.92,
    "mutex":           0.70,
    "registry_key":    0.72,
    "file_path":       0.65,
    "user_agent":      0.68,
    "asn":             0.60,
    "malware_name":    0.75,
    "actor_name":      0.70,
}

# ── False-positive filters ──────────────────────────────────────────────
_PRIVATE_IP_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.0.0.", "255.",
    "169.254.",
)
_LOOPBACK_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

_FP_DOMAINS: Set[str] = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "google.com", "googleapis.com", "gstatic.com", "github.com",
    "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "icloud.com", "cdn.com", "cloudflare.com",
    "akamai.com", "akamaiedge.com", "amazonaws.com", "aws.amazon.com",
    "azure.com", "azurewebsites.net", "office.com", "live.com",
    "outlook.com", "yahoo.com", "gmail.com", "hotmail.com",
    "schema.org", "w3.org", "ietf.org", "iana.org",
    "wordpress.org", "wordpress.com", "jquery.com",
    "nvd.nist.gov", "nist.gov", "cisa.gov", "cve.mitre.org",
    "mitre.org", "cert.org",
}

_FP_HASH_PATTERNS: Set[str] = {
    "a" * 32, "0" * 32, "f" * 32,
    "a" * 40, "0" * 40, "f" * 40,
    "a" * 64, "0" * 64, "f" * 64,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 empty
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty
}

# ── Regex patterns — comprehensive ──────────────────────────────────────
_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_IPV4_DEFANGED = re.compile(
    r'\b(\d{1,3})(?:\[\.?\]|\(\.?\)|{\.\}|\s*\[\s*\.\s*\]\s*)(\d{1,3})'
    r'(?:\[\.?\]|\(\.?\)|{\.\}|\s*\[\s*\.\s*\]\s*)(\d{1,3})'
    r'(?:\[\.?\]|\(\.?\)|{\.\}|\s*\[\s*\.\s*\]\s*)(\d{1,3})\b'
)
_RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
)
_RE_DOMAIN = re.compile(
    r'\b(?:(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+)'
    r'(?:com|net|org|io|info|gov|edu|mil|co|xyz|top|biz|site|club|online|'
    r'ru|cn|uk|de|fr|jp|br|in|au|ca|eu|us|kr|tech|app|dev|cloud|'
    r'bank|finance|secure|login|update|support|service|portal|admin|'
    r'onion|i2p)\b',
    re.IGNORECASE
)
_RE_DOMAIN_DEFANGED = re.compile(
    r'\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)'
    r'(?:\[\.?\]|\(\.?\)|{\.\}|\[\s*\.\s*\])'
    r'(?:[a-z]{2,}))\b',
    re.IGNORECASE
)
_RE_URL = re.compile(
    r'(?:https?|ftp|hxxp|hxxps)://[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)
_RE_URL_DEFANGED = re.compile(
    r'hxxp[s]?://[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_SSDEEP = re.compile(r'\b\d+:[A-Za-z0-9+/]{6,}:[A-Za-z0-9+/]{1,}\b')
_RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)
_RE_CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_RE_BTC = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_RE_REGISTRY = re.compile(
    r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)'
    r'(?:\\[^\s\\:*?"<>|,;]+)+\b',
    re.IGNORECASE
)
_RE_MUTEX = re.compile(
    r'\bMutex(?:Name)?[:\s]+([^\s,;:\"\'<>]{4,64})\b|'
    r'\b(?:CreateMutex|OpenMutex)\s*\([^)]{0,200}["\']([^"\']{4,64})["\']',
    re.IGNORECASE
)
_RE_FILEPATH_WIN = re.compile(
    r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]+\.[a-zA-Z]{1,6}\b'
)
_RE_FILEPATH_UNIX = re.compile(
    r'(?:/(?:etc|tmp|var|usr|home|root|bin|sbin|opt|proc|dev|sys)'
    r'(?:/[^\s:*?"<>|]+){1,6})\b'
)
_RE_USER_AGENT = re.compile(
    r'User-Agent:\s*([^\r\n]{10,200})',
    re.IGNORECASE
)
_RE_ASN = re.compile(r'\bAS\d{1,6}\b')
_RE_IMPHASH = re.compile(r'\bimphash[:\s=]+([a-fA-F0-9]{32})\b', re.IGNORECASE)
_RE_YARA_RULE = re.compile(
    r'\brule\s+(\w+)\s*(?:\:[^\{]*)?\{[^}]{20,}',
    re.IGNORECASE | re.DOTALL
)

# ── Context/NLP keyword lists ───────────────────────────────────────────
_KNOWN_MALWARE_FAMILIES = {
    "cobalt strike", "cobaltstrike", "mimikatz", "metasploit", "empire",
    "lockbit", "lockbit 3.0", "blackcat", "alphv", "conti", "ryuk",
    "wannacry", "notpetya", "revil", "sodinokibi", "darkside",
    "emotet", "trickbot", "qakbot", "qbot", "bumblebee", "icedid",
    "snake", "turla", "sandworm", "fancy bear", "apt28", "apt29",
    "cozy bear", "lazarus", "kimsuky", "volt typhoon", "salt typhoon",
    "blackbasta", "scattered spider", "lapsus$", "fin7", "fin8",
    "ursnif", "dridex", "gameover zeus", "gootkit", "ragnar locker",
    "cl0p", "clop", "havoc", "brute ratel", "sliver c2", "sliver",
    "silverado", "nighthawk", "deimos", "strelka", "stealc",
    "rhadamanthys", "lumma stealer", "vidar stealer", "formbook",
    "asyncrat", "njrat", "remcos", "xworm", "darkcomet",
}

_KNOWN_THREAT_ACTORS = {
    "apt1", "apt2", "apt3", "apt10", "apt28", "apt29", "apt30",
    "apt32", "apt33", "apt34", "apt38", "apt40", "apt41", "apt43",
    "apt44", "fin6", "fin7", "fin8", "ta505", "ta416", "ta453",
    "lazarus", "kimsuky", "bluenoroff", "andariel", "sandworm",
    "turla", "cozy bear", "fancy bear", "charming kitten", "pioneer kitten",
    "scattered spider", "lapsus$", "unc4899", "unc2452", "unc3944",
    "volt typhoon", "salt typhoon", "flax typhoon", "silk typhoon",
    "citrine sleet", "aqua blizzard", "midnight blizzard", "forest blizzard",
    "storm-0558", "storm-0977", "storm-1283",
}

_INFRA_KEYWORDS = {
    "c2 server", "c&c server", "command and control", "command-and-control",
    "drop server", "loader", "downloader", "dropper", "stager",
    "payload server", "exfiltration server", "beacon", "implant",
    "staging server", "jump server", "pivot", "proxy chain",
}

# ── TLD extension list for domain validation ────────────────────────────
_VALID_TLDS = {
    "com", "net", "org", "io", "info", "gov", "edu", "mil", "co",
    "xyz", "top", "biz", "site", "club", "online", "ru", "cn", "uk",
    "de", "fr", "jp", "br", "in", "au", "ca", "eu", "us", "kr",
    "tech", "app", "dev", "cloud", "bank", "finance", "secure", "login",
    "update", "support", "service", "portal", "admin", "onion", "i2p",
    "me", "cc", "su", "pw", "icu", "live", "store", "space", "host",
    "pro", "mobi", "name", "int", "arpa",
}


# ═══════════════════════════════════════════════════════════════════════
# PRIMARY EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def extract_ips(text: str) -> List[str]:
    """
    Extract all IPv4 and IPv6 addresses from text.
    Handles direct and defanged notation.
    Returns deduplicated list, false positives removed.
    """
    found: Set[str] = set()

    # Layer 1: Direct IPv4
    for match in _RE_IPV4.finditer(text):
        ip = match.group()
        if _is_valid_public_ip(ip):
            found.add(ip)

    # Layer 2: Defanged IPv4 (1[.]2[.]3[.]4)
    for match in _RE_IPV4_DEFANGED.finditer(text):
        ip = f"{match.group(1)}.{match.group(2)}.{match.group(3)}.{match.group(4)}"
        if _is_valid_public_ip(ip):
            found.add(ip)

    # Layer 3: IPv6
    for match in _RE_IPV6.finditer(text):
        ip = match.group()
        if ip not in {"::1", "::", "fe80::"}:
            found.add(ip)

    return sorted(found)[:50]  # cap at 50


def extract_domains(text: str) -> List[str]:
    """
    Extract domain names (direct + defanged).
    Removes false positives (CDN, well-known, documentation domains).
    """
    found: Set[str] = set()

    # Layer 1: Direct domains
    for match in _RE_DOMAIN.finditer(text):
        d = match.group().lower()
        if _is_suspicious_domain(d):
            found.add(d)

    # Layer 2: Defanged domains (evil[.]com)
    for match in _RE_DOMAIN_DEFANGED.finditer(text):
        raw = match.group()
        d = re.sub(r'\[\.?\]|\(\.?\)|{\.\}', '.', raw).lower()
        if _is_suspicious_domain(d):
            found.add(d)

    # Layer 3: Extract domains from URLs already found
    for match in _RE_URL.finditer(text):
        url = match.group()
        dm = _extract_domain_from_url(url)
        if dm and _is_suspicious_domain(dm):
            found.add(dm)

    return sorted(found)[:50]


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs including hxxp:// defanged variants.
    """
    found: Set[str] = set()

    # Direct URLs
    for match in _RE_URL.finditer(text):
        url = match.group().rstrip('.,;)')
        if len(url) > 10:
            found.add(url)

    # Defanged hxxp:// URLs
    for match in _RE_URL_DEFANGED.finditer(text):
        url = re.sub(r'^hxxps?://', 'https://', match.group(), flags=re.IGNORECASE).rstrip('.,;)')
        if len(url) > 10:
            found.add(url)

    # Filter out benign URLs
    filtered = [u for u in found if not _is_benign_url(u)]
    return sorted(filtered)[:30]


def extract_hashes(text: str) -> Dict[str, List[str]]:
    """
    Extract file hashes: SHA256, SHA1, MD5, SSDeep, ImpHash.
    Returns dict keyed by hash type.
    """
    result: Dict[str, List[str]] = {}

    sha256 = []
    for m in _RE_SHA256.finditer(text):
        h = m.group().lower()
        if h not in _FP_HASH_PATTERNS and _is_likely_hash_context(text, m.start()):
            sha256.append(h)
    if sha256:
        result["sha256"] = list(dict.fromkeys(sha256))[:20]

    sha1 = []
    for m in _RE_SHA1.finditer(text):
        h = m.group().lower()
        # Exclude strings also matching SHA256 (avoid overlaps)
        if h not in _FP_HASH_PATTERNS and len(h) == 40:
            sha1.append(h)
    if sha1:
        result["sha1"] = list(dict.fromkeys(sha1))[:20]

    md5 = []
    for m in _RE_MD5.finditer(text):
        h = m.group().lower()
        if h not in _FP_HASH_PATTERNS and len(h) == 32:
            md5.append(h)
    if md5:
        result["md5"] = list(dict.fromkeys(md5))[:20]

    # ImpHash (explicitly labeled)
    imphashes = []
    for m in _RE_IMPHASH.finditer(text):
        imphashes.append(m.group(1).lower())
    if imphashes:
        result["imphash"] = list(dict.fromkeys(imphashes))[:10]

    # SSDeep fuzzy hash
    ssdeeps = []
    for m in _RE_SSDEEP.finditer(text):
        h = m.group()
        if ':' in h and len(h) > 15:
            ssdeeps.append(h)
    if ssdeeps:
        result["ssdeep"] = list(dict.fromkeys(ssdeeps))[:5]

    return result


def extract_emails(text: str) -> List[str]:
    """Extract email addresses, filtering out documentation/example emails."""
    found: Set[str] = set()
    for m in _RE_EMAIL.finditer(text):
        email = m.group().lower()
        if not any(email.endswith(fp) for fp in {"@example.com", "@test.com", "@domain.com"}):
            found.add(email)
    return sorted(found)[:20]


def extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers. Always uppercase, deduplicated."""
    matches = list(set(m.upper() for m in _RE_CVE.findall(text)))
    return sorted(matches)[:30]


def extract_context_iocs(text: str, item: Optional[Dict] = None) -> Dict[str, List[str]]:
    """
    Layer 3: Context-aware NLP extraction.
    Detects malware family names, threat actor names, C2 infrastructure keywords,
    Windows registry keys, mutex names, file paths, user agents.
    """
    context: Dict[str, List[str]] = {}
    text_lower = text.lower()

    # Malware families
    malware = []
    for mw in _KNOWN_MALWARE_FAMILIES:
        if mw in text_lower:
            malware.append(mw.title())
    if malware:
        context["malware_family"] = list(dict.fromkeys(malware))[:10]

    # Threat actors
    actors = []
    for actor in _KNOWN_THREAT_ACTORS:
        if actor.lower() in text_lower:
            actors.append(actor.upper())
    if actors:
        context["threat_actor"] = list(dict.fromkeys(actors))[:8]

    # Infrastructure indicators (C2, staging, etc.)
    infra_hits = [kw for kw in _INFRA_KEYWORDS if kw in text_lower]
    if infra_hits:
        context["infra_indicator"] = list(dict.fromkeys(infra_hits))[:5]

    # Windows registry keys
    reg_keys = [m.group() for m in _RE_REGISTRY.finditer(text)]
    if reg_keys:
        context["registry_key"] = list(dict.fromkeys(reg_keys))[:10]

    # Mutex names
    mutexes = []
    for m in _RE_MUTEX.finditer(text):
        val = m.group(1) or m.group(2)
        if val:
            mutexes.append(val.strip())
    if mutexes:
        context["mutex"] = list(dict.fromkeys(mutexes))[:5]

    # File paths (Windows + Unix)
    paths = ([m.group() for m in _RE_FILEPATH_WIN.finditer(text)] +
             [m.group() for m in _RE_FILEPATH_UNIX.finditer(text)])
    suspicious_paths = [p for p in paths if _is_suspicious_path(p)]
    if suspicious_paths:
        context["file_path"] = list(dict.fromkeys(suspicious_paths))[:10]

    # User agents
    uas = [m.group(1).strip() for m in _RE_USER_AGENT.finditer(text)]
    if uas:
        context["user_agent"] = list(dict.fromkeys(uas))[:3]

    # ASN references
    asns = [m.group() for m in _RE_ASN.finditer(text)]
    if asns:
        context["asn"] = list(dict.fromkeys(asns))[:5]

    # Cryptocurrency addresses (ransom payments)
    btc = [m.group() for m in _RE_BTC.finditer(text) if _is_likely_btc_context(text, m.start())]
    if btc:
        context["btc_address"] = list(dict.fromkeys(btc))[:5]
    eth = [m.group() for m in _RE_ETH.finditer(text)]
    if eth:
        context["eth_address"] = list(dict.fromkeys(eth))[:5]

    # YARA rule names
    yara_names = [m.group(1) for m in _RE_YARA_RULE.finditer(text)]
    if yara_names:
        context["yara_rule"] = list(dict.fromkeys(yara_names))[:5]

    return context


def classify_iocs(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify and score a complete IOC dictionary.

    Returns:
        {
            "total_count": int,
            "categories": {type: count},
            "confidence_score": float (0-100),
            "threat_level": str (NONE/LOW/MEDIUM/HIGH/CRITICAL),
            "is_low_value": bool,
            "primary_types": List[str],
            "enrichment_priority": str,
        }
    """
    categories: Dict[str, int] = {}
    total = 0
    weighted_confidence = 0.0
    weight_sum = 0.0

    for ioc_type, values in iocs.items():
        if not values:
            continue
        count = len(values) if isinstance(values, list) else 1
        categories[ioc_type] = count
        total += count

        # Get confidence weight for this type
        conf = IOC_CONFIDENCE.get(ioc_type, 0.65)
        weighted_confidence += conf * count
        weight_sum += count

    confidence = (weighted_confidence / weight_sum * 100) if weight_sum > 0 else 0.0
    confidence = min(100.0, round(confidence, 1))

    # Determine threat level from IOC richness
    high_value_types = {"sha256", "sha1", "md5", "ipv4", "domain", "cve", "url", "malware_family"}
    high_value_count = sum(categories.get(t, 0) for t in high_value_types)

    if total == 0:
        threat_level = "NONE"
    elif high_value_count >= 10 or categories.get("malware_family"):
        threat_level = "CRITICAL"
    elif high_value_count >= 5:
        threat_level = "HIGH"
    elif high_value_count >= 2 or total >= 3:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # Primary IOC types (sorted by count desc)
    primary_types = sorted(categories.keys(), key=lambda k: categories[k], reverse=True)[:3]

    # Enrichment priority
    if categories.get("sha256") or categories.get("sha1"):
        enrichment_priority = "VT_HASH_LOOKUP"
    elif categories.get("ipv4") or categories.get("domain"):
        enrichment_priority = "PASSIVE_DNS_LOOKUP"
    elif categories.get("cve"):
        enrichment_priority = "NVD_CVE_LOOKUP"
    elif categories.get("malware_family"):
        enrichment_priority = "MALWARE_SANDBOX"
    else:
        enrichment_priority = "STANDARD"

    return {
        "total_count":         total,
        "categories":          categories,
        "confidence_score":    confidence,
        "threat_level":        threat_level,
        "is_low_value":        total < MIN_IOC_THRESHOLD,
        "primary_types":       primary_types,
        "enrichment_priority": enrichment_priority,
        "ioc_density":         round(total / max(1, total), 2),
    }


def extract_all(text: str, item: Optional[Dict] = None) -> Dict[str, Any]:
    """
    PRIMARY ENTRY POINT — Full multi-layer IOC extraction.

    Runs all 4 extraction layers and returns a unified IOC dictionary
    suitable for pipeline consumption.

    Args:
        text: Combined title + content text to extract from
        item: Original pipeline item dict (for source-specific extraction)

    Returns:
        {
            "ips":            List[str],
            "domains":        List[str],
            "urls":           List[str],
            "sha256":         List[str],
            "sha1":           List[str],
            "md5":            List[str],
            "emails":         List[str],
            "cves":           List[str],
            "malware_family": List[str],
            "threat_actor":   List[str],
            "registry_key":   List[str],
            "mutex":          List[str],
            "file_path":      List[str],
            ... (other context types),
            "_meta": {
                "total_count": int,
                "confidence_score": float,
                "threat_level": str,
                "is_low_value": bool,
                "extraction_layers": List[str],
            }
        }
    """
    if not text:
        text = ""

    result: Dict[str, Any] = {}
    layers_used = []

    # ── Layer 1: IP extraction ─────────────────────────────────────────
    ips = extract_ips(text)
    if ips:
        result["ips"] = ips
        layers_used.append("L1_IP")

    # ── Layer 1: Domain extraction ─────────────────────────────────────
    domains = extract_domains(text)
    if domains:
        result["domains"] = domains
        if "L1_IP" not in layers_used:
            layers_used.append("L1_DOMAIN")

    # ── Layer 1: URL extraction ─────────────────────────────────────────
    urls = extract_urls(text)
    if urls:
        result["urls"] = urls

    # ── Layer 1: Hash extraction ────────────────────────────────────────
    hashes = extract_hashes(text)
    result.update(hashes)
    if hashes:
        layers_used.append("L1_HASH")

    # ── Layer 1: Email extraction ───────────────────────────────────────
    emails = extract_emails(text)
    if emails:
        result["emails"] = emails

    # ── Layer 1: CVE extraction ─────────────────────────────────────────
    cves = extract_cves(text)
    if cves:
        result["cves"] = cves
        layers_used.append("L1_CVE")

    # ── Layer 3: Context/NLP extraction ────────────────────────────────
    context_iocs = extract_context_iocs(text, item)
    result.update(context_iocs)
    if context_iocs:
        layers_used.append("L3_CONTEXT")

    # ── Layer 4: Source-specific extraction (if item provided) ─────────
    if item:
        source_iocs = _extract_source_specific(item)
        for k, v in source_iocs.items():
            if k in result:
                result[k] = list(dict.fromkeys(result[k] + v))
            else:
                result[k] = v
        if source_iocs:
            layers_used.append("L4_SOURCE")

    # ── Compute classification metadata ────────────────────────────────
    classification = classify_iocs(result)

    result["_meta"] = {
        "total_count":      classification["total_count"],
        "confidence_score": classification["confidence_score"],
        "threat_level":     classification["threat_level"],
        "is_low_value":     classification["is_low_value"],
        "primary_types":    classification["primary_types"],
        "extraction_layers": layers_used,
        "enrichment_priority": classification["enrichment_priority"],
        "extracted_at":     datetime.now(timezone.utc).isoformat(),
    }

    logger.debug(
        f"IOC extraction complete: {classification['total_count']} IOCs "
        f"across {len(result)-1} types, confidence={classification['confidence_score']:.1f}%, "
        f"layers={layers_used}"
    )

    return result


# ═══════════════════════════════════════════════════════════════════════
# PIPELINE INTEGRATION — Drop-in upgrade for NormalizeStage
# ═══════════════════════════════════════════════════════════════════════

def upgrade_pipeline_item(item: Dict) -> Dict:
    """
    Upgrade an existing pipeline item with enhanced IOC extraction.
    Merges new IOCs with any existing ones, updates counts and flags.

    Use this in NormalizeStage and ScoreStage._fallback_ioc_expansion.
    """
    text = f"{item.get('title', '')} {item.get('content', '')} {item.get('summary', '')}"
    existing_iocs = item.get("iocs") or {}

    # Run full extraction
    new_iocs = extract_all(text, item)
    meta = new_iocs.pop("_meta", {})

    # Merge with existing (new takes priority, dedup)
    merged: Dict[str, List[str]] = {}
    all_keys = set(list(existing_iocs.keys()) + list(new_iocs.keys()))
    for k in all_keys:
        old_vals = existing_iocs.get(k, []) if isinstance(existing_iocs.get(k), list) else []
        new_vals = new_iocs.get(k, [])
        merged[k] = list(dict.fromkeys(old_vals + new_vals))[:20]

    item["iocs"] = {k: v for k, v in merged.items() if v}
    item["ioc_counts"] = {k: len(v) for k, v in item["iocs"].items()}
    item["ioc_confidence"] = meta.get("confidence_score", 0.0)
    item["ioc_threat_level"] = meta.get("threat_level", "NONE")
    item["ioc_extraction_meta"] = meta

    total = sum(len(v) for v in item["iocs"].values())
    if total == 0:
        existing_flags = item.get("quality_flags") or []
        if "INTEL-LOW-VALUE" not in existing_flags:
            item["quality_flags"] = existing_flags + ["INTEL-LOW-VALUE"]

    return item


def enrich_from_stix_bundle(item: Dict, bundle_json: str) -> Dict:
    """
    Layer 4: Extract IOCs from a STIX 2.1 bundle JSON string.
    Parses indicator objects and populates item["iocs"].
    """
    try:
        import json
        bundle = json.loads(bundle_json)
        objects = bundle.get("objects", [])

        stix_iocs: Dict[str, List[str]] = {}
        for obj in objects:
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                # Extract from STIX patterns like: [file:hashes.'SHA-256' = '...']
                sha256_m = re.findall(r"SHA-256'\s*=\s*'([a-fA-F0-9]{64})'", pattern)
                md5_m = re.findall(r"MD5'\s*=\s*'([a-fA-F0-9]{32})'", pattern)
                ip_m = re.findall(r"value\s*=\s*'([\d.]+)'", pattern)
                domain_m = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                url_m = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)

                for lst, key in [
                    (sha256_m, "sha256"), (md5_m, "md5"),
                    (ip_m, "ips"), (domain_m, "domains"), (url_m, "urls")
                ]:
                    if lst:
                        stix_iocs[key] = stix_iocs.get(key, []) + lst

        # Merge into item
        for k, v in stix_iocs.items():
            existing = item.get("iocs", {}).get(k, [])
            item.setdefault("iocs", {})[k] = list(dict.fromkeys(existing + v))[:20]

    except Exception as e:
        logger.debug(f"STIX bundle IOC extraction failed: {e}")

    return item


# ═══════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _is_valid_public_ip(ip: str) -> bool:
    """Returns True if IP is a valid, non-private, non-loopback IPv4."""
    if ip in _LOOPBACK_IPS:
        return False
    if any(ip.startswith(p) for p in _PRIVATE_IP_RANGES):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _is_suspicious_domain(domain: str) -> bool:
    """Returns True if domain looks like a real threat indicator."""
    domain = domain.lower().strip(".")
    if not domain or len(domain) < 5:
        return False
    if domain in _FP_DOMAINS:
        return False
    if any(domain.endswith("." + fp) for fp in _FP_DOMAINS):
        return False
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld not in _VALID_TLDS:
        return False
    # Skip version numbers like 1.0.0.1
    if all(p.isdigit() for p in parts):
        return False
    return True


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from a URL string."""
    try:
        # Simple extraction without urllib dependency
        s = url.split("//", 1)[-1]
        domain = s.split("/")[0].split("?")[0].split("#")[0]
        # Remove port
        if ":" in domain:
            domain = domain.rsplit(":", 1)[0]
        return domain.lower() if domain else None
    except Exception:
        return None


def _is_benign_url(url: str) -> bool:
    """Returns True if URL is known-benign (docs, CDN, etc.)."""
    url_lower = url.lower()
    benign_patterns = [
        "schema.org", "w3.org", "iana.org", "docs.microsoft.com",
        "support.microsoft.com", "docs.github.com", "nvd.nist.gov",
        "cve.mitre.org", "attack.mitre.org", "docs.python.org",
        "pypi.org", "npmjs.com", "cdn.cloudflare.com",
    ]
    return any(p in url_lower for p in benign_patterns)


def _is_likely_hash_context(text: str, pos: int) -> bool:
    """
    Heuristic: check if the hash appears in a context that suggests
    it's actually a file hash (near keywords like hash, sha, md5, sample, etc.)
    """
    window_start = max(0, pos - 100)
    window_end = min(len(text), pos + 100)
    window = text[window_start:window_end].lower()
    hash_keywords = {
        "hash", "sha", "md5", "sha256", "sha-256", "sha1", "sha-1",
        "checksum", "digest", "sample", "malware", "file:", "hashes",
        "indicator", "ioc", "artifact", "payload"
    }
    return any(kw in window for kw in hash_keywords)


def _is_suspicious_path(path: str) -> bool:
    """Check if a file path looks like a malware artifact."""
    path_lower = path.lower()
    suspicious_dirs = {
        "\\temp\\", "\\tmp\\", "\\appdata\\", "%temp%", "%appdata%",
        "\\programdata\\", "\\users\\public\\", "\\windows\\temp\\",
        "/tmp/", "/var/tmp/", "/dev/shm/", "/proc/",
    }
    suspicious_exts = {
        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta",
        ".scr", ".lnk", ".jar", ".sh", ".py", ".php", ".asp",
    }
    has_suspicious_dir = any(d in path_lower for d in suspicious_dirs)
    has_suspicious_ext = any(path_lower.endswith(e) for e in suspicious_exts)
    return has_suspicious_dir or has_suspicious_ext


def _is_likely_btc_context(text: str, pos: int) -> bool:
    """Check if BTC address appears near ransom/payment context."""
    window = text[max(0, pos - 150):pos + 150].lower()
    ransom_keywords = {"bitcoin", "btc", "ransom", "payment", "wallet", "crypto", "monero"}
    return any(kw in window for kw in ransom_keywords)


def _extract_source_specific(item: Dict) -> Dict[str, List[str]]:
    """
    Layer 4: Extract IOCs from structured source-specific fields.
    Handles NVD advisories, MalwareBazaar entries, AbuseIPDB reports.
    """
    extra: Dict[str, List[str]] = {}
    source = (item.get("feed_source") or "").lower()

    if "nvd" in source or "cve" in source:
        # NVD: extract CPE vendor/product strings as context
        cpe_refs = item.get("cpe_refs") or item.get("affected_products") or []
        if cpe_refs:
            extra["affected_product"] = [str(c) for c in cpe_refs[:10]]

        # NVD: extract reference URLs
        refs = item.get("references") or []
        if isinstance(refs, list):
            ref_urls = [r.get("url", "") if isinstance(r, dict) else str(r) for r in refs]
            suspicious_refs = [u for u in ref_urls if u and not _is_benign_url(u)]
            if suspicious_refs:
                existing = extra.get("urls", [])
                extra["urls"] = list(dict.fromkeys(existing + suspicious_refs))[:10]

    elif "malwarebazaar" in source or "bazaar" in source:
        # MalwareBazaar: structured hash fields
        for hash_type in ("sha256_hash", "sha1_hash", "md5_hash"):
            val = item.get(hash_type)
            if val and isinstance(val, str) and len(val) in (32, 40, 64):
                k = hash_type.split("_")[0]
                extra[k] = extra.get(k, []) + [val.lower()]

        # Tags → malware families
        tags = item.get("tags") or []
        if isinstance(tags, list):
            families = [t for t in tags if isinstance(t, str) and len(t) > 2]
            if families:
                extra["malware_family"] = families[:5]

    elif "abuseipdb" in source:
        # AbuseIPDB: IP is the primary IOC
        ip = item.get("ip_address") or item.get("ip")
        if ip and _is_valid_public_ip(str(ip)):
            extra["ips"] = [str(ip)]

    return extra


# ═══════════════════════════════════════════════════════════════════════
# CONVENIENCE: backward-compatible wrapper matching legacy stages.py API
# ═══════════════════════════════════════════════════════════════════════

class IOCEngine:
    """
    Stateful IOC engine wrapping all extraction functions.
    Use as drop-in replacement for NormalizeStage._extract_iocs().
    """

    def __init__(self):
        self._false_positive_ips: Set[str] = set()
        self._false_positive_domains: Set[str] = set(_FP_DOMAINS)
        self._extraction_count = 0
        self._total_iocs = 0

    def extract(self, text: str, item: Optional[Dict] = None) -> Dict[str, Any]:
        """Full extraction — returns flat dict suitable for item['iocs']."""
        full = extract_all(text, item)
        meta = full.pop("_meta", {})
        self._extraction_count += 1
        self._total_iocs += meta.get("total_count", 0)
        # Rename keys to match legacy format expected by pipeline
        result = {}
        if full.get("ips"):
            result["ipv4"] = full.pop("ips")
        if full.get("domains"):
            result["domain"] = full.pop("domains")
        if full.get("urls"):
            result["url"] = full.pop("urls")
        if full.get("emails"):
            result["email"] = full.pop("emails")
        if full.get("cves"):
            result["cve"] = full.pop("cves")
        # Pass through hashes and context directly
        result.update(full)
        result["_meta"] = meta
        return result

    def get_stats(self) -> Dict[str, int]:
        return {
            "extractions": self._extraction_count,
            "total_iocs": self._total_iocs,
            "avg_iocs_per_item": round(self._total_iocs / max(1, self._extraction_count), 1),
        }


# Module-level singleton
_engine_instance: Optional[IOCEngine] = None


def get_ioc_engine() -> IOCEngine:
    """Get or create the IOC engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = IOCEngine()
    return _engine_instance
