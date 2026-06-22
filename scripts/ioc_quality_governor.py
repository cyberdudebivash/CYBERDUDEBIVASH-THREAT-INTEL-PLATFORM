#!/usr/bin/env python3
"""
IOC QUALITY GOVERNOR  v1.1  -- SENTINEL APEX
=============================================
Validates IOC indicators and rejects parser artifacts, library names,
function names, and other false positives.

PROBLEM: Parser artifacts appearing as IOCs:
  - re.match, unicodedata.normalize  (Python standard library functions)
  - bgpupdate.decodefrombytes        (Go library method name)
  - js.monoglyphrat                  (JavaScript parser artifact)
  - CVE IDs from other advisories contaminating sibling records

VALID IOC TYPES (v1.1 additions):
  IPv4, IPv6, CIDR, Domain, URL, MD5, SHA1, SHA256, Email, CVE ID, MITRE TTP,
  Windows Registry Key, Windows File Path, Mutex/Named Pipe, ASN, GUID

INVALID (reject):
  Python/Go/JS function calls, library names, parser artifacts, random strings,
  version strings, news/advisory source URLs, tracking URLs

v1.1 CHANGES (v185.0):
  - Added CIDR, Registry key, File path, Mutex, ASN, GUID patterns
  - Extended artifact patterns: version strings, single-word alphanumerics,
    news/advisory site URLs, non-hash hex strings of wrong length
  - Fixes false_positive_rate_pct calculation edge case (dict feeds)

TARGET: False IOC Rate < 5%

Usage:
  python3 scripts/ioc_quality_governor.py [--feed api/feed.json] [--fix] [--report]
"""
import json, os, sys, re, argparse, datetime, pathlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Validation patterns ──────────────────────────────────────────────────────

_RE_IPV4   = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_RE_IPV4_CIDR = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
_RE_IPV6   = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
_RE_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_RE_URL    = re.compile(r'^https?://.{4,}')
_RE_MD5    = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_SHA1   = re.compile(r'^[0-9a-fA-F]{40}$')
_RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
_RE_EMAIL  = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
_RE_CVE    = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)
_RE_MITRE  = re.compile(r'^T\d{4}(\.\d{3})?$')
# Windows registry keys (valid host-based IOC)
_RE_REGISTRY = re.compile(r'^(HKEY_|HKLM\\|HKCU\\|HKLM/|HKCU/|SOFTWARE\\|SYSTEM\\|\\Registry)', re.I)
# Windows file paths (valid host-based IOC)
_RE_WIN_PATH = re.compile(r'^(%[A-Z_]+%\\|[A-Za-z]:\\|\\\\)', re.I)
# Unix/Linux file paths
_RE_UNIX_PATH = re.compile(r'^/(?:etc|var|tmp|usr|home|root|proc|sys|dev|opt|run)/[^\s]+')
# Mutex / named pipe (host-based IOC)
_RE_MUTEX = re.compile(r'^(Global\\|Local\\|\\BaseNamedObjects\\|\\\\.\\pipe\\|\\Device\\)', re.I)
# GUID / UUID
_RE_GUID = re.compile(r'^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$')
# ASN (Autonomous System Number)
_RE_ASN = re.compile(r'^AS\d{1,10}$', re.I)
# Filename with malicious extension
_RE_MALICIOUS_FILENAME = re.compile(r'^[a-zA-Z0-9_\-\.]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|scr|pif|msi|vba|xlsm|docm|jar|class|elf|so)$', re.I)
# JA3/JA3S TLS fingerprint (32-char hex = MD5-length but context means TLS fingerprint)
# SHA512 hash
_RE_SHA512 = re.compile(r'^[0-9a-fA-F]{128}$')

# Known artifact patterns -- if an IOC matches any of these, reject it
_ARTIFACT_PATTERNS = [
    re.compile(r'\.(normalize|match|compile|search|findall|sub|split|join|format|encode|decode|read|write|open|close|get|set|post|put|delete|parse|load|dump|loads|dumps|update|replace|strip|lower|upper|title)\b', re.I),
    re.compile(r'\b(re|os|sys|json|time|math|io|csv|xml|html|http|urllib|requests|flask|django|numpy|pandas|torch|sklearn|scipy)\b\.',  re.I),
    re.compile(r'^[a-z]+\.[a-z]+$'),           # generic "module.function" with only lowercase
    re.compile(r'\bdecodefrom\b', re.I),        # Go method artifact bgpupdate.decodefrombytes
    re.compile(r'\bmonoglyphrat\b', re.I),      # JS parser artifact
    re.compile(r'^js\.[a-z]', re.I),            # js.* artifacts
    re.compile(r'^[a-z_]+\.[a-z_]+\b$'),        # snake_case.method patterns
    re.compile(r'utm_source=', re.I),            # tracking URLs masquerading as IOCs
    # Source/advisory site URLs (not operational IOCs)
    re.compile(r'^https?://vulners\.com', re.I),
    re.compile(r'^https?://cvefeed\.io', re.I),
    re.compile(r'^https?://nvd\.nist\.gov', re.I),
    re.compile(r'^https?://cve\.mitre\.org', re.I),
    re.compile(r'^https?://www\.cisa\.gov', re.I),
    re.compile(r'^https?://us-cert\.cisa\.gov', re.I),
    re.compile(r'^https?://github\.com/[^/]+/[^/]+/(security|commit|releases|issues|pull|advisory)', re.I),
    re.compile(r'^https?://thehackernews\.com/', re.I),
    re.compile(r'^https?://www\.bleepingcomputer\.com/', re.I),
    re.compile(r'^https?://krebsonsecurity\.com/', re.I),
    re.compile(r'^https?://securityaffairs\.com/', re.I),
    re.compile(r'^https?://www\.securityweek\.com/', re.I),
    # Version strings (v1.2.3, 1.2.3, 1.2.3.4 that isn't an IPv4)
    re.compile(r'^v?\d+\.\d+(\.\d+)*(-[a-zA-Z0-9]+)?$'),
    # Hex strings of wrong lengths (not 32/40/64/128 = not a known hash)
    re.compile(r'^[0-9a-fA-F]{8}$'),
    re.compile(r'^[0-9a-fA-F]{16}$'),
    re.compile(r'^[0-9a-fA-F]{24}$'),
    re.compile(r'^[0-9a-fA-F]{48}$'),
    # Pure numeric strings — not an IOC (port numbers, counts, etc.)
    re.compile(r'^\d+$'),
]

# Domain allowlist suffixes that are common false positives when very short
_COMMON_FP_DOMAINS = {
    "example.com", "test.com", "localhost", "localhost.localdomain",
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
}

# Private IP ranges
_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                         "127.", "0.0.0.", "169.254.", "::1", "fc", "fd")


def _is_valid_ipv4(s: str) -> bool:
    if not _RE_IPV4.match(s):
        return False
    if s.startswith(_PRIVATE_IP_PREFIXES):
        return False
    parts = s.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def classify_ioc(indicator) -> tuple:
    """Returns (type_str, is_valid, reason).
    Accepts string or dict-style IOC (extracts indicator/value key if dict).

    Order of precedence:
      1. Unambiguous structured types (CVE, MITRE, GUID, hashes, registry, paths,
         mutex, filenames, ASN) — checked BEFORE artifact patterns to prevent
         legitimate IOCs being classified as artifacts.
      2. Artifact pattern rejection — for strings not matched in step 1.
      3. Network IOCs (IP, CIDR, IPv6, URL, domain, email).
      4. Unknown fallthrough.
    """
    if isinstance(indicator, dict):
        indicator = (indicator.get("indicator") or indicator.get("value")
                     or indicator.get("ioc") or indicator.get("id") or "")
    s = (str(indicator) if indicator else "").strip()
    if not s or len(s) < 4:
        return ("UNKNOWN", False, "too short")

    if s in _COMMON_FP_DOMAINS:
        return ("DOMAIN_FP", False, "common false positive domain")

    # ── STEP 1: Unambiguous structured types (checked before artifact filter) ──

    # CVE
    if _RE_CVE.match(s):
        return ("CVE", True, "valid CVE ID")

    # MITRE TTP (T1234 / T1234.001)
    if _RE_MITRE.match(s):
        return ("MITRE_TTP", True, "valid MITRE technique ID")

    # GUID / UUID — check before MD5 (MD5 also 32 hex chars but no dashes)
    if _RE_GUID.match(s):
        return ("GUID", True, "valid GUID/mutex identifier")

    # Hashes — check BEFORE artifact patterns (all-hex strings of exact length)
    if _RE_SHA512.match(s):
        return ("SHA512", True, "valid SHA512 hash")
    if _RE_SHA256.match(s):
        return ("SHA256", True, "valid SHA256 hash")
    if _RE_SHA1.match(s):
        return ("SHA1", True, "valid SHA1 hash")
    if _RE_MD5.match(s):
        return ("MD5", True, "valid MD5 hash")

    # ASN (AS + digits, e.g. AS12345)
    if _RE_ASN.match(s):
        return ("ASN", True, "valid ASN")

    # Windows Registry key — has backslash + HKEY_ prefix or similar
    if _RE_REGISTRY.match(s):
        return ("REGISTRY_KEY", True, "valid Windows registry key IOC")

    # Windows file path (%APPDATA%\, C:\, \\UNC)
    if _RE_WIN_PATH.match(s):
        return ("WIN_PATH", True, "valid Windows file path IOC")

    # Unix/Linux file path (/etc/, /var/, /tmp/, etc.)
    if _RE_UNIX_PATH.match(s):
        return ("UNIX_PATH", True, "valid Unix file path IOC")

    # Mutex / named pipe (Global\, Local\, \BaseNamedObjects\, \\.\pipe\)
    if _RE_MUTEX.match(s):
        return ("MUTEX", True, "valid mutex/named pipe IOC")

    # Malicious filename (svchost.exe, dropper.dll, script.ps1, etc.)
    if _RE_MALICIOUS_FILENAME.match(s):
        return ("FILENAME", True, "valid malicious filename IOC")

    # IPv4 / CIDR — unambiguous; must precede version-string artifact pattern
    if _RE_IPV4_CIDR.match(s):
        try:
            prefix_len = int(s.split("/")[1])
            if 0 <= prefix_len <= 32:
                return ("IPv4_CIDR", True, "valid IPv4 CIDR network")
        except (ValueError, IndexError):
            pass

    if _RE_IPV4.match(s):
        if _is_valid_ipv4(s):
            return ("IPv4", True, "valid public IPv4")
        return ("IPv4_PRIVATE", False, "private/loopback IPv4")

    # ── STEP 2: Artifact pattern rejection ──────────────────────────────────────
    for pat in _ARTIFACT_PATTERNS:
        if pat.search(s):
            return ("ARTIFACT", False, f"matches artifact pattern: {pat.pattern[:40]}")

    # ── STEP 3: Remaining network IOCs ─────────────────────────────────────────

    # URL (before domain to avoid misclassification)
    if _RE_URL.match(s):
        return ("URL", True, "valid URL")

    # Email
    if _RE_EMAIL.match(s):
        return ("EMAIL", True, "valid email address")

    # IPv6
    if _RE_IPV6.match(s):
        return ("IPv6", True, "valid IPv6")

    # Domain — require 2-char minimum on first and last label
    if _RE_DOMAIN.match(s):
        parts = s.split(".")
        if len(parts) >= 2 and len(parts[-1]) >= 2 and len(parts[0]) >= 2:
            return ("DOMAIN", True, "valid domain")

    return ("UNKNOWN", False, "does not match any valid IOC pattern")


def audit_iocs(items: list) -> dict:
    """Audit all IOC fields in a feed for quality."""
    total = 0
    valid = 0
    invalid = 0
    by_type: dict = {}
    artifact_examples = []
    unknown_examples = []

    for item in items:
        iocs = item.get("iocs") or []
        for ioc in iocs:
            # Normalize dict-style IOCs {"indicator": "...", "type": "..."} to string
            if isinstance(ioc, dict):
                ioc_str = str(ioc.get("indicator") or ioc.get("value") or ioc.get("ioc") or "")
            else:
                ioc_str = str(ioc) if ioc else ""
            total += 1
            ioc_type, is_valid, reason = classify_ioc(ioc_str)
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            if is_valid:
                valid += 1
            else:
                invalid += 1
                if ioc_type == "ARTIFACT" and len(artifact_examples) < 20:
                    artifact_examples.append({"ioc": ioc_str, "reason": reason, "item": item.get("title", "")[:50]})
                elif ioc_type == "UNKNOWN" and len(unknown_examples) < 10:
                    unknown_examples.append({"ioc": ioc_str, "reason": reason, "item": item.get("title", "")[:50]})

    false_rate = round(100 * invalid / max(total, 1), 2)
    return {
        "total_iocs": total,
        "valid_iocs": valid,
        "invalid_iocs": invalid,
        "false_positive_rate_pct": false_rate,
        "by_type": by_type,
        "artifact_examples": artifact_examples,
        "unknown_examples": unknown_examples,
        "TARGET_MET": false_rate < 1.0,
        "VERDICT": "PASS" if false_rate < 1.0 else "FAIL",
    }


def clean_item_iocs(item: dict) -> dict:
    """Remove invalid IOCs from a single item."""
    iocs = item.get("iocs")
    if not iocs:
        return item
    clean = [ioc for ioc in iocs if classify_ioc(ioc)[1]]
    out = dict(item)
    out["iocs"] = clean
    out["ioc_count"] = len(clean)
    return out


def clean_feed_iocs(items: list) -> list:
    return [clean_item_iocs(i) for i in items]


# ─── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IOC Quality Governor v1.0")
    parser.add_argument("--feed",   default=os.path.join(REPO, "api", "feed.json"))
    parser.add_argument("--fix",    action="store_true")
    parser.add_argument("--report", default=os.path.join(REPO, "reports", "ioc_quality_report.json"))
    args = parser.parse_args()

    feed_path = pathlib.Path(args.feed)
    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", [])

    print("=" * 60)
    print("IOC QUALITY GOVERNOR  v1.0")
    print(f"Feed: {feed_path}  ({len(items)} items)")
    print("=" * 60)

    audit = audit_iocs(items)
    print(f"Total IOCs   : {audit['total_iocs']}")
    print(f"Valid        : {audit['valid_iocs']}")
    print(f"Invalid/FP   : {audit['invalid_iocs']}")
    print(f"False+ Rate  : {audit['false_positive_rate_pct']}%  (target <1%)")
    print(f"Verdict      : {audit['VERDICT']}")
    print(f"\nBy type: {audit['by_type']}")
    if audit["artifact_examples"]:
        print(f"\nArtifact examples:")
        for ex in audit["artifact_examples"][:5]:
            print(f"  [{ex['ioc']}] in '{ex['item']}'")

    if args.fix:
        cleaned = clean_feed_iocs(items)
        tmp = feed_path.with_suffix(".iocq.tmp")
        out = cleaned if isinstance(raw, list) else {**raw, "items": cleaned}
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(feed_path)
        print(f"\n[FIX] Cleaned IOCs written to {feed_path}")

    rpath = pathlib.Path(args.report)
    rpath.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "report_type": "ioc_quality_report",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": "v1.0",
        "feed_path": str(feed_path),
        "audit": audit,
        "fix_applied": args.fix,
        "VERDICT": audit["VERDICT"],
    }
    rpath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[REPORT] {rpath}")
    sys.exit(0 if audit["TARGET_MET"] else 1)
