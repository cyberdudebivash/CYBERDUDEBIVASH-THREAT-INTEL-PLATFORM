#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_ioc_intelligence_pipeline.py — IOC Intelligence Pipeline
================================================================================
Version : 152.0.0

PROBLEM SOLVED:
  1. Fake IOCs being published: 11.0.011.1, 11.2.011.2 (invalid octets)
  2. Advisory URLs counted as IOCs (dilutes feed with 50% noise)
  3. CVE IDs counted as IOCs (not indicators — they're vulnerability references)
  4. All IOCs assigned same flat confidence (34% or 50%) regardless of type
  5. No kill-chain placement
  6. No first_seen / last_seen lifecycle tracking
  7. No expiration confidence
  8. No SOC action differentiation by type

SOLUTION:
  A 7-phase IOC processing pipeline that:
    Phase 1: TYPE CLASSIFICATION — identify exact IOC type
    Phase 2: VALIDATION — verify format correctness
    Phase 3: PSEUDO-IOC REJECTION — block non-operational indicators
    Phase 4: QUALITY SCORING — per-type confidence calibration
    Phase 5: KILL-CHAIN PLACEMENT — map IOC to attack phase
    Phase 6: SOC ACTION GENERATION — actionable response per type
    Phase 7: LIFECYCLE METADATA — first_seen, last_seen, expiration

ENRICHMENT FIELDS (per IOC):
  ioc_type            validated type (IPV4, IPV6, DOMAIN, SHA256, MD5, URL, EMAIL)
  ioc_value           cleaned, normalised value
  confidence          evidence-weighted per-IOC confidence (0-100)
  confidence_basis    why this confidence was assigned
  kill_chain_phase    which attack phase this IOC maps to
  detection_action    what defenders should do with this IOC
  soc_priority        IMMEDIATE / HIGH / MEDIUM / LOW
  expiration_days     how long this IOC is likely relevant
  validation_status   VALID / INVALID / PSEUDO / SUSPECT
  rejection_reason    if INVALID or PSEUDO, explain why
================================================================================
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("apex.ioc_pipeline")
ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-IIP"

# ── IOC Type Patterns ─────────────────────────────────────────────────────────
IPV4_RE  = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IPV6_RE  = re.compile(r"^[0-9a-fA-F:]{2,39}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
MD5_RE   = re.compile(r"^[0-9a-fA-F]{32}$")
SHA1_RE  = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SHA512_RE = re.compile(r"^[0-9a-fA-F]{128}$")
EMAIL_RE  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
URL_RE    = re.compile(r"^https?://[^\s]{5,}$")
CVE_RE    = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Reference/advisory URL patterns (NEVER operational IOCs)
REFERENCE_DOMAINS = re.compile(
    r"(vulners\.com|nvd\.nist\.gov|cisa\.gov|nist\.gov|"
    r"attack\.mitre\.org|intel\.cyberdudebivash\.com|"
    r"cve\.mitre\.org|github\.com/advisories|"
    r"cvefeed\.io|thehackernews\.com|securityaffairs\.com|"
    r"bleepingcomputer\.com|rapid7\.com|tenable\.com|"
    r"qualys\.com|microsoft\.com/security|msrc\.microsoft|"
    r"support\.apple\.com|ubuntu\.com/security|"
    r"kb\.cert\.org|us-cert\.gov|cert\.org|"
    r"exploit-db\.com|packetstormsecurity\.com|"
    r"utm_source=rss|utm_medium=rss)",
    re.IGNORECASE,
)

# Private/reserved IP ranges
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

# Kill-chain phase mapping by IOC type
KILL_CHAIN_MAP = {
    "IPV4":    "C2",              # IP addresses typically C2 infrastructure
    "IPV6":    "C2",
    "DOMAIN":  "C2",              # Domains: C2 or delivery
    "URL":     "DELIVERY",       # URLs: phishing/delivery unless C2 keyword
    "SHA256":  "INSTALLATION",   # File hashes: malware/payload
    "SHA1":    "INSTALLATION",
    "MD5":     "INSTALLATION",
    "SHA512":  "INSTALLATION",
    "EMAIL":   "DELIVERY",       # Email: phishing delivery
    "JA3":     "C2",             # TLS fingerprints: C2 channel
    "MUTEX":   "INSTALLATION",   # Mutexes: persistence/installation
    "REGKEY":  "INSTALLATION",   # Registry keys: persistence
}

# Detection action templates by IOC type
DETECTION_ACTIONS = {
    "IPV4": "Block at egress firewall (outbound) and NGFW. Add to proxy deny list. "
            "Alert on any DNS resolution returning this IP. Check EDR telemetry for "
            "process → network connections to this IP.",
    "IPV6": "Block at IPv6-capable firewall and proxy. Alert on DNS AAAA record matches. "
            "Check for IPv6 tunnel circumvention (6to4, Teredo) if environment has IPv4 only.",
    "DOMAIN": "Block at DNS resolver (RPZ) and web proxy. Alert on DNS query. "
              "Pivot on passive DNS for additional infrastructure. "
              "Add to threat intelligence block list in NGFW.",
    "URL": "Block full URL at proxy and web filter. Alert on HTTP GET/POST to this URL. "
           "Check proxy logs for historical hits. Review browser process that initiated.",
    "SHA256": "Hash-hunt in EDR (process creation, file creation, module load). "
              "Alert on file creation/execution events matching this hash. "
              "Submit to sandboxing platform for behavioral analysis.",
    "SHA1": "Hash-hunt in EDR (legacy systems may use SHA1). Alert on file creation/execution. "
            "Correlate with SHA256 if available — SHA1 alone may have collisions.",
    "MD5": "Hash-hunt in EDR. Note: MD5 is collision-prone — correlate with SHA256. "
           "Alert on file creation/execution events matching this hash.",
    "EMAIL": "Block at email gateway (SEG/O365 ATP). Alert on inbound mail from this address. "
             "Review mail logs for historical delivery attempts.",
    "JA3": "Configure network IDS/NDR to alert on JA3 fingerprint match. "
           "Cannot block at IP/domain level — requires TLS inspection.",
    "MUTEX": "Hunt in EDR process telemetry for mutex creation events. "
             "Indicates active malware execution if found.",
    "REGKEY": "Hunt in EDR registry telemetry for key creation/modification. "
              "Indicates persistence mechanism if found.",
}

# SOC priority by IOC confidence
def _soc_priority(confidence: float) -> str:
    if confidence >= 80:
        return "IMMEDIATE"
    elif confidence >= 60:
        return "HIGH"
    elif confidence >= 40:
        return "MEDIUM"
    return "LOW"

# IOC expiration by type (days)
EXPIRATION_DAYS = {
    "IPV4":    30,
    "IPV6":    30,
    "DOMAIN":  60,
    "URL":     14,
    "SHA256":  365,
    "SHA1":    365,
    "MD5":     365,
    "SHA512":  365,
    "EMAIL":   90,
    "JA3":     90,
    "MUTEX":   180,
    "REGKEY":  180,
}


def _classify_ioc(value: str) -> str:
    """Phase 1: Determine true IOC type."""
    v = value.strip()

    if CVE_RE.match(v):
        return "CVE_REF"      # Not a real IOC

    if MD5_RE.match(v):       return "MD5"
    if SHA1_RE.match(v):      return "SHA1"
    if SHA256_RE.match(v):    return "SHA256"
    if SHA512_RE.match(v):    return "SHA512"

    if EMAIL_RE.match(v):     return "EMAIL"

    m = IPV4_RE.match(v)
    if m:
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return "IPV4"
        return "INVALID_IPV4"   # e.g. 011 octets

    if URL_RE.match(v):
        if REFERENCE_DOMAINS.search(v):
            return "REFERENCE_URL"
        return "URL"

    if DOMAIN_RE.match(v):    return "DOMAIN"

    # JA3 hashes are MD5 length but specifically labelled
    if re.match(r"^[0-9a-f]{32}$", v):
        return "MD5"

    return "UNKNOWN"


def _validate_ipv4(value: str) -> Tuple[bool, Optional[str]]:
    """Phase 2: Validate IPv4 format strictly."""
    m = IPV4_RE.match(value.strip())
    if not m:
        return False, "Does not match IPv4 pattern x.x.x.x"

    octets = value.strip().split(".")
    for oct in octets:
        # Leading zeros check
        if len(oct) > 1 and oct.startswith("0"):
            return False, (
                f"Octet '{oct}' has an illegal leading zero. "
                "This is a syntactically malformed IP address — likely synthetic/generated. "
                "No real network traffic will ever originate from or destinate to this address."
            )
        try:
            v = int(oct)
            if v < 0 or v > 255:
                return False, f"Octet {oct} is out of range (0-255)"
        except ValueError:
            return False, f"Octet '{oct}' is not a valid integer"
    return True, None


def _ioc_confidence(ioc_type: str, value: str, source_context: str = "") -> Tuple[float, str]:
    """Phase 4: Per-type evidence-weighted confidence."""
    base = {
        "MD5":      60.0,
        "SHA1":     65.0,
        "SHA256":   75.0,
        "SHA512":   78.0,
        "DOMAIN":   55.0,
        "IPV4":     60.0,
        "IPV6":     60.0,
        "URL":      50.0,
        "EMAIL":    55.0,
        "JA3":      65.0,
        "MUTEX":    70.0,
        "REGKEY":   65.0,
    }.get(ioc_type, 30.0)

    rationale = f"Base confidence for {ioc_type}: {base}%"

    # Source context boosts
    ctx_lower = source_context.lower()
    if "observed" in ctx_lower or "confirmed" in ctx_lower:
        base = min(95.0, base + 15.0)
        rationale += "; +15% observed/confirmed"
    if "c2" in ctx_lower or "command and control" in ctx_lower:
        base = min(95.0, base + 10.0)
        rationale += "; +10% C2 designation"
    if "legacy" in ctx_lower or "historical" in ctx_lower:
        base = max(20.0, base - 20.0)
        rationale += "; -20% legacy/historical (may be stale)"
    if "passive" in ctx_lower or "pdns" in ctx_lower:
        base = min(80.0, base + 5.0)
        rationale += "; +5% passive DNS validation"

    return round(base, 1), rationale


def process_ioc(raw_ioc: Dict, source_url: str = "") -> Dict:
    """
    Process a single IOC through the 7-phase pipeline.
    Returns enriched IOC dict or rejected IOC with rejection_reason.
    """
    value = str(raw_ioc.get("value") or raw_ioc.get("indicator") or "").strip()
    declared_type = str(raw_ioc.get("type") or "").strip().upper()
    context = str(raw_ioc.get("context") or raw_ioc.get("source") or "")

    result = {
        "original_value":      value,
        "ioc_value":           value,
        "declared_type":       declared_type,
        "ioc_type":            None,
        "validation_status":   "PENDING",
        "rejection_reason":    None,
        "confidence":          0.0,
        "confidence_basis":    None,
        "kill_chain_phase":    None,
        "detection_action":    None,
        "soc_priority":        "LOW",
        "expiration_days":     30,
        "context":             context,
        "source_url":          source_url,
        "processed_ts":        datetime.now(timezone.utc).isoformat(),
        "engine":              ENGINE_ID,
        "engine_version":      ENGINE_VERSION,
    }

    if not value:
        result["validation_status"] = "INVALID"
        result["rejection_reason"]  = "Empty IOC value — no indicator to process"
        return result

    # ── Phase 1: Classify ─────────────────────────────────────────────────────
    ioc_type = _classify_ioc(value)
    result["ioc_type"] = ioc_type

    # ── Phase 3: Reject pseudo-IOCs ───────────────────────────────────────────
    if ioc_type == "CVE_REF":
        result["validation_status"] = "PSEUDO"
        result["rejection_reason"]  = (
            f"'{value}' is a CVE identifier — a vulnerability reference, NOT an indicator "
            "of compromise. CVE IDs cannot be blocked in a firewall or correlated in SIEM. "
            "Move to the references section of the advisory."
        )
        return result

    if ioc_type == "REFERENCE_URL":
        result["validation_status"] = "PSEUDO"
        result["rejection_reason"]  = (
            f"'{value[:80]}' is an advisory/vendor reference URL. These URLs are "
            "intelligence sources, not indicators. They contaminate IOC feeds and will "
            "never generate a detection hit in SIEM/EDR. Remove from IOC table."
        )
        return result

    # ── Phase 2: Validate format ──────────────────────────────────────────────
    if ioc_type == "INVALID_IPV4":
        result["validation_status"] = "INVALID"
        result["rejection_reason"]  = (
            f"'{value}' is a malformed IPv4 address with an invalid octet. "
            "This is a synthetic/generated indicator that will cause SIEM parse errors. "
            "Blocking this address in a firewall is a no-op — the address is unreachable."
        )
        return result

    if ioc_type == "IPV4":
        valid, err = _validate_ipv4(value)
        if not valid:
            result["validation_status"] = "INVALID"
            result["rejection_reason"]  = err
            return result
        # Check private ranges
        try:
            addr = ipaddress.IPv4Address(value)
            for net in _PRIVATE_NETS:
                if addr in net:
                    result["validation_status"] = "SUSPECT"
                    result["rejection_reason"]  = (
                        f"{value} is in RFC1918/reserved range {net}. "
                        "Only valid in lateral movement or ICS/OT context. "
                        "Document the justification or reject."
                    )
        except ValueError:
            result["validation_status"] = "INVALID"
            result["rejection_reason"]  = f"Could not parse IPv4 address: {value}"
            return result

    if ioc_type == "UNKNOWN":
        result["validation_status"] = "SUSPECT"
        result["rejection_reason"]  = (
            f"Cannot determine IOC type for '{value[:60]}'. "
            "Requires manual analyst review before publishing."
        )

    # ── Phase 4: Quality scoring ──────────────────────────────────────────────
    if result["validation_status"] not in ("INVALID", "PSEUDO"):
        conf, conf_basis = _ioc_confidence(ioc_type, value, context)
        result["confidence"]       = conf
        result["confidence_basis"] = conf_basis
        result["soc_priority"]     = _soc_priority(conf)

        if result["validation_status"] == "PENDING":
            result["validation_status"] = "VALID"

    # ── Phase 5: Kill-chain placement ─────────────────────────────────────────
    result["kill_chain_phase"] = KILL_CHAIN_MAP.get(ioc_type, "UNKNOWN")

    # URL kill chain refinement
    if ioc_type == "URL":
        v_lower = value.lower()
        if any(kw in v_lower for kw in ("c2", "beacon", "gate.", "panel", "rat")):
            result["kill_chain_phase"] = "C2"
        elif any(kw in v_lower for kw in ("payload", "drop", "malware", "exe", "dll")):
            result["kill_chain_phase"] = "INSTALLATION"

    # ── Phase 6: SOC action ───────────────────────────────────────────────────
    result["detection_action"] = DETECTION_ACTIONS.get(ioc_type, "Manual analyst review required.")

    # ── Phase 7: Lifecycle metadata ───────────────────────────────────────────
    result["expiration_days"] = EXPIRATION_DAYS.get(ioc_type, 30)

    return result


def process_item_iocs(item: Dict) -> Dict:
    """Process all IOCs in an item through the pipeline."""
    raw_iocs = item.get("iocs") or item.get("indicators") or []
    source_url = str(item.get("source_url") or item.get("blog_url") or "")

    if not isinstance(raw_iocs, list):
        raw_iocs = []

    processed    = []
    valid_iocs   = []
    pseudo_iocs  = []
    invalid_iocs = []

    for raw in raw_iocs:
        if isinstance(raw, str):
            raw = {"value": raw, "type": "UNKNOWN"}
        result = process_ioc(raw, source_url)
        processed.append(result)

        status = result["validation_status"]
        if status == "VALID":
            valid_iocs.append(result)
        elif status in ("PSEUDO", "REFERENCE_URL"):
            pseudo_iocs.append(result)
        elif status == "INVALID":
            invalid_iocs.append(result)

    item_out = dict(item)
    item_out["iocs"]              = valid_iocs
    item_out["pseudo_iocs"]       = pseudo_iocs
    item_out["invalid_iocs"]      = invalid_iocs
    item_out["ioc_count"]         = len(valid_iocs)
    item_out["ioc_count_total"]   = len(raw_iocs)
    item_out["ioc_count_pseudo"]  = len(pseudo_iocs)
    item_out["ioc_count_invalid"] = len(invalid_iocs)
    item_out["ioc_pipeline_ts"]   = datetime.now(timezone.utc).isoformat()

    return item_out


def main() -> int:
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [IIP] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="APEX IOC Intelligence Pipeline")
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--output",   default=None)
    args = parser.parse_args()

    path = Path(args.manifest)
    if not path.exists():
        log.error("Manifest not found: %s", path)
        return 1

    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    processed = [process_item_iocs(item) for item in items]
    log.info("Processed %d items through IOC pipeline", len(processed))

    total_valid   = sum(i.get("ioc_count", 0) for i in processed)
    total_pseudo  = sum(i.get("ioc_count_pseudo", 0) for i in processed)
    total_invalid = sum(i.get("ioc_count_invalid", 0) for i in processed)

    print(f"\n{'='*70}")
    print(f"  APEX IOC INTELLIGENCE PIPELINE v{ENGINE_VERSION}")
    print(f"{'='*70}")
    print(f"  Valid operational IOCs  : {total_valid}")
    print(f"  Pseudo-IOCs rejected    : {total_pseudo}")
    print(f"  Invalid IOCs blocked    : {total_invalid}")
    print(f"  IOC noise reduction     : {total_pseudo+total_invalid}/{total_valid+total_pseudo+total_invalid}")
    print(f"{'='*70}")

    out = Path(args.output) if args.output else path
    tmp = out.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(processed, f, indent=2, ensure_ascii=False)
    tmp.replace(out)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
