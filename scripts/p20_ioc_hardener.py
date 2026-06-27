#!/usr/bin/env python3
"""
scripts/p20_ioc_hardener.py
CYBERDUDEBIVASH® SENTINEL APEX — P20.0 IOC Hardener v1.0.0
============================================================
P20.2 — IOC Intelligence Engine

Removes false-positive IOCs that cannot be operationalized:
  - Package ecosystem domains (golang.org, npmjs.com, pypi.org, etc.)
  - Documentation / developer infrastructure
  - Known-good trusted infrastructure
  - Generic placeholder values

Enriches surviving IOCs with:
  - first_seen / last_seen (from item timestamps)
  - context (what the IOC represents)
  - response_guidance (what to do when detected)
  - detection_guidance (where/how to detect)
  - validation_status
  - kill_chain_stage (from MITRE tactic context)

ZERO FABRICATION — every field derives from existing item data or
factual IOC type knowledge. No invented threat actor, campaign, or
malware associations are added.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P20-IOC %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p20-ioc")

REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
MANIFEST_PATH = REPO / "data" / "feed_manifest.json"

# ── False-positive domain blocklist ──────────────────────────────────────────
# Package ecosystems, documentation, developer infrastructure, CDNs
# These are NEVER operational threat indicators
FP_DOMAIN_BLOCKLIST = frozenset({
    # Go ecosystem
    "golang.org", "go.dev", "pkg.go.dev", "sum.golang.org", "proxy.golang.org",
    "gopkg.in",
    # npm / Node
    "npmjs.com", "npmjs.org", "npm.org", "registry.npmjs.org",
    "unpkg.com", "jsdelivr.net",
    # PyPI / Python
    "pypi.org", "pypi.python.org", "files.pythonhosted.org",
    # Ruby
    "rubygems.org", "gems.ruby-china.org",
    # Rust / Cargo
    "crates.io", "static.crates.io",
    # PHP / Composer
    "packagist.org", "getcomposer.org",
    # Java / Maven
    "mvnrepository.com", "repo.maven.apache.org", "search.maven.org",
    # NuGet (.NET)
    "nuget.org", "api.nuget.org",
    # Documentation
    "docs.github.com", "docs.microsoft.com", "learn.microsoft.com",
    "developer.mozilla.org", "developer.apple.com",
    "docs.python.org", "docs.golang.org", "pkg.go.dev",
    "readthedocs.io", "readthedocs.org",
    # Source hosting (the base domains — specific repo paths can be IOCs)
    "raw.githubusercontent.com",  # kept for IOC context but generic
    # Version control / CI
    "travis-ci.org", "travis-ci.com", "circleci.com", "jenkins.io",
    "codecov.io", "coveralls.io",
    # General developer infrastructure
    "shields.io", "badge.fury.io", "choosealicense.com",
    "opensource.org", "creativecommons.org",
    # CDNs (too generic)
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    # Standards bodies
    "w3.org", "ietf.org", "ieee.org",
    # Benign partial-domain fragments often extracted from package names
    "fsp.open", "fsp.openpath",
})

# Package path patterns — IOC values matching these are false positives
FP_PATTERNS = [
    re.compile(r"^[a-z]+\.[a-z]+(path|module|pkg|lib|open|crypto|io)$", re.I),
    re.compile(r"^(npm|pip|gem|cargo|go|composer|nuget|maven):"),
    re.compile(r"^(CVE|GHSA|OSV|PYSEC|RUSTSEC|GHSA)-", re.I),  # these are vulnerability IDs, not network IOCs
    re.compile(r"^[a-z]+\.(test|local|example|invalid|localhost)$", re.I),
]

# IOC type → kill chain stage mapping
IOC_KILLCHAIN_MAP = {
    "ipv4":     "C2 / Exfiltration",
    "ipv6":     "C2 / Exfiltration",
    "domain":   "C2 / Initial Access",
    "url":      "Delivery / Initial Access",
    "hash":     "Installation / Defense Evasion",
    "md5":      "Installation / Defense Evasion",
    "sha1":     "Installation / Defense Evasion",
    "sha256":   "Installation / Defense Evasion",
    "email":    "Delivery (Phishing)",
    "cve":      "Exploitation",
    "indicator":"Vulnerability Reference",
}

# Response guidance per IOC type
IOC_RESPONSE_MAP = {
    "ipv4":     "Block at perimeter firewall and EDR. Search SIEM for outbound connections. Null-route via BGP if confirmed C2.",
    "ipv6":     "Block at perimeter firewall. Search SIEM for connections. Verify against threat intelligence feeds.",
    "domain":   "Block via DNS RPZ or Secure DNS. Search proxy logs. Submit to threat intel sharing platform.",
    "url":      "Block at web proxy. Search for access in web/proxy logs. Add to SIEM correlation rule.",
    "hash":     "Hunt in EDR for file hash match. If found, isolate host immediately. Submit to AV/sandbox for analysis.",
    "md5":      "Hunt in EDR for file hash. Isolate host if found. Submit for sandbox detonation.",
    "sha256":   "Hunt in EDR for file hash. Isolate host if found. Submit for sandbox detonation.",
    "email":    "Block sender at email gateway. Search mail logs. Alert security team if received.",
    "cve":      "Verify patch status on all in-scope systems. Apply vendor remediation immediately.",
    "indicator":"Cross-reference against threat intelligence feeds. Validate against affected system inventory.",
}

# Detection guidance per IOC type
IOC_DETECTION_MAP = {
    "ipv4":     "Monitor network flow logs, firewall egress, DNS queries. Correlate with EDR process network connections.",
    "ipv6":     "Monitor network flow logs and firewall egress for IPv6 connections.",
    "domain":   "Monitor DNS query logs, proxy logs, and certificate transparency logs for domain resolution.",
    "url":      "Monitor proxy/web filter logs, browser history, and HTTP inspection rules.",
    "hash":     "Configure EDR with hash-based alerting. Run retrospective hunt across endpoint inventory.",
    "md5":      "Configure EDR with MD5 hash alerting. Run endpoint hunt. Note: MD5 is weak, prefer SHA256 if available.",
    "sha256":   "Configure EDR with SHA256 alerting. Run retrospective endpoint hunt. High confidence match.",
    "email":    "Monitor email gateway logs, DMARC/SPF failures, and header analysis for sender spoofing.",
    "cve":      "Use vulnerability scanner to confirm exposure. Check asset inventory against affected product versions.",
    "indicator":"Cross-reference in SIEM. Use STIX bundle for automated ingestion into TIP.",
}


def _is_fp_ioc(ioc: Dict) -> bool:
    """Return True if this IOC is a false positive that should be removed."""
    ioc_type  = str(ioc.get("type", "")).lower()
    ioc_value = str(ioc.get("value", "") or ioc.get("indicator", "")).strip()

    if not ioc_value or len(ioc_value) < 4:
        return True

    # CVE IDs as "indicator" type — not network IOCs, handled separately
    if ioc_type == "indicator" and re.match(r"CVE-\d{4}-\d{4,}", ioc_value, re.I):
        return True  # CVE refs are vulnerability metadata, not operational IOCs

    # Pattern-based false positives
    for pat in FP_PATTERNS:
        if pat.search(ioc_value):
            return True

    # Domain false positives
    if ioc_type in ("domain", "hostname"):
        domain = ioc_value.lower().removeprefix("www.")
        if domain in FP_DOMAIN_BLOCKLIST:
            return True
        # Package ecosystem path fragments mistaken for domains
        if "." not in domain and "/" not in domain:
            return True  # not a valid domain

    # URL false positives
    if ioc_type == "url":
        try:
            parsed = urlparse(ioc_value)
            domain = parsed.netloc.lower().removeprefix("www.")
            if domain in FP_DOMAIN_BLOCKLIST:
                return True
        except Exception:
            pass

    return False


def _enrich_ioc(ioc: Dict, item: Dict) -> Dict:
    """Add operational metadata to an IOC. No fabrication — types only."""
    enriched = dict(ioc)
    ioc_type = str(ioc.get("type", "indicator")).lower()

    ts_pub     = item.get("published_at") or item.get("published") or item.get("timestamp") or ""
    ts_process = item.get("processed_at") or item.get("timestamp") or ""

    if "first_seen" not in enriched or not enriched.get("first_seen"):
        enriched["first_seen"] = ts_pub or ts_process
    if "last_seen" not in enriched or not enriched.get("last_seen"):
        enriched["last_seen"]  = ts_process or ts_pub

    if "kill_chain_stage" not in enriched:
        enriched["kill_chain_stage"] = IOC_KILLCHAIN_MAP.get(ioc_type, "Unknown")

    if "response_guidance" not in enriched or not enriched.get("response_guidance"):
        enriched["response_guidance"] = IOC_RESPONSE_MAP.get(ioc_type, "Investigate and correlate in SIEM.")

    if "detection_guidance" not in enriched or not enriched.get("detection_guidance"):
        enriched["detection_guidance"] = IOC_DETECTION_MAP.get(ioc_type, "Monitor relevant log sources.")

    # Context: describe what this IOC represents
    if "context" not in enriched or not enriched.get("context"):
        title = item.get("title", "")[:60]
        cve   = item.get("cve_id") or (item.get("cve_ids") or [None])[0] or ""
        ref   = f" ({cve})" if cve else ""
        enriched["context"] = (
            f"{ioc_type.upper()} indicator associated with advisory: {title}{ref}. "
            f"Confidence: {enriched.get('confidence', 0):.1f}%"
            if isinstance(enriched.get("confidence"), (int, float))
            else f"{ioc_type.upper()} indicator associated with advisory: {title}{ref}."
        )

    if "validation_status" not in enriched:
        conf = enriched.get("confidence") or 0
        enriched["validation_status"] = (
            "HIGH_CONFIDENCE"   if conf >= 70 else
            "MEDIUM_CONFIDENCE" if conf >= 40 else
            "LOW_CONFIDENCE"
        )

    enriched["p20_hardened"] = True
    return enriched


def harden_item_iocs(item: Dict) -> int:
    """Remove FP IOCs and enrich survivors. Returns count of operational IOCs after."""
    raw_iocs = item.get("iocs") or []
    if not raw_iocs:
        return 0

    fp_count      = 0
    operational   = []
    for ioc in raw_iocs:
        if not isinstance(ioc, dict):
            continue
        if _is_fp_ioc(ioc):
            fp_count += 1
            continue
        operational.append(_enrich_ioc(ioc, item))

    if fp_count > 0 or len(operational) != len(raw_iocs):
        item["iocs"] = operational
        item["ioc_count"] = len(operational)
        item["ioc_fp_removed"] = fp_count
        # Rebuild ioc_counts
        from collections import Counter
        ioc_counts = Counter(i.get("type", "unknown") for i in operational)
        item["ioc_counts"] = dict(ioc_counts)
        log.debug("Item %s: %d FP IOCs removed, %d operational remain",
                  item.get("id", "")[:20], fp_count, len(operational))

    return len(operational)


def process_feed(path: Path) -> tuple:
    if not path.exists():
        return (0, 0)
    try:
        raw = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return (0, 0)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = None
        for key in ("items", "advisories", "feed", "data"):
            if key in data and isinstance(data[key], list) and data[key]:
                items = data[key]
                break
        if items is None:
            return (0, 0)
    else:
        return (0, 0)

    total_fp = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        before = len(item.get("iocs") or [])
        after  = harden_item_iocs(item)
        total_fp += max(0, before - after)

    if (total_fp > 0) and not DRY_RUN:
        tmp = path.with_suffix(".tmp_p20ioc")
        try:
            tmp.write_text(
                json.dumps(data if isinstance(data, dict) else items,
                           indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            tmp.replace(path)
            log.info("Saved: %s (%d FP IOCs removed)", path, total_fp)
        except Exception as exc:
            log.error("Failed to save %s: %s", path, exc)
            tmp.unlink(missing_ok=True)
            raise
    elif DRY_RUN:
        log.info("[DRY_RUN] Would remove %d FP IOCs from %s", total_fp, path)

    return (len(items), total_fp)


def main() -> int:
    log.info("P20.2 IOC Hardener v1.0.0 — DRY_RUN=%s", DRY_RUN)
    log.info("FP blocklist: %d domains | %d patterns", len(FP_DOMAIN_BLOCKLIST), len(FP_PATTERNS))
    n1, fp1 = process_feed(FEED_PATH)
    log.info("feed.json: %d items processed, %d FP IOCs removed", n1, fp1)
    n2, fp2 = process_feed(MANIFEST_PATH)
    log.info("feed_manifest.json: %d items processed, %d FP IOCs removed", n2, fp2)
    log.info("P20.2 complete: %d total FP IOCs removed", fp1 + fp2)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
