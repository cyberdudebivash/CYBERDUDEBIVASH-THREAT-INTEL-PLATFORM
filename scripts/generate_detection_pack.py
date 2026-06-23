#!/usr/bin/env python3
"""
SENTINEL APEX v185.0 — Detection Pack Generator [GOD-MODE]
===========================================================
PURPOSE — PREMIUM DETECTION ENGINEERING PRODUCT:
  Extracts and packages all detection rules (Sigma, KQL, Suricata) and structured
  IOC data from the certified baseline into a deployable Detection Pack that
  customers can import directly into their SIEM, EDR, and firewall platforms.

PRODUCTS GENERATED:
  api/detections/pack_manifest.json     — Detection pack catalogue
  api/detections/sigma_rules.yml        — All Sigma rules (GOLD+SILVER tier)
  api/detections/kql_queries.kql        — Microsoft Sentinel / Defender KQL rules
  api/detections/ioc_blocklist.txt      — Flat IOC list for firewall/DNS blocking
  api/detections/ioc_structured.json   — Structured IOC export (type, value, context)
  api/detections/cve_watchlist.csv      — CVE watchlist for vuln management tools

PRICING / PACKAGING:
  Detection Pack Add-On: +$149/mo on top of any plan
  Enterprise Bundle:      Included in Enterprise Plan ($999/mo)

CUSTOMER INTEGRATION PATHS:
  - Microsoft Sentinel: Import KQL queries directly as analytics rules
  - Splunk / SIEM:      Import Sigma rules via sigma2splunk / Uncoder.io
  - Palo Alto / FortiGate: Import ioc_blocklist.txt as external block list
  - Qualys / Tenable:   Import cve_watchlist.csv for prioritized scanning
  - CrowdStrike:        Import Sigma rules via MITRE ATT&CK mapping
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

REPO          = Path(__file__).resolve().parent.parent
BASELINE_PATH = Path(os.environ.get("BASELINE_PATH", str(REPO / "api" / "feed.baseline.json")))
DETECTIONS_DIR = REPO / "api" / "detections"
DRY_RUN       = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
PLATFORM_BASE = "https://intel.cyberdudebivash.com"
VERSION       = "185.0"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("detection_pack")


def _safe_float(val: object, default: float = 0.0) -> float:
    try:
        return float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _extract_cve(item: Dict) -> Optional[str]:
    for field in ("title", "id", "stix_id", "source_url"):
        m = _CVE_RE.search(str(item.get(field) or ""))
        if m:
            return m.group(0).upper()
    return None


def _atomic_write_bytes(path: Path, data: bytes) -> bool:
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
        return True
    except Exception as exc:
        log.error("Write failed %s: %s", path, exc)
        tmp.unlink(missing_ok=True)
        return False


def _atomic_write_text(path: Path, data: str) -> bool:
    return _atomic_write_bytes(path, data.encode("utf-8"))


def _atomic_write_json(path: Path, data: object) -> bool:
    return _atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — Detection Pack Generator v%s [GOD-MODE]", VERSION)
    log.info("Baseline : %s", BASELINE_PATH)
    log.info("Output   : %s", DETECTIONS_DIR)
    log.info("=" * 60)

    if not BASELINE_PATH.exists():
        log.error("Baseline not found: %s", BASELINE_PATH)
        return 1

    try:
        baseline: List[Dict] = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to parse baseline: %s", exc)
        return 1

    if not isinstance(baseline, list):
        log.error("Baseline must be a list")
        return 1

    total = len(baseline)
    log.info("Loaded baseline: %d items", total)

    now_ts = datetime.now(timezone.utc).isoformat()
    DETECTIONS_DIR.mkdir(parents=True, exist_ok=True)

    # ── 1. Sigma rules (YAML bundle) ─────────────────────────────────────────────
    sigma_lines: List[str] = []
    sigma_count = 0
    for item in baseline:
        sigma_raw = str(item.get("sigma_rule") or "").strip()
        if not sigma_raw:
            continue
        cve_id = _extract_cve(item)
        tier   = item.get("premium_tier", "STANDARD")
        # Sanitize title: replace newlines with space so YAML comment stays on one line
        title  = str(item.get("title") or "").replace("\r", "").replace("\n", " ").strip()[:80]
        sigma_lines.append(f"# ── [{tier}] {title}")
        if cve_id:
            sigma_lines.append(f"# CVE: {cve_id}")
        sigma_lines.append(f"# Source: {item.get('source_url', '')}")
        sigma_lines.append(f"# Risk: {_safe_float(item.get('risk_score')):.2f} | Severity: {item.get('severity', 'UNKNOWN')}")
        # --- MUST come BEFORE the rule body so YAML sees a proper document-start
        # marker. Without it, every rule's `title:` is treated as a new mapping
        # in the same document, which is a YAML parse error.
        sigma_lines.append("---")
        # Strip any leading --- from sigma_raw to avoid double document markers
        sigma_clean = sigma_raw.lstrip("-").lstrip()
        sigma_lines.append(sigma_clean)
        sigma_lines.append("")  # blank line between rules
        sigma_count += 1

    sigma_header = "\n".join([
        "# CYBERDUDEBIVASH SENTINEL APEX — Sigma Detection Rules Bundle",
        f"# Version: {VERSION} | Generated: {now_ts}",
        f"# Platform: {PLATFORM_BASE}",
        f"# Total rules: {sigma_count}",
        f"# Coverage: GOLD+SILVER+STANDARD certified items",
        f"# Import: sigma2splunk, Uncoder.io, SIEM native Sigma import",
        "# TLP: Handle per individual rule TLP classification",
        "",
        "# ═══════════════════════════════════════════════════════════════════",
        "",
    ])
    sigma_body = sigma_header + "\n".join(sigma_lines)

    # ── 2. KQL queries (Microsoft Sentinel / Defender) ────────────────────────────
    kql_lines: List[str] = []
    kql_count = 0
    for item in baseline:
        kql_raw = str(item.get("kql_query") or "").strip()
        if not kql_raw:
            continue
        cve_id = _extract_cve(item)
        tier   = item.get("premium_tier", "STANDARD")
        title  = str(item.get("title") or "").replace("\r", "").replace("\n", " ").strip()[:80]
        kql_lines.append(f"// ── [{tier}] {title}")
        if cve_id:
            kql_lines.append(f"// CVE: {cve_id}")
        kql_lines.append(f"// Risk: {_safe_float(item.get('risk_score')):.2f} | Severity: {item.get('severity', 'UNKNOWN')}")
        kql_lines.append(f"// STIX ID: {item.get('id', '')}")
        kql_lines.append(kql_raw)
        kql_lines.append("")
        kql_count += 1

    kql_header = "\n".join([
        "// CYBERDUDEBIVASH SENTINEL APEX — KQL Detection Queries Bundle",
        f"// Version: {VERSION} | Generated: {now_ts}",
        f"// Platform: {PLATFORM_BASE}",
        f"// Total queries: {kql_count}",
        f"// Import: Microsoft Sentinel Analytics Rules, Defender Advanced Hunting",
        "",
        "// ═══════════════════════════════════════════════════════════════════",
        "",
    ])
    kql_body = kql_header + "\n".join(kql_lines)

    # ── 3. IOC blocklist (flat text, firewall/DNS ready) ─────────────────────────
    blocklist_lines: List[str] = []
    blocklist_lines.append(f"# CYBERDUDEBIVASH SENTINEL APEX — IOC Blocklist")
    blocklist_lines.append(f"# Version: {VERSION} | Generated: {now_ts}")
    blocklist_lines.append(f"# Platform: {PLATFORM_BASE}")
    blocklist_lines.append(f"# Format: one indicator per line (domains, IPs, hashes, URLs)")
    blocklist_lines.append(f"# Import: Palo Alto, FortiGate, Pi-hole, pfSense, CrowdStrike")
    blocklist_lines.append("")

    seen_iocs: Set[str] = set()
    ioc_count = 0
    type_map: Dict[str, List[str]] = {}
    for item in baseline:
        iocs = item.get("iocs") or []
        if not isinstance(iocs, list):
            continue
        for ioc_entry in iocs:
            # Handle both string IOCs and dict IOCs {type, value, confidence, ...}
            if isinstance(ioc_entry, dict):
                ioc_val  = str(ioc_entry.get("value") or "").strip()
                ioc_type = str(ioc_entry.get("type") or "indicator").strip()
            elif isinstance(ioc_entry, str):
                ioc_val  = ioc_entry.strip()
                ioc_type = "indicator"
            else:
                continue
            if not ioc_val or ioc_val in seen_iocs:
                continue
            # Filter CVE-ID strings — not actionable in blocklists
            if _CVE_RE.match(ioc_val):
                continue
            # Re-derive type from value if dict had generic "indicator" type
            if ioc_type == "indicator":
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc_val):
                    ioc_type = "ipv4"
                elif re.match(r"^[a-f0-9]{64}$", ioc_val, re.IGNORECASE):
                    ioc_type = "sha256"
                elif re.match(r"^[a-f0-9]{40}$", ioc_val, re.IGNORECASE):
                    ioc_type = "sha1"
                elif re.match(r"^[a-f0-9]{32}$", ioc_val, re.IGNORECASE):
                    ioc_type = "md5"
                elif re.match(r"^https?://", ioc_val, re.IGNORECASE):
                    ioc_type = "url"
                elif re.match(r"^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$", ioc_val, re.IGNORECASE):
                    ioc_type = "domain"
            seen_iocs.add(ioc_val)
            type_map.setdefault(ioc_type, []).append(ioc_val)
            ioc_count += 1

    # Group by type in blocklist
    for ioc_type, iocs_of_type in sorted(type_map.items()):
        blocklist_lines.append(f"# ── {ioc_type.upper()} ({len(iocs_of_type)} indicators)")
        blocklist_lines.extend(iocs_of_type)
        blocklist_lines.append("")

    blocklist_body = "\n".join(blocklist_lines)

    # ── 4. Structured IOC JSON export ────────────────────────────────────────────
    structured_iocs: List[Dict] = []
    for item in baseline:
        iocs = item.get("iocs") or []
        if not isinstance(iocs, list):
            continue
        cve_id = _extract_cve(item)
        for ioc_entry in iocs:
            if isinstance(ioc_entry, dict):
                ioc_val  = str(ioc_entry.get("value") or "").strip()
                ioc_type = str(ioc_entry.get("type") or "indicator")
                conf     = ioc_entry.get("confidence")
            elif isinstance(ioc_entry, str):
                ioc_val, ioc_type, conf = ioc_entry.strip(), "indicator", None
            else:
                continue
            if not ioc_val or _CVE_RE.match(ioc_val):
                continue
            structured_iocs.append({
                "value":        ioc_val,
                "type":         ioc_type,
                "confidence":   conf,
                "source_id":    item.get("id", ""),
                "source_title": str(item.get("title") or "")[:80],
                "cve_id":       cve_id,
                "severity":     item.get("severity", ""),
                "risk_score":   _safe_float(item.get("risk_score")),
                "kev":          item.get("kev") is True,
                "premium_tier": item.get("premium_tier", ""),
                "observed_at":  item.get("published_at", ""),
                "platform":     PLATFORM_BASE,
            })

    ioc_export = {
        "_meta": {
            "product":      "SENTINEL APEX — Structured IOC Export",
            "version":      VERSION,
            "generated_at": now_ts,
            "total_iocs":   len(structured_iocs),
            "types":        {k: len(v) for k, v in type_map.items()},
            "platform":     PLATFORM_BASE,
        },
        "iocs": structured_iocs,
    }

    # ── 5. CVE watchlist CSV (for vuln management tools) ─────────────────────────
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow([
        "CVE_ID", "Title", "CVSS_Score", "EPSS_Score", "Severity",
        "Risk_Score", "KEV", "NVD_Status", "Premium_Tier",
        "Intelligence_Richness", "Published_At", "Source_URL", "NVD_URL",
    ])
    cve_rows = 0
    for item in baseline:
        cve_id = _extract_cve(item)
        if not cve_id:
            continue
        writer.writerow([
            cve_id,
            str(item.get("title") or "")[:100],
            item.get("cvss_score", ""),
            item.get("epss_score", ""),
            item.get("severity", ""),
            _safe_float(item.get("risk_score")),
            "YES" if item.get("kev") is True else "NO",
            item.get("nvd_status", "UNVERIFIED"),
            item.get("premium_tier", ""),
            item.get("_intelligence_richness", ""),
            item.get("published_at", ""),
            item.get("source_url", ""),
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ])
        cve_rows += 1

    # ── 6. Pack manifest ──────────────────────────────────────────────────────────
    kev_cves = [_extract_cve(i) for i in baseline if i.get("kev") is True]
    kev_cves = [c for c in kev_cves if c]

    manifest = {
        "_meta": {
            "product":      "SENTINEL APEX — Detection Pack",
            "version":      VERSION,
            "generated_at": now_ts,
            "platform":     PLATFORM_BASE,
            "pricing":      "+$149/mo add-on (included in Enterprise Plan)",
            "upgrade_url":  f"{PLATFORM_BASE}/pricing",
        },
        "contents": {
            "sigma_rules":       {"file": "api/detections/sigma_rules.yml",      "count": sigma_count,          "format": "Sigma YAML"},
            "kql_queries":       {"file": "api/detections/kql_queries.kql",      "count": kql_count,            "format": "KQL (Sentinel / Defender)"},
            "ioc_blocklist":     {"file": "api/detections/ioc_blocklist.txt",    "count": ioc_count,            "format": "Flat text (one IOC per line)"},
            "ioc_structured":    {"file": "api/detections/ioc_structured.json",  "count": len(structured_iocs), "format": "JSON (type, value, context)"},
            "cve_watchlist":     {"file": "api/detections/cve_watchlist.csv",    "count": cve_rows,             "format": "CSV (vuln management import)"},
        },
        "kev_cves_covered": kev_cves,
        "ioc_types":  {k: len(v) for k, v in type_map.items()},
        "source_baseline": str(BASELINE_PATH.name),
        "integration_guides": {
            "microsoft_sentinel":   f"{PLATFORM_BASE}/docs/integrations/sentinel",
            "splunk":               f"{PLATFORM_BASE}/docs/integrations/splunk",
            "crowdstrike":          f"{PLATFORM_BASE}/docs/integrations/crowdstrike",
            "palo_alto":            f"{PLATFORM_BASE}/docs/integrations/palo-alto",
            "qualys":               f"{PLATFORM_BASE}/docs/integrations/qualys",
        },
    }

    # ── Write all outputs ─────────────────────────────────────────────────────────
    outputs = [
        (DETECTIONS_DIR / "pack_manifest.json",   _atomic_write_json, manifest),
        (DETECTIONS_DIR / "sigma_rules.yml",      _atomic_write_text, sigma_body),
        (DETECTIONS_DIR / "kql_queries.kql",      _atomic_write_text, kql_body),
        (DETECTIONS_DIR / "ioc_blocklist.txt",    _atomic_write_text, blocklist_body),
        (DETECTIONS_DIR / "ioc_structured.json",  _atomic_write_json, ioc_export),
        (DETECTIONS_DIR / "cve_watchlist.csv",    _atomic_write_text, csv_buffer.getvalue()),
    ]

    written = 0
    for path, writer_fn, data in outputs:
        if DRY_RUN:
            log.info("[DRY RUN] Would write %s", path.name)
            written += 1
        else:
            if writer_fn(path, data):
                log.info("Written: %s", path.name)
                written += 1

    # ── Create ZIP bundle for easy download ──────────────────────────────────────
    zip_path = DETECTIONS_DIR / "detection_pack.zip"
    if not DRY_RUN:
        try:
            with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
                for path, _, _ in outputs:
                    if path.exists():
                        zf.write(path, path.name)
            log.info("Detection pack ZIP: %s (%.1f KB)", zip_path.name, zip_path.stat().st_size / 1024)
        except Exception as exc:
            log.error("ZIP creation failed: %s", exc)

    log.info("=" * 60)
    log.info("DETECTION PACK COMPLETE — %d/%d files written", written, len(outputs))
    log.info("  Sigma rules    : %d", sigma_count)
    log.info("  KQL queries    : %d", kql_count)
    log.info("  IOC blocklist  : %d unique indicators", ioc_count)
    log.info("  Structured IOCs: %d entries", len(structured_iocs))
    log.info("  CVE watchlist  : %d CVEs", cve_rows)
    log.info("  KEV CVEs       : %d (CISA active exploits)", len(kev_cves))
    log.info("  IOC types      : %s", dict(sorted(type_map.items(), key=lambda x: -len(x[1]))))
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
