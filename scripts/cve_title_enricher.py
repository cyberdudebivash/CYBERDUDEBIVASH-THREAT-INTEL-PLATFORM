#!/usr/bin/env python3
"""
scripts/cve_title_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX — CVE Title Enrichment Engine v1.0.0
======================================================================
REVENUE-CRITICAL FIX:
  The live feed shows raw CVE IDs as titles: "CVE-2026-10114", "CVE-2026-10115"
  This produces zero value for paying customers. A SOC analyst needs:
    "Critical SQL Injection in Apache Struts 2.5 — RCE Without Auth (CVE-2026-10114)"
  This script fetches NVD descriptions + affected products and builds
  analyst-grade titles that justify the subscription price.

WHAT THIS DOES:
  1. Reads api/feed.json
  2. Identifies items where title == CVE ID (the bad pattern)
  3. Fetches NVD API v2.0 for description + affected CPE/product
  4. Builds a human-readable title: "{severity} {vuln_type} in {product} — {cve_id}"
  5. Also enriches: description, affected_product, cvss_score, cvss_vector
  6. Writes atomically back to api/feed.json AND data/stix/feed_manifest.json
  7. Writes telemetry to data/telemetry/cve_title_enrichment_report.json

TITLE TEMPLATE:
  CRITICAL: "Critical Remote Code Execution in {Product} — Actively Exploited (CVE-XXXX)"
  HIGH:     "{Product} — Authentication Bypass Allows Privilege Escalation (CVE-XXXX)"
  MEDIUM:   "{Product} — Cross-Site Scripting Enables Session Hijacking (CVE-XXXX)"
  LOW:      "{Product} — Information Disclosure via {mechanism} (CVE-XXXX)"

RATE LIMITING:
  No key : 1 req / 6.5s
  NVD key: 1 req / 0.7s

ENV:
  NVD_API_KEY   — increases NVD rate limit 10x
  FEED_PATH     — override feed location
  DRY_RUN=true  — print without writing

USAGE:
  python3 scripts/cve_title_enricher.py
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import urllib.request
import urllib.parse
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-CVE-TITLE] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CDB-CVE-TITLE")

REPO_ROOT    = Path(__file__).resolve().parent.parent
FEED_PATH    = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
TELEMETRY    = REPO_ROOT / "data" / "telemetry" / "cve_title_enrichment_report.json"
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
DRY_RUN      = os.environ.get("DRY_RUN", "").lower() == "true"

NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP_NO_KEY = 6.5
SLEEP_KEY    = 0.8
MAX_ENRICH   = int(os.environ.get("MAX_ENRICH", "120"))

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ------------------------------------------------------------------
# Vulnerability type classification from NVD description keywords
# ------------------------------------------------------------------
VULN_TYPE_MAP = [
    (re.compile(r"remote code exec|rce|arbitrary code", re.I), "Remote Code Execution"),
    (re.compile(r"sql inject|sqli", re.I),                     "SQL Injection"),
    (re.compile(r"cross.site script|xss", re.I),               "Cross-Site Scripting"),
    (re.compile(r"path traversal|directory traversal", re.I),  "Path Traversal"),
    (re.compile(r"privilege escal|priv esc", re.I),            "Privilege Escalation"),
    (re.compile(r"auth.{0,20}bypass|authentication bypass", re.I), "Authentication Bypass"),
    (re.compile(r"denial.of.service|dos\b", re.I),             "Denial of Service"),
    (re.compile(r"buffer overflow|heap overflow|stack overflow", re.I), "Buffer Overflow"),
    (re.compile(r"server.side request forgery|ssrf", re.I),    "SSRF"),
    (re.compile(r"command inject|os command", re.I),           "Command Injection"),
    (re.compile(r"deserialization", re.I),                     "Deserialization"),
    (re.compile(r"xml.{0,20}external|xxe", re.I),              "XXE Injection"),
    (re.compile(r"information disclosure|info.{0,10}leak|sensitive.*expos", re.I), "Information Disclosure"),
    (re.compile(r"open redirect", re.I),                       "Open Redirect"),
    (re.compile(r"cross.site request|csrf", re.I),             "CSRF"),
    (re.compile(r"use.after.free", re.I),                      "Use-After-Free"),
    (re.compile(r"null pointer|null dereference", re.I),       "Null Dereference"),
    (re.compile(r"integer overflow", re.I),                    "Integer Overflow"),
    (re.compile(r"improper input|input validation", re.I),     "Input Validation Failure"),
    (re.compile(r"weak cryptograph|insecure crypto", re.I),    "Weak Cryptography"),
]

SEVERITY_PREFIX = {
    "CRITICAL": "Critical",
    "HIGH":     "High-Severity",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "NONE":     "Informational",
}


def _extract_vuln_type(description: str) -> str:
    for pattern, label in VULN_TYPE_MAP:
        if pattern.search(description):
            return label
    return "Vulnerability"


def _extract_product(nvd_item: dict) -> str:
    """Extract the most relevant product name from NVD CPE data."""
    try:
        configs = nvd_item.get("configurations") or []
        for cfg in configs:
            for node in cfg.get("nodes") or []:
                for cpe_match in node.get("cpeMatch") or []:
                    if cpe_match.get("vulnerable"):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            vendor  = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            version = parts[5] if len(parts) > 5 and parts[5] not in ("-", "*", "") else ""
                            if product and product.lower() not in ("*", "-", ""):
                                if version and version not in ("*", "-"):
                                    return f"{product} {version}"
                                return product
    except Exception:
        pass
    return ""


def _build_title(cve_id: str, description: str, product: str,
                 severity: str, is_kev: bool) -> str:
    """Build an analyst-grade title from NVD data."""
    vuln_type = _extract_vuln_type(description)
    sev_pfx   = SEVERITY_PREFIX.get(severity.upper(), "")
    kev_tag   = " — Actively Exploited" if is_kev else ""

    if product:
        # "Critical Remote Code Execution in Apache Struts 2.5 — Actively Exploited (CVE-2026-10114)"
        if sev_pfx:
            return f"{sev_pfx} {vuln_type} in {product}{kev_tag} ({cve_id})"
        return f"{vuln_type} in {product}{kev_tag} ({cve_id})"
    else:
        # "Critical Remote Code Execution — Actively Exploited (CVE-2026-10114)"
        if sev_pfx:
            return f"{sev_pfx} {vuln_type}{kev_tag} ({cve_id})"
        return f"{vuln_type}{kev_tag} ({cve_id})"


def _fetch_nvd(cve_id: str) -> Optional[dict]:
    """Fetch a single CVE from NVD API v2.0."""
    url = f"{NVD_BASE}?cveId={cve_id}"
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities") or []
            if vulns:
                return vulns[0].get("cve") or {}
    except Exception as e:
        log.warning("[NVD] Fetch failed for %s: %s", cve_id, e)
    return None


def _needs_title_enrichment(item: dict) -> bool:
    """Return True if item title is a raw CVE ID (the bad pattern)."""
    title = str(item.get("title") or "")
    return bool(CVE_RE.fullmatch(title.strip()))


def _get_nvd_severity(nvd_cve: dict) -> str:
    """Extract severity from NVD CVSS v3.1 or v3.0 or v2."""
    try:
        metrics = nvd_cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in (metrics.get(key) or []):
                sev = (m.get("cvssData") or {}).get("baseSeverity", "")
                if sev:
                    return sev.upper()
    except Exception:
        pass
    return ""


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run_enrichment(feed_path: Path, manifest_path: Path) -> dict:
    log.info("=" * 60)
    log.info("CVE TITLE ENRICHER v1.0.0 — Start")
    log.info("Feed: %s | DRY_RUN=%s", feed_path, DRY_RUN)
    log.info("=" * 60)

    # Load feed
    try:
        with open(feed_path, encoding="utf-8") as f:
            feed = json.load(f)
    except Exception as e:
        log.error("Cannot load feed: %s", e)
        return {"status": "ERROR", "error": str(e)}

    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    log.info("Loaded %d items from feed", len(items))

    # Also load manifest for sync
    manifest_items = []
    manifest_by_id: dict = {}
    try:
        with open(manifest_path, encoding="utf-8") as f:
            raw = json.load(f)
        manifest_items = raw if isinstance(raw, list) else raw.get("advisories", [])
        manifest_by_id = {str(it.get("stix_id") or it.get("id") or ""): it
                          for it in manifest_items}
    except Exception as e:
        log.warning("Cannot load manifest (non-fatal): %s", e)

    sleep_time = SLEEP_KEY if NVD_API_KEY else SLEEP_NO_KEY
    candidates = [it for it in items if _needs_title_enrichment(it)]
    log.info("Items needing title enrichment: %d (capped at %d)", len(candidates), MAX_ENRICH)
    candidates = candidates[:MAX_ENRICH]

    enriched = 0
    skipped  = 0
    failed   = 0
    stats: list = []

    for item in candidates:
        cve_id = str(item.get("title") or item.get("cve_id") or "").strip()
        if not CVE_RE.fullmatch(cve_id):
            skipped += 1
            continue

        log.info("[TITLE] Enriching: %s", cve_id)
        nvd_cve = _fetch_nvd(cve_id)
        time.sleep(sleep_time)

        if not nvd_cve:
            failed += 1
            stats.append({"cve": cve_id, "status": "nvd_fetch_failed"})
            continue

        # Extract fields from NVD response
        descriptions = nvd_cve.get("descriptions") or []
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        product  = _extract_product(nvd_cve)
        nvd_sev  = _get_nvd_severity(nvd_cve)
        severity = nvd_sev or item.get("severity", "MEDIUM")
        is_kev   = bool(item.get("kev") or item.get("cisa_kev"))

        new_title = _build_title(cve_id, desc_en, product, severity, is_kev)
        old_title = item.get("title", "")

        # Update feed item
        item["title"]           = new_title
        item["_orig_cve_title"] = old_title
        if desc_en and not item.get("description"):
            item["description"] = desc_en[:800]
        if product:
            item["affected_product"] = product
        if nvd_sev:
            item["severity"] = nvd_sev

        # Sync to manifest if present
        stix_id = str(item.get("stix_id") or item.get("id") or "")
        if stix_id in manifest_by_id:
            manifest_by_id[stix_id]["title"]            = new_title
            manifest_by_id[stix_id]["_orig_cve_title"]  = old_title
            if desc_en and not manifest_by_id[stix_id].get("description"):
                manifest_by_id[stix_id]["description"] = desc_en[:800]
            if product:
                manifest_by_id[stix_id]["affected_product"] = product

        enriched += 1
        log.info("[TITLE] %s → %s", old_title, new_title)
        stats.append({"cve": cve_id, "old_title": old_title, "new_title": new_title,
                       "product": product, "vuln_type": _extract_vuln_type(desc_en)})

    log.info("=" * 60)
    log.info("TITLE ENRICHMENT COMPLETE: enriched=%d skipped=%d failed=%d",
             enriched, skipped, failed)
    log.info("=" * 60)

    if not DRY_RUN and enriched > 0:
        # Write feed
        out = feed if isinstance(feed, list) else {**feed, "advisories": items}
        _atomic_write(feed_path, out)
        log.info("[WRITE] Feed updated: %s", feed_path)

        # Write manifest
        if manifest_items:
            out_manifest = manifest_items
            _atomic_write(manifest_path, out_manifest)
            log.info("[WRITE] Manifest synced: %s", manifest_path)

        # Write telemetry
        report = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine_version": "1.0.0",
            "total_input": len(items),
            "candidates": len(candidates),
            "enriched": enriched,
            "skipped": skipped,
            "failed": failed,
            "stats": stats,
        }
        _atomic_write(TELEMETRY, report)

    return {"enriched": enriched, "skipped": skipped, "failed": failed}


if __name__ == "__main__":
    result = run_enrichment(FEED_PATH, MANIFEST_PATH)
    print(f"[DONE] {result}")
