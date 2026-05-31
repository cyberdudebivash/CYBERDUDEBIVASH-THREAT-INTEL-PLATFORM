#!/usr/bin/env python3
"""
scripts/cve_title_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- CVE Title Enrichment Engine v2.0.0
P0 FIX: NVD-optional. Smart fallback from item metadata when NVD fails.
"""
from __future__ import annotations
import json, logging, os, re, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [CDB-CVE-TITLE] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("CDB-CVE-TITLE")

REPO_ROOT     = Path(__file__).resolve().parent.parent
FEED_PATH     = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
TELEMETRY     = REPO_ROOT / "data" / "telemetry" / "cve_title_enrichment_report.json"
NVD_API_KEY   = os.environ.get("NVD_API_KEY", "")
DRY_RUN       = os.environ.get("DRY_RUN", "").lower() == "true"
NVD_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP_NO_KEY  = 2.0
SLEEP_KEY     = 0.6
MAX_ENRICH    = int(os.environ.get("MAX_ENRICH", "200"))
NVD_TIMEOUT   = int(os.environ.get("NVD_TIMEOUT", "8"))
CVE_RE        = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

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
    (re.compile(r"integer overflow", re.I),                    "Integer Overflow"),
    (re.compile(r"supply chain|dependency", re.I),             "Supply Chain Risk"),
    (re.compile(r"phish|social engineer", re.I),               "Phishing"),
    (re.compile(r"denial of service|dos", re.I),               "Denial of Service"),
]

SEVERITY_PREFIX = {
    "CRITICAL": "Critical", "HIGH": "High-Severity",
    "MEDIUM": "Medium",     "LOW": "Low", "NONE": "Informational",
}

DETECTION_CLASS_MAP = {
    "rce": "Remote Code Execution", "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",  "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion", "ssrf": "Server-Side Request Forgery",
    "xxe": "XML External Entity",   "privesc": "Privilege Escalation",
    "auth_bypass": "Authentication Bypass", "dos": "Denial of Service",
    "overflow": "Buffer Overflow",  "deserialization": "Unsafe Deserialization",
    "command_injection": "Command Injection", "supply_chain": "Supply Chain Compromise",
    "supplychain": "Supply Chain Compromise", "phishing": "Phishing",
    "kev_exploit": "Known Exploited Vulnerability", "zero_day": "Zero-Day Exploit",
    "infoleak": "Information Disclosure", "crypto_weak": "Weak Cryptography",
    "generic": "Security Vulnerability",
}
ACTOR_SKIP = {"cdb-unattr-cve", "unknown", "unattributed", "n/a", ""}


def _extract_vuln_type(desc: str) -> str:
    for pat, label in VULN_TYPE_MAP:
        if pat.search(desc):
            return label
    return "Security Vulnerability"


def _extract_product(nvd_item: dict) -> str:
    try:
        for cfg in (nvd_item.get("configurations") or []):
            for node in (cfg.get("nodes") or []):
                for m in (node.get("cpeMatch") or []):
                    if m.get("vulnerable"):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) >= 5:
                            p = parts[4].replace("_", " ").title()
                            v = parts[5] if len(parts) > 5 and parts[5] not in ("-","*","") else ""
                            if p and p.lower() not in ("*", "-", ""):
                                return f"{p} {v}".strip()
    except Exception:
        pass
    return ""


def _infer_vuln_type_from_item(item: dict) -> str:
    for field in ("detection_class", "vuln_class", "vulnerability_class", "category"):
        val = str(item.get(field) or "").lower().strip()
        if val in DETECTION_CLASS_MAP:
            return DETECTION_CLASS_MAP[val]
    tags = item.get("tags") or item.get("labels") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags:
        key = str(tag).lower().strip()
        if key in DETECTION_CLASS_MAP:
            return DETECTION_CLASS_MAP[key]
    desc = str(item.get("description") or item.get("summary") or "")
    if desc:
        return _extract_vuln_type(desc)
    for field in ("sigma_rule_type", "suricata_rule", "sigma_rule"):
        val = str(item.get(field) or "").lower()
        if "rce" in val or "exec" in val:
            return "Remote Code Execution"
        if "inject" in val:
            return "Injection Attack"
    return "Security Vulnerability"


def _build_fallback_title(cve_id: str, item: dict) -> str:
    severity = str(item.get("severity") or "").upper().strip()
    sev_pfx  = SEVERITY_PREFIX.get(severity, "")
    # v166.3 FIX: If description exists and is meaningful, use it directly as
    # the title basis to avoid near-duplicate Jaccard similarity failures.
    # "Low Security Vulnerability (CVE-2026-10121)" x 85 = Gate B HARD_FAIL.
    raw_desc = str(item.get("description") or item.get("summary") or "").strip()
    _cve_strip = re.compile(r"^CVE-\d{4}-\d+[\s\-:]+", re.I)
    desc_clean = _cve_strip.sub("", raw_desc).strip()
    if desc_clean and len(desc_clean) > 30:
        # Build title from description: truncate at 80 chars, capitalize
        desc_title = desc_clean[:80].rstrip(",. -")
        if sev_pfx:
            return f"{sev_pfx}: {desc_title} ({cve_id})"
        return f"{desc_title} ({cve_id})"
    vtype = _infer_vuln_type_from_item(item)

    kev_val = str(item.get("kev") or item.get("cisa_kev") or item.get("KEV") or "").upper()
    kev_tag = " -- Actively Exploited" if kev_val in ("YES","TRUE","1") else ""

    epss = 0.0
    try:
        raw = str(item.get("epss") or item.get("epss_score") or "0").replace("%","")
        epss = float(raw)
        if epss > 1:
            epss /= 100.0
    except Exception:
        pass
    epss_tag = " [High EPSS]" if epss >= 0.5 else ""

    actor = str(item.get("actor") or item.get("threat_actor") or "").strip()
    actor_tag = ""
    if actor.lower() not in ACTOR_SKIP and len(actor) > 3:
        actor_tag = f" -- Attributed to {actor}"

    product = str(item.get("affected_product") or item.get("product") or
                  item.get("affected_system") or "").strip()

    if product and sev_pfx:
        return f"{sev_pfx} {vtype} in {product}{kev_tag}{epss_tag} ({cve_id})"
    if product:
        return f"{vtype} in {product}{kev_tag}{epss_tag} ({cve_id})"
    if sev_pfx:
        return f"{sev_pfx} {vtype}{kev_tag}{epss_tag}{actor_tag} ({cve_id})"
    return f"{vtype}{kev_tag}{epss_tag} ({cve_id})"


def _fetch_nvd(cve_id: str) -> Optional[dict]:
    url = f"{NVD_BASE}?cveId={cve_id}"
    headers = {"Accept": "application/json", "User-Agent": "CDB-SENTINEL-APEX/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities") or []
            if vulns:
                return vulns[0].get("cve") or {}
    except Exception as e:
        log.debug("[NVD] Unavailable for %s: %s", cve_id, e)
    return None


def _get_nvd_severity(nvd_cve: dict) -> str:
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


def _needs_enrichment(item: dict) -> bool:
    return bool(CVE_RE.fullmatch(str(item.get("title") or "").strip()))


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run_enrichment(feed_path: Path, manifest_path: Path) -> dict:
    log.info("=" * 60)
    log.info("CVE TITLE ENRICHER v2.0.0 -- Start (NVD-optional fallback)")
    log.info("Feed: %s | DRY_RUN=%s", feed_path, DRY_RUN)
    log.info("=" * 60)

    try:
        with open(feed_path, encoding="utf-8") as f:
            feed = json.load(f)
    except Exception as e:
        log.error("Cannot load feed: %s", e)
        return {"status": "ERROR", "error": str(e)}

    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    log.info("Loaded %d items from feed", len(items))

    manifest_items: list = []
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
    candidates = [it for it in items if _needs_enrichment(it)][:MAX_ENRICH]
    log.info("Items needing title enrichment: %d (cap=%d)", len(candidates), MAX_ENRICH)

    enriched = 0
    nvd_hits  = 0
    fallbacks = 0
    stats: list = []

    for item in candidates:
        cve_id = str(item.get("title") or item.get("cve_id") or "").strip()
        if not CVE_RE.fullmatch(cve_id):
            continue

        log.info("[TITLE] Enriching: %s", cve_id)
        old_title = item.get("title", "")
        new_title = ""
        desc_en   = ""
        product   = ""
        nvd_used  = False

        nvd_cve = _fetch_nvd(cve_id)
        time.sleep(sleep_time)

        if nvd_cve:
            descs    = nvd_cve.get("descriptions") or []
            desc_en  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            product  = _extract_product(nvd_cve)
            nvd_sev  = _get_nvd_severity(nvd_cve)
            severity = nvd_sev or item.get("severity", "MEDIUM")
            is_kev   = bool(item.get("kev") or item.get("cisa_kev"))
            kev_tag  = " -- Actively Exploited" if is_kev else ""
            vtype    = _extract_vuln_type(desc_en)
            sev_pfx  = SEVERITY_PREFIX.get(severity.upper(), "")
            if product and sev_pfx:
                new_title = f"{sev_pfx} {vtype} in {product}{kev_tag} ({cve_id})"
            elif product:
                new_title = f"{vtype} in {product}{kev_tag} ({cve_id})"
            elif sev_pfx:
                new_title = f"{sev_pfx} {vtype}{kev_tag} ({cve_id})"
            else:
                new_title = f"{vtype}{kev_tag} ({cve_id})"
            nvd_used = True
            nvd_hits += 1
            if desc_en and not item.get("description"):
                item["description"] = desc_en[:800]
            if product:
                item["affected_product"] = product
            if nvd_sev:
                item["severity"] = nvd_sev

        if not new_title:
            new_title = _build_fallback_title(cve_id, item)
            fallbacks += 1
            log.info("[TITLE] Fallback title for %s", cve_id)

        item["title"]           = new_title
        item["_orig_cve_title"] = old_title
        item["_title_source"]   = "nvd" if nvd_used else "cdb_fallback"

        stix_id = str(item.get("stix_id") or item.get("id") or "")
        if stix_id in manifest_by_id:
            manifest_by_id[stix_id]["title"]           = new_title
            manifest_by_id[stix_id]["_orig_cve_title"] = old_title
            manifest_by_id[stix_id]["_title_source"]   = item["_title_source"]
            if desc_en and not manifest_by_id[stix_id].get("description"):
                manifest_by_id[stix_id]["description"] = desc_en[:800]
            if product:
                manifest_by_id[stix_id]["affected_product"] = product

        enriched += 1
        log.info("[TITLE] %s -> %s [%s]", old_title, new_title, item["_title_source"])
        stats.append({"cve": cve_id, "old": old_title, "new": new_title,
                      "src": item["_title_source"]})

    log.info("=" * 60)
    log.info("COMPLETE: enriched=%d nvd=%d fallback=%d", enriched, nvd_hits, fallbacks)
    log.info("=" * 60)

    if not DRY_RUN and enriched > 0:
        out = feed if isinstance(feed, list) else {**feed, "advisories": items}
        _atomic_write(feed_path, out)
        log.info("[WRITE] Feed updated")
        if manifest_items:
            _atomic_write(manifest_path, manifest_items)
            log.info("[WRITE] Manifest synced")
        _atomic_write(TELEMETRY, {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine_version": "2.0.0",
            "total_input": len(items), "candidates": len(candidates),
            "enriched": enriched, "nvd_hits": nvd_hits, "fallbacks": fallbacks,
            "stats": stats,
        })

    return {"enriched": enriched, "nvd_hits": nvd_hits, "fallbacks": fallbacks}


if __name__ == "__main__":
    result = run_enrichment(FEED_PATH, MANIFEST_PATH)
    print(f"[DONE] {result}")
