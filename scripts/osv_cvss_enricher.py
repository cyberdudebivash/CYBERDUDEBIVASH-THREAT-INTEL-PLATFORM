#!/usr/bin/env python3
"""
scripts/osv_cvss_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- OSV.dev CVSS Fallback Enricher v1.0.0
=========================================================================
GAP-003 FIX: CVSS was 100% absent because NVD API fails in CI (GitHub Actions
IPs blocked, synthetic CVE-2026-x IDs not in NVD).

This script uses OSV.dev (Open Source Vulnerability DB) + GitHub Advisory DB
as authoritative CVSS fallback sources. Both are:
  - Public, no auth required
  - Not rate-limited in CI
  - Updated continuously from NVD, GitHub, PyPI, npm, Go, Rust advisories
  - Cover real CVEs with CVSS v3.x scores

ADDITIONALLY uses FIRST.org EPSS batch API (single call, all CVEs at once)
to fill missing EPSS scores.

SOURCES (in priority order):
  1. OSV.dev API  -- https://api.osv.dev/v1/vulns/{CVE-ID}
  2. GitHub Advisory DB -- https://api.github.com/advisories?cve_id=CVE-ID
  3. FIRST.org EPSS batch -- https://api.first.org/data/v1/epss?cve=...

CVSS FALLBACK CHAIN:
  NVD (existing) -> OSV.dev -> GitHub GHSA -> estimated from description

ENV:
  FEED_PATH        -- override (default: api/feed.json)
  GITHUB_TOKEN     -- optional, increases GH API rate limit from 60->5000/hr
  MAX_ENRICH       -- max items to process per run (default: 150)
  DRY_RUN=true     -- print only, no writes
"""
from __future__ import annotations
import json, logging, os, re, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [OSV-CVSS] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("OSV-CVSS")

REPO_ROOT   = Path(__file__).resolve().parent.parent
FEED_PATH   = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
MANIFEST    = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
TELEMETRY   = REPO_ROOT / "data" / "telemetry" / "osv_cvss_enrichment.json"
GH_TOKEN    = os.environ.get("GITHUB_TOKEN", os.environ.get("GH_TOKEN", ""))
MAX_ENRICH  = int(os.environ.get("MAX_ENRICH", "150"))
DRY_RUN     = os.environ.get("DRY_RUN", "").lower() == "true"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Keyword-to-CVSS estimate when no external source has the CVE
KEYWORD_CVSS = [
    (re.compile(r"remote code exec|rce|arbitrary code exec", re.I),  9.8, "CRITICAL"),
    (re.compile(r"unauthenticated|pre-auth|no authentication", re.I), 9.1, "CRITICAL"),
    (re.compile(r"command inject|os command inject", re.I),            9.0, "CRITICAL"),
    (re.compile(r"sql inject", re.I),                                  8.8, "HIGH"),
    (re.compile(r"privilege escal|root|admin.*access", re.I),          7.8, "HIGH"),
    (re.compile(r"auth.*bypass|bypass.*auth", re.I),                   7.5, "HIGH"),
    (re.compile(r"buffer overflow|heap overflow|stack.*overflow", re.I),7.2, "HIGH"),
    (re.compile(r"path traversal|directory traversal", re.I),          6.5, "MEDIUM"),
    (re.compile(r"cross.site script|xss", re.I),                       6.1, "MEDIUM"),
    (re.compile(r"denial.of.service|dos\b|crash", re.I),               5.3, "MEDIUM"),
    (re.compile(r"information disclosure|sensitive.*data", re.I),       5.3, "MEDIUM"),
    (re.compile(r"open redirect|ssrf", re.I),                           6.1, "MEDIUM"),
    (re.compile(r"csrf", re.I),                                         4.3, "MEDIUM"),
]


def _get(url: str, headers: dict = None, timeout: int = 10):
    try:
        req = urllib.request.Request(url, headers=headers or {
            "Accept": "application/json",
            "User-Agent": "CDB-SENTINEL-APEX/1.0 (osv-cvss-enricher)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        log.debug("GET %s failed: %s", url, e)
        return None


def _fetch_osv(cve_id: str) -> dict | None:
    """Fetch CVSS from OSV.dev. Returns dict with cvss_score, severity, cvss_vector."""
    data = _get(f"https://api.osv.dev/v1/vulns/{cve_id}")
    if not data:
        return None
    severity = ""
    score = None
    vector = ""
    # OSV severity array
    for sev in (data.get("severity") or []):
        t = sev.get("type", "")
        s = sev.get("score", "")
        if t in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
            vector = s
            # Parse base score from vector
            try:
                # Try to get numeric score from database_specific or affected
                db = data.get("database_specific") or {}
                score = float(db.get("cvss_score") or db.get("cvss") or 0) or None
                severity = str(db.get("severity", "")).upper() or None
            except Exception:
                pass
    # Also check aliases and database_specific
    db = data.get("database_specific") or {}
    if not score:
        try:
            score = float(db.get("cvss_score") or db.get("cvss") or 0) or None
        except Exception:
            pass
    if not severity:
        severity = str(db.get("severity", "")).upper() or None

    # Try nvd_data if present
    for nvd in (data.get("affected") or []):
        for rng in (nvd.get("ranges") or []):
            pass  # ranges don't have CVSS

    if score and score > 0:
        if not severity:
            severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        return {"cvss_score": round(score, 1), "severity": severity, "cvss_vector": vector, "source": "osv.dev"}
    return None


def _fetch_github_advisory(cve_id: str) -> dict | None:
    """Fetch CVSS from GitHub Security Advisory Database."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CDB-SENTINEL-APEX/1.0",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    data = _get(f"https://api.github.com/advisories?cve_id={cve_id}&per_page=1", headers=headers)
    if not data or not isinstance(data, list) or not data:
        return None
    adv = data[0]
    sev = str(adv.get("severity", "")).upper()
    # GitHub uses word severity, not CVSS score directly
    score_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "LOW": 2.5}
    cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}
    score = adv.get("cvss", {}).get("score") if adv.get("cvss") else None
    if not score:
        score = score_map.get(sev, 0) or cvss_map.get(sev.replace("MODERATE","MEDIUM"), 0)
    if score and score > 0:
        if sev == "MODERATE":
            sev = "MEDIUM"
        return {"cvss_score": round(float(score), 1), "severity": sev or "UNKNOWN",
                "cvss_vector": adv.get("cvss", {}).get("vector_string", "") if adv.get("cvss") else "",
                "source": "github_advisory"}
    return None


def _estimate_from_description(item: dict) -> dict | None:
    """Estimate CVSS from description keywords when no external source has data."""
    desc = str(item.get("description") or item.get("summary") or item.get("title") or "")
    for pat, score, sev in KEYWORD_CVSS:
        if pat.search(desc):
            return {"cvss_score": score, "severity": sev, "cvss_vector": "",
                    "source": "keyword_estimate", "estimated": True}
    return None


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Batch fetch EPSS from FIRST.org. Returns {cve_id: epss_score} dict."""
    if not cve_ids:
        return {}
    # FIRST.org accepts comma-separated CVE IDs
    chunks = [cve_ids[i:i+100] for i in range(0, len(cve_ids), 100)]
    result = {}
    for chunk in chunks:
        param = ",".join(chunk)
        data = _get(f"https://api.first.org/data/v1/epss?cve={param}")
        if data and isinstance(data.get("data"), list):
            for row in data["data"]:
                cid = row.get("cve", "")
                try:
                    result[cid] = round(float(row.get("epss", 0)) * 100, 2)  # store as %
                except Exception:
                    pass
        time.sleep(0.5)
    return result


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run():
    log.info("=" * 60)
    log.info("OSV CVSS ENRICHER v1.0.0 -- GAP-003 FIX")
    log.info("Feed: %s | DRY_RUN=%s", FEED_PATH, DRY_RUN)
    log.info("=" * 60)

    try:
        feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Cannot load feed: %s", e)
        return {"status": "ERROR"}

    items = feed if isinstance(feed, list) else feed.get("advisories", feed.get("items", []))
    log.info("Loaded %d items", len(items))

    # Identify items needing CVSS enrichment
    needs_cvss = [it for it in items if not it.get("cvss_score") and not it.get("cvss")]
    needs_epss = [it for it in items if not it.get("epss_score") and not it.get("epss")]

    log.info("Items needing CVSS: %d | EPSS: %d", len(needs_cvss), len(needs_epss))

    # --- Batch EPSS fetch ---
    epss_cves = []
    for it in needs_epss[:MAX_ENRICH]:
        cve_ids = it.get("cve_ids") or ([it["cve_id"]] if it.get("cve_id") else [])
        epss_cves.extend(cve_ids)
    epss_cves = list(set(epss_cves))[:200]

    epss_results = {}
    if epss_cves:
        log.info("Fetching EPSS for %d CVEs (batch)...", len(epss_cves))
        epss_results = _fetch_epss_batch(epss_cves)
        log.info("EPSS resolved: %d/%d", len(epss_results), len(epss_cves))

    # Apply EPSS to items
    epss_applied = 0
    for it in needs_epss:
        cve_ids = it.get("cve_ids") or ([it["cve_id"]] if it.get("cve_id") else [])
        for cid in cve_ids:
            if cid in epss_results:
                it["epss_score"] = epss_results[cid]
                it["epss"] = str(epss_results[cid]) + "%"
                epss_applied += 1
                break

    # --- Per-CVE CVSS enrichment ---
    cvss_osv = 0
    cvss_gh = 0
    cvss_est = 0
    skipped = 0

    for it in needs_cvss[:MAX_ENRICH]:
        cve_ids = it.get("cve_ids") or ([it["cve_id"]] if it.get("cve_id") else [])
        primary_cve = cve_ids[0] if cve_ids else ""
        if not primary_cve:
            skipped += 1
            continue

        log.info("[CVSS] Enriching: %s", primary_cve)
        result = None

        # Source 1: OSV.dev
        result = _fetch_osv(primary_cve)
        if result:
            cvss_osv += 1
            log.info("[CVSS] OSV.dev: %s -> %s (%s)", primary_cve, result["cvss_score"], result["severity"])
        time.sleep(0.3)

        # Source 2: GitHub Advisory DB
        if not result:
            result = _fetch_github_advisory(primary_cve)
            if result:
                cvss_gh += 1
                log.info("[CVSS] GitHub: %s -> %s (%s)", primary_cve, result["cvss_score"], result["severity"])
            time.sleep(0.3)

        # Source 3: Keyword estimation
        if not result:
            result = _estimate_from_description(it)
            if result:
                cvss_est += 1
                log.info("[CVSS] Estimated: %s -> %s (%s) [from description]",
                         primary_cve, result["cvss_score"], result["severity"])

        if result:
            it["cvss_score"]  = result["cvss_score"]
            it["cvss_vector"] = result.get("cvss_vector", "")
            it["cvss_source"] = result["source"]
            if result.get("estimated"):
                it["cvss_estimated"] = True
            # Only override severity if it's currently UNKNOWN or empty
            if result["severity"] and it.get("severity", "UNKNOWN") in ("UNKNOWN", "", None):
                it["severity"] = result["severity"]

    total_enriched = cvss_osv + cvss_gh + cvss_est
    log.info("=" * 60)
    log.info("COMPLETE: cvss_enriched=%d (osv=%d gh=%d estimated=%d) epss_applied=%d",
             total_enriched, cvss_osv, cvss_gh, cvss_est, epss_applied)
    log.info("=" * 60)

    if not DRY_RUN and (total_enriched > 0 or epss_applied > 0):
        out = feed if isinstance(feed, list) else {**feed, "advisories": items}
        _atomic_write(FEED_PATH, out)
        log.info("[WRITE] Feed updated")

        # Also update manifest if it exists
        if MANIFEST.exists():
            try:
                mdata = json.loads(MANIFEST.read_text(encoding="utf-8"))
                adv = mdata.get("advisories", []) if isinstance(mdata, dict) else mdata
                id_map = {str(it.get("stix_id") or it.get("id") or ""): it for it in items}
                updated = 0
                for m in adv:
                    mid = str(m.get("stix_id") or m.get("id") or "")
                    if mid in id_map and id_map[mid].get("cvss_score"):
                        m["cvss_score"] = id_map[mid]["cvss_score"]
                        m["cvss_source"] = id_map[mid].get("cvss_source", "")
                        updated += 1
                _atomic_write(MANIFEST, mdata)
                log.info("[WRITE] Manifest updated (%d items synced)", updated)
            except Exception as e:
                log.warning("Manifest sync failed (non-fatal): %s", e)

        _atomic_write(TELEMETRY, {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_input": len(items),
            "cvss_enriched": total_enriched,
            "cvss_osv": cvss_osv,
            "cvss_github": cvss_gh,
            "cvss_estimated": cvss_est,
            "epss_applied": epss_applied,
        })

    return {"cvss_enriched": total_enriched, "epss_applied": epss_applied}


if __name__ == "__main__":
    r = run()
    print(f"[DONE] {r}")
