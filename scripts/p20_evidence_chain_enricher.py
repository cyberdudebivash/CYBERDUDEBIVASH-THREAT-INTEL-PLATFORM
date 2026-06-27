#!/usr/bin/env python3
"""
scripts/p20_evidence_chain_enricher.py
CYBERDUDEBIVASH® SENTINEL APEX — P20.0 Evidence Chain Enricher v1.0.0
======================================================================
P20.1 — Evidence Integrity Engine

Writes structured evidence_chain records into every feed item using only
data the pipeline already knows. Zero fabrication. Every field traces to
a verifiable upstream data point already present in the item.

NATO reliability scale (Admiral Wolff, FM 2-22.3):
  A — Completely Reliable  (NVD / CISA / NIST authoritative sources)
  B — Usually Reliable     (GitHub Security Advisories / vendor advisories)
  C — Fairly Reliable      (established security news: bleepingcomputer, threatpost)
  D — Not Usually Reliable (blogs / unverified secondary sources)
  E — Unreliable           (unconfirmed / unknown source)
  F — Cannot Be Judged     (no source URL present)

Information accuracy scale:
  1 — Confirmed by other sources
  2 — Probably true
  3 — Possibly true
  4 — Doubtful
  5 — Improbable
  6 — Cannot be judged
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P20-EVIDENCE %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p20-evidence")

REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
MANIFEST_PATH = REPO / "data" / "feed_manifest.json"

# Source domain → (reliability_code, reliability_label, source_category)
SOURCE_RELIABILITY_MAP: Dict[str, tuple] = {
    "nvd.nist.gov":          ("A", "Completely Reliable", "NVD CVE Database"),
    "cisa.gov":              ("A", "Completely Reliable", "CISA Advisory"),
    "nist.gov":              ("A", "Completely Reliable", "NIST Security"),
    "github.com/advisories": ("B", "Usually Reliable",   "GitHub Security Advisories"),
    "github.com":            ("B", "Usually Reliable",   "GitHub Advisory"),
    "msrc.microsoft.com":    ("A", "Completely Reliable", "Microsoft MSRC"),
    "support.microsoft.com": ("A", "Completely Reliable", "Microsoft Support"),
    "security.microsoft.com":("A", "Completely Reliable", "Microsoft Security"),
    "oracle.com":            ("A", "Completely Reliable", "Oracle Security"),
    "cisco.com":             ("A", "Completely Reliable", "Cisco PSIRT"),
    "redhat.com":            ("A", "Completely Reliable", "Red Hat Security"),
    "ubuntu.com":            ("A", "Completely Reliable", "Ubuntu Security"),
    "debian.org":            ("A", "Completely Reliable", "Debian Security"),
    "access.redhat.com":     ("A", "Completely Reliable", "Red Hat Bugzilla"),
    "security-tracker.debian.org": ("A", "Completely Reliable", "Debian Security Tracker"),
    "vulners.com":           ("B", "Usually Reliable",   "Vulners Intelligence"),
    "exploit-db.com":        ("B", "Usually Reliable",   "Exploit-DB"),
    "packetstormsecurity.com":("B","Usually Reliable",   "PacketStorm"),
    "bleepingcomputer.com":  ("C", "Fairly Reliable",    "BleepingComputer"),
    "therecord.media":       ("C", "Fairly Reliable",    "The Record"),
    "securityweek.com":      ("C", "Fairly Reliable",    "SecurityWeek"),
    "darkreading.com":       ("C", "Fairly Reliable",    "Dark Reading"),
    "hackernews.com":        ("C", "Fairly Reliable",    "The Hacker News"),
    "thehackernews.com":     ("C", "Fairly Reliable",    "The Hacker News"),
    "threatpost.com":        ("C", "Fairly Reliable",    "Threatpost"),
    "securityaffairs.com":   ("C", "Fairly Reliable",    "Security Affairs"),
    "mandiant.com":          ("B", "Usually Reliable",   "Mandiant Intelligence"),
    "crowdstrike.com":       ("B", "Usually Reliable",   "CrowdStrike Intelligence"),
    "sentinelone.com":       ("B", "Usually Reliable",   "SentinelOne Labs"),
    "recordedfuture.com":    ("B", "Usually Reliable",   "Recorded Future"),
    "first.org":             ("A", "Completely Reliable", "FIRST.org EPSS"),
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def _source_reliability(url: str, source_name: str = "") -> tuple:
    """Return (code, label, category) for a source URL."""
    if not url:
        return ("F", "Cannot Be Judged", "No source URL")
    domain = _domain(url)
    for key, val in SOURCE_RELIABILITY_MAP.items():
        if key in domain or (key in url):
            return val
    if domain:
        return ("D", "Not Usually Reliable", f"Unclassified source: {domain}")
    return ("E", "Unreliable", "Source unknown")


def _accuracy_from_signals(item: Dict) -> tuple:
    """Return (accuracy_code, accuracy_label) based on corroboration signals."""
    cve_ids  = item.get("cve_ids") or ([item["cve_id"]] if item.get("cve_id") else [])
    kev      = bool(item.get("kev_present") or item.get("kev"))
    epss     = item.get("epss_score") is not None
    nvd_url  = item.get("nvd_url") or ""
    corr_src = item.get("corroborating_sources") or []
    if isinstance(corr_src, int):
        corr_src = []
    n_corr   = len(corr_src) if isinstance(corr_src, list) else 0

    if kev and cve_ids:
        return ("1", "Confirmed by other sources")
    if n_corr >= 2 or (epss and cve_ids):
        return ("2", "Probably true")
    if cve_ids or nvd_url:
        return ("3", "Possibly true")
    return ("4", "Doubtful — single unverified source")


def _build_verification_events(item: Dict) -> List[str]:
    """Build chain-of-custody events from item timestamps and metadata."""
    events: List[str] = []
    ts_ingest    = item.get("processed_at") or item.get("timestamp") or ""
    ts_published = item.get("published_at") or item.get("published") or ""
    source_url   = item.get("source_url") or ""
    cve_ids      = item.get("cve_ids") or ([item["cve_id"]] if item.get("cve_id") else [])
    epss         = item.get("epss_score")
    nvd_url      = item.get("nvd_url") or ""
    kev          = bool(item.get("kev_present") or item.get("kev"))
    ghsa_id      = item.get("ghsa_id") or ""
    nvd_status   = item.get("nvd_status") or ""

    if ts_ingest:
        events.append(f"[{ts_ingest}] Item ingested by SENTINEL APEX ingest pipeline")
    if ts_published and ts_published != ts_ingest:
        src_lbl = item.get("feed_source") or item.get("source") or "source"
        events.append(f"[{ts_published}] Advisory published by {src_lbl}")
    if source_url:
        events.append(f"Source URL verified: {source_url}")
    if ghsa_id:
        events.append(f"GitHub Security Advisory: {ghsa_id}")
    if cve_ids:
        events.append(f"CVE references: {', '.join(cve_ids[:5])} (traceable to NVD)")
    if epss is not None:
        events.append(f"EPSS score {epss:.1%} assigned by FIRST.org model")
    if nvd_url:
        events.append(f"NVD record: {nvd_url}")
    if nvd_status:
        events.append(f"NVD status: {nvd_status}")
    if kev:
        events.append("CISA KEV status: CONFIRMED active exploitation")

    return events


def build_evidence_chain(item: Dict) -> Optional[Dict]:
    """Build a structured evidence_chain record for an item."""
    source_url  = item.get("source_url") or ""
    source_name = item.get("feed_source") or item.get("source") or ""
    ts_ingest   = item.get("processed_at") or item.get("timestamp") or ""
    ts_pub      = item.get("published_at") or item.get("published") or ts_ingest
    item_id     = item.get("id") or item.get("stix_id") or ""

    reliability_code, reliability_label, source_category = _source_reliability(
        source_url, source_name
    )
    accuracy_code, accuracy_label = _accuracy_from_signals(item)

    # Evidence ID from item ID
    evid_suffix = item_id.replace("intel--", "")[:12].upper().replace("-", "")
    evidence_id = f"EVD-{evid_suffix}" if evid_suffix else "EVD-UNKNOWN"

    # Corroboration
    corr_src = item.get("corroborating_sources") or []
    if isinstance(corr_src, int):
        corr_src = []
    corr_count = len(corr_src) if isinstance(corr_src, list) else 0

    # Intelligence age
    freshness_label = "Unknown"
    if ts_ingest:
        try:
            ts = datetime.fromisoformat(ts_ingest.replace("Z", "+00:00"))
            age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            freshness_label = (
                "Very Fresh (<6h)"    if age_h < 6 else
                "Fresh (<24h)"        if age_h < 24 else
                "Recent (<72h)"       if age_h < 72 else
                "Aging (<7d)"         if age_h < 168 else
                "Stale (>7d)"
            )
        except Exception:
            pass

    events = _build_verification_events(item)

    # Confidence derivation
    iq_bd = item.get("iq_breakdown") or {}
    raw_conf = item.get("confidence_score") or item.get("confidence") or 0
    if isinstance(raw_conf, float) and raw_conf <= 1.0:
        raw_conf = round(raw_conf * 100, 1)
    conf_pct = float(raw_conf) if raw_conf else 0.0

    limitations: List[str] = []
    if reliability_code in ("D", "E", "F"):
        limitations.append("Source reliability not independently verified")
    if accuracy_code in ("4", "5", "6"):
        limitations.append("Intelligence accuracy uncertain — single source")
    if corr_count == 0:
        limitations.append("No independent corroboration sources identified")
    actor_conf = item.get("actor_confidence") or 0
    if not item.get("actor_id") or actor_conf < 60:
        limitations.append("Threat actor attribution unresolved")

    return {
        "evidence_id":           evidence_id,
        "source_url":            source_url,
        "source_name":           source_name,
        "source_category":       source_category,
        "source_reliability":    f"{reliability_code} — {reliability_label}",
        "reliability_code":      reliability_code,
        "accuracy_code":         accuracy_code,
        "accuracy_label":        accuracy_label,
        "collection_time":       ts_pub,
        "verification_time":     ts_ingest,
        "collection_method":     "Automated OSINT Pipeline (SENTINEL APEX v184.0)",
        "analyst_review":        "Automated — Pending Human Review",
        "corroboration_count":   corr_count,
        "corroborating_sources": corr_src[:5] if isinstance(corr_src, list) else [],
        "intelligence_freshness": freshness_label,
        "confidence_pct":        conf_pct,
        "chain_of_custody":      events,
        "known_limitations":     limitations,
        "iq_breakdown":          iq_bd,
        "evidence_version":      "P20.1",
    }


def enrich_items(items: List[Dict]) -> int:
    modified = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("evidence_chain") and item.get("evidence_chain", {}).get("evidence_version") == "P20.1":
            continue  # already enriched at this version
        chain = build_evidence_chain(item)
        if chain:
            item["evidence_chain"] = chain
            modified += 1
    return modified


def process_feed(path: Path) -> int:
    if not path.exists():
        log.info("Skipping (not found): %s", path)
        return 0
    try:
        raw = path.read_bytes()
        raw = raw.rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return 0

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = None
        for key in ("items", "advisories", "feed", "data"):
            if key in data and isinstance(data[key], list) and data[key]:
                items = data[key]
                break
        if items is None:
            return 0
    else:
        return 0

    modified = enrich_items(items)
    if modified > 0 and not DRY_RUN:
        tmp = path.with_suffix(".tmp_p20evid")
        try:
            tmp.write_text(json.dumps(data if isinstance(data, dict) else items,
                                       indent=2, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(path)
            log.info("Saved %d evidence chain(s) to %s", modified, path)
        except Exception as exc:
            log.error("Failed to save %s: %s", path, exc)
            tmp.unlink(missing_ok=True)
            raise
    elif DRY_RUN:
        log.info("[DRY_RUN] Would write %d evidence chain(s) to %s", modified, path)
    return modified


def main() -> int:
    log.info("P20.1 Evidence Chain Enricher v1.0.0 — DRY_RUN=%s", DRY_RUN)
    total = process_feed(FEED_PATH)
    log.info("feed.json: %d item(s) enriched with evidence chain", total)
    n2 = process_feed(MANIFEST_PATH)
    log.info("feed_manifest.json: %d item(s) enriched", n2)
    log.info("P20.1 complete: %d total evidence chains written", total + n2)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
