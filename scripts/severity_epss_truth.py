#!/usr/bin/env python3
"""
scripts/severity_epss_truth.py
CYBERDUDEBIVASH® SENTINEL APEX — Severity & EPSS Truth Stage v1.0.0
===================================================================
The one place that decides an advisory's published `severity` (for CVSS-rated
items) and `epss_score`. Runs twice per sentinel-blogger cycle: before the
premium baseline / product feeds / reports are built from the feed, and
immediately before the evidence chain (the last feed mutation before the API
manifests are published).

Why (production /api/feed.json, 2026-09-26, 54 items):
  * 11 of 34 CVSS-rated items were LOW with CVSS 4.3-6.7 (MEDIUM): the APEX
    composite risk score (0-10, not a CVSS score) was mapped through the CVSS
    bands (enrich_cvss_epss_batch.py Pass 4.7; premium_feed_baseline.py).
  * a CVSS 3.1 (AV:N/AC:H/PR:L/C:L) SSRF was CRITICAL.
  * epss_score is written in mixed scales by ~20 scripts: CVE-2026-15583 read
    53 while FIRST.org rates it 0.53%; renderers then printed 53%, 53.00%,
    5300.0%.

Severity rule
  1. CISA KEV confirmed (kev_present / kev affirmative): unchanged. The KEV
     marker's CRITICAL is platform policy for exploitation confirmed in the
     wild. severity_basis = "cisa_kev".
  2. A CVSS v3.x base score that equals the score recomputed from its own
     vector (FIRST CVSS v3.1 specification): severity = the CVSS qualitative
     rating (0.1-3.9 LOW, 4.0-6.9 MEDIUM, 7.0-8.9 HIGH, 9.0-10.0 CRITICAL).
     severity_basis = "cvss_v3_base".
  3. Anything else (no CVSS, CVSS v4, a score without a vector, a score that
     contradicts its vector): unchanged. severity_basis = "source".

EPSS rule (EPSS is defined per CVE only)
  * epss_score (percent, 0-100 -- the published API contract, see
    openapi_generator.py) comes from FIRST.org for the item's primary CVE,
    together with epss ("0.53%"), epss_pct, epss_date, epss_source.
  * FIRST.org has no score for the CVE, or the item has no CVE: no EPSS.
  * FIRST.org unreachable: a value is kept only when its own percent string
    agrees with it (p20 rule); otherwise it is removed. Never guessed.

epss_percent(item) is the reader every renderer uses (never re-derive scale).

Output: data/quality/severity_epss_truth_report.json
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

log = logging.getLogger("severity_epss_truth")

REPO = Path(__file__).resolve().parents[1]
DRY_RUN = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
FEED_PATHS = [
    Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json"))),
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "feed_manifest.json",
]
REPORT_PATH = REPO / "data" / "quality" / "severity_epss_truth_report.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_SOURCE = "FIRST.org"
VERSION = "1.0.0"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_EPSS_PCT_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d+)?)\s*%\s*$")
_KEV_FALSE_TOKENS = {"FALSE", "NO", "0", "NONE", "NULL", "N/A", ""}
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# ── CVSS v3.x base score (FIRST CVSS v3.1 specification, section 7) ─────────────
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Base score of a CVSS:3.0 / CVSS:3.1 vector, or None if it is not one."""
    if not isinstance(vector, str) or not vector.upper().startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.strip().split("/")[1:])
        scope = m["S"]
        if scope not in ("U", "C"):
            return None
        pr = {"N": 0.85, "L": 0.62 if scope == "U" else 0.68, "H": 0.27 if scope == "U" else 0.5}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + expl if scope == "U" else 1.08 * (impact + expl)
    return _roundup(min(total, 10.0))


def cvss_rating(score: float) -> Optional[str]:
    """CVSS v3.x qualitative severity rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return None  # 0.0 = None: no published severity is derived from it


def verified_cvss(item: Dict) -> Optional[float]:
    """cvss_score when it equals the base score of its own v3.x vector."""
    try:
        score = float(item.get("cvss_score"))
    except (TypeError, ValueError):
        return None
    computed = cvss3_base_score(item.get("cvss_vector") or "")
    if computed is None or abs(computed - score) > 0.05:
        return None
    return computed


def kev_confirmed(item: Dict) -> bool:
    """Affirmative KEV only (the feed carries kev == "NO")."""
    for key in ("kev_present", "kev"):
        val = item.get(key)
        if val is None or val is False:
            continue
        if val is True or str(val).strip().upper() not in _KEV_FALSE_TOKENS:
            return True
    return False


def truthful_severity(item: Dict) -> tuple:
    """(severity, basis) for an item under the rule in the module docstring."""
    current = str(item.get("severity") or "").strip().upper() or None
    if kev_confirmed(item):
        return current, "cisa_kev"
    score = verified_cvss(item)
    if score is not None:
        rating = cvss_rating(score)
        if rating:
            return rating, "cvss_v3_base"
    return current, "source"


# ── EPSS ────────────────────────────────────────────────────────────────────────
def item_cves(item: Dict) -> List[str]:
    """The item's CVE ids (cve_id first, then cve_ids), validated and de-duplicated."""
    cands: List[str] = []
    if item.get("cve_id"):
        cands.append(str(item["cve_id"]))
    ids = item.get("cve_ids") or []
    if isinstance(ids, str):
        ids = [ids]
    cands.extend(str(x) for x in ids if x)
    out: List[str] = []
    for c in cands:
        c = c.strip().upper()
        if _CVE_RE.match(c) and c not in out:
            out.append(c)
    return out


def primary_cve(item: Dict) -> Optional[str]:
    cves = item_cves(item)
    return cves[0] if cves else None


def _string_verified_pct(item: Dict) -> Optional[float]:
    m = _EPSS_PCT_RE.match(str(item.get("epss") or ""))
    if not m:
        return None
    pct = float(m.group(1))
    if not 0.0 <= pct <= 100.0:
        return None
    score = item.get("epss_score")
    if score is not None:
        try:
            if abs(float(score) - pct) > 0.01:
                return None
        except (TypeError, ValueError):
            return None
    return pct


def epss_percent(item: Dict) -> Optional[float]:
    """EPSS as a percentage (0-100) when its value and scale are proven, else None.

    Readers MUST use this instead of epss_score, whose scale is not uniform
    before this stage runs."""
    if not isinstance(item, dict):
        return None
    if item.get("epss_source") == EPSS_SOURCE:
        try:
            pct = float(item.get("epss_pct"))
            if 0.0 <= pct <= 100.0:
                return pct
        except (TypeError, ValueError):
            pass
        return None
    return _string_verified_pct(item)


def fmt_pct(pct: float) -> str:
    """0.529 -> '0.529', 53.0 -> '53', 0.0004 -> '0.0004' (no scientific notation)."""
    return f"{pct:.4f}".rstrip("0").rstrip(".") or "0"


def fetch_first_epss(cves: Iterable[str], timeout: int = 20) -> Optional[Dict[str, Dict]]:
    """{cve: {"epss": fraction, "date": ...}} from FIRST.org, or None if unreachable."""
    cves = sorted(set(cves))
    out: Dict[str, Dict] = {}
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        url = f"{FIRST_EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(chunk)})}"
        data = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CDB-SENTINEL-APEX/severity-epss-truth"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except Exception as exc:  # network / HTTP / JSON
                log.warning("FIRST.org EPSS request failed (attempt %d): %s", attempt + 1, exc)
                time.sleep(2 * (attempt + 1))
        if not isinstance(data, dict) or data.get("status") != "OK" or not isinstance(data.get("data"), list):
            return None
        for row in data["data"]:
            try:
                out[str(row["cve"]).upper()] = {"epss": float(row["epss"]), "date": row.get("date")}
            except (KeyError, TypeError, ValueError):
                continue
    return out


def _clear_epss(item: Dict) -> None:
    item["epss_score"] = None
    item["epss_pct"] = None
    for k in ("epss", "epss_date", "epss_cve", "epss_source"):
        item.pop(k, None)


def apply_epss(item: Dict, first: Optional[Dict[str, Dict]]) -> str:
    """Canonicalise one item's EPSS. Returns the outcome label."""
    cves = item_cves(item)
    cve = cves[0] if cves else None
    if first is not None:
        # Several CVEs: the highest FIRST.org score, and which CVE it belongs to.
        rows = [(first[c]["epss"], c) for c in cves if c in first]
        row, cve = (first[max(rows)[1]], max(rows)[1]) if rows else (None, cve)
        if row is None:
            had = item.get("epss_score") is not None
            _clear_epss(item)
            return "removed_no_first_record" if had else "none"
        pct = round(min(max(row["epss"], 0.0), 1.0) * 100.0, 4)
        item["epss_score"] = pct
        item["epss_pct"] = pct
        item["epss"] = fmt_pct(pct) + "%"
        item["epss_date"] = row.get("date")
        item["epss_cve"] = cve
        item["epss_source"] = EPSS_SOURCE
        return "first"
    # FIRST.org unreachable: keep only what the item itself proves.
    if item.get("epss_source") == EPSS_SOURCE and epss_percent(item) is not None:
        return "kept_first_previous"
    pct = _string_verified_pct(item)
    if pct is not None and cve:
        item["epss_score"] = pct
        item["epss_pct"] = pct
        item["epss"] = fmt_pct(pct) + "%"
        return "kept_string_verified"
    had = item.get("epss_score") is not None
    _clear_epss(item)
    return "removed_unverifiable" if had else "none"


def apply_severity(item: Dict) -> Optional[tuple]:
    """Set severity/severity_basis. Returns (old, new) when severity changed."""
    new, basis = truthful_severity(item)
    old = str(item.get("severity") or "").strip().upper() or None
    item["severity_basis"] = basis
    if new and new != old:
        item["severity"] = new
        if "severity_pre_truth" not in item:
            item["severity_pre_truth"] = old
        return old, new
    return None


# ── Feed I/O ────────────────────────────────────────────────────────────────────
def _items_of(data) -> Optional[List[Dict]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "advisories", "feed", "data"):
            if isinstance(data.get(key), list) and data[key]:
                return data[key]
    return None


def _load(path: Path):
    raw = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
    return json.loads(raw.decode("utf-8", errors="replace"))


def process(items: List[Dict], first: Optional[Dict[str, Dict]]) -> Dict:
    stats = {"items": 0, "severity_changed": 0, "severity_changes": {}, "severity_basis": {},
             "epss": {}}
    for item in items:
        if not isinstance(item, dict):
            continue
        stats["items"] += 1
        outcome = apply_epss(item, first)
        stats["epss"][outcome] = stats["epss"].get(outcome, 0) + 1
        changed = apply_severity(item)
        basis = item.get("severity_basis")
        stats["severity_basis"][basis] = stats["severity_basis"].get(basis, 0) + 1
        if changed:
            stats["severity_changed"] += 1
            key = f"{changed[0]}->{changed[1]}"
            stats["severity_changes"][key] = stats["severity_changes"].get(key, 0) + 1
    return stats


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [severity-epss-truth] %(levelname)s: %(message)s")
    log.info("Severity & EPSS Truth Stage v%s — DRY_RUN=%s", VERSION, DRY_RUN)
    loaded = []
    for path in FEED_PATHS:
        if not path.exists():
            log.info("Skipping (not found): %s", path)
            continue
        try:
            data = _load(path)
        except Exception as exc:
            log.warning("Failed to load %s: %s", path, exc)
            continue
        items = _items_of(data)
        if items is None:
            log.info("No items in %s", path)
            continue
        loaded.append((path, data, items))

    cves = {c for _, _, items in loaded for it in items if isinstance(it, dict) for c in item_cves(it)}
    first = fetch_first_epss(cves) if cves else {}
    first_ok = first is not None
    if not first_ok:
        log.warning("FIRST.org EPSS unreachable: keeping only self-verified EPSS values, removing the rest")

    report = {"version": VERSION, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "first_org_reachable": first_ok, "cves_queried": len(cves),
              "first_records": len(first or {}), "files": {}}
    for path, data, items in loaded:
        stats = process(items, first)
        report["files"][str(path.relative_to(REPO)) if path.is_relative_to(REPO) else str(path)] = stats
        log.info("%s: %s", path, json.dumps(stats, sort_keys=True))
        if DRY_RUN:
            continue
        tmp = path.with_suffix(".tmp_sevepss")
        try:
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    if not DRY_RUN:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
