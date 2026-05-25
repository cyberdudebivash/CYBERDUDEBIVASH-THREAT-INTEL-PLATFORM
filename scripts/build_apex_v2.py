#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
APEX V2 INTELLIGENCE BUILDER v162.8
================================================================================
PURPOSE:
  Generates api/apex_v2/priority.json and api/apex_v2/critical.json from the
  master feed manifest. These files are the PRIMARY data source for the
  dashboard _fetchLiveIntel() bridge, loaded before fallback to api/feed.json.

SCORE NORMALIZATION:
  All threat scores normalized to 0-10 scale before filtering:
  - risk_score (api/feed.json)        -- 0-10, used as-is
  - threat_score (feed_manifest.json) -- 0-100, divided by 10
  - apex_ai.predictive_risk           -- 0-10, used as-is
  - cvss_score / cvss                 -- standard CVSS, used as-is
  - epss_score                        -- 0-1 probability, multiplied by 10

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [build_apex_v2] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-APEX-V2")

REPO_ROOT = Path(__file__).resolve().parent.parent

FEED_SOURCES = [
    REPO_ROOT / "data" / "feed_manifest.json",
    REPO_ROOT / "api" / "feed.json",
    REPO_ROOT / "feed.json",
    REPO_ROOT / "data" / "feed.json",
]

OUTPUT_PRIORITY = REPO_ROOT / "api" / "apex_v2" / "priority.json"
OUTPUT_CRITICAL = REPO_ROOT / "api" / "apex_v2" / "critical.json"

PRIORITY_LIMIT = 100
CRITICAL_LIMIT = 50


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_score(v):
    if v > 10.0:
        return min(v / 10.0, 10.0)
    return min(max(v, 0.0), 10.0)


def get_cvss(item):
    # 1. risk_score (0-10, api/feed.json primary)
    rs = item.get("risk_score")
    if rs is not None:
        try:
            return _normalize_score(float(rs))
        except (ValueError, TypeError):
            pass

    # 2. threat_score (0-100 in feed_manifest.json, auto-normalized)
    ts = item.get("threat_score")
    if ts is not None:
        try:
            return _normalize_score(float(ts))
        except (ValueError, TypeError):
            pass

    # 3. apex_ai.predictive_risk
    apex_ai = item.get("apex_ai")
    if isinstance(apex_ai, dict):
        pr = apex_ai.get("predictive_risk")
        if pr is not None:
            try:
                return _normalize_score(float(pr))
            except (ValueError, TypeError):
                pass

    # 4. apex.threat_level (numeric)
    apex = item.get("apex")
    if isinstance(apex, dict):
        tl = apex.get("threat_level")
        if tl is not None:
            try:
                return _normalize_score(float(tl))
            except (ValueError, TypeError):
                pass

    # 5. Standard CVSS fields
    for field in ("cvss_score", "cvss", "base_score", "cvss_v3", "cvss3_score", "score"):
        v = item.get(field)
        if v is not None:
            try:
                return _normalize_score(float(str(v).split("/")[0]))
            except (ValueError, TypeError):
                continue

    # 6. EPSS x10 (0-1 to 0-10)
    epss = item.get("epss_score")
    if epss is not None:
        try:
            return min(float(epss) * 10.0, 10.0)
        except (ValueError, TypeError):
            pass

    return 0.0


def is_kev(item):
    kp = item.get("kev_present")
    if kp is not None:
        if isinstance(kp, bool):
            return kp
        if isinstance(kp, str):
            return kp.lower() in ("true", "yes", "1")
    return bool(
        item.get("kev") or item.get("in_kev") or item.get("cisa_kev")
        or item.get("kev_date") or item.get("known_exploited")
    )


def get_severity(item):
    raw = (
        item.get("severity")
        or item.get("risk_level")
        or item.get("risk")
        or ""
    )
    if not raw:
        apex_ai = item.get("apex_ai")
        if isinstance(apex_ai, dict):
            raw = apex_ai.get("soc_priority") or ""
    return raw.strip().lower()


def _parse_json_robust(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(text.lstrip())
        return obj
    except json.JSONDecodeError:
        raise


def load_feed():
    for path in FEED_SOURCES:
        if not path.exists():
            continue
        try:
            raw = _parse_json_robust(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                items = (
                    raw.get("advisories")
                    or raw.get("reports")
                    or raw.get("items")
                    or raw.get("data")
                    or []
                )
            else:
                continue
            if items:
                log.info("Loaded %d items from %s", len(items), path.relative_to(REPO_ROOT))
                return items
        except Exception as e:
            log.warning("Failed to load %s: %s", path, e)
    return []


def build_priority(items):
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        score = get_cvss(item)
        kev   = is_kev(item)
        sev   = get_severity(item)
        rl    = (item.get("risk_level") or "").strip().lower()
        if score >= 7.0 or kev or sev in ("high", "critical", "medium") or rl in ("high", "medium"):
            result.append(item)
    result.sort(key=lambda x: (get_cvss(x), is_kev(x)), reverse=True)
    return result[:PRIORITY_LIMIT]


def build_critical(items):
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        score = get_cvss(item)
        kev   = is_kev(item)
        sev   = get_severity(item)
        rl    = (item.get("risk_level") or "").strip().lower()
        if score >= 9.0 or sev == "critical" or rl == "high" or (kev and score >= 7.0):
            result.append(item)
    result.sort(key=lambda x: (get_cvss(x), is_kev(x)), reverse=True)
    return result[:CRITICAL_LIMIT]


def write_output(path, data, label):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    log.info("Wrote %s: %d items -> %s (%d bytes)", label, len(data), path.relative_to(REPO_ROOT), path.stat().st_size)


def main():
    log.info("=" * 60)
    log.info("SENTINEL APEX -- Apex V2 Intelligence Builder v162.8")
    log.info("=" * 60)

    items = load_feed()
    if not items:
        log.error("No feed items found -- cannot build apex_v2 outputs")
        write_output(OUTPUT_PRIORITY, [], "priority (empty fallback)")
        write_output(OUTPUT_CRITICAL, [], "critical (empty fallback)")
        return 0

    log.info("Feed loaded: %d total items", len(items))

    priority = build_priority(items)
    critical = build_critical(items)

    log.info("Priority (score>=7/KEV/HIGH+): %d / %d", len(priority), PRIORITY_LIMIT)
    log.info("Critical (score>=9/CRITICAL/HIGH/KEV+7): %d / %d", len(critical), CRITICAL_LIMIT)

    write_output(OUTPUT_PRIORITY, priority, "priority")
    write_output(OUTPUT_CRITICAL, critical, "critical")

    if priority:
        top = priority[0]
        log.info("Top priority: %s (score=%.1f, KEV=%s)",
                 top.get("cve_id") or top.get("advisory_id") or top.get("id", "?"),
                 get_cvss(top), is_kev(top))
    if critical:
        top = critical[0]
        log.info("Top critical: %s (score=%.1f, KEV=%s)",
                 top.get("cve_id") or top.get("advisory_id") or top.get("id", "?"),
                 get_cvss(top), is_kev(top))

    log.info("=" * 60)
    log.info("Apex V2 build COMPLETE -- 2 files written")
    log.info("  api/apex_v2/priority.json: %d items", len(priority))
    log.info("  api/apex_v2/critical.json: %d items", len(critical))
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
