#!/usr/bin/env python3
"""
scripts/source_fabric_health.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Global Intelligence Source Fabric (P40.0)
Source Health / Observability Aggregator.

Computes real, evidence-based per-source health by cross-referencing:
  - data/registry/source_registry.json  (canonical source declarations)
  - data/cache/feed_state.json          (per-source last_seen cursor, written
                                          by scripts/true_intel_ingestor.py)
  - data/stix/feed_manifest.json        (rolling window of ingested items,
                                          gives current-window volume)
  - data/attck/enterprise-attack.json   (MITRE ATT&CK reference sync state)

This is intentionally a read-only aggregator: it never mutates the registry,
feed_state, or manifest. It writes ONE output artifact,
data/quality/source_fabric_health.json, which is:
  - the input to scripts/p40_production_certification.py's health gates
  - what workers/intel-gateway P40 handlers serve (via the R2 upload bridge)
  - what dashboard/source_fabric_dashboard.html renders

Mission Section 19 (Freshness Engine) + Section 24 (Observability): detects
stale feeds, silent failures, and volume anomalies -- e.g. this is the
mechanism that WOULD have caught the URLhaus Auth-Key regression (fixed
elsewhere in this change) automatically, had it existed before.

Run: python3 scripts/source_fabric_health.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from source_registry import load_registry, all_sources  # noqa: E402
from canonical_timestamp import parse_ts as _canonical_parse_ts  # noqa: E402

FEED_STATE_PATH   = ROOT / "data" / "cache" / "feed_state.json"
MANIFEST_PATH     = ROOT / "data" / "stix" / "feed_manifest.json"
ATTCK_PATH        = ROOT / "data" / "attck" / "enterprise-attack.json"
OUT_PATH          = ROOT / "data" / "quality" / "source_fabric_health.json"

# Freshness expectation -> max tolerable age before a source is considered
# STALE. Deliberately generous (mission Section 19 lists these as
# expectation *tiers*, not hard SLAs) -- this flags genuine silence, not
# every run that happens to land a few minutes late.
_FRESHNESS_MAX_AGE = {
    "REALTIME":         timedelta(hours=6),
    "HOURLY":           timedelta(hours=12),
    "DAILY":            timedelta(days=3),
    "WEEKLY":           timedelta(days=14),
    "ON_DEMAND":        None,   # no staleness expectation
    "HISTORICAL_STATIC": None,
}


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """
    Parses to a UTC-aware datetime, or None. The manifest this reads from
    is merged by several independent pipelines (see reconnaissance findings
    in the P40 deliverables report) with inconsistent timestamp formatting,
    so this always normalizes to tz-aware UTC rather than assuming one
    format -- a naive/aware mismatch here would crash every health run.

    Delegates to scripts/canonical_timestamp.py (see true_intel_ingestor.py's
    _parse_ts for the incident that motivated consolidating this repo's many
    independent timestamp parsers into one engine). Strictly gains coverage
    versus the two-format list this used to have -- e.g. RFC-822/RFC-7231
    dates now parse instead of silently returning None -- verified
    byte-for-byte against every format this function previously handled
    before the swap.
    """
    return _canonical_parse_ts(ts)


def _load_json_safe(path: Path) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _match_manifest_key(pipeline_key: str, feed_source: str) -> bool:
    """
    pipeline_feed_source_key matching convention (see
    scripts/build_source_registry.py's mk() docstring for why this exists):
      - exact string match for EVENT_STREAM sources with a single fixed key
      - "rss:<substring>" matches any feed_source starting with "rss_" that
        contains <substring> (e.g. "rss:cisa.gov" heuristically matches
        rss_www_cisa_gov_cybersecurity_advisories_all_xml)
      - "rss:*" is the catch-all for any "rss_"-prefixed feed_source not
        claimed by a more specific rss: entry (caller is responsible for
        checking specific entries first -- see compute_health() below)
    """
    if pipeline_key.startswith("rss:"):
        if not feed_source.startswith("rss_"):
            return False
        substring = pipeline_key[len("rss:"):]
        if substring == "*":
            return True
        return substring.replace(".", "_") in feed_source
    return pipeline_key == feed_source


def _feed_state_last_seen(pipeline_key: str, feed_state_sources: Dict[str, Any]) -> Optional[datetime]:
    """
    Resolves a source's most recent feed_state cursor. For a plain
    pipeline_feed_source_key this is a direct dict lookup; for an "rss:"
    sentinel (which is never itself a real feed_state key -- see
    _match_manifest_key's docstring) this scans all feed_state source keys
    using the same matching rule and returns the newest last_seen among the
    matches, so RSS-bucketed registry entries still get real freshness data
    instead of silently falling back to "never seen."
    """
    if not pipeline_key.startswith("rss:"):
        return _parse_ts(feed_state_sources.get(pipeline_key, {}).get("last_seen"))

    newest: Optional[datetime] = None
    for key, entry in feed_state_sources.items():
        if _match_manifest_key(pipeline_key, key):
            ts = _parse_ts(entry.get("last_seen"))
            if ts and (newest is None or ts > newest):
                newest = ts
    return newest


def _feed_state_reason_code(pipeline_key: str, feed_state_sources: Dict[str, Any]) -> Optional[str]:
    """
    Resolves the most recent fetch-outcome reason code
    scripts/true_intel_ingestor.py persisted for this source (e.g. "OK",
    "HTTP_403", "NETWORK_TIMEOUT") -- see FeedState.set_reason_code and
    _record_source_outcome there. Mirrors _feed_state_last_seen's
    same-key / "rss:" matching so RSS-bucketed registry entries resolve
    correctly too. This is what lets the CISA advisories RSS block surface
    as "HTTP_403" instead of generic silence -- confirmed live against the
    real Akamai 403 during this change.
    """
    if not pipeline_key.startswith("rss:"):
        return feed_state_sources.get(pipeline_key, {}).get("last_reason_code")

    newest_ts: Optional[datetime] = None
    newest_reason: Optional[str] = None
    for key, entry in feed_state_sources.items():
        if _match_manifest_key(pipeline_key, key):
            ts = _parse_ts(entry.get("last_seen")) or _parse_ts(entry.get("last_reason_at"))
            if ts and (newest_ts is None or ts > newest_ts):
                newest_ts = ts
                newest_reason = entry.get("last_reason_code")
    return newest_reason


# Non-ACTIVE/IMPLEMENTED registry status -> reason code (Section 7's
# vocabulary). Additive alongside health_status -- see compute_health().
_STATUS_REASON_CODE = {
    "REQUIRES_CREDENTIALS": "CREDENTIAL_REQUIRED",
    "REQUIRES_LICENSE":     "LICENSE_REQUIRED",
    "DISABLED":              "DISABLED_BY_CONFIG",
    "PLANNED":               "NOT_YET_IMPLEMENTED",
}

# health_status -> the task's preferred state vocabulary (Section 6), as an
# ADDITIVE alias field -- health_status itself is unchanged for backward
# compatibility with existing API consumers (the dashboard, the P40
# certification gates, handleP40SourceHealth). A reason_code of HTTP_401/
# AUTH_FAILURE, HTTP_403, or a transport-level failure upgrades a merely
# "STALE" source to the more actionable AUTH_FAILURE/FAILING state -- this
# is what distinguishes "CISA RSS is blocked by a WAF" from "CISA KEV
# genuinely hasn't published anything new this week."
_HEALTH_TO_STATE = {
    "HEALTHY":              "LIVE",
    "DEGRADED":              "LIVE_DEGRADED",
    "NO_DATA":               "LIVE_DEGRADED",
    "AWAITING_CREDENTIALS":  "CREDENTIAL_REQUIRED",
    "AWAITING_LICENSE":      "LICENSE_REQUIRED",
    "NOT_RUNNING":           "IMPLEMENTED_NOT_ENABLED",
    "NOT_APPLICABLE":        "PLANNED",
    "DISABLED":              "DISABLED",
}
_FAILURE_REASON_CODES = {"HTTP_403", "HTTP_429", "NETWORK_TIMEOUT", "NETWORK_FAILURE", "PARSER_FAILURE"}


def _compute_reason_code(status: str, health: str, fs_reason: Optional[str],
                         has_connector: bool = True) -> str:
    """Resolve the actionable reason a source is not delivering data.

    `has_connector` distinguishes the two very different blockers that the
    single REQUIRES_CREDENTIALS status collapses together:

      * a source whose adapter is written and wired into the live pipeline
        and is genuinely one API key away from delivering
        (abuse_ch_urlhaus -- scripts/true_intel_ingestor.py:ingest_urlhaus);
      * a source with no reachable adapter at all, where supplying a key
        would change nothing because no code would ever call it.

    Reporting CREDENTIAL_REQUIRED for the second kind overstates readiness:
    it tells an operator (and, through handleP40SourceHealth, a customer)
    that a credential is the ONLY thing standing between that source and
    live data. At the time this parameter was added that was true of 1 of
    the 25 REQUIRES_CREDENTIALS sources and false of the other 24.

    The registry already carries the ground truth for this in
    connector_ref/integration_mode; this only stops the derived reason_code
    from discarding it. Defaults to True so existing 3-argument callers keep
    their exact previous behaviour.
    """
    if status == "REQUIRES_CREDENTIALS" and not has_connector:
        return "CONNECTOR_NOT_IMPLEMENTED"
    if status in _STATUS_REASON_CODE:
        return _STATUS_REASON_CODE[status]
    if status == "IMPLEMENTED":
        return "NOT_ENABLED"
    if health == "HEALTHY":
        return "OK"
    if health == "NO_DATA":
        return fs_reason if fs_reason and fs_reason not in ("OK",) else "ZERO_OUTPUT"
    if health == "STALE":
        return fs_reason if fs_reason and fs_reason not in ("OK",) else "NO_RECENT_DATA"
    return fs_reason or "UNKNOWN"


def _compute_state(health: str, reason_code: str) -> str:
    # A source with no adapter is not merely "awaiting a credential" -- see
    # _compute_reason_code's docstring. Surfaced as its own state so the
    # dashboard and /api/v1/p40/source-health distinguish "paste in a key"
    # from "this still needs to be built".
    if reason_code == "CONNECTOR_NOT_IMPLEMENTED":
        return "CONNECTOR_REQUIRED"
    if health == "STALE":
        if reason_code == "AUTH_FAILURE":
            return "AUTH_FAILURE"
        if reason_code in _FAILURE_REASON_CODES:
            return "FAILING"
        return "STALE"
    return _HEALTH_TO_STATE.get(health, "UNKNOWN")


def compute_health() -> Dict[str, Any]:
    registry = load_registry()
    sources = all_sources()

    feed_state = _load_json_safe(FEED_STATE_PATH) or {}
    feed_state_sources: Dict[str, Any] = feed_state.get("sources", {})

    manifest = _load_json_safe(MANIFEST_PATH) or []
    if not isinstance(manifest, list):
        manifest = []

    attck_ref = _load_json_safe(ATTCK_PATH)

    now = datetime.now(timezone.utc)

    # Specific rss: entries must be checked before the "rss:*" catch-all, so
    # sort event-stream sources with an rss: key by specificity (longest
    # substring first, catch-all last).
    rss_ordered = sorted(
        (s for s in sources if s["pipeline_feed_source_key"].startswith("rss:")),
        key=lambda s: (s["pipeline_feed_source_key"] == "rss:*", -len(s["pipeline_feed_source_key"])),
    )
    non_rss = [s for s in sources if not s["pipeline_feed_source_key"].startswith("rss:")]

    per_source: Dict[str, Dict[str, Any]] = {}
    unmatched_manifest_feed_sources: Dict[str, int] = {}

    for entry in manifest:
        fsrc = entry.get("feed_source", "") or ""
        matched_id = None
        for s in non_rss:
            if _match_manifest_key(s["pipeline_feed_source_key"], fsrc):
                matched_id = s["source_id"]
                break
        if matched_id is None:
            for s in rss_ordered:
                if _match_manifest_key(s["pipeline_feed_source_key"], fsrc):
                    matched_id = s["source_id"]
                    break
        if matched_id is None:
            unmatched_manifest_feed_sources[fsrc] = unmatched_manifest_feed_sources.get(fsrc, 0) + 1
            continue

        bucket = per_source.setdefault(matched_id, {"manifest_count": 0, "latest_ts": None})
        bucket["manifest_count"] += 1
        item_ts = _parse_ts(entry.get("timestamp") or entry.get("published_at") or entry.get("processed_at"))
        if item_ts and (bucket["latest_ts"] is None or item_ts > bucket["latest_ts"]):
            bucket["latest_ts"] = item_ts

    results: List[Dict[str, Any]] = []
    counts_by_health = {"HEALTHY": 0, "STALE": 0, "NO_DATA": 0, "DEGRADED": 0,
                         "AWAITING_CREDENTIALS": 0, "AWAITING_LICENSE": 0,
                         "NOT_RUNNING": 0, "NOT_APPLICABLE": 0, "DISABLED": 0}

    for s in sources:
        sid = s["source_id"]
        status = s["implementation_status"]
        manifest_bucket = per_source.get(sid, {"manifest_count": 0, "latest_ts": None})
        fs_last_seen = _feed_state_last_seen(s["pipeline_feed_source_key"], feed_state_sources)
        fs_reason_code = _feed_state_reason_code(s["pipeline_feed_source_key"], feed_state_sources)

        # ATT&CK is REFERENCE_SYNC, not manifest-tracked -- health comes from
        # its own state file.
        last_event: Optional[datetime] = manifest_bucket["latest_ts"] or fs_last_seen
        records_received = manifest_bucket["manifest_count"]
        if s["integration_mode"] == "REFERENCE_SYNC" and sid == "mitre_attack" and attck_ref:
            last_event = _parse_ts(attck_ref.get("synced_at"))
            records_received = sum(attck_ref.get("counts", {}).values())

        if status not in ("ACTIVE", "IMPLEMENTED"):
            health = {
                "REQUIRES_CREDENTIALS": "AWAITING_CREDENTIALS",
                "REQUIRES_LICENSE": "AWAITING_LICENSE",
                "DISABLED": "DISABLED",
                "PLANNED": "NOT_APPLICABLE",
            }.get(status, "NOT_APPLICABLE")
        elif status == "IMPLEMENTED":
            health = "NOT_RUNNING"
        elif last_event is None:
            # ACTIVE but we have never once observed output — the exact shape
            # of the URLhaus regression this change fixed elsewhere.
            health = "NO_DATA"
        else:
            max_age = _FRESHNESS_MAX_AGE.get(s["freshness_expectation"])
            if max_age is not None and (now - last_event) > max_age:
                health = "STALE"
            else:
                health = "HEALTHY"

        counts_by_health[health] = counts_by_health.get(health, 0) + 1
        # Ground truth for "is there an adapter at all" already lives in the
        # registry; NOT_INTEGRATED is the registry's own term for a source
        # with no wired adapter (see build_source_registry.py).
        has_connector = bool(s.get("connector_ref")) and s.get("integration_mode") != "NOT_INTEGRATED"
        reason_code = _compute_reason_code(status, health, fs_reason_code, has_connector)
        state = _compute_state(health, reason_code)

        results.append({
            "source_id": sid,
            "canonical_name": s["canonical_name"],
            "implementation_status": status,
            "wave": s["wave"],
            "integration_mode": s["integration_mode"],
            "health_status": health,
            "state": state,
            "reason_code": reason_code,
            "records_received_current_window": records_received,
            "last_event": last_event.strftime("%Y-%m-%dT%H:%M:%SZ") if last_event else None,
            "age_hours": round((now - last_event).total_seconds() / 3600, 1) if last_event else None,
            "freshness_expectation": s["freshness_expectation"],
            "criticality": s["criticality"],
        })

    total_active_or_implemented = sum(1 for s in sources if s["implementation_status"] in ("ACTIVE", "IMPLEMENTED"))
    health_report = {
        "schema_version": "1.0.0",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registry_version": registry["registry_version"],
        "total_sources": len(sources),
        "live_or_implemented_sources": total_active_or_implemented,
        "health_breakdown": counts_by_health,
        "manifest_total_entries": len(manifest),
        "manifest_unmatched_feed_sources": unmatched_manifest_feed_sources,
        "sources": sorted(results, key=lambda r: (r["health_status"] != "STALE" and r["health_status"] != "NO_DATA", r["source_id"])),
    }
    return health_report


def main() -> int:
    report = compute_health()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[source-fabric-health] {report['total_sources']} sources, "
          f"{report['live_or_implemented_sources']} live/implemented")
    print(f"[source-fabric-health] health breakdown: {report['health_breakdown']}")
    if report["manifest_unmatched_feed_sources"]:
        print(f"[source-fabric-health] WARNING: {len(report['manifest_unmatched_feed_sources'])} "
              f"manifest feed_source value(s) not matched to any registry entry: "
              f"{list(report['manifest_unmatched_feed_sources'].keys())[:5]}")
    print(f"[source-fabric-health] wrote -> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
