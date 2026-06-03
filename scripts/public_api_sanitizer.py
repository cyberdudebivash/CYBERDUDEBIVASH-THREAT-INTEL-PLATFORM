#!/usr/bin/env python3
"""
PUBLIC API SANITIZER  v1.0  -- SENTINEL APEX
=============================================
Strips ALL premium fields from feed items before they are written
to any public API endpoint.

PREMIUM FIELDS (must never appear in public APIs):
  Tier PRO:
    report_url, internal_report_url, stix_bundle_url, stix_bundle,
    pdf_url, pdf_report_url, apex_ai, ioc_hashes, ioc_payload,
    kill_chain, detection_rules, sigma_rules, yara_rules,
    actor_attribution, mitre_navigator_url, detailed_analysis,
    executive_summary, technical_analysis, recommendations
  Tier ENTERPRISE:
    stix_id_bundle, taxii_url, misp_export, splunk_query,
    sentinel_query, elastic_query, qradar_query,
    siem_rules, integration_payload

PUBLIC FIELDS (safe to expose):
  id, title, severity, risk_score, source, published, published_at,
  threat_type, tags, ioc_count, cve_id, cve_ids, stix_id,
  _tier_notice, _upgrade_url, intelligence_origin, apex_source_label,
  confidence, tlp, actor_id, actor_name (name only, not full attribution),
  cvss_score, epss_score, kev, kev_present, kev_date

DEPLOYMENT CONTRACT:
  Any public API endpoint that exposes a premium field MUST fail
  the CI/CD pipeline (Stage 5.6.2 -- Public API Sanitization Gate).

Usage:
  from public_api_sanitizer import sanitize_for_public, audit_leakage
"""
import json, os, sys, re
from typing import Any

# ----- Premium field registry ------------------------------------------------
# Fields that are NEVER allowed in public API responses.
# Add new premium fields here as the platform grows.
PREMIUM_FIELDS: frozenset = frozenset([
    # PRO tier
    "report_url",
    "internal_report_url",
    "stix_bundle_url",
    "stix_bundle",
    "pdf_url",
    "pdf_report_url",
    "apex_ai",
    "ioc_hashes",
    "ioc_payload",
    "kill_chain",
    "kill_chain_phases",
    "detection_rules",
    "sigma_rules",
    "yara_rules",
    "actor_attribution",
    "attribution_evidence",
    "mitre_navigator_url",
    "detailed_analysis",
    "executive_summary",
    "technical_analysis",
    "recommendations",
    "raw_iocs",
    "full_iocs",
    "ioc_list",
    # ENTERPRISE tier
    "stix_id_bundle",
    "taxii_url",
    "misp_export",
    "splunk_query",
    "sentinel_query",
    "elastic_query",
    "qradar_query",
    "siem_rules",
    "integration_payload",
    "enterprise_package",
    "full_stix_bundle",
    "stix_objects",
])

# Fields that are safe for public consumption
PUBLIC_FIELDS: frozenset = frozenset([
    "id", "title", "severity", "risk_score", "source",
    "published", "published_at", "processed_at",
    "threat_type", "tags", "ioc_count", "cve_id", "cve_ids",
    "stix_id", "_tier_notice", "_upgrade_url",
    "intelligence_origin", "apex_source_label",
    "confidence", "tlp", "actor_id", "actor_name",
    "cvss_score", "epss_score", "epss_percentile",
    "kev", "kev_present", "kev_date",
    "mitre_techniques", "attack_techniques", "ttps",
    "description_public", "summary",
    "ioc_paywall",
])

TIER_NOTICE = "Upgrade to PRO for full enrichment: actor attribution, kill chain, IOC hashes, AI analysis, STIX bundle."
UPGRADE_URL = "/upgrade.html?plan=pro"


def sanitize_for_public(item: dict) -> dict:
    """Return a copy of item with all premium fields removed.
    Adds _tier_notice and _upgrade_url to every item so clients know
    premium content exists but is gated."""
    out = {}
    for k, v in item.items():
        if k not in PREMIUM_FIELDS:
            out[k] = v
    # Always inject tier notice so public clients see the upgrade path
    out["_tier_notice"] = TIER_NOTICE
    out["_upgrade_url"]  = UPGRADE_URL
    return out


def sanitize_feed(items: list) -> list:
    """Sanitize a list of feed items for public API output."""
    return [sanitize_for_public(i) for i in items]


def audit_leakage(items: list) -> dict:
    """Audit a list of items for premium field exposure.
    Returns a dict with leakage counts per field and per item."""
    field_counts: dict = {}
    leaking_items: list = []
    for item in items:
        leaked = [f for f in PREMIUM_FIELDS if item.get(f) is not None]
        if leaked:
            for f in leaked:
                field_counts[f] = field_counts.get(f, 0) + 1
            leaking_items.append({
                "id":     item.get("id") or item.get("stix_id", "?"),
                "title":  (item.get("title") or "")[:80],
                "fields": leaked,
            })
    return {
        "total_items":     len(items),
        "leaking_items":   len(leaking_items),
        "clean_items":     len(items) - len(leaking_items),
        "leak_rate_pct":   round(100 * len(leaking_items) / max(len(items), 1), 2),
        "field_counts":    field_counts,
        "leaking_details": leaking_items[:50],  # cap at 50 for report size
        "PASS":            len(leaking_items) == 0,
    }


# ---- Standalone audit + report mode -----------------------------------------
if __name__ == "__main__":
    import argparse, datetime, pathlib

    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    parser = argparse.ArgumentParser(description="SENTINEL APEX Public API Sanitizer")
    parser.add_argument("--feed",   default=os.path.join(REPO, "api", "feed.json"),
                        help="Path to api/feed.json")
    parser.add_argument("--fix",    action="store_true",
                        help="Write sanitized feed back in-place (atomic)")
    parser.add_argument("--report", default=os.path.join(REPO, "reports", "public_api_sanitization_audit.json"),
                        help="Output report path")
    parser.add_argument("--hard-fail", action="store_true",
                        help="Exit 1 if any premium field is found in feed")
    args = parser.parse_args()

    feed_path = pathlib.Path(args.feed)
    if not feed_path.exists():
        print(f"[ERROR] Feed not found: {feed_path}")
        sys.exit(1)

    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", [])

    print("=" * 60)
    print("PUBLIC API SANITIZER  v1.0  -- AUDIT MODE")
    print("=" * 60)
    print(f"Feed: {feed_path}  ({len(items)} items)")

    audit = audit_leakage(items)

    # Per-field breakdown
    print(f"\nLEAKAGE SUMMARY:")
    print(f"  Total items   : {audit['total_items']}")
    print(f"  Leaking items : {audit['leaking_items']}")
    print(f"  Clean items   : {audit['clean_items']}")
    print(f"  Leak rate     : {audit['leak_rate_pct']}%")
    if audit["field_counts"]:
        print(f"\n  LEAKED FIELDS:")
        for field, count in sorted(audit["field_counts"].items(), key=lambda x: -x[1]):
            print(f"    [{count:3d} items] {field}")
    else:
        print(f"\n  No premium fields found -- CLEAN")

    # Apply fix if requested
    sanitized_count = 0
    if args.fix and audit["leaking_items"] > 0:
        sanitized = sanitize_feed(items)
        tmp = feed_path.with_suffix(".sanitize.tmp")
        out_payload = sanitized if isinstance(raw, list) else {**raw, "items": sanitized}
        tmp.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(feed_path)
        sanitized_count = audit["leaking_items"]
        print(f"\n[FIX] Sanitized {sanitized_count} items -- written to {feed_path}")

    # Write report
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = {
        "report_type":     "public_api_sanitization_audit",
        "generated_at":    now,
        "version":         "v1.0",
        "feed_path":       str(feed_path),
        "audit":           audit,
        "fix_applied":     args.fix and sanitized_count > 0,
        "items_sanitized": sanitized_count,
        "VERDICT":         "PASS" if audit["PASS"] else "FAIL",
        "VERDICT_DETAIL":  (
            "No premium fields exposed in public API."
            if audit["PASS"]
            else f"{audit['leaking_items']} items expose premium fields: "
                 f"{list(audit['field_counts'].keys())}"
        ),
    }

    report_path = pathlib.Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[REPORT] Written: {report_path}")
    print(f"[VERDICT] {report['VERDICT']} -- {report['VERDICT_DETAIL']}")
    print("=" * 60)

    if args.hard_fail and not audit["PASS"]:
        print("[HARD-FAIL] Premium field leakage detected -- deployment blocked")
        sys.exit(1)

    sys.exit(0)
