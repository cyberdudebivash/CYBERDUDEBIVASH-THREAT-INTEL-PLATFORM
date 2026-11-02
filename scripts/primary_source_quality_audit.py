#!/usr/bin/env python3
"""Offline, read-only cross-check of public CTI against approved primary-source assertions.

This does not fetch sources, alter intelligence, or certify paid-tier artifacts.
Evidence is curated separately, with exact provenance and an explicit observation scope.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SEVERITIES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_INPUT_BYTES = 5_000_000


class AuditInputError(ValueError):
    """Fail closed for invalid or untrusted local audit input."""


def _https_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        p = urlsplit(value)
        return p.scheme == "https" and bool(p.hostname) and not p.username and not p.password and not p.fragment
    except ValueError:
        return False


def _read_json(path: Path) -> object:
    if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise AuditInputError("Input missing or exceeds 5 MB limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditInputError("Input is not valid UTF-8 JSON") from exc


def _check_evidence(evidence: object) -> list[dict]:
    if not isinstance(evidence, dict) or evidence.get("schema_version") != "1.0":
        raise AuditInputError("Unsupported evidence schema")
    assertions = evidence.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise AuditInputError("Evidence assertions must be a nonempty list")
    seen = set()
    for a in assertions:
        if not isinstance(a, dict) or not isinstance(a.get("id"), str) or not a["id"].strip():
            raise AuditInputError("Every assertion requires a nonempty id")
        if a["id"] in seen:
            raise AuditInputError("Duplicate assertion id")
        seen.add(a["id"])
        if not _https_url(a.get("primary_source_url")) or not a.get("primary_source_published_at"):
            raise AuditInputError("Primary-source HTTPS URL and publication date required")
        if not _https_url(a.get("feed_source_url")):
            raise AuditInputError("Exact public-feed source URL required")
        if a.get("cve_id") is not None and not CVE_RE.fullmatch(a["cve_id"]):
            raise AuditInputError("Invalid CVE identifier")
        if a.get("minimum_severity") is not None and a["minimum_severity"] not in SEVERITIES:
            raise AuditInputError("Invalid minimum severity")
        for key in ("primary_indicators_published", "primary_attribution_published", "primary_cvss_published"):
            if key in a and not isinstance(a[key], bool):
                raise AuditInputError("Primary-source claim flags must be booleans")
    return assertions


def audit(feed: object, evidence: object) -> dict:
    """Return a deterministic verdict; no network, writes, or paid-tier inference."""
    assertions = _check_evidence(evidence)
    if not isinstance(feed, dict) or not isinstance(feed.get("items"), list):
        raise AuditInputError("Feed must contain an items array")
    findings: list[dict] = []
    for a in assertions:
        candidates = [i for i in feed["items"] if isinstance(i, dict) and i.get("source_url") == a["feed_source_url"]]
        if a.get("cve_id"):
            candidates = [i for i in candidates if a["cve_id"] in (
                [i.get("cve_id")] + (i.get("cve_ids") if isinstance(i.get("cve_ids"), list) else [])
            )]
        if not candidates:
            findings.append({"assertion_id": a["id"], "code": "FEED_ITEM_NOT_PRESENT", "level": "info"})
            continue
        for item in candidates:
            item_id = str(item.get("id") or "unknown")
            minimum = a.get("minimum_severity")
            if minimum and SEVERITIES.get(str(item.get("severity") or "").upper(), 0) < SEVERITIES[minimum]:
                findings.append({"assertion_id": a["id"], "item_id": item_id,
                                 "code": "PRIMARY_SEVERITY_UNDERTRIAGE", "level": "block",
                                 "observed": str(item.get("severity") or "UNKNOWN"), "minimum": minimum})
            if a.get("primary_indicators_published") and item.get("ioc_count") == 0:
                findings.append({"assertion_id": a["id"], "item_id": item_id,
                                 "code": "PUBLIC_FEED_IOC_COVERAGE_GAP", "level": "review"})
            if a.get("primary_attribution_published") and str(item.get("actor_display_name") or "").lower() in ("", "unknown threat actor", "unknown"):
                findings.append({"assertion_id": a["id"], "item_id": item_id,
                                 "code": "PUBLIC_FEED_ATTRIBUTION_GAP", "level": "review"})
            if a.get("primary_cvss_published") is False and item.get("cvss_score") is not None:
                findings.append({"assertion_id": a["id"], "item_id": item_id,
                                 "code": "CVSS_PROVENANCE_REVIEW", "level": "review"})
    counts = {k: sum(f["level"] == k for f in findings) for k in ("block", "review", "info")}
    return {"schema_version": "1.0", "scope": "public_feed_only", "source_generated_at": feed.get("generated_at"),
            "assertions_checked": len(assertions), "findings": findings, "counts": counts,
            "verdict": "BLOCK" if counts["block"] else ("REVIEW" if counts["review"] else "PASS")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, required=True, help="Local snapshot of public latest.json")
    parser.add_argument("--evidence", type=Path, required=True, help="Manually reviewed primary-source assertions JSON")
    args = parser.parse_args(argv)
    try:
        result = audit(_read_json(args.feed), _read_json(args.evidence))
    except AuditInputError as exc:
        print(json.dumps({"verdict": "INPUT_ERROR", "error": str(exc)}), file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return {"PASS": 0, "REVIEW": 1, "BLOCK": 2}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
