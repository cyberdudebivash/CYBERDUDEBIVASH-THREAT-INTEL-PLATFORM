#!/usr/bin/env python3
"""Fail-closed customer report-link gate for the weekly R2 publication.

A valid weekly intelligence summary does NOT authorize the separate linked
report pages. The /reports/** Worker requires its own P20/P21/P23/P26
publication gate. Before publishing the weekly JSON, keep links only if
the report's public publication-status endpoint confirms CUSTOMER_READY.

One bounded, same-origin, TLS-only GET per unique top-10/KEV report;
never probes external URLs, follows redirects, writes R2, or notifies anyone.
Unavailable/rejected links are removed; verified weekly summary data remains.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

try:
    from scripts import weekly_threat_brief as generator
except ImportError:
    import weekly_threat_brief as generator

BASE_URL = "https://intel.cyberdudebivash.com"
REPORT_URL = re.compile(
    r"^https://intel\.cyberdudebivash\.com/reports/(?:20\d{2})/(?:0[1-9]|1[0-2])/"
    r"(intel--[0-9a-f]{8,64})\.html$",
    re.ASCII,
)
MAX_LINKS = 15


def _approved(slug: str) -> bool:
    """Only verified customer publication status authorizes an active link."""
    url = f"{BASE_URL}/api/v1/reports/{slug}/publication-status"
    try:
        resp = requests.get(
            url, timeout=(3, 6), allow_redirects=False,
            headers={"Accept": "application/json", "Cache-Control": "no-cache"},
        )
        if resp.status_code != 200:
            return False
        payload = resp.json()
        return (
            isinstance(payload, dict)
            and payload.get("report_id") == slug
            and payload.get("customer_ready") is True
            and payload.get("state") == "CUSTOMER_READY"
        )
    except (requests.RequestException, ValueError):
        return False


def reconcile(doc: dict, approve: Callable[[str], bool] = _approved) -> tuple[dict, dict]:
    """Never link a report that the *separate* report Worker would 404.

    The explicit 10+5 maximum prevents unexpected source arrays from
    triggering an unbounded remote request fanout. The input is not mutated.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("top_threats"), list):
        raise ValueError("WEEKLY_LINK_GATE_INVALID_BRIEF")
    entries = doc["top_threats"]
    kev = doc.get("kev_additions", [])
    if not isinstance(kev, list) or not 1 <= len(entries) <= 10 or len(kev) > 5:
        raise ValueError("WEEKLY_LINK_GATE_BOUNDS")
    if not all(isinstance(x, dict) for x in entries + kev):
        raise ValueError("WEEKLY_LINK_GATE_INVALID_ENTRY")
    out = copy.deepcopy(doc)
    cache: dict[str, bool] = {}
    stats = {"linked": 0, "withheld": 0, "unlinked": 0}
    for item in out["top_threats"] + out.get("kev_additions", []):
        original = item.get("report_url")
        if not original:
            item["report_url"] = ""
            stats["unlinked"] += 1
            continue
        match = REPORT_URL.fullmatch(original) if isinstance(original, str) else None
        if match:
            slug = match.group(1)
            if slug not in cache:
                if len(cache) >= MAX_LINKS:
                    raise ValueError("WEEKLY_LINK_GATE_TOO_MANY_CHECKS")
                try:
                    cache[slug] = approve(slug) is True
                except Exception:
                    cache[slug] = False
            if cache[slug]:
                stats["linked"] += 1
                continue
        item["report_url"] = ""
        stats["withheld"] += 1
    # Supplemental evidence, not a claim of report or incident certification.
    out["report_link_verification"] = {
        **stats,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "policy": "CUSTOMER_READY_ONLY",
    }
    return out, stats


def main() -> int:
    path = generator.BRIEF_JSON_PATH
    try:
        original = json.loads(path.read_text(encoding="utf-8"))
        checked, stats = reconcile(original)
        html = generator._render_html(checked)
        # Do not re-render the live dynamic shell; this is a diagnostic snapshot.
        generator._atomic_write(path, checked)
        generator.BRIEF_HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
        generator.BRIEF_HTML_PATH.write_text(html, encoding="utf-8")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"::error::WEEKLY_LINK_GATE_FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(
        "[WEEKLY REPORT LINK GATE] customer-ready links=%d; "
        "withheld rejected/unavailable=%d; originally unlinked=%d"
        % (stats["linked"], stats["withheld"], stats["unlinked"])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
