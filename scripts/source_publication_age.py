#!/usr/bin/env python3
"""
scripts/source_publication_age.py
SENTINEL APEX -- source publication age (the one place that decides it)

Production /api/v1/intel/latest.json, 2026-09-26T06:28Z (42 items): 12 items
were blog articles published 2026-01-14 .. 2026-08-07 (Project Zero, Google
security blog, SentinelOne weekly recap, Krebs) ingested by the 06:00Z run as
new intelligence. The newest-first feed led with the January article; each
said intelligence_age_days 0; 10 had no source link and a 404 report link.

  - agent/sentinel_blogger.py read up to MAX_ENTRIES_PER_FEED (20) entries per
    RSS feed and never looked at the article date (is_temporally_relevant()
    only checked the CVE year in the title). A low-volume blog's 20 newest
    entries go back months; once the cross-run dedup state no longer lists
    them, they are "new".
  - intelligence_quality_scorer.py computed the age from the processing
    timestamp, so a January article was 0 days old and its confidence never
    decayed.

Rule (additive, one constant): an item whose SOURCE publication date is known
and older than MAX_SOURCE_AGE_DAYS is not new intelligence, unless it carries
an active-exploitation signal (CISA KEV confirmed, or exploitation language in
the title). An item with no readable source date is never judged stale here:
missing is not evidence of old.

Consumers:
  agent/sentinel_blogger.py             ingest gate (is_temporally_relevant)
  scripts/run_pipeline.py               Stage 3.9 STIX reconstruction
  scripts/intelligence_quality_scorer.py intelligence_age_days
  scripts/stale_source_guard.py         feed / manifest guard (CI stages)
"""
from __future__ import annotations

import calendar
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from p20_evidence_chain_enricher import _kev_confirmed  # canonical KEV reader
except Exception:  # pragma: no cover - never block ingestion on an import
    def _kev_confirmed(item: Dict) -> bool:
        for key in ("kev_present", "kev"):
            val = item.get(key)
            if val is True:
                return True
            if val not in (None, False) and str(val).strip().upper() not in {
                    "FALSE", "NO", "0", "NONE", "NULL", "N/A", ""}:
                return True
        return False


def _env_days(name: str, default: int) -> int:
    try:
        val = int(os.environ.get(name, "").strip() or default)
        return val if val > 0 else default
    except ValueError:
        return default


MAX_SOURCE_AGE_DAYS = _env_days("INTEL_MAX_SOURCE_AGE_DAYS", 14)

# Same vocabulary sentinel_blogger.is_temporally_relevant() uses for old CVEs.
ACTIVE_EXPLOITATION_SIGNALS = (
    "actively exploited", "actively exploiting", "attackers actively exploit",
    "in the wild", "active exploitation", "exploited in the wild",
    "under active attack", "mass exploitation", "widespread exploitation",
    "weaponized", "zero-day exploit", "0-day exploit",
)

# Source publication fields, most specific first. processed_at / timestamp /
# created are pipeline clocks and are never read here.
SOURCE_DATE_KEYS = ("published_at", "source_published_at", "x_cdb_published_at", "published")


def parse_source_datetime(value: Any) -> Optional[datetime]:
    """ISO-8601 (Z or offset) or RFC 2822 -> aware UTC datetime; else None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        dt = None
        if text[:4].isdigit():
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                dt = None
        if dt is None:
            try:
                dt = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError):
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def source_published_at(item: Dict) -> Optional[datetime]:
    for key in SOURCE_DATE_KEYS:
        dt = parse_source_datetime(item.get(key))
        if dt is not None:
            return dt
    return None


def _securityaffairs_archive_conflict(item: Dict) -> Optional[datetime]:
    """Conservative archive-month upper bound for a demonstrably misdated source.

    SecurityAffairs uses /YYYYMM/ article archive permalinks. If a claimed
    publication timestamp is >31 days after that archive month, the claimed
    timestamp cannot establish *fresh* intelligence. Return the last instant
    of the archive month (not its first day) to avoid overstating age.

    Deliberately restricted to this verified source and explicit timestamp
    conflicts; generic URL numbers, other publishers and undated items are
    never reinterpreted. No network or source mutation.
    """
    url = item.get("source_url")
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("https", "http") or parsed.hostname not in (
            "securityaffairs.com", "www.securityaffairs.com"
        ):
            return None
        match = re.match(r"^/(20[0-9]{2})(0[1-9]|1[0-2])(?:/|$)", parsed.path)
        if match is None:
            return None
        year, month = map(int, match.groups())
        month_end = datetime(
            year, month, calendar.monthrange(year, month)[1],
            23, 59, 59, tzinfo=timezone.utc
        )
        stated = source_published_at(item)
        if stated is None or stated <= month_end + timedelta(days=31):
            return None
        return month_end
    except (TypeError, ValueError, OverflowError):
        return None


def source_age_days(item: Dict, now: Optional[datetime] = None) -> Optional[float]:
    """Days since the source published the item; None when no source date."""
    dt = _securityaffairs_archive_conflict(item) or source_published_at(item)
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def has_active_exploitation_signal(item: Dict) -> bool:
    if _kev_confirmed(item):
        return True
    title = str(item.get("title") or "").lower()
    return any(s in title for s in ACTIVE_EXPLOITATION_SIGNALS)


def is_stale_source(item: Dict, max_age_days: Optional[int] = None,
                    now: Optional[datetime] = None) -> bool:
    """True when the source date is known, older than the window, and the item
    carries no active-exploitation signal."""
    age = source_age_days(item, now=now)
    if age is None:
        return False
    limit = max_age_days if max_age_days is not None else MAX_SOURCE_AGE_DAYS
    if age <= limit:
        return False
    return not has_active_exploitation_signal(item)
