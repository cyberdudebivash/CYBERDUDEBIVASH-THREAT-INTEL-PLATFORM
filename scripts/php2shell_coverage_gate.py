#!/usr/bin/env python3
"""Fail-closed PHP2Shell customer-feed coverage gate. Stdlib only; read-only.

Usage:
  python scripts/php2shell_coverage_gate.py --url https://intel.cyberdudebivash.com/api/v1/intel/latest.json
  python scripts/php2shell_coverage_gate.py --file evidence/latest.json

Exit 0 only when both CVEs are present in this bounded published snapshot,
with links to recognized source domains and a fresh manifest. A domain match
is NOT proof that an advisory corroborates the CVE. Absence in a bounded
snapshot does NOT prove ingestion failure. Never manufactures intelligence.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

REQUIRED = {"CVE-2026-109618", "CVE-2026-109619"}
CVE_RE = re.compile(r"\bCVE-2026-10961(?:8|9)\b", re.I)
SOURCE_HOSTS = {"php.net", "www.php.net", "nvd.nist.gov", "www.cve.org", "cve.org"}
MAX_BYTES = 4_000_000

def _read(url=None, file=None):
    if file:
        return json.loads(Path(file).read_text(encoding="utf-8"))
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("HTTPS URL required")
    if parsed.hostname != "intel.cyberdudebivash.com" or parsed.port not in (None, 443):
        raise ValueError("Only canonical production host permitted")
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "sentinel-apex-coverage-gate/1"})
    with urlopen(req, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Response exceeds size limit")
        return json.loads(raw)

def _valid_source(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and host in SOURCE_HOSTS and not parsed.username and not parsed.password and parsed.port in (None, 443)

def _sources(item):
    result = []
    for key in ("references", "sources", "source_urls", "source_url", "source", "url"):
        val = item.get(key)
        if isinstance(val, str):
            result.append(val)
        elif isinstance(val, list):
            for entry in val:
                if isinstance(entry, str):
                    result.append(entry)
                elif isinstance(entry, dict):
                    result.extend(entry.get(k) for k in ("url", "href") if isinstance(entry.get(k), str))
    return result

def check(payload, max_age_hours=6, now=None):
    if not isinstance(payload, dict):
        return ["payload_not_object"]
    items = payload.get("items")
    if not isinstance(items, list):
        return ["missing_items_array"]
    errors = []
    found = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        identifiers = " ".join(str(item.get(k, "")) for k in ("id", "cve_id", "cve_ids", "cve", "title", "name"))
        ids = {m.upper() for m in CVE_RE.findall(identifiers)}
        for cve in ids:
            if not any(_valid_source(s) for s in _sources(item)):
                errors.append(f"{cve}:missing_authoritative_source")
            else:
                found.add(cve)
    errors.extend(f"{cve}:not_verified_in_public_feed" for cve in sorted(REQUIRED - found))
    generated = payload.get("generated_at")
    if not isinstance(generated, str):
        errors.append("missing_generated_at")
    else:
        try:
            dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError("timezone required")
            age = ((now or datetime.now(timezone.utc)) - dt).total_seconds()
            if age < -300 or age > max_age_hours * 3600:
                errors.append("feed_timestamp_outside_freshness_contract")
        except (ValueError, OverflowError):
            errors.append("invalid_generated_at")
    return sorted(set(errors))

def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--file")
    parser.add_argument("--max-age-hours", type=float, default=6)
    args = parser.parse_args()
    try:
        if not 0 < args.max_age_hours <= 168:
            raise ValueError("invalid max age")
        errors = check(_read(url=args.url, file=args.file), args.max_age_hours)
    except Exception as exc:
        errors = [f"unverifiable:{type(exc).__name__}:{exc}"]
    print(json.dumps({"gate": "php2shell_public_coverage", "passed": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1

if __name__ == "__main__":
    sys.exit(main())
