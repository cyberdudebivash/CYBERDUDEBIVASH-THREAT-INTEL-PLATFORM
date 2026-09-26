#!/usr/bin/env python3
"""
scripts/security_txt_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- security.txt validator (RFC 9116)
======================================================================
The platform publishes its vulnerability-disclosure contact at
  /.well-known/security.txt   canonical location (RFC 9116 section 3)
  /security.txt               identical copy for legacy clients
Both are served from GitHub Pages, which cannot redirect, so the two files
must stay byte-identical.

Checks (RFC 9116 section 2):
  - UTF-8 text; every non-comment line is "Field-Name: value"
  - Contact: at least one, each a mailto:, https: or tel: URI
  - Expires: exactly one, ISO 8601 / RFC 3339 date-time, in the future,
    and no more than a year ahead (the RFC recommends less than a year)
  - Preferred-Languages: at most one
  - Canonical: https URIs; must list every location this site serves
  - Policy / Acknowledgments / Encryption / Hiring / CSAF: https URIs
  - the legacy copy is byte-identical to the canonical file

Exit codes: 0 valid, 1 invalid (including expired), 2 valid but expiring
within --warn-days (default 45) -- time to renew Expires.

Usage:
  python3 scripts/security_txt_validator.py            # validate, print report
  python3 scripts/security_txt_validator.py --json     # machine-readable report

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_PATH = ".well-known/security.txt"
LEGACY_PATH = "security.txt"
SITE = "https://intel.cyberdudebivash.com"
SERVED_URLS = (f"{SITE}/{CANONICAL_PATH}", f"{SITE}/{LEGACY_PATH}")

MAX_AHEAD = timedelta(days=366)
DEFAULT_WARN_DAYS = 45

KNOWN_FIELDS = {
    "acknowledgments", "canonical", "contact", "encryption", "expires",
    "hiring", "policy", "preferred-languages", "csaf",
}
HTTPS_ONLY = {"canonical", "policy", "acknowledgments", "encryption", "hiring", "csaf"}
FIELD_RE = re.compile(r"^([A-Za-z0-9-]+):[ \t]*(\S.*?)[ \t]*$")
# RFC 3339 / ISO 8601 date-time with explicit offset (RFC 9116 section 2.5.5)
EXPIRES_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def parse_fields(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Returns ([(lowercased field, value)], [format errors])."""
    fields, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-----BEGIN PGP") or stripped.startswith("-----END PGP"):
            continue
        m = FIELD_RE.match(line)
        if not m:
            errors.append(f"line {n}: not a 'Field-Name: value' line: {line!r}")
            continue
        fields.append((m.group(1).lower(), m.group(2)))
    return fields, errors


def validate_text(text: str, now: datetime | None = None,
                  warn_days: int = DEFAULT_WARN_DAYS) -> dict:
    """Validates one security.txt body. Returns {errors, warnings, expires}."""
    now = now or datetime.now(UTC)
    fields, errors = parse_fields(text)
    warnings: list[str] = []
    values: dict[str, list[str]] = {}
    for name, value in fields:
        values.setdefault(name, []).append(value)
        if name not in KNOWN_FIELDS:
            warnings.append(f"unknown field {name!r} (allowed, but not defined by RFC 9116)")

    contacts = values.get("contact", [])
    if not contacts:
        errors.append("Contact: missing (RFC 9116 requires at least one)")
    for c in contacts:
        if not re.match(r"^(mailto:[^@\s]+@[^@\s]+\.[^@\s]+|https://\S+|tel:\+?[0-9 ()-]+)$", c):
            errors.append(f"Contact: {c!r} is not a mailto:, https: or tel: URI")

    expires_values = values.get("expires", [])
    expires_at = None
    if len(expires_values) != 1:
        errors.append(f"Expires: must appear exactly once (found {len(expires_values)})")
    else:
        raw = expires_values[0]
        if not EXPIRES_RE.match(raw):
            errors.append(f"Expires: {raw!r} is not an RFC 3339 date-time with a timezone")
        else:
            expires_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if expires_at <= now:
                errors.append(f"Expires: {raw} has passed -- the file is stale and must be renewed")
            elif expires_at - now > MAX_AHEAD:
                errors.append(f"Expires: {raw} is more than a year ahead (RFC 9116 recommends less)")
            elif expires_at - now <= timedelta(days=warn_days):
                days = (expires_at - now).days
                warnings.append(f"Expires: {raw} is {days} day(s) away -- renew it (set a date under a year ahead)")

    if len(values.get("preferred-languages", [])) > 1:
        errors.append("Preferred-Languages: must appear at most once")

    for name in HTTPS_ONLY:
        for v in values.get(name, []):
            if not v.startswith("https://"):
                errors.append(f"{name.title()}: {v!r} must be an https:// URI")

    return {
        "errors": errors,
        "warnings": warnings,
        "expires": expires_at.isoformat() if expires_at else None,
        "canonical": values.get("canonical", []),
    }


def validate_repo(root: Path | str | None = None, now: datetime | None = None,
                  warn_days: int = DEFAULT_WARN_DAYS) -> dict:
    """Validates both published copies. Returns a report dict with a status."""
    base = Path(root) if root is not None else REPO_ROOT
    report: dict = {"files": {}, "errors": [], "warnings": []}
    canonical = base / CANONICAL_PATH
    legacy = base / LEGACY_PATH
    if not canonical.is_file():
        report["errors"].append(f"{CANONICAL_PATH}: missing")
    else:
        try:
            text = canonical.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            report["errors"].append(f"{CANONICAL_PATH}: not valid UTF-8")
            text = None
        if text is not None:
            r = validate_text(text, now=now, warn_days=warn_days)
            report["files"][CANONICAL_PATH] = r
            report["errors"] += [f"{CANONICAL_PATH}: {e}" for e in r["errors"]]
            report["warnings"] += [f"{CANONICAL_PATH}: {w}" for w in r["warnings"]]
            for url in SERVED_URLS:
                if url not in r["canonical"]:
                    report["errors"].append(f"{CANONICAL_PATH}: Canonical must list {url} (it is served there)")
    if not legacy.is_file():
        report["errors"].append(f"{LEGACY_PATH}: missing (legacy /security.txt would 404)")
    elif canonical.is_file() and legacy.read_bytes() != canonical.read_bytes():
        report["errors"].append(f"{LEGACY_PATH}: differs from {CANONICAL_PATH} -- copy it verbatim")
    report["status"] = "INVALID" if report["errors"] else ("EXPIRING" if report["warnings"] else "VALID")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate security.txt (RFC 9116)")
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = validate_repo(warn_days=args.warn_days)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"security.txt: {report['status']}")
        for e in report["errors"]:
            print(f"  ERROR   {e}")
        for w in report["warnings"]:
            print(f"  WARNING {w}")
    if report["errors"]:
        return 1
    return 2 if any("Expires" in w for w in report["warnings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
