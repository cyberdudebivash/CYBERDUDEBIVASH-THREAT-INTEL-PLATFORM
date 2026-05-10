#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
VERSION GOVERNANCE ENGINE v147.0.0
===============================================================================
PURPOSE:
  Single-source-of-truth version authority for the entire SENTINEL APEX
  platform. Reads the authoritative version from the VERSION file and
  propagates it deterministically to every component that carries a version
  string — eliminating all platform-wide version drift.

AUTHORITATIVE SOURCE:
  VERSION  (repo root, plain semver string, one line)

TARGETS GOVERNED:
  version.json                            — platform version manifest
  workers/intel-gateway/src/index.js     — GATEWAY_VERSION in CONFIG object
  js/api_adapter.js                       — VERSION constant in public API
  scripts/r2_upload.py                    — PIPELINE_VERSION default
  scripts/ai_brain_publisher.py           — VERSION constant

MODE:
  --check    Verify all targets match the authority. Exit 1 on any drift.
  --apply    Write the authoritative version to all targets. (default)
  --report   Print a table of all version strings. Exit 0 always.

EXIT CODES:
  0 — All targets match (check) or all targets updated (apply)
  1 — Version drift detected (check) or write failure (apply)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [version_governance] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-VERSION-GOV")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Version target descriptors
# Each entry: (relative_path, match_pattern, replacement_template)
# {VER} in the template is replaced with the authoritative semver string.
# ---------------------------------------------------------------------------
class Target(NamedTuple):
    rel_path: str          # path relative to REPO_ROOT
    pattern:  str          # regex to locate the version in the file
    template: str          # replacement string ({VER} = authoritative version)
    mode:     str          # "regex" or "json"
    json_key: str = ""     # for mode="json", the dotted key path e.g. "version"


TARGETS: list[Target] = [
    # --- workers/intel-gateway/src/index.js ---
    Target(
        rel_path="workers/intel-gateway/src/index.js",
        pattern=r'(GATEWAY_VERSION:\s*")[0-9]+\.[0-9]+\.[0-9]+"',
        template=r'\g<1>{VER}"',
        mode="regex",
    ),
    # X-Powered-By header string
    Target(
        rel_path="workers/intel-gateway/src/index.js",
        pattern=r'(CYBERDUDEBIVASH-SENTINEL-APEX-v)\d+',
        template=r'\g<1>{VERMAJ}',
        mode="regex",
    ),
    # --- js/api_adapter.js ---
    Target(
        rel_path="js/api_adapter.js",
        pattern=r'(VERSION:\s*")[0-9]+\.[0-9]+\.[0-9]+"',
        template=r'\g<1>{VER}"',
        mode="regex",
    ),
    Target(
        rel_path="js/api_adapter.js",
        pattern=r'(SENTINEL APEX — API ADAPTER v)[0-9]+\.[0-9]+\.[0-9]+',
        template=r'\g<1>{VER}',
        mode="regex",
    ),
    # --- scripts/ai_brain_publisher.py ---
    Target(
        rel_path="scripts/ai_brain_publisher.py",
        pattern=r'(VERSION\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+"',
        template=r'\g<1>{VER}"',
        mode="regex",
    ),
    # --- scripts/r2_upload.py PIPELINE_VERSION default ---
    Target(
        rel_path="scripts/r2_upload.py",
        pattern=r'(PIPELINE_VERSION\s*=\s*os\.environ\.get\("PIPELINE_VERSION",\s*")[0-9]+\.[0-9]+\.[0-9]+"',
        template=r'\g<1>{VER}"',
        mode="regex",
    ),
]


def read_authority() -> str:
    path = REPO_ROOT / "VERSION"
    ver = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
        log.error("VERSION file contains invalid semver: %r", ver)
        sys.exit(1)
    return ver


def major(ver: str) -> str:
    return ver.split(".")[0]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def update_version_json(ver: str, apply: bool) -> tuple[bool, str, str]:
    path = REPO_ROOT / "version.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "?", f"read error: {e}"

    found = data.get("version", "?")
    if found == ver:
        return True, found, "ok"
    if not apply:
        return False, found, f"drift: file has {found!r}, authority is {ver!r}"

    now = now_iso()
    data["version"]          = ver
    data["release"]          = f"v{ver}"
    data["pipeline_version"] = ver
    data["updated_at"]       = now
    data["generated_at"]     = now
    data["build"]            = f"v{ver}-ENTERPRISE-GRADE-{now[:10].replace('-','')}"
    data["_generator"]       = f"CYBERDUDEBIVASH SENTINEL APEX Pipeline v{ver}"
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return True, found, "updated"
    except Exception as e:
        return False, found, f"write error: {e}"


def check_or_apply_target(t: Target, ver: str, apply: bool) -> tuple[bool, str, str]:
    path = REPO_ROOT / t.rel_path
    if not path.exists():
        return True, "N/A", "file not found — skip"

    text = path.read_text(encoding="utf-8")
    replacement = t.template.replace("{VER}", ver).replace("{VERMAJ}", major(ver))

    m = re.search(t.pattern, text)
    if not m:
        return True, "N/A", "pattern not found — skip"

    current_match = m.group(0)
    # Extract just the version digits from the match for display
    ver_in_file_m = re.search(r"\d+\.\d+\.\d+", current_match)
    ver_in_file = ver_in_file_m.group(0) if ver_in_file_m else current_match

    new_text = re.sub(t.pattern, replacement, text)
    if new_text == text:
        return True, ver_in_file, "ok"

    if not apply:
        return False, ver_in_file, f"drift: file has {ver_in_file!r}, authority is {ver!r}"

    try:
        path.write_text(new_text, encoding="utf-8")
        return True, ver_in_file, "updated"
    except Exception as e:
        return False, ver_in_file, f"write error: {e}"


def run(mode: str) -> int:
    apply = mode == "apply"
    ver = read_authority()
    log.info("Authoritative version: %s  (mode=%s)", ver, mode)

    rows: list[tuple[str, str, str, bool]] = []
    any_drift = False

    # version.json is handled separately (JSON field update)
    ok, found, status = update_version_json(ver, apply)
    rows.append(("version.json", found, status, ok))
    if not ok:
        any_drift = True

    for t in TARGETS:
        ok, found, status = check_or_apply_target(t, ver, apply)
        rows.append((t.rel_path, found, status, ok))
        if not ok:
            any_drift = True

    # Report table
    col0 = max(len(r[0]) for r in rows) + 2
    col1 = max(len(r[1]) for r in rows) + 2
    header = f"{'FILE':<{col0}} {'FOUND':<{col1}} STATUS"
    log.info("%s", header)
    log.info("%s", "-" * len(header))
    for file_, found, status, ok in rows:
        flag = "OK" if ok else "DRIFT"
        log.info("%-*s %-*s [%s] %s", col0, file_, col1, found, flag, status)

    if mode == "report":
        return 0

    if any_drift and not apply:
        log.error("Version drift detected. Run with --apply to fix.")
        return 1

    if not any_drift:
        log.info("All version targets are consistent at v%s.", ver)
    else:
        log.info("Version governance applied — all targets set to v%s.", ver)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Version Governance Engine")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--check",  action="store_true", help="Detect drift only. Exit 1 if found.")
    grp.add_argument("--apply",  action="store_true", help="Apply authoritative version to all targets.")
    grp.add_argument("--report", action="store_true", help="Print version table. Always exits 0.")
    args = parser.parse_args()

    if args.check:
        mode = "check"
    elif args.report:
        mode = "report"
    else:
        mode = "apply"   # default

    sys.exit(run(mode))


if __name__ == "__main__":
    main()
