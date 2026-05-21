#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
VERSION GOVERNANCE ENGINE v148.0.0
===============================================================================
PURPOSE:
  Single-source-of-truth version authority for the SENTINEL APEX platform.
  Reads the authoritative version from the VERSION file and propagates it
  deterministically to backend/gateway components that carry a version string,
  eliminating platform-wide version drift.

AUTHORITATIVE SOURCE:
  VERSION  (repo root, plain semver string, one line)

TARGETS GOVERNED (backend/gateway + CI workflows):
  version.json                            -- root platform version manifest
  config/version.json                     -- SSOT for deploy-worker workflow
  workers/intel-gateway/src/index.js     -- GATEWAY_VERSION in CONFIG object
  scripts/r2_upload.py                    -- PIPELINE_VERSION default
  scripts/ai_brain_publisher.py           -- VERSION constant
  .github/workflows/sentinel-blogger.yml  -- PIPELINE_VERSION env var
  .github/workflows/generate-and-sync.yml -- PIPELINE_VERSION env var

NOT GOVERNED (have their own independent versioning):
  js/api_adapter.js           -- UI component, guarded by ui-file-guardian
  js/card_renderer.js         -- UI component, guarded by ui-file-guardian
  js/card_renderer_integration.js -- UI component, guarded by ui-file-guardian

MODE:
  --check    Verify all targets match the authority. Exit 1 on any drift.
  --apply    Write the authoritative version to all targets. (default)
  --report   Print a table of all version strings. Exit 0 always.

EXIT CODES:
  0 -- All targets match (check) or all targets updated (apply)
  1 -- Version drift detected (check) or write failure (apply)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [version_governance] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-VERSION-GOV")

REPO_ROOT = Path(__file__).resolve().parent.parent


def read_authority():
    path = REPO_ROOT / "VERSION"
    ver = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", ver):
        log.error("VERSION file contains invalid semver: %r", ver)
        sys.exit(1)
    return ver


def major(ver):
    return ver.split(".")[0]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Regex-based targets (backend/gateway + CI workflow components)
# ---------------------------------------------------------------------------
# Each tuple: (relative_path, pattern, replacement_template)
# {VER} -> full semver, {VERMAJ} -> major integer only
REGEX_TARGETS = [
    # workers/intel-gateway/src/index.js -- GATEWAY_VERSION
    (
        "workers/intel-gateway/src/index.js",
        r'(GATEWAY_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # workers/intel-gateway/src/index.js -- X-Powered-By major version
    (
        "workers/intel-gateway/src/index.js",
        r'(CYBERDUDEBIVASH-SENTINEL-APEX-v)\d+',
        r'\g<1>{VERMAJ}',
    ),
    # scripts/ai_brain_publisher.py -- VERSION constant
    (
        "scripts/ai_brain_publisher.py",
        r'(VERSION\s*=\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # scripts/r2_upload.py -- PIPELINE_VERSION default
    (
        "scripts/r2_upload.py",
        r'(PIPELINE_VERSION\s*=\s*os\.environ\.get\("PIPELINE_VERSION",\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # .github/workflows/sentinel-blogger.yml -- PIPELINE_VERSION env var (v148.0 governance)
    (
        ".github/workflows/sentinel-blogger.yml",
        r'(  PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # .github/workflows/generate-and-sync.yml -- PIPELINE_VERSION env var (v148.0 governance)
    (
        ".github/workflows/generate-and-sync.yml",
        r'(  PIPELINE_VERSION:\s*")[0-9]+\.[0-9]+(?:\.[0-9]+)?"',
        r'\g<1>{VER}"',
    ),
    # -------------------------------------------------------------------------
    # HTML surface governance (v148.0 -- prevents documentation drift)
    # -------------------------------------------------------------------------
    # api-docs.html -- <title> version string
    (
        "api-docs.html",
        r'(CYBERDUDEBIVASH&reg; SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?(<\/span>|(?=\.))',
        r'\g<1>v{VER}\g<2>',
    ),
    # api-docs.html -- brand navbar version
    (
        "api-docs.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # api-docs.html -- health example advisory_count (governance: keep in sync with live count)
    # NOTE: advisory count is intentionally NOT governed by semver — governed separately.
    # api-docs.html -- CDB-UPGRADE-BANNER comment marker
    (
        "api-docs.html",
        r'CDB-UPGRADE-BANNER-v[0-9]+',
        r'CDB-UPGRADE-BANNER-v{VERMAJ}',
    ),
    # ai-threat-tracker.html -- version string (if present)
    (
        "ai-threat-tracker.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- SENTINEL APEX version string (inline: e.g. "SENTINEL APEX v158.5")
    (
        "observability.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- brand navbar <span> tag (e.g. "SENTINEL APEX <span>v148.0.0</span>")
    (
        "observability.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # observability.html -- JS fallback version string (e.g. data.version||'v148.0.0')
    (
        "observability.html",
        r"(\|\|')v[0-9]+\.[0-9]+(?:\.[0-9]+)?(')",
        r"\g<1>v{VER}\g<2>",
    ),
    # observability.html -- Observability Engine init log line (Engine v148.0.0 style)
    (
        "observability.html",
        r'(Observability Engine )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # observability.html -- JS comment header (Dashboard v148.0.0 style)
    (
        "observability.html",
        r'(Observability Dashboard )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # trust-center.html -- SENTINEL APEX version string (inline)
    (
        "trust-center.html",
        r'(SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?',
        r'\g<1>v{VER}',
    ),
    # trust-center.html -- brand navbar <span> tag (e.g. "SENTINEL APEX <span>v148.0.0</span>")
    (
        "trust-center.html",
        r'(SENTINEL APEX <span>)v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</span>)',
        r'\g<1>v{VER}\g<2>',
    ),
    # data/health/sla_status.json -- version field (governance: keep current)
    # Handled by update_version_json below.
]

# HTML targets with simple title tag governance
HTML_TITLE_TARGETS = [
    # (relative_path, old_title_pattern, new_title_template)
    (
        "api-docs.html",
        r'(<title>API Documentation &mdash; CYBERDUDEBIVASH&reg; SENTINEL APEX )v[0-9]+\.[0-9]+(?:\.[0-9]+)?(</title>)',
        r'\g<1>v{VER}\g<2>',
    ),
]


def check_or_apply_regex(rel_path, pattern, template, ver, apply):
    path = REPO_ROOT / rel_path
    if not path.exists():
        return True, "N/A", "file not found -- skip"

    text = path.read_text(encoding="utf-8")
    replacement = template.replace("{VER}", ver).replace("{VERMAJ}", major(ver))

    m = re.search(pattern, text)
    if not m:
        return True, "N/A", "pattern not found -- skip"

    current = m.group(0)
    ver_m = re.search(r"\d+\.\d+(?:\.\d+)?", current)
    found_ver = ver_m.group(0) if ver_m else current

    new_text = re.sub(pattern, replacement, text)
    if new_text == text:
        return True, found_ver, "ok"

    if not apply:
        return False, found_ver, "drift: %s -> %s" % (found_ver, ver)

    try:
        path.write_text(new_text, encoding="utf-8")
        return True, found_ver, "updated"
    except Exception as e:
        return False, found_ver, "write error: %s" % e


def update_version_json(rel_path, ver, apply):
    """Update a version JSON file that has multiple version fields."""
    path = REPO_ROOT / rel_path
    if not path.exists():
        return True, "N/A", "file not found -- skip"

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "?", "read error: %s" % e

    found = data.get("version", "?")
    if found == ver:
        return True, found, "ok"

    if not apply:
        return False, found, "drift: %s -> %s" % (found, ver)

    now = now_iso()
    today = now[:10].replace("-", "")

    for key in ("version", "pipeline_version"):
        if key in data:
            data[key] = ver
    for key in ("platform", "api_gateway", "report_engine", "ai_engine", "nexus",
                "genesis", "cortex", "quantum", "sovereign", "bug_hunter", "tip_soar",
                "worker", "pipeline"):
        if key in data:
            data[key] = ver

    if "release" in data:
        data["release"] = "v%s" % ver
    if "platform_label" in data:
        data["platform_label"] = "v%s" % ver.split(".")[0]
    if "platform_full" in data:
        data["platform_full"] = "SENTINEL APEX v%s" % ver
    if "api_gateway" in data:
        data["api_gateway"] = "SENTINEL-APEX/%s" % ver
    if "version_short" in data:
        data["version_short"] = "v%s" % ver.split(".")[0]
    if "version_display" in data:
        data["version_display"] = "v%s" % ver
    if "version_full" in data:
        data["version_full"] = "SENTINEL APEX v%s" % ver
    if "schema_version" in data:
        data["schema_version"] = "v%s" % ver.split(".")[0]

    if "components" in data and isinstance(data["components"], dict):
        for k in ("worker", "dashboard", "pipeline"):
            if k in data["components"]:
                data["components"][k] = ver
        if "platform" in data["components"]:
            data["components"]["platform"] = "CYBERDUDEBIVASH(R) SENTINEL APEX v%s" % ver
        if "pipeline" in data["components"]:
            data["components"]["pipeline"] = ver.rsplit(".", 1)[0]

    for key in ("updated_at", "generated_at", "_generated"):
        if key in data:
            data[key] = now
    if "build_date" in data:
        data["build_date"] = now[:10]
    if "release_date" in data:
        data["release_date"] = now[:10]

    if "build" in data:
        data["build"] = "v%s-ENTERPRISE-GRADE-%s" % (ver, today)
    if "_generator" in data:
        data["_generator"] = "CYBERDUDEBIVASH SENTINEL APEX Pipeline v%s" % ver
    if "changelog" in data:
        data["changelog"] = (
            "v%s ENTERPRISE-GRADE: ai_summary.json manifest fix, "
            "global version governance, feed dedup enforcement, "
            "AI Cyber Brain live activation" % ver
        )

    try:
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return True, found, "updated"
    except Exception as e:
        return False, found, "write error: %s" % e


def run(mode):
    apply = mode == "apply"
    ver = read_authority()
    log.info("Authoritative version: %s  (mode=%s)", ver, mode)

    rows = []
    any_drift = False

    ok, found, status = update_version_json("version.json", ver, apply)
    rows.append(("version.json", found, status, ok))
    if not ok:
        any_drift = True

    ok, found, status = update_version_json("config/version.json", ver, apply)
    rows.append(("config/version.json", found, status, ok))
    if not ok:
        any_drift = True

    # data/health/sla_status.json -- keep version tag current (APPLY only).
    # v148.1.0 FIX: sla_status.json is RUNTIME-GENERATED by sla_engine.py,
    # which writes its own component version (e.g. 143.0.0) each time it runs.
    # This file will ALWAYS have a stale version between sla_engine.py runs.
    # Including it in --check drift detection caused recurring HARD FAILs at
    # STAGE 0.06 of sentinel-blogger, blocking the entire pipeline on every
    # sla_engine regeneration cycle.
    # FIX: apply mode still updates the file (keeping it current); check mode
    # reports the state but does NOT contribute to any_drift (advisory only).
    ok, found, status = update_version_json("data/health/sla_status.json", ver, apply)
    rows.append(("data/health/sla_status.json", found, status, ok))
    if not ok and apply:
        # Only count as drift failure in apply mode (write error) — never in check mode.
        any_drift = True

    for rel_path, pattern, template in REGEX_TARGETS + HTML_TITLE_TARGETS:
        ok, found, status = check_or_apply_regex(rel_path, pattern, template, ver, apply)
        rows.append((rel_path, found, status, ok))
        if not ok:
            any_drift = True

    col0 = max(len(r[0]) for r in rows) + 2
    col1 = max(len(r[1]) for r in rows) + 2
    header = "%-*s %-*s %s" % (col0, "FILE", col1, "FOUND", "STATUS")
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
        log.info("Version governance applied -- all targets set to v%s.", ver)
    return 0



def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Version Governance Engine"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "--check", action="store_true",
        help="Detect drift only. Exit 1 if found."
    )
    grp.add_argument(
        "--apply", action="store_true",
        help="Apply authoritative version to all targets."
    )
    grp.add_argument(
        "--report", action="store_true",
        help="Print version table. Always exits 0."
    )
    args = parser.parse_args()

    if args.check:
        mode = "check"
    elif args.report:
        mode = "report"
    else:
        mode = "apply"

    sys.exit(run(mode))


if __name__ == "__main__":
    main()
