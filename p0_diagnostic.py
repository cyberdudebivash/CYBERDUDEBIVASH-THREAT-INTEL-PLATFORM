#!/usr/bin/env python3
"""
=================================================================
SENTINEL APEX v46.0 — P0 LIVE DIAGNOSTIC SCRIPT
=================================================================
Run this locally or in GitHub Actions to diagnose exact failure.

Usage:
    python3 -m tests.p0_diagnostic
    OR
    python3 p0_diagnostic.py

Output: Structured JSON report of all failure points
=================================================================
"""

import json
import sys
import os
import traceback
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

REPORT = {
    "run_at": datetime.now(timezone.utc).isoformat(),
    "platform": "SENTINEL APEX v46.0",
    "checks": {},
    "failure_vectors": [],
    "recommended_actions": [],
    "overall_status": "UNKNOWN"
}

def check(name):
    """Decorator / context for structured check reporting"""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = fn(*args, **kwargs)
                REPORT["checks"][name] = {
                    "status": "PASS",
                    "duration_ms": round((time.time() - start) * 1000),
                    "detail": result if isinstance(result, str) else str(result)
                }
                print(f"  ✓ {name}: PASS")
                return result
            except Exception as e:
                REPORT["checks"][name] = {
                    "status": "FAIL",
                    "duration_ms": round((time.time() - start) * 1000),
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                REPORT["failure_vectors"].append(name)
                print(f"  ✗ {name}: FAIL — {e}")
                return None
        return wrapper
    return decorator


# ─── CHECK 1: MANIFEST FILE EXISTS ───────────────────────────
@check("manifest_file_exists")
def check_manifest_exists():
    paths = [
        Path("data/stix/feed_manifest.json"),
        Path("data/feed_manifest.json"),
        Path("feed_manifest.json"),
    ]
    for p in paths:
        if p.exists():
            size = p.stat().st_size
            return f"Found at {p} ({size} bytes)"
    raise FileNotFoundError(f"feed_manifest.json not found in any expected location: {[str(p) for p in paths]}")


# ─── CHECK 2: MANIFEST IS VALID JSON ─────────────────────────
@check("manifest_valid_json")
def check_manifest_json():
    paths = [
        Path("data/stix/feed_manifest.json"),
        Path("data/feed_manifest.json"),
    ]
    for p in paths:
        if p.exists():
            with open(p) as f:
                data = json.load(f)
            advisories = data if isinstance(data, list) else data.get("advisories", [])
            return f"{len(advisories)} advisories parsed"
    raise FileNotFoundError("No manifest found to parse")


# ─── CHECK 3: MANIFEST HAS DATA ──────────────────────────────
@check("manifest_has_advisories")
def check_manifest_nonempty():
    for p in [Path("data/stix/feed_manifest.json"), Path("data/feed_manifest.json")]:
        if p.exists():
            with open(p) as f:
                data = json.load(f)
            advisories = data if isinstance(data, list) else data.get("advisories", [])
            if len(advisories) == 0:
                raise ValueError("Manifest is empty — pipeline ran but produced no intel (feed fetch failure)")
            return f"{len(advisories)} advisories present"
    raise FileNotFoundError("No manifest file found")


# ─── CHECK 4: MANIFEST SCHEMA FIELDS ─────────────────────────
@check("manifest_schema_v46_compatible")
def check_manifest_schema():
    for p in [Path("data/stix/feed_manifest.json"), Path("data/feed_manifest.json")]:
        if p.exists():
            with open(p) as f:
                data = json.load(f)
            advisories = data if isinstance(data, list) else data.get("advisories", [])
            if not advisories:
                return "Empty manifest — schema check skipped"

            entry = advisories[0]
            dashboard_required = ["title", "timestamp"]
            missing = [f for f in dashboard_required if f not in entry]
            all_keys = list(entry.keys())

            if missing:
                raise ValueError(f"Missing required dashboard fields: {missing}. Available: {all_keys}")

            return f"Schema OK. Fields: {all_keys[:10]}{'...' if len(all_keys) > 10 else ''}"
    raise FileNotFoundError("No manifest found for schema check")


# ─── CHECK 5: GITHUB PAGES DATA ENDPOINT ─────────────────────
@check("github_pages_endpoint_reachable")
def check_github_pages():
    urls = [
        "https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/data/stix/feed_manifest.json",
        "https://cdn.jsdelivr.net/gh/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM@main/data/stix/feed_manifest.json",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CDB-Diagnostic/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content_length = len(resp.read())
                if content_length > 100:
                    return f"Reachable: {url} ({content_length} bytes)"
                else:
                    raise ValueError(f"Response too small ({content_length} bytes) — likely empty file")
        except Exception as e:
            continue
    raise ConnectionError("All remote endpoints unreachable or returning empty data")


# ─── CHECK 6: SENTINEL BLOGGER IMPORTS ───────────────────────
@check("sentinel_blogger_importable")
def check_agent_imports():
    sys.path.insert(0, str(Path.cwd()))
    errors = []
    modules = [
        "agent.sentinel_blogger",
        "agent.config",
        "agent.enricher",
    ]
    available = []
    for m in modules:
        try:
            __import__(m)
            available.append(m)
        except ImportError as e:
            errors.append(f"{m}: {e}")
    if errors:
        raise ImportError(f"Import failures: {'; '.join(errors)}")
    return f"All importable: {available}"


# ─── CHECK 7: REQUIRED ENV SECRETS ───────────────────────────
@check("required_secrets_present")
def check_secrets():
    required = ["BLOG_ID", "REFRESH_TOKEN", "CLIENT_ID", "CLIENT_SECRET"]
    optional = ["VT_API_KEY", "DISCORD_WEBHOOK", "SLACK_WEBHOOK"]

    missing_required = [k for k in required if not os.environ.get(k)]
    missing_optional = [k for k in optional if not os.environ.get(k)]

    if missing_required:
        raise EnvironmentError(f"Missing REQUIRED secrets: {missing_required}")

    msg = "All required secrets present"
    if missing_optional:
        msg += f" (optional missing: {missing_optional})"
    return msg


# ─── CHECK 8: index.html DATA FETCH URL ──────────────────────
@check("index_html_fetch_url_valid")
def check_index_html_fetch():
    index_path = Path("index.html")
    if not index_path.exists():
        raise FileNotFoundError("index.html not found")

    content = index_path.read_text(encoding="utf-8", errors="ignore")

    # Look for fetch calls to the manifest
    import re
    fetch_patterns = re.findall(r"fetch\(['\"`]([^'\"`,]+feed_manifest[^'\"`,]*)['\"`]", content)
    url_patterns = re.findall(r"(https?://[^\s'\"`,]+feed_manifest[^\s'\"`,]*)", content)
    const_patterns = re.findall(r"(?:MANIFEST_URL|manifest_url|manifestUrl)\s*=\s*['\"`]([^'\"`,]+)['\"`]", content)

    found = fetch_patterns + url_patterns + const_patterns

    if not found:
        raise ValueError("No feed_manifest.json reference found in index.html — data fetch wiring missing")

    return f"Found {len(found)} manifest references: {found[:3]}"


# ─── GENERATE REPORT ─────────────────────────────────────────
def generate_recommendations():
    vectors = REPORT["failure_vectors"]
    recs = []

    if "manifest_file_exists" in vectors:
        recs.append("ACTION 1 [CRITICAL]: feed_manifest.json missing — run pipeline: python -m agent.sentinel_blogger")

    if "manifest_has_advisories" in vectors:
        recs.append("ACTION 2 [HIGH]: Manifest empty — check RSS feeds are accessible, verify API keys")

    if "manifest_schema_v46_compatible" in vectors:
        recs.append("ACTION 3 [HIGH]: Schema mismatch — update index.html JS parser for v46 fields")

    if "github_pages_endpoint_reachable" in vectors:
        recs.append("ACTION 4 [HIGH]: Remote endpoint unreachable — check GitHub Pages deployment, use jsDelivr CDN fallback")

    if "sentinel_blogger_importable" in vectors:
        recs.append("ACTION 5 [CRITICAL]: Agent import failure — fix Python dependencies: pip install -r requirements.txt")

    if "required_secrets_present" in vectors:
        recs.append("ACTION 6 [CRITICAL]: Missing GitHub Secrets — add BLOG_ID, REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET in repo Settings → Secrets")

    if "index_html_fetch_url_valid" in vectors:
        recs.append("ACTION 7 [HIGH]: index.html has no manifest fetch wiring — apply DATA_FETCH_ENGINE_PATCH.js")

    if not vectors:
        recs.append("All checks PASSED — issue may be intermittent or browser-side. Hard refresh (Ctrl+Shift+R) and check browser console.")

    REPORT["recommended_actions"] = recs


def main():
    print("\n" + "="*60)
    print("  SENTINEL APEX v46.0 — P0 DIAGNOSTIC")
    print("="*60)
    print(f"  Run at: {REPORT['run_at']}")
    print()

    print("[1/8] Manifest file presence...")
    check_manifest_exists()

    print("[2/8] Manifest JSON validity...")
    check_manifest_json()

    print("[3/8] Manifest data presence...")
    check_manifest_nonempty()

    print("[4/8] Schema v46 compatibility...")
    check_manifest_schema()

    print("[5/8] Remote endpoint reachability...")
    check_github_pages()

    print("[6/8] Agent module imports...")
    check_agent_imports()

    print("[7/8] Environment secrets...")
    check_secrets()

    print("[8/8] index.html fetch wiring...")
    check_index_html_fetch()

    generate_recommendations()

    failed = len(REPORT["failure_vectors"])
    total = len(REPORT["checks"])
    passed = total - failed

    REPORT["overall_status"] = "HEALTHY" if failed == 0 else f"DEGRADED ({failed} failures)"

    print()
    print("="*60)
    print(f"  RESULT: {REPORT['overall_status']}")
    print(f"  PASS: {passed}/{total}  |  FAIL: {failed}/{total}")
    print()

    if REPORT["recommended_actions"]:
        print("  RECOMMENDED ACTIONS:")
        for rec in REPORT["recommended_actions"]:
            print(f"    → {rec}")
    print("="*60 + "\n")

    # Write JSON report
    report_path = Path("data/p0_diagnostic_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(REPORT, f, indent=2)
    print(f"  Full report: {report_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
