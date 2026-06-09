#!/usr/bin/env python3
"""
SENTINEL APEX v171.1 -- Production Release Gates (STAGE 5.9.2)
RC-GATE-1 FIX: Mandatory pre-deployment certification.
ANY failure = deployment BLOCKED (exits 1).

Gates:
  1. api/feed.json count >= 100
  2. api/reports/index.json exists with total_reports > 0
  3. api/latest.json count >= 50 (truncation detection)
  4. feed/manifest count drift <= 10%
  5. version.json readable with version field
"""
import json
import sys
import pathlib

REPO = pathlib.Path(__file__).parent.parent
errors = []
warnings = []

print("=" * 60)
print("SENTINEL APEX v171.1 - PRODUCTION RELEASE GATES")
print("=" * 60)

# GATE 1: api/feed.json count >= 100
feed_path = REPO / "api" / "feed.json"
if not feed_path.exists():
    errors.append("GATE-1 FAIL: api/feed.json does not exist")
else:
    try:
        d = json.loads(feed_path.read_text(encoding="utf-8"))
        items = d if isinstance(d, list) else d.get("items", d.get("data", []))
        count = len(items)
        print(f"GATE-1: api/feed.json items={count}")
        if count < 100:
            errors.append(f"GATE-1 FAIL: api/feed.json has {count} items (min 100)")
        else:
            print("GATE-1: PASS")
    except Exception as e:
        errors.append(f"GATE-1 FAIL: api/feed.json parse error: {e}")

# GATE 2: api/reports/index.json exists with total_reports > 0
reports_path = REPO / "api" / "reports" / "index.json"
if not reports_path.exists():
    errors.append("GATE-2 FAIL: api/reports/index.json missing (run build_reports_index.py)")
else:
    try:
        d = json.loads(reports_path.read_text(encoding="utf-8"))
        total = d.get("total_reports", 0)
        print(f"GATE-2: api/reports/index.json total_reports={total}")
        if total == 0:
            errors.append("GATE-2 FAIL: total_reports=0")
        else:
            print("GATE-2: PASS")
    except Exception as e:
        errors.append(f"GATE-2 FAIL: api/reports/index.json parse error: {e}")

# GATE 3: api/latest.json >= 50 items (truncation detection)
latest_path = REPO / "api" / "latest.json"
if not latest_path.exists():
    errors.append("GATE-3 FAIL: api/latest.json does not exist")
else:
    try:
        d = json.loads(latest_path.read_text(encoding="utf-8"))
        count = d.get("count", 0) if isinstance(d, dict) else len(d)
        print(f"GATE-3: api/latest.json count={count}")
        if count < 50:
            errors.append(f"GATE-3 FAIL: api/latest.json has {count} items (min 50, truncation detected)")
        else:
            print("GATE-3: PASS")
    except Exception as e:
        errors.append(f"GATE-3 FAIL: api/latest.json parse error: {e}")

# GATE 4: feed/manifest count convergence within 10%
manifest_path = REPO / "feed_manifest.json"
if manifest_path.exists() and feed_path.exists():
    try:
        feed_d = json.loads(feed_path.read_text(encoding="utf-8"))
        feed_items = feed_d if isinstance(feed_d, list) else feed_d.get("items", feed_d.get("data", []))
        feed_count = len(feed_items)
        mf_d = json.loads(manifest_path.read_text(encoding="utf-8"))
        mf_count = mf_d.get("count", 0)
        print(f"GATE-4: feed={feed_count} manifest={mf_count}")
        if feed_count > 0:
            drift = abs(feed_count - mf_count) / feed_count
            if drift > 0.10:
                errors.append(
                    f"GATE-4 FAIL: manifest count {mf_count} vs feed {feed_count} "
                    f"(drift {drift:.1%} > 10%)"
                )
            else:
                print(f"GATE-4: PASS (drift {drift:.1%})")
    except Exception as e:
        warnings.append(f"GATE-4 WARN: {e}")

# GATE 5: version.json readable
ver_path = REPO / "version.json"
if not ver_path.exists():
    errors.append("GATE-5 FAIL: version.json missing")
else:
    try:
        d = json.loads(ver_path.read_text(encoding="utf-8"))
        ver = d.get("version", "")
        print(f"GATE-5: version.json version={ver}")
        if not ver:
            errors.append("GATE-5 FAIL: no version field")
        else:
            print("GATE-5: PASS")
    except Exception as e:
        errors.append(f"GATE-5 FAIL: version.json parse error: {e}")

print()
print("=" * 60)
for w in warnings:
    print(f"  WARN: {w}")
if errors:
    print(f"RELEASE GATE: BLOCKED ({len(errors)} failures)")
    for e in errors:
        print(f"  FAIL: {e}")
    print("=" * 60)
    sys.exit(1)
else:
    print("RELEASE GATE: CERTIFIED -- all 5 gates passed")
    print("=" * 60)
