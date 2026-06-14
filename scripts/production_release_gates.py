#!/usr/bin/env python3
"""
SENTINEL APEX v171.4 -- Production Release Gates (STAGE 5.9.2)
RC-GATE-3 FIX v171.4: Corrected GATE-4 semantics for accumulating latest.json.
  - GATE-4 rebalanced: api/latest.json accumulates historical intel across runs
    while api/feed.json holds the current incremental batch only. latest >= feed
    is always expected and PASSES. Only feed >> latest (>50%) is a failure signal
    indicating api/latest.json lost accumulated data.
ANY failure = deployment BLOCKED (exits 1).

Gates:
  1. api/feed.json exists with count >= 5
  2. api/reports/index.json exists with total_reports > 0
  3. api/latest.json exists with count >= 5
  4. api/latest.json >= api/feed.json (accumulated) OR feed-to-latest drift <= 50%
  5. version.json readable with version field
"""
import json
import sys
import pathlib

REPO = pathlib.Path(__file__).parent.parent
errors = []
warnings = []

print("=" * 60)
print("SENTINEL APEX v171.4 - PRODUCTION RELEASE GATES")
print("=" * 60)

# GATE 1: api/feed.json exists with count >= 5
# Note: api/feed.json is runtime-generated (gitignored); count varies by run (10-200).
# Threshold=5 catches truly empty/failed pipeline runs without false-positives
# on normal incremental runs.
feed_path = REPO / "api" / "feed.json"
feed_count = 0
if not feed_path.exists():
    errors.append("GATE-1 FAIL: api/feed.json does not exist (pipeline did not generate data)")
else:
    try:
        d = json.loads(feed_path.read_text(encoding="utf-8"))
        items = d if isinstance(d, list) else d.get("items", d.get("data", []))
        feed_count = len(items)
        print(f"GATE-1: api/feed.json items={feed_count}")
        if feed_count < 5:
            errors.append(
                f"GATE-1 FAIL: api/feed.json has {feed_count} items (min 5 -- "
                "pipeline produced empty or near-empty feed)"
            )
        else:
            print("GATE-1: PASS")
    except Exception as e:
        errors.append(f"GATE-1 FAIL: api/feed.json parse error: {e}")

# GATE 2: api/reports/index.json exists with total_reports > 0
reports_path = REPO / "api" / "reports" / "index.json"
if not reports_path.exists():
    errors.append("GATE-2 FAIL: api/reports/index.json missing")
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

# GATE 3: api/latest.json exists with count >= 5
# Note: api/latest.json is regenerated each run; threshold=5 catches empty outputs.
latest_path = REPO / "api" / "latest.json"
latest_count = 0
if not latest_path.exists():
    errors.append("GATE-3 FAIL: api/latest.json does not exist")
else:
    try:
        d = json.loads(latest_path.read_text(encoding="utf-8"))
        latest_count = d.get("count", 0) if isinstance(d, dict) else len(d)
        print(f"GATE-3: api/latest.json count={latest_count}")
        if latest_count < 5:
            errors.append(
                f"GATE-3 FAIL: api/latest.json has {latest_count} items (min 5 -- "
                "pipeline produced empty or near-empty latest endpoint)"
            )
        else:
            print("GATE-3: PASS")
    except Exception as e:
        errors.append(f"GATE-3 FAIL: api/latest.json parse error: {e}")

# GATE 4: API endpoint consistency check
# RC-GATE-3 FIX v171.4: api/latest.json accumulates historical intelligence across runs
# (managed by generate-and-sync), while api/feed.json holds the current incremental batch
# (~50 items per sentinel-blogger run). latest.json is intentionally larger than feed.json.
# The previous symmetric drift check (abs difference / max) always fired because
# accumulated latest (200-400 items) >> current batch (10-100 items) = >50% drift.
# CORRECT SEMANTICS:
#   - latest >= feed: PASS (normal -- latest accumulates more than current batch)
#   - feed >> latest by >50%: FAIL (abnormal -- latest.json lost accumulated data)
if feed_count > 0 and latest_count > 0:
    if latest_count >= feed_count:
        print(f"GATE-4: feed={feed_count} latest={latest_count} (latest >= feed -- accumulated feed normal)")
        print("GATE-4: PASS")
    else:
        drift = (feed_count - latest_count) / feed_count
        print(f"GATE-4: feed={feed_count} latest={latest_count} drift={drift:.1%} (feed > latest)")
        if drift > 0.50:
            errors.append(
                f"GATE-4 FAIL: api/feed.json ({feed_count}) >> api/latest.json ({latest_count}) "
                f"drift {drift:.1%} > 50% -- api/latest.json may have lost accumulated intelligence data"
            )
        else:
            print(f"GATE-4: PASS (drift {drift:.1%})")
elif feed_count == 0 and latest_count == 0:
    warnings.append("GATE-4 SKIP: both feed and latest empty (covered by GATE-1 and GATE-3)")
else:
    warnings.append(f"GATE-4 WARN: feed={feed_count} latest={latest_count} -- one endpoint empty")

# GATE 5: version.json readable with version field
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
