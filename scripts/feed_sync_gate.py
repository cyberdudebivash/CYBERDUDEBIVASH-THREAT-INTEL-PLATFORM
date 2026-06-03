#!/usr/bin/env python3
"""
STAGE 5.6.0 -- Feed Sync Gate (v166.3 PERMANENT FIX P0)

ROOT CAUSE:
  api/feed.json (authoritative, enriched through 15+ pipeline stages) gains
  items and reordering that never propagate back to root feed.json.

FIX (v166.2):
  Sync api/feed.json -> feed.json immediately before the regression check.
  api/feed.json is the single authoritative source of truth.

v166.3 FIX -- Sort Order Regression Guard:
  Re-apply the canonical (ts_string, stix_id) DESC sort to api/feed.json and
  feed.json immediately before the regression immunity check.
  Root cause of recurring regression: field_preserving_merge.py (and other
  enrichment stages) wrote api/feed.json using a float-based sort key with no
  stix_id tie-breaking. When two items share the same timestamp the float sort
  leaves them in insertion order, which diverges from the string-based
  (ts_string, stix_id) key used by regression_immunity.py Check 6, causing
  exactly 1 out-of-order pair and a HARD FAIL.
  This stage is the last write point before Check 6 -- applying the canonical
  sort here is the definitive permanent fix.

GUARANTEE: Check 4 (API vs Dashboard top-50 stix_id match) -- ALWAYS PASS.
GUARANTEE: Check 6 (feed.json sorted published_at DESC) -- ALWAYS PASS.
"""
import json
import os
import pathlib
import sys

REPO      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_FEED  = os.path.join(REPO, "api", "feed.json")
ROOT_FEED = os.path.join(REPO, "feed.json")

print("=" * 60)
print("STAGE 5.6.0 -- Feed Sync Gate (v166.3 P0 PERMANENT FIX)")
print("=" * 60)


def canonical_sort_key(item):
    """Canonical sort key: (ts_string, stix_id) DESC.
    Matches regression_immunity.py Check 6 and run_pipeline.py exactly.
    String-based comparison avoids float precision issues; stix_id provides
    deterministic tie-breaking when timestamps are identical."""
    ts_val  = (item.get("published_at") or item.get("timestamp") or
               item.get("processed_at") or "")
    sid_val = (item.get("stix_id") or item.get("id") or "")
    return (ts_val, sid_val)


# -- Guard: api/feed.json must exist -------------------------------------------
if not os.path.exists(API_FEED):
    print("[ERROR] api/feed.json not found at " + API_FEED)
    print("[ERROR] Cannot sync -- pipeline misconfiguration")
    sys.exit(1)

# -- Load api/feed.json --------------------------------------------------------
try:
    with open(API_FEED, "r", encoding="utf-8") as fh:
        api_data = json.load(fh)
except Exception as exc:
    print("[ERROR] Failed to parse api/feed.json: " + str(exc))
    sys.exit(1)

items = api_data if isinstance(api_data, list) else api_data.get("items", [])
print("[SYNC] api/feed.json loaded: " + str(len(items)) + " items")

# -- v166.3: Apply canonical sort BEFORE writing feed.json ---------------------
items_sorted = sorted(items, key=canonical_sort_key, reverse=True)
if items_sorted != items:
    print("[SORT] Canonical re-sort applied (" + str(len(items_sorted)) + " items) -- upstream order corrected")
    try:
        api_tmp = pathlib.Path(API_FEED).with_suffix(".sync_sort.tmp")
        with open(str(api_tmp), "w", encoding="utf-8") as fh:
            json.dump(items_sorted, fh, ensure_ascii=False, indent=2)
        api_tmp.replace(pathlib.Path(API_FEED))
        api_data = items_sorted
        print("[SORT] api/feed.json saved in canonical order (" + str(len(items_sorted)) + " items)")
    except Exception as sort_exc:
        print("[WARN] Could not persist canonical sort to api/feed.json: " + str(sort_exc))
        api_data = items_sorted
else:
    print("[SORT] api/feed.json already in canonical order -- no change needed")
items = items_sorted

# -- Load current root feed.json (for diff report) -----------------------------
root_count = 0
if os.path.exists(ROOT_FEED):
    try:
        with open(ROOT_FEED, "r", encoding="utf-8") as fh:
            root_data = json.load(fh)
        root_items = root_data if isinstance(root_data, list) else root_data.get("items", [])
        root_count = len(root_items)
        print("[SYNC] feed.json (before): " + str(root_count) + " items")
    except Exception:
        print("[SYNC] feed.json (before): unreadable -- will overwrite")
else:
    print("[SYNC] feed.json (before): does not exist -- will create")

# -- Write canonical-sorted list -> feed.json ----------------------------------
try:
    with open(ROOT_FEED, "w", encoding="utf-8") as fh:
        json.dump(items, fh, ensure_ascii=False, separators=(",", ":"))
    print("[SYNC] feed.json (after):  " + str(len(items)) + " items")
except Exception as exc:
    print("[ERROR] Failed to write feed.json: " + str(exc))
    sys.exit(1)

# -- Verify: top-50 stix_id match ----------------------------------------------
def top50_ids(data):
    lst = data if isinstance(data, list) else data.get("items", [])
    return [(i.get("stix_id") or i.get("id", "")) for i in lst[:50]]

api_ids = top50_ids(api_data)
with open(ROOT_FEED, "r", encoding="utf-8") as fh:
    root_verify = json.load(fh)
root_ids = top50_ids(root_verify)
mismatches = sum(1 for a, r in zip(api_ids, root_ids) if a != r)
if mismatches > 0:
    print("[ERROR] Post-sync verification FAILED: " + str(mismatches) + " stix_id mismatches")
    sys.exit(1)

# -- Verify: sort order of written feed.json (mirrors regression_immunity Check 6) --
written = root_verify if isinstance(root_verify, list) else root_verify.get("items", [])
out_of_order = 0
for i in range(len(written) - 1):
    cur = canonical_sort_key(written[i])
    nxt = canonical_sort_key(written[i + 1])
    if cur != ("", "") and nxt != ("", "") and cur < nxt:
        out_of_order += 1
if out_of_order > 0:
    print("[ERROR] Sort order check FAILED: " + str(out_of_order) + " out-of-order pairs in feed.json")
    sys.exit(1)

delta = len(items) - root_count
sign  = "+" if delta >= 0 else ""
print("[SYNC] Delta: " + sign + str(delta) + " items")
print("[SYNC] Top-50 stix_id verification: 0 mismatches -- PASS")
print("[SORT] Sort order verification: 0 out-of-order pairs -- PASS")
print("[SYNC] Feed sync complete. Check 4 and Check 6 will PASS.")
print("=" * 60)
sys.exit(0)
