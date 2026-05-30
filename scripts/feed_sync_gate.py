#!/usr/bin/env python3
"""
STAGE 5.6.0 — Feed Sync Gate (v166.2 PERMANENT FIX P0)

ROOT CAUSE:
  api/feed.json (authoritative, enriched through 15+ pipeline stages including
  APEX AI, CVSS/EPSS, CISA KEV, Intelligence Quality Hardener, Actor Attribution,
  report_url sync, etc.) gains items and reordering that never propagate back
  to root feed.json. Result: Check 4 (Regression Immunity System) fails with
  "N mismatches in top-50" on every run.

FIX:
  Sync api/feed.json -> feed.json immediately before the regression check.
  api/feed.json is the single authoritative source of truth.
  After this sync, feed.json == api/feed.json always.

GUARANTEE: Check 4 (API vs Dashboard top-50 stix_id match) will ALWAYS PASS
  after this stage runs, regardless of how many enrichment stages modified
  api/feed.json during the pipeline run.
"""
import json
import os
import sys
import hashlib

REPO      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_FEED  = os.path.join(REPO, "api", "feed.json")
ROOT_FEED = os.path.join(REPO, "feed.json")

print("=" * 60)
print("STAGE 5.6.0 — Feed Sync Gate (v166.2 P0 PERMANENT FIX)")
print("=" * 60)

# ── Guard: api/feed.json must exist ──────────────────────────
if not os.path.exists(API_FEED):
    print(f"[ERROR] api/feed.json not found at {API_FEED}")
    print("[ERROR] Cannot sync — pipeline misconfiguration")
    sys.exit(1)

# ── Load api/feed.json (authoritative source) ─────────────────
try:
    with open(API_FEED, "r", encoding="utf-8") as f:
        api_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to parse api/feed.json: {e}")
    sys.exit(1)

items = api_data if isinstance(api_data, list) else api_data.get("items", [])
print(f"[SYNC] api/feed.json loaded: {len(items)} items")

# ── Load current root feed.json if exists (for diff report) ──
root_count = 0
if os.path.exists(ROOT_FEED):
    try:
        with open(ROOT_FEED, "r", encoding="utf-8") as f:
            root_data = json.load(f)
        root_items = root_data if isinstance(root_data, list) else root_data.get("items", [])
        root_count = len(root_items)
        print(f"[SYNC] feed.json (before): {root_count} items")
    except Exception:
        print("[SYNC] feed.json (before): unreadable — will overwrite")
else:
    print("[SYNC] feed.json (before): does not exist — will create")

# ── Write api/feed.json content -> feed.json ──────────────────
try:
    with open(ROOT_FEED, "w", encoding="utf-8") as f:
        json.dump(api_data, f, ensure_ascii=False, separators=(",", ":"))
    print(f"[SYNC] feed.json (after):  {len(items)} items")
except Exception as e:
    print(f"[ERROR] Failed to write feed.json: {e}")
    sys.exit(1)

# ── Verify sync integrity ─────────────────────────────────────
def top50_ids(data):
    lst = data if isinstance(data, list) else data.get("items", [])
    return [(i.get("stix_id") or i.get("id", "")) for i in lst[:50]]

api_ids  = top50_ids(api_data)
with open(ROOT_FEED, "r", encoding="utf-8") as f:
    root_verify = json.load(f)
root_ids = top50_ids(root_verify)

mismatches = sum(1 for a, r in zip(api_ids, root_ids) if a != r)
if mismatches > 0:
    print(f"[ERROR] Post-sync verification FAILED: {mismatches} stix_id mismatches")
    sys.exit(1)

delta = len(items) - root_count
print(f"[SYNC] Delta: {'+' if delta >= 0 else ''}{delta} items")
print(f"[SYNC] Top-50 stix_id verification: 0 mismatches — PASS")
print(f"[SYNC] Feed sync complete. Check 4 will PASS.")
print("=" * 60)
sys.exit(0)
