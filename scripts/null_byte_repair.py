#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX -- Null-Byte Auto-Repair
=======================================
Strips null-byte padding from all critical JSON files before the output
validation gate runs.  Null bytes are a write-path artefact (pre-allocated
buffer not truncated) and must never reach STAGE 3.9 as a hard-fail.

Scans: api/feed.json, feed.json, manifest.json, data/stix/feed_manifest.json,
       api/v1/intel/ai_summary.json, api/v1/intel/latest.json, api/v1/intel/apex.json,
       data/quality/*.json, config/*.json, api/v1/intel/*.json

Exit code:
  0  -- all files clean OR repaired successfully
  1  -- one or more files could not be repaired (still invalid JSON after strip)
"""

import json
import os
import glob
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = [
    "api/feed.json",
    "feed.json",
    "manifest.json",
    "data/stix/feed_manifest.json",
    # AI output files (generate-and-sync + ai_brain_publisher outputs)
    "api/v1/intel/ai_summary.json",
    "api/v1/intel/latest.json",
    "api/v1/intel/apex.json",
]

# Also scan quality, config, and all api/v1/intel dirs
TARGETS += glob.glob(os.path.join(REPO_ROOT, "data", "quality", "*.json"))
TARGETS += glob.glob(os.path.join(REPO_ROOT, "config", "*.json"))
TARGETS += glob.glob(os.path.join(REPO_ROOT, "api", "v1", "intel", "*.json"))

fixed = 0
failed = 0
clean = 0

for rel_or_abs in TARGETS:
    path = rel_or_abs if os.path.isabs(rel_or_abs) else os.path.join(REPO_ROOT, rel_or_abs)
    if not os.path.exists(path):
        continue

    with open(path, "rb") as f:
        raw = f.read()

    if b"\x00" not in raw:
        clean += 1
        continue

    stripped = raw.rstrip(b"\x00")
    try:
        json.loads(stripped.decode("utf-8"))
        with open(path, "wb") as f:
            f.write(stripped)
        removed = len(raw) - len(stripped)
        print(f"[null-repair] FIXED: {os.path.relpath(path, REPO_ROOT)} "
              f"({removed:,} null bytes removed)")
        fixed += 1
    except Exception as e:
        print(f"[null-repair] WARN: {os.path.relpath(path, REPO_ROOT)} "
              f"still invalid after strip: {e}", file=sys.stderr)
        failed += 1

if fixed == 0 and failed == 0:
    print(f"[null-repair] All {clean} scanned JSON files are clean -- no null bytes found")
else:
    print(f"[null-repair] Summary: {fixed} fixed | {failed} failed | {clean} already clean")

sys.exit(1 if failed > 0 else 0)
