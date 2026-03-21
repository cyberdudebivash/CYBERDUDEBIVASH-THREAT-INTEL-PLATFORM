#!/usr/bin/env python3
"""
SENTINEL APEX v72.1 — PRE-DEPLOY INTEGRITY GATE
==================================================
MANDATORY check before EVERY gh-pages deploy.
If ANY check fails → exit(1) → deployment BLOCKED.

Prevents:
  - Git merge conflict markers in JavaScript
  - Duplicate EMBEDDED_INTEL declarations (fatal SyntaxError)
  - Empty/corrupt EMBEDDED_INTEL data
  - JavaScript brace imbalance (frozen dashboard)

This is the PERMANENT LOCK against dashboard death.
"""

import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(REPO_ROOT, "index.html")


def main():
    print("=" * 60)
    print("  SENTINEL APEX — PRE-DEPLOY INTEGRITY GATE")
    print("=" * 60)

    if not os.path.exists(INDEX_HTML):
        print("  FATAL: index.html not found")
        sys.exit(1)

    with open(INDEX_HTML, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    print(f"  File: {len(content):,} bytes")
    failed = False

    # ── CHECK 1: No git conflict markers in <script> blocks ──
    script_text = ""
    for m in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        script_text += m.group(1)

    for marker in ["<<<<<<<", ">>>>>>>"]:
        if marker in script_text:
            print(f"  FATAL: Git conflict marker '{marker}' in <script>")
            failed = True

    if not failed:
        print("  [1/5] No conflict markers in JavaScript")

    # ── CHECK 2: Exactly ONE EMBEDDED_INTEL declaration ──
    ei_count = len(re.findall(r"(?:const|let|var)\s+EMBEDDED_INTEL\s*=", content))
    if ei_count == 0:
        print("  FATAL: EMBEDDED_INTEL declaration missing")
        failed = True
    elif ei_count > 1:
        print(f"  FATAL: {ei_count} EMBEDDED_INTEL declarations (causes SyntaxError)")
        failed = True
    else:
        print("  [2/5] Single EMBEDDED_INTEL declaration")

    # ── CHECK 3: EMBEDDED_INTEL has valid JSON with >= 5 items ──
    ei_match = re.search(r"const\s+EMBEDDED_INTEL\s*=\s*(\[[\s\S]*?\])\s*;", content)
    if ei_match:
        try:
            items = json.loads(ei_match.group(1))
            if len(items) < 5:
                print(f"  FATAL: EMBEDDED_INTEL has {len(items)} items (min: 5)")
                failed = True
            else:
                print(f"  [3/5] EMBEDDED_INTEL: {len(items)} items OK")
        except json.JSONDecodeError as e:
            print(f"  FATAL: EMBEDDED_INTEL JSON parse error: {e}")
            failed = True
    elif ei_count == 1:
        print("  FATAL: EMBEDDED_INTEL present but not parseable")
        failed = True

    # ── CHECK 4: JavaScript brace balance ──
    brace_ok = True
    for m in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        block = m.group(1)
        if len(block) < 100:
            continue
        depth = 0
        in_str = None
        prev = ""
        for ch in block:
            if in_str:
                if ch == in_str and prev != "\\":
                    in_str = None
            else:
                if ch in ("'", '"', "`"):
                    in_str = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth < 0:
                        brace_ok = False
                        break
            prev = ch
        if depth != 0:
            brace_ok = False
    if not brace_ok:
        print("  FATAL: JavaScript brace imbalance")
        failed = True
    else:
        print("  [4/5] JavaScript braces balanced")

    # ── CHECK 5: Critical boot functions exist ──
    missing = []
    for func in ["bootFromEmbeddedCache", "computeMetrics", "renderCards"]:
        if f"function {func}" not in content:
            missing.append(func)
    if missing:
        print(f"  FATAL: Missing functions: {', '.join(missing)}")
        failed = True
    else:
        print("  [5/5] Critical boot functions present")

    # ── VERDICT ──
    print()
    if failed:
        print("  ████ DEPLOYMENT BLOCKED ████")
        print("  Fix the errors above, commit, and re-run.")
        print("=" * 60)
        sys.exit(1)
    else:
        print("  DEPLOY AUTHORIZED")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
