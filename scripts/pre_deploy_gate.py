#!/usr/bin/env python3
"""
SENTINEL APEX v72.1 — Conflict Marker Guard
=============================================
MANDATORY pre-deploy check. Blocks deployment if index.html
contains git merge conflict markers or duplicate EMBEDDED_INTEL.

This is the ONLY check needed to prevent the dashboard death bug.
If this passes, the dashboard will render.

EXIT 0 = safe to deploy
EXIT 1 = BLOCKED — conflict markers found
"""
import re, sys, json, os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(REPO_ROOT, "index.html")

def main():
    print("=" * 60)
    print("  SENTINEL APEX — PRE-DEPLOY CONFLICT GUARD")
    print("=" * 60)

    if not os.path.exists(INDEX_HTML):
        print(f"  FATAL: {INDEX_HTML} not found")
        sys.exit(1)

    with open(INDEX_HTML, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    print(f"  File: {len(content):,} bytes")
    failed = False

    # CHECK 1: Git conflict markers inside <script> blocks
    script_content = ""
    for m in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        script_content += m.group(1)

    for marker in ["<<<<<<<", ">>>>>>>", "======="]:
        if marker in script_content:
            print(f"  ❌ FATAL: Git conflict marker '{marker}' found inside <script>")
            failed = True

    if not failed:
        print(f"  ✅ No conflict markers in JavaScript")

    # CHECK 2: Exactly ONE EMBEDDED_INTEL declaration
    ei_count = len(re.findall(r"(?:const|let|var)\s+EMBEDDED_INTEL\s*=", content))
    if ei_count == 0:
        print(f"  ❌ FATAL: EMBEDDED_INTEL not found")
        failed = True
    elif ei_count > 1:
        print(f"  ❌ FATAL: {ei_count} EMBEDDED_INTEL declarations (must be exactly 1)")
        failed = True
    else:
        print(f"  ✅ Exactly 1 EMBEDDED_INTEL declaration")

    # CHECK 3: EMBEDDED_INTEL has valid JSON with >= 5 items
    ei_match = re.search(r"const\s+EMBEDDED_INTEL\s*=\s*(\[[\s\S]*?\])\s*;", content)
    if ei_match:
        try:
            items = json.loads(ei_match.group(1))
            if len(items) < 5:
                print(f"  ❌ FATAL: EMBEDDED_INTEL has only {len(items)} items (min: 5)")
                failed = True
            else:
                print(f"  ✅ EMBEDDED_INTEL: {len(items)} items, valid JSON")
        except json.JSONDecodeError as e:
            print(f"  ❌ FATAL: EMBEDDED_INTEL JSON parse error: {e}")
            failed = True
    elif ei_count == 1:
        print(f"  ❌ FATAL: EMBEDDED_INTEL found but array not extractable")
        failed = True

    # CHECK 4: Brace balance
    for block_match in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        block = block_match.group(1)
        if len(block) < 100: continue
        depth = 0; in_str = None; prev = ""
        ok = True
        for ch in block:
            if in_str:
                if ch == in_str and prev != "\\": in_str = None
            else:
                if ch in ("'", '"', '`'): in_str = ch
                elif ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth < 0: ok = False; break
            prev = ch
        if not ok or depth != 0:
            print(f"  ❌ FATAL: JavaScript brace imbalance detected")
            failed = True
            break
    else:
        print(f"  ✅ JavaScript braces balanced")

    print()
    if failed:
        print("  ████ DEPLOYMENT BLOCKED — FIX ABOVE ERRORS ████")
        print("=" * 60)
        sys.exit(1)
    else:
        print("  ✅ ALL CHECKS PASSED — DEPLOY AUTHORIZED")
        print("=" * 60)
        sys.exit(0)

if __name__ == "__main__":
    main()
