#!/usr/bin/env python3
"""
SENTINEL APEX — Dashboard Version Bump v46.0 → v54.0
Updates all version references in index.html while preserving all functionality.

Only modifies version string text — no structural HTML/JS/CSS changes.
"""

import re
import sys
import os

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "index.html")

# Patterns to replace (only version number strings, not code identifiers)
REPLACEMENTS = [
    # Title and meta tags
    ("Sentinel APEX v46.0", "Sentinel APEX v54.0"),
    ("APEX ULTRA v46.0", "APEX ULTRA v54.0"),
    # CSS/design system comments
    ("SENTINEL APEX ULTRA v46.0", "SENTINEL APEX ULTRA v54.0"),
    ("v46.0 APEX ULTRA", "v54.0 APEX ULTRA"),
    ("v46.0 ENHANCEMENTS", "v54.0 ENHANCEMENTS"),
    # HTML overlays and modals
    ("v46.0 ═══", "v54.0 ═══"),
    # Section headers in dashboard
    ("BUG HUNTER v46.0", "BUG HUNTER v54.0"),
    ("NEXUS INTELLIGENCE v46.0", "NEXUS INTELLIGENCE v54.0"),
    ("CORTEX · QUANTUM · SOVEREIGN", "CORTEX · QUANTUM · SOVEREIGN"),  # No version in this one
    ("Full-Stack AI Cybersecurity Ecosystem v46.0", "Full-Stack AI Cybersecurity Ecosystem v54.0"),
    ("GENESIS v46.0", "GENESIS v54.0"),
    # JS engine version references
    ("ENGINE: APEX ULTRA v46.0", "ENGINE: APEX ULTRA v54.0"),
]


def main():
    if not os.path.exists(TARGET):
        print(f"Target not found: {TARGET}")
        sys.exit(1)

    with open(TARGET, "r", encoding="utf-8") as f:
        content = f.read()

    original = content
    changes = 0

    for old, new in REPLACEMENTS:
        count = content.count(old)
        if count > 0:
            content = content.replace(old, new)
            changes += count
            print(f"  ✅ '{old}' → '{new}' ({count} occurrences)")

    if changes == 0:
        print("No v46.0 references found — may already be updated.")
        sys.exit(0)

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\n✅ Updated {changes} version references (v46.0 → v54.0)")
    print(f"   File: {TARGET}")
    print(f"   Size: {len(content)} bytes (was {len(original)} bytes)")


if __name__ == "__main__":
    main()
