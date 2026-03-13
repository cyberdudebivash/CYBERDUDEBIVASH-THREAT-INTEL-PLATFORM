#!/usr/bin/env python3
"""
SENTINEL APEX v26.0 - Automated Fix Script
============================================
Fixes the index.html timestamp display bug automatically.

Usage:
    python apply_v26_fix.py

This script:
1. Backs up index.html
2. Fixes the timestamp bug (line ~2285)
3. Updates version strings to v26.0
"""

import re
import os
import sys
import shutil
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if not REPO_ROOT:
    REPO_ROOT = "."

INDEX_PATH = os.path.join(REPO_ROOT, "index.html")
BACKUP_PATH = os.path.join(REPO_ROOT, f"index.html.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}")


def fix_timestamp_bug(content: str) -> str:
    """Fix the timestamp display bug in index.html"""
    
    # Pattern: The buggy line that reads from the OLDEST entry
    buggy_pattern = r"const lastTs = data\.length \? timeSince\(data\[data\.length - 1\]\.timestamp \|\| data\[0\]\.timestamp\) : '—';"
    
    # Fixed code: Sort data and read from NEWEST entry (index 0)
    fixed_code = """// v26.0 FIX: Sort and read NEWEST entry (index 0) - manifest may not be pre-sorted
            let sortedData = [...data].sort((a, b) =>
                new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
            );
            const lastTs = sortedData.length ? timeSince(sortedData[0].timestamp) : '—';"""
    
    if re.search(buggy_pattern, content):
        content = re.sub(buggy_pattern, fixed_code, content)
        print("✓ Fixed: Timestamp display bug (line ~2285)")
        return content
    
    # Check if already fixed
    if "sortedData = [...data].sort" in content:
        print("✓ Already fixed: Timestamp display bug")
        return content
    
    print("⚠ Warning: Could not find buggy timestamp pattern to fix")
    return content


def update_version_strings(content: str) -> str:
    """Update version strings from v24/v25 to v26"""
    
    # Update title
    content = re.sub(
        r'Sentinel APEX v2[45]\.0',
        'Sentinel APEX v26.0',
        content
    )
    
    # Update meta description
    content = re.sub(
        r'APEX v2[45]\.0 ULTRA',
        'APEX v26.0 ULTRA',
        content
    )
    
    print("✓ Updated: Version strings to v26.0")
    return content


def main():
    print("=" * 60)
    print("  SENTINEL APEX v26.0 - Automated Fix Script")
    print("=" * 60)
    print()
    
    if not os.path.exists(INDEX_PATH):
        print(f"✗ Error: {INDEX_PATH} not found")
        print("  Run this script from the repository root")
        sys.exit(1)
    
    # Read current content
    with open(INDEX_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Backup
    shutil.copy2(INDEX_PATH, BACKUP_PATH)
    print(f"✓ Backup: {BACKUP_PATH}")
    
    # Apply fixes
    content = fix_timestamp_bug(content)
    content = update_version_strings(content)
    
    # Write fixed content
    with open(INDEX_PATH, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print()
    print("=" * 60)
    print("  v26.0 FIX APPLIED SUCCESSFULLY")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Review changes: git diff index.html")
    print("  2. Commit: git add index.html && git commit -m 'v26.0: Fix timestamp bug'")
    print("  3. Push: git push origin main")
    print()


if __name__ == "__main__":
    main()
