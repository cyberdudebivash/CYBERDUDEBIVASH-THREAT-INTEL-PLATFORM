#!/usr/bin/env python3
"""
SENTINEL APEX v27.0 — Version Update Script
=============================================
Updates index.html to v27.0 version strings.

Usage:
    python apply_v27_version.py

This script will:
1. Replace v24.0/v26.0 → v27.0 in index.html
2. Update ENGINE version badge
3. Backup original file
"""

import os
import re
import shutil
from datetime import datetime

INDEX_FILE = "index.html"
BACKUP_SUFFIX = f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"

VERSION_REPLACEMENTS = [
    # Title tag
    (r'v24\.0 ULTRA', 'v27.0 ULTRA'),
    (r'v26\.0 ULTRA', 'v27.0 ULTRA'),
    
    # Meta descriptions
    (r'Sentinel APEX v24\.0', 'Sentinel APEX v27.0'),
    (r'Sentinel APEX v26\.0', 'Sentinel APEX v27.0'),
    
    # Header display (case insensitive)
    (r'V24\.0 ULTRA', 'V27.0 ULTRA'),
    (r'V26\.0 ULTRA', 'V27.0 ULTRA'),
    
    # Engine badge
    (r'APEX ULTRA v24\.0', 'APEX ULTRA v27.0'),
    (r'APEX ULTRA v26\.0', 'APEX ULTRA v27.0'),
    
    # Generic version strings
    (r'version: "24\.0"', 'version: "27.0"'),
    (r'version: "26\.0"', 'version: "27.0"'),
    (r'"v24\.0"', '"v27.0"'),
    (r'"v26\.0"', '"v27.0"'),
]


def apply_version_update():
    """Apply version updates to index.html"""
    
    if not os.path.exists(INDEX_FILE):
        print(f"❌ {INDEX_FILE} not found in current directory")
        return False
    
    # Create backup
    backup_file = INDEX_FILE + BACKUP_SUFFIX
    shutil.copy2(INDEX_FILE, backup_file)
    print(f"✅ Backup created: {backup_file}")
    
    # Read file
    with open(INDEX_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Apply replacements
    for pattern, replacement in VERSION_REPLACEMENTS:
        content, count = re.subn(pattern, replacement, content, flags=re.IGNORECASE)
        if count > 0:
            print(f"  • Replaced '{pattern}' → '{replacement}' ({count} occurrences)")
    
    # Check if changes were made
    if content == original_content:
        print("⚠️ No changes made - version may already be updated")
        return True
    
    # Write updated file
    with open(INDEX_FILE, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ {INDEX_FILE} updated to v27.0")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("SENTINEL APEX v27.0 — Version Update")
    print("=" * 60)
    
    success = apply_version_update()
    
    if success:
        print("\n✅ Version update complete!")
        print("\nNext steps:")
        print("  1. Review changes in index.html")
        print("  2. Commit: git add . && git commit -m 'Update to v27.0'")
        print("  3. Push: git push")
    else:
        print("\n❌ Version update failed")
