#!/usr/bin/env python3
"""
SENTINEL APEX v72.0 — Dashboard Sync Display Patcher
======================================================
P0 FIX: Patches index.html to prevent fetchPipelineSyncTime() from
overwriting fresh manifest-derived "Last Sync" with stale sync_marker.json.

ROOT CAUSE:
  1. computeMetrics() correctly sets m-last-sync = "1h ago" from EMBEDDED_INTEL
  2. fetchPipelineSyncTime() then fetches sync_marker.json (often stale)
  3. It BLINDLY overwrites m-last-sync = "21h ago" from stale sync_marker
  
FIX: Freshest-wins guard — only override if sync source is NEWER than manifest.

SAFE: Idempotent. Detects if already patched. Zero regression.
Run: python3 scripts/patch_sync_display.py
"""

import os
import re
import sys
import shutil
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(REPO_ROOT, "index.html")

# ─── The OLD pattern: fetchPipelineSyncTime that blindly overwrites ───
# We match the function signature + the blind overwrite pattern
OLD_PATTERN_BLIND_OVERWRITE = re.compile(
    r"(async\s+function\s+fetchPipelineSyncTime\s*\(\)\s*\{)"  # function start
    r"([\s\S]*?)"  # function body
    r"(if\s*\(syncTs\)\s*\{[\s\S]*?)"  # the if(syncTs) block
    r"(const\s+el\s*=\s*document\.getElementById\(['\"]m-last-sync['\"]\);?\s*\n?"
    r"\s*if\s*\(el\)\s*el\.textContent\s*=\s*timeSince\(syncTs\);)"  # the BLIND overwrite
    r"([\s\S]*?\}\s*catch\s*\(e\)\s*\{\s*console\.debug\(\s*\[?['\"]?\[?SYNC-MARKER\]?['\"]?\]?\s*,?\s*e\s*\)\s*;?\s*\})"  # rest + catch
)

# Signature that indicates the fix is already applied
ALREADY_PATCHED_MARKER = "v64.2 GUARD"
ALREADY_PATCHED_MARKER_2 = "v72.0 GUARD"
ALREADY_PATCHED_MARKER_3 = "manifestNewest"

# ─── The NEW replacement function ───
NEW_FUNCTION = '''        // v72.0 FIX: Freshest-wins sync time — only override m-last-sync if
        // sync_marker/status.json provides a NEWER timestamp than manifest data.
        // ROOT CAUSE: sync_marker.json was not updated by recent pipeline runs,
        // so fetchPipelineSyncTime() was overwriting the correct manifest-derived
        // "1h ago" with stale "21h ago" from sync_marker.
        async function fetchPipelineSyncTime() {
            try {
                // Compute the freshest timestamp already displayed from manifest data
                const manifestNewest = (typeof manifestData !== 'undefined' && Array.isArray(manifestData) && manifestData.length)
                    ? Math.max(...manifestData.filter(d => d.timestamp || d.published || d.published_date).map(d => new Date(d.timestamp || d.published || d.published_date).getTime()))
                    : 0;

                const SYNC_URLS = [
                    atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNL21haW4v') + 'data/sync_marker.json',
                    atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNL21haW4v') + 'data/status/status.json',
                ];
                for (const url of SYNC_URLS) {
                    try {
                        const r = await fetch(url, {cache: 'no-cache'});
                        if (!r.ok) continue;
                        const d = await r.json();
                        const syncTs = d.last_sync || d.generated_at || (d.components && d.components.pipeline && d.components.pipeline.last_run_at);
                        if (syncTs) {
                            const syncTime = new Date(syncTs).getTime();
                            // v72.0 GUARD: Only override if sync source is FRESHER than manifest
                            if (syncTime > manifestNewest) {
                                const el = document.getElementById('m-last-sync');
                                if (el) el.textContent = timeSince(syncTs);
                            }
                            return;
                        }
                    } catch(e) { continue; }
                }
            } catch(e) { console.debug('[SYNC-MARKER]', e); }
        }'''


def check_already_patched(content: str) -> bool:
    """Check if the freshest-wins guard is already in place."""
    return (ALREADY_PATCHED_MARKER in content or 
            ALREADY_PATCHED_MARKER_2 in content or
            ALREADY_PATCHED_MARKER_3 in content)


def find_and_replace_function(content: str) -> tuple:
    """Find fetchPipelineSyncTime and replace with guarded version.
    Returns (new_content, was_modified)."""
    
    # Strategy 1: Find the exact function block using regex
    # Match: "async function fetchPipelineSyncTime()" through end of function
    func_start_pattern = re.compile(
        r'(\s*)(//[^\n]*\n\s*)*'  # optional comments before
        r'async\s+function\s+fetchPipelineSyncTime\s*\(\)\s*\{'
    )
    
    match = func_start_pattern.search(content)
    if not match:
        return content, False
    
    func_start = match.start()
    indent = match.group(1) or '        '
    
    # Find the end of the function by brace-matching
    brace_depth = 0
    func_body_start = content.index('{', match.start())
    pos = func_body_start
    
    while pos < len(content):
        ch = content[pos]
        if ch == '{':
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
            if brace_depth == 0:
                func_end = pos + 1
                break
        elif ch == "'" or ch == '"' or ch == '`':
            # Skip string literals
            quote = ch
            pos += 1
            while pos < len(content) and content[pos] != quote:
                if content[pos] == '\\':
                    pos += 1  # skip escaped char
                pos += 1
        elif ch == '/' and pos + 1 < len(content):
            if content[pos + 1] == '/':
                # Skip line comment
                while pos < len(content) and content[pos] != '\n':
                    pos += 1
            elif content[pos + 1] == '*':
                # Skip block comment
                pos += 2
                while pos + 1 < len(content) and not (content[pos] == '*' and content[pos + 1] == '/'):
                    pos += 1
                pos += 1  # skip the '/'
        pos += 1
    else:
        print("[PATCH] ERROR: Could not find end of fetchPipelineSyncTime()")
        return content, False
    
    # Also capture any comment block immediately before the function
    comment_search_start = max(0, func_start - 500)
    preceding = content[comment_search_start:func_start]
    
    # Look for the comment block that starts with // and relates to sync
    comment_lines = preceding.rstrip().split('\n')
    comment_start_offset = func_start
    for i in range(len(comment_lines) - 1, -1, -1):
        stripped = comment_lines[i].strip()
        if stripped.startswith('//'):
            comment_start_offset = comment_search_start + preceding.rfind(comment_lines[i])
        else:
            break
    
    # Find the actual start including comments
    actual_start = min(func_start, comment_start_offset)
    
    # Extract old function
    old_function = content[actual_start:func_end]
    
    # Replace
    new_content = content[:actual_start] + NEW_FUNCTION + content[func_end:]
    
    return new_content, True


def main():
    print("=" * 60)
    print("SENTINEL APEX v72.0 — Dashboard Sync Display Patcher")
    print("=" * 60)
    
    if not os.path.exists(INDEX_HTML):
        print(f"[PATCH] FATAL: {INDEX_HTML} not found")
        sys.exit(1)
    
    with open(INDEX_HTML, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_size = len(content)
    print(f"[PATCH] Loaded index.html: {original_size:,} bytes")
    
    # Check if already patched
    if check_already_patched(content):
        print("[PATCH] ALREADY PATCHED — freshest-wins guard detected. No changes needed.")
        sys.exit(0)
    
    # Verify function exists
    if 'fetchPipelineSyncTime' not in content:
        print("[PATCH] WARN: fetchPipelineSyncTime() not found in index.html")
        print("[PATCH] This function may have been removed or renamed.")
        sys.exit(0)
    
    # Create backup
    backup_path = INDEX_HTML + f'.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    shutil.copy2(INDEX_HTML, backup_path)
    print(f"[PATCH] Backup: {backup_path}")
    
    # Apply patch
    new_content, was_modified = find_and_replace_function(content)
    
    if not was_modified:
        print("[PATCH] ERROR: Could not locate fetchPipelineSyncTime function for patching")
        sys.exit(1)
    
    # Validate the result
    if 'manifestNewest' not in new_content:
        print("[PATCH] ERROR: Patch verification failed — manifestNewest not found")
        sys.exit(1)
    
    # Verify HTML is still valid (basic checks)
    if new_content.count('<html') != content.count('<html'):
        print("[PATCH] ERROR: HTML structure corrupted")
        sys.exit(1)
    
    # Verify EMBEDDED_INTEL still present
    if 'EMBEDDED_INTEL' not in new_content:
        print("[PATCH] ERROR: EMBEDDED_INTEL lost during patch")
        sys.exit(1)
    
    # Write patched file
    with open(INDEX_HTML, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    new_size = len(new_content)
    delta = new_size - original_size
    print(f"[PATCH] Patched: {new_size:,} bytes (delta: {'+' if delta >= 0 else ''}{delta})")
    print(f"[PATCH] fetchPipelineSyncTime() now has freshest-wins guard")
    print(f"[PATCH] SUCCESS — stale sync_marker.json will no longer overwrite fresh data")
    print("=" * 60)


if __name__ == "__main__":
    main()
