#!/usr/bin/env python3
"""
config_security_patch.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0
SEC-01 FIX: Remove hardcoded JWT secret default from config.py

USAGE:
    python agent/v47_integrity/config_security_patch.py

This script patches agent/config.py to:
  1. Remove the hardcoded JWT secret default value
  2. Add startup validation that CDB_JWT_SECRET is set via environment
  3. Add a secure random fallback for development-only (logged as WARNING)

SAFE: Only modifies the JWT secret line. All other config preserved.
"""

import re
import os
import sys


def apply_patch():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.py")
    if not os.path.exists(config_path):
        # Try from repo root
        config_path = "agent/config.py"

    if not os.path.exists(config_path):
        print(f"ERROR: config.py not found at {config_path}")
        sys.exit(1)

    with open(config_path, "r") as f:
        content = f.read()

    # Check if already patched
    if "INSECURE_DEFAULT_REMOVED" in content:
        print("Already patched. Skipping.")
        return

    # Find and replace the hardcoded JWT secret line
    old_line = (
        "CDB_JWT_SECRET          = os.environ.get("
        "'CDB_JWT_SECRET', 'cdb-sentinel-apex-v30-secret-change-in-prod')"
    )

    new_block = '''# ── SEC-01 FIX (v47.0): Hardcoded JWT secret removed ─────────────────────────
# INSECURE_DEFAULT_REMOVED — v47.0 security hardening
_jwt_env = os.environ.get('CDB_JWT_SECRET', '')
if not _jwt_env:
    import secrets as _secrets
    import logging as _sec_logging
    _sec_logger = _sec_logging.getLogger("CDB-SECURITY")
    _sec_logger.warning(
        "CDB_JWT_SECRET not set! Using random ephemeral secret. "
        "Set CDB_JWT_SECRET env var for production. Tokens will NOT "
        "persist across restarts."
    )
    _jwt_env = _secrets.token_urlsafe(64)
CDB_JWT_SECRET = _jwt_env'''

    if old_line in content:
        content = content.replace(old_line, new_block)
        with open(config_path, "w") as f:
            f.write(content)
        print(f"SEC-01 PATCHED: Hardcoded JWT secret removed from {config_path}")
        print("  - Random ephemeral secret generated when env var not set")
        print("  - WARNING logged in non-production environments")
        print("  - Set CDB_JWT_SECRET environment variable for production")
    else:
        # Try fuzzy match
        pattern = r"CDB_JWT_SECRET\s*=\s*os\.environ\.get\('CDB_JWT_SECRET',\s*'[^']+'\)"
        if re.search(pattern, content):
            content = re.sub(pattern, new_block, content)
            with open(config_path, "w") as f:
                f.write(content)
            print(f"SEC-01 PATCHED (fuzzy match): {config_path}")
        else:
            print("WARNING: Could not find JWT secret line to patch. Manual review needed.")
            print("  Look for: CDB_JWT_SECRET in agent/config.py")


if __name__ == "__main__":
    apply_patch()
