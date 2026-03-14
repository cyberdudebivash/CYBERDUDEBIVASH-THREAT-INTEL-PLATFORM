#!/usr/bin/env python3
"""
apply_sec01_fix.py — CYBERDUDEBIVASH® SENTINEL APEX v48.0
SEC-01 CRITICAL: Remove hardcoded JWT secret from agent/config.py

The public repository exposes:
  CDB_JWT_SECRET = os.environ.get('CDB_JWT_SECRET', 'cdb-sentinel-apex-v30-secret-change-in-prod')

This allows ANY attacker to forge valid JWT tokens for ALL API tiers.

FIX: Replace with environment-only loading + ephemeral random fallback
     that logs a WARNING in non-production environments.

Usage:
    python agent/v48_pipeline_hardening/apply_sec01_fix.py
"""
import os
import re
import sys


def apply():
    # Find config.py
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "config.py"),
        "agent/config.py",
    ]
    config_path = None
    for c in candidates:
        if os.path.exists(c):
            config_path = os.path.abspath(c)
            break

    if not config_path:
        print("ERROR: agent/config.py not found")
        sys.exit(1)

    with open(config_path, "r") as f:
        content = f.read()

    # Check if already patched
    if "SEC01_PATCHED_v48" in content:
        print("Already patched (v48). No changes needed.")
        return

    # Pattern to match the hardcoded JWT line
    pattern = (
        r"CDB_JWT_SECRET\s*=\s*os\.environ\.get\(\s*'CDB_JWT_SECRET'\s*,\s*"
        r"'cdb-sentinel-apex-v[0-9]+-secret-change-in-prod'\s*\)"
    )

    replacement = """# SEC01_PATCHED_v48 — Hardcoded JWT secret removed
_jwt_from_env = os.environ.get('CDB_JWT_SECRET', '')
if not _jwt_from_env:
    import secrets as _sec_secrets
    import logging as _sec_logging
    _sec_logging.getLogger("CDB-SECURITY").warning(
        "CDB_JWT_SECRET not set. Using ephemeral random secret. "
        "Tokens will NOT persist across restarts. "
        "Set CDB_JWT_SECRET environment variable for production."
    )
    _jwt_from_env = _sec_secrets.token_urlsafe(64)
CDB_JWT_SECRET = _jwt_from_env"""

    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
        with open(config_path, "w") as f:
            f.write(content)
        print(f"SEC-01 FIXED: {config_path}")
        print("  - Hardcoded JWT secret removed")
        print("  - Ephemeral random fallback with WARNING log")
        print("  - Set CDB_JWT_SECRET env var for production")
    else:
        # Try exact string match
        old_exact = "CDB_JWT_SECRET          = os.environ.get('CDB_JWT_SECRET', 'cdb-sentinel-apex-v30-secret-change-in-prod')"
        if old_exact in content:
            content = content.replace(old_exact, replacement)
            with open(config_path, "w") as f:
                f.write(content)
            print(f"SEC-01 FIXED (exact match): {config_path}")
        else:
            print("WARNING: JWT secret line not found. Manual review needed.")
            print(f"  File: {config_path}")
            # Show what we found
            for i, line in enumerate(content.split("\n"), 1):
                if "JWT_SECRET" in line:
                    print(f"  Line {i}: {line.strip()}")


if __name__ == "__main__":
    apply()
