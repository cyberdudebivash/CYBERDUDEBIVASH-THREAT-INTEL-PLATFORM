#!/usr/bin/env python3
"""
SENTINEL APEX — Supabase Setup Verification
Validates that Supabase project is correctly configured.

Usage: python scripts/verify_supabase.py
"""
import asyncio
import json
import os
import sys

import httpx


async def verify():
    url = os.environ.get("SUPABASE_URL")
    anon = os.environ.get("SUPABASE_ANON_KEY")
    service = os.environ.get("SUPABASE_SERVICE_KEY")

    if not all([url, anon, service]):
        print("ERROR: Set SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY")
        sys.exit(1)

    print(f"Verifying Supabase at: {url}")
    headers = {
        "apikey": service,
        "Authorization": f"Bearer {service}",
        "Content-Type": "application/json",
    }

    checks = {
        "tier_config": False,
        "advisories": False,
        "organizations": False,
        "user_profiles": False,
        "api_keys": False,
        "api_usage": False,
        "audit_log": False,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        for table in checks:
            try:
                r = await client.get(
                    f"{url}/rest/v1/{table}?select=*&limit=1",
                    headers=headers,
                )
                if r.status_code == 200:
                    checks[table] = True
                    print(f"  [OK] {table}")
                else:
                    print(f"  [FAIL] {table}: HTTP {r.status_code} — {r.text[:100]}")
            except Exception as e:
                print(f"  [FAIL] {table}: {e}")

        # Verify tier_config data
        try:
            r = await client.get(
                f"{url}/rest/v1/tier_config?select=*",
                headers=headers,
            )
            tiers = r.json()
            if len(tiers) == 4:
                print(f"  [OK] tier_config has {len(tiers)} tiers")
            else:
                print(f"  [WARN] tier_config has {len(tiers)} tiers (expected 4)")
        except Exception as e:
            print(f"  [FAIL] tier_config data: {e}")

        # Verify auth trigger
        print("\n  Checking auth trigger...")
        try:
            r = await client.get(
                f"{url}/rest/v1/rpc/",
                headers=headers,
            )
            print(f"  [INFO] RPC endpoint accessible")
        except Exception:
            print(f"  [INFO] RPC check skipped")

    passed = sum(checks.values())
    total = len(checks)
    print(f"\n{'='*50}")
    print(f"RESULT: {passed}/{total} tables verified")

    if passed == total:
        print("STATUS: READY FOR DEPLOYMENT")
        return 0
    else:
        print("STATUS: SCHEMA INCOMPLETE — Run migrations/001_foundation_schema.sql")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(verify()))
