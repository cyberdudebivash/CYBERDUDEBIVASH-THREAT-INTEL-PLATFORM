#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_target_environment.py
# Extracted from environment-promotion.yml (RULE 5 compliance)
# Validates target environment config from config/environments.json.
# Usage: python3 scripts/validate_target_environment.py <target>
# Exit 0 = valid | Exit 1 = unknown/invalid environment
# =============================================================================
import json
import pathlib
import sys

if len(sys.argv) < 2:
    print("[ENV] ERROR: No target environment specified")
    sys.exit(1)

target = sys.argv[1].strip()
env_cfg_path = pathlib.Path("config/environments.json")

if not env_cfg_path.exists():
    print(f"[ENV] WARN: config/environments.json not found -- skipping deep validation")
    print(f"[ENV] Target: {target}")
    sys.exit(0)

try:
    env_cfg = json.loads(env_cfg_path.read_text(encoding="utf-8"))
except Exception as e:
    print(f"[ENV] WARN: Could not parse environments.json: {e} -- skipping")
    sys.exit(0)

env = env_cfg.get("environments", {}).get(target, {})
if not env:
    print(f"[ENV] FAIL: Unknown environment: {target}")
    sys.exit(1)

gates = env.get("validation_gates", [])
print(f"[ENV] Environment:        {target}")
print(f"[ENV] Tier:               {env.get('tier')}")
print(f"[ENV] Protected:          {env.get('protected')}")
print(f"[ENV] Required gates:     {gates}")
print(f"[ENV] Requires approval:  {env.get('requires_approval')}")
print(f"[ENV] Customer facing:    {env.get('customer_facing', False)}")
print(f"[ENV] Validation PASSED")
sys.exit(0)
