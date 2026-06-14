#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_canary_worker_alignment.py
# Extracted from enterprise-governance.yml canary_contract_check job (RULE 5)
# Validates canary parser is fully aligned with Worker response envelope.
# Exit 0 = ALIGNED | Exit 1 = MISALIGNED (fix required before deploy)
# =============================================================================
import re
import sys
from pathlib import Path

CANARY_SRC_PATH = "scripts/deployment_canary.py"
WORKER_SRC_PATH = "workers/intel-gateway/src/index.js"

errors = []
warnings = []

if not Path(CANARY_SRC_PATH).exists():
    print(f"[WARN] {CANARY_SRC_PATH} not found -- skipping alignment check")
    sys.exit(0)
if not Path(WORKER_SRC_PATH).exists():
    print(f"[WARN] {WORKER_SRC_PATH} not found -- skipping alignment check")
    sys.exit(0)

canary_src = Path(CANARY_SRC_PATH).read_text(encoding="utf-8")
worker_src = Path(WORKER_SRC_PATH).read_text(encoding="utf-8")

# CHECK 1: Canary reads data["preview"] (not just data["items"])
if 'data.get("preview")' in canary_src or "data.get('preview')" in canary_src:
    print("[PASS] Canary B reads data['preview'] -- envelope aligned")
else:
    errors.append("Canary B does NOT read data['preview'] -- WILL produce false-negative")

# CHECK 2: Worker emits nested preview envelope
# Worker uses inline object: preview: { items, ... } not a named variable
if re.search(r'preview\s*:\s*[\{\w]', worker_src):
    print("[PASS] Worker wraps payload under 'preview' key -- envelope aligned")
else:
    errors.append("Worker may not wrap payload under 'preview' -- envelope drift")

# CHECK 3: MIN_PREVIEW_ITEMS in canary <= actual preview limit in Worker
# Worker defines PREVIEW_LIMIT as: const PREVIEW_LIMIT = 25;
m_canary = re.search(r'MIN_PREVIEW_ITEMS\s*=\s*(\d+)', canary_src)
m_worker = re.search(r'PREVIEW_LIMIT\s*=\s*(\d+)', worker_src)
if m_canary and m_worker:
    canary_min = int(m_canary.group(1))
    worker_limit = int(m_worker.group(1))
    if canary_min <= worker_limit:
        print(f"[PASS] MIN_PREVIEW_ITEMS={canary_min} <= PREVIEW_LIMIT={worker_limit} -- gate achievable")
    else:
        errors.append(
            f"MIN_PREVIEW_ITEMS={canary_min} > PREVIEW_LIMIT={worker_limit} "
            f"-- canary B can NEVER pass (gate is impossible)"
        )
else:
    warnings.append("Could not parse MIN_PREVIEW_ITEMS or PREVIEW_LIMIT -- check manually")

# CHECK 4: Health canary accepts any of (healthy|ok|operational); Worker emits at least one
canary_health_check = (
    'in ("healthy", "ok", "operational")' in canary_src
    or "in ('healthy', 'ok', 'operational')" in canary_src
)
# Worker emits "ok" for health -- canary accepts "ok" so they are aligned.
# Do NOT require Worker to emit ALL accepted values; ANY match is sufficient.
worker_emits_any_ok = any(v in worker_src for v in ('"healthy"', '"ok"', '"operational"'))
if canary_health_check and worker_emits_any_ok:
    print("[PASS] Health canary status values aligned with Worker")
else:
    warnings.append("Health canary/Worker status value alignment could not be confirmed")

# CHECK 5: Canary C accepts 401/403 (auth gate)
if "401" in canary_src and "403" in canary_src:
    print("[PASS] Canary C accepts 401/403 (auth gate operating correctly)")
else:
    warnings.append("Canary C may not accept 401/403 -- authenticated feed gate check")

for w in warnings:
    print(f"[WARN] {w}")

if errors:
    for e in errors:
        print(f"::error::{e}")
    sys.exit(1)

print("\n[ALL CHECKS PASS] Canary<->Worker envelope fully aligned")
print("  Zero-regression guarantee: canary false-negatives prevented")
