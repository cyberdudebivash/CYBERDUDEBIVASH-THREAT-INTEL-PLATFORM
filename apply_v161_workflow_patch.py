#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — v161.0 Workflow Patch
Appends new enterprise transformation stages to sentinel-blogger.yml.
Each stage is non-blocking (continue-on-error: true) for zero regression.
"""
from pathlib import Path
import sys

REPO = Path(__file__).parent
WF   = REPO / ".github" / "workflows" / "sentinel-blogger.yml"

NEW_STAGES = """
      # =====================================================================
      # STAGE 5.9 — v161.0 ENTERPRISE TRANSFORMATION STAGES
      # All stages: continue-on-error: true (non-blocking, zero regression)
      # =====================================================================

      - name: "Stage 5.9.1 — Manifest URL Repair (P1-004)"
        run: |
          echo "=== STAGE 5.9.1: Manifest URL Backfill ==="
          python3 scripts/manifest_repair.py \
            --manifest data/feed_manifest.json 2>&1 || true
          echo "=== STAGE 5.9.1 COMPLETE ==="
        continue-on-error: true

      - name: "Stage 5.9.2 — OpenAPI Spec Generation (P2-001)"
        run: |
          echo "=== STAGE 5.9.2: OpenAPI 3.0 Spec ==="
          python3 scripts/openapi_generator.py 2>&1 || true
          echo "=== STAGE 5.9.2 COMPLETE ==="
        continue-on-error: true

      - name: "Stage 5.9.3 — EPSS + CVSS Quality Gate (P0-004 / P1-006)"
        run: |
          echo "=== STAGE 5.9.3: EPSS Sanity + NVD CVSS Backfill ==="
          python3 -c "
import sys, json
from pathlib import Path
sys.path.insert(0, 'scripts')
from ioc_quality_hardener import apply_ioc_hardening
result = apply_ioc_hardening()
print(json.dumps({k: v for k, v in result.items() if not isinstance(v, dict)}, indent=2))
epss_fixed = result.get('epss_anomalies_corrected', 0)
cvss_backfilled = result.get('cvss_backfilled', 0)
print(f'  EPSS anomalies corrected: {epss_fixed}')
print(f'  CVSS scores backfilled:   {cvss_backfilled}')
" 2>&1 || true
          echo "=== STAGE 5.9.3 COMPLETE ==="
        continue-on-error: true

      - name: "Stage 5.9.4 — Enterprise Page Validation (P1-005 / P2-002)"
        run: |
          echo "=== STAGE 5.9.4: Enterprise Page Presence Check ==="
          python3 -c "
from pathlib import Path
pages = ['sla.html', 'pricing.html', 'terms.html', 'api-docs.html', 'docs/index.html', '.well-known/security.txt']
missing = [p for p in pages if not Path(p).exists()]
for p in pages:
    status = 'OK' if Path(p).exists() else 'MISSING'
    print(f'  [{status}] {p}')
if missing:
    print(f'WARNING: {len(missing)} enterprise pages missing')
else:
    print('ALL ENTERPRISE PAGES PRESENT')
" 2>&1 || true
          echo "=== STAGE 5.9.4 COMPLETE ==="
        continue-on-error: true

      # ---------------------------------------------
"""

src = WF.read_text(encoding="utf-8")

# The workflow ends with "      # ---------------------------------------------"
# We replace the final occurrence to inject our stages before the last comment
ANCHOR = "\n      # ---------------------------------------------"
last_pos = src.rfind(ANCHOR)

if last_pos == -1:
    print("ERROR: Anchor not found in workflow")
    sys.exit(1)

if "STAGE 5.9" in src:
    print("WARNING: v161.0 stages already present — skipping workflow patch")
    sys.exit(0)

src = src[:last_pos] + NEW_STAGES.rstrip("\n") + src[last_pos:]
WF.write_text(src, encoding="utf-8")
new_lines = src.count("\n")
print(f"[OK] Workflow patched: {new_lines} lines (added Stage 5.9.1–5.9.4)")
