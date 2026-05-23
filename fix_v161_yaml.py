#!/usr/bin/env python3
"""Fix YAML syntax error: replace broken python3 -c multi-line blocks in Stage 5.9.3 and 5.9.4."""
from pathlib import Path
import sys

WF = Path(".github/workflows/sentinel-blogger.yml")
src = WF.read_text(encoding="utf-8")

# ── Stage 5.9.3 fix: replace broken python3 -c inline with direct script call ──
OLD_593 = '''      - name: "Stage 5.9.3 — EPSS + CVSS Quality Gate (P0-004 / P1-006)"
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
        continue-on-error: true'''

NEW_593 = '''      - name: "Stage 5.9.3 — EPSS + CVSS Quality Gate (P0-004 / P1-006)"
        run: |
          echo "=== STAGE 5.9.3: EPSS Sanity + NVD CVSS Backfill ==="
          python3 scripts/ioc_quality_hardener.py --manifest data/feed_manifest.json 2>&1 || true
          echo "=== STAGE 5.9.3 COMPLETE ==="
        continue-on-error: true'''

# ── Stage 5.9.4 fix: replace broken python3 -c inline with direct script call ──
OLD_594 = '''      - name: "Stage 5.9.4 — Enterprise Page Validation (P1-005 / P2-002)"
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
        continue-on-error: true'''

NEW_594 = '''      - name: "Stage 5.9.4 — Enterprise Page Validation (P1-005 / P2-002)"
        run: |
          echo "=== STAGE 5.9.4: Enterprise Page Presence Check ==="
          python3 scripts/validate_enterprise_pages.py 2>&1 || true
          echo "=== STAGE 5.9.4 COMPLETE ==="
        continue-on-error: true'''

changed = 0

if OLD_593 in src:
    src = src.replace(OLD_593, NEW_593)
    print("  [FIXED] Stage 5.9.3 inline Python replaced with script call")
    changed += 1
else:
    # Try with em-dash encoded differently
    print("  WARNING: Stage 5.9.3 anchor not found — trying alternate encoding")
    # Try scanning for the block directly
    import re
    pat593 = re.compile(
        r'      - name: "Stage 5\.9\.3[^"]+"\s+run: \|\s+echo "=== STAGE 5\.9\.3[^=]+==="\s+python3 -c ".*?"[^\n]*\n\s+echo "=== STAGE 5\.9\.3 COMPLETE ==="\s+continue-on-error: true',
        re.DOTALL
    )
    m = pat593.search(src)
    if m:
        src = src[:m.start()] + NEW_593 + src[m.end():]
        print("  [FIXED] Stage 5.9.3 fixed via regex")
        changed += 1
    else:
        print("  ERROR: Stage 5.9.3 not found by either method")

if OLD_594 in src:
    src = src.replace(OLD_594, NEW_594)
    print("  [FIXED] Stage 5.9.4 inline Python replaced with script call")
    changed += 1
else:
    print("  WARNING: Stage 5.9.4 anchor not found — trying alternate encoding")
    import re
    pat594 = re.compile(
        r'      - name: "Stage 5\.9\.4[^"]+"\s+run: \|\s+echo "=== STAGE 5\.9\.4[^=]+==="\s+python3 -c ".*?"[^\n]*\n\s+echo "=== STAGE 5\.9\.4 COMPLETE ==="\s+continue-on-error: true',
        re.DOTALL
    )
    m = pat594.search(src)
    if m:
        src = src[:m.start()] + NEW_594 + src[m.end():]
        print("  [FIXED] Stage 5.9.4 fixed via regex")
        changed += 1
    else:
        print("  ERROR: Stage 5.9.4 not found by either method")

WF.write_text(src, encoding="utf-8")
print(f"\n[OK] Workflow written ({src.count(chr(10))} lines, {changed}/2 fixes applied)")
sys.exit(0 if changed >= 1 else 1)
