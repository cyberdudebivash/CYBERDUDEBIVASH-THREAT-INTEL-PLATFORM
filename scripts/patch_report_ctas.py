#!/usr/bin/env python3
"""
scripts/patch_report_ctas.py
CYBERDUDEBIVASH SENTINEL APEX — Report CTA Patcher
===================================================
Phase 2 Revenue Validation: fix dead CTA URLs in all report HTML files
and inject lightweight conversion tracking snippet.

Run standalone: python scripts/patch_report_ctas.py
(c) 2026 CyberDudeBivash Pvt. Ltd.
"""
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports"

REPLACEMENTS = [
    (
        b"href='https://cyberdudebivash.com/sentinel-premium'",
        b"href='https://cyberdudebivash.com/upgrade.html?plan=pro&utm_source=report&utm_medium=cta'"
        b" data-apex-track='cta_click' data-plan='pro'",
    ),
    (
        b"href='https://cyberdudebivash.com/sentinel-enterprise'",
        b"href='https://cyberdudebivash.com/upgrade.html?plan=enterprise&utm_source=report&utm_medium=cta'"
        b" data-apex-track='cta_click' data-plan='enterprise'",
    ),
]

TRACK_SNIPPET = (
    b"\n<script>\n"
    b"(function(){"
    b"var K='apex_funnel_v1';"
    b"function t(ev,m){try{var s=JSON.parse(localStorage.getItem(K)||'{}');"
    b"s[ev]=(s[ev]||0)+1;s['last_'+ev]=new Date().toISOString();"
    b"if(m)Object.keys(m).forEach(function(k){s['meta_'+k]=m[k];});"
    b"localStorage.setItem(K,JSON.stringify(s));}catch(_){}}"
    b"t('page_view',{path:location.pathname,type:'report'});"
    b"document.querySelectorAll('a[data-apex-track]').forEach(function(a){"
    b"a.addEventListener('click',function(){"
    b"t('cta_click',{plan:a.dataset.plan||'unknown',source:'report'});});});"
    b"})();\n</script>"
)

def main():
    t0 = time.monotonic()
    files = list(REPORTS.rglob("*.html"))
    total = len(files)
    patched = skipped = errors = 0

    print(f"[patch_report_ctas] Scanning {total} report files...")

    for i, f in enumerate(files):
        try:
            raw = f.read_bytes()
            if b"data-apex-track" in raw and b"apex_funnel_v1" in raw:
                skipped += 1
                continue

            modified = raw
            changed = False

            for old, new in REPLACEMENTS:
                if old in modified:
                    modified = modified.replace(old, new)
                    changed = True

            if b"apex_funnel_v1" not in modified and b"</body>" in modified:
                modified = modified.replace(b"</body>", TRACK_SNIPPET + b"\n</body>", 1)
                changed = True

            if changed:
                f.write_bytes(modified)
                patched += 1

            if (i + 1) % 1000 == 0:
                print(f"  [{i+1}/{total}] patched={patched} skipped={skipped}")

        except Exception as e:
            errors += 1
            print(f"  ERROR {f.name}: {e}")

    elapsed = time.monotonic() - t0
    print(f"\n[patch_report_ctas] COMPLETE")
    print(f"  Total:   {total}")
    print(f"  Patched: {patched}")
    print(f"  Skipped: {skipped}")
    print(f"  Errors:  {errors}")
    print(f"  Time:    {elapsed:.1f}s")
    return 0 if errors == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
