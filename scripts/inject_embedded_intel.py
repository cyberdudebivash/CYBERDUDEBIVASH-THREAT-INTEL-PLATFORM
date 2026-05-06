#!/usr/bin/env python3
"""
SENTINEL APEX v150.0 -- INJECT EMBEDDED INTEL (DEPRECATED PASSTHROUGH)
=======================================================================
STAGE 3.93 -- THIS SCRIPT IS NOW A SAFE NO-OP

ARCHITECTURE CHANGE (v150.0):
  OLD: This script injected window.EMBEDDED_INTEL = [...] into index.html.
       This caused index.html to grow to 6.6MB and be overwritten on every
       pipeline run, causing repeated P0 rendering regressions.

  NEW: generate_api_manifests.py generates /api/v1/intel/*.json instead.
       index.html is NEVER modified by the pipeline.
       Frontend fetches from immutable API bundles at runtime.

This script now exits 0 immediately without touching any files.
It remains for backward compatibility. All pipeline stages should now
call generate_api_manifests.py directly.

Exit 0 = always (safe no-op)
"""

import sys
import datetime


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


print('=' * 68)
print('SENTINEL APEX v150.0 -- EMBEDDED INTEL INJECTOR (DEPRECATED NO-OP)')
print(f'Timestamp : {now_iso()}')
print('=' * 68)
print()
print('[NO-OP] inject_embedded_intel.py is deprecated in v150.0 architecture.')
print('[NO-OP] HTML mutation of index.html is PERMANENTLY DISABLED.')
print('[NO-OP] Use generate_api_manifests.py for immutable API bundle generation.')
print('[NO-OP] Outputs: api/v1/intel/latest.json, top10.json, apex.json')
print('[NO-OP] Frontend fetches from immutable API bundles at runtime.')
print('[NO-OP] index.html is read-only -- zero HTML mutation enforced.')
print()
print('[PASS] No files modified. Exiting 0.')
sys.exit(0)
