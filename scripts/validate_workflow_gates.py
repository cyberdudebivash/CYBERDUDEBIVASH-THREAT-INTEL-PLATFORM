#!/usr/bin/env python3
import sys
from pathlib import Path

src = Path(r'C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\.github\workflows\sentinel-blogger.yml').read_text(encoding='utf-8')

checks = [
    ('Pre-deploy gate stage present',       'STAGE 5.4.5d - Pre-Deploy Gate v158.0' in src),
    ('pre_deploy_gate.py called in CI',     'pre_deploy_gate.py' in src),
    ('Post-deploy smoke stage present',     'STAGE 5.5.0 - Post-Deploy Smoke Tests v158.0' in src),
    ('post_deploy_smoke_test.py in CI',     'post_deploy_smoke_test.py' in src),
    ('continue-on-error for smoke tests',   'continue-on-error: true' in src),
    ('PLATFORM_URL env var configured',     'PLATFORM_URL: https://intel.cyberdudebivash.com' in src),
    ('STAGE 5 deploy still present',        'STAGE 5 - Deploy to GitHub Pages' in src),
    ('STAGE 5.4.6 build still present',     'STAGE 5.4.6' in src),
    ('STAGE 5.5 final validation present',  'STAGE 5.5 - Final Repository Validation Gate' in src),
    ('build_dist_artifact.py still called', 'build_dist_artifact.py' in src),
    # build_dist_artifact.py appears in YAML comments earlier; compare against the actual `run:` line
    ('Pre-gate before build (ordering)',    src.index('pre_deploy_gate.py') < src.index('run: python3 scripts/build_dist_artifact.py')),
    ('Smoke after deploy (ordering)',       src.index('post_deploy_smoke_test.py') > src.index('Deploy to GitHub Pages')),
]

failed = 0
for name, result in checks:
    print(('[PASS] ' if result else '[FAIL] ') + name)
    if not result: failed += 1

print()
if failed:
    print('FAILURES: ' + str(failed))
    sys.exit(1)
else:
    print('ALL ' + str(len(checks)) + ' CHECKS PASSED')
    sys.exit(0)
