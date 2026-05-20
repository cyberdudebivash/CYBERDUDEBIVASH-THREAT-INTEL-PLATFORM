#!/usr/bin/env python3
import sys
from pathlib import Path

src = Path(r'C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\index.html').read_text(encoding='utf-8')

checks = [
    ('enterprise-intel-command section present',    'enterprise-intel-command' in src),
    ('SOC tab panel intact',                        'id="cdb-panel-soc"' in src),
    ('premium-intel-products intact',               'id="premium-intel-products"' in src),
    ('PAYMENT-GATEWAY link in upgrade CTA',         '/PAYMENT-GATEWAY.html' in src),
    ('AI prediction engine present',                'eicc-ai-predictions' in src),
    ('live threat ticker present',                  'eicc-ticker-inner' in src),
    ('cyber warfare heatmap present',               'eicc-heatmap' in src),
    ('SOC status panel present',                    'eicc-soc-status' in src),
    ('live feed preview present',                   'eicc-feed-preview' in src),
    ('enterprise onboarding CTA present',           'ENTERPRISE ONBOARDING' in src),
    ('live metrics row present',                    'eicc-metrics-row' in src),
    ('EICC data engine script present',             'eiccEngine' in src),
    ('V173 renderer intact',                        'CDB-RENDERER-ENGINE-V173-START' in src),
    ('No duplicate premium section',                src.count('id="premium-intel-products"') == 1),
    ('No duplicate eicc section',                   src.count('enterprise-intel-command') == 1),
    ('SOC tab system intact',                       'cdb-panel-soc' in src),
    ('Tab bar intact',                              'cdb-tab-bar' in src),
    ('Threat grid intact',                          'id="threat-grid"' in src),
    ('File size reasonable (>1MB)',                 len(src) > 1_000_000),
    ('EICC block after SOC panels',                 src.index('enterprise-intel-command') > src.index('cdb-panel-soc')),
    ('EICC block before premium-intel',             src.index('enterprise-intel-command') < src.index('premium-intel-products')),
]

failed = 0
for name, result in checks:
    status = 'PASS' if result else 'FAIL'
    if not result: failed += 1
    print(f'  [{status}] {name}')

print()
if failed:
    print(f'RESULT: {failed} FAILURES — FIX REQUIRED')
    sys.exit(1)
else:
    print(f'RESULT: ALL {len(checks)} CHECKS PASSED — injection verified')
    sys.exit(0)
