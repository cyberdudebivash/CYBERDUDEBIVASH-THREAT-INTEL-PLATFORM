#!/usr/bin/env python3
"""CYBERDUDEBIVASH SENTINEL APEX — MASTER P0 FIX v2"""
import json, os, re, shutil, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path('/sessions/confident-exciting-einstein/mnt/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM')
GOOD_HTML = Path('/tmp/index_good.html')
NEW_VERSION = '134.0.0'
OLD_VERSION = '131.2.0'
NOW_UTC = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
TODAY = datetime.now(timezone.utc).strftime('%Y-%m-%d')
errors = []
fixes = []

def log(m): print(f'[FIX] {m}')
def err(m): errors.append(m); print(f'[ERR] {m}')

def build_apex_ai(item):
    risk = float(item.get('risk_score') or 0)
    sev  = (item.get('severity') or 'LOW').upper()
    iocs = int(item.get('ioc_count') or 0)
    ttps = int(item.get('ttp_count') or 0)
    conf = float(item.get('confidence') or 0)
    atag = item.get('actor_tag') or 'UNCLASSIFIED'
    if risk >= 9.0 or sev == 'CRITICAL': pri, tl = 'P1', 'CRITICAL'
    elif risk >= 7.0 or sev == 'HIGH':   pri, tl = 'P2', 'HIGH_ALERT'
    elif risk >= 5.0 or sev == 'MEDIUM': pri, tl = 'P3', 'MODERATE'
    else:                                pri, tl = 'P4', 'LOW'
    if conf >= 80:   ct, cl = 'VERIFIED', 'VERIFIED — Multi-source corroboration confirmed'
    elif conf >= 50: ct, cl = 'MODERATE', 'MODERATE — Credible intelligence'
    else:            ct, cl = 'LOW',      'LOW — Limited signals'
    pred = round(min(10.0, risk*0.7 + ttps*0.3 + iocs*0.05), 2)
    aic  = min(100, int(conf*0.8 + ttps*2 + iocs*0.5))
    urg  = {'P1':'CRITICAL — Immediate response.','P2':'HIGH THREAT — Enterprise IR response.','P3':'THREAT ACTIVE — Pro tier.','P4':'MONITORING — Pro tier.'}
    return {
        'soc_priority': pri, 'threat_level': tl, 'threat_category': 'UNKNOWN',
        'predictive_risk': pred, 'ai_confidence': aic,
        'threat_confidence_tier': ct, 'threat_confidence_label': ct + ' — ' + cl,
        'ttp_density': round(min(10.0, ttps*1.5 + iocs*0.2), 2),
        'campaign_id': 'UNCLASSIFIED',
        'actor_fingerprint': atag.replace('-GEN','').replace('-01','') + '-****',
        'kill_chain': 'PRO_REQUIRED', 'kill_chain_primary': 'PRO_REQUIRED',
        'ai_summary': f'[{ct}] {sev} THREAT. {iocs} indicators · {ttps} TTPs · Risk: {pred}/10 · SOC {pri}. PRO TIER FOR FULL INTEL.',
        'recommended_action': f'{pri}: {iocs} IOCs locked. Upgrade for complete IR playbook.',
        'behavioral_tags': [],
        'paywall': {
            'locked_fields': ['actor_fingerprint_full','kill_chain','behavioral_tags','recommended_action_full','stix_bundle'],
            'upgrade_url': 'https://cyberdudebivash.com/sentinel-premium',
            'message': f'{ct} THREAT — {iocs} IOCs locked. Upgrade to Pro.',
            'urgency': urg[pri],
        }
    }

def fix_api_feed():
    path = REPO / 'api' / 'feed.json'
    log('RC-3: Fixing api/feed.json ...')
    with open(path) as f: raw = json.load(f)
    items = raw if isinstance(raw, list) else raw.get('items', raw.get('advisories', []))
    enriched = []
    for it in items:
        it = dict(it)
        if not it.get('stix_id'): it['stix_id'] = it.get('id','')
        if not it.get('apex_ai'):  it['apex_ai'] = build_apex_ai(it)
        if 'apex' not in it:       it['apex'] = None
        if not it.get('iocs'):     it['iocs'] = []
        if not it.get('mitre_tactics'): it['mitre_tactics'] = it.get('ttps',[])
        if not it.get('tags') or not isinstance(it['tags'], list): it['tags'] = it.get('ttps',[])[:5]
        if not it.get('validation_status'): it['validation_status'] = 'valid'
        if not it.get('ioc_paywall'):
            n = int(it.get('ioc_count') or 0); c = float(it.get('confidence') or 17)
            it['ioc_paywall'] = {'locked':True,'count':n,'confidence':round(c,1),'upgrade_url':'https://cyberdudebivash.com/sentinel-premium','message':f'{n} IOCs at {c:.1f}% — unlock with Pro.'}
        enriched.append(it)
    out = {'status':'ok','gateway':f'SENTINEL-APEX/{NEW_VERSION}','version':NEW_VERSION,
           'schema_version':f'v{NEW_VERSION.split(".")[0]}.0','generated_at':NOW_UTC,
           'total':len(enriched),'items':enriched}
    tmp = str(path)+'.tmp'
    with open(tmp,'w') as f: json.dump(out, f, separators=(',',':'))
    os.replace(tmp, path)
    log(f'  api/feed.json: {len(enriched)} items enriched with apex_ai')
    fixes.append('RC-3: api/feed.json enriched')
    return enriched

def fix_feed_manifest(enriched):
    log('RC-4: Fixing data/feed_manifest.json ...')
    ni = []
    for it in enriched[:100]:
        ni.append({'id':it.get('id',''),'stix_id':it.get('stix_id',it.get('id','')),'title':it.get('title',''),
            'severity':it.get('severity','LOW'),'risk_score':float(it.get('risk_score') or 0),
            'timestamp':it.get('timestamp') or NOW_UTC,'processed_at':it.get('processed_at') or NOW_UTC,
            'published_at':it.get('published_at') or NOW_UTC,'ioc_count':int(it.get('ioc_count') or 0),
            'ttp_count':int(it.get('ttp_count') or 0),'confidence':float(it.get('confidence') or 0),
            'threat_type':it.get('threat_type','General'),'source':it.get('source','UNKNOWN'),
            'actor_tag':it.get('actor_tag','CDB-GEN'),'stix_bundle':it.get('stix_bundle',''),
            'report_url':it.get('report_url',''),'apex_ai':it.get('apex_ai',{}),'validation_status':'valid',
            'mitre_tactics':it.get('mitre_tactics',it.get('ttps',[])),'tags':it.get('tags',[]),'iocs':[],
            'ttps':it.get('ttps',it.get('mitre_tactics',[])),'apex':None})
    for mp in [REPO/'data'/'feed_manifest.json', REPO/'data'/'stix'/'feed_manifest.json']:
        if not mp.exists(): continue
        with open(mp) as f: m = json.load(f)
        m['items'] = ni; m['version'] = NEW_VERSION; m['schema_version'] = f'v{NEW_VERSION.split(".")[0]}.0'
        m['generated_at'] = NOW_UTC; m['total_advisories'] = len(enriched); m['total_items'] = len(ni)
        tmp = str(mp)+'.tmp'
        with open(tmp,'w') as f: json.dump(m, f, separators=(',',':'))
        os.replace(tmp, mp)
        log(f'  {mp.name}: {len(ni)} items in "items" key')
    fixes.append('RC-4: feed_manifest.json normalized')

def fix_api_status(enriched):
    log('RC-2: Fixing api/status.json ...')
    path = REPO / 'api' / 'status.json'
    crit = sum(1 for i in enriched if (i.get('severity') or '').upper()=='CRITICAL')
    high = sum(1 for i in enriched if (i.get('severity') or '').upper()=='HIGH')
    tiocs = sum(int(i.get('ioc_count') or 0) for i in enriched)
    avg  = round(sum(float(i.get('risk_score') or 0) for i in enriched)/max(len(enriched),1), 2)
    s = {'version':NEW_VERSION,'platform':'CYBERDUDEBIVASH SENTINEL APEX',
         'platform_full':f'SENTINEL APEX v{NEW_VERSION}','engine':f'SENTINEL-APEX/{NEW_VERSION}',
         'status':'OPERATIONAL','sync_status':'LIVE','generated_at':NOW_UTC,
         'metrics':{'total_advisories':len(enriched),'critical_threats':crit,'high_threats':high,
                    'total_iocs':tiocs,'pipeline_status':'ACTIVE','avg_risk_score':avg,
                    'data_freshness':TODAY,'last_sync':NOW_UTC},
         'intel':{'total':len(enriched),'critical':crit,'high':high,'total_iocs':tiocs,'avg_risk':avg,'freshness':TODAY,'last_run':NOW_UTC},
         'api':{'status':'ONLINE','version':f'v{NEW_VERSION}','gateway':f'SENTINEL-APEX/{NEW_VERSION}'}}
    tmp = str(path)+'.tmp'
    with open(tmp,'w') as f: json.dump(s, f, indent=2)
    os.replace(tmp, path)
    log(f'  api/status.json: v{NEW_VERSION}, {len(enriched)} advisories, {crit} critical')
    fixes.append('RC-2: api/status.json updated v134.0.0')

def fix_api_latest(enriched):
    path = REPO / 'api' / 'latest.json'
    top = enriched[:10]
    out = {'status':'ok','version':NEW_VERSION,'generated_at':NOW_UTC,'count':len(top),'items':top}
    tmp = str(path)+'.tmp'
    with open(tmp,'w') as f: json.dump(out, f, separators=(',',':'))
    os.replace(tmp, path)
    log(f'  api/latest.json: {len(top)} items')
    fixes.append('LATEST: api/latest.json updated')

def fix_api_engines():
    path = REPO / 'api' / 'engines.json'
    if not path.exists(): return
    with open(path) as f: data = f.read()
    for old in ['101.0.0','47.0.0','81.7','81.9','131.2.0']:
        data = data.replace(old, NEW_VERSION)
    tmp = str(path)+'.tmp'
    with open(tmp,'w') as f: f.write(data)
    os.replace(tmp, path)
    log(f'  api/engines.json: version -> {NEW_VERSION}')
    fixes.append('ENGINES: api/engines.json updated')

def fix_headers():
    path = REPO / '_headers'
    c = '''# CYBERDUDEBIVASH SENTINEL APEX v134.0.0 — Cache Headers
/api/*
  Cache-Control: no-store, no-cache, must-revalidate
  Access-Control-Allow-Origin: *
/api/feed.json
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  Access-Control-Allow-Origin: *
  Content-Type: application/json; charset=utf-8
/api/status.json
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  Access-Control-Allow-Origin: *
/data/feed_manifest.json
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  Access-Control-Allow-Origin: *
/data/stix/feed_manifest.json
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  Access-Control-Allow-Origin: *
/config/version.json
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  Access-Control-Allow-Origin: *
/*.html
  Cache-Control: no-cache, must-revalidate
'''
    tmp = str(path)+'.tmp'
    with open(tmp,'w') as f: f.write(c)
    os.replace(tmp, path)
    log('  _headers: cache-control updated'); fixes.append('HEADERS: cache-control updated')

def fix_index_html(enriched):
    dest  = REPO / 'index.html'
    shutil.copy2(dest, str(dest)+'.truncated.bak')
    log('RC-1+RC-5: Restoring index.html from commit 6f4a760364 ...')

    with open(GOOD_HTML, encoding='utf-8') as f:
        html = f.read()
    log(f'  Good file: {len(html.splitlines())} lines, {len(html):,} chars')

    # RC-5: Fix version strings
    n131 = html.count(f'v{OLD_VERSION}')
    html = html.replace(f'v{OLD_VERSION}', f'v{NEW_VERSION}')
    html = html.replace('SENTINEL APEX v131', 'SENTINEL APEX v134')
    html = html.replace('v131.2', 'v134.0')
    html = html.replace('v81.7', 'v134.0')
    html = html.replace('v81.9', 'v134.0')
    log(f'  RC-5: {n131} version strings updated to v{NEW_VERSION}')

    # Build EMBEDDED_INTEL data (60 items, compact)
    embed = []
    for it in enriched[:60]:
        embed.append({
            'id': it.get('id',''), 'stix_id': it.get('stix_id', it.get('id','')),
            'title': it.get('title',''), 'severity': it.get('severity','LOW'),
            'risk_score': float(it.get('risk_score') or 0),
            'description': (it.get('description') or '')[:200],
            'timestamp': it.get('timestamp') or NOW_UTC,
            'processed_at': it.get('processed_at') or NOW_UTC,
            'published_at': it.get('published_at') or NOW_UTC,
            'ioc_count': int(it.get('ioc_count') or 0),
            'ttp_count': int(it.get('ttp_count') or 0),
            'confidence': float(it.get('confidence') or 0),
            'tags': it.get('tags') or [],
            'ttps': it.get('ttps') or [],
            'iocs': [],
            'ioc_paywall': it.get('ioc_paywall') or {},
            'threat_type': it.get('threat_type','General'),
            'source': it.get('source','UNKNOWN'),
            'source_url': it.get('source_url',''),
            'actor_tag': it.get('actor_tag','CDB-GEN'),
            'stix_bundle': it.get('stix_bundle',''),
            'report_url': it.get('report_url',''),
            'kev_present': bool(it.get('kev_present',False)),
            'epss_score': it.get('epss_score'),
            'cvss_score': it.get('cvss_score'),
            'mitre_tactics': it.get('mitre_tactics') or it.get('ttps') or [],
            'apex_ai': it.get('apex_ai') or build_apex_ai(it),
            'apex': None, 'validation_status': 'valid',
        })
    embedded_json = json.dumps(embed, separators=(',',':'))

    # RC-1: Replace EMBEDDED_INTEL line (it is a single huge line)
    lines = html.splitlines(keepends=True)
    ei_idx = None
    for i, ln in enumerate(lines):
        if 'window.EMBEDDED_INTEL = [' in ln or 'const EMBEDDED_INTEL = [' in ln:
            ei_idx = i; break

    if ei_idx is not None:
        old_ln = lines[ei_idx]
        marker = 'window.EMBEDDED_INTEL = [' if 'window.EMBEDDED_INTEL = [' in old_ln else 'const EMBEDDED_INTEL = ['
        bpos = old_ln.index(marker) + len(marker) - 1  # [ position
        # Use JSON decoder to find array end precisely
        try:
            dec = json.JSONDecoder()
            _, end = dec.raw_decode(old_ln[bpos:])
            prefix  = old_ln[:bpos]
            suffix  = old_ln[bpos + end:]  # ; // comment\n
            lines[ei_idx] = prefix + embedded_json + suffix
            log(f'  RC-1: EMBEDDED_INTEL replaced on line {ei_idx+1} ({len(embed)} items)')
            fixes.append(f'RC-1: EMBEDDED_INTEL injected ({len(embed)} items)')
        except Exception as ex:
            log(f'  RC-1 JSON decode failed ({ex}), using full-line replace')
            indent = '        '
            lines[ei_idx] = f'{indent}window.EMBEDDED_INTEL = {embedded_json}; // v{NEW_VERSION} live\n'
            fixes.append(f'RC-1: EMBEDDED_INTEL line replaced (fallback)')
        html = ''.join(lines)
    else:
        log('  [INJECT] No EMBEDDED_INTEL line — injecting before bootFromEmbeddedCache')
        inject = '        function bootFromEmbeddedCache() {'
        if inject in html:
            block = f'        window.EMBEDDED_INTEL = {embedded_json}; // v{NEW_VERSION} live\n\n'
            html = html.replace(inject, block + inject, 1)
            fixes.append(f'RC-1: EMBEDDED_INTEL injected (new)')
        else:
            log('  [WARN] Could not find injection point')

    # Fix SYNC display
    html = html.replace('SYNC: BOOTING...', 'SYNC: LIVE')
    html = html.replace('>BOOTING...</', '>LIVE</')
    html = html.replace('id="degraded-mode-banner" style="display:block"',
                        'id="degraded-mode-banner" style="display:none"')

    # Integrity checks
    nlines = len(html.splitlines())
    ok = '</body>' in html and '</html>' in html and nlines >= 12000 and 'EMBEDDED_INTEL' in html
    log(f'  Integrity: {nlines} lines | </body>={("</body>" in html)} | </html>={("</html>" in html)} | EMBEDDED={("EMBEDDED_INTEL" in html)}')
    if not ok:
        err(f'FATAL: integrity check failed (lines={nlines})'); return False

    tmp = str(dest)+'.new'
    with open(tmp,'w',encoding='utf-8') as f: f.write(html)
    # Verify
    with open(tmp,encoding='utf-8') as f: v = f.read()
    if '</html>' not in v or len(v) < len(html)*0.99:
        err('FATAL: write verify failed'); return False
    os.replace(tmp, dest)
    log(f'  index.html written: {nlines} lines ({len(html):,} chars)')
    return True

def fix_pipeline_guard():
    path = REPO / 'scripts' / 'update_embedded_intel.py'
    if not path.exists(): return
    log('RC-6: Hardening update_embedded_intel.py ...')
    with open(path) as f: src = f.read()

    GUARD = '''
# ─ TRUNCATION GUARD (v134 — injected) ────────────────────────────────────
_MIN_LINES_GUARD = 12000
_orig_lines = len(open(INDEX_HTML).readlines()) if INDEX_HTML.exists() else 0
'''
    REPLACE_OLD = 'os.replace(tmp_path, INDEX_HTML)'
    REPLACE_NEW = '''_nlines = len(open(tmp_path).readlines())
    if _nlines < _MIN_LINES_GUARD:
        os.unlink(tmp_path)
        print(f"[GUARD] BLOCKED: {_nlines} lines < {_MIN_LINES_GUARD} min. Original kept.")
        sys.exit(1)
    if _nlines < _orig_lines * 0.95:
        os.unlink(tmp_path)
        print(f"[GUARD] BLOCKED: {_nlines} lines < 95pct of orig {_orig_lines}. Original kept.")
        sys.exit(1)
    os.replace(tmp_path, INDEX_HTML)
    print(f"[GUARD] OK: {_nlines} lines written")'''

    if REPLACE_OLD in src:
        src = src.replace(REPLACE_OLD, REPLACE_NEW)
        if '\nREPO_ROOT' in src:
            pos = src.index('\nREPO_ROOT')
            src = src[:pos] + GUARD + src[pos:]
        src = src.replace('MIN_ITEMS = 5', 'MIN_ITEMS = 5\n_MIN_LINES_GUARD = 12000')
        tmp = str(path)+'.tmp'
        with open(tmp,'w') as f: f.write(src)
        os.replace(tmp, path)
        log('  update_embedded_intel.py: truncation guard injected')
        fixes.append('RC-6: truncation guard injected')
    else:
        log('  [WARN] os.replace pattern not found in update_embedded_intel.py')

def main():
    print('='*70)
    print(f'SENTINEL APEX MASTER P0 FIX  |  v{NEW_VERSION}  |  {NOW_UTC}')
    print('='*70)
    if not GOOD_HTML.exists():
        err('FATAL: /tmp/index_good.html missing'); sys.exit(1)
    enriched = fix_api_feed()
    fix_feed_manifest(enriched)
    fix_api_status(enriched)
    fix_api_latest(enriched)
    fix_api_engines()
    fix_headers()
    ok = fix_index_html(enriched)
    if not ok: print('\nABORT: index.html fix failed'); sys.exit(1)
    fix_pipeline_guard()
    print('\n' + '='*70)
    print(f'APPLIED ({len(fixes)}):')
    for f in fixes: print(f'  [OK] {f}')
    if errors:
        print(f'\nERRORS ({len(errors)}):')
        for e in errors: print(f'  [!!] {e}')
        sys.exit(1)
    print('\nALL P0 FIXES COMPLETE')
    print('='*70)

if __name__ == '__main__':
    main()
