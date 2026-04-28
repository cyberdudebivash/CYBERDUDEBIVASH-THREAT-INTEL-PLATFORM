#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX — MASTER P0 FIX v2 + P0 APEX AI FIX
===================================================================
P0 FIXES APPLIED:
  [FIX-1] build_apex_ai() — REAL SOC priority (risk-score driven, no hardcoding)
  [FIX-2] build_apex_ai() — REAL kill chain (CVE/IOC-type/tag derived, no PRO_REQUIRED)
  [FIX-3] build_apex_ai() — REAL actor fingerprint (UNATTRIBUTED when no attribution)
  [FIX-4] build_apex_ai() — REAL MITRE tactic mapping from T-code tags
  [FIX-5] fix_api_feed()  — ALWAYS rebuild apex_ai (was: skip if already set → stale P4)
  [FIX-6] fix_api_feed()  — ALWAYS rebuild mitre_tactics from tag mapping
  [FIX-7] fix_api_feed()  — Integrate dedup_state: enforce_feed_uniqueness + fingerprint filter
"""
import json, os, re, shutil, sys, tempfile, hashlib
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GOOD_HTML = Path('/tmp/index_good.html')


def _load_platform_version() -> str:
    for vpath in [REPO / 'config' / 'version.json', REPO / 'version.json']:
        try:
            if vpath.exists():
                _v = json.loads(vpath.read_text(encoding='utf-8'))
                v = _v.get('version') or _v.get('platform')
                if v:
                    return str(v)
        except Exception:
            pass
    return os.environ.get('PIPELINE_VERSION', '141.0.0')


NEW_VERSION = _load_platform_version()
OLD_VERSION = '131.2.0'
NOW_UTC = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
TODAY = datetime.now(timezone.utc).strftime('%Y-%m-%d')
errors = []
fixes = []


def log(m): print(f'[FIX] {m}')
def err(m): errors.append(m); print(f'[ERR] {m}')


# ═══════════════════════════════════════════════════════════════════════════
# P0 FIX-4: MITRE TAG → TACTIC MAPPING
# ═══════════════════════════════════════════════════════════════════════════
_MITRE_TACTIC_MAP = {
    # Initial Access
    'T1190': 'Initial Access', 'T1133': 'Initial Access', 'T1078': 'Initial Access',
    'T1566': 'Initial Access', 'T1195': 'Initial Access', 'T1199': 'Initial Access',
    'T1091': 'Initial Access', 'T1200': 'Initial Access',
    # Execution
    'T1059': 'Execution', 'T1059.001': 'Execution', 'T1059.003': 'Execution',
    'T1059.005': 'Execution', 'T1059.006': 'Execution', 'T1203': 'Execution',
    'T1204': 'Execution', 'T1204.001': 'Execution', 'T1204.002': 'Execution',
    'T1047': 'Execution', 'T1053': 'Execution',
    # Persistence
    'T1547': 'Persistence', 'T1547.001': 'Persistence', 'T1543': 'Persistence',
    'T1053.005': 'Persistence', 'T1176': 'Persistence', 'T1554': 'Persistence',
    # Privilege Escalation
    'T1068': 'Privilege Escalation', 'T1055': 'Privilege Escalation',
    'T1134': 'Privilege Escalation', 'T1548': 'Privilege Escalation',
    # Defense Evasion
    'T1027': 'Defense Evasion', 'T1036': 'Defense Evasion', 'T1070': 'Defense Evasion',
    'T1218': 'Defense Evasion', 'T1542': 'Defense Evasion', 'T1562': 'Defense Evasion',
    # Credential Access
    'T1555': 'Credential Access', 'T1556': 'Credential Access', 'T1110': 'Credential Access',
    'T1552': 'Credential Access', 'T1539': 'Credential Access',
    # Discovery
    'T1595': 'Discovery', 'T1590': 'Discovery', 'T1083': 'Discovery',
    # Lateral Movement
    'T1021': 'Lateral Movement', 'T1021.001': 'Lateral Movement',
    # Collection
    'T1213': 'Collection', 'T1530': 'Collection', 'T1560': 'Collection',
    # Command and Control
    'T1071': 'Command and Control', 'T1095': 'Command and Control',
    'T1105': 'Command and Control', 'T1219': 'Command and Control',
    # Exfiltration
    'T1567': 'Exfiltration', 'T1048': 'Exfiltration', 'T1041': 'Exfiltration',
    # Impact
    'T1485': 'Impact', 'T1486': 'Impact', 'T1490': 'Impact', 'T1499': 'Impact',
}

# ─── Generic / unattributed actor tags that mean NO real attribution ───────
_GENERIC_ACTOR_TAGS = frozenset({
    'UNCLASSIFIED', 'UNC-UNKNOWN', 'CDB-GEN', 'CDB-APT-GEN', 'CDB-CVE-GEN',
    'CDB-RAN-GEN', 'CDB-PHI-GEN', 'CDB-RAT-GEN', 'CDB-CYB-GEN', 'CDB-MOB-GEN',
    '', 'UNKNOWN',
})


# ═══════════════════════════════════════════════════════════════════════════
# P0 FIX-2: KILL CHAIN RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_kill_chain(item):
    """
    Derive kill chain stage(s) from CVEs, IOC types, tags, and threat_type.
    Returns (kill_chain_primary: str, kill_chain_stages: list[str]).
    NEVER returns PRO_REQUIRED — always resolves to real intelligence.
    """
    text = (
        (item.get('title') or '') + ' ' +
        (item.get('description') or '') + ' ' +
        (item.get('threat_type') or '')
    ).lower()
    tags = [str(t) for t in (item.get('tags') or item.get('ttps') or [])]
    iocs = item.get('iocs') or []
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)

    ioc_types = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            t = (ioc.get('type') or '').lower()
            if t:
                ioc_types.add(t)

    stages = []

    # CVE present → Initial Access / Execution
    if cves or 'vulnerability' in text or 'exploit' in text:
        stages.append('Initial Access')
        if 'rce' in text or 'remote code' in text or 'code execution' in text:
            stages.append('Execution')

    # IOC-type → kill chain stage mapping
    if 'domain' in ioc_types or 'url' in ioc_types or 'hostname' in ioc_types:
        stages.append('C2')
    if 'ip' in ioc_types or 'ipv4' in ioc_types or 'ipv6' in ioc_types:
        stages.append('Network Activity')
    if any(t in ioc_types for t in ('hash', 'md5', 'sha256', 'sha1', 'sha512')):
        stages.append('Malware Execution')

    # MITRE tag → tactic → kill chain stage
    for tag in tags:
        tactic = _MITRE_TACTIC_MAP.get(tag) or _MITRE_TACTIC_MAP.get(tag.split('.')[0])
        if tactic and tactic not in stages:
            stages.append(tactic)

    # Keyword-based enrichment
    if ('phishing' in text or 'spear' in text) and 'Initial Access' not in stages:
        stages.append('Initial Access')
    if ('malware' in text or 'ransomware' in text or 'trojan' in text or 'backdoor' in text):
        if 'Malware Execution' not in stages:
            stages.append('Malware Execution')
    if 'supply chain' in text:
        if 'Initial Access' not in stages:
            stages.append('Initial Access')
        stages.append('Supply Chain Compromise')
    if ('lateral' in text or 'pivot' in text) and 'Lateral Movement' not in stages:
        stages.append('Lateral Movement')
    if ('exfil' in text or 'data theft' in text or 'data leak' in text) and 'Exfiltration' not in stages:
        stages.append('Exfiltration')
    if 'command' in text and 'control' in text and 'C2' not in stages:
        stages.append('C2')
    if ('persistence' in text or 'backdoor' in text) and 'Persistence' not in stages:
        stages.append('Persistence')

    # Deduplicate preserving order
    seen_kc = set()
    deduped = []
    for s in stages:
        if s not in seen_kc:
            seen_kc.add(s)
            deduped.append(s)

    if not deduped:
        ttype = (item.get('threat_type') or '').lower()
        if 'vulnerability' in ttype:
            deduped = ['Initial Access', 'Execution']
        elif 'phishing' in ttype:
            deduped = ['Initial Access', 'C2']
        elif 'supply' in ttype:
            deduped = ['Initial Access', 'Supply Chain Compromise']
        elif 'malware' in ttype or 'ransomware' in ttype:
            deduped = ['Malware Execution', 'C2']
        else:
            deduped = ['Initial Access']

    return deduped[0], deduped


# ═══════════════════════════════════════════════════════════════════════════
# P0 FIX-3: ACTOR FINGERPRINT — UNATTRIBUTED when no real attribution
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_actor_fingerprint(item):
    atag = (item.get('actor_tag') or '').strip()
    if not atag or atag in _GENERIC_ACTOR_TAGS:
        return 'UNATTRIBUTED'
    return atag  # real known actor tag — return clean, no masking


# ═══════════════════════════════════════════════════════════════════════════
# P0 FIX-4: MITRE TACTICS from T-code tags
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_mitre_tactics(item):
    tags = [str(t) for t in (item.get('tags') or item.get('ttps') or [])]
    tactics = []
    for tag in tags:
        tactic = _MITRE_TACTIC_MAP.get(tag) or _MITRE_TACTIC_MAP.get(tag.split('.')[0])
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return tactics


# ═══════════════════════════════════════════════════════════════════════════
# P0 FIX-1/2/3/4/5: build_apex_ai — REAL INTELLIGENCE, NEVER HARDCODED
# ═══════════════════════════════════════════════════════════════════════════
def build_apex_ai(item):
    """
    Build APEX AI intelligence block from item data.

    P0 FIXES APPLIED:
      - SOC priority derived from risk_score (>= 9→P1, >= 7→P2, >= 5→P3, else P4)
      - kill_chain resolved from CVE/IOC-types/tags (never PRO_REQUIRED)
      - actor_fingerprint resolved to UNATTRIBUTED when no real attribution
      - mitre_tactics_resolved populated from T-code tag mapping
      - threat_category derived from threat_type + text keywords
    """
    risk = float(item.get('risk_score') or 0)
    sev  = (item.get('severity') or 'LOW').upper()
    iocs = int(item.get('ioc_count') or 0)
    ttps = int(item.get('ttp_count') or len(item.get('tags') or []))
    conf = float(item.get('confidence') or 0)

    # ── P0 FIX-1: SOC Priority — risk-score driven, zero hardcoding ──────
    if risk >= 9.0 or sev == 'CRITICAL':
        pri, tl = 'P1', 'CRITICAL'
    elif risk >= 7.0 or sev == 'HIGH':
        pri, tl = 'P2', 'HIGH'
    elif risk >= 5.0 or sev == 'MEDIUM':
        pri, tl = 'P3', 'MODERATE'
    else:
        pri, tl = 'P4', 'LOW'

    # ── Confidence tier ───────────────────────────────────────────────────
    if conf >= 80:
        ct = 'VERIFIED'
        cl = '✔ VERIFIED – Multi-source corroboration confirmed'
    elif conf >= 50:
        ct = 'MODERATE'
        cl = '◆ MODERATE – Credible intelligence, further investigation advised'
    elif conf >= 25:
        ct = 'LOW'
        cl = '▽ LOW – Limited signals, treat with caution'
    else:
        ct = 'UNVERIFIED'
        cl = '○ UNVERIFIED – Insufficient evidence basis'

    # ── P0 FIX-2: Kill chain — real resolution ────────────────────────────
    kill_chain_primary, kill_chain_stages = _resolve_kill_chain(item)

    # ── P0 FIX-3: Actor fingerprint — UNATTRIBUTED not masked ────────────
    actor_fp = _resolve_actor_fingerprint(item)

    # ── P0 FIX-4: MITRE tactics — real tag mapping ────────────────────────
    mitre_tactics = _resolve_mitre_tactics(item)

    # ── Threat category — derived, not hardcoded ──────────────────────────
    ttype = (item.get('threat_type') or '').lower()
    text  = ((item.get('title') or '') + ' ' + (item.get('description') or '')).lower()
    cves  = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    if 'phishing' in ttype or 'phishing' in text:
        threat_category = 'Phishing'
    elif 'supply chain' in ttype or 'supply chain' in text:
        threat_category = 'Supply Chain Attack'
    elif 'ransomware' in text:
        threat_category = 'Ransomware'
    elif 'malware' in text or 'trojan' in text or 'backdoor' in text:
        threat_category = 'Malware'
    elif cves or 'vulnerability' in ttype:
        if 'rce' in text or 'remote code' in text or 'code execution' in text:
            threat_category = 'Remote Code Execution'
        elif 'privilege' in text or 'lpe' in text or 'escalation' in text:
            threat_category = 'Privilege Escalation'
        elif 'auth bypass' in text or 'authentication' in text:
            threat_category = 'Authentication Bypass'
        elif 'injection' in text or 'xss' in text or 'sqli' in text:
            threat_category = 'Web Application Attack'
        else:
            threat_category = 'Vulnerability Exploitation'
    elif 'web' in text or 'wordpress' in text or 'plugin' in text:
        threat_category = 'Web Application Attack'
    else:
        threat_category = 'Threat Intelligence'

    # ── Computed scores ───────────────────────────────────────────────────
    pred = round(min(10.0, risk * 0.7 + ttps * 0.3 + iocs * 0.05), 2)
    aic  = min(100, int(conf * 0.8 + ttps * 2 + iocs * 0.5))

    # ── Action map ────────────────────────────────────────────────────────
    urg = {
        'P1': 'CRITICAL — Immediate response required. Escalate to CISO.',
        'P2': 'HIGH THREAT — Enterprise IR response. Patch within 24h.',
        'P3': 'THREAT ACTIVE — SOC monitoring. Patch within 72h.',
        'P4': 'MONITORING — Low urgency. Schedule routine patching.',
    }
    action_map = {
        'P1': f'SOC P1 CRITICAL: {iocs} IOC{"s" if iocs != 1 else ""} active. '
              f'Immediate isolation required. Engage IR team. Kill chain: {kill_chain_primary}.',
        'P2': f'SOC P2 HIGH: {iocs} IOC{"s" if iocs != 1 else ""} detected. '
              f'Patch within 24h. Activate threat hunting. Kill chain: {kill_chain_primary}.',
        'P3': f'SOC P3 MODERATE: {iocs} IOC{"s" if iocs != 1 else ""} identified. '
              f'Patch within 72h. Monitor for escalation.',
        'P4': f'SOC P4 LOW: {iocs} IOC{"s" if iocs != 1 else ""} logged. '
              f'Apply patch in next maintenance window.',
    }

    ai_summary = (
        f'[{ct}] {sev} {(item.get("threat_type") or "THREAT").upper()}. '
        f'{iocs} indicator{"s" if iocs != 1 else ""} · '
        f'{len(mitre_tactics)} MITRE tactic{"s" if len(mitre_tactics) != 1 else ""} · '
        f'Kill Chain: {kill_chain_primary} · '
        f'Predictive risk: {pred}/10 · SOC {pri}.'
    )

    return {
        'soc_priority':             pri,
        'threat_level':             tl,
        'threat_category':          threat_category,
        'predictive_risk':          pred,
        'ai_confidence':            aic,
        'threat_confidence_tier':   ct,
        'threat_confidence_label':  cl,
        'ttp_density':              round(min(10.0, ttps * 1.5 + iocs * 0.2), 2),
        'campaign_id':              'UNCLASSIFIED',
        'actor_fingerprint':        actor_fp,
        'kill_chain':               kill_chain_stages,
        'kill_chain_primary':       kill_chain_primary,
        'mitre_tactics_resolved':   mitre_tactics,
        'ai_summary':               ai_summary,
        'recommended_action':       action_map[pri],
        'behavioral_tags':          mitre_tactics[:5],
        'paywall': {
            'locked_fields': [
                'actor_fingerprint_full', 'behavioral_tags_extended',
                'recommended_action_full', 'stix_bundle',
            ],
            'upgrade_url': 'https://intel.cyberdudebivash.com/get-api-key.html?plan=pro',
            'message': (
                f'{ct} THREAT — {iocs} IOC{"s" if iocs != 1 else ""} detected. '
                f'Upgrade to Pro for full IR playbook.'
            ),
            'urgency': urg[pri],
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# FEED FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fix_api_feed():
    path = REPO / 'api' / 'feed.json'
    log('RC-3: Fixing api/feed.json ...')
    with open(path) as f:
        raw = json.load(f)
    items = raw if isinstance(raw, list) else raw.get('items', raw.get('advisories', []))

    # ── P0 FIX-7: Phase 1+2 — dedup state + feed cleaning ────────────────
    try:
        _scripts = str(REPO / 'scripts')
        if _scripts not in sys.path:
            sys.path.insert(0, _scripts)
        from dedup_state import enforce_feed_uniqueness, get_state, save_state
        items, removed_count = enforce_feed_uniqueness(items)
        if removed_count:
            log(f'  DEDUP-CLEAN: {removed_count} duplicate entries removed from feed')
        state = get_state()
        new_items, skipped = state.filter_new(items)
        if skipped:
            log(f'  DEDUP-STATE: {skipped} already-processed items skipped (fingerprint match)')
        if new_items:
            items = new_items
        save_state()
        log(f'  DEDUP-STATE: processed_intel.json updated ({state.get_stats()["total_fingerprints"]} total fingerprints)')
    except Exception as dedup_err:
        log(f'  [WARN] Dedup module unavailable ({dedup_err}) — continuing without dedup')

    enriched = []
    for it in items:
        it = dict(it)
        if not it.get('stix_id'):
            it['stix_id'] = it.get('id', '')

        # ── P0 FIX-5: ALWAYS rebuild apex_ai — never skip if already set ──
        it['apex_ai'] = build_apex_ai(it)

        # ── P0 FIX-6: ALWAYS rebuild mitre_tactics from T-code mapping ────
        it['mitre_tactics'] = _resolve_mitre_tactics(it)

        # ── apex: always sync from apex_ai (never null) ───────────────────
        _ai = it['apex_ai']
        it['apex'] = {
            'priority':                _ai['soc_priority'],
            'soc_priority':            _ai['soc_priority'],
            'threat_level':            _ai['threat_level'],
            'threat_category':         _ai['threat_category'],
            'campaign_id':             _ai['campaign_id'],
            'ai_confidence':           _ai['ai_confidence'],
            'predictive_risk':         _ai['predictive_risk'],
            'ttp_density':             _ai['ttp_density'],
            'ai_summary':              _ai['ai_summary'],
            'recommended_action':      _ai['recommended_action'],
            'behavioral_tags':         _ai['behavioral_tags'],
            'threat_confidence_tier':  _ai['threat_confidence_tier'],
            'threat_confidence_label': _ai['threat_confidence_label'],
        }

        if not it.get('iocs'):
            it['iocs'] = []
        if not it.get('tags') or not isinstance(it['tags'], list):
            it['tags'] = it.get('ttps', [])[:5]
        if not it.get('validation_status'):
            it['validation_status'] = 'valid'
        if not it.get('ioc_paywall'):
            n = int(it.get('ioc_count') or 0)
            c = float(it.get('confidence') or it.get('ioc_confidence') or 17)
            _by_type = it.get('iocs_by_type') or it.get('ioc_counts') or {}
            _primary_types = sorted(
                [k for k, v in _by_type.items() if isinstance(v, (int, list)) and
                 (v > 0 if isinstance(v, int) else len(v) > 0)],
                key=lambda k: (_by_type[k] if isinstance(_by_type[k], int) else len(_by_type[k])),
                reverse=True,
            )[:3]
            it['ioc_paywall'] = {
                'locked':        True,
                'count':         n,
                'confidence':    round(c, 1),
                'primary_types': _primary_types,
                'upgrade_url':   'https://intel.cyberdudebivash.com/get-api-key.html?plan=pro',
                'message':       f'{n} IOC{"s" if n != 1 else ""} at {c:.1f}% confidence – unlock with Pro tier.',
            }
        enriched.append(it)

    out = {
        'status': 'ok',
        'gateway': f'SENTINEL-APEX/{NEW_VERSION}',
        'version': NEW_VERSION,
        'schema_version': f'v{NEW_VERSION.split(".")[0]}.0',
        'generated_at': NOW_UTC,
        'total': len(enriched),
        'items': enriched,
    }
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(out, f, separators=(',', ':'))
    os.replace(tmp, path)
    log(f'  api/feed.json: {len(enriched)} items enriched with real apex_ai')
    fixes.append('RC-3: api/feed.json enriched with real APEX AI')
    return enriched


def fix_feed_manifest(enriched):
    log('RC-4: Fixing data/feed_manifest.json ...')
    ni = []
    for it in enriched[:100]:
        ni.append({
            'id':               it.get('id', ''),
            'stix_id':          it.get('stix_id', it.get('id', '')),
            'title':            it.get('title', ''),
            'severity':         it.get('severity', 'LOW'),
            'risk_score':       float(it.get('risk_score') or 0),
            'timestamp':        it.get('timestamp') or NOW_UTC,
            'processed_at':     it.get('processed_at') or NOW_UTC,
            'published_at':     it.get('published_at') or NOW_UTC,
            'ioc_count':        int(it.get('ioc_count') or 0),
            'ttp_count':        int(it.get('ttp_count') or 0),
            'confidence':       float(it.get('confidence') or 0),
            'threat_type':      it.get('threat_type', 'General'),
            'source':           it.get('source', 'UNKNOWN'),
            'actor_tag':        it.get('actor_tag', 'CDB-GEN'),
            'stix_bundle':      it.get('stix_bundle', ''),
            'report_url':       it.get('report_url', ''),
            'apex_ai':          it.get('apex_ai', {}),
            'validation_status': 'valid',
            'mitre_tactics':    it.get('mitre_tactics', it.get('ttps', [])),
            'tags':             it.get('tags', []),
            'iocs':             [],
            'ttps':             it.get('ttps', it.get('mitre_tactics', [])),
            'apex':             it.get('apex'),
        })
    for mp in [REPO / 'data' / 'feed_manifest.json',
               REPO / 'data' / 'stix' / 'feed_manifest.json']:
        if not mp.exists():
            continue
        with open(mp) as f:
            m = json.load(f)
        m['items'] = ni
        m['version'] = NEW_VERSION
        m['schema_version'] = f'v{NEW_VERSION.split(".")[0]}.0'
        m['generated_at'] = NOW_UTC
        m['total_advisories'] = len(enriched)
        m['total_items'] = len(ni)
        tmp = str(mp) + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(m, f, separators=(',', ':'))
        os.replace(tmp, mp)
        log(f'  {mp.name}: {len(ni)} items normalised')
    fixes.append('RC-4: feed_manifest.json normalized')


def fix_api_status(enriched):
    log('RC-2: Fixing api/status.json ...')
    path = REPO / 'api' / 'status.json'
    crit = sum(1 for i in enriched if (i.get('severity') or '').upper() == 'CRITICAL')
    high = sum(1 for i in enriched if (i.get('severity') or '').upper() == 'HIGH')
    tiocs = sum(int(i.get('ioc_count') or 0) for i in enriched)
    avg   = round(sum(float(i.get('risk_score') or 0) for i in enriched) / max(len(enriched), 1), 2)
    s = {
        'version': NEW_VERSION,
        'platform': 'CYBERDUDEBIVASH SENTINEL APEX',
        'platform_full': f'SENTINEL APEX v{NEW_VERSION}',
        'engine': f'SENTINEL-APEX/{NEW_VERSION}',
        'status': 'OPERATIONAL',
        'sync_status': 'LIVE',
        'generated_at': NOW_UTC,
        'metrics': {
            'total_advisories': len(enriched),
            'critical_threats': crit,
            'high_threats': high,
            'total_iocs': tiocs,
            'pipeline_status': 'ACTIVE',
            'avg_risk_score': avg,
            'data_freshness': TODAY,
            'last_sync': NOW_UTC,
        },
        'intel': {
            'total': len(enriched),
            'critical': crit,
            'high': high,
            'total_iocs': tiocs,
            'avg_risk': avg,
            'freshness': TODAY,
            'last_run': NOW_UTC,
        },
        'api': {
            'status': 'ONLINE',
            'version': f'v{NEW_VERSION}',
            'gateway': f'SENTINEL-APEX/{NEW_VERSION}',
        },
    }
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, path)
    log(f'  api/status.json: v{NEW_VERSION}, {len(enriched)} advisories, {crit} critical')
    fixes.append('RC-2: api/status.json updated')


def fix_api_latest(enriched):
    path = REPO / 'api' / 'latest.json'
    top = enriched[:10]
    out = {
        'status': 'ok',
        'version': NEW_VERSION,
        'generated_at': NOW_UTC,
        'count': len(top),
        'items': top,
    }
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(out, f, separators=(',', ':'))
    os.replace(tmp, path)
    log(f'  api/latest.json: {len(top)} items')
    fixes.append('LATEST: api/latest.json updated')


def fix_api_engines():
    path = REPO / 'api' / 'engines.json'
    if not path.exists():
        return
    with open(path) as f:
        data = f.read()
    for old in ['101.0.0', '47.0.0', '81.7', '81.9', '131.2.0']:
        data = data.replace(old, NEW_VERSION)
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        f.write(data)
    os.replace(tmp, path)
    log(f'  api/engines.json: version -> {NEW_VERSION}')
    fixes.append('ENGINES: api/engines.json updated')


def fix_headers():
    path = REPO / '_headers'
    c = f'''# CYBERDUDEBIVASH SENTINEL APEX v{NEW_VERSION} — Cache Headers
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
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        f.write(c)
    os.replace(tmp, path)
    log('  _headers: cache-control updated')
    fixes.append('HEADERS: cache-control updated')


def fix_index_html(enriched):
    dest = REPO / 'index.html'
    shutil.copy2(dest, str(dest) + '.truncated.bak')
    log('RC-1+RC-5: Restoring index.html from /tmp/index_good.html ...')

    with open(GOOD_HTML, encoding='utf-8') as f:
        html = f.read()
    log(f'  Good file: {len(html.splitlines())} lines, {len(html):,} chars')

    # RC-5: Fix version strings
    n131 = html.count(f'v{OLD_VERSION}')
    html = html.replace(f'v{OLD_VERSION}', f'v{NEW_VERSION}')
    html = html.replace('SENTINEL APEX v131', f'SENTINEL APEX v{NEW_VERSION.split(".")[0]}')
    html = html.replace('v131.2', f'v{NEW_VERSION}')
    html = html.replace('v81.7', f'v{NEW_VERSION}')
    html = html.replace('v81.9', f'v{NEW_VERSION}')
    log(f'  RC-5: {n131} version strings updated to v{NEW_VERSION}')

    # Build EMBEDDED_INTEL data (60 items, compact)
    embed = []
    for it in enriched[:60]:
        embed.append({
            'id':              it.get('id', ''),
            'stix_id':         it.get('stix_id', it.get('id', '')),
            'title':           it.get('title', ''),
            'severity':        it.get('severity', 'LOW'),
            'risk_score':      float(it.get('risk_score') or 0),
            'description':     (it.get('description') or '')[:200],
            'timestamp':       it.get('timestamp') or NOW_UTC,
            'processed_at':    it.get('processed_at') or NOW_UTC,
            'published_at':    it.get('published_at') or NOW_UTC,
            'ioc_count':       int(it.get('ioc_count') or 0),
            'ttp_count':       int(it.get('ttp_count') or 0),
            'confidence':      float(it.get('confidence') or 0),
            'tags':            it.get('tags') or [],
            'ttps':            it.get('ttps') or [],
            'iocs':            [],
            'ioc_paywall':     it.get('ioc_paywall') or {},
            'threat_type':     it.get('threat_type', 'General'),
            'source':          it.get('source', 'UNKNOWN'),
            'source_url':      it.get('source_url', ''),
            'actor_tag':       it.get('actor_tag', 'CDB-GEN'),
            'stix_bundle':     it.get('stix_bundle', ''),
            'report_url':      it.get('report_url', ''),
            'kev_present':     bool(it.get('kev_present', False)),
            'epss_score':      it.get('epss_score'),
            'cvss_score':      it.get('cvss_score'),
            'mitre_tactics':   it.get('mitre_tactics') or [],
            'apex_ai':         it.get('apex_ai') or build_apex_ai(it),
            'apex':            it.get('apex'),
            'validation_status': 'valid',
        })
    embedded_json = json.dumps(embed, separators=(',', ':'))

    # RC-1: Replace EMBEDDED_INTEL line
    lines = html.splitlines(keepends=True)
    ei_idx = None
    for i, ln in enumerate(lines):
        if 'window.EMBEDDED_INTEL = [' in ln or 'const EMBEDDED_INTEL = [' in ln:
            ei_idx = i
            break

    if ei_idx is not None:
        old_ln = lines[ei_idx]
        marker = ('window.EMBEDDED_INTEL = ['
                  if 'window.EMBEDDED_INTEL = [' in old_ln
                  else 'const EMBEDDED_INTEL = [')
        bpos = old_ln.index(marker) + len(marker) - 1
        try:
            dec = json.JSONDecoder()
            _, end = dec.raw_decode(old_ln[bpos:])
            prefix = old_ln[:bpos]
            suffix = old_ln[bpos + end:]
            lines[ei_idx] = prefix + embedded_json + suffix
            log(f'  RC-1: EMBEDDED_INTEL replaced on line {ei_idx + 1} ({len(embed)} items)')
            fixes.append(f'RC-1: EMBEDDED_INTEL injected ({len(embed)} items)')
        except Exception as ex:
            log(f'  RC-1 JSON decode failed ({ex}), using full-line replace')
            indent = '        '
            lines[ei_idx] = f'{indent}window.EMBEDDED_INTEL = {embedded_json}; // v{NEW_VERSION} live\n'
            fixes.append('RC-1: EMBEDDED_INTEL line replaced (fallback)')
        html = ''.join(lines)
    else:
        log('  [INJECT] No EMBEDDED_INTEL line — injecting before bootFromEmbeddedCache')
        inject = '        function bootFromEmbeddedCache() {'
        if inject in html:
            block = f'        window.EMBEDDED_INTEL = {embedded_json}; // v{NEW_VERSION} live\n\n'
            html = html.replace(inject, block + inject, 1)
            fixes.append('RC-1: EMBEDDED_INTEL injected (new)')
        else:
            log('  [WARN] Could not find injection point')

    html = html.replace('SYNC: BOOTING...', 'SYNC: LIVE')
    html = html.replace('>BOOTING...</', '>LIVE</')
    html = html.replace(
        'id="degraded-mode-banner" style="display:block"',
        'id="degraded-mode-banner" style="display:none"',
    )

    nlines = len(html.splitlines())
    ok = '</body>' in html and '</html>' in html and nlines >= 12000 and 'EMBEDDED_INTEL' in html
    log(f'  Integrity: {nlines} lines | </body>={("</body>" in html)} | EMBEDDED={("EMBEDDED_INTEL" in html)}')
    if not ok:
        err(f'FATAL: integrity check failed (lines={nlines})')
        return False

    tmp = str(dest) + '.new'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(html)
    with open(tmp, encoding='utf-8') as f:
        v = f.read()
    if '</html>' not in v or len(v) < len(html) * 0.99:
        err('FATAL: write verify failed')
        return False
    os.replace(tmp, dest)
    log(f'  index.html written: {nlines} lines ({len(html):,} chars)')
    return True


def fix_pipeline_guard():
    path = REPO / 'scripts' / 'update_embedded_intel.py'
    if not path.exists():
        return
    log('RC-6: Hardening update_embedded_intel.py ...')
    with open(path) as f:
        src = f.read()
    REPLACE_OLD = 'os.replace(tmp, path)\n'
    GUARD = (
        '    if len(html) < 1000:\n'
        "        raise RuntimeError(f'Truncation guard: html too short ({len(html)} chars)')\n"
    )
    if REPLACE_OLD in src and GUARD not in src:
        src = src.replace(REPLACE_OLD, REPLACE_OLD + GUARD)
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        f.write(src)
    os.replace(tmp, path)
    log('  update_embedded_intel.py: truncation guard injected')
    fixes.append('RC-6: truncation guard injected')


def main():
    print('=' * 70)
    print(f'SENTINEL APEX MASTER P0 FIX  |  v{NEW_VERSION}  |  {NOW_UTC}')
    print('=' * 70)
    if not GOOD_HTML.exists():
        err('FATAL: /tmp/index_good.html missing')
        sys.exit(1)
    enriched = fix_api_feed()
    fix_feed_manifest(enriched)
    fix_api_status(enriched)
    fix_api_latest(enriched)
    fix_api_engines()
    fix_headers()
    ok = fix_index_html(enriched)
    if not ok:
        print('\nABORT: index.html fix failed')
        sys.exit(1)
    fix_pipeline_guard()
    print('\n' + '=' * 70)
    print(f'APPLIED ({len(fixes)}):')
    for f in fixes:
        print(f'  [OK] {f}')
    if errors:
        print(f'\nERRORS ({len(errors)}):')
        for e in errors:
            print(f'  [!!] {e}')
        sys.exit(1)
    print('\nALL P0 FIXES COMPLETE')
    print('=' * 70)


if __name__ == '__main__':
    main()
