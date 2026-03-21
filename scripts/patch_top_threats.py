#!/usr/bin/env python3
"""
SENTINEL APEX v73.0 — Feature Enhancement Patcher
====================================================
Enhances TWO features with ZERO REGRESSION:

1. renderTopThreats() — Replaces basic card grid with production-grade
   actionable threat cards (severity badges, CVEs, MITRE, time-ago, source)

2. intel-status-bar — Wires up "Last Sync", "New Intel", "Filtered" counters

SAFE: Only replaces the renderTopThreats function body.
Does NOT touch EMBEDDED_INTEL, boot sequence, or any other function.

Run: python3 scripts/patch_top_threats.py
"""

import os
import re
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(REPO_ROOT, "index.html")

# The enhanced renderTopThreats function
ENHANCED_FUNCTION = r'''function renderTopThreats(data) {
    const container = document.getElementById('top-threats-section');
    if (!container) return;

    const top = getTopThreats(data);

    if (!top.length) {
        container.innerHTML = '';
        return;
    }

    // Wire up intel-status-bar counters
    try {
        const lastEl = document.getElementById('intel-last-update');
        const newEl = document.getElementById('intel-new-count');
        const dedupEl = document.getElementById('intel-dedup-count');
        const now = Date.now();
        const recent = data.filter(d => {
            const ts = new Date(d.timestamp || 0).getTime();
            return (now - ts) < 86400000;
        }).length;
        if (lastEl) {
            const newest = data.reduce((best, d) => {
                const t = new Date(d.timestamp || 0).getTime();
                return t > best ? t : best;
            }, 0);
            if (newest > 0) {
                const diff = Math.floor((now - newest) / 60000);
                lastEl.textContent = 'Last Sync: ' + (diff < 60 ? diff + 'm ago' : Math.floor(diff/60) + 'h ago');
            }
        }
        if (newEl) newEl.textContent = 'New Intel: ' + recent;
        if (dedupEl) dedupEl.textContent = 'Filtered: ' + data.length;
    } catch(e) {}

    function getSev(score) {
        if (score >= 9) return { label: 'CRITICAL', cls: 'cdb-sev-crit', color: '#dc2626' };
        if (score >= 7) return { label: 'HIGH', cls: 'cdb-sev-high', color: '#ea580c' };
        if (score >= 4) return { label: 'MEDIUM', cls: 'cdb-sev-med', color: '#d97706' };
        return { label: 'LOW', cls: 'cdb-sev-low', color: '#16a34a' };
    }

    function timeAgo(ts) {
        if (!ts) return '';
        const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
        if (diff < 1) return 'Just now';
        if (diff < 60) return diff + 'm ago';
        if (diff < 1440) return Math.floor(diff / 60) + 'h ago';
        return Math.floor(diff / 1440) + 'd ago';
    }

    function extractCVE(title) {
        const m = (title || '').match(/CVE-\d{4}-\d{4,}/i);
        return m ? m[0] : null;
    }

    const cards = top.map((item, idx) => {
        const score = item.risk_score || 0;
        const sev = getSev(score);
        const cve = extractCVE(item.title);
        const tactics = (item.mitre_tactics || []).slice(0, 3);
        const source = (item.feed_source || item.source_url || '').replace(/https?:\/\//,'').split('/')[0] || '';
        const age = timeAgo(item.timestamp);
        const kev = item.kev_present ? '<span style="display:inline-block;background:rgba(220,38,38,0.12);color:#dc2626;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;margin-left:4px;">KEV</span>' : '';
        const epss = item.epss_score ? '<span style="font-size:9px;color:var(--text-muted);">EPSS ' + (item.epss_score * 100).toFixed(1) + '%</span>' : '';

        return '<div style="background:var(--bg-card);border:1px solid var(--border);padding:0;overflow:hidden;position:relative;transition:border-color 0.2s,transform 0.2s;" onmouseover="this.style.borderColor=\'' + sev.color + '30\';this.style.transform=\'translateY(-2px)\'" onmouseout="this.style.borderColor=\'var(--border)\';this.style.transform=\'none\'">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px 0;">' +
                '<div style="display:flex;align-items:center;gap:6px;">' +
                    '<span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);opacity:0.5;">#' + (idx + 1) + '</span>' +
                    '<span style="display:inline-block;background:' + sev.color + '18;color:' + sev.color + ';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;font-family:var(--font-mono);letter-spacing:0.5px;">' + sev.label + '</span>' +
                    kev +
                '</div>' +
                '<span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">' + age + '</span>' +
            '</div>' +
            '<div style="padding:8px 14px 6px;">' +
                '<div style="font-size:12px;font-weight:700;color:var(--white);line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">' +
                    (item.title || 'Unknown Threat').substring(0, 100) +
                '</div>' +
            '</div>' +
            '<div style="padding:0 14px 10px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">' +
                (cve ? '<span style="display:inline-block;background:rgba(59,130,246,0.1);color:#3b82f6;padding:1px 6px;border-radius:3px;font-size:9px;font-family:var(--font-mono);">' + cve + '</span>' : '') +
                tactics.map(function(t) { return '<span style="display:inline-block;background:rgba(139,92,246,0.1);color:#8b5cf6;padding:1px 5px;border-radius:3px;font-size:8px;font-family:var(--font-mono);">' + t + '</span>'; }).join('') +
                (source ? '<span style="font-size:8px;color:var(--text-muted);margin-left:auto;">' + source.substring(0, 25) + '</span>' : '') +
            '</div>' +
            '<div style="height:3px;background:linear-gradient(90deg,' + sev.color + ' ' + Math.min(score * 10, 100) + '%,transparent ' + Math.min(score * 10, 100) + '%);"></div>' +
        '</div>';
    }).join('');

    container.innerHTML = '' +
        '<div style="margin-bottom:15px;">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">' +
                '<div style="display:flex;align-items:center;gap:12px;">' +
                    '<div id="intel-status-bar" class="intel-status" style="display:flex;gap:16px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">' +
                        '<span style="color:var(--accent);">&#x1f6f0; STATUS: ACTIVE</span>' +
                        '<span id="intel-last-update">Last Sync: ' + (function() {
                            var newest = data.reduce(function(b, d) { var t = new Date(d.timestamp || 0).getTime(); return t > b ? t : b; }, 0);
                            if (!newest) return '--';
                            var diff = Math.floor((Date.now() - newest) / 60000);
                            return diff < 60 ? diff + 'm ago' : Math.floor(diff / 60) + 'h ago';
                        })() + '</span>' +
                        '<span id="intel-new-count">New Intel: ' + data.filter(function(d) { return (Date.now() - new Date(d.timestamp || 0).getTime()) < 86400000; }).length + '</span>' +
                        '<span id="intel-dedup-count">Filtered: ' + data.length + '</span>' +
                    '</div>' +
                '</div>' +
                '<div style="font-family:var(--font-mono);font-size:10px;color:var(--accent);letter-spacing:3px;">' +
                    '&#x1f525; TOP 10 ACTIONABLE THREATS' +
                '</div>' +
            '</div>' +
        '</div>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;">' +
            cards +
        '</div>';
}'''


def main():
    print("=" * 60)
    print("  SENTINEL APEX v73.0 — TOP 10 Threats Enhancement")
    print("=" * 60)

    if not os.path.exists(INDEX_HTML):
        print("  FATAL: index.html not found")
        sys.exit(1)

    with open(INDEX_HTML, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    print(f"  Loaded: {len(content):,} bytes")

    # Check if already enhanced
    if 'cdb-sev-crit' in content:
        print("  ALREADY ENHANCED — v73 markers detected. Skipping.")
        sys.exit(0)

    # Find the existing renderTopThreats function
    func_pattern = re.compile(r'function\s+renderTopThreats\s*\(\s*data\s*\)\s*\{')
    match = func_pattern.search(content)
    if not match:
        print("  ERROR: renderTopThreats function not found")
        sys.exit(1)

    func_start = match.start()

    # Brace-match to find end
    depth = 0
    pos = content.index('{', func_start)
    while pos < len(content):
        ch = content[pos]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                func_end = pos + 1
                break
        elif ch in ("'", '"', '`'):
            q = ch
            pos += 1
            while pos < len(content) and content[pos] != q:
                if content[pos] == '\\': pos += 1
                pos += 1
        pos += 1

    old_func = content[func_start:func_end]
    print(f"  Old function: {len(old_func)} chars at [{func_start}:{func_end}]")

    # Create backup
    backup = INDEX_HTML + '.pre_v73'
    shutil.copy2(INDEX_HTML, backup)

    # Replace
    new_content = content[:func_start] + ENHANCED_FUNCTION + content[func_end:]

    # Verify EMBEDDED_INTEL still present
    if 'const EMBEDDED_INTEL' not in new_content:
        print("  FATAL: EMBEDDED_INTEL lost during patch — rolling back")
        shutil.copy2(backup, INDEX_HTML)
        sys.exit(1)

    # Verify brace balance of the new function (quick check)
    d = 0
    for ch in ENHANCED_FUNCTION:
        if ch == '{': d += 1
        elif ch == '}': d -= 1
    if d != 0:
        print(f"  FATAL: Enhanced function has brace imbalance ({d}) — rolling back")
        shutil.copy2(backup, INDEX_HTML)
        sys.exit(1)

    with open(INDEX_HTML, 'w', encoding='utf-8') as f:
        f.write(new_content)

    os.remove(backup)
    print(f"  Patched: {len(new_content):,} bytes (delta: {len(new_content) - len(content):+,})")
    print("  TOP 10 ACTIONABLE THREATS: Enhanced with severity badges, CVE tags,")
    print("    MITRE tactics, KEV markers, EPSS scores, time-ago, risk bars")
    print("  Intel status bar: Wired to live data counters")
    print("  SUCCESS")
    print("=" * 60)


if __name__ == "__main__":
    main()
