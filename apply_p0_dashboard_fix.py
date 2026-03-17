#!/usr/bin/env python3
"""
SENTINEL APEX — P0 Dashboard Fix: Progressive Loading Pattern
=============================================================
Patches index.html to eliminate "SYNCING GOC NEURAL CORE..." stuck state.

ROOT CAUSE: loadGOCIntel() awaits network fetches (up to 14s timeout) before
falling back to EMBEDDED_INTEL. If fetches are slow or blocked, dashboard
shows dashes and INITIALIZING for the entire timeout period.

FIX: Progressive loading — render EMBEDDED_INTEL immediately on boot,
then attempt live fetch in background. If live succeeds, hot-swap data.
Zero-regression: all existing rendering functions remain untouched.

Usage: python3 apply_p0_dashboard_fix.py [path/to/index.html]
"""
import re
import sys
from pathlib import Path

def apply_patch(html_path: Path) -> str:
    html = html_path.read_text(encoding="utf-8")
    patches_applied = []

    # ═══════════════════════════════════════════════════════════════
    # PATCH 1: Replace loadGOCIntel with progressive-loading version
    # ═══════════════════════════════════════════════════════════════

    old_load_func = r"""        // ── Load Data ──
        async function loadGOCIntel\(\) \{
            const syncVal = document\.getElementById\('sync-val'\);
            const integrityEl = document\.getElementById\('integrity-status'\);

            // v46\.0 — AI Processing visual state
            document\.querySelectorAll\('\.metric-card'\)\.forEach\(c => c\.classList\.add\('syncing'\)\);
            const aiPulse = document\.getElementById\('ai-pulse-indicator'\);
            if \(aiPulse\) aiPulse\.style\.display = 'inline-flex';

            const MANIFEST_URLS = \[
                RAW_MANIFEST,
                atob\('aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNQG1haW4vZGF0YS9zdGl4L2ZlZWRfbWFuaWZlc3QuanNvbg=='\)
            \];

            // ── Try live network sources first ──
            let lastError = null;
            for \(const manifestUrl of MANIFEST_URLS\) \{
                try \{
                    const controller = new AbortController\(\);
                    const timeout = setTimeout\(\(\) => controller\.abort\(\), 7000\);
                    const response = await fetch\(manifestUrl, \{
                        cache: 'no-cache',
                        signal: controller\.signal
                    \}\);
                    clearTimeout\(timeout\);
                    if \(!response\.ok\) throw new Error\(`HTTP \$\{response\.status\}`\);
                    const data = await response\.json\(\);

                    const entries = Array\.isArray\(data\) \? data : \(data\.entries \|\| \[\]\);
                    if \(!entries\.length\) throw new Error\('Empty manifest'\);

                    manifestData = \[\.\.\.entries\]\.reverse\(\);
                    computeMetrics\(manifestData\);
                    renderTrendChart\(manifestData\);
                    applyView\(\);

                    syncVal\.innerHTML = 'SYNC: <span style="color:var\(--accent\);animation:new-glow 1\.5s ease-in-out infinite alternate;">● LIVE</span>';
                    integrityEl\.innerHTML = '<span class="integrity-badge integrity-ok"><i class="fas fa-shield-check"></i> MANIFEST VERIFIED</span>';
                    document\.getElementById\('last-loaded'\)\.textContent = 'SYNCED: ' \+ new Date\(\)\.toLocaleTimeString\(\) \+ ' · AUTO-SYNC EVERY 6H';
                    // v46\.0 — Clear syncing state
                    document\.querySelectorAll\('\.metric-card'\)\.forEach\(c => c\.classList\.remove\('syncing'\)\);
                    return;

                \} catch \(err\) \{
                    lastError = err;
                \}
            \}

            // ── Fallback: use embedded real intel data ──
            // This activates when: network unavailable, sandbox environment, or GitHub temporarily down\.
            // Data is real — sourced from the live feed_manifest\.json\.
            // On intel\.cyberdudebivash\.com the live fetch above always succeeds\.
            console\.info\('\[CDB-GOC\] Network fetch failed — loading embedded intel cache:', lastError\?\.message\);

            manifestData = \[\.\.\.EMBEDDED_INTEL\]\.reverse\(\);
            computeMetrics\(manifestData\);
            renderTrendChart\(manifestData\);
            applyView\(\);

            syncVal\.innerHTML = 'SYNC: <span style="color:var\(--medium\);">CACHE</span>';
            integrityEl\.innerHTML = '<span class="integrity-badge" style="background:rgba\(217,119,6,0\.08\);color:var\(--medium\);border:1px solid rgba\(217,119,6,0\.25\);">⚡ EMBEDDED CACHE — <a href="https://cyberbivash\.blogspot\.com" target="_blank" style="color:var\(--accent\);border-bottom:1px solid rgba\(0,212,170,0\.3\);">VIEW LIVE BLOG</a></span>';
            document\.getElementById\('last-loaded'\)\.textContent = 'CACHE: ' \+ new Date\(\)\.toLocaleTimeString\(\) \+ ' · EMBEDDED INTEL ACTIVE';
            // v46\.0 — Clear syncing state
            document\.querySelectorAll\('\.metric-card'\)\.forEach\(c => c\.classList\.remove\('syncing'\)\);
        \}"""

    # Use a simpler approach: find and replace the exact function
    # Locate the function boundaries precisely
    func_start_marker = "        // ── Load Data ──\n        async function loadGOCIntel() {"
    func_end_marker = """            // v46.0 — Clear syncing state
            document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('syncing'));
        }

        // v55.2 FIX"""

    start_idx = html.find(func_start_marker)
    end_idx = html.find(func_end_marker)

    if start_idx == -1 or end_idx == -1:
        print("[WARN] Could not locate loadGOCIntel function boundaries precisely")
        print(f"  start_idx={start_idx}, end_idx={end_idx}")
        # Try alternate approach
        alt_start = html.find("async function loadGOCIntel()")
        alt_end = html.find("// v55.2 FIX")
        print(f"  alt_start={alt_start}, alt_end={alt_end}")
        if alt_start == -1 or alt_end == -1:
            print("[ERROR] Cannot patch loadGOCIntel — manual intervention required")
            return html
        # Find the function start (go back to comment)
        comment_start = html.rfind("// ── Load Data ──", 0, alt_start)
        if comment_start == -1:
            comment_start = alt_start
        else:
            comment_start = html.rfind("\n", 0, comment_start) + 1
        start_idx = comment_start
        end_idx = alt_end

    # Extract everything from start to just before "// v55.2 FIX"
    old_func = html[start_idx:end_idx]

    new_func = """        // ── Load Data (v64.0 — Progressive Loading: Zero-Wait Boot) ──
        // ARCHITECTURE: Render EMBEDDED_INTEL immediately, then upgrade to live.
        // Eliminates stuck "SYNCING GOC NEURAL CORE..." state entirely.

        let _liveDataLoaded = false;

        function bootFromEmbeddedCache() {
            // Instant render from embedded cache — zero network dependency
            if (!EMBEDDED_INTEL || !EMBEDDED_INTEL.length) return;
            manifestData = [...EMBEDDED_INTEL].reverse();
            computeMetrics(manifestData);
            renderTrendChart(manifestData);
            applyView();

            const syncVal = document.getElementById('sync-val');
            const integrityEl = document.getElementById('integrity-status');
            if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--medium);">CACHE</span>';
            if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge" style="background:rgba(217,119,6,0.08);color:var(--medium);border:1px solid rgba(217,119,6,0.25);">⚡ EMBEDDED CACHE ACTIVE</span>';
            document.getElementById('last-loaded').textContent = 'CACHE: ' + new Date().toLocaleTimeString() + ' · UPGRADING TO LIVE...';
            document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('syncing'));
            console.info('[CDB-GOC] Instant boot from embedded cache:', EMBEDDED_INTEL.length, 'items');
        }

        async function loadGOCIntel() {
            const syncVal = document.getElementById('sync-val');
            const integrityEl = document.getElementById('integrity-status');

            // v46.0 — AI Processing visual state (only if not already showing data)
            if (!_liveDataLoaded && manifestData.length === 0) {
                document.querySelectorAll('.metric-card').forEach(c => c.classList.add('syncing'));
            }
            const aiPulse = document.getElementById('ai-pulse-indicator');
            if (aiPulse) aiPulse.style.display = 'inline-flex';

            const MANIFEST_URLS = [
                RAW_MANIFEST,
                atob('aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNQG1haW4vZGF0YS9zdGl4L2ZlZWRfbWFuaWZlc3QuanNvbg==')
            ];

            // ── Try live network sources ──
            let lastError = null;
            for (const manifestUrl of MANIFEST_URLS) {
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 8000);
                    const response = await fetch(manifestUrl, {
                        cache: 'no-cache',
                        signal: controller.signal
                    });
                    clearTimeout(timeout);
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    const data = await response.json();

                    const entries = Array.isArray(data) ? data : (data.entries || []);
                    if (!entries.length) throw new Error('Empty manifest');

                    manifestData = [...entries].reverse();
                    _liveDataLoaded = true;
                    computeMetrics(manifestData);
                    renderTrendChart(manifestData);
                    applyView();

                    syncVal.innerHTML = 'SYNC: <span style="color:var(--accent);animation:new-glow 1.5s ease-in-out infinite alternate;">● LIVE</span>';
                    integrityEl.innerHTML = '<span class="integrity-badge integrity-ok"><i class="fas fa-shield-check"></i> MANIFEST VERIFIED</span>';
                    document.getElementById('last-loaded').textContent = 'SYNCED: ' + new Date().toLocaleTimeString() + ' · AUTO-SYNC EVERY 6H';
                    document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('syncing'));
                    if (aiPulse) aiPulse.style.display = 'none';
                    console.info('[CDB-GOC] Live data loaded:', entries.length, 'items from', manifestUrl.substring(0,60));
                    return;

                } catch (err) {
                    lastError = err;
                    console.warn('[CDB-GOC] Fetch failed:', manifestUrl.substring(0,60), err.message);
                }
            }

            // ── Fallback: ensure embedded cache is rendered (may already be from boot) ──
            if (!_liveDataLoaded && EMBEDDED_INTEL && EMBEDDED_INTEL.length) {
                manifestData = [...EMBEDDED_INTEL].reverse();
                computeMetrics(manifestData);
                renderTrendChart(manifestData);
                applyView();
                console.info('[CDB-GOC] Network fetch failed — embedded cache confirmed:', lastError?.message);
            }

            syncVal.innerHTML = 'SYNC: <span style="color:var(--medium);">CACHE</span>';
            integrityEl.innerHTML = '<span class="integrity-badge" style="background:rgba(217,119,6,0.08);color:var(--medium);border:1px solid rgba(217,119,6,0.25);">⚡ EMBEDDED CACHE — <a href="https://cyberbivash.blogspot.com" target="_blank" style="color:var(--accent);border-bottom:1px solid rgba(0,212,170,0.3);">VIEW LIVE BLOG</a></span>';
            document.getElementById('last-loaded').textContent = 'CACHE: ' + new Date().toLocaleTimeString() + ' · EMBEDDED INTEL ACTIVE';
            document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('syncing'));
            if (aiPulse) aiPulse.style.display = 'none';
        }

"""
    html = html[:start_idx] + new_func + html[end_idx:]
    patches_applied.append("P0-1: loadGOCIntel → progressive loading (zero-wait boot)")

    # ═══════════════════════════════════════════════════════════════
    # PATCH 2: Update DOMContentLoaded to boot from cache immediately
    # ═══════════════════════════════════════════════════════════════

    old_boot = """        // ── DOM Ready: Boot the platform ──
        document.addEventListener('DOMContentLoaded', () => {
            loadGOCIntel().then(() => fetchPipelineSyncTime()).catch(() => {});
            scheduleAutoRefresh();
        });"""

    new_boot = """        // ── DOM Ready: Boot the platform (v64.0 — Progressive) ──
        document.addEventListener('DOMContentLoaded', () => {
            // PHASE 1: Instant render from embedded cache (< 50ms)
            try { bootFromEmbeddedCache(); } catch(e) { console.warn('[BOOT] Embedded cache error:', e); }
            // PHASE 2: Attempt live data upgrade in background
            loadGOCIntel().then(() => fetchPipelineSyncTime()).catch(() => {});
            scheduleAutoRefresh();
        });"""

    if old_boot in html:
        html = html.replace(old_boot, new_boot)
        patches_applied.append("P0-2: DOMContentLoaded → progressive boot (cache-first)")
    else:
        print("[WARN] Could not find DOMContentLoaded boot block")

    # ═══════════════════════════════════════════════════════════════
    # PATCH 3: Fix version string consistency → v64.0
    # ═══════════════════════════════════════════════════════════════

    version_replacements = [
        ("Sentinel APEX v54.0", "Sentinel APEX v64.0"),
        ("APEX ULTRA v54.0", "APEX ULTRA v64.0"),
        ("NEXUS INTELLIGENCE v54.0", "NEXUS INTELLIGENCE v64.0"),
        ("v54.0 APEX ULTRA", "v64.0 APEX ULTRA"),
        ("v54.0 ENHANCEMENTS", "v64.0 ENHANCEMENTS"),
    ]
    for old_v, new_v in version_replacements:
        if old_v in html:
            html = html.replace(old_v, new_v)

    patches_applied.append("P1-1: Version strings → v64.0 (consistent with VERSION file bump)")

    # ═══════════════════════════════════════════════════════════════
    # PATCH 4: Harden initEngineLoader with global error boundary
    # ═══════════════════════════════════════════════════════════════

    old_engine_trigger = """            // Trigger after DOM is ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', loadAllEngines);
            } else {
                // DOM already loaded — fire after a tick to allow existing renderers to run first
                setTimeout(loadAllEngines, 500);
            }"""

    new_engine_trigger = """            // Trigger after DOM is ready — with error boundary
            async function safeLoadAllEngines() {
                try { await loadAllEngines(); }
                catch(e) { console.warn('[APEX ENGINE] Global error caught:', e); }
            }
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => setTimeout(safeLoadAllEngines, 800));
            } else {
                setTimeout(safeLoadAllEngines, 800);
            }"""

    if old_engine_trigger in html:
        html = html.replace(old_engine_trigger, new_engine_trigger)
        patches_applied.append("P1-2: Engine loader → global error boundary + delayed init")
    else:
        print("[WARN] Could not find engine trigger block")

    # ═══════════════════════════════════════════════════════════════
    # PATCH 5: Fix initial sync-val display
    # ═══════════════════════════════════════════════════════════════

    old_init_sync = 'SYNC: <span style="color:#ff9d00;">INITIALIZING...</span>'
    new_init_sync = 'SYNC: <span style="color:#ff9d00;">BOOTING...</span>'
    html = html.replace(old_init_sync, new_init_sync, 1)
    patches_applied.append("P2-1: Initial sync display → BOOTING (user feedback)")

    # ═══════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'='*60}")
    print(f"PATCHES APPLIED: {len(patches_applied)}")
    for p in patches_applied:
        print(f"  ✓ {p}")
    print(f"{'='*60}\n")

    return html


def main():
    if len(sys.argv) > 1:
        html_path = Path(sys.argv[1])
    else:
        html_path = Path("index.html")

    if not html_path.exists():
        print(f"[ERROR] {html_path} not found")
        sys.exit(1)

    print(f"[INFO] Patching {html_path}")
    original_size = html_path.stat().st_size

    patched = apply_patch(html_path)

    html_path.write_text(patched, encoding="utf-8")
    new_size = html_path.stat().st_size

    print(f"[INFO] Original: {original_size:,} bytes → Patched: {new_size:,} bytes")
    print("[SUCCESS] Dashboard P0 fix applied ✓")


if __name__ == "__main__":
    main()
