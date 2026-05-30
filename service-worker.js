// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v174.0 (pipeline v166.2)
// CDB-RENDERER-ENGINE-V174 — Enterprise Render Governance System
// v174.0 FIX (ANTI-STALE DASHBOARD ROLLBACK — PERMANENT FIX):
//   Root cause of dashboard reverting to stalled/old version:
//   CACHE_VERSION mismatch between pipeline and SW caused activation
//   races where old SW instances weren't purged on re-deploy.
//   Fix: CACHE_VERSION now includes full platform version (166.2).
//   SW minor bumped to v174. All sentinel-apex-v* caches purged on activate.
//   index.html + all HTML files NEVER cached (network-first absolute).
// v173.0 (Chrome canvas blank fix) — all fixes preserved.
// v172 RC12 FIX: box-shadow:none + border-radius:0 + border:none !important on canvas.
// v170 RC7-RC9 fixes, v168 governance suite — all preserved and hardened.
// Force-update strategy: clears ALL old sentinel-apex-v* caches on deploy.
// CRITICAL: index.html + JS engines are NEVER cached (always network-first).
// ═══════════════════════════════════════════════════════════════════════════

// ── GVOS: Single source of truth for cache version ──
// v166.2 FIX: CACHE_VERSION now embeds FULL platform version (166.2) so
// SW cache is automatically invalidated on every platform version bump.
// Format: sentinel-apex-v{SW_MINOR}-p{PIPELINE}-live
const CACHE_VERSION = 'sentinel-apex-v174-p166.2-live';   // ← GVOS: v174 + pipeline v166.2
const CACHE_NAME    = CACHE_VERSION;

// Assets to cache for offline use (non-HTML only)
const STATIC_ASSETS = [
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// ── Install: cache static assets, activate immediately ──
self.addEventListener('install', event => {
    console.log('[SW v174] Installing:', CACHE_VERSION);
    // Skip waiting immediately — no old SW holdout
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS).catch(err => {
                console.warn('[SW v174] Pre-cache failed (non-fatal):', err);
            });
        })
    );
});

// ── Activate: purge ALL stale sentinel-apex-v* caches ──
self.addEventListener('activate', event => {
    console.log('[SW v174] Activating:', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key.startsWith('sentinel-apex-') && key !== CACHE_NAME)
                    .map(key => {
                        console.log('[SW v174] Purging stale cache:', key);
                        return caches.delete(key);
                    })
            );
        }).then(() => {
            // Take control of ALL open pages immediately
            return self.clients.claim();
        }).then(() => {
            // v174.0: Notify all clients to reload after SW activation
            // This ensures stale dashboards get the latest version immediately
            return self.clients.matchAll({ type: 'window' }).then(clients => {
                clients.forEach(client => {
                    client.postMessage({ type: 'SW_ACTIVATED', version: CACHE_VERSION });
                });
            });
        })
    );
});

// ── Message handler: SKIP_WAITING + version query support ──
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        console.log('[SW v174] SKIP_WAITING received — forcing activation');
        self.skipWaiting();
    }
    if (event.data && event.data.type === 'GET_VERSION') {
        event.source.postMessage({ type: 'VERSION', version: CACHE_VERSION });
    }
});

// ── Fetch: NETWORK-FIRST for HTML/data, cache-first for static assets ──
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // CRITICAL: NEVER cache HTML files, dynamic feeds, or API endpoints.
    // Prevents stale dashboard from being served from SW cache.
    if (
        url.pathname === '/'                          ||
        url.pathname === '/index.html'                ||
        url.pathname.endsWith('.html')                ||
        url.pathname.includes('feed_manifest')        ||
        url.pathname.includes('sync_marker')          ||
        url.pathname.includes('version.json')         ||
        url.pathname.includes('api/')                 ||
        url.pathname.includes('/js/engines/')          /* v168: governance engines always fresh */
    ) {
        event.respondWith(
            fetch(event.request, { cache: 'no-store' }).catch(() => {
                // Offline fallback only
                return caches.match(event.request);
            })
        );
        return;
    }

    // Static assets: cache-first with network fallback
    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) return cached;
            return fetch(event.request).then(response => {
                if (response && response.status === 200 && response.type === 'basic') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                }
                return response;
            });
        })
    );
});
