// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v168.0
// CDB-RENDERER-ENGINE-V168 — Enterprise Render Governance System
// v168 adds:
//   G1: 5-engine governance suite (compositor/RAF/canvas/telemetry/recovery)
//   G2: RAF ownership registry — blocks all intruder engine RAF access
//   G3: Canvas lifecycle engine — DPR-governed resize, context preservation
//   G4: Compositor governance — two-phase GPU layer promotion
//   G5: Telemetry engine — FPS + stall detection
//   G6: Recovery engine — blank-frame scan + context-loss self-healing
//   v167 RC1-RC5 fixes preserved and hardened by governance layer
// Force-update strategy: clears ALL old sentinel-apex-v* caches on deploy.
// CRITICAL: index.html + JS engines are NEVER cached (always network-first).
// ═══════════════════════════════════════════════════════════════════════════

// ── GVOS: Single source of truth for cache version ──
const CACHE_VERSION = 'sentinel-apex-v168-live';   // ← GVOS: bumped for v168 deploy
const CACHE_NAME    = CACHE_VERSION;

// Assets to cache for offline use (non-HTML only)
const STATIC_ASSETS = [
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// ── Install: cache static assets, activate immediately ──
self.addEventListener('install', event => {
    console.log('[SW v168] Installing:', CACHE_VERSION);
    // Skip waiting immediately — no old SW holdout
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS).catch(err => {
                console.warn('[SW v168] Pre-cache failed (non-fatal):', err);
            });
        })
    );
});

// ── Activate: purge ALL stale sentinel-apex-v* caches ──
self.addEventListener('activate', event => {
    console.log('[SW v168] Activating:', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key.startsWith('sentinel-apex-') && key !== CACHE_NAME)
                    .map(key => {
                        console.log('[SW v168] Purging stale cache:', key);
                        return caches.delete(key);
                    })
            );
        }).then(() => {
            // Take control of ALL open pages immediately
            return self.clients.claim();
        })
    );
});

// ── Message handler: SKIP_WAITING + version query support ──
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        console.log('[SW v168] SKIP_WAITING received — forcing activation');
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
    // Chrome desktop was serving stale index.html via SW cache.
    // This ensures every page load gets the latest production build.
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
