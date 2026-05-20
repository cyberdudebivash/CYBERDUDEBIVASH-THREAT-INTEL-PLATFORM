// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v172.0
// CDB-RENDERER-ENGINE-V171 — Enterprise Render Governance System
// v172 RC12 FIX (CHROME THREAT MAP BLANK CANVAS — DEFINITIVE FINAL):
//   Root cause: overflow:hidden on #cdb-threat-map-panel created a Chrome
//   D3D11/ANGLE stencil-clip region. When canvas (position:absolute) was
//   GPU-promoted to a separate compositor layer via translateZ(0) (RC11),
//   Chrome clipped that compositor layer using the parent stencil → BLANK.
//   Edge does NOT apply the stencil to separate compositor layers this way.
//   Fix RC10: overflow:visible on panel — eliminates the stencil entirely.
//   Panel has explicit height:340px, nothing can visually overflow.
// v172 RC12 FIX: box-shadow:none + border-radius:0 + border:none !important on canvas.
// Eliminates Chrome D3D11/ANGLE shadow pre-promotion compositor trap (definitive root cause).
//   Canvas2D does not need GPU layer promotion for correctness. The promotion
//   was the mechanism that triggered the stencil-clip → blank canvas trap.
// v170 RC7-RC9 fixes, v168 governance suite — all preserved and hardened.
// Force-update strategy: clears ALL old sentinel-apex-v* caches on deploy.
// CRITICAL: index.html + JS engines are NEVER cached (always network-first).
// ═══════════════════════════════════════════════════════════════════════════

// ── GVOS: Single source of truth for cache version ──
const CACHE_VERSION = 'sentinel-apex-v173-live';   // ← GVOS: bumped for v173 RC13 Immutable Viewport Governance
const CACHE_NAME    = CACHE_VERSION;

// Assets to cache for offline use (non-HTML only)
const STATIC_ASSETS = [
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// ── Install: cache static assets, activate immediately ──
self.addEventListener('install', event => {
    console.log('[SW v173] Installing:', CACHE_VERSION);
    // Skip waiting immediately — no old SW holdout
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS).catch(err => {
                console.warn('[SW v173] Pre-cache failed (non-fatal):', err);
            });
        })
    );
});

// ── Activate: purge ALL stale sentinel-apex-v* caches ──
self.addEventListener('activate', event => {
    console.log('[SW v173] Activating:', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key.startsWith('sentinel-apex-') && key !== CACHE_NAME)
                    .map(key => {
                        console.log('[SW v173] Purging stale cache:', key);
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
        console.log('[SW v173] SKIP_WAITING received — forcing activation');
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
