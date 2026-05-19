// ═══════════════════════════════════════════════════════════════════════════
// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v167.0
// CDB-RENDERER-ENGINE-V167 — Chrome Render Collapse Fix + Cinematic Upgrade
// v167 fixes:
//   RC1: Old v2.0 engine neutralized (no more runtime ownership collision)
//   RC2: applySize() dim caching (no 60x/sec GPU texture reset)
//   RC3: will-change:auto on canvas (no pre-paint empty compositor layer)
//   RC4: renderFrame uses cached dims (no per-frame context reset)
//   V1-V10: Cinematic military-grade visual upgrade
// Force-update strategy: clears ALL old sentinel-apex-v* caches on deploy.
// CRITICAL: index.html is NEVER cached (always network-first, no-store).
// ═══════════════════════════════════════════════════════════════════════════

// ── GVOS: Single source of truth for cache version ──
const CACHE_VERSION = 'sentinel-apex-v167-live';   // ← GVOS: bumped for v167 deploy
const CACHE_NAME    = CACHE_VERSION;

// Assets to cache for offline use (non-HTML only)
const STATIC_ASSETS = [
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// ── Install: cache static assets, activate immediately ──
self.addEventListener('install', event => {
    console.log('[SW v167] Installing:', CACHE_VERSION);
    // Skip waiting immediately — no old SW holdout
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS).catch(err => {
                console.warn('[SW v166] Pre-cache failed (non-fatal):', err);
            });
        })
    );
});

// ── Activate: purge ALL stale sentinel-apex-v* caches ──
self.addEventListener('activate', event => {
    console.log('[SW v167] Activating:', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key.startsWith('sentinel-apex-') && key !== CACHE_NAME)
                    .map(key => {
                        console.log('[SW v166] Purging stale cache:', key);
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
        console.log('[SW v167] SKIP_WAITING received — forcing activation');
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
        url.pathname.includes('api/')
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
