// ═══════════════════════════════════════════════════════
// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v77.1
// Force-update strategy: clears cache on new deploy,
// activates immediately (skipWaiting + clientsClaim)
// ═══════════════════════════════════════════════════════

const CACHE_VERSION = 'sentinel-apex-v773-syncfix';
const CACHE_NAME    = CACHE_VERSION;

// Assets to cache for offline use (non-HTML only)
const STATIC_ASSETS = [
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// ── Install: cache static assets ──
self.addEventListener('install', event => {
    console.log('[SW] Installing version:', CACHE_VERSION);
    // Skip waiting immediately — don't wait for old SW to release
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS).catch(err => {
                console.warn('[SW] Pre-cache failed (non-fatal):', err);
            });
        })
    );
});

// ── Activate: clear ALL old caches immediately ──
self.addEventListener('activate', event => {
    console.log('[SW] Activating version:', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys
                    .filter(key => key !== CACHE_NAME)
                    .map(key => {
                        console.log('[SW] Deleting old cache:', key);
                        return caches.delete(key);
                    })
            );
        }).then(() => {
            // Take control of all open pages immediately
            return self.clients.claim();
        })
    );
});

// ── Message handler: support SKIP_WAITING from page ──
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        console.log('[SW] Received SKIP_WAITING — activating new version');
        self.skipWaiting();
    }
});

// ── Fetch: network-first for HTML, cache-first for assets ──
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // NEVER cache index.html or dynamic data — always fetch fresh
    if (
        url.pathname === '/'           ||
        url.pathname === '/index.html' ||
        url.pathname.includes('feed_manifest') ||
        url.pathname.includes('sync_marker')   ||
        url.pathname.includes('api/')
    ) {
        event.respondWith(
            fetch(event.request, { cache: 'no-store' }).catch(() => {
                // Offline fallback: serve cached version if available
                return caches.match(event.request);
            })
        );
        return;
    }

    // For all other assets: cache-first with network fallback
    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) return cached;
            return fetch(event.request).then(response => {
                // Cache valid responses
                if (response && response.status === 200 && response.type === 'basic') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                }
                return response;
            });
        })
    );
});
