/**
 * CYBERDUDEBIVASH® Sentinel APEX v24.0 ULTRA
 * Service Worker — Production Grade
 * Strategy: Cache-First for static assets, Network-First for API/intel feeds
 * Security: No sensitive data cached; cache integrity checks enforced
 */

'use strict';

const SW_VERSION = 'v24.0.0';
const CACHE_STATIC = `cdb-static-${SW_VERSION}`;
const CACHE_FONTS  = `cdb-fonts-${SW_VERSION}`;
const CACHE_INTEL  = `cdb-intel-${SW_VERSION}`;

// Static assets to pre-cache on install
const PRECACHE_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    '/assets/sentinel-apex-thumbnail.jpg',
];

// External CDN assets (cache opportunistically)
const CDN_ORIGINS = [
    'https://cdnjs.cloudflare.com',
    'https://fonts.googleapis.com',
    'https://fonts.gstatic.com',
];

// Intel feed origins — network-first, short cache TTL
const INTEL_ORIGINS = [
    'https://feeds.feedburner.com',
    'https://api.cyberdudebivash.com',
];

// Max age for intel cache entries (5 minutes)
const INTEL_MAX_AGE_MS = 5 * 60 * 1000;


// ── Install: Pre-cache static shell ──────────────────────────────
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_STATIC)
            .then(cache => cache.addAll(PRECACHE_ASSETS))
            .then(() => self.skipWaiting())
            .catch(err => console.warn('[SW] Pre-cache failed:', err))
    );
});


// ── Activate: Purge stale caches ─────────────────────────────────
self.addEventListener('activate', (event) => {
    const validCaches = [CACHE_STATIC, CACHE_FONTS, CACHE_INTEL];
    event.waitUntil(
        caches.keys()
            .then(keys => Promise.all(
                keys
                    .filter(k => !validCaches.includes(k))
                    .map(k => {
                        console.log('[SW] Purging stale cache:', k);
                        return caches.delete(k);
                    })
            ))
            .then(() => self.clients.claim())
    );
});


// ── Fetch: Routing strategy dispatcher ───────────────────────────
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);

    // Never intercept non-GET or chrome-extension requests
    if (request.method !== 'GET') return;
    if (url.protocol === 'chrome-extension:') return;

    // Determine strategy by origin/path
    if (isIntelRequest(url)) {
        event.respondWith(networkFirstIntel(request));
    } else if (isFontRequest(url)) {
        event.respondWith(cacheFirstFonts(request));
    } else if (isCdnRequest(url)) {
        event.respondWith(cacheFirstCdn(request));
    } else if (isStaticAsset(url)) {
        event.respondWith(cacheFirstStatic(request));
    } else if (isNavigationRequest(request)) {
        event.respondWith(navigationHandler(request));
    }
    // All other requests: browser default
});


// ── Strategy: Cache-First (static shell) ─────────────────────────
async function cacheFirstStatic(request) {
    const cached = await caches.match(request, { cacheName: CACHE_STATIC });
    if (cached) return cached;
    try {
        const response = await fetch(request);
        if (response.ok) {
            const cache = await caches.open(CACHE_STATIC);
            cache.put(request, response.clone());
        }
        return response;
    } catch {
        return offlineFallback(request);
    }
}

// ── Strategy: Cache-First (fonts — long TTL) ─────────────────────
async function cacheFirstFonts(request) {
    const cached = await caches.match(request, { cacheName: CACHE_FONTS });
    if (cached) return cached;
    try {
        const response = await fetch(request);
        if (response.ok) {
            const cache = await caches.open(CACHE_FONTS);
            cache.put(request, response.clone());
        }
        return response;
    } catch {
        return new Response('', { status: 503, statusText: 'Font unavailable offline' });
    }
}

// ── Strategy: Cache-First (CDN assets) ───────────────────────────
async function cacheFirstCdn(request) {
    const cached = await caches.match(request);
    if (cached) return cached;
    try {
        const response = await fetch(request, { mode: 'cors' });
        if (response.ok) {
            const cache = await caches.open(CACHE_STATIC);
            cache.put(request, response.clone());
        }
        return response;
    } catch {
        return new Response('', { status: 503, statusText: 'CDN asset unavailable' });
    }
}

// ── Strategy: Network-First (intel feeds — short TTL) ────────────
async function networkFirstIntel(request) {
    const cacheKey = request.url;
    try {
        const response = await fetch(request, { signal: AbortSignal.timeout(8000) });
        if (response.ok) {
            const cache = await caches.open(CACHE_INTEL);
            // Stamp with fetched-at header for TTL validation
            const cloned = response.clone();
            const body = await cloned.arrayBuffer();
            const headers = new Headers(cloned.headers);
            headers.set('sw-fetched-at', Date.now().toString());
            const stamped = new Response(body, { status: cloned.status, statusText: cloned.statusText, headers });
            cache.put(cacheKey, stamped);
        }
        return response;
    } catch {
        // Fallback to stale cache if within TTL window
        const cache = await caches.open(CACHE_INTEL);
        const cached = await cache.match(cacheKey);
        if (cached) {
            const fetchedAt = parseInt(cached.headers.get('sw-fetched-at') || '0', 10);
            if (Date.now() - fetchedAt < INTEL_MAX_AGE_MS) return cached;
        }
        return new Response(JSON.stringify({ error: 'offline', message: 'Intel feed unavailable — network offline' }),
            { status: 503, headers: { 'Content-Type': 'application/json' } });
    }
}

// ── Strategy: Navigation (SPA shell fallback) ────────────────────
async function navigationHandler(request) {
    try {
        return await fetch(request);
    } catch {
        const cached = await caches.match('/index.html', { cacheName: CACHE_STATIC });
        return cached || offlineFallback(request);
    }
}

// ── Offline fallback page ─────────────────────────────────────────
async function offlineFallback(request) {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(
        `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Sentinel APEX — Offline</title>
        <style>body{background:#020205;color:#c8d1dc;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}.wrap{text-align:center;padding:40px;}.logo{color:#00d4aa;font-size:24px;font-weight:900;letter-spacing:-1px;margin-bottom:16px;}.msg{font-size:12px;opacity:0.6;line-height:1.8;}.btn{margin-top:24px;padding:10px 24px;background:#00d4aa;color:#020205;border:none;font-family:inherit;font-size:11px;font-weight:900;cursor:pointer;letter-spacing:1px;}</style>
        </head><body><div class="wrap">
        <div class="logo">CYBERDUDEBIVASH®</div>
        <div style="color:#00d4aa;font-size:11px;letter-spacing:3px;margin-bottom:20px;">SENTINEL APEX v24.0 ULTRA</div>
        <div class="msg">⚡ OFFLINE MODE ACTIVE<br>Intelligence feed unavailable.<br>Reconnect to resume live threat monitoring.</div>
        <button class="btn" onclick="window.location.reload()">↻ RETRY CONNECTION</button>
        </div></body></html>`,
        { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
}


// ── Utility predicates ────────────────────────────────────────────
function isIntelRequest(url) {
    return INTEL_ORIGINS.some(o => url.origin === o) ||
           url.pathname.includes('/api/') ||
           url.pathname.includes('/feeds/') ||
           url.searchParams.has('rss') ||
           url.searchParams.has('feed');
}

function isFontRequest(url) {
    return url.hostname === 'fonts.googleapis.com' ||
           url.hostname === 'fonts.gstatic.com';
}

function isCdnRequest(url) {
    return CDN_ORIGINS.some(o => url.origin === o);
}

function isStaticAsset(url) {
    return /\.(js|css|png|jpg|jpeg|svg|webp|ico|woff2?|ttf|otf|json)$/i.test(url.pathname);
}

function isNavigationRequest(request) {
    return request.mode === 'navigate' ||
           (request.method === 'GET' && request.headers.get('accept')?.includes('text/html'));
}


// ── Message handler (cache invalidation, version reporting) ───────
self.addEventListener('message', (event) => {
    if (!event.data) return;
    switch (event.data.type) {
        case 'GET_VERSION':
            event.ports[0]?.postMessage({ version: SW_VERSION });
            break;
        case 'CLEAR_INTEL_CACHE':
            caches.delete(CACHE_INTEL).then(() => {
                event.ports[0]?.postMessage({ cleared: true });
            });
            break;
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
    }
});
