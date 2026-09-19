// CYBERDUDEBIVASH SENTINEL APEX — Service Worker v200.2
// P0 dashboard freshness semantics + stale-client convergence (2026-09-07)
//
// Production invariant:
//   * HTML, JS, CSS, JSON, API/data routes and service-worker.js are NETWORK ONLY.
//   * Only explicit immutable/offline-safe STATIC_ASSETS allow cache-first.
//   * Every SW release changes CACHE_VERSION, purging prior sentinel-apex caches.
//   * No runtime intelligence or executable frontend code may be served stale.
//
// Freshness compatibility invariant:
//   /api/v1/intel/stats historically exposes `last_sync` as the newest source
//   item's published timestamp. That is source recency, NOT pipeline sync time.
//   The gateway now also exposes authoritative `last_feed_sync_utc`, derived from
//   the feed artifact generated_at timestamp. Legacy dashboard code still renders
//   stats.last_sync as "Last Sync", which can therefore display an old date while
//   the production pipeline is healthy. Until all legacy consumers migrate, this
//   SW compatibility boundary aliases last_sync to last_feed_sync_utc for the
//   browser dashboard only and preserves the source timestamp separately as
//   latest_item_published_at. Direct API responses remain unchanged.

'use strict';

const CACHE_VERSION = 'sentinel-apex-v200.2-live';
const CACHE_NAME = CACHE_VERSION;

const STATIC_ASSETS = Object.freeze([
  '/manifest.json',
  '/assets/sentinel-apex-thumbnail.jpg',
]);
const STATIC_ASSET_SET = new Set(STATIC_ASSETS);

self.addEventListener('install', event => {
  console.log('[SW v200.2] Installing:', CACHE_VERSION);
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      cache.addAll(STATIC_ASSETS).catch(err => {
        console.warn('[SW v200.2] Optional pre-cache failed:', err);
      })
    )
  );
});

self.addEventListener('activate', event => {
  console.log('[SW v200.2] Activating:', CACHE_VERSION);
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key.startsWith('sentinel-apex-') && key !== CACHE_NAME)
          .map(key => {
            console.log('[SW v200.2] Purging stale cache:', key);
            return caches.delete(key);
          })
      ))
      .then(() => self.clients.claim())
      .then(() => self.clients.matchAll({ type: 'window' }))
      .then(clients => {
        clients.forEach(client => client.postMessage({
          type: 'SW_ACTIVATED',
          version: CACHE_VERSION,
        }));
      })
  );
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data && event.data.type === 'GET_VERSION') {
    event.source.postMessage({ type: 'VERSION', version: CACHE_VERSION });
  }
});

function isExplicitStaticAsset(url) {
  return url.origin === self.location.origin && STATIC_ASSET_SET.has(url.pathname);
}

function isDashboardStatsRequest(url) {
  return url.origin === self.location.origin && url.pathname === '/api/v1/intel/stats';
}

async function fetchDashboardStats(request) {
  const response = await fetch(request, { cache: 'no-store' });
  if (!response.ok) return response;

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return response;

  try {
    const payload = await response.clone().json();
    if (!payload || !payload.last_feed_sync_utc) return response;

    const normalized = {
      ...payload,
      latest_item_published_at: payload.latest_item_published_at || payload.last_sync || null,
      last_sync: payload.last_feed_sync_utc,
    };

    const headers = new Headers(response.headers);
    headers.delete('content-length');
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    headers.set('X-Sentinel-Freshness-Semantics', 'feed-generated-at');

    return new Response(JSON.stringify(normalized), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (err) {
    console.warn('[SW v200.2] Stats freshness normalization skipped:', err);
    return response;
  }
}

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  // Never cache non-GET requests.
  if (request.method !== 'GET') {
    event.respondWith(fetch(request));
    return;
  }

  // Compatibility boundary for legacy dashboard Last Sync rendering.
  // This never fabricates time: it only consumes the gateway's authoritative
  // last_feed_sync_utc field and keeps the source-publish timestamp separately.
  if (isDashboardStatsRequest(url)) {
    event.respondWith(fetchDashboardStats(request));
    return;
  }

  // The ONLY cache-first paths are explicit offline-safe static assets.
  if (isExplicitStaticAsset(url)) {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (response && response.ok && response.type === 'basic') {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  // Production safety boundary: dashboard code and intelligence are network-only.
  // In particular this covers /, *.html, *.js, *.css, *.json, /api/*,
  // /service-worker.js and every future frontend/data route by default.
  event.respondWith(fetch(request, { cache: 'no-store' }));
});
