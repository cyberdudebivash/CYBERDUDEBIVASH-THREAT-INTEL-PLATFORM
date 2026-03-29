/**
 * CYBERDUDEBIVASH® SENTINEL APEX — API Integration Layer v1.0
 * All backend calls. Handles errors gracefully. Never crashes UI.
 */
'use strict';

const APEX = (() => {
  const BASE = 'https://cyberdudebivash-threat-intel-platform-production.up.railway.app';
  const TIMEOUT_MS = 12000;

  /** Fetch with timeout + structured error */
  async function apiFetch(path, opts = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(BASE + path, { ...opts, signal: ctrl.signal });
      clearTimeout(timer);
      const ct = res.headers.get('content-type') || '';
      const data = ct.includes('json') ? await res.json() : await res.text();
      if (!res.ok) throw { status: res.status, data };
      return { ok: true, data, status: res.status };
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError')
        return { ok: false, error: 'Request timed out. Please try again.', status: 0 };
      if (err.status) return { ok: false, error: err.data?.detail || err.data || 'API error', status: err.status };
      return { ok: false, error: 'Network error — check your connection.', status: 0 };
    }
  }

  /** GET /api/v1/onboard — pricing + quick-start guide */
  async function onboard() {
    return apiFetch('/api/v1/onboard');
  }

  /** POST /api/v1/subscribe — create checkout session */
  async function subscribe(plan, provider = 'stripe', name = '', email = '') {
    return apiFetch('/api/v1/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier: plan, payment_provider: provider, name, email }),
    });
  }

  /** GET /api/v1/intel/latest — fetch latest advisories */
  async function fetchIntel(apiKey, limit = 20) {
    const headers = {};
    if (apiKey && apiKey !== 'anon') headers['X-API-Key'] = apiKey;
    return apiFetch(`/api/v1/intel/latest?limit=${limit}`, { headers });
  }

  /** GET /api/v1/intel/feed — paginated feed */
  async function fetchFeed(apiKey, limit = 50, offset = 0) {
    const headers = {};
    if (apiKey && apiKey !== 'anon') headers['X-API-Key'] = apiKey;
    return apiFetch(`/api/v1/intel/feed?limit=${limit}&offset=${offset}`, { headers });
  }

  /** GET /api/v1/stats — platform stats */
  async function fetchStats(apiKey) {
    const headers = {};
    if (apiKey && apiKey !== 'anon') headers['X-API-Key'] = apiKey;
    return apiFetch('/api/v1/stats', { headers });
  }

  /** GET /api/v1/tiers — public tier info */
  async function fetchTiers() {
    return apiFetch('/api/v1/tiers');
  }

  /** GET /api/v1/health — liveness check */
  async function health() {
    return apiFetch('/api/v1/health');
  }

  return { onboard, subscribe, fetchIntel, fetchFeed, fetchStats, fetchTiers, health };
})();

/* Make available globally */
if (typeof window !== 'undefined') window.APEX = APEX;
if (typeof module !== 'undefined') module.exports = APEX;
