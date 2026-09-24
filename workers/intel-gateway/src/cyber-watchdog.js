/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG
 *
 * Classifies items already published on the Sentinel APEX feed into three
 * customer lenses: cybersecurity, technology, and security operations.
 * Customer watches are keyword/CVE filters over that same feed.
 *
 * It does not crawl the public internet, does not watch private networks,
 * and does not invent events when the feed is empty. An empty feed is an
 * empty brief.
 *
 * Commercial list (existing checkout, not a second invoice):
 *   Pro Defense      $49/mo  — hosted brief + 25 watches
 *   Enterprise SOC   $499/mo — hosted brief + 200 watches + customer-environment poller
 * Book rate 83 INR per USD, locked 2026-09-20. View math only. Razorpay
 * charge amounts are the existing plan prices.
 */

export const WATCHDOG_NAME = 'CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG';
export const WATCHDOG_VERSION = '1.0.0';
export const BOOK_INR_PER_USD = 83;
export const BOOK_LOCKED = '2026-09-20';

export const LENSES = Object.freeze({
  cybersecurity: {
    id: 'cybersecurity',
    label: 'Cybersecurity',
    description: 'Vulnerabilities, KEV, ransomware, malware, and intrusion reporting already on the Sentinel APEX feed.',
  },
  technology: {
    id: 'technology',
    label: 'Technology',
    description: 'Vendor, cloud, software, and supply-chain items already on the Sentinel APEX feed.',
  },
  security_operations: {
    id: 'security_operations',
    label: 'Security operations',
    description: 'Detection, incident-response, and SOC-relevant items already on the Sentinel APEX feed.',
  },
});

const LENS_RULES = [
  ['cybersecurity', /\b(cve-\d{4}-\d+|ransomware|malware|exploit|kev|vulnerabilit|phish|apt\b|intrusion|backdoor|zero-?day|ioc\b)/i],
  ['technology', /\b(cloud|kubernetes|k8s|microsoft|windows|apple|google|aws|azure|gcp|firmware|vendor|supply[- ]chain|openssl|chrome|linux)\b/i],
  ['security_operations', /\b(sigma|yara|detection|siem|soar|playbook|incident|soc\b|triage|suricata|kql|splunk)\b/i],
];

const PLAN_USD = { PRO: 49, ENTERPRISE: 499 };

function bookInr(usd) {
  return Math.round(Number(usd) * BOOK_INR_PER_USD);
}

export function watchdogOffer() {
  return {
    product: WATCHDOG_NAME,
    version: WATCHDOG_VERSION,
    seller: {
      legal_name: 'CYBERDUDEBIVASH Pvt. Ltd.',
      gstin: '21ARKPN8270G1ZP',
      pan: 'ARKPN8270G',
    },
    book: { inr_per_usd: BOOK_INR_PER_USD, locked: BOOK_LOCKED },
    scope: {
      watches: Object.values(LENSES).map((l) => l.description),
      does_not: [
        'Does not watch the entire internet.',
        'Does not watch private customer networks or hosts you did not put in a watch keyword.',
        'Does not query dark-web marketplaces. That monitor is separately unavailable.',
        'Does not invent advisories when the live feed is empty.',
      ],
    },
    plans: [
      {
        id: 'FREE',
        name: 'Public preview',
        price_usd_monthly: 0,
        price_inr_book_monthly: 0,
        watches: 0,
        brief_items: 8,
        customer_deploy: false,
        checkout: null,
      },
      {
        id: 'PRO',
        name: 'Pro Defense',
        price_usd_monthly: PLAN_USD.PRO,
        price_inr_book_monthly: bookInr(PLAN_USD.PRO),
        price_label: `$${PLAN_USD.PRO}/mo · ₹${bookInr(PLAN_USD.PRO).toLocaleString('en-IN')}/mo`,
        watches: 25,
        brief_items: 50,
        customer_deploy: false,
        checkout: '/upgrade.html?plan=pro&feature=cyber-watchdog',
        note: 'Existing Pro Defense charge. Cyber Watchdog is included. No second invoice.',
      },
      {
        id: 'ENTERPRISE',
        name: 'Enterprise SOC',
        price_usd_monthly: PLAN_USD.ENTERPRISE,
        price_inr_book_monthly: bookInr(PLAN_USD.ENTERPRISE),
        price_label: `$${PLAN_USD.ENTERPRISE}/mo · ₹${bookInr(PLAN_USD.ENTERPRISE).toLocaleString('en-IN')}/mo`,
        watches: 200,
        brief_items: 200,
        customer_deploy: true,
        checkout: '/upgrade.html?plan=enterprise&feature=cyber-watchdog',
        note: 'Existing Enterprise SOC charge. Includes the customer-environment poller.',
      },
      {
        id: 'MSSP',
        name: 'MSSP',
        price_usd_monthly: null,
        price_label: 'Contracted MSSP order',
        watches: 200,
        brief_items: 200,
        customer_deploy: true,
        checkout: '/upgrade.html?plan=enterprise&feature=cyber-watchdog',
        note: 'Included on an active MSSP key. Not a new public sticker.',
      },
    ],
    endpoints: {
      offer: 'GET /api/watchdog/offer',
      brief: 'GET /api/watchdog/brief',
      watches: 'GET|POST /api/watchdog/watches',
      watch_delete: 'DELETE /api/watchdog/watches?id=',
      matches: 'GET /api/watchdog/matches',
      deploy: 'GET /api/watchdog/deploy',
    },
    dashboard: '/cyber-watchdog.html',
    aligned_not_certified: 'ISO 27001 / SOC 2: aligned, not certified.',
  };
}

export function quotaForTier(tier) {
  const t = String(tier || 'FREE').toUpperCase();
  if (t === 'ENTERPRISE' || t === 'MSSP') return { watches: 200, brief_items: 200, customer_deploy: true, paid: true };
  if (t === 'PRO') return { watches: 25, brief_items: 50, customer_deploy: false, paid: true };
  return { watches: 0, brief_items: 8, customer_deploy: false, paid: false };
}

function clean(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001F\u007F<>]/g, '').trim().slice(0, max);
}

function itemText(item) {
  const bits = [
    item.title, item.name, item.summary, item.description, item.ai_summary,
    item.severity, item.category, item.source, item.source_name, item.actor_tag,
  ];
  if (Array.isArray(item.tags)) bits.push(item.tags.join(' '));
  if (Array.isArray(item.cve_ids)) bits.push(item.cve_ids.join(' '));
  if (typeof item.cve_id === 'string') bits.push(item.cve_id);
  return bits.filter(Boolean).join(' ');
}

export function classifyItem(item) {
  const text = itemText(item || {});
  const lenses = [];
  for (const [id, re] of LENS_RULES) {
    if (re.test(text)) lenses.push(id);
  }
  return lenses;
}

function cveIds(item) {
  const found = new Set();
  const blob = itemText(item);
  for (const m of blob.matchAll(/CVE-\d{4}-\d{4,}/gi)) found.add(m[0].toUpperCase());
  if (Array.isArray(item.cve_ids)) {
    for (const c of item.cve_ids) {
      if (typeof c === 'string' && /^CVE-\d{4}-\d{4,}$/i.test(c)) found.add(c.toUpperCase());
    }
  }
  return [...found].slice(0, 12);
}

function publicItem(item, paid) {
  const id = clean(String(item.id || item.stix_id || ''), 128);
  const title = clean(String(item.title || item.name || 'Untitled advisory'), paid ? 240 : 120);
  const summary = clean(String(item.summary || item.description || item.ai_summary || ''), paid ? 500 : 0);
  return {
    id: id || null,
    title,
    summary: summary || null,
    severity: clean(String(item.severity || ''), 24) || null,
    source: clean(String(item.source || item.source_name || ''), 80) || null,
    observed_at: clean(String(item.published || item.timestamp || item.processed_at || ''), 40) || null,
    cve_ids: paid ? cveIds(item) : [],
    lenses: classifyItem(item),
    provenance: 'sentinel-apex-feed',
  };
}

export function buildWatchdogBrief(items, opts = {}) {
  const quota = quotaForTier(opts.tier);
  const lens = opts.lens && LENSES[opts.lens] ? opts.lens : null;
  const q = clean(String(opts.q || ''), 80).toLowerCase();
  const cap = Math.min(quota.brief_items, Math.max(1, Number(opts.limit) || quota.brief_items));
  const source = Array.isArray(items) ? items : [];
  const rows = [];
  for (const item of source) {
    if (!item || typeof item !== 'object') continue;
    const lenses = classifyItem(item);
    if (lens && !lenses.includes(lens)) continue;
    if (q && !itemText(item).toLowerCase().includes(q)) continue;
    const row = publicItem(item, quota.paid);
    if (lens) row.lenses = lenses;
    rows.push(row);
    if (rows.length >= cap) break;
  }
  return {
    product: WATCHDOG_NAME,
    version: WATCHDOG_VERSION,
    tier: String(opts.tier || 'FREE').toUpperCase(),
    lens: lens || 'all',
    count: rows.length,
    feed_items_seen: source.length,
    truncated: source.length > rows.length,
    items: rows,
    empty: rows.length === 0,
    empty_reason: rows.length === 0
      ? (source.length === 0
        ? 'Live Sentinel APEX feed returned no items. No events were invented.'
        : 'No feed items matched this lens or query.')
      : null,
    generated_at: opts.now || new Date().toISOString(),
  };
}

function watchKey(sub) {
  return `watchdog:watches:${sub}`;
}

async function kvRead(kv, key) {
  if (!kv || typeof kv.get !== 'function') return null;
  try {
    const parsed = await kv.get(key, 'json');
    if (parsed && typeof parsed === 'object') return parsed;
  } catch { /* try raw */ }
  try {
    const raw = await kv.get(key);
    if (!raw) return null;
    if (typeof raw === 'object') return raw;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function kvWrite(kv, key, value) {
  if (!kv || typeof kv.put !== 'function') {
    return { ok: false, error: 'watch_store_unavailable' };
  }
  try {
    await kv.put(key, JSON.stringify(value));
    return { ok: true };
  } catch {
    return { ok: false, error: 'watch_store_unavailable' };
  }
}

function normalizeWatch(input, id) {
  const name = clean(String(input?.name || ''), 80);
  const keywords = Array.isArray(input?.keywords)
    ? input.keywords.map((k) => clean(String(k), 48).toLowerCase()).filter(Boolean).slice(0, 8)
    : [];
  const cves = Array.isArray(input?.cves)
    ? input.cves.map((c) => clean(String(c), 20).toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)).slice(0, 8)
    : [];
  const lenses = Array.isArray(input?.lenses)
    ? input.lenses.map((l) => String(l)).filter((l) => LENSES[l]).slice(0, 3)
    : [];
  if (!name || (keywords.length === 0 && cves.length === 0)) return null;
  return { id, name, keywords, cves, lenses };
}

export function matchWatch(watch, item) {
  const text = itemText(item).toLowerCase();
  const cves = cveIds(item);
  const keywordHit = (watch.keywords || []).some((k) => k && text.includes(k));
  const cveHit = (watch.cves || []).some((c) => cves.includes(c));
  const lenses = classifyItem(item);
  const lensOk = !watch.lenses?.length || watch.lenses.some((l) => lenses.includes(l));
  return lensOk && (keywordHit || cveHit);
}

export function deployManifest(tier) {
  const quota = quotaForTier(tier);
  if (!quota.customer_deploy) {
    return {
      error: 'tier_required',
      message: 'Customer-environment Cyber Watchdog is included with Enterprise SOC ($499/mo) or an active MSSP key. Pro Defense includes the hosted watch only.',
      checkout: '/upgrade.html?plan=enterprise&feature=cyber-watchdog',
    };
  }
  return {
    product: WATCHDOG_NAME,
    mode: 'customer-environment',
    seller: 'CYBERDUDEBIVASH Pvt. Ltd.',
    runtime: 'Node.js 18+',
    poll: {
      endpoint: 'https://intel.cyberdudebivash.com/api/watchdog/brief',
      auth_header: 'X-API-Key',
      interval_seconds: 900,
      package: 'deploy/cyber-watchdog/poll.mjs',
    },
    does_not: [
      'The poller does not scan the internet from the customer host.',
      'It pulls the entitled Sentinel APEX brief and writes it locally.',
    ],
    included_with: tier === 'MSSP' ? 'MSSP contract' : 'Enterprise SOC $499/mo',
  };
}

export async function routeWatchdog(req) {
  const path = req.path || '';
  if (!path.startsWith('/api/watchdog')) return null;
  const method = String(req.method || 'GET').toUpperCase();
  const tier = String(req.auth?.tier || 'FREE').toUpperCase();
  const quota = quotaForTier(tier);
  const now = req.now || new Date().toISOString();

  if (path === '/api/watchdog/offer') {
    if (method !== 'GET' && method !== 'HEAD') return { status: 405, body: { error: 'method_not_allowed', allowed: ['GET'] } };
    return { status: 200, body: watchdogOffer() };
  }

  if (path === '/api/watchdog/brief') {
    if (method !== 'GET' && method !== 'HEAD') return { status: 405, body: { error: 'method_not_allowed', allowed: ['GET'] } };
    const lens = req.searchParams?.get?.('lens') || req.lens || null;
    const q = req.searchParams?.get?.('q') || '';
    const limit = req.searchParams?.get?.('limit');
    return {
      status: 200,
      body: buildWatchdogBrief(req.items, { tier, lens, q, limit, now }),
    };
  }

  if (path === '/api/watchdog/deploy') {
    if (method !== 'GET' && method !== 'HEAD') return { status: 405, body: { error: 'method_not_allowed', allowed: ['GET'] } };
    const body = deployManifest(tier);
    return { status: body.error ? 403 : 200, body };
  }

  if (path === '/api/watchdog/matches') {
    if (method !== 'GET' && method !== 'HEAD') return { status: 405, body: { error: 'method_not_allowed', allowed: ['GET'] } };
    if (!quota.paid || !req.auth?.sub) {
      return { status: 403, body: { error: 'tier_required', message: 'Saved-watch matching is included with Pro Defense ($49/mo).', checkout: '/upgrade.html?plan=pro&feature=cyber-watchdog' } };
    }
    const stored = (await kvRead(req.kv, watchKey(req.auth.sub))) || { watches: [] };
    const watches = Array.isArray(stored.watches) ? stored.watches : [];
    const items = Array.isArray(req.items) ? req.items : [];
    const matches = [];
    for (const watch of watches) {
      const hits = [];
      for (const item of items) {
        if (matchWatch(watch, item)) hits.push(publicItem(item, true));
        if (hits.length >= 20) break;
      }
      matches.push({ watch_id: watch.id, name: watch.name, hit_count: hits.length, hits });
    }
    return { status: 200, body: { product: WATCHDOG_NAME, tier, matches, generated_at: now } };
  }

  if (path === '/api/watchdog/watches') {
    if (!quota.paid || !req.auth?.sub) {
      return { status: 403, body: { error: 'tier_required', message: 'Customer watches are included with Pro Defense ($49/mo).', checkout: '/upgrade.html?plan=pro&feature=cyber-watchdog' } };
    }
    const key = watchKey(req.auth.sub);
    const stored = (await kvRead(req.kv, key)) || { watches: [] };
    const watches = Array.isArray(stored.watches) ? stored.watches : [];

    if (method === 'GET' || method === 'HEAD') {
      return { status: 200, body: { watches, limit: quota.watches, tier } };
    }
    if (method === 'POST') {
      if (watches.length >= quota.watches) {
        return { status: 403, body: { error: 'watch_limit', limit: quota.watches, message: 'Watch limit for this plan is reached.' } };
      }
      const id = `w_${(req.id || Math.random().toString(16).slice(2)).replace(/[^a-z0-9]/gi, '').slice(0, 24)}`;
      const watch = normalizeWatch(req.body, id);
      if (!watch) {
        return { status: 400, body: { error: 'invalid_watch', message: 'Provide a name plus at least one keyword or CVE id.' } };
      }
      watch.created_at = now;
      watches.push(watch);
      const wrote = await kvWrite(req.kv, key, { watches });
      if (!wrote.ok) return { status: 503, body: { error: wrote.error, message: 'Watch store is temporarily unavailable. Nothing was saved.' } };
      return { status: 201, body: { watch, count: watches.length, limit: quota.watches } };
    }
    if (method === 'DELETE') {
      const id = clean(String(req.searchParams?.get?.('id') || req.body?.id || ''), 40);
      const next = watches.filter((w) => w.id !== id);
      if (next.length === watches.length) return { status: 404, body: { error: 'not_found' } };
      const wrote = await kvWrite(req.kv, key, { watches: next });
      if (!wrote.ok) return { status: 503, body: { error: wrote.error } };
      return { status: 200, body: { deleted: id, count: next.length } };
    }
    return { status: 405, body: { error: 'method_not_allowed', allowed: ['GET', 'POST', 'DELETE'] } };
  }

  return { status: 404, body: { error: 'not_found', path } };
}
