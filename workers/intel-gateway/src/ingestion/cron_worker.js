// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Live Threat Indicator Ingestion Pipeline
// =============================================================================
// Cloudflare Cron Trigger: runs every 6 hours (wrangler.toml `[triggers]`,
// second cron string "0 */6 * * *"), dispatched from index.js's scheduled()
// handler by matching event.cron -- the pre-existing 15-minute cron and its
// fetchAndCacheCVEs() call are untouched (see index.js's scheduled()).
//
// STORAGE DECISION (documented per CLAUDE.md's evidence-based governance):
// the task brief describes a "KV/D1 write buffer" for `threat_indicators`.
// This Worker has zero D1 binding today and provisioning a new D1 database
// or KV namespace requires `wrangler d1 create` / `wrangler kv namespace
// create` against the real Cloudflare account -- infrastructure creation
// this session has no credentials to perform safely. INTEL_R2 is already
// deployed and is the documented home for "CTI data" (wrangler.toml), so
// this pipeline upserts into NEW, additive keys inside that existing
// bucket (threat-indicators/latest.json + summary.json) rather than
// touching LATEST_JSON_KEY (a different key, owned by the separate Python
// CVE/advisory pipeline) or fabricating a binding that would fail to
// deploy. R2 has no native per-object TTL, so the 30-day expiry the brief
// asks for is enforced in mergeIndicators() on every write (expired
// indicators are dropped, not merely marked). Migrating this to a
// dedicated KV namespace (native expirationTtl) or D1 table is a natural,
// low-risk follow-up once that binding is actually provisioned -- tracked
// here rather than silently worked around.
//
// Every upstream fetch is independently try/caught (ingestSource()) so one
// source outage never blocks the other two, matching this codebase's
// existing "fail open, never hard-fail a scheduled job" convention (see
// fetchAndCacheCVEs() in index.js).
// =============================================================================

const KEV_URL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const URLHAUS_URL   = "https://urlhaus.abuse.ch/downloads/json_recent/";
const TOR_EXIT_URL  = "https://check.torproject.org/torbulkexitlist";

export const INDICATORS_R2_KEY = "threat-indicators/latest.json";
export const SUMMARY_R2_KEY    = "threat-indicators/summary.json";

const EXPIRY_MS         = 30 * 24 * 60 * 60 * 1000; // 30-day TTL (enforced on merge/read, see storage note above)
const FETCH_TIMEOUT_MS  = 15000;
const HIGH_RISK_CUTOFF  = 70;
const USER_AGENT        = "CyberDudeBivash-Sentinel-Apex-Ingestion/1.0 (+https://intel.cyberdudebivash.com)";

// -----------------------------------------------------------------------------
// Small pure helpers
// -----------------------------------------------------------------------------

function parseDate(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every(o => Number(o) <= 255);
}

function normalizeTags(tags) {
  if (Array.isArray(tags)) return tags.map(String).map(t => t.trim()).filter(Boolean).slice(0, 10);
  if (typeof tags === "string") return tags.split(",").map(t => t.trim()).filter(Boolean).slice(0, 10);
  return [];
}

function indicatorKey(i) {
  return `${i.type}:${String(i.indicator).toLowerCase()}`;
}

// -----------------------------------------------------------------------------
// Per-source normalization -- each returns the common indicator shape:
//   { indicator, type, source, source_confidence, first_seen, last_seen,
//     sighting_count, tags, meta }
// Pure functions (no I/O) so Task 4's mocked-payload tests exercise the
// exact parser this pipeline runs, not a reimplementation of it.
// -----------------------------------------------------------------------------

/** CISA Known Exploited Vulnerabilities catalog -- government-verified, highest confidence. */
export function normalizeKEV(raw) {
  const vulns = Array.isArray(raw?.vulnerabilities) ? raw.vulnerabilities : [];
  const nowIso = new Date().toISOString();
  return vulns
    .map(v => {
      const indicator = String(v.cveID || "").toUpperCase().trim();
      if (!indicator) return null;
      return {
        indicator, type: "cve", source: "CISA_KEV", source_confidence: 0.95,
        first_seen: parseDate(v.dateAdded) || nowIso, last_seen: nowIso, sighting_count: 1,
        tags: [v.knownRansomwareCampaignUse === "Known" ? "ransomware" : null, "kev"].filter(Boolean),
        meta: {
          vendor_project: v.vendorProject || "", product: v.product || "",
          vulnerability_name: v.vulnerabilityName || "", due_date: v.dueDate || null,
        },
      };
    })
    .filter(Boolean);
}

/** URLhaus "json_recent" -- active malware-distribution URLs. Endpoint returns an
 *  object keyed by numeric id => array of one entry; tolerate a plain array too. */
export function normalizeURLhaus(raw) {
  const entries = [];
  if (Array.isArray(raw)) {
    entries.push(...raw);
  } else if (raw && typeof raw === "object") {
    for (const v of Object.values(raw)) {
      if (Array.isArray(v)) entries.push(...v);
      else if (v && typeof v === "object") entries.push(v);
    }
  }
  const nowIso = new Date().toISOString();
  return entries
    .map(e => {
      const url = e.url || e.url_string || "";
      if (!url) return null;
      let host = "";
      try { host = new URL(url).hostname; } catch (_) { /* malformed URL from upstream -- keep url, blank host */ }
      return {
        indicator: url, type: "url", source: "URLHAUS", source_confidence: 0.85,
        first_seen: parseDate(e.date_added || e.dateadded) || nowIso, last_seen: nowIso, sighting_count: 1,
        tags: normalizeTags(e.tags),
        meta: { host, threat: e.threat || "malware_download", url_status: e.url_status || "unknown" },
      };
    })
    .filter(Boolean);
}

/** Tor Project bulk exit list -- plaintext, one IP per line, `#`-prefixed comments. */
export function normalizeTorExitNodes(text) {
  const nowIso = new Date().toISOString();
  return String(text || "")
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#") && isIPv4(l))
    .map(ip => ({
      indicator: ip, type: "ip", source: "TOR_EXIT_NODE", source_confidence: 0.6,
      first_seen: nowIso, last_seen: nowIso, sighting_count: 1,
      tags: ["tor", "anonymization"],
      meta: {},
    }));
}

// -----------------------------------------------------------------------------
// Sentinel Risk Score (0-100): source confidence weight + recency decay +
// infra/threat-context risk factor. Bounded by construction (40+30+15+15=100),
// still clamped defensively.
//
// "ASN infrastructure risk factor" note: this Worker has no ASN/geo database
// binding (e.g. MaxMind) and adding one is a new paid external dependency
// out of scope for this pipeline. What IS available without new
// infrastructure -- and is used here, honestly labeled -- is source-
// confirmed threat context: Tor-exit status (definitionally anonymizing
// infra), URLhaus-confirmed active distribution, and CISA-confirmed
// ransomware use. A real per-IP ASN reputation lookup is a documented
// future enhancement, not silently faked.
// -----------------------------------------------------------------------------

const SOURCE_WEIGHT = { CISA_KEV: 40, URLHAUS: 32, TOR_EXIT_NODE: 18 };

function recencyScore(indicator, nowMs = Date.now()) {
  const ageMs = nowMs - new Date(indicator.last_seen || indicator.first_seen).getTime();
  const ageDays = Math.max(0, ageMs / 86400000);
  return Math.max(0, 30 * (1 - ageDays / 30)); // 0-30, full weight inside 24h, decays to 0 at 30d
}

function sightingScore(indicator) {
  return Math.min(15, Math.log2(1 + (indicator.sighting_count || 1)) * 6); // repeat sightings raise confidence, capped
}

function infraRiskFactor(indicator) {
  let score = 0;
  if (indicator.source === "TOR_EXIT_NODE") score += 10;
  if (indicator.type === "url" && indicator.meta && indicator.meta.threat) score += 5;
  if (Array.isArray(indicator.tags) && indicator.tags.includes("ransomware")) score += 5;
  return Math.min(15, score);
}

// `nowMs` (default: the wall clock, exactly as before) is the evaluation
// instant; mergeIndicators() passes its own so TTL and recency scoring are
// judged against the same instant, and tests can pin it.
export function computeSentinelRiskScore(indicator, nowMs = Date.now()) {
  const base = SOURCE_WEIGHT[indicator.source] ?? 20;
  const raw = base + recencyScore(indicator, nowMs) + sightingScore(indicator) + infraRiskFactor(indicator);
  return Math.max(0, Math.min(100, Math.round(raw)));
}

// -----------------------------------------------------------------------------
// Merge/upsert: keyed by type+indicator value. Repeat sightings bump
// sighting_count and refresh last_seen/risk_score; anything whose last_seen
// has aged past the 30-day window is dropped (R2-native TTL substitute).
// A single-writer cron job every 6h makes this read-modify-write
// effectively atomic in practice; it is not a transactional guarantee in
// the database sense, and is not oversold as one.
// -----------------------------------------------------------------------------

//
// `nowMs` is the evaluation instant for the TTL and recency scoring. It
// defaults to Date.now(), so the production caller (runScheduledIngestion)
// is unchanged; tests pass a pinned instant so fixtures cannot silently
// expire as the calendar advances (a hard-coded last_seen of 2026-08-25
// crossed the 30-day TTL on 2026-09-24 and broke the gateway suite).
// Boundary: an item exactly EXPIRY_MS old is retained; EXPIRY_MS + 1 ms is
// dropped (`>` below).
export function mergeIndicators(previous, incoming, nowMs = Date.now()) {
  const map = new Map();
  for (const p of previous || []) {
    if (p && p.indicator && p.type) map.set(indicatorKey(p), { ...p });
  }
  for (const n of incoming || []) {
    if (!n || !n.indicator || !n.type) continue;
    const k = indicatorKey(n);
    const existing = map.get(k);
    if (existing) {
      map.set(k, {
        ...existing,
        last_seen: n.last_seen || existing.last_seen,
        sighting_count: (existing.sighting_count || 1) + 1,
        source_confidence: Math.max(existing.source_confidence || 0, n.source_confidence || 0),
        tags: Array.from(new Set([...(existing.tags || []), ...(n.tags || [])])),
        meta: { ...(existing.meta || {}), ...(n.meta || {}) },
      });
    } else {
      map.set(k, { ...n });
    }
  }

  const merged = [];
  for (const item of map.values()) {
    const lastSeenMs = new Date(item.last_seen || item.first_seen).getTime();
    if (!Number.isFinite(lastSeenMs) || nowMs - lastSeenMs > EXPIRY_MS) continue; // expired -- dropped, not just flagged
    item.expires_at = new Date(lastSeenMs + EXPIRY_MS).toISOString();
    item.risk_score = computeSentinelRiskScore(item, nowMs);
    merged.push(item);
  }
  merged.sort((a, b) => b.risk_score - a.risk_score);
  return merged;
}

// -----------------------------------------------------------------------------
// Summary builder -- powers the "cached summary" surfaces (getLiveIndicatorsSummary)
// consumed additively by /api/preview + /api/feed and by the export routes.
// -----------------------------------------------------------------------------

export function buildIndicatorSummary(items, sourceResults, generatedAt) {
  const bySource = {};
  const byType = {};
  let highRisk = 0;
  for (const i of items) {
    bySource[i.source] = (bySource[i.source] || 0) + 1;
    byType[i.type] = (byType[i.type] || 0) + 1;
    if (i.risk_score >= HIGH_RISK_CUTOFF) highRisk++;
  }
  return {
    generated_at: generatedAt,
    total_indicators: items.length,
    high_risk_count: highRisk,
    by_source: bySource,
    by_type: byType,
    sources: (sourceResults || []).map(r => ({ name: r.name, ok: r.ok, ingested: r.items.length, error: r.error || null })),
    top_indicators: items.slice(0, 10).map(i => ({ indicator: i.indicator, type: i.type, source: i.source, risk_score: i.risk_score })),
  };
}

// -----------------------------------------------------------------------------
// I/O: network fetch + R2 read/write. Kept separate from the pure functions
// above so Task 4's tests exercise real parsing/scoring/merge logic against
// mocked payloads without any network or R2 dependency.
// -----------------------------------------------------------------------------

async function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal, cf: { cacheTtl: 0 } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function ingestSource(name, fn) {
  try {
    const items = await fn();
    return { name, ok: true, items };
  } catch (err) {
    console.error(`[cron_worker] ${name} ingestion failed: ${err && err.message ? err.message : err}`);
    return { name, ok: false, items: [], error: String(err && err.message ? err.message : err) };
  }
}

/**
 * Entry point called from index.js's scheduled() handler on the 6-hourly
 * cron. Fetches all three sources (independently fault-tolerant), scores
 * and upserts against the previous R2 snapshot, writes both R2 keys, and
 * returns the summary (also used by tests to assert on a full dry run
 * given an injected `env.INTEL_R2` fake).
 */
export async function runScheduledIngestion(env) {
  const results = await Promise.all([
    ingestSource("CISA_KEV", async () => {
      const res = await fetchWithTimeout(KEV_URL, { headers: { "User-Agent": USER_AGENT, "Accept": "application/json" } });
      return normalizeKEV(await res.json());
    }),
    ingestSource("URLHAUS", async () => {
      const res = await fetchWithTimeout(URLHAUS_URL, { headers: { "User-Agent": USER_AGENT } });
      return normalizeURLhaus(await res.json());
    }),
    ingestSource("TOR_EXIT_NODE", async () => {
      const res = await fetchWithTimeout(TOR_EXIT_URL, { headers: { "User-Agent": USER_AGENT } });
      return normalizeTorExitNodes(await res.text());
    }),
  ]);

  const incoming = results.flatMap(r => r.items);

  let previous = [];
  try {
    const prevObj = env?.INTEL_R2 ? await env.INTEL_R2.get(INDICATORS_R2_KEY) : null;
    if (prevObj) {
      const text = await prevObj.text();
      const parsed = text && text.trim() ? JSON.parse(text) : null;
      previous = Array.isArray(parsed?.items) ? parsed.items : [];
    }
  } catch (err) {
    console.error(`[cron_worker] failed to read previous snapshot: ${err && err.message ? err.message : err}`);
  }

  const merged      = mergeIndicators(previous, incoming);
  const generatedAt = new Date().toISOString();
  const summary      = buildIndicatorSummary(merged, results, generatedAt);

  try {
    if (env?.INTEL_R2) {
      await env.INTEL_R2.put(INDICATORS_R2_KEY, JSON.stringify({ generated_at: generatedAt, count: merged.length, items: merged }), {
        httpMetadata: { contentType: "application/json" },
      });
      await env.INTEL_R2.put(SUMMARY_R2_KEY, JSON.stringify(summary), { httpMetadata: { contentType: "application/json" } });
    }
  } catch (err) {
    console.error(`[cron_worker] failed to write R2 snapshot: ${err && err.message ? err.message : err}`);
  }

  return summary;
}

/** Fail-soft read for API handlers: never throws, returns null if the pipeline hasn't run yet or R2 is unavailable. */
export async function getLiveIndicatorsSummary(env) {
  try {
    if (!env?.INTEL_R2) return null;
    const obj = await env.INTEL_R2.get(SUMMARY_R2_KEY);
    if (!obj) return null;
    const text = await obj.text();
    if (!text || !text.trim()) return null;
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

/** Fail-soft read of the full indicator list (risk-sorted), capped at `limit`. Used by the export routes. */
export async function getLiveIndicators(env, { limit = 1000 } = {}) {
  try {
    if (!env?.INTEL_R2) return [];
    const obj = await env.INTEL_R2.get(INDICATORS_R2_KEY);
    if (!obj) return [];
    const text = await obj.text();
    if (!text || !text.trim()) return [];
    const parsed = JSON.parse(text);
    const items = Array.isArray(parsed?.items) ? parsed.items : [];
    return items.slice(0, limit);
  } catch (_) {
    return [];
  }
}
