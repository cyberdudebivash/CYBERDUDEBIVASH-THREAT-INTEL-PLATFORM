/**
 * Shared Cyber Watchdog harness (not a test file: the suite glob is
 * *.test.js). Drives the REAL gateway router (index.js default export), the
 * REAL WatchdogLedger / WatchdogScheduler Durable Object classes over
 * in-memory storage, and a fake network standing in for DNS-over-HTTPS and
 * customer webhook receivers. Nothing here touches production.
 */
import worker from "../index.js";
import { WatchdogLedger } from "../watchdog-ledger.js";
import { WatchdogScheduler } from "../watchdog-scheduler.js";
import { fromPersisted } from "../cyber-watchdog.js";

export const PRO_KEY = "cdb_pro_wd_0123456789abcdef0123456789abcdef";
export const PRO2_KEY = "cdb_pro_wd_1123456789abcdef0123456789abcdef";
export const ENT_KEY = "cdb_ent_wd_0123456789abcdef0123456789abcdef";
export const MSSP_KEY = "cdb_mssp_wd_0123456789abcdef0123456789abcdef";
export const MSSP_LEGACY_KEY = "cdb_mssp_wd_legacy_89abcdef0123456789abcdef";
export const EXPIRED_KEY = "cdb_ent_wd_expired_89abcdef0123456789abcdef";
export const MSSP_A_ONLY_KEY = "cdb_mssp_wd_a_only_89abcdef0123456789abcdef";

export function fakeKV(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    map: m,
    get: async (k, o) => {
      const v = m.get(k);
      if (v === undefined) return null;
      return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v;
    },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

export class MemStorage {
  constructor() { this.data = new Map(); this.alarm = null; this.writes = 0; this.reads = 0; }
  async get(k) { this.reads += 1; const v = this.data.get(k); return v === undefined ? undefined : structuredClone(v); }
  async put(k, v) { this.writes += 1; this.data.set(k, structuredClone(v)); }
  async delete(k) { this.writes += 1; return this.data.delete(k); }
  async getAlarm() { return this.alarm; }
  async setAlarm(t) { this.alarm = typeof t === "number" ? t : Number(t); }
  async deleteAlarm() { this.alarm = null; }
}

export function fakeNamespace(Klass, envRef) {
  const instances = new Map();
  const ns = {
    requests: 0,
    instances,
    idFromName: (name) => ({ name, toString: () => name }),
    get: (id) => {
      const name = id.name;
      if (!instances.has(name)) {
        const storage = new MemStorage();
        instances.set(name, { storage, obj: new Klass({ storage }, envRef.env) });
      }
      const inst = instances.get(name);
      return {
        fetch: async (url, init) => {
          ns.requests += 1;
          return inst.obj.fetch(new Request(url, init));
        },
      };
    },
    instance: (name) => instances.get(name),
  };
  return ns;
}

/**
 * Fake network: DoH answers by hostname (mutable, to simulate rebinding),
 * and webhook receivers by URL. Records every non-DNS request.
 */
export function fakeNetwork() {
  const net = {
    dns: new Map(),          // hostname -> [{type, data}] or {status}
    receivers: new Map(),    // url -> async (init) => {status, body, headers}
    posts: [],
    dnsQueries: 0,
  };
  net.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      net.dnsQueries += 1;
      const u = new URL(url);
      const name = u.searchParams.get("name");
      const type = u.searchParams.get("type");
      const rec = net.dns.get(name);
      if (rec && rec.throw) throw new Error("doh down");
      if (!rec) return new Response(JSON.stringify({ Status: 3 }), { status: 200 });
      if (rec.status != null) return new Response(JSON.stringify({ Status: rec.status }), { status: 200 });
      const want = type === "A" ? 1 : 28;
      const Answer = rec.filter((a) => a.type === 5 || a.type === want);
      return new Response(JSON.stringify({ Status: 0, Answer }), { status: 200 });
    }
    net.posts.push({ url, init });
    const handler = net.receivers.get(url);
    if (!handler) throw new Error("connect failed");
    const out = await handler(init);
    return new Response(out.body == null ? null : (typeof out.body === "string" ? out.body : JSON.stringify(out.body)), { status: out.status, headers: out.headers || {} });
  };
  return net;
}

export const iso = (offsetSec, base = Date.now()) => new Date(base + offsetSec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

export const FEED_ITEMS = [
  { id: "intel--kev-1", title: "CVE-2026-1000 exploited in ransomware campaign", severity: "CRITICAL", source: "CISA KEV", cve_ids: ["CVE-2026-1000"], kev_present: true, processed_at: "2026-09-24T05:00:00Z", affected_products: ["Microsoft Windows"] },
  { id: "intel--cloud-2", title: "Azure Kubernetes supply-chain advisory", severity: "HIGH", source: "Vendor", processed_at: "2026-09-24T05:01:00Z" },
  { id: "intel--soc-3", title: "Sigma detection for suspicious PowerShell", severity: "MEDIUM", source: "Detection pack", processed_at: "2026-09-24T05:02:00Z" },
];

export function feedObject(items = FEED_ITEMS, ageSec = 600) {
  return { generated_at: iso(-ageSec), count: items.length, items };
}

export function harness(opts = {}) {
  const envRef = { env: null };
  const net = fakeNetwork();
  const state = { feed: opts.feed === undefined ? feedObject() : opts.feed, r2Gets: 0, r2Lists: 0 };
  const edge = new Map();
  globalThis.caches = {
    default: {
      match: async (req) => edge.get(req.url),
      put: async (req, res) => { edge.set(req.url, res); },
    },
  };
  globalThis.fetch = net.fetch;
  const keyRecord = (tier, customer, extra = {}) => JSON.stringify({ tier, customer_id: customer, status: "active", ...extra });
  const env = {
    INTEL_R2: {
      get: async (key) => {
        // Only the authoritative feed key counts: the same cron also runs the
        // pre-existing CVE cache refresh, which is not Watchdog cost.
        if (key === "api/v1/intel/latest.json") state.r2Gets += 1;
        state.r2Keys = (state.r2Keys || []).concat(key);
        if (key !== "api/v1/intel/latest.json" || state.feed == null) return null;
        const text = JSON.stringify(state.feed);
        return { text: async () => text, json: async () => JSON.parse(text) };
      },
      list: async () => { state.r2Lists += 1; return { objects: [] }; },
    },
    RATE_LIMIT_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    API_KEYS_KV: fakeKV({
      [PRO_KEY]: keyRecord("PRO", "cust_pro_1"),
      [PRO2_KEY]: keyRecord("PRO", "cust_pro_2"),
      [ENT_KEY]: keyRecord("ENTERPRISE", "cust_ent_1"),
      [MSSP_KEY]: keyRecord("MSSP", "cust_mssp_1", { managed_tenants: ["CANARY-A", "CANARY-B"] }),
      [MSSP_LEGACY_KEY]: keyRecord("MSSP", "cust_mssp_legacy"),
      [MSSP_A_ONLY_KEY]: keyRecord("MSSP", "cust_mssp_1", { managed_tenants: ["CANARY-A"] }),
      [EXPIRED_KEY]: keyRecord("ENTERPRISE", "cust_ent_expired", { subscription_status: "expired" }),
    }),
    CDB_JWT_SECRET: "jwt-test-secret-0123456789abcdef", ADMIN_SECRET: "admin-test-secret",
    // Production value from wrangler.toml; tests of the kill switch delete it.
    WATCHDOG_WEBHOOK_DELIVERY_ENABLED: opts.deliveryFlag === undefined ? "true" : opts.deliveryFlag,
  };
  if (opts.deliveryFlag === null) delete env.WATCHDOG_WEBHOOK_DELIVERY_ENABLED;
  env.WATCHDOG_LEDGER = fakeNamespace(WatchdogLedger, envRef);
  env.WATCHDOG_SCHEDULER = fakeNamespace(WatchdogScheduler, envRef);
  envRef.env = env;
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  let ipCounter = 10;

  async function call(method, path, { key, bearer, body, headers = {}, admin } = {}) {
    const h = { "cf-connecting-ip": "198.51.100." + (ipCounter++ % 200 + 1), ...headers };
    if (key) h["X-API-Key"] = key;
    if (bearer) h.Authorization = "Bearer " + bearer;
    if (admin) h["X-Admin-Key"] = admin;
    if (body !== undefined) h["Content-Type"] = "application/json";
    const res = await worker.fetch(new Request("https://intel.cyberdudebivash.com" + path, {
      method, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
    }), env, ctx);
    await Promise.allSettled(waits.splice(0));
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, body: json, text, headers: res.headers };
  }

  async function cron() {
    await worker.scheduled({ cron: "*/15 * * * *", scheduledTime: Date.now() }, env, ctx);
    await Promise.allSettled(waits.splice(0));
  }

  async function runAlarms() {
    for (const [, inst] of env.WATCHDOG_LEDGER.instances) {
      if (inst.storage.alarm != null) {
        inst.storage.alarm = null;
        await inst.obj.alarm();
      }
    }
  }

  // Logical ledger state: both persisted keys joined, as v3 reads them.
  function ledgerState(key) {
    const inst = env.WATCHDOG_LEDGER.instance("wd:" + key);
    if (!inst) return null;
    const ledger = inst.storage.data.get("ledger");
    if (!ledger) return null;
    return fromPersisted(ledger, inst.storage.data.get("watchdog_v3_signed_destinations"), inst.storage.data.get("watchdog_exposure_profile_v1"));
  }

  function ledgerStorage(key) {
    const inst = env.WATCHDOG_LEDGER.instance("wd:" + key);
    return inst ? inst.storage : null;
  }

  function schedulerState() {
    const inst = env.WATCHDOG_SCHEDULER.instance("watchdog-scheduler-v1");
    return inst ? inst.storage.data.get("scheduler") : null;
  }

  return { env, net, state, call, cron, runAlarms, ledgerState, ledgerStorage, schedulerState, ctx };
}

/** HS256 JWT signed like the gateway's signJWT (for crafting bad tokens). */
export async function craftJwt(payload, secret = "jwt-test-secret-0123456789abcdef") {
  const b64 = (str) => btoa(str).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const data = b64(JSON.stringify({ alg: "HS256", typ: "JWT" })) + "." + b64(JSON.stringify(payload));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return data + "." + b64(String.fromCharCode(...new Uint8Array(sig)));
}
