/**
 * /api/preview bounded pagination (P0 Phase 3D).
 *
 * The live feed-contract validator reads at most 131072 bytes; a default
 * preview page is 25 FREE-masked items (~13 KB each, ~300 KB), so the
 * validator saw truncated JSON. Rather than raising the read limit, the
 * preview now honours an explicit ?limit=1..25 and ?offset=, the default
 * response is unchanged (25 items, same keys), and the validator probes a
 * bounded page.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "../index.js";

function fakeKV() {
  const m = new Map();
  return {
    get: async (k, o) => { const v = m.get(k); return v === undefined ? null : (o === "json" || (o && o.type === "json") ? JSON.parse(v) : v); },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

// Realistically heavy items so the size assertion means something.
const bulky = (i) => ({
  id: `intel--${String(i).padStart(4, "0")}`, stix_id: `intel--${i}`, title: `Advisory ${i}`,
  severity: "HIGH", risk_score: 7.5, description: "x".repeat(4000),
  ttps: Array.from({ length: 20 }, (_, n) => `T${1000 + n}`), iocs: [`198.51.100.${i % 250}`],
});
const FEED = JSON.stringify({
  generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  count: 40, items: Array.from({ length: 40 }, (_, i) => bulky(i)),
});

async function preview(query = "") {
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async (k) => (k === "api/v1/intel/latest.json" ? { text: async () => FEED } : null) },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com/api/preview${query}`), env, { waitUntil() {} });
  const text = await res.text();
  return { status: res.status, bytes: Buffer.byteLength(text), body: JSON.parse(text) };
}

test("default page is unchanged: 25 items, first 25 of the feed, existing keys kept", async () => {
  const { status, body } = await preview();
  assert.equal(status, 200);
  const p = body.preview;
  assert.equal(p.items.length, 25);
  assert.equal(p.total_preview, 25);
  assert.equal(p.preview_limit, 25);
  assert.equal(p.feed_total, 40);
  assert.equal(p.items[0].id, "intel--0000");
  for (const k of ["items", "total_preview", "feed_total", "preview_limit", "generated_at", "version", "_tier", "_upgrade_url"]) {
    assert.ok(k in p, `existing key ${k} must remain`);
  }
  assert.equal(p.limit, 25);
  assert.equal(p.offset, 0);
  assert.equal(p.has_more, false);
  assert.equal(p.next_offset, null);
});

test("?limit=5 returns 5 items, has_more, and fits the validator read limit", async () => {
  const { bytes, body } = await preview("?limit=5");
  assert.equal(body.preview.items.length, 5);
  assert.equal(body.preview.limit, 5);
  assert.equal(body.preview.has_more, true);
  assert.equal(body.preview.next_offset, 5);
  assert.ok(bytes < 131072, `bounded page is ${bytes} bytes`);
});

test("?offset pages through the preview window without overlap", async () => {
  const a = (await preview("?limit=10&offset=0")).body.preview;
  const b = (await preview("?limit=10&offset=10")).body.preview;
  const c = (await preview("?limit=10&offset=20")).body.preview;
  assert.deepEqual([a.items[0].id, b.items[0].id, c.items[0].id], ["intel--0000", "intel--0010", "intel--0020"]);
  assert.equal(c.items.length, 5, "window ends at PREVIEW_LIMIT (25), never past it");
  assert.equal(c.has_more, false);
  assert.equal(c.next_offset, null);
});

test("pagination never exposes items beyond the 25-item FREE preview window", async () => {
  const p = (await preview("?limit=25&offset=24")).body.preview;
  assert.equal(p.items.length, 1);
  assert.equal(p.items[0].id, "intel--0024");
  const past = (await preview("?offset=999")).body.preview;
  assert.equal(past.items.length, 0);
  assert.equal(past.offset, 25);
});

test("limit is clamped to 1..25; non-numeric falls back to defaults", async () => {
  assert.equal((await preview("?limit=0")).body.preview.items.length, 1);
  assert.equal((await preview("?limit=-7")).body.preview.items.length, 1);
  assert.equal((await preview("?limit=500")).body.preview.items.length, 25);
  const junk = (await preview("?limit=abc&offset=xyz")).body.preview;
  assert.equal(junk.items.length, 25);
  assert.equal(junk.offset, 0);
});

test("paged items are still FREE-masked (no paid IOC arrays)", async () => {
  const item = (await preview("?limit=2")).body.preview.items[0];
  assert.deepEqual(item.iocs, [], "FREE view must not carry IOC values");
  assert.equal(item.ioc_count, 1);
  assert.equal(item.ioc_paywall.allowed, false);
});
