/**
 * Feed staleness contract (/api/feed.json envelope) and homepage fail-closed
 * publication badge.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

import { publicationEnvelope, freshnessStatusFor, evaluatePublicIntelligence } from "../freshness-contract.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../../../..");
const NOW_MS = Date.parse("2026-09-24T06:00:00Z");
const items = [{ id: "a" }, { id: "b" }];

test("feed envelope: only a proven-fresh feed is FRESH; everything else says why", () => {
  const cases = [
    [{ generated_at: "2026-09-24T05:50:00Z", count: 2, items }, "FRESH", "fresh"],
    [{ generated_at: "2026-08-26T09:55:27Z", count: 2, items }, "STALE", "stale"],
    [{ count: 2, items }, "INVALID", "missing_timestamp"],
    [{ generated_at: "yesterday", count: 2, items }, "INVALID", "invalid_timestamp"],
    [{ generated_at: "2026-09-25T06:00:00Z", count: 2, items }, "INVALID", "future_timestamp"],
    [{ generated_at: "2026-09-24T05:50:00Z", count: 0, items: [] }, "EMPTY", "empty"],
    [{ generated_at: "2026-09-24T05:50:00Z", count: 9, items }, "INVALID", "count_mismatch"],
    [null, "UNAVAILABLE", "unavailable"],
  ];
  for (const [feed, status, state] of cases) {
    const env = publicationEnvelope(feed, NOW_MS, 120);
    assert.equal(env.fields.freshness_status, status, state);
    assert.equal(env.fields.publication_state, state);
    assert.equal(env.headers["X-Sentinel-Freshness"], status);
    assert.equal(env.edge_ttl_seconds > 0, status === "FRESH", state + " edge ttl");
    assert.equal(freshnessStatusFor(evaluatePublicIntelligence(feed, NOW_MS), feed), status);
  }
  const fresh = publicationEnvelope({ generated_at: "2026-09-24T05:59:00Z", count: 2, items }, NOW_MS, 120);
  assert.equal(fresh.fields.age_seconds, 60);
  assert.equal(fresh.headers["X-Sentinel-Feed-Age-Seconds"], "60");
  const nearEdge = publicationEnvelope({ generated_at: "2026-09-24T00:01:00Z", count: 2, items }, NOW_MS, 120);
  assert.equal(nearEdge.edge_ttl_seconds, 60, "a cached fresh body never outlives the freshness window");
});

function badgeFn() {
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  const start = html.indexOf("function cdbPublicationBadge(intel)");
  assert.ok(start > 0, "cdbPublicationBadge present");
  const end = html.indexOf("window.cdbPublicationBadge", start);
  const ctx = {};
  vm.runInNewContext(html.slice(start, end) + ";this.f = cdbPublicationBadge;", ctx);
  return { f: ctx.f, html };
}

test("homepage: LIVE only from proven FRESH; absence of evidence is never LIVE", () => {
  const { f, html } = badgeFn();
  const good = { publication_state: "fresh", publication_generated_at: "2026-09-24T05:50:00Z", publication_age_seconds: 600 };
  assert.equal(f(good).text, "LIVE");
  assert.equal(f({ ...good, publication_state: "stale" }).text, "DEGRADED");
  assert.equal(f({ ...good, publication_state: undefined }).text, "UNKNOWN", "missing publication_state");
  assert.equal(f({ ...good, publication_state: "FRESH!" }).text, "UNKNOWN", "invalid publication_state");
  assert.equal(f({ ...good, publication_generated_at: undefined }).text, "UNKNOWN", "missing timestamp");
  assert.equal(f({ ...good, publication_generated_at: "2026-09-24" }).text, "UNKNOWN", "invalid timestamp");
  assert.equal(f({ ...good, publication_age_seconds: null }).text, "UNKNOWN", "missing age");
  assert.equal(f({}).text, "UNKNOWN");
  assert.equal(f(null).text, "UNAVAILABLE");
  // The static markup does not claim LIVE before evidence arrives.
  assert.doesNotMatch(html, /id="eicc-m-total-delta">LIVE</);
  assert.match(html, /id="eicc-m-total-delta">CHECKING</);
});
