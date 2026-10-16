/**
 * Enterprise failure-watch canary vs a feed that moves during the run.
 * The production failure on 2026-10-16 was a second watch built from the
 * startup snapshot after the authoritative feed had already been replaced.
 * A miss must stay a miss: the canary does not pass without a recorded event.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { ENT_KEY, FEED_ITEMS, feedObject, harness } from "../../workers/intel-gateway/src/__tests__/watchdog-harness.js";
import { runEnterpriseCanary } from "./canary-lib.mjs";

function bind(h) {
  return (method, p, opts = {}) => h.call(method, p, opts);
}

function sinkFor(h) {
  h.net.dns.set("sink.owner.example", [{ type: 1, data: "93.184.216.34" }]);
  const url = "https://sink.owner.example/wd";
  const recs = [];
  let mode = { status: 204 };
  h.net.receivers.set(url, async (init) => {
    const body = JSON.parse(init.body);
    recs.unshift({ headers: init.headers, raw: init.body });
    if (body.type === "watchdog.verification") return { status: 200, body: { challenge: body.challenge } };
    return mode;
  });
  return {
    url,
    records: async () => { await h.runAlarms(); return recs; },
    setMode: async (status, ra) => { mode = { status, headers: ra ? { "Retry-After": String(ra) } : {} }; },
  };
}

test("failure watch is chosen from the feed generation that replaced the startup snapshot", async () => {
  const h = harness();
  const rotated = [{ id: "intel--after-1", title: "Fortinet firewall zero-day", severity: "CRITICAL", source: "Vendor", cve_ids: ["CVE-2026-7777"], processed_at: "2026-10-16T06:12:38Z" }];
  const ev = await runEnterpriseCanary({
    http: bind(h),
    key: ENT_KEY,
    runId: "rotate",
    feedItems: FEED_ITEMS,
    sink: sinkFor(h),
    sleep: async () => {},
    loadFeed: async () => {
      h.state.feed = feedObject(rotated, 30);
      return rotated;
    },
  });
  assert.equal(ev.result, "PASS");
  assert.equal(ev.failure_matched_item_id, "intel--after-1");
  assert.equal(ev.failure_attempts, 1);
  assert.ok(ev.steps.some((s) => s.step === "failure_recorded"));
});

test("failure watch does not pass when the live feed never matches", async () => {
  const h = harness();
  const ghost = [{ id: "intel--ghost", title: "distinctive cryptominer campaign", severity: "HIGH", cve_ids: ["CVE-2026-8888"], processed_at: "2026-10-16T06:12:38Z" }];
  await assert.rejects(
    () => runEnterpriseCanary({
      http: bind(h),
      key: ENT_KEY,
      runId: "miss",
      feedItems: FEED_ITEMS,
      sink: sinkFor(h),
      sleep: async () => {},
      loadFeed: async () => ghost,
    }),
    (err) => err.step === "failure_event" && /no event for failure watch/.test(String(err.message)),
  );
});
