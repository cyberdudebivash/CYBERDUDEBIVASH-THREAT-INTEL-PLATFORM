import assert from "node:assert/strict";
import { test } from "node:test";
import { buildScopeSet, handleCSVExport } from "../api-extensions.js";

const PUBLIC = "api/v1/intel/latest.json";
const PAID = "api/v1/intel/latest_pro.json";
const csvUrl = "https://intel.cyberdudebivash.com/api/export/csv";

const sample = {
  id: "intel--synthetic-fixture",
  tlp: "TLP:CLEAR",
  stix_id: "report--00000000-0000-4000-8000-000000000001",
  title: "Synthetic regression advisory, not a production IOC",
  severity: "HIGH",
  risk_score: 8,
  processed_at: "2026-10-16T10:00:00Z",
  iocs: [
    { type: "domain", value: "fixture.invalid", confidence: 0.9 },
    { type: "ipv4", value: "192.0.2.4", confidence: 0.8 },
    null,
    { type: "domain", value: "   " },
    { type: "domain", value: null },
  ],
};

function freshPaid(items, overrides = {}) {
  return {
    tier: "PRO",
    generated_at: new Date().toISOString(),
    count: items.length,
    items,
    ...overrides,
  };
}

function setup(files = {}) {
  const reads = [];
  return {
    reads,
    env: {
      INTEL_R2: {
        async get(key) {
          reads.push(key);
          if (!Object.hasOwn(files, key)) return null;
          return { async json() { return files[key]; } };
        },
      },
      // A stale shared/public cache must never affect an authenticated CSV.
      SECURITY_HUB_KV: { async get() { throw Error("public KV cache must not be read"); } },
    },
  };
}

function auth(tier = "PRO") {
  return { tier, scopes: buildScopeSet(tier, null) };
}

async function exportCsv(ctx, tier = "PRO", suffix = "") {
  return handleCSVExport(new Request(csvUrl + suffix), ctx.env, auth(tier), "csv-regression");
}

test("PRO/ENTERPRISE/MSSP export real authorized IOC rows exclusively from paid R2 manifest", async () => {
  for (const tier of ["PRO", "ENTERPRISE", "MSSP"]) {
    const ctx = setup({
      [PUBLIC]: { items: [{ ...sample, iocs: undefined, ioc_count: 2 }] },
      [PAID]: freshPaid([sample]),
    });
    const response = await exportCsv(ctx, tier);
    const body = await response.text();
    assert.equal(response.status, 200, tier);
    assert.equal(response.headers.get("x-record-count"), "2", tier);
    assert.match(body, /^ioc_type,ioc_value,confidence,/);
    assert.match(body, /domain,fixture\.invalid/);
    assert.match(body, /ipv4,192\.0\.2\.4/);
    assert.deepEqual(ctx.reads, [PAID], tier);
  }
});

test("FREE and explicitly unscoped PRO never read either R2 object", async () => {
  for (const identity of [auth("FREE"), { tier: "PRO", scopes: ["read:intel"] }]) {
    const ctx = setup({ [PAID]: freshPaid([sample]) });
    const response = await handleCSVExport(new Request(csvUrl), ctx.env, identity, "scope-denied");
    assert.equal(response.status, 403);
    assert.deepEqual(ctx.reads, []);
    assert.doesNotMatch(await response.text(), /fixture\.invalid/);
  }
});

test("missing paid source fails closed even when public projection is fresh", async () => {
  const ctx = setup({ [PUBLIC]: { items: [{ ...sample, iocs: undefined, ioc_count: 2 }] } });
  const response = await exportCsv(ctx);
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "ioc_feed_unavailable");
  assert.deepEqual(ctx.reads, [PAID]);
});

test("header-only or malformed paid source is 503, never a success", async () => {
  for (const items of [[], [{ ...sample, iocs: undefined }], [{ ...sample, iocs: [null, { type: "domain", value: "" }] }]]) {
    const ctx = setup({ [PAID]: freshPaid(items) });
    const response = await exportCsv(ctx);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "ioc_feed_unavailable");
  }
});

test("stale or unverifiable PRO intelligence cannot be exported as live IOC CSV", async () => {
  const old = new Date(Date.now() - 7 * 3600 * 1000).toISOString();
  const future = new Date(Date.now() + 4 * 3600 * 1000).toISOString();
  const scenarios = [
    ["expired", { generated_at: old }],
    ["missing timestamp", { generated_at: undefined }],
    ["invalid timestamp", { generated_at: "not-a-date" }],
    ["impossible future", { generated_at: future }],
    ["incorrect count", { count: 8 }],
    ["missing record ID", { items: [{ ...sample, id: undefined }] }],
  ];
  for (const [label, changes] of scenarios) {
    const ctx = setup({
      // Public fallback is available, but paid scope must never be silently downgraded.
      [PUBLIC]: freshPaid([sample]),
      [PAID]: freshPaid([sample], changes),
    });
    const response = await exportCsv(ctx);
    assert.equal(response.status, 503, label);
    assert.match(response.headers.get("cache-control"), /no-store/, label);
    const body = await response.text();
    assert.match(body, /paid_intelligence_freshness_unverified/, label);
    assert.doesNotMatch(body, /fixture\.invalid|192\.0\.2\.4|private R2/i, label);
    assert.deepEqual(ctx.reads, [PAID], label);
  }
});

test("paid IOC export denies restricted or unlabeled source and nested TLP contradictions", async () => {
  const scenarios = [
    ["restricted", { ...sample, tlp: "TLP:RED" }],
    ["missing classification", { ...sample, tlp: undefined }],
    ["conflicting labels", { ...sample, classification: "TLP:CLEAR; TLP:AMBER" }],
    ["restricted nested advisory", {
      ...sample,
      related: { id: "intel--red-child", title: "Withheld child", tlp: "TLP:RED" },
    }],
  ];
  for (const [label, item] of scenarios) {
    const ctx = setup({ [PAID]: freshPaid([item]) });
    const response = await exportCsv(ctx);
    assert.equal(response.status, 503, label);
    assert.match(response.headers.get("cache-control"), /no-store/, label);
    const body = await response.text();
    assert.match(body, /paid_intelligence_classification_unverified/, label);
    assert.doesNotMatch(body, /fixture\.invalid|192\.0\.2\.4|Withheld child/i, label);
    assert.deepEqual(ctx.reads, [PAID], label);
  }
});

test("five-hour-old valid PRO data stays usable, but data beyond six hours fails", async () => {
  const valid = setup({ [PAID]: freshPaid([sample], {
    generated_at: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
  }) });
  const good = await exportCsv(valid);
  assert.equal(good.status, 200);
  assert.match(await good.text(), /fixture\.invalid/);

  const expired = setup({ [PAID]: freshPaid([sample], {
    generated_at: new Date(Date.now() - 6 * 3600 * 1000 - 30000).toISOString(),
  }) });
  const denied = await exportCsv(expired);
  assert.equal(denied.status, 503);
  assert.doesNotMatch(await denied.text(), /fixture\.invalid/);
});

test("customer-selected filters may legitimately produce empty CSV with count zero", async () => {
  const ctx = setup({ [PAID]: freshPaid([sample]) });
  const response = await exportCsv(ctx, "PRO", "?types=sha256&since=2026-10-15");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-record-count"), "0");
  assert.equal((await response.text()).trim().split("\n").length, 1);
});

test("CSV preserves valid limit and type filters, and spreadsheet formula guard", async () => {
  const item = { ...sample, iocs: [{ type: "domain", value: "=1+1" }, { type: "domain", value: "other.invalid" }] };
  const ctx = setup({ [PAID]: freshPaid([item]) });
  const response = await exportCsv(ctx, "PRO", "?types=domain&limit=1");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-record-count"), "1");
  const body = await response.text();
  assert.match(body, /domain,'=1\+1/);
  assert.doesNotMatch(body, /other\.invalid/);
  assert.match(response.headers.get("cache-control"), /no-store/);
});

test("R2 parse failure never falls back to the anonymous feed or leaks exception details", async () => {
  const ctx = setup({ [PUBLIC]: { items: [sample] }, [PAID]: freshPaid([sample]) });
  ctx.env.INTEL_R2.get = async (key) => {
    ctx.reads.push(key);
    return { async json() { throw Error("private R2 infrastructure detail"); } };
  };
  const response = await exportCsv(ctx);
  assert.equal(response.status, 500);
  const body = await response.text();
  assert.match(body, /csv_export_failed/);
  assert.doesNotMatch(body, /private R2 infrastructure detail/);
  assert.deepEqual(ctx.reads, [PAID]);
});

test("missing confidence stays empty, explicit zero stays zero, invalid limits cannot empty exports", async () => {
  const item = { ...sample, id: "advisory-123", stix_id: null,
    iocs: [{ type: "domain", value: "unscored.invalid" }, { type: "ipv4", value: "192.0.2.8", confidence: 0 }] };
  const ctx = setup({ [PAID]: freshPaid([item]) });
  const response = await exportCsv(ctx, "PRO", "?limit=-99");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-record-count"), "2");
  const csv = await response.text();
  assert.match(csv, /domain,unscored\.invalid,,advisory-123/);
  assert.match(csv, /ipv4,192\.0\.2\.8,0,advisory-123/);
  assert.doesNotMatch(csv, /,0\.7,/);
});
