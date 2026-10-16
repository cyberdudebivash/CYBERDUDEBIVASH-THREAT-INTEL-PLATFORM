import assert from "node:assert/strict";
import { test } from "node:test";
import { buildScopeSet, handleCSVExport } from "../api-extensions.js";

const PUBLIC = "api/v1/intel/latest.json";
const PAID = "api/v1/intel/latest_pro.json";
const csvUrl = "https://intel.cyberdudebivash.com/api/export/csv";

const sample = {
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
      [PAID]: { tier: "PRO", items: [sample] },
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
    const ctx = setup({ [PAID]: { items: [sample] } });
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
    const ctx = setup({ [PAID]: { items } });
    const response = await exportCsv(ctx);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "ioc_feed_unavailable");
  }
});

test("customer-selected filters may legitimately produce empty CSV with count zero", async () => {
  const ctx = setup({ [PAID]: { items: [sample] } });
  const response = await exportCsv(ctx, "PRO", "?types=sha256&since=2026-10-15");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-record-count"), "0");
  assert.equal((await response.text()).trim().split("\n").length, 1);
});

test("CSV preserves valid limit and type filters, and spreadsheet formula guard", async () => {
  const item = { ...sample, iocs: [{ type: "domain", value: "=1+1" }, { type: "domain", value: "other.invalid" }] };
  const ctx = setup({ [PAID]: { items: [item] } });
  const response = await exportCsv(ctx, "PRO", "?types=domain&limit=1");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-record-count"), "1");
  const body = await response.text();
  assert.match(body, /domain,'=1\+1/);
  assert.doesNotMatch(body, /other\.invalid/);
  assert.match(response.headers.get("cache-control"), /no-store/);
});

test("R2 parse failure never falls back to the anonymous feed or leaks exception details", async () => {
  const ctx = setup({ [PUBLIC]: { items: [sample] }, [PAID]: { items: [sample] } });
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
