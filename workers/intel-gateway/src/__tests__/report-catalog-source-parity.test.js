import assert from "node:assert/strict";
import { test } from "node:test";
import { _resolveFeedItemsById } from "../index.js";
import { evaluatePublicationGate } from "../publication-gate.js";
import { harness } from "./watchdog-harness.js";

const PRO = "api/v1/intel/latest_pro.json";
const LATEST = "api/v1/intel/latest.json";
const FALLBACK = "intel/feed_manifest.json";
const CATALOG = "api/reports/index.json";
const ID = "intel--aabbccddeeff001122334455";

function readyItem(id = ID, tlp = "TLP:CLEAR") {
  // Synthetic, fully enriched fixture: approved by the REAL P20/P21/P23/P25/P26
  // engines. No public or production intelligence is copied or modified.
  return {
    id, stix_id: id, tlp,
    title: "CVE-2026-99999: Critical RCE in Example Product",
    severity: "CRITICAL",
    description: "A".repeat(200),
    cvss_score: 9.8, risk_score: 9.8,
    kev_present: true, epss_score: 0.85,
    evidence_chain: { reliability_code: "A", source_reliability: "HIGH", source_name: "Vendor Advisory" },
    iocs: [{ value: "192.0.2.1", type: "ip", response_guidance: "Block at firewall" }],
    ioc_count: 1, ttps: ["T1190"], mitre_techniques: ["T1190"],
    detection_bundle: [{ type: "sigma", rule: "title: Example Detection" }],
    executive_summary: "Critical vulnerability requiring immediate patching.",
    exec_summary: "Critical vulnerability requiring immediate patching.",
    source_url: "https://vendor.example.com/advisory/2026-99999",
    confidence: 0.9, apex: { ai_summary: "AI narrative.", kev_listed: true },
  };
}
function r2Objects(files, reads) {
  return { async get(key) {
    reads.push(key);
    if (!Object.hasOwn(files, key)) return null;
    const text = JSON.stringify(files[key]);
    return { text: async () => text, json: async () => JSON.parse(text) };
  } };
}
function setR2(hx, files, reads) {
  const oldGet = hx.env.INTEL_R2.get;
  hx.env.INTEL_R2.get = async key => {
    reads.push(key);
    if (Object.hasOwn(files, key)) {
      const text = JSON.stringify(files[key]);
      return { text: async () => text, json: async () => JSON.parse(text) };
    }
    return oldGet(key);
  };
  hx.env.INTEL_R2.put = async () => {};
}
function catalog(id = ID) {
  return { generated_at: new Date().toISOString(), total_reports: 1, reports: [{
    id, url: `https://intel.cyberdudebivash.com/reports/2026/11/${id}.html`,
    path: `/reports/2026/11/${id}.html`, timestamp: "2026-11-12T21:00:00Z",
    title: "Synthetic quality-gate report",
  }] };
}

test("catalog source resolver: do not read fallback when all required IDs have enriched sources", async () => {
  const first = readyItem("intel--111111111111111111111111");
  const reads = [];
  const byId = await _resolveFeedItemsById({ INTEL_R2: r2Objects({
    [PRO]: { items: [first] },
    [FALLBACK]: [{ ...first, title: "lower-priority copy" }],
  }, reads) }, [first.id]);
  assert.equal(byId.get(first.id).title, first.title);
  assert.equal(reads.filter(key => key === FALLBACK).length, 0,
    "additional billable R2 GET must be conditional on unresolved catalog ID");
});

test("catalog source resolver: fifth fallback is bounded once, and never overrides richer source", async () => {
  const first = readyItem("intel--111111111111111111111111");
  const second = readyItem("intel--222222222222222222222222");
  const reads = [];
  const byId = await _resolveFeedItemsById({ INTEL_R2: r2Objects({
    [PRO]: { items: [first] },
    [LATEST]: { items: [first] },
    [FALLBACK]: [{ ...first, title: "unsafe lower-priority overwrite" }, second],
  }, reads) }, [first.id, second.id]);
  assert.equal(byId.get(first.id).title, first.title, "first-source-wins must be preserved");
  assert.equal(byId.get(second.id).title, second.title);
  assert.equal(reads.filter(key => key === FALLBACK).length, 1);
});

test("catalog source resolver: missing fallback stays unresolved without synthetic approval", async () => {
  const reads = [];
  const env = { INTEL_R2: {
    async get(key) {
      reads.push(key);
      if (key === FALLBACK) throw new Error("synthetic R2 failure");
      return null;
    },
  } };
  const byId = await _resolveFeedItemsById(env, [ID]);
  assert.equal(byId.has(ID), false);
  assert.equal(reads.filter(key => key === FALLBACK).length, 1);
});

test("catalog route: customer-ready fallback-only report is listed after real certification", async () => {
  const item = readyItem();
  assert.equal(evaluatePublicationGate(item).customer_ready, true,
    "fixture must pass unchanged real quality engines");
  const hx = harness();
  const reads = [];
  setR2(hx, { [CATALOG]: catalog(), [FALLBACK]: [item] }, reads);
  const response = await hx.call("GET", "/api/reports/index.json");
  assert.equal(response.status, 200);
  assert.equal(response.body.customer_ready_count, 1);
  assert.equal(response.body.reports[0].id, ID);
  assert.equal(reads.filter(key => key === FALLBACK).length, 1);
});

for (const tlp of ["TLP:RED", undefined]) {
  test(`catalog route: ${tlp || "missing"} TLP never publishes an otherwise quality-qualified report`, async () => {
    const item = readyItem(ID, tlp);
    if (tlp === undefined) delete item.tlp;
    assert.equal(evaluatePublicationGate(item).customer_ready, true,
      "this negative control proves TLP checks, not quality checks, deny access");
    const hx = harness();
    setR2(hx, { [CATALOG]: catalog(), [FALLBACK]: [item] }, []);
    const response = await hx.call("GET", "/api/reports/index.json");
    assert.equal(response.status, 200);
    assert.equal(response.body.customer_ready_count, 0);
    assert.deepEqual(response.body.reports, []);
  });
}

test("catalog route: historical persisted approval without current source does not advertise a 404 report", async () => {
  const item = readyItem();
  const gate = evaluatePublicationGate(item);
  const approved = {
    certification_status: "CERTIFIED", publication_status: "CUSTOMER_READY",
    policy_version: "1.0.0", content_hash: gate.content_hash, blocking_gates: [],
  };
  const hx = harness();
  setR2(hx, { [CATALOG]: catalog(), "certification/index.json": {
    records: { [ID]: approved },
  }, [FALLBACK]: [] }, []);
  const response = await hx.call("GET", "/api/reports/index.json");
  assert.equal(response.status, 200);
  assert.equal(response.body.customer_ready_count, 0);
  assert.deepEqual(response.body.reports, []);
});
