// P0 2026-09-26 (evidence truth): the chain of evidence states an EPSS value
// only when its scale is proven (ingest percent string agrees with epss_score).
// Values are production items from /api/feed.json checked against FIRST.org.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEvidenceAttribution, verifiedEpssPercent } from "../p18-handlers.js";

const epssLine = (item) => buildEvidenceAttribution(item).chain_of_evidence.find((l) => l.startsWith("EPSS"));

test("percent string that agrees with epss_score is stated (FIRST.org 0.0029 = 0.29%)", () => {
  const item = { id: "intel--a", epss_score: 0.29, epss: "0.29%", cve_ids: ["CVE-2026-57232"] };
  assert.equal(verifiedEpssPercent(item), 0.29);
  assert.equal(epssLine(item), "EPSS score 0.29% assigned by FIRST.org model");
});

test("double-scaled value without a percent string is not stated (53 for FIRST.org 0.53%)", () => {
  const item = { id: "intel--b", epss_score: 53, cve_ids: ["CVE-2026-15583"] };
  assert.equal(verifiedEpssPercent(item), null);
  assert.equal(epssLine(item), undefined);
});

test("string and score that disagree are not stated", () => {
  assert.equal(verifiedEpssPercent({ epss_score: 29, epss: "0.29%" }), null);
  assert.equal(verifiedEpssPercent({ epss: "250%" }), null);
  assert.equal(verifiedEpssPercent({ epss: "high" }), null);
  assert.equal(verifiedEpssPercent(null), null);
});
