import assert from "node:assert/strict";
import { test } from "node:test";
import { auditPublicFeedDocument, inspectLocalFile } from "../../scripts/p0_r2_public_feed_diagnostic.mjs";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const NOW = Date.parse("2026-10-13T07:00:00Z");
const generated = new Date(NOW - 60_000).toISOString();
const item = overrides => ({
  id: "intel--synthetic-canary", title: "SECRET_FICTIONAL_CANARY_SHOULD_NEVER_BE_LOGGED",
  tlp: "TLP:CLEAR", severity: "HIGH", ...overrides,
});
const feed = (...items) => ({ generated_at: generated, count: items.length, items });

test("verified fresh CLEAR public feed is deliverable", () => {
  const r = auditPublicFeedDocument(feed(item()), NOW);
  assert.equal(r.verdict, "DELIVERABLE");
  assert.equal(r.worker_public_tlp_gate, "PASS");
  assert.equal(r.top_level_label_counts["TLP:CLEAR"], 1);
  assert.equal(r.root_cause_family, "NONE");
  assert.equal(JSON.stringify(r).includes("SECRET_FICTIONAL_CANARY"), false);
  assert.equal(JSON.stringify(r).includes("intel--synthetic-canary"), false);
});

for (const label of ["TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED", "TLP:WHITE", "nonsense"]) {
  test("explicit denied label cannot be certified as public: " + label, () => {
    const r = auditPublicFeedDocument(feed(item({ tlp: label })), NOW);
    assert.equal(r.verdict, "BLOCKED");
    assert.equal(r.worker_public_tlp_gate, "BLOCKED");
    assert.equal(r.top_level_label_counts[label === "TLP:WHITE" || label === "nonsense" ? "INVALID" : label], 1);
  });
}

test("unlabeled title/id is not silently promoted to CLEAR", () => {
  const value = item();
  delete value.tlp;
  const r = auditPublicFeedDocument(feed(value), NOW);
  assert.equal(r.verdict, "BLOCKED");
  assert.equal(r.top_level_label_counts.MISSING, 1);
  assert.equal(r.unlabeled_advisory_candidates, 1);
});

test("unlabeled id-only top-level record is flagged even if old Worker heuristic misses it", () => {
  const r = auditPublicFeedDocument(feed({ id: "intel--no-title", severity: "HIGH" }), NOW);
  assert.equal(r.verdict, "BLOCKED");
  assert.equal(r.top_level_label_counts.MISSING, 1);
  assert.equal(r.worker_public_tlp_gate, "PASS"); // existing bug signal, not authorization
});

test("nested RED under outer CLEAR never passes", () => {
  const r = auditPublicFeedDocument(feed(item({ linked_evidence: [{ tlp: "TLP:RED" }] })), NOW);
  assert.equal(r.verdict, "BLOCKED");
  assert.equal(r.nested_label_counts["TLP:RED"], 1);
});

test("missing or invalid timestamp blocks even CLEAR objects", () => {
  const a = auditPublicFeedDocument({ count: 1, items: [item()] }, NOW);
  const b = auditPublicFeedDocument({ generated_at: "not-a-date", count: 1, items: [item()] }, NOW);
  assert.equal(a.verdict, "BLOCKED");
  assert.equal(b.verdict, "BLOCKED");
  assert.equal(a.root_cause_family, "FEED_FRESHNESS_OR_STRUCTURE");
});

test("oversized traversal budget rejects rather than skipping hidden labels", () => {
  const excessive = Array.from({ length: 26000 }, () => "x");
  const r = auditPublicFeedDocument(feed(item({ auxiliary: excessive })), NOW);
  assert.equal(r.verdict, "BLOCKED");
  assert.equal(r.worker_node_budget_exceeded, true);
});

test("private local file inspection does not echo raw inputs", () => {
  const d = mkdtempSync(path.join(tmpdir(), "p0-readonly-census-"));
  try {
    const f = path.join(d, "feed.json");
    writeFileSync(f, JSON.stringify(feed(item())));
    const r = inspectLocalFile(f, NOW);
    assert.equal(r.verdict, "DELIVERABLE");
    assert.equal(JSON.stringify(r).includes("SECRET_FICTIONAL_CANARY"), false);
    writeFileSync(f, "{bad");
    assert.throws(() => inspectLocalFile(f, NOW), /LOCAL_DOCUMENT_NOT_JSON/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("wrong input shape must never certify a public advisory list", () => {
  assert.equal(auditPublicFeedDocument([item()], NOW).verdict, "BLOCKED");
  assert.equal(auditPublicFeedDocument(null, NOW).verdict, "BLOCKED");
});
