import assert from "node:assert/strict";
import { test } from "node:test";
import Adapter from "../api_adapter.js";

// ---------------------------------------------------------------------------
// P0 (2026-08-11) -- live production found every free-tier view of a
// non-CVE intelligence item (verified: OpenPhish-sourced phishing URLs)
// rendering a generic, identical "High-severity threat with credible impact
// potential..." AI verdict and "Threat actor activity tracked. Monitoring
// and detection recommended." impact context across unrelated items --
// regardless of severity variety, this collapsed distinct threats into
// boilerplate copy.
//
// Root cause: `apex_ai.threat_category` (the properly human-readable
// category, e.g. "Phishing") is paywall-gated and stripped from the
// free-tier feed response. The top-level `threat_type`/`threat_category`
// fields have also been collapsed to the generic "Threat Intelligence"
// bucket somewhere downstream of ingestion by the time a free-tier item is
// served live (verified: true_intel_ingestor.py's ingest_openphish() writes
// threat_type="PHISHING-URL", but the same item's live-served api/feed.json
// has threat_type="Threat Intelligence"). Neither value ever matched
// ATTACK_TYPE_META / VERDICT_NARRATIVE's specific keys (e.g. "Phishing"),
// so the lookup always fell through to the "default"/"Threat Intelligence"
// entries.
//
// `tags` survives that collapse intact -- every non-CVE ingester in
// true_intel_ingestor.py tags items with the category keyword -- and is
// never paywall-gated, making it the most reliable free-tier signal.
// ---------------------------------------------------------------------------

function rawPhishingItem(overrides) {
  return Object.assign(
    {
      id: "intel--test-phish",
      title: "[OpenPhish] Phishing URL: https://example-phish.test/",
      severity: "HIGH",
      sla_priority: "P3",
      risk_score: 7.05,
      tags: ["openphish", "phishing"],
      threat_type: "Threat Intelligence", // genericized value, as actually served live
      apex_ai: { predictive_risk: 7.05, ai_confidence: 20, locked: true }, // no threat_category -- paywall-gated
    },
    overrides
  );
}

test("HIGH-severity phishing item with genericized threat_type still resolves the Phishing category via tags", () => {
  const item = Adapter.normalizeIntelItem(rawPhishingItem(), 0);
  assert.equal(item.impact_context.attack_type, "Phishing");
  assert.match(item.ai_verdict, /phishing/i);
});

test("category resolution never overrides a real, already-enriched apex_ai.threat_category", () => {
  const raw = rawPhishingItem({ apex_ai: { threat_category: "Phishing", predictive_risk: 7.05, ai_confidence: 80 } });
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.impact_context.attack_type, "Phishing");
});

test("ransomware item resolves via tags even when threat_type is genericized", () => {
  const raw = rawPhishingItem({
    title: "[RANSOMWARE] LockBit: Example Corp",
    tags: ["ransomware", "lockbit", "extortion"],
    threat_type: "Threat Intelligence",
    apex_ai: {},
  });
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.impact_context.attack_type, "Ransomware");
});

test("malware-url item (URLhaus) resolves via tags", () => {
  const raw = rawPhishingItem({
    title: "[URLhaus] MALWARE: https://example-malware.test/",
    tags: ["urlhaus", "malware", "trojan"],
    threat_type: "Threat Intelligence",
    apex_ai: {},
  });
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.impact_context.attack_type, "Malware");
});

test("a genuine CVE item without a matching tag keyword is unaffected (falls through to its own threat_type)", () => {
  const raw = {
    id: "intel--test-cve",
    title: "CVE-2026-99999 - Example vulnerability",
    severity: "MEDIUM",
    sla_priority: "P3",
    threat_type: "Vulnerability",
    tags: ["T1190", "T1059"],
    apex_ai: {},
  };
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.impact_context.attack_type, "Vulnerability");
});

test("item with no recognizable category signal at all falls through to the default/generic bucket (no crash, no fabricated category)", () => {
  const raw = {
    id: "intel--test-unknown",
    title: "Unclassified intelligence item",
    severity: "LOW",
    sla_priority: "P4",
    tags: [],
    apex_ai: {},
  };
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.impact_context.attack_type, "Threat Intelligence");
});
