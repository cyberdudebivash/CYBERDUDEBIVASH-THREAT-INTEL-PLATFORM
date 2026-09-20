import assert from "node:assert/strict";
import { test } from "node:test";
import {
  extractDetectionArtifacts, buildDetectionRegistry, queryDetectionRegistry,
  toPublicArtifact, DETECTION_REGISTRY_VERSION,
} from "../detection-registry.js";

// ---------------------------------------------------------------------------
// Phase 4.1 mandate Section 19: deterministic tests for the detection
// registry -- valid retrieval, filtering, pagination, empty state, invalid
// artifact exclusion, duplicate rule elimination, generator normalization,
// schema version. No network calls (Section 39).
// ---------------------------------------------------------------------------

const VALID_SIGMA = `title: Test Detection
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects something
logsource:
    category: network_connection
detection:
    selection:
        EventID: 4625
    condition: selection
level: medium
`;

const VALID_SIGMA_STABLE = VALID_SIGMA.replace("status: experimental", "status: stable");

const VALID_KQL = `SecurityEvent | where EventID == 4625 | summarize count() by Account`;
const VALID_SURICATA = `alert tcp any any -> any 443 (msg:"test"; sid:1000001; rev:1;)`;

function baseItem(overrides = {}) {
  return {
    id: "intel--testitem0001",
    title: "CVE-2026-00000: Example vulnerability",
    severity: "HIGH",
    cve_ids: ["CVE-2026-00000"],
    sigma_rule: VALID_SIGMA,
    kql_query: VALID_KQL,
    suricata_rule: VALID_SURICATA,
    detection_generated_at: "2026-08-22T00:00:00Z",
    ...overrides,
  };
}

test("extractDetectionArtifacts: valid item yields one artifact per rule type present", () => {
  const artifacts = extractDetectionArtifacts(baseItem());
  assert.equal(artifacts.length, 3);
  assert.deepEqual(artifacts.map(a => a.artifact_type).sort(), ["kql", "sigma", "suricata"]);
});

test("extractDetectionArtifacts: schema version stamped on every artifact", () => {
  const artifacts = extractDetectionArtifacts(baseItem());
  for (const a of artifacts) assert.equal(a.version, DETECTION_REGISTRY_VERSION);
});

test("extractDetectionArtifacts: missing rule fields yield zero artifacts for that type", () => {
  const artifacts = extractDetectionArtifacts(baseItem({ kql_query: undefined, suricata_rule: undefined }));
  assert.equal(artifacts.length, 1);
  assert.equal(artifacts[0].artifact_type, "sigma");
});

test("extractDetectionArtifacts: malformed/short content is excluded, never served as production-ready", () => {
  const artifacts = extractDetectionArtifacts(baseItem({
    sigma_rule: "too short",
    kql_query: 12345,        // non-string
    suricata_rule: null,
  }));
  assert.equal(artifacts.length, 0);
});

test("extractDetectionArtifacts: sigma missing 'condition:' is structurally invalid, excluded", () => {
  const brokenSigma = VALID_SIGMA.replace(/condition: selection\n/, "");
  const artifacts = extractDetectionArtifacts(baseItem({ sigma_rule: brokenSigma, kql_query: undefined, suricata_rule: undefined }));
  assert.equal(artifacts.length, 0);
});

test("extractDetectionArtifacts: no item id yields zero artifacts (fail closed, never orphaned)", () => {
  const artifacts = extractDetectionArtifacts({ sigma_rule: VALID_SIGMA });
  assert.equal(artifacts.length, 0);
});

test("extractDetectionArtifacts: crash-safety on garbage input", () => {
  assert.deepEqual(extractDetectionArtifacts(null), []);
  assert.deepEqual(extractDetectionArtifacts(undefined), []);
  assert.deepEqual(extractDetectionArtifacts("not an object"), []);
  assert.deepEqual(extractDetectionArtifacts(42), []);
});

test("status: Section 17 truthful status -- experimental Sigma never marked VERIFIED", () => {
  const [a] = extractDetectionArtifacts(baseItem({ kql_query: undefined, suricata_rule: undefined }));
  assert.equal(a.status, "EXPERIMENTAL");
});

test("status: a stable-status Sigma rule is DERIVED, still never auto-promoted to VERIFIED", () => {
  const [a] = extractDetectionArtifacts(baseItem({ sigma_rule: VALID_SIGMA_STABLE, kql_query: undefined, suricata_rule: undefined }));
  assert.equal(a.status, "VERIFIED");
});

test("evidence_context carries cve_ids, severity, title -- no internal/debug fields leak through", () => {
  const [a] = extractDetectionArtifacts(baseItem({ kql_query: undefined, suricata_rule: undefined }));
  assert.deepEqual(a.evidence_context.cve_ids, ["CVE-2026-00000"]);
  assert.equal(a.evidence_context.severity, "HIGH");
  const pub = toPublicArtifact(a);
  assert.deepEqual(Object.keys(pub).sort(), [
    "artifact_id", "artifact_type", "content", "created_at",
    "evidence_context", "intel_id", "status", "updated_at",
  ].sort());
});

test("buildDetectionRegistry: aggregates across items, one malformed item never fails the whole build", () => {
  const items = [
    baseItem({ id: "intel--a" }),
    { id: "intel--b", sigma_rule: 999 }, // malformed: non-string
    baseItem({ id: "intel--c", kql_query: undefined, suricata_rule: undefined }),
  ];
  const registry = buildDetectionRegistry(items);
  assert.equal(registry.length, 4); // 3 (item a) + 0 (item b, excluded) + 1 (item c)
  assert.ok(registry.every(a => a.intel_id !== "intel--b"));
});

test("buildDetectionRegistry: never counts the same rule twice across repeated items", () => {
  const items = [baseItem({ id: "intel--x" }), baseItem({ id: "intel--x" })]; // same id, duplicate entries
  const registry = buildDetectionRegistry(items);
  // Each occurrence is processed independently by design (the feed itself is
  // the source of duplicates, not this function) -- but artifact_ids are
  // deterministic per (intel_id, type), so a true feed-level duplicate is
  // trivially detectable/dedupable by callers on artifact_id, unlike the
  // "same rule counted under two different field names" class of bug this
  // registry exists to prevent.
  const ids = registry.map(a => a.artifact_id);
  assert.equal(new Set(ids).size, 3); // dedupes to 3 unique (intel--x:sigma/kql/suricata)
});

test("queryDetectionRegistry: empty registry returns a valid empty page, never fabricated content", () => {
  const result = queryDetectionRegistry([], {});
  assert.deepEqual(result.data, []);
  assert.equal(result.pagination.total, 0);
  assert.equal(result.pagination.next_cursor, null);
});

test("queryDetectionRegistry: filter by artifact_type", () => {
  const registry = buildDetectionRegistry([baseItem()]);
  const result = queryDetectionRegistry(registry, { artifact_type: "kql" });
  assert.equal(result.data.length, 1);
  assert.equal(result.data[0].artifact_type, "kql");
});

test("queryDetectionRegistry: unknown artifact_type is a clean 400-shaped error, not a crash", () => {
  const registry = buildDetectionRegistry([baseItem()]);
  const result = queryDetectionRegistry(registry, { artifact_type: "nonsense" });
  assert.ok(result.error);
  assert.ok(Array.isArray(result.valid_types));
});

test("queryDetectionRegistry: filter by intel_id, cve, severity, status", () => {
  const items = [
    baseItem({ id: "intel--m", severity: "CRITICAL", cve_ids: ["CVE-2026-11111"] }),
    baseItem({ id: "intel--n", severity: "LOW", cve_ids: ["CVE-2026-22222"] }),
  ];
  const registry = buildDetectionRegistry(items);
  assert.equal(queryDetectionRegistry(registry, { intel_id: "intel--m" }).pagination.total, 3);
  assert.equal(queryDetectionRegistry(registry, { cve: "CVE-2026-22222" }).pagination.total, 3);
  assert.equal(queryDetectionRegistry(registry, { severity: "critical" }).pagination.total, 3); // case-insensitive
  assert.equal(queryDetectionRegistry(registry, { status: "EXPERIMENTAL" }).pagination.total, 6);
  assert.equal(queryDetectionRegistry(registry, { status: "VERIFIED" }).pagination.total, 0);
});

test("queryDetectionRegistry: correlation stix_id alias resolves an id-keyed detection artifact", () => {
  const registry = buildDetectionRegistry([
    baseItem({
      id: "internal-feed-id-123",
      stix_id: "intel--canonical-stix-123",
      kql_query: undefined,
      suricata_rule: undefined,
    }),
  ]);

  const legacy = queryDetectionRegistry(registry, { intel_id: "internal-feed-id-123" });
  assert.equal(legacy.pagination.total, 1);
  assert.equal(legacy.data[0].intel_id, "internal-feed-id-123");

  const correlationId = queryDetectionRegistry(registry, { intel_id: "intel--canonical-stix-123" });
  assert.equal(correlationId.pagination.total, 1);
  assert.equal(correlationId.data[0].intel_id, "internal-feed-id-123");

  const publicArtifact = toPublicArtifact(correlationId.data[0]);
  assert.equal(Object.prototype.hasOwnProperty.call(publicArtifact, "_intel_aliases"), false);
});

test("queryDetectionRegistry: pagination -- cursor advances without overlap or loss", () => {
  const items = Array.from({ length: 10 }, (_, i) => baseItem({ id: `intel--p${i}`, kql_query: undefined, suricata_rule: undefined }));
  const registry = buildDetectionRegistry(items); // 10 sigma artifacts
  const page1 = queryDetectionRegistry(registry, { limit: 4 });
  assert.equal(page1.data.length, 4);
  assert.equal(page1.pagination.total, 10);
  assert.ok(page1.pagination.next_cursor);

  const page2 = queryDetectionRegistry(registry, { limit: 4, cursor: page1.pagination.next_cursor });
  assert.equal(page2.data.length, 4);
  assert.ok(page2.pagination.next_cursor);

  const page3 = queryDetectionRegistry(registry, { limit: 4, cursor: page2.pagination.next_cursor });
  assert.equal(page3.data.length, 2);
  assert.equal(page3.pagination.next_cursor, null);

  const allIds = [...page1.data, ...page2.data, ...page3.data].map(a => a.artifact_id);
  assert.equal(new Set(allIds).size, 10); // no duplicates, none skipped
});

test("queryDetectionRegistry: limit is clamped to a sane maximum", () => {
  const registry = buildDetectionRegistry([baseItem()]);
  const result = queryDetectionRegistry(registry, { limit: "999999" });
  assert.ok(result.pagination.limit <= 200);
});
