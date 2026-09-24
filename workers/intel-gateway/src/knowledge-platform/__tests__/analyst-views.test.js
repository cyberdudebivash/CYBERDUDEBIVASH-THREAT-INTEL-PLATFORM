import assert from "node:assert/strict";
import { test } from "node:test";
import { AnalystViewService } from "../analyst-views.js";
import { buildKnowledgePlatform, evidence, UUID_1, UUID_2 } from "./test-helpers.js";

test("AnalystViewService requires knowledgeObject and navigation dependencies", () => {
  assert.throws(() => new AnalystViewService({}), /requires knowledgeObject and navigation/);
});

test("investigationView(): returns the full Knowledge Object unmodified", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(evidence(UUID_1));
  const [view, knowledgeObject] = await Promise.all([
    platform.analystViews.investigationView(UUID_1),
    platform.object.build(UUID_1),
  ]);
  assert.equal(typeof view.generatedAt, "string");
  assert.equal(typeof knowledgeObject.generatedAt, "string");
  const { generatedAt: viewAt, ...viewRest } = view;
  const { generatedAt: objectAt, ...objectRest } = knowledgeObject;
  assert.deepEqual(viewRest, objectRest);
  assert.ok(Math.abs(Date.parse(viewAt) - Date.parse(objectAt)) < 5000);
});

test("correlationView(): composes related, similar, and contradictory evidence in one response", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(
    evidence(UUID_1, { related_cves: ["CVE-2026-5001"], verification_status: "VERIFIED" })
  );
  await intelligenceService.evidenceService.registerEvidence(
    evidence(UUID_2, { related_cves: ["CVE-2026-5001"], verification_status: "DISPUTED" })
  );

  const view = await platform.analystViews.correlationView(UUID_1);
  assert.equal(view.relatedIntelligence.length, 1);
  assert.equal(view.similarIntelligence.length, 1);
  assert.equal(view.contradictoryEvidence.length, 1);
  assert.equal(view.statusDisagreement, true);
});

test("evidenceTimeline(): reshapes version lineage into a compact per-version summary", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(evidence(UUID_1, { verification_status: "VERIFIED" }));
  const view = await platform.analystViews.evidenceTimeline(UUID_1);
  assert.equal(view.timeline.length, 1);
  assert.equal(view.timeline[0].version, 1);
  assert.equal(view.timeline[0].verification_status, "VERIFIED");
  assert.equal(typeof view.timeline[0].created_at, "string");
});

test("confidenceContext(): surfaces existing verbatim values only, reports found:false when unregistered", async () => {
  const { platform } = buildKnowledgePlatform();
  const notFound = await platform.analystViews.confidenceContext("does-not-exist");
  assert.equal(notFound.found, false);
});

test("confidenceContext(): matches the Knowledge Object's own confidenceAsRecorded field exactly", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(
    evidence(UUID_1, { canonical_confidence_object: { tier: "MEDIUM" } })
  );
  const [context, knowledgeObject] = await Promise.all([
    platform.analystViews.confidenceContext(UUID_1),
    platform.object.build(UUID_1),
  ]);
  assert.deepEqual(context.confidenceAsRecorded, knowledgeObject.confidenceAsRecorded);
});

test("intelligenceGapView(): returns gaps and their templated recommendations together", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(
    evidence(UUID_1, { related_cves: ["CVE-2026-5002"] })
  );
  const view = await platform.analystViews.intelligenceGapView(UUID_1);
  assert.equal(view.found, true);
  assert.equal(view.gaps.length, view.recommendations.length);
});

test("collectionPriorityView(): groups recommendations by dimension, ordered by gap count descending", async () => {
  const { intelligenceService, platform } = buildKnowledgePlatform();
  await intelligenceService.evidenceService.registerEvidence(
    evidence(UUID_1, {
      related_cves: ["CVE-2026-5003", "CVE-2026-5004"], // 2 gaps in this dimension
      related_threat_actors: ["APT-SOLO"], // 1 gap in this dimension
    })
  );

  const view = await platform.analystViews.collectionPriorityView(UUID_1);
  assert.equal(view.found, true);
  assert.equal(view.priorities[0].dimension, "related_cves");
  assert.equal(view.priorities[0].gapCount, 2);
  assert.ok(view.priorities.every((p, i) => i === 0 || p.gapCount <= view.priorities[i - 1].gapCount));
});

test("collectionPriorityView(): reports found:false for an unregistered evidence_uuid", async () => {
  const { platform } = buildKnowledgePlatform();
  const view = await platform.analystViews.collectionPriorityView("does-not-exist");
  assert.equal(view.found, false);
  assert.deepEqual(view.priorities, []);
});
