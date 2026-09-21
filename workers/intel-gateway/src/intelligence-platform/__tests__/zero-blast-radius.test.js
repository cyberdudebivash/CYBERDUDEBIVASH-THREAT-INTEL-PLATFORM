/**
 * Zero-blast-radius test for Stage 13's intelligence-platform/ directory, mirroring
 * evidence-registry/__tests__/zero-blast-radius.test.js's exact pattern (Stage 8-12 precedent).
 * Confirms this stage's brand-new directory has not been wired into any production route, and
 * confirms it did not have to modify evidence-registry/ (a Stage 8-12 file set) to compose it.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "../../__tests__/boundary-scan-helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EIPS_DIR = dirname(HERE); // .../intelligence-platform
const WORKER_SRC_DIR = dirname(EIPS_DIR); // .../src
const EVIDENCE_REGISTRY_DIR = join(WORKER_SRC_DIR, "evidence-registry");

/**
 * Stage 14 (Project TITAN): enterprise-gateway/ is the first explicitly-authorized consumer of
 * this directory -- its own brief requires composing IntelligenceService via dependency
 * injection (see TITAN_STAGE14_SERVICE_ARCHITECTURE.md), mirroring exactly how
 * evidence-registry/__tests__/zero-blast-radius.test.js's own AUTHORIZED_CONSUMER_DIRS
 * authorized this directory as Stage 13's consumer one layer down. This does not weaken what
 * this test actually protects: intelligence-platform/ still must not be reachable from index.js
 * or any pNN-handlers.js file -- see the "index.js does not import..." test below, and
 * enterprise-gateway/__tests__/zero-blast-radius.test.js's own independent boundary tests, which
 * confirm both that index.js does not import enterprise-gateway/ and that enterprise-gateway/
 * never imports a pNN-handlers.js file or index.js itself, nor evidence-registry/ directly.
 * Exempting this one named, documented directory -- rather than relaxing the check generally --
 * keeps this test able to catch any OTHER, unauthorized reference.
 *
 * Stage 16: relationship-framework/ is added for the same reason -- ADR-0010 Acceptance means
 * its production code legitimately composes createIntelligencePlatform() (its integration test
 * injects a real relationshipResolution via that factory's `deps` parameter; see
 * relationship-framework/__tests__/integration.test.js). Its own docstrings also cite
 * "intelligence-platform" by name as precedent (service-contracts.js) without importing it,
 * and its own zero-blast-radius test necessarily names this directory throughout -- exempting
 * the whole directory, as already done for enterprise-gateway above, covers both without
 * weakening what this test actually protects (index.js/pNN-handlers.js reachability, checked
 * independently below).
 *
 * Stage 18: knowledge-platform/ is added because its production code legitimately composes
 * IntelligenceService's own public lookup/correlation/provenance/explainability properties (one
 * hop up, the same pattern enterprise-gateway/ already uses) and imports one pure function,
 * correlation-policy.js's detectConflicts(), directly (see TITAN_STAGE18_READINESS_REPORT.md
 * Sec 3 for why that one-hop-down import is authorized and does not create a circular
 * dependency -- knowledge-platform/ is a peer of enterprise-gateway/, not a consumer of it, and
 * intelligence-service.js itself is not modified to reference knowledge-platform/ at all, which
 * the "intelligence-service.js does not import knowledge-platform/" test in knowledge-platform/
 * __tests__/zero-blast-radius.test.js independently confirms).
 *
 * Stage 19: product-platform/ is added because its feature-flags.js docstring names
 * "intelligence-platform" in prose (documenting that it composes knowledge-platform/, not this
 * directory, directly), not because its production code imports this directory -- it does not
 * (product-platform/ holds itself to the one-hop-down rule into knowledge-platform/ only, per
 * TITAN_STAGE19_READINESS_REPORT.md Sec 3.2 and its own independent zero-blast-radius test).
 *
 * Stage 21: commercial-catalog/ is added because its __tests__/gateway-integration.test.js
 * imports createIntelligencePlatform directly to build isolated, fully-composed test fixtures,
 * mirroring product-platform/__tests__/gateway-integration.test.js's identical pattern exactly
 * (see TITAN_STAGE21_GATEWAY_ACTIVATION_AUDIT.md Sec 3). commercial-catalog/'s own PRODUCTION
 * code (platform.js) does not import this directory -- it reaches IntelligenceService only via
 * EnterpriseGateway's already-public `platform` getter, one hop further removed than even
 * knowledge-platform/product-platform's own production code -- confirmed independently by
 * commercial-catalog/__tests__/zero-blast-radius.test.js.
 */
const AUTHORIZED_CONSUMER_DIRS = [
  join(WORKER_SRC_DIR, "enterprise-gateway"),
  join(WORKER_SRC_DIR, "relationship-framework"),
  join(WORKER_SRC_DIR, "knowledge-platform"),
  join(WORKER_SRC_DIR, "product-platform"),
  join(WORKER_SRC_DIR, "commercial-catalog"),
];

/**
 * True only if `file` IS `dir`, or is a path strictly inside it -- a bare `startsWith(dir)`/
 * `.includes(\`${dir}/...\`)` also matches a sibling directory whose name merely EXTENDS `dir`'s
 * name (no separator in between), and hardcoding `/` breaks on Windows where `join()` produces
 * `\`. Requiring `path.sep` immediately after `dir` closes both gaps. Mirrors
 * evidence-registry/__tests__/zero-blast-radius.test.js's own identical helper.
 */
function isInside(file, dir) {
  return file === dir || file.startsWith(dir + sep);
}

function listJsFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (name === "node_modules") continue;
      out.push(...listJsFiles(full));
    } else if (name.endsWith(".js")) {
      out.push(full);
    }
  }
  return out;
}

test("isInside does not treat a sibling directory whose name merely extends dir's name as being inside it", () => {
  assert.equal(isInside(join(EIPS_DIR, "platform.js"), EIPS_DIR), true, "a real child file must still match");
  assert.equal(isInside(EIPS_DIR, EIPS_DIR), true, "the directory itself must match");
  assert.equal(
    isInside(join(WORKER_SRC_DIR, "intelligence-platform-experimental", "x.js"), EIPS_DIR),
    false,
    "a sibling directory whose name extends EIPS_DIR's name must NOT be treated as inside it"
  );
});

test("nothing outside intelligence-platform/ references 'intelligence-platform'", () => {
  // __tests__ directories are exempt from this sweep: this test's own counterpart in
  // evidence-registry/__tests__/zero-blast-radius.test.js legitimately documents this
  // directory BY NAME in its own authorized-exception comment (the mirror image of what this
  // file does for evidence-registry below) -- that is boundary documentation, not production
  // coupling. Production reachability is what actually matters and is covered precisely by the
  // two tests below (index.js, and pNN-handlers.js/index.js imports from inside this directory).
  const violations = [];
  const evidenceRegistryTestsDir = join(EVIDENCE_REGISTRY_DIR, "__tests__");
  for (const file of listJsFiles(WORKER_SRC_DIR)) {
    if (isInside(file, EIPS_DIR)) continue; // files inside this directory are exempt
    if (isInside(file, evidenceRegistryTestsDir)) continue; // see above
    if (AUTHORIZED_CONSUMER_DIRS.some((dir) => isInside(file, dir))) continue; // Stage 14, see above
    const text = stripComments(readFileSync(file, "utf-8"));
    if (text.includes("intelligence-platform")) {
      violations.push(relative(WORKER_SRC_DIR, file));
    }
  }
  assert.deepEqual(violations, [], `boundary violation(s) found: ${violations.join(", ")}`);
});

test("index.js does not import any intelligence-platform/ file", () => {
  const indexJs = join(WORKER_SRC_DIR, "index.js");
  const text = readFileSync(indexJs, "utf-8");
  for (const newFile of [
    "intelligence-service.js",
    "query-service.js",
    "correlation-engine.js",
    "platform.js",
    "service-contracts.js",
    "correlation-policy.js",
    "explainability-engine.js",
  ]) {
    assert.equal(text.includes(newFile), false, `index.js must not reference ${newFile}`);
  }
});

test("intelligence-platform/ never imports a pNN-handlers.js file or index.js directly (same boundary rule evidence-registry/README.md documents for itself)", () => {
  const eipsTestsDir = join(EIPS_DIR, "__tests__");
  for (const file of listJsFiles(EIPS_DIR)) {
    if (isInside(file, eipsTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    assert.equal(/from\s+["'].*p\d+-handlers\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import a pNN-handlers.js file`);
    assert.equal(/from\s+["'].*\/index\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import index.js`);
  }
});

test("intelligence-platform/ only imports evidence-registry/ files that already exist -- it does not modify evidence-registry/ itself", () => {
  const evidenceRegistryFiles = new Set(readdirSync(EVIDENCE_REGISTRY_DIR).filter((f) => f.endsWith(".js")));
  const eipsTestsDir = join(EIPS_DIR, "__tests__");
  for (const file of listJsFiles(EIPS_DIR)) {
    if (isInside(file, eipsTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    const importMatches = [...text.matchAll(/from\s+["']\.\.\/evidence-registry\/([\w-]+\.js)["']/g)];
    for (const match of importMatches) {
      assert.ok(evidenceRegistryFiles.has(match[1]), `${match[1]} imported from evidence-registry/ must be a pre-existing Stage 8-12 file`);
    }
  }
});

test("no evidence-registry/ PRODUCTION file references intelligence-platform/ (one-directional dependency, matching P-layer import direction)", () => {
  // evidence-registry/__tests__/zero-blast-radius.test.js is exempt: it legitimately documents
  // this directory BY NAME in its own authorized-exception comment (see that file). What this
  // test actually protects -- evidence-registry's PRODUCTION code never importing "upward" into
  // its one authorized consumer -- is unaffected by a test file's own boundary documentation.
  const evidenceRegistryTestsDir = join(EVIDENCE_REGISTRY_DIR, "__tests__");
  for (const file of listJsFiles(EVIDENCE_REGISTRY_DIR)) {
    if (isInside(file, evidenceRegistryTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    assert.equal(text.includes("intelligence-platform"), false, `${relative(WORKER_SRC_DIR, file)} must not reference intelligence-platform/`);
  }
});

test("evidence-registry/__tests__/zero-blast-radius.test.js's authorized exceptions name exactly these six directories, nothing broader (the exempted test file itself stays honest)", () => {
  // Stage 14: evidence-registry's own array grew a second, narrowly-named entry
  // (enterprise-gateway) alongside this stage's pre-existing intelligence-platform entry -- see
  // that file's own updated doc comment for why. Stage 16 added a third (relationship-framework).
  // Stage 18 added a fourth (knowledge-platform). Stage 19 added a fifth (product-platform).
  // Stage 21 added a sixth (commercial-catalog). This assertion is updated in lockstep so it
  // keeps proving the array is exactly these six named directories, not a general relaxation.
  const text = readFileSync(join(EVIDENCE_REGISTRY_DIR, "__tests__", "zero-blast-radius.test.js"), "utf-8");
  assert.match(
    text,
    /AUTHORIZED_CONSUMER_DIRS\s*=\s*\[\s*join\(WORKER_SRC_DIR,\s*"intelligence-platform"\),\s*join\(WORKER_SRC_DIR,\s*"enterprise-gateway"\),\s*join\(WORKER_SRC_DIR,\s*"relationship-framework"\),\s*join\(WORKER_SRC_DIR,\s*"knowledge-platform"\),\s*join\(WORKER_SRC_DIR,\s*"product-platform"\),\s*join\(WORKER_SRC_DIR,\s*"commercial-catalog"\),?\s*\]/
  );
});
