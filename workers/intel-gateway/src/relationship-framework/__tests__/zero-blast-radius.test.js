/**
 * Zero-blast-radius test for Stage 16's relationship-framework/ directory, mirroring
 * enterprise-gateway/__tests__/zero-blast-radius.test.js (Stage 14 precedent) exactly. Confirms
 * this stage's new directory has not been wired into any production route, imports
 * evidence-registry/ only through the one authorized, pre-existing file
 * (relationship-resolution.js), and never imports a pNN-handlers.js file directly -- the
 * property that makes ADR-0010's Acceptance safe even though this directory now carries real
 * relationship data.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "../../__tests__/boundary-scan-helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const RF_DIR = dirname(HERE); // .../relationship-framework
const WORKER_SRC_DIR = dirname(RF_DIR); // .../src
const EVIDENCE_REGISTRY_DIR = join(WORKER_SRC_DIR, "evidence-registry");
const INTELLIGENCE_PLATFORM_DIR = join(WORKER_SRC_DIR, "intelligence-platform");
const ENTERPRISE_GATEWAY_DIR = join(WORKER_SRC_DIR, "enterprise-gateway");

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
  assert.equal(isInside(join(RF_DIR, "relationship-service.js"), RF_DIR), true);
  assert.equal(isInside(RF_DIR, RF_DIR), true);
  assert.equal(
    isInside(join(WORKER_SRC_DIR, "relationship-framework-experimental", "x.js"), RF_DIR),
    false,
    "a sibling directory whose name extends RF_DIR's name must NOT be treated as inside it"
  );
});

test("nothing outside relationship-framework/ references 'relationship-framework' except the documented sibling-directory exceptions", () => {
  // Each sibling directory's own zero-blast-radius.test.js legitimately names this directory in
  // its own AUTHORIZED_CONSUMER_DIRS (Stage 16 addition, cascading: evidence-registry ->
  // intelligence-platform's own verifying test -> enterprise-gateway's own verifying test) --
  // that is boundary documentation, not production coupling. Those three test files, plus the
  // three PRODUCTION files Stage 16 deliberately edited to update now-stale ADR-0010 prose
  // (their own docstrings/description strings citing where the real wiring now lives -- see
  // TITAN_STAGE16_RELATIONSHIP_FRAMEWORK_REPORT.md's file list), are the permitted exceptions --
  // none of the six gained an IMPORT of this directory, only a
  // comment/description-string mention. Everything else must be clean, including index.js and
  // every pNN-handlers.js file, checked explicitly below.
  const violations = [];
  const documentationOnlyExceptions = new Set([
    join(EVIDENCE_REGISTRY_DIR, "__tests__", "zero-blast-radius.test.js"),
    join(EVIDENCE_REGISTRY_DIR, "relationship-resolution.js"),
    join(INTELLIGENCE_PLATFORM_DIR, "correlation-engine.js"),
    join(INTELLIGENCE_PLATFORM_DIR, "__tests__", "zero-blast-radius.test.js"),
    join(ENTERPRISE_GATEWAY_DIR, "gateway-service.js"),
    join(ENTERPRISE_GATEWAY_DIR, "__tests__", "zero-blast-radius.test.js"),
  ]);
  for (const file of listJsFiles(WORKER_SRC_DIR)) {
    if (isInside(file, RF_DIR)) continue; // files inside this directory are exempt
    if (documentationOnlyExceptions.has(file)) continue; // see above -- prose only, no import
    const text = stripComments(readFileSync(file, "utf-8"));
    if (text.includes("relationship-framework")) {
      violations.push(relative(WORKER_SRC_DIR, file));
    }
  }
  assert.deepEqual(violations, [], `boundary violation(s) found: ${violations.join(", ")}`);
});

test("index.js does not import any relationship-framework file", () => {
  const indexJs = join(WORKER_SRC_DIR, "index.js");
  const text = readFileSync(indexJs, "utf-8");
  for (const newFile of [
    "relationship-types.js",
    "relationship-registry.js",
    "edge-repository-interface.js",
    "in-memory-edge-repository.js",
    "p31-edge-adapter.js",
    "relationship-provider.js",
    "relationship-traversal.js",
    "relationship-validation.js",
    "relationship-metrics.js",
    "relationship-lookup.js",
    "relationship-service.js",
  ]) {
    assert.equal(text.includes(newFile), false, `index.js must not reference ${newFile}`);
  }
});

test("relationship-framework/ production files never import a pNN-handlers.js file or index.js directly", () => {
  const rfTestsDir = join(RF_DIR, "__tests__");
  for (const file of listJsFiles(RF_DIR)) {
    if (isInside(file, rfTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    assert.equal(/from\s+["'].*p\d+-handlers\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import a pNN-handlers.js file`);
    assert.equal(/from\s+["'].*\/index\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import index.js`);
  }
});

test("relationship-framework/ production files import evidence-registry/ only via relationship-resolution.js or service-contracts.js, nothing broader", () => {
  // service-contracts.js is authorized on the same precedent intelligence-platform/service-contracts.js
  // (Stage 13) already established: reusing isContractForwardCompatible()/checkContractCompatibility()
  // UNCHANGED rather than redefining them (Reuse Before Build) -- see this file's own docstring.
  const AUTHORIZED_EVIDENCE_REGISTRY_IMPORTS = new Set(["relationship-resolution.js", "service-contracts.js"]);
  const rfTestsDir = join(RF_DIR, "__tests__");
  for (const file of listJsFiles(RF_DIR)) {
    if (isInside(file, rfTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    const evidenceRegistryImports = [...text.matchAll(/from\s+["']\.\.\/evidence-registry\/([\w-]+\.js)["']/g)];
    for (const match of evidenceRegistryImports) {
      assert.ok(
        AUTHORIZED_EVIDENCE_REGISTRY_IMPORTS.has(match[1]),
        `${relative(WORKER_SRC_DIR, file)} imports evidence-registry/${match[1]} -- not on the authorized list`
      );
    }
  }
});

test("relationship-framework/ production files never IMPORT intelligence-platform/ or enterprise-gateway/ (composition happens the other way -- those directories inject a relationship-framework-backed provider into themselves, not vice versa). Checks actual import statements, not bare substring, since this stage's own docstrings legitimately CITE both stages by name as precedent (e.g. service-contracts.js's own module docstring) without importing either.", () => {
  const rfTestsDir = join(RF_DIR, "__tests__");
  for (const file of listJsFiles(RF_DIR)) {
    if (isInside(file, rfTestsDir)) continue;
    const text = readFileSync(file, "utf-8");
    assert.deepEqual(
      [...text.matchAll(/from\s+["']\.\.\/intelligence-platform\//g)],
      [],
      `${relative(WORKER_SRC_DIR, file)} must not import intelligence-platform/`
    );
    assert.deepEqual(
      [...text.matchAll(/from\s+["']\.\.\/enterprise-gateway\//g)],
      [],
      `${relative(WORKER_SRC_DIR, file)} must not import enterprise-gateway/`
    );
  }
  void INTELLIGENCE_PLATFORM_DIR;
  void ENTERPRISE_GATEWAY_DIR;
});

test("evidence-registry/__tests__/zero-blast-radius.test.js's Stage 16 exception names exactly this directory, nothing broader", () => {
  const text = readFileSync(join(EVIDENCE_REGISTRY_DIR, "__tests__", "zero-blast-radius.test.js"), "utf-8");
  assert.match(text, /join\(WORKER_SRC_DIR,\s*"relationship-framework"\)/);
});
