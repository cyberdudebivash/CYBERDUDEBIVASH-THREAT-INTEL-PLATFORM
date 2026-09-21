/**
 * Zero-blast-radius test for Stage 19's product-platform/ directory, mirroring
 * knowledge-platform/__tests__/zero-blast-radius.test.js's (Stage 18) exact pattern. Confirms
 * this stage's brand-new directory has not been wired into any production route, and that it
 * only reaches one hop down into knowledge-platform/ -- never into intelligence-platform/,
 * evidence-registry/, or enterprise-gateway/ from production code. Also confirms no coupling to
 * the Python dossier/report pipeline (TITAN_STAGE19_READINESS_REPORT.md Sec 2.3).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "../../__tests__/boundary-scan-helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PP_DIR = dirname(HERE); // .../product-platform
const WORKER_SRC_DIR = dirname(PP_DIR); // .../src
const KNOWLEDGE_PLATFORM_DIR = join(WORKER_SRC_DIR, "knowledge-platform");
const INTELLIGENCE_PLATFORM_DIR = join(WORKER_SRC_DIR, "intelligence-platform");
const EVIDENCE_REGISTRY_DIR = join(WORKER_SRC_DIR, "evidence-registry");
const ENTERPRISE_GATEWAY_DIR = join(WORKER_SRC_DIR, "enterprise-gateway");
const COMMERCIAL_CATALOG_DIR = join(WORKER_SRC_DIR, "commercial-catalog");
const PP_TESTS_DIR = join(PP_DIR, "__tests__");

const PP_PRODUCTION_FILES = Object.freeze([
  "feature-flags.js",
  "service-contracts.js",
  "product-engine.js",
  "product-profiles.js",
  "product-packaging.js",
  "product-quality.js",
  "product-platform.js",
  "platform.js",
]);

/**
 * Same helper as every other zero-blast-radius.test.js in this lineage: true only if `file` IS
 * `dir`, or is strictly inside it (path.sep-bounded, not a bare startsWith/includes, which would
 * also match a sibling directory whose name merely extends `dir`'s name).
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

test("nothing outside product-platform/ references 'product-platform' except the four lower layers' own boundary-documentation __tests__ files and commercial-catalog/ (Stage 21, the first authorized real consumer)", () => {
  // evidence-registry/, intelligence-platform/, enterprise-gateway/, and knowledge-platform/'s
  // own __tests__/zero-blast-radius.test.js files each legitimately name "product-platform" in
  // their own AUTHORIZED_CONSUMER_DIRS array and doc comments (added alongside this directory,
  // mirroring exactly how each of them already documents the layers above them by name for the
  // identical reason). That is boundary documentation, not production coupling -- the same
  // distinction those files' own doc comments draw for themselves. Production reachability is
  // what actually matters and is covered precisely by the tests below.
  //
  // commercial-catalog/ (Stage 21) is exempted as a whole directory, not just its __tests__/
  // subdirectory, because its production platform.js imports createProductPlatform from
  // product-platform/platform.js (this directory's own composition root, called unchanged, not
  // reimplemented) -- Stage 21 is the first real production consumer of this directory. See
  // TITAN_STAGE21_GATEWAY_ACTIVATION_AUDIT.md Sec 3.
  const violations = [];
  const exemptTestsDirs = [
    join(EVIDENCE_REGISTRY_DIR, "__tests__"),
    join(INTELLIGENCE_PLATFORM_DIR, "__tests__"),
    join(ENTERPRISE_GATEWAY_DIR, "__tests__"),
    join(KNOWLEDGE_PLATFORM_DIR, "__tests__"),
  ];
  for (const file of listJsFiles(WORKER_SRC_DIR)) {
    if (isInside(file, PP_DIR)) continue; // files inside this directory are exempt
    if (exemptTestsDirs.some((dir) => isInside(file, dir))) continue; // see above
    if (isInside(file, COMMERCIAL_CATALOG_DIR)) continue; // Stage 21, see above
    const text = stripComments(readFileSync(file, "utf-8"));
    if (text.includes("product-platform")) violations.push(relative(WORKER_SRC_DIR, file));
  }
  assert.deepEqual(violations, [], `boundary violation(s) found: ${violations.join(", ")}`);
});

test("index.js does not import any product-platform/ file", () => {
  const indexJs = join(WORKER_SRC_DIR, "index.js");
  const text = readFileSync(indexJs, "utf-8");
  for (const file of PP_PRODUCTION_FILES) {
    assert.equal(text.includes(file), false, `index.js must not reference ${file}`);
  }
});

test("product-platform/ production files never import a pNN-handlers.js file or index.js directly", () => {
  for (const file of listJsFiles(PP_DIR)) {
    if (isInside(file, PP_TESTS_DIR)) continue;
    const text = readFileSync(file, "utf-8");
    assert.equal(/from\s+["'].*p\d+-handlers\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import a pNN-handlers.js file`);
    assert.equal(/from\s+["'].*\/index\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import index.js`);
  }
});

test("product-platform/ production files never import evidence-registry/, intelligence-platform/, or enterprise-gateway/ directly -- only the one authorized hop into knowledge-platform/", () => {
  for (const file of listJsFiles(PP_DIR)) {
    if (isInside(file, PP_TESTS_DIR)) continue; // __tests__ is the established exception (test-helpers.js constructs fixtures directly)
    const text = readFileSync(file, "utf-8");
    const realImports = [...text.matchAll(/^import\s+.*?from\s+["'](.+?)["'];?\s*$/gm)].map((m) => m[1]);
    for (const specifier of realImports) {
      assert.equal(specifier.includes("evidence-registry"), false, `${relative(WORKER_SRC_DIR, file)} must not import evidence-registry/ directly (specifier: ${specifier})`);
      assert.equal(specifier.includes("intelligence-platform"), false, `${relative(WORKER_SRC_DIR, file)} must not import intelligence-platform/ directly (specifier: ${specifier})`);
      assert.equal(specifier.includes("enterprise-gateway"), false, `${relative(WORKER_SRC_DIR, file)} must not import enterprise-gateway/ directly (specifier: ${specifier})`);
    }
  }
});

test("product-platform/ only imports knowledge-platform/ files that already exist -- it does not modify knowledge-platform/ itself", () => {
  const knowledgePlatformFiles = new Set(readdirSync(KNOWLEDGE_PLATFORM_DIR).filter((f) => f.endsWith(".js")));
  for (const file of listJsFiles(PP_DIR)) {
    if (isInside(file, PP_TESTS_DIR)) continue;
    const text = readFileSync(file, "utf-8");
    const importMatches = [...text.matchAll(/from\s+["']\.\.\/knowledge-platform\/([\w-]+\.js)["']/g)];
    for (const match of importMatches) {
      assert.ok(knowledgePlatformFiles.has(match[1]), `${match[1]} imported from knowledge-platform/ must be a pre-existing Stage 18 file`);
    }
  }
});

test("knowledge-platform.js (knowledge-platform/) does not import product-platform/ -- avoids a circular dependency", () => {
  const path = join(KNOWLEDGE_PLATFORM_DIR, "knowledge-platform.js");
  const text = readFileSync(path, "utf-8");
  assert.equal(text.includes("product-platform"), false);
});

test("intelligence-service.js (intelligence-platform/) does not import product-platform/", () => {
  const path = join(INTELLIGENCE_PLATFORM_DIR, "intelligence-service.js");
  const text = readFileSync(path, "utf-8");
  assert.equal(text.includes("product-platform"), false);
});

test("gateway-service.js (enterprise-gateway/) does not import product-platform/ -- Phase 6 integration uses registerCapability() from a composition script, not a gateway-service.js change", () => {
  const path = join(WORKER_SRC_DIR, "enterprise-gateway", "gateway-service.js");
  const text = readFileSync(path, "utf-8");
  assert.equal(text.includes("product-platform"), false);
});

test("all Stage 19 production files are present (Deprecation Instead of Deletion -- no silent removal)", () => {
  for (const file of PP_PRODUCTION_FILES) {
    assert.doesNotThrow(() => readFileSync(join(PP_DIR, file), "utf-8"), `${file} must exist`);
  }
});

const PYTHON_PIPELINE_MARKERS = Object.freeze([
  "report_generator.py",
  "dynamic_dossier_engine.py",
  "dossier_quality_engine.py",
  "generate_intel_reports.py",
]);

test("product-platform/ production files never reference the Python dossier/report pipeline (TITAN_STAGE19_READINESS_REPORT.md Sec 2.3 -- independent, unmodified, uncoupled)", () => {
  for (const file of listJsFiles(PP_DIR)) {
    if (isInside(file, PP_TESTS_DIR)) continue;
    const text = readFileSync(file, "utf-8");
    for (const marker of PYTHON_PIPELINE_MARKERS) {
      assert.equal(text.includes(marker), false, `${relative(WORKER_SRC_DIR, file)} must not reference Python pipeline file "${marker}"`);
    }
  }
});
