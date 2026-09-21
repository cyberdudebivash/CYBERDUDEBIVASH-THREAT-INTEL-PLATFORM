/**
 * Zero-blast-radius test for Stage 18's knowledge-platform/ directory, mirroring
 * intelligence-platform/__tests__/zero-blast-radius.test.js's (Stage 13) and
 * evidence-registry/__tests__/zero-blast-radius.test.js's (Stage 8-12) exact pattern. Confirms
 * this stage's brand-new directory has not been wired into any production route, and that it
 * only reaches one hop down into intelligence-platform/ -- never into evidence-registry/ or
 * enterprise-gateway/ from production code.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "../../__tests__/boundary-scan-helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const KP_DIR = dirname(HERE); // .../knowledge-platform
const WORKER_SRC_DIR = dirname(KP_DIR); // .../src
const INTELLIGENCE_PLATFORM_DIR = join(WORKER_SRC_DIR, "intelligence-platform");
const EVIDENCE_REGISTRY_DIR = join(WORKER_SRC_DIR, "evidence-registry");
const ENTERPRISE_GATEWAY_DIR = join(WORKER_SRC_DIR, "enterprise-gateway");
const PRODUCT_PLATFORM_DIR = join(WORKER_SRC_DIR, "product-platform");
const COMMERCIAL_CATALOG_DIR = join(WORKER_SRC_DIR, "commercial-catalog");
const KP_TESTS_DIR = join(KP_DIR, "__tests__");

const KP_PRODUCTION_FILES = Object.freeze([
  "feature-flags.js",
  "service-contracts.js",
  "knowledge-object.js",
  "knowledge-navigation.js",
  "analyst-views.js",
  "executive-views.js",
  "knowledge-quality.js",
  "knowledge-platform.js",
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

test("nothing outside knowledge-platform/ references 'knowledge-platform' except the three lower layers' own boundary-documentation __tests__ files, product-platform/ (Stage 19), and commercial-catalog/ (Stage 21) -- the authorized real consumers", () => {
  // evidence-registry/, intelligence-platform/, and enterprise-gateway/'s own
  // __tests__/zero-blast-radius.test.js files each legitimately name "knowledge-platform" in
  // their own AUTHORIZED_CONSUMER_DIRS array and doc comments (added alongside this directory,
  // mirroring exactly how each of them already documents intelligence-platform/enterprise-gateway/
  // relationship-framework by name for the identical reason). That is boundary documentation, not
  // production coupling -- the same distinction those three files' own doc comments draw for
  // themselves. Production reachability is what actually matters and is covered precisely by the
  // tests below (index.js, and pNN-handlers.js/index.js imports from inside this directory).
  //
  // product-platform/ (Stage 19) is exempted as a whole directory, not just its __tests__/
  // subdirectory, because its PRODUCTION code has a real, legitimate import of this directory --
  // feature-flags.js imports DEPLOYMENT_ENVIRONMENTS from ./feature-flags.js, service-contracts.js
  // imports isContractForwardCompatible/checkContractCompatibility from ./service-contracts.js,
  // and product-quality.js imports evaluateKnowledgeObjectQuality from ./knowledge-quality.js --
  // the one authorized hop down this stage's own README.md documents. See
  // TITAN_STAGE19_READINESS_REPORT.md Sec 3.2.
  //
  // commercial-catalog/ (Stage 21) is exempted for the identical reason -- its production
  // platform.js imports createKnowledgePlatform from knowledge-platform/platform.js (this
  // directory's own composition root, called unchanged, not reimplemented), per
  // TITAN_STAGE21_GATEWAY_ACTIVATION_AUDIT.md Sec 3. Unlike product-platform/, this is a
  // deliberate cross-cutting composition (Stage 21 also imports enterprise-gateway/ and
  // product-platform/ directly), not a strict one-hop-down relationship -- documented explicitly
  // in that audit rather than silently treated as another instance of the one-hop pattern.
  const violations = [];
  const exemptTestsDirs = [
    join(EVIDENCE_REGISTRY_DIR, "__tests__"),
    join(INTELLIGENCE_PLATFORM_DIR, "__tests__"),
    join(ENTERPRISE_GATEWAY_DIR, "__tests__"),
  ];
  for (const file of listJsFiles(WORKER_SRC_DIR)) {
    if (isInside(file, KP_DIR)) continue; // files inside this directory are exempt
    if (exemptTestsDirs.some((dir) => isInside(file, dir))) continue; // see above
    if (isInside(file, PRODUCT_PLATFORM_DIR)) continue; // Stage 19, see above
    if (isInside(file, COMMERCIAL_CATALOG_DIR)) continue; // Stage 21, see above
    const text = stripComments(readFileSync(file, "utf-8"));
    if (text.includes("knowledge-platform")) violations.push(relative(WORKER_SRC_DIR, file));
  }
  assert.deepEqual(violations, [], `boundary violation(s) found: ${violations.join(", ")}`);
});

test("index.js does not import any knowledge-platform/ file", () => {
  const indexJs = join(WORKER_SRC_DIR, "index.js");
  const text = readFileSync(indexJs, "utf-8");
  for (const file of KP_PRODUCTION_FILES) {
    assert.equal(text.includes(file), false, `index.js must not reference ${file}`);
  }
});

test("knowledge-platform/ production files never import a pNN-handlers.js file or index.js directly", () => {
  for (const file of listJsFiles(KP_DIR)) {
    if (isInside(file, KP_TESTS_DIR)) continue;
    const text = readFileSync(file, "utf-8");
    assert.equal(/from\s+["'].*p\d+-handlers\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import a pNN-handlers.js file`);
    assert.equal(/from\s+["'].*\/index\.js["']/.test(text), false, `${relative(WORKER_SRC_DIR, file)} must not import index.js`);
  }
});

test("knowledge-platform/ production files never import evidence-registry/ or enterprise-gateway/ directly -- only the one authorized hop into intelligence-platform/", () => {
  for (const file of listJsFiles(KP_DIR)) {
    if (isInside(file, KP_TESTS_DIR)) continue; // __tests__ is the established exception (test-helpers.js constructs fixtures directly)
    const text = readFileSync(file, "utf-8");
    const realImports = [...text.matchAll(/^import\s+.*?from\s+["'](.+?)["'];?\s*$/gm)].map((m) => m[1]);
    for (const specifier of realImports) {
      assert.equal(specifier.includes("evidence-registry"), false, `${relative(WORKER_SRC_DIR, file)} must not import evidence-registry/ directly (specifier: ${specifier})`);
      assert.equal(specifier.includes("enterprise-gateway"), false, `${relative(WORKER_SRC_DIR, file)} must not import enterprise-gateway/ directly (specifier: ${specifier})`);
    }
  }
});

test("knowledge-platform/ only imports intelligence-platform/ files that already exist -- it does not modify intelligence-platform/ itself", () => {
  const intelligencePlatformFiles = new Set(readdirSync(INTELLIGENCE_PLATFORM_DIR).filter((f) => f.endsWith(".js")));
  for (const file of listJsFiles(KP_DIR)) {
    if (isInside(file, KP_TESTS_DIR)) continue;
    const text = readFileSync(file, "utf-8");
    const importMatches = [...text.matchAll(/from\s+["']\.\.\/intelligence-platform\/([\w-]+\.js)["']/g)];
    for (const match of importMatches) {
      assert.ok(intelligencePlatformFiles.has(match[1]), `${match[1]} imported from intelligence-platform/ must be a pre-existing Stage 13/17 file`);
    }
  }
});

test("intelligence-service.js (intelligence-platform/) does not import knowledge-platform/ -- avoids the circular dependency a .knowledge property would have created", () => {
  const path = join(INTELLIGENCE_PLATFORM_DIR, "intelligence-service.js");
  const text = readFileSync(path, "utf-8");
  assert.equal(text.includes("knowledge-platform"), false);
});

test("gateway-service.js (enterprise-gateway/) does not import knowledge-platform/ -- Phase 7 integration uses registerCapability() from a composition script, not a gateway-service.js change", () => {
  const path = join(WORKER_SRC_DIR, "enterprise-gateway", "gateway-service.js");
  const text = readFileSync(path, "utf-8");
  assert.equal(text.includes("knowledge-platform"), false);
});

test("all Stage 18 production files are present (Deprecation Instead of Deletion -- no silent removal)", () => {
  for (const file of KP_PRODUCTION_FILES) {
    assert.doesNotThrow(() => readFileSync(join(KP_DIR, file), "utf-8"), `${file} must exist`);
  }
});
