#!/usr/bin/env node
/**
 * Cyber Watchdog negative controls (mutation proof).
 *
 * For each control, copies the relevant tree to a temp directory, applies ONE
 * deliberate defect, runs the named test files there, and requires them to
 * FAIL. A control whose mutation leaves the tests green means that property is
 * not actually covered, and this script exits 1. The working tree is never
 * modified.
 *
 *   node workers/intel-gateway/scripts/watchdog-negative-controls.mjs
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const COPY = [
  "workers/intel-gateway/src",
  "workers/intel-gateway/package.json",
  "workers/intel-gateway/wrangler.toml",
  "deploy/cyber-watchdog",
  "config/commercial-contract.json",
  "config/public_freshness_contract.json",
  "index.html",
  "dashboard.html",
  "cyber-watchdog.html",
];
const T = (f) => "workers/intel-gateway/src/__tests__/" + f;

const CONTROLS = [
  {
    id: "dns_validation_disabled",
    file: "workers/intel-gateway/src/watchdog-webhook.js",
    find: "    if (!c.allowed) return { ok: false, error: \"forbidden_address\", retryable: false, reason: c.reason };\n  }\n  return { ok: true, addresses",
    replace: "    if (false) return null;\n  }\n  return { ok: true, addresses",
    tests: [T("watchdog-webhook.test.js"), T("watchdog-e2e.test.js")],
  },
  {
    id: "webhook_hmac_removed",
    file: "workers/intel-gateway/src/watchdog-webhook.js",
    find: "[h.signature]: WEBHOOK_CONTRACT.signature_scheme + \"=\" + sig,",
    replace: "[h.signature]: WEBHOOK_CONTRACT.signature_scheme + \"=\" + \"0\".repeat(64),",
    tests: [T("watchdog-webhook.test.js"), T("watchdog-e2e.test.js")],
  },
  {
    id: "dedupe_disabled",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  const seen = index.get(k);\n  if (!seen) return false;",
    replace: "  const seen = index.get(k);\n  return false;",
    tests: [T("watchdog-e2e.test.js"), T("cyber-watchdog.test.js")],
  },
  {
    id: "tenant_membership_check_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  if (!managed || !managed.includes(tenant)) return { error: FORBIDDEN };",
    replace: "",
    tests: [T("watchdog-e2e.test.js")],
  },
  {
    id: "freshness_gate_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    serve_live: freshness_status === \"FRESH\",",
    replace: "    serve_live: true,",
    tests: [T("watchdog-e2e.test.js"), T("cyber-watchdog.test.js")],
  },
  {
    id: "store_freshness_recheck_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "if (op.publication?.freshness_status !== \"FRESH\" || !Array.isArray(op.items)) {",
    replace: "if (!Array.isArray(op.items)) {",
    tests: [T("watchdog-scheduler.test.js")],
  },
  {
    id: "pro_destination_permitted",
    file: "workers/intel-gateway/src/watchdog-policy.js",
    find: "    watches: 25, brief_items: 50, poller: true, events: true,\n    webhooks: 0,",
    replace: "    watches: 25, brief_items: 50, poller: true, events: true,\n    webhooks: 3,",
    tests: [T("watchdog-e2e.test.js"), T("cyber-watchdog.test.js"), T("watchdog-policy.test.js")],
  },
  {
    id: "session_scope_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  return have.includes(need) ? null : { status: 403, body: { error: \"insufficient_scope\", required_scope: need } };",
    replace: "  return null;",
    tests: [T("watchdog-e2e.test.js")],
  },
  {
    id: "session_audience_not_enforced",
    file: "workers/intel-gateway/src/index.js",
    find: "if (auth.aud === WATCHDOG_SESSION_POLICY.audience && !path.startsWith(\"/api/watchdog\")) {",
    replace: "if (false) {",
    tests: [T("watchdog-e2e.test.js")],
  },
  {
    id: "scheduler_bound_removed",
    file: "workers/intel-gateway/src/watchdog-policy.js",
    find: "  max_subjects_per_run: 25,",
    replace: "  max_subjects_per_run: 100000,",
    tests: [T("watchdog-scheduler.test.js")],
  },
  {
    id: "retry_bound_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "} else if (r.outcome === \"retry\" && d.attempts < DELIVERY_POLICY.max_attempts) {",
    replace: "} else if (r.outcome === \"retry\") {",
    tests: [T("watchdog-webhook.test.js")],
  },
  {
    id: "redirects_followed",
    file: "workers/intel-gateway/src/watchdog-policy.js",
    find: "  redirect: \"manual\",",
    replace: "  redirect: \"follow\",",
    tests: [T("cyber-watchdog.test.js")],
  },
  {
    id: "unverified_destination_receives",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  return (destinations || []).filter((d) => destinationState(d) === \"active\");",
    replace: "  return (destinations || []).filter((d) => destinationState(d) !== \"disabled\");",
    tests: [T("watchdog-e2e.test.js"), T("cyber-watchdog.test.js")],
  },
  {
    id: "watchdog_price_mirror_reintroduced",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  const row = RAZORPAY_TIER_PRICES[tierId];",
    replace: "  const row = { PRO: { monthly: 410000, usd_monthly: 49 }, ENTERPRISE: { monthly: 4160000, usd_monthly: 499 }, MSSP: { monthly: 8330000, usd_monthly: 999 } }[tierId];",
    tests: [T("watchdog-policy.test.js")],
  },
  {
    id: "v3_verified_persisted_in_v2_readable_ledger",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    ledger: { ...state, destinations: all.filter((d) => !isSignedV3(d)) },",
    replace: "    ledger: { ...state, destinations: all },",
    tests: [T("watchdog-rollback-compat.test.js")],
  },
  {
    id: "v3_accepts_unsigned_v2_destination",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  if (!isSignedV3(d)) return \"disabled\";\n  return d.state || \"pending\";",
    replace: "  if (!d) return \"disabled\";\n  return d.state || \"active\";",
    tests: [T("watchdog-rollback-compat.test.js")],
  },
  {
    id: "kill_switch_default_open",
    file: "workers/intel-gateway/src/watchdog-policy.js",
    find: "  return !!env && env[WEBHOOK_DELIVERY_FLAG] === \"true\";",
    replace: "  return !env || env[WEBHOOK_DELIVERY_FLAG] !== \"false\";",
    tests: [T("watchdog-rollback-compat.test.js")],
  },
  {
    id: "homepage_missing_state_is_live",
    file: "index.html",
    find: "if (state === 'fresh' && tsOk && ageOk) return { text: 'LIVE', color: '#10b981' };",
    replace: "if (state !== 'stale') return { text: 'LIVE', color: '#10b981' };",
    tests: [T("publication-truth.test.js")],
  },
  {
    id: "feed_json_stale_reported_fresh",
    file: "workers/intel-gateway/src/freshness-contract.js",
    find: "  if (evaluation.intelligence && evaluation.intelligence.status === STATES.STALE) return \"STALE\";",
    replace: "  if (evaluation.intelligence && evaluation.intelligence.status === STATES.STALE) return \"FRESH\";",
    tests: [T("publication-truth.test.js"), T("watchdog-e2e.test.js")],
  },
  {
    id: "paid_feed_edge_cached",
    file: "workers/intel-gateway/src/index.js",
    find: "      ? { ...feedTruth.headers, \"Cache-Control\": \"private, no-store\" }",
    replace: "      ? { ...feedTruth.headers, \"Cache-Control\": \"public, max-age=120\" }",
    tests: [T("watchdog-e2e.test.js")],
  },
];

function runTests(root, files) {
  const r = spawnSync(process.execPath, ["--test", ...files], { cwd: path.join(root, "workers/intel-gateway"), encoding: "utf8", env: { ...process.env, NODE_NO_WARNINGS: "1" } });
  const fail = /# fail (\d+)/.exec(r.stdout || "");
  return { code: r.status, failed: fail ? Number(fail[1]) : null };
}

function stage() {
  const root = mkdtempSync(path.join(tmpdir(), "wd-neg-"));
  for (const rel of COPY) {
    const dst = path.join(root, rel);
    mkdirSync(path.dirname(dst), { recursive: true });
    cpSync(path.join(REPO, rel), dst, { recursive: true });
  }
  return root;
}

const rel = (f) => f.replace(/^workers\/intel-gateway\//, "");
const results = [];
const baselineRoot = stage();
const allTests = [...new Set(CONTROLS.flatMap((c) => c.tests))].map(rel);
const baseline = runTests(baselineRoot, allTests);
rmSync(baselineRoot, { recursive: true, force: true });
if (baseline.code !== 0) {
  console.log(JSON.stringify({ result: "BASELINE_NOT_GREEN", baseline }, null, 2));
  process.exit(1);
}
for (const c of CONTROLS) {
  const root = stage();
  try {
    const target = path.join(root, c.file);
    const src = readFileSync(target, "utf8");
    if (!src.includes(c.find)) {
      results.push({ id: c.id, status: "MUTATION_ANCHOR_MISSING" });
      continue;
    }
    writeFileSync(target, src.replace(c.find, c.replace));
    const r = runTests(root, c.tests.map(rel));
    results.push({ id: c.id, status: r.code !== 0 ? "CAUGHT" : "NOT_CAUGHT", failing_tests: r.failed });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const bad = results.filter((r) => r.status !== "CAUGHT");
console.log(JSON.stringify({ baseline: "green", controls: results.length, caught: results.length - bad.length, results }, null, 2));
process.exit(bad.length ? 1 : 0);
