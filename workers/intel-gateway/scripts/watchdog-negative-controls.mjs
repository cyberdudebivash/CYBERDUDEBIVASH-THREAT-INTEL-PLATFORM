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
  "docs/CYBER_WATCHDOG_P3.md",
  "workers/revenue-engine/src",
  "MSSP_PARTNER_PROGRAM.md",
  "mssp.html",
  "docs/MSSP_TENANT_IDENTITY_V185.md",
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
    tests: [T("watchdog-rollback-compat.test.js"), T("watchdog-rollback-matrix.test.js")],
  },
  {
    id: "v3_accepts_unsigned_v2_destination",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  if (!isSignedV3(d)) return \"disabled\";\n  return d.state || \"pending\";",
    replace: "  if (!d) return \"disabled\";\n  return d.state || \"active\";",
    tests: [T("watchdog-rollback-compat.test.js")],
  },
  {
    // Both suppression layers of the safe rollback target restored to v2.
    id: "safe_rollback_suppression_removed",
    edits: [
      {
        file: "deploy/cyber-watchdog/safe-rollback/overlay/workers/intel-gateway/src/cyber-watchdog.js",
        find: "      // SAFE ROLLBACK: the v2 webhook delivery loop is removed.\n",
        replace: "      if (quota.webhooks && evaluated.inserted.length && (got.result.destinations || []).length && req.fetchImpl) {\n        for (const event of evaluated.inserted) {\n          for (const dest of got.result.destinations) {\n            const sent = await deliverWebhook(dest.url, buildWebhookPayload(event), req.fetchImpl);\n            await ledger(req, { type: \"record_delivery\", delivery: { event_id: event.id, destination_id: dest.id, status: sent.status, http_status: sent.http_status } });\n          }\n        }\n      }\n",
      },
      {
        file: "deploy/cyber-watchdog/safe-rollback/overlay/workers/intel-gateway/src/cyber-watchdog.js",
        find: "  return { status: \"suppressed_safe_rollback\", http_status: null };",
        replace: "  try { const res = await _fetchImpl(_url, { method: \"POST\", body: JSON.stringify(_payload) }); return { status: res.ok ? \"delivered\" : \"failed\", http_status: res.status }; } catch { return { status: \"failed\", http_status: null }; }",
      },
    ],
    tests: [T("watchdog-rollback-matrix.test.js")],
  },
  {
    id: "safe_rollback_delivery_loop_restored_only",
    file: "deploy/cyber-watchdog/safe-rollback/overlay/workers/intel-gateway/src/cyber-watchdog.js",
    find: "      // SAFE ROLLBACK: the v2 webhook delivery loop is removed.\n",
    replace: "      if (quota.webhooks && evaluated.inserted.length && (got.result.destinations || []).length && req.fetchImpl) {\n        for (const event of evaluated.inserted) {\n          for (const dest of got.result.destinations) {\n            const sent = await deliverWebhook(dest.url, buildWebhookPayload(event), req.fetchImpl);\n            await ledger(req, { type: \"record_delivery\", delivery: { event_id: event.id, destination_id: dest.id, status: sent.status, http_status: sent.http_status } });\n          }\n        }\n      }\n",
    tests: [T("watchdog-safe-rollback-artifact.test.js")],
  },
  {
    id: "early_v3_read_migrate_removed",
    file: "workers/intel-gateway/src/watchdog-ledger.js",
    find: "    if (migrate && (out.readOnly || out.error)) {",
    replace: "    if (false) {",
    tests: [T("watchdog-rollback-matrix.test.js")],
  },
  {
    id: "early_v3_rows_not_migrated",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    d && !d.delivery_protocol && typeof d.secret === \"string\" && d.secret.startsWith(\"whsec_\")",
    replace: "    false",
    tests: [T("watchdog-rollback-compat.test.js"), T("watchdog-rollback-matrix.test.js")],
  },
  {
    id: "kill_switch_default_open",
    file: "workers/intel-gateway/src/watchdog-policy.js",
    find: "  return !!env && env[WEBHOOK_DELIVERY_FLAG] === \"true\";",
    replace: "  return !env || env[WEBHOOK_DELIVERY_FLAG] !== \"false\";",
    tests: [T("watchdog-rollback-compat.test.js"), T("watchdog-rollback-matrix.test.js")],
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
  // ---- MSSP tenant self-service (mssp-tenants.js) ----
  {
    id: "paid_mssp_key_provisioned_unrestricted",
    file: "workers/intel-gateway/src/index.js",
    find: "    ...(validTier === \"MSSP\" && managedTenants === undefined ? { managed_tenants: [], tenant_auth_version: TENANT_AUTH_VERSION } : {}),",
    replace: "    ...(false ? {} : {}),",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "admin_mssp_key_created_unrestricted",
    file: "workers/intel-gateway/src/index.js",
    find: "      ...(tier === \"MSSP\" && managed_tenants === undefined ? { managed_tenants: [], tenant_auth_version: TENANT_AUTH_VERSION } : {}),",
    replace: "      ...(false ? {} : {}),",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "tenant_owner_or_fields_taken_from_body",
    edits: [
      { file: "workers/intel-gateway/src/mssp-tenants.js", find: "      const owned = OWNER_FIELDS.find((f) => Object.prototype.hasOwnProperty.call(body, f));", replace: "      const owned = null;" },
      { file: "workers/intel-gateway/src/mssp-tenants.js", find: "      const unknown = Object.keys(body).find((k) => !ALLOWED_CREATE_FIELDS.has(k));", replace: "      const unknown = null;" },
    ],
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "pro_key_can_create_tenants",
    file: "workers/intel-gateway/src/mssp-tenants.js",
    find: "  if (auth.tier !== \"MSSP\") {",
    replace: "  if (auth.tier === \"FREE\") {",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "customer_a_reads_customer_b_tenants",
    edits: [
      { file: "workers/intel-gateway/src/index.js", find: "      const stub = ns.get(ns.idFromName(TENANT_DO_PREFIX + owner));", replace: "      const stub = ns.get(ns.idFromName(TENANT_DO_PREFIX + \"shared\"));" },
      { file: "workers/intel-gateway/src/mssp-tenants.js", find: "  if (state.owner !== owner) return { error: \"not_found\", status: 404 };", replace: "  if (false) return null;" },
    ],
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "tenant_revoke_not_enforced",
    file: "workers/intel-gateway/src/mssp-tenants.js",
    find: "  return (state?.tenants || []).filter((t) => t.status === \"active\").map((t) => t.id);",
    replace: "  return (state?.tenants || []).map((t) => t.id);",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "membership_store_failure_fails_open",
    edits: [
      { file: "workers/intel-gateway/src/index.js", find: "  let ids = [];\n  try {\n    const store = msspMembership(env, auth.sub);", replace: "  let ids = null;\n  try {\n    const store = msspMembership(env, auth.sub);" },
      { file: "workers/intel-gateway/src/index.js", find: "  } catch (_) { ids = []; }\n  return { ...auth, managed_tenants: ids };", replace: "  } catch (_) { ids = null; }\n  return { ...auth, managed_tenants: ids };" },
    ],
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "watchdog_ignores_self_service_membership",
    file: "workers/intel-gateway/src/index.js",
    find: "    const watchdogAuth = requestSelectsTenant(path, request.headers, url.searchParams, auth) ? await resolveMsspMembership(env, auth) : auth;",
    replace: "    const watchdogAuth = auth;",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "scheduler_keeps_revoked_tenant",
    file: "workers/intel-gateway/src/index.js",
    find: "          if (out.result.initialized && !out.result.active) return { denied: true };",
    replace: "",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "gateway_rotation_loses_self_service_tenants",
    file: "workers/intel-gateway/src/index.js",
    find: "      existing.tenant_auth_version === TENANT_AUTH_VERSION ? TENANT_AUTH_VERSION : undefined\n    );",
    replace: "      undefined\n    );",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "gateway_rotation_widens_legacy_or_corrupt",
    file: "workers/intel-gateway/src/index.js",
    find: "      existing.managed_tenants === undefined ? null : (Array.isArray(existing.managed_tenants) ? existing.managed_tenants : []),",
    replace: "      Array.isArray(existing.managed_tenants) ? existing.managed_tenants : undefined,",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "revenue_engine_rotation_loses_tenants",
    file: "workers/revenue-engine/src/index.js",
    find: "      ...gatewayTenantFields(cust.tier, previous),",
    replace: "      ...gatewayTenantFields(cust.tier, null),",
    tests: ["../revenue-engine/src/__tests__/mssp-tenant-fields.test.js"],
  },
  {
    id: "razorpay_verify_mssp_parity_broken",
    file: "workers/intel-gateway/src/index.js",
    find: "  }, billing === \"annual\" ? \"annual\" : \"monthly\");",
    replace: "  }, billing === \"annual\" ? \"annual\" : \"monthly\", null);",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "gumroad_mssp_parity_broken",
    file: "workers/intel-gateway/src/index.js",
    find: "    sale_id, product_id, product_name, price, variants, subscription_id,\n  }, billingCycle);",
    replace: "    sale_id, product_id, product_name, price, variants, subscription_id,\n  }, billingCycle, null);",
    tests: [T("mssp-tenants.test.js")],
  },
  {
    id: "priority_missing_evidence_scored_zero",
    file: "workers/intel-gateway/src/watchdog-priority.js",
    find: "  if (!coreKnown.length) {",
    replace: "  if (false) {",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "priority_kev_floor_removed",
    file: "workers/intel-gateway/src/watchdog-priority.js",
    find: "  if (kev === true) floor(\"HIGH\", \"kev_listed\");",
    replace: "",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "triage_acknowledged_not_synced",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    acknowledged: status !== \"NEW\",",
    replace: "    acknowledged: true,",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "triage_status_validation_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    if (!TRIAGE_STATUSES.includes(status)) return { error: \"invalid_status\"",
    replace: "    if (false) return { error: \"invalid_status\"",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "triage_status_scope_removed",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "  [\"/api/watchdog/events/status\", [\"POST\"], WATCHDOG_SCOPES.EVENTS_ACK],",
    replace: "",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "inbox_priority_filter_ignored",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    if (query.priority && !query.priority.includes(eventPriority(e).band)) return false;",
    replace: "",
    tests: [T("watchdog-command-center.test.js")],
  },
  {
    id: "detail_serves_stale_feed_item",
    file: "workers/intel-gateway/src/cyber-watchdog.js",
    find: "    let feedItemStatus = \"feed_not_fresh\";\n    if (pub.serve_live) {",
    replace: "    let feedItemStatus = \"feed_not_fresh\";\n    if (true) {",
    tests: [T("watchdog-command-center.test.js")],
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
    // A control is one edit ({file, find, replace}) or several ({edits: [...]})
    // that together remove one protection.
    const edits = c.edits || [{ file: c.file, find: c.find, replace: c.replace }];
    let missing = false;
    for (const e of edits) {
      const target = path.join(root, e.file);
      const src = readFileSync(target, "utf8");
      if (!src.includes(e.find)) { missing = true; break; }
      writeFileSync(target, src.replace(e.find, e.replace));
    }
    if (missing) {
      results.push({ id: c.id, status: "MUTATION_ANCHOR_MISSING" });
      continue;
    }
    const r = runTests(root, c.tests.map(rel));
    results.push({ id: c.id, status: r.code !== 0 ? "CAUGHT" : "NOT_CAUGHT", failing_tests: r.failed });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const bad = results.filter((r) => r.status !== "CAUGHT");
console.log(JSON.stringify({ baseline: "green", controls: results.length, caught: results.length - bad.length, results }, null, 2));
process.exit(bad.length ? 1 : 0);
