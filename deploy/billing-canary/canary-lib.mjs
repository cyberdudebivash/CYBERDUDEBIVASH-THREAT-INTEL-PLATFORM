/**
 * CYBERDUDEBIVASH SENTINEL APEX -- billing canary steps (S28).
 *
 * Pure step functions over two injected HTTP clients, so the same steps run
 * against a live deployment (canary.mjs) and against both Workers in-process
 * (__tests__/billing-canary.test.mjs). Nothing here reads the environment.
 *
 *   intel(method, path, opts)    intel.cyberdudebivash.com (gateway + /api/v2/billing/*)
 *   revenue(method, path, opts)  revenue.intel.cyberdudebivash.com (revenue engine)
 *   opts: { headers?, body?, raw? }  body is JSON unless raw (sent as-is)
 *   -> { status, body (parsed JSON or null), text }
 *
 * Levels:
 *   public         no credentials, never mutates: every commercial boundary
 *                  refuses what it must (unauthenticated, unsigned, retired).
 *   admin          + revenue admin secret, read-only: health summary and the
 *                  commercial readiness verdict.
 *   test-checkout  + a Razorpay TEST-mode deployment only: creates one unpaid
 *                  test subscription (proves the Plan price check against the
 *                  real Plan) and proves create idempotency. REFUSED unless
 *                  readiness proves the key is a test-mode key.
 * Evidence carries statuses and verdicts only: never secrets, keys or
 * subscription ids beyond their prefix.
 */

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, OPERATOR_CREDENTIAL_REQUIRED: 10, LIVE_MODE_REFUSED: 13 });

function step(steps, name, ok, detail) {
  steps.push({ step: name, ok: !!ok, ...(detail === undefined ? {} : { detail }) });
  return !!ok;
}

export async function runPublicChecks({ intel, revenue }) {
  const steps = [];

  const h = await revenue("GET", "/api/health");
  step(steps, "revenue_health_anonymous_is_minimal", h.status === 200 && h.body &&
    JSON.stringify(Object.keys(h.body).sort()) === JSON.stringify(["engine", "generated_at", "status", "version"]),
    { status: h.status, keys: h.body ? Object.keys(h.body).sort() : null });

  const acct = await intel("GET", "/api/v2/billing/account");
  step(steps, "billing_account_requires_key", acct.status === 401, { status: acct.status });

  const acctBad = await intel("GET", "/api/v2/billing/account", { headers: { "X-API-Key": "cdb_canary_not_a_real_key_000000" } });
  step(steps, "billing_account_refuses_unknown_key", acctBad.status === 401, { status: acctBad.status });

  const ready = await intel("GET", "/api/v2/billing/admin/readiness");
  step(steps, "readiness_requires_admin", ready.status === 401, { status: ready.status });

  const cancel = await intel("POST", "/api/v2/billing/subscriptions/cancel", { body: {} });
  step(steps, "cancel_requires_key", cancel.status === 401 || cancel.status === 503, { status: cancel.status });

  const refund = await intel("POST", "/api/v2/billing/refunds/approve", { body: { request_id: "rfr_canary" } });
  step(steps, "refund_approval_requires_admin", refund.status === 401, { status: refund.status });

  const unsigned = await intel("POST", "/api/v2/billing/webhooks/razorpay", {
    headers: { "Content-Type": "application/json", "X-Razorpay-Signature": "0".repeat(64) },
    body: { event: "subscription.activated", payload: {} },
  });
  // 401 = configured and refusing. 500 = RAZORPAY_WEBHOOK_SECRET missing:
  // every real payment webhook would be rejected too.
  step(steps, "razorpay_webhook_refuses_bad_signature", unsigned.status === 401,
    { status: unsigned.status, ...(unsigned.status === 500 ? { finding: "RAZORPAY_WEBHOOK_SECRET not configured: no payment can activate" } : {}) });

  const badType = await intel("POST", "/api/v2/billing/webhooks/razorpay", { headers: { "Content-Type": "text/plain" }, body: "x", raw: true });
  step(steps, "razorpay_webhook_requires_json", badType.status === 415, { status: badType.status });

  const badTier = await intel("POST", "/api/v2/billing/subscriptions/create", { body: { email: "billing-canary@example.com", tier: "PLATINUM" } });
  step(steps, "checkout_refuses_unknown_tier", badTier.status === 400, { status: badTier.status });

  const gum = await intel("POST", "/api/webhooks/gumroad", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "sale_id=canary", raw: true });
  // 401 = configured and refusing. 500 = GUMROAD_WEBHOOK_SECRET missing on
  // the gateway: every real Gumroad sale ping is rejected, no buyer gets a key.
  step(steps, "gumroad_webhook_requires_secret", gum.status === 401,
    { status: gum.status, ...(gum.status === 500 ? { finding: "GUMROAD_WEBHOOK_SECRET not configured: Gumroad sales cannot provision" } : {}) });

  const holds = await intel("GET", "/api/admin/gumroad/holds");
  step(steps, "gumroad_holds_require_admin", holds.status === 401 || holds.status === 403, { status: holds.status });

  const manual = await intel("POST", "/api/payment/manual-notify", { body: {} });
  step(steps, "gateway_manual_payment_retired", manual.status === 410, { status: manual.status });

  const submit = await revenue("POST", "/api/payments/submit", { body: {} });
  step(steps, "revenue_manual_payment_retired", submit.status === 410, { status: submit.status });

  const page = await intel("GET", "/billing.html");
  step(steps, "billing_center_page_served", page.status === 200 && /Billing Center/.test(page.text) && page.text.includes("/api/v2/billing/account"),
    { status: page.status });

  const admin = await intel("GET", "/admin.html");
  step(steps, "admin_page_complete", admin.status === 200 && admin.text.trimEnd().toLowerCase().endsWith("</html>"), { status: admin.status });

  return steps;
}

/** Admin, read-only. `requireReady` (live) turns a BLOCKED verdict into a failure. */
export async function runAdminChecks({ intel, revenue }, adminSecret, { requireReady }) {
  const steps = [];
  const hdr = { "X-Admin-Secret": adminSecret };
  const h = await revenue("GET", "/api/health", { headers: hdr });
  step(steps, "admin_health_has_commercial_summary", h.status === 200 && h.body && h.body.commercial && typeof h.body.commercial.verdict === "string",
    { status: h.status, verdict: h.body?.commercial?.verdict ?? null });
  const r = await intel("GET", "/api/v2/billing/admin/readiness", { headers: hdr });
  const ok = r.status === 200 && r.body && (r.body.verdict === "READY" || r.body.verdict === "BLOCKED");
  step(steps, "readiness_readable", ok, { status: r.status });
  const readiness = ok ? r.body : null;
  if (readiness) {
    step(steps, "readiness_verdict", !requireReady || readiness.verdict === "READY",
      { verdict: readiness.verdict, blockers: readiness.blockers, warnings: readiness.warnings, queue_attention: readiness.queue?.attention ?? null });
  }
  return { steps, readiness };
}

/** True only when readiness proves the deployment's Razorpay key is test-mode. */
export function readinessProvesTestMode(readiness) {
  const c = readiness && Array.isArray(readiness.checks) ? readiness.checks.find((x) => x.id === "razorpay_live_mode") : null;
  return !!(c && c.ok === false && /test mode/.test(String(c.detail || "")));
}

/**
 * One unpaid Razorpay TEST subscription. Caller must have checked
 * readinessProvesTestMode(); this re-checks the returned public key id.
 */
export async function runTestCheckout({ intel }, { email, tier = "PRO", cycle = "monthly" }) {
  const steps = [];
  const body = { email, tier, billing_cycle: cycle };
  const a = await intel("POST", "/api/v2/billing/subscriptions/create", { body });
  const created = a.status === 200 && a.body && /^sub_/.test(a.body.subscription_id || "");
  step(steps, "test_checkout_created_after_plan_price_check", created,
    { status: a.status, error: a.body?.error ?? null, subscription_prefix: created ? a.body.subscription_id.slice(0, 8) : null });
  step(steps, "test_checkout_uses_test_key", created && /^rzp_test_/.test(a.body.key_id || ""), { key_mode: created ? String(a.body.key_id || "").slice(0, 9) : null });
  if (!created) return steps;
  const b = await intel("POST", "/api/v2/billing/subscriptions/create", { body });
  step(steps, "test_checkout_retry_reuses_subscription", b.status === 200 && b.body?.subscription_id === a.body.subscription_id && b.body?.reused === true,
    { status: b.status, reused: b.body?.reused ?? null });
  const st = await intel("GET", `/api/v2/billing/subscriptions/status?subscription_id=${encodeURIComponent(a.body.subscription_id)}`);
  step(steps, "status_requires_payment_proof", st.status === 400, { status: st.status });
  const forged = await intel("GET", `/api/v2/billing/subscriptions/status?subscription_id=${encodeURIComponent(a.body.subscription_id)}&payment_id=pay_canary&signature=${"0".repeat(64)}`);
  step(steps, "status_refuses_forged_signature", forged.status === 401, { status: forged.status });
  return steps;
}
