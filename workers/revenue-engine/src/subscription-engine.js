// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: Razorpay Subscriptions
// Phase 2 (foundational pass) -- Subscription creation + webhook lifecycle +
// entitlement sync + audit logging, built on Razorpay's native Subscriptions
// API rather than emulating recurring billing with one-time Orders.
//
// Explicitly OUT OF SCOPE for this pass (deferred to independently reviewable
// follow-ups, per the "one production problem per PR" discipline):
//   - Refunds (full/partial)
//   - Upgrades / downgrades / plan changes
//   - Checkout-page cutover (upgrade.html / PAYMENT-GATEWAY.html still point
//     at the existing one-time-order endpoints; nothing about that changes)
//   - Any change to existing one-time-order customers or their API keys
//
// Routes (mounted in index.js's fetch(), before the isAdmin() gate -- these
// must be reachable by real customers and by Razorpay's webhook caller, which
// send no X-Admin-Secret header):
//   POST /api/v2/billing/subscriptions/create   -- checkout entry point
//   POST /api/v2/billing/webhooks/razorpay      -- subscription lifecycle events
//
// Reuses (does not re-implement):
//   provisionCustomer()  -- customer/API-key/subscription-record creation +
//                            welcome email + MRR update (index.js)
//   TIERS, SUB_STATUS    -- canonical tier config + subscription status enum
//   trackEvent()         -- existing D1 `events` table + KV daily counter,
//                            reused here as the audit trail for billing
//                            events rather than introducing a new table
//   sanitizeEmail, genId, json -- existing formatting/validation helpers
// =============================================================================

import {
  json, sanitizeEmail, genId, TIERS, SUB_STATUS, provisionCustomer, trackEvent,
} from "./index.js";
import { Subscription } from "./subscription-domain.js";
import { normalizeBuyerTaxId, normalizeBillingState, normalizeBillingName, normalizeBillingCountry } from "./gst.js";
import { recordCapturedPayment, issueInvoiceForPayment } from "./billing-ledger.js";
import { applyBillingWebhookEvent } from "./billing-routes.js";

const RAZORPAY_API_BASE = "https://api.razorpay.com/v1";

export const RAZORPAY_BILLING_EVENTS = Object.freeze([
  "subscription.authenticated",
  "subscription.activated",
  "subscription.charged",
  "subscription.pending",
  "subscription.halted",
  "subscription.cancelled",
  "subscription.completed",
  "payment.failed",
  "refund.created",
  "refund.processed",
  "refund.failed",
  "payment.dispute.created",
]);
const MAX_RAZORPAY_WEBHOOK_BYTES = 256 * 1024;
const RAZORPAY_EVENT_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const JWT_DENY_TTL_SECONDS = 25 * 60 * 60;
const PENDING_CHECKOUT_TTL_SECONDS = 30 * 60;
// Subscription statuses (SUB_STATUS values, index.js) that already entitle
// the email to its tier. Literal: index.js imports this module, so its
// SUB_STATUS binding is not initialised while this module evaluates.
const LIVE_SUB_STATUSES = Object.freeze(["active", "trial", "past_due", "expiring", "renewed"]);

async function sha256Hex(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// One Razorpay Plan (pre-created in the Razorpay Dashboard or via the Plans
// API -- a one-time manual step outside what this session can do without
// live credentials) per tier/cycle. Missing plan_id => 503, not a crash.
export const PLAN_ID_ENV_KEYS = {
  PRO:        { monthly: "RAZORPAY_PLAN_ID_PRO_MONTHLY",        annual: "RAZORPAY_PLAN_ID_PRO_ANNUAL" },
  ENTERPRISE: { monthly: "RAZORPAY_PLAN_ID_ENTERPRISE_MONTHLY",  annual: "RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL" },
  MSSP:       { monthly: "RAZORPAY_PLAN_ID_MSSP_MONTHLY",        annual: "RAZORPAY_PLAN_ID_MSSP_ANNUAL" },
};

// Razorpay requires a finite total_count of billing cycles. This is a
// structural default (enough cycles to span roughly a decade at each
// cadence, i.e. "renews until cancelled" in practice) -- NOT a business
// decision about contract length. Adjust freely once a real policy exists.
const TOTAL_COUNT_BY_CYCLE = { monthly: 120, annual: 10 };

// Ported from workers/intel-gateway/src/index.js's verifyRazorpayHmac.
// revenue-engine and intel-gateway are independently deployed Workers with no
// shared module between them today, so this is a direct copy of a small
// (already-proven) function rather than a new implementation. Introducing a
// shared module across two independently-deployed Workers is a bigger
// architectural change than this pass warrants.
async function verifyRazorpayHmac(payload, signature, secret) {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBytes = new Uint8Array(signature.match(/.{2}/g).map(b => parseInt(b, 16)));
    return await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(payload));
  } catch (_) { return false; }
}

function unixToIso(sec) {
  return sec ? new Date(sec * 1000).toISOString() : null;
}

// ── REVENUE_CRM_KV access helpers ───────────────────────────────────────────
// Same get -> merge -> put convention already used throughout index.js
// (provisionCustomer, handleSubUpdate, handleSubExpireCheck all follow this
// exact pattern for `sub:{id}` / `sub:email:{email}` records) -- not a new
// pattern, just one more instance of the existing one.

export async function getProviderLink(env, providerSubId) {
  return await env.REVENUE_CRM_KV.get(`razorpay_sub:${providerSubId}`, "json");
}

export async function putProviderLink(env, providerSubId, record) {
  await env.REVENUE_CRM_KV.put(`razorpay_sub:${providerSubId}`, JSON.stringify(record));
}

export async function patchInternalSub(env, internalSubId, patch) {
  const rec = await env.REVENUE_CRM_KV.get(`sub:${internalSubId}`, "json");
  if (!rec) return null;
  const updated = { ...rec, ...patch, updated_at: new Date().toISOString() };
  await env.REVENUE_CRM_KV.put(`sub:${internalSubId}`, JSON.stringify(updated));
  await env.REVENUE_CRM_KV.put(`sub:email:${rec.email}`, JSON.stringify(updated));
  // Phase 2: keep subscriptions:index in sync. Previously this list's
  // `status`/`current_period_end` fields went stale forever after any patch
  // -- nothing re-saved the index after individual sub:{id}/sub:email:{email}
  // updates. revenueDashboard() and handleSubExpireCheck() both filter/count
  // directly off this index, so a stale entry silently mis-reported
  // dashboard counts (e.g. a cancelled subscription still counted as active)
  // with no error anywhere. Best-effort: a failure here doesn't invalidate
  // the write to the two records above, which remain the source of truth.
  try {
    const idx = await env.REVENUE_CRM_KV.get("subscriptions:index", "json") || [];
    const i = idx.findIndex(s => s.id === internalSubId);
    if (i >= 0) {
      idx[i] = { ...idx[i], status: updated.status, current_period_end: updated.current_period_end };
      await env.REVENUE_CRM_KV.put("subscriptions:index", JSON.stringify(idx));
    }
  } catch (_) {}
  return updated;
}

/**
 * Phase 2: validates a lifecycle transition against SUBSCRIPTION_TRANSITIONS
 * (subscription-domain.js) before applying it, instead of patchInternalSub's
 * previous blind accept-any-patch behavior. On an invalid transition (e.g. a
 * late/out-of-order "charged" webhook arriving after we've already recorded
 * a cancellation), logs the anomaly and leaves the existing, more-authoritative
 * record untouched rather than overwriting it -- fail-safe, not fail-open.
 */
export async function tryTransition(env, internalSubId, newStatus, extraPatch, rid) {
  const rec = await env.REVENUE_CRM_KV.get(`sub:${internalSubId}`, "json");
  if (!rec) return null;
  const sub = new Subscription(rec);
  if (!sub.canTransitionTo(newStatus)) {
    await trackEvent(env, "subscription_invalid_transition", {
      internal_sub_id: internalSubId, from_status: sub.status, to_status: newStatus, rid,
    }).catch(() => {});
    return null;
  }
  return await patchInternalSub(env, internalSubId, { ...extraPatch, status: newStatus });
}

export async function patchApiKeyEntitlement(env, apiKey, patch) {
  if (!env.API_KEYS_KV || !apiKey) return;
  const rec = await env.API_KEYS_KV.get(apiKey, "json");
  if (!rec) return;
  await env.API_KEYS_KV.put(apiKey, JSON.stringify({ ...rec, ...patch }));
}

/**
 * S10 cross-worker revocation: the one way the revenue engine takes access
 * away at intel-gateway. API_KEYS_KV is the only state the two Workers
 * share, so the deny is written there in both forms the gateway enforces:
 *   - the key record gets an explicit gateway deny state
 *     (subscription-lifecycle.js SUBSCRIPTION_STATUS_DENY_STATES) and
 *     expires now: the API key is refused on its next request;
 *   - jwt_deny:{customer_id}: a Bearer JWT the customer obtained before the
 *     event is refused too (resolveAuth checks it by `sub`), instead of
 *     living out its 24-hour lifetime.
 * A refunded key keeps "refunded" (a later cancel/halt never relabels it).
 * @param {"refunded"|"cancelled"|"suspended"} status
 * @returns {Promise<object|null>} the key record before the change
 */
export async function denyGatewayAccess(env, link, status, at, meta = {}) {
  if (!env.API_KEYS_KV || !link) return null;
  let keyRecord = null;
  if (link.api_key) {
    keyRecord = await env.API_KEYS_KV.get(link.api_key, "json").catch(() => null);
    const keep = keyRecord && keyRecord.subscription_status === "refunded" ? "refunded" : status;
    await patchApiKeyEntitlement(env, link.api_key, { subscription_status: keep, expires_at: at });
  }
  const customerId = link.internal_customer_id || keyRecord?.customer_id || null;
  if (customerId) {
    await env.API_KEYS_KV.put(`jwt_deny:${customerId}`, JSON.stringify({
      reason: status, denied_at: at, ...meta,
    }), { expirationTtl: JWT_DENY_TTL_SECONDS });
  }
  return keyRecord;
}

/**
 * Inverse of denyGatewayAccess() for a recovered halt only: the key the
 * customer already holds works again at intel-gateway until periodEnd, and
 * the jwt_deny marker is cleared so a new login works. A key the gateway
 * holds as refunded or cancelled is never revived here.
 * @returns {Promise<boolean>} whether access was restored
 */
export async function restoreGatewayAccess(env, link, periodEnd) {
  if (!env.API_KEYS_KV || !link || !link.api_key) return false;
  const rec = await env.API_KEYS_KV.get(link.api_key, "json").catch(() => null);
  if (!rec || rec.subscription_status === "refunded" || rec.subscription_status === "cancelled") return false;
  await patchApiKeyEntitlement(env, link.api_key, { subscription_status: "active", expires_at: periodEnd });
  const customerId = link.internal_customer_id || rec.customer_id || null;
  if (customerId) await env.API_KEYS_KV.delete(`jwt_deny:${customerId}`);
  return true;
}

/**
 * Owner decision 2026-09-25: a halted subscription reactivates automatically
 * when Razorpay later captures a charge on it (the customer paid after the
 * retries ran out). Requires the signed webhook to carry a CAPTURED payment
 * for this subscription; then SUSPENDED -> ACTIVE, the same API key is
 * restored (never a second key), and the period follows Razorpay.
 */
export async function recoverHaltedSubscription(env, link, providerId, subEntity, payEntity, event, rid) {
  if (!link?.internal_sub_id || !payEntity || payEntity.status !== "captured") {
    await trackEvent(env, "subscription_recovery_unverified", {
      razorpay_subscription_id: providerId, event, payment_status: payEntity?.status || null, rid,
    });
    return false;
  }
  const at = new Date().toISOString();
  const periodEnd = unixToIso(subEntity?.current_end) || link.current_period_end;
  const transitioned = await tryTransition(env, link.internal_sub_id, SUB_STATUS.ACTIVE, {
    current_period_start: unixToIso(subEntity?.current_start), current_period_end: periodEnd,
    renewal_reminder_sent: false, recovered_at: at,
  }, rid);
  if (!transitioned) return false;
  const restored = await restoreGatewayAccess(env, link, periodEnd);
  await putProviderLink(env, providerId, {
    ...link, status: "active", current_period_end: periodEnd, recovered_at: at,
    renewal_count: (link.renewal_count || 0) + 1,
  });
  await trackEvent(env, "subscription_recovered", {
    email: link.email, tier: link.tier, razorpay_subscription_id: providerId, payment_id: payEntity.id, access_restored: restored, event, rid,
  });
  return true;
}

// Webhook idempotency guard -- Razorpay's delivery is at-least-once, so any
// event may be redelivered. Uses REVENUE_CRM_KV (already bound in this
// Worker) rather than intel-gateway's SECURITY_HUB_KV (not bound here, and
// binding it would be a wider change than this fix needs).
export async function alreadyProcessed(env, idempKey) {
  return !!(await env.REVENUE_CRM_KV.get(`rzp_sub_event:${idempKey}`));
}
export async function markProcessed(env, idempKey, meta) {
  await env.REVENUE_CRM_KV.put(`rzp_sub_event:${idempKey}`, JSON.stringify(meta), { expirationTtl: 86400 * 365 });
}

// =============================================================================
// S19 pricing fail-closed: a Razorpay Plan must charge the canonical price
// =============================================================================
// Razorpay bills whatever the Plan behind RAZORPAY_PLAN_ID_* says. Before any
// subscription is created, the Plan is read from Razorpay and its currency,
// amount and billing period compared with the canonical price (TIERS,
// verified against config/commercial-contract.json by
// scripts/verify_commercial_contract.py). A mismatch, or a Plan that cannot
// be read, refuses the checkout: no subscription, no payment UI.
const PLAN_VERIFIED_TTL_SECONDS = 3600;

/** Canonical charge in paise for a tier/cycle, or null. */
export function canonicalPlanPaise(tier, cycle) {
  const t = TIERS[tier];
  if (!t) return null;
  const inr = cycle === "annual" ? t.price_inr_annual : t.price_inr;
  return Number.isInteger(inr) && inr > 0 ? inr * 100 : null;
}

/** Pure comparison of a Razorpay Plan entity with the canonical price. */
export function planMatchesCanonical(plan, tier, cycle) {
  const expected = canonicalPlanPaise(tier, cycle);
  if (!expected) return { ok: false, reason: "no_canonical_price" };
  if (!plan || !plan.item) return { ok: false, reason: "plan_unreadable" };
  if (String(plan.item.currency || "").toUpperCase() !== "INR") return { ok: false, reason: "currency_mismatch", expected_paise: expected };
  if (plan.item.amount !== expected) return { ok: false, reason: "amount_mismatch", expected_paise: expected, plan_paise: plan.item.amount };
  const period = String(plan.period || ""), interval = Number(plan.interval);
  const periodOk = cycle === "annual"
    ? (period === "yearly" && interval === 1) || (period === "monthly" && interval === 12)
    : period === "monthly" && interval === 1;
  if (!periodOk) return { ok: false, reason: "period_mismatch", expected_paise: expected };
  return { ok: true, expected_paise: expected };
}

/**
 * Reads the Plan from Razorpay (cached for an hour once verified) and checks
 * it. Fails closed: an unreadable Plan is not a verified Plan.
 */
export async function verifyPlanPrice(env, tier, cycle, planId) {
  const cacheKey = `rzp_plan_verified:${planId}:${tier}:${cycle}`;
  const cached = await env.REVENUE_CRM_KV.get(cacheKey, "json").catch(() => null);
  if (cached && cached.ok) return cached;
  let plan = null;
  try {
    const resp = await fetch(`${RAZORPAY_API_BASE}/plans/${encodeURIComponent(planId)}`, {
      headers: { "Authorization": `Basic ${btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`)}` },
    });
    if (resp.ok) plan = await resp.json();
  } catch (_) { plan = null; }
  const verdict = { ...planMatchesCanonical(plan, tier, cycle), checked_at: new Date().toISOString() };
  if (verdict.ok) await env.REVENUE_CRM_KV.put(cacheKey, JSON.stringify(verdict), { expirationTtl: PLAN_VERIFIED_TTL_SECONDS }).catch(() => {});
  return verdict;
}

// =============================================================================
// POST /api/v2/billing/subscriptions/create
// =============================================================================
export async function handleBillingSubscriptionCreate(request, env, ctx, rid) {
  if (request.method !== "POST") return json({ error: "POST required" }, 405);
  let body = {};
  try { body = await request.json(); } catch (_) {}

  const email = sanitizeEmail(body.email);
  const tier  = (body.tier || "").toUpperCase();
  const cycle = body.billing_cycle === "annual" ? "annual" : "monthly";

  if (!email) return json({ error: "valid email is required" }, 400);
  if (!["PRO", "ENTERPRISE", "MSSP"].includes(tier) || !TIERS[tier]) {
    return json({ error: "Invalid tier. Valid: PRO, ENTERPRISE, MSSP" }, 400);
  }
  // Buyer details for the GST invoice (all optional). Validated here and
  // carried on the subscription (notes + provider link) so every captured
  // charge is recorded on the ledger with them. Place of supply is derived
  // from them, never guessed.
  const taxId = normalizeBuyerTaxId(body.gstin);
  if (!taxId.ok) return json({ error: taxId.reason, field: "gstin" }, 400);
  const billingState = normalizeBillingState(body.billing_state);
  if (!billingState.ok) return json({ error: billingState.reason, field: "billing_state" }, 400);
  const billingName = normalizeBillingName(body.billing_name);
  if (!billingName.ok) return json({ error: billingName.reason, field: "billing_name" }, 400);
  const billingAddress = typeof body.billing_address === "string"
    ? body.billing_address.normalize("NFKC").replace(/[\u0000-\u001f\u007f<>{}]/g, " ").replace(/\s+/g, " ").trim() : "";
  if (billingAddress && (billingAddress.length < 10 || billingAddress.length > 250)) {
    return json({ error: "Billing address must be 10-250 characters.", field: "billing_address" }, 400);
  }
  // Export of services: a buyer outside India names their country (ISO
  // 3166-1). It is only meaningful with billing_state OUTSIDE_INDIA.
  const billingCountry = normalizeBillingCountry(body.billing_country);
  if (!billingCountry.ok) return json({ error: billingCountry.reason, field: "billing_country" }, 400);
  if (billingCountry.value && (taxId.kind === "gstin" || billingState.value !== "OUTSIDE_INDIA")) {
    return json({ error: "A billing country applies only to a buyer outside India.", field: "billing_country" }, 400);
  }
  const buyer = {
    gstin: taxId.kind === "gstin" ? taxId.value : "", vat_id: taxId.kind === "vat" ? taxId.value : "",
    billing_state: taxId.kind === "gstin" ? taxId.value.slice(0, 2) : billingState.value,
    billing_name: billingName.value, billing_address: billingAddress, billing_country: billingCountry.value,
  };
  const buyerNotes = {};
  for (const [k, v] of Object.entries(buyer)) if (v) buyerNotes[k] = v;
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: "Razorpay not configured on server", fallback_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 503);
  }
  const planEnvKey = PLAN_ID_ENV_KEYS[tier][cycle];
  const planId = env[planEnvKey];
  if (!planId) {
    return json({ error: `Razorpay plan not configured (${planEnvKey})`, fallback_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 503);
  }
  const planCheck = await verifyPlanPrice(env, tier, cycle, planId);
  if (!planCheck.ok) {
    await trackEvent(env, "subscription_plan_price_unverified", {
      tier, billing_cycle: cycle, reason: planCheck.reason, expected_paise: planCheck.expected_paise ?? null, plan_paise: planCheck.plan_paise ?? null, rid,
    });
    return json({
      error: "plan_price_unverified",
      message: "This billing cycle is temporarily unavailable. No payment was taken.",
    }, 503);
  }

  // S5 idempotency / double-billing guard. (1) An email that already holds
  // a live subscription on this tier is sent to the Billing Center instead
  // of being billed a second time. (2) A retried or double-submitted
  // checkout (same email, tier, cycle and buyer details) within
  // PENDING_CHECKOUT_TTL_SECONDS reuses the subscription it already created
  // while that one is still unpaid, instead of creating a second one.
  // KV is not transactional, so two truly simultaneous requests can still
  // both create one; only one checkout modal is ever opened per page (the
  // client state machine), and an unpaid Razorpay subscription never bills.
  const existing = await env.REVENUE_CRM_KV.get(`sub:email:${email}`, "json");
  if (existing && existing.tier === tier && LIVE_SUB_STATUSES.includes(existing.status) &&
      (!existing.current_period_end || Date.parse(existing.current_period_end) > Date.now())) {
    await trackEvent(env, "subscription_checkout_already_subscribed", { tier, billing_cycle: cycle, rid });
    return json({
      error: "already_subscribed",
      message: "An active subscription for this plan already exists for this email. Manage it in the Billing Center.",
      billing_center_url: "/billing.html",
    }, 409);
  }
  const pendingKey = `rzp_sub_pending:${await sha256Hex(JSON.stringify([email, tier, cycle, buyer]))}`;
  const pendingId = await env.REVENUE_CRM_KV.get(pendingKey);
  if (pendingId) {
    const pendingLink = await getProviderLink(env, pendingId);
    if (pendingLink && pendingLink.status === "created") {
      await trackEvent(env, "subscription_checkout_reused", { tier, billing_cycle: cycle, rid });
      return json({
        subscription_id: pendingId, short_url: pendingLink.short_url || null, key_id: env.RAZORPAY_KEY_ID,
        tier, billing_cycle: cycle, status: "created", prefill: { email }, reused: true,
      });
    }
  }

  try {
    const creds = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
    const resp  = await fetch(`${RAZORPAY_API_BASE}/subscriptions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Basic ${creds}` },
      body: JSON.stringify({
        plan_id: planId,
        customer_notify: 1,
        quantity: 1,
        total_count: TOTAL_COUNT_BY_CYCLE[cycle],
        notes: { email, tier, billing_cycle: cycle, platform: "SENTINEL-APEX", ...buyerNotes },
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return json({ error: "Razorpay subscription creation failed", detail: errText }, 502);
    }
    const sub = await resp.json();

    await putProviderLink(env, sub.id, {
      razorpay_subscription_id: sub.id, email, tier, billing_cycle: cycle,
      status: "created", plan_id: planId, created_at: new Date().toISOString(), buyer,
      short_url: sub.short_url || null,
    });
    await env.REVENUE_CRM_KV.put(pendingKey, sub.id, { expirationTtl: PENDING_CHECKOUT_TTL_SECONDS });
    await trackEvent(env, "subscription_checkout_created", { email, tier, billing_cycle: cycle, razorpay_subscription_id: sub.id, rid });

    return json({
      subscription_id: sub.id,
      short_url: sub.short_url || null,
      key_id: env.RAZORPAY_KEY_ID,
      tier, billing_cycle: cycle,
      status: sub.status || "created",
      prefill: { email },
    });
  } catch (e) {
    console.error(`[subscription-create] Razorpay API failed: ${e.message}`);
    return json({ error: "Razorpay API unavailable" }, 503);
  }
}

// =============================================================================
// GET /api/v2/billing/subscriptions/status?subscription_id=...
// =============================================================================
/**
 * Polling target for the checkout page: reports whether a Razorpay
 * subscription has been activated yet.
 *
 * Subscription activation happens asynchronously via the webhook above, not
 * synchronously in the Razorpay Checkout response the way the one-time-order
 * flow's /api/payment/razorpay/verify works -- the checkout-page frontend
 * needs something to poll after the Checkout modal's handler fires. Reuses
 * getProviderLink() (the same lookup putProviderLink()/the webhook handler
 * already maintain) rather than introducing a second record of the same
 * state.
 *
 * Requires payment_id + signature (Razorpay Checkout's own handler callback
 * for a subscription returns {razorpay_payment_id, razorpay_subscription_id,
 * razorpay_signature}, with signature = HMAC_SHA256(payment_id + "|" +
 * subscription_id, key_secret)) -- the same proof-of-checkout-completion
 * pattern the one-time-order flow's /api/payment/razorpay/verify already
 * requires via razorpay_signature, adapted to the Subscriptions signature
 * formula. subscription_id alone is not a secret: it's returned directly to
 * the browser by the create-subscription response above and handed to
 * Razorpay's own Checkout widget client-side, so anyone who observed it
 * (shared logs, a support ticket, browser history) could otherwise read
 * another customer's live api_key with nothing but that ID (IDOR).
 *
 * @param {Request} request - must carry `subscription_id`, `payment_id`,
 *   and `signature` query params.
 * @param {object} env - Worker bindings (REVENUE_CRM_KV via getProviderLink,
 *   RAZORPAY_KEY_SECRET for signature verification).
 * @param {object} ctx - Worker execution context (unused, kept for the same
 *   (request, env, ctx, rid) signature every route handler in this file uses).
 * @param {string} rid - request id, accepted for signature consistency with
 *   the other handlers though not currently used in the response.
 * @returns {Promise<Response>} `{status, tier, billing_cycle}`, plus
 *   `api_key` only once status is "active" -- before that there is nothing
 *   to hand back yet. 401 if payment_id/signature don't match subscription_id.
 */
export async function handleBillingSubscriptionStatus(request, env, ctx, rid) {
  const url = new URL(request.url);
  const providerId = url.searchParams.get("subscription_id");
  const paymentId  = url.searchParams.get("payment_id");
  const signature  = url.searchParams.get("signature");
  if (!providerId) return json({ error: "subscription_id is required" }, 400);
  if (!paymentId || !signature) return json({ error: "payment_id and signature are required" }, 400);
  if (!env.RAZORPAY_KEY_SECRET) return json({ error: "Razorpay not configured on server" }, 503);

  const validProof = await verifyRazorpayHmac(`${paymentId}|${providerId}`, signature, env.RAZORPAY_KEY_SECRET);
  if (!validProof) return json({ error: "Invalid payment signature" }, 401);

  const link = await getProviderLink(env, providerId);
  if (!link) return json({ status: "not_found" }, 404);

  const body = { status: link.status, tier: link.tier, billing_cycle: link.billing_cycle };
  if (link.status === "active" && link.api_key) body.api_key = link.api_key;
  return json(body);
}

// =============================================================================
// POST /api/v2/billing/webhooks/razorpay
// =============================================================================
export async function handleBillingWebhook(request, env, ctx, rid) {
  if (request.method !== "POST") return json({ error: "POST required" }, 405);
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.includes("application/json")) return json({ error: "application/json required" }, 415);

  const declaredLength = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RAZORPAY_WEBHOOK_BYTES) {
    return json({ error: "payload_too_large" }, 413);
  }

  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > MAX_RAZORPAY_WEBHOOK_BYTES) {
    return json({ error: "payload_too_large" }, 413);
  }

  const sig     = request.headers.get("X-Razorpay-Signature") || "";
  const secret  = env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return json({ error: "Webhook secret not configured" }, 500);
  if (!/^[0-9a-f]{64}$/i.test(sig)) {
    await trackEvent(env, "subscription_webhook_sig_fail", { rid, reason: "malformed_signature" });
    return json({ error: "Signature mismatch" }, 401);
  }

  const valid = await verifyRazorpayHmac(rawBody, sig, secret);
  if (!valid) {
    await trackEvent(env, "subscription_webhook_sig_fail", { rid, reason: "verification_failed" });
    return json({ error: "Signature mismatch" }, 401);
  }

  let payload = {};
  try { payload = JSON.parse(rawBody); } catch (_) {
    return json({ error: "Invalid JSON payload" }, 400);
  }

  const event = typeof payload.event === "string" ? payload.event : "";
  if (!RAZORPAY_BILLING_EVENTS.includes(event)) {
    await trackEvent(env, "subscription_webhook_event_ignored", { event: event || null, rid });
    return json({ status: "ignored", event: event || null });
  }
  // Optional account binding: once RAZORPAY_ACCOUNT_ID is configured, an
  // event must name that account (a payload without account_id is refused).
  if (env.RAZORPAY_ACCOUNT_ID && payload.account_id !== env.RAZORPAY_ACCOUNT_ID) {
    await trackEvent(env, "subscription_webhook_account_mismatch", { event, rid });
    return json({ error: "account_mismatch" }, 403);
  }

  const subEntity  = payload.payload?.subscription?.entity || null;
  const payEntity  = payload.payload?.payment?.entity || null;
  const notes      = subEntity?.notes || payEntity?.notes || {};
  const providerId = subEntity?.id || null;

  const eventId = request.headers.get("X-Razorpay-Event-Id") || "";
  if (eventId && !RAZORPAY_EVENT_ID_RE.test(eventId)) return json({ error: "invalid_event_id" }, 400);
  const idempKey = eventId || `body-sha256:${await sha256Hex(rawBody)}`;
  if (await alreadyProcessed(env, idempKey)) {
    return json({ status: "already_processed", event });
  }
  // Claim BEFORE processing, not after. Razorpay's delivery is at-least-once,
  // so a redelivery arriving while this request is still mid-flight (e.g.
  // during provisionCustomer()'s ~10 sequential KV writes for
  // subscription.activated) previously saw alreadyProcessed()===false too
  // and could double-provision the same customer. Unclaimed on failure below
  // so a genuine retry after a transient error isn't blocked forever.
  // Phase 2: persist the raw payload alongside the marker (previously only
  // {event, providerId, ts} was kept) -- the idempotency key already exists
  // and already has a 1-year TTL; this makes it double as a real webhook
  // audit/replay record instead of adding a second storage mechanism.
  await markProcessed(env, idempKey, { event, providerId, ts: Date.now(), payload });

  const link  = providerId ? await getProviderLink(env, providerId) : null;
  const email = sanitizeEmail(link?.email || notes.email);
  const tier  = (link?.tier || notes.tier || "").toUpperCase();
  const cycle = link?.billing_cycle || notes.billing_cycle || "monthly";

  try {
  // Refunds and disputes (billing-routes.js): reconcile the ledger, the
  // refund request and the entitlement.
  if (event.startsWith("refund.") || event.startsWith("payment.dispute.")) {
    await applyBillingWebhookEvent(env, event, payload, {
      rid, revokeEntitlementForSubscription: (subId, status) => revokeEntitlementForSubscription(env, subId, status, rid),
    });
    return json({ status: "processed", event });
  }

  // Every captured subscription charge goes on the billing ledger (the
  // authority for refunds and GST invoices), then gets its invoice or a
  // recorded hold. Never blocks the entitlement change below: a ledger
  // failure is logged, and the raw payload is already stored with the
  // idempotency marker above for replay.
  if (subEntity && payEntity && payEntity.status === "captured" && email && TIERS[tier]) {
    try {
      const buyer = link?.buyer || {
        gstin: notes.gstin || "", vat_id: notes.vat_id || "", billing_state: notes.billing_state || "",
        billing_name: notes.billing_name || "", billing_address: notes.billing_address || "",
        billing_country: notes.billing_country || "",
      };
      await recordCapturedPayment(env.CRM_DB, {
        payment: payEntity, providerSubId: providerId, email, tier, billingCycle: cycle, buyer,
      });
      const inv = await issueInvoiceForPayment(env.CRM_DB, env, payEntity.id);
      await trackEvent(env, inv.status === "issued" ? "invoice_issued" : "invoice_held", {
        payment_id: payEntity.id, invoice_number: inv.invoice?.invoice_number || null, reason: inv.reason || null, rid,
      });
    } catch (ledgerErr) {
      await trackEvent(env, "billing_ledger_write_failed", {
        payment_id: payEntity.id, event, error: ledgerErr?.message || String(ledgerErr), rid,
      }).catch(() => {});
    }
  }

  switch (event) {
    case "subscription.authenticated": {
      if (providerId) await putProviderLink(env, providerId, { ...(link || {}), status: "authenticated" });
      await trackEvent(env, "subscription_authenticated", { email, tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.activated": {
      if (link?.status === "halted" && link.internal_sub_id) {
        // Already provisioned: a halted subscription resuming is a recovery
        // of the SAME key, never a second provisioning.
        await recoverHaltedSubscription(env, link, providerId, subEntity, payEntity, event, rid);
        break;
      }
      if (link && ["refunded", "cancelled", "completed"].includes(link.status)) {
        // An ended subscription is never provisioned again: that would mint
        // a second key and clear the refund/cancel jwt_deny marker.
        await trackEvent(env, "subscription_billing_anomaly", { reason: "activated_after_end", status: link.status, razorpay_subscription_id: providerId, rid });
        break;
      }
      if (link?.status === "active") {
        // Already provisioned by an earlier delivery of this same event.
        // (idempKey is already claimed above, before this switch runs.)
        return json({ status: "already_active", razorpay_subscription_id: providerId });
      }
      if (!email || !TIERS[tier]) {
        await trackEvent(env, "subscription_activation_failed", { reason: "missing_or_invalid_email_or_tier", razorpay_subscription_id: providerId, rid });
        break;
      }
      const result = await provisionCustomer(env, {
        email, tier, billing_cycle: cycle,
        payment_id: null, payment_method: "razorpay_subscription",
        amount_paid: null, currency: "INR", trial: false,
      });
      if (env.API_KEYS_KV && result.customer_id) {
        await env.API_KEYS_KV.delete(`jwt_deny:${result.customer_id}`);
      }
      await putProviderLink(env, providerId, {
        ...(link || {}), email, tier, billing_cycle: cycle, status: "active",
        internal_sub_id: result.sub_id, internal_customer_id: result.customer_id,
        api_key: result.api_key,
        current_period_end: unixToIso(subEntity?.current_end) || result.period_end,
      });
      await patchInternalSub(env, result.sub_id, { provider_sub_id: providerId, billing_provider: "razorpay" });
      await trackEvent(env, "subscription_activated", { email, tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.charged": {
      if (!link?.internal_sub_id) {
        await trackEvent(env, "subscription_billing_anomaly", { reason: "charged_event_with_no_provider_link", razorpay_subscription_id: providerId, rid });
        break;
      }
      if (link.status === "halted") {
        await recoverHaltedSubscription(env, link, providerId, subEntity, payEntity, event, rid);
        break;
      }
      // ACTIVE -> ACTIVE is a valid self-transition (a normal renewal), so
      // tryTransition() alone doesn't protect against a delayed/out-of-order
      // "charged" event (Razorpay's delivery is at-least-once, unordered)
      // whose current_end is OLDER than what a later event already recorded
      // -- that would regress a paying customer's expires_at backward and
      // could prematurely deny them access. Take whichever period end is
      // actually later, regardless of delivery order.
      const receivedPeriodEnd = unixToIso(subEntity?.current_end);
      const periodEnd = (receivedPeriodEnd && link.current_period_end)
        ? (new Date(receivedPeriodEnd) > new Date(link.current_period_end) ? receivedPeriodEnd : link.current_period_end)
        : (receivedPeriodEnd || link.current_period_end);
      const transitioned = await tryTransition(env, link.internal_sub_id, SUB_STATUS.ACTIVE, {
        current_period_start: unixToIso(subEntity?.current_start),
        current_period_end: periodEnd,
        renewal_reminder_sent: false,
        renewal_count: (link.renewal_count || 0) + 1,
      }, rid);
      if (!transitioned) {
        // tryTransition() already logged subscription_invalid_transition and
        // left sub:{internal_sub_id} untouched (fail-safe, not fail-open) --
        // e.g. a late/out-of-order "charged" event arriving after this
        // subscription was already CANCELLED/SUSPENDED/EXPIRED. Extending
        // the live API key's expiry or flipping the provider link back to
        // "active" here would silently undo that fail-safe through a side
        // door, so neither runs.
        break;
      }
      await patchApiKeyEntitlement(env, link.api_key, { expires_at: periodEnd });
      await putProviderLink(env, providerId, { ...link, status: "active", current_period_end: periodEnd, renewal_count: (link.renewal_count || 0) + 1 });
      await trackEvent(env, "subscription_renewed", { email: link.email, tier: link.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.pending": {
      if (link?.internal_sub_id) {
        await tryTransition(env, link.internal_sub_id, SUB_STATUS.PAST_DUE, {}, rid);
        await putProviderLink(env, providerId, { ...link, status: "pending" });
      }
      await trackEvent(env, "subscription_payment_pending", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.halted": {
      if (link?.internal_sub_id) {
        await tryTransition(env, link.internal_sub_id, SUB_STATUS.SUSPENDED, {}, rid);
        await denyGatewayAccess(env, link, "suspended", new Date().toISOString(), { provider_sub_id: providerId });
        await putProviderLink(env, providerId, { ...link, status: "halted" });
      }
      await trackEvent(env, "subscription_suspended", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.cancelled":
    case "subscription.completed": {
      if (link?.internal_sub_id) {
        await tryTransition(env, link.internal_sub_id, SUB_STATUS.CANCELLED, { cancelled_at: new Date().toISOString() }, rid);
        await denyGatewayAccess(env, link, "cancelled", new Date().toISOString(), { provider_sub_id: providerId });
        await putProviderLink(env, providerId, { ...link, status: "cancelled" });
      }
      await trackEvent(env, "subscription_cancelled", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, event, rid });
      break;
    }

    case "payment.failed": {
      // Only meaningful in a subscription context (payload.subscription present
      // alongside payload.payment) -- one-time-order payment failures are
      // handled entirely by the existing intel-gateway payment flow.
      if (subEntity && link?.internal_sub_id) {
        await patchInternalSub(env, link.internal_sub_id, {
          retry_count: (link.retry_count || 0) + 1,
          failure_reason: payEntity?.error_description || payEntity?.error_reason || "unknown",
        });
        await putProviderLink(env, providerId, { ...link, retry_count: (link.retry_count || 0) + 1 });
      }
      await trackEvent(env, "subscription_payment_failed", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    default: {
      await trackEvent(env, "subscription_webhook_unhandled_event", { event, razorpay_subscription_id: providerId, rid });
      break;
    }
  }
  } catch (err) {
    // Unclaim so Razorpay's automatic retry (it retries on non-2xx
    // responses) can reprocess this event instead of it being silently
    // dropped forever by the idempotency guard.
    await env.REVENUE_CRM_KV.delete(`rzp_sub_event:${idempKey}`).catch(() => {});
    await trackEvent(env, "subscription_webhook_processing_failed", {
      event, razorpay_subscription_id: providerId, error: err?.message || String(err), rid,
    }).catch(() => {});
    return json({ error: "processing_failed" }, 500);
  }

  return json({ status: "processed", event });
}

/**
 * Revokes a subscription's entitlement after a refund (Razorpay confirmed it
 * via webhook): the API key is denied at the gateway (subscription_status
 * "refunded" is a deny state there) and expires now, the internal
 * subscription is cancelled, and the provider link records the refund.
 */
export async function revokeEntitlementForSubscription(env, providerSubId, status, rid) {
  const link = await getProviderLink(env, providerSubId);
  if (!link) {
    await trackEvent(env, "refund_revoke_no_provider_link", { razorpay_subscription_id: providerSubId, rid });
    return false;
  }
  const at = new Date().toISOString();
  await denyGatewayAccess(env, link, status, at, { provider_sub_id: providerSubId });
  if (link.internal_sub_id) await tryTransition(env, link.internal_sub_id, SUB_STATUS.CANCELLED, { cancelled_at: at, cancel_reason: status }, rid);
  await putProviderLink(env, providerSubId, { ...link, status });
  await trackEvent(env, "entitlement_revoked", { razorpay_subscription_id: providerSubId, email: link.email, reason: status, rid });
  return true;
}
