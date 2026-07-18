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

const RAZORPAY_API_BASE = "https://api.razorpay.com/v1";

// One Razorpay Plan (pre-created in the Razorpay Dashboard or via the Plans
// API -- a one-time manual step outside what this session can do without
// live credentials) per tier/cycle. Missing plan_id => 503, not a crash.
const PLAN_ID_ENV_KEYS = {
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

async function getProviderLink(env, providerSubId) {
  return await env.REVENUE_CRM_KV.get(`razorpay_sub:${providerSubId}`, "json");
}

async function putProviderLink(env, providerSubId, record) {
  await env.REVENUE_CRM_KV.put(`razorpay_sub:${providerSubId}`, JSON.stringify(record));
}

async function patchInternalSub(env, internalSubId, patch) {
  const rec = await env.REVENUE_CRM_KV.get(`sub:${internalSubId}`, "json");
  if (!rec) return null;
  const updated = { ...rec, ...patch, updated_at: new Date().toISOString() };
  await env.REVENUE_CRM_KV.put(`sub:${internalSubId}`, JSON.stringify(updated));
  await env.REVENUE_CRM_KV.put(`sub:email:${rec.email}`, JSON.stringify(updated));
  return updated;
}

async function patchApiKeyEntitlement(env, apiKey, patch) {
  if (!env.API_KEYS_KV || !apiKey) return;
  const rec = await env.API_KEYS_KV.get(apiKey, "json");
  if (!rec) return;
  await env.API_KEYS_KV.put(apiKey, JSON.stringify({ ...rec, ...patch }));
}

// Webhook idempotency guard -- Razorpay's delivery is at-least-once, so any
// event may be redelivered. Uses REVENUE_CRM_KV (already bound in this
// Worker) rather than intel-gateway's SECURITY_HUB_KV (not bound here, and
// binding it would be a wider change than this fix needs).
async function alreadyProcessed(env, idempKey) {
  return !!(await env.REVENUE_CRM_KV.get(`rzp_sub_event:${idempKey}`));
}
async function markProcessed(env, idempKey, meta) {
  await env.REVENUE_CRM_KV.put(`rzp_sub_event:${idempKey}`, JSON.stringify(meta), { expirationTtl: 86400 * 365 });
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
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: "Razorpay not configured on server", fallback_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 503);
  }
  const planEnvKey = PLAN_ID_ENV_KEYS[tier][cycle];
  const planId = env[planEnvKey];
  if (!planId) {
    return json({ error: `Razorpay plan not configured (${planEnvKey})`, fallback_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 503);
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
        notes: { email, tier, billing_cycle: cycle, platform: "SENTINEL-APEX" },
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return json({ error: "Razorpay subscription creation failed", detail: errText }, 502);
    }
    const sub = await resp.json();

    await putProviderLink(env, sub.id, {
      razorpay_subscription_id: sub.id, email, tier, billing_cycle: cycle,
      status: "created", plan_id: planId, created_at: new Date().toISOString(),
    });
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
    return json({ error: "Razorpay API unavailable", detail: e.message }, 503);
  }
}

// =============================================================================
// POST /api/v2/billing/webhooks/razorpay
// =============================================================================
export async function handleBillingWebhook(request, env, ctx, rid) {
  const rawBody = await request.text();
  const sig     = request.headers.get("X-Razorpay-Signature") || "";
  const secret  = env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return json({ error: "Webhook secret not configured" }, 500);

  const valid = await verifyRazorpayHmac(rawBody, sig, secret);
  if (!valid) {
    await trackEvent(env, "subscription_webhook_sig_fail", { rid });
    return json({ error: "Signature mismatch" }, 401);
  }

  let payload = {};
  try { payload = JSON.parse(rawBody); } catch (_) {
    return json({ error: "Invalid JSON payload" }, 400);
  }

  const event      = payload.event || "";
  const subEntity  = payload.payload?.subscription?.entity || null;
  const payEntity  = payload.payload?.payment?.entity || null;
  const entity     = subEntity || payEntity || {};
  const notes      = subEntity?.notes || payEntity?.notes || {};
  const providerId = subEntity?.id || null;

  // Idempotency -- prefer Razorpay's own event id header; fall back to a
  // composite of event + subscription id + payment id.
  const idempKey = request.headers.get("X-Razorpay-Event-Id")
    || `${event}:${providerId || "none"}:${payEntity?.id || "none"}`;
  if (await alreadyProcessed(env, idempKey)) {
    return json({ status: "already_processed", event });
  }
  // Claim BEFORE processing, not after. Razorpay's delivery is at-least-once,
  // so a redelivery arriving while this request is still mid-flight (e.g.
  // during provisionCustomer()'s ~10 sequential KV writes for
  // subscription.activated) previously saw alreadyProcessed()===false too
  // and could double-provision the same customer. Unclaimed on failure below
  // so a genuine retry after a transient error isn't blocked forever.
  await markProcessed(env, idempKey, { event, providerId, ts: Date.now() });

  const link  = providerId ? await getProviderLink(env, providerId) : null;
  const email = sanitizeEmail(link?.email || notes.email);
  const tier  = (link?.tier || notes.tier || "").toUpperCase();
  const cycle = link?.billing_cycle || notes.billing_cycle || "monthly";

  try {
  switch (event) {
    case "subscription.authenticated": {
      if (providerId) await putProviderLink(env, providerId, { ...(link || {}), status: "authenticated" });
      await trackEvent(env, "subscription_authenticated", { email, tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.activated": {
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
      const periodEnd = unixToIso(subEntity?.current_end);
      await patchInternalSub(env, link.internal_sub_id, {
        status: SUB_STATUS.ACTIVE,
        current_period_start: unixToIso(subEntity?.current_start),
        current_period_end: periodEnd || link.current_period_end,
        renewal_reminder_sent: false,
        renewal_count: (link.renewal_count || 0) + 1,
      });
      await patchApiKeyEntitlement(env, link.api_key, { expires_at: periodEnd || link.current_period_end });
      await putProviderLink(env, providerId, { ...link, status: "active", current_period_end: periodEnd || link.current_period_end, renewal_count: (link.renewal_count || 0) + 1 });
      await trackEvent(env, "subscription_renewed", { email: link.email, tier: link.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.pending": {
      if (link?.internal_sub_id) {
        await patchInternalSub(env, link.internal_sub_id, { status: SUB_STATUS.PAST_DUE });
        await putProviderLink(env, providerId, { ...link, status: "pending" });
      }
      await trackEvent(env, "subscription_payment_pending", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.halted": {
      if (link?.internal_sub_id) {
        await patchInternalSub(env, link.internal_sub_id, { status: SUB_STATUS.SUSPENDED });
        await patchApiKeyEntitlement(env, link.api_key, { expires_at: new Date().toISOString() });
        await putProviderLink(env, providerId, { ...link, status: "halted" });
      }
      await trackEvent(env, "subscription_suspended", { email: link?.email, tier: link?.tier, razorpay_subscription_id: providerId, rid });
      break;
    }

    case "subscription.cancelled":
    case "subscription.completed": {
      if (link?.internal_sub_id) {
        await patchInternalSub(env, link.internal_sub_id, { status: SUB_STATUS.CANCELLED, cancelled_at: new Date().toISOString() });
        await patchApiKeyEntitlement(env, link.api_key, { expires_at: new Date().toISOString() });
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
