/**
 * Razorpay Subscriptions integration -- Phase 2 (new subsystem).
 *
 * This is the first automated, recurring-billing path in the platform. It
 * does not replace intel-gateway's existing one-time Razorpay Orders
 * checkout (workers/intel-gateway/src/index.js) -- that keeps working
 * unchanged. It calls into the existing customer/subscription/API-key logic
 * in ./index.js (provisionCustomer, renewCustomerSubscription,
 * suspendCustomerSubscription, cancelCustomerSubscription) rather than
 * duplicating it, so every consumer of that logic (manual payment approval,
 * admin endpoints, this new webhook path) shares one implementation.
 *
 * VERIFICATION STATUS: syntax, bundling, and state-transition logic are
 * verified locally against hand-built payloads matching Razorpay's
 * documented Subscriptions API. Nothing here has been exercised against a
 * real or Razorpay test-mode account -- no live credentials exist in the
 * environment this was written in. Treat as code-reviewed, not
 * production-verified, until a post-deploy smoke test happens.
 */
import {
  provisionCustomer,
  renewCustomerSubscription,
  suspendCustomerSubscription,
  cancelCustomerSubscription,
  syncGatewayEntitlement,
  TIERS,
  SUB_STATUS,
  appendAuditLog,
  genId,
} from './index.js';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function sanitizeEmail(email) {
  const e = String(email || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
}

// Same HMAC-SHA256 constant-time verification approach already proven in
// workers/intel-gateway/src/index.js's verifyRazorpayHmac. Copied rather than
// imported -- these are two separately-deployed Workers with no shared
// module between them (Cloudflare Workers do not support cross-Worker
// imports; a service binding would let one Worker call the other's fetch
// handler, but not import its internal functions).
async function verifyRazorpayHmac(payload, signature, secret) {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = new Uint8Array(signature.match(/.{2}/g).map(b => parseInt(b, 16)));
    return await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(payload));
  } catch (_) {
    return false;
  }
}

function planIdFor(env, tier, billingCycle) {
  const cycle = billingCycle === 'annual' ? 'ANNUAL' : 'MONTHLY';
  return env[`RAZORPAY_PLAN_ID_${tier}_${cycle}`] || null;
}

// POST /api/v2/billing/subscriptions/create
export async function handleSubscriptionCreate(request, env, rid) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const body = await request.json().catch(() => ({}));
  const email = sanitizeEmail(body.email);
  const tier = String(body.tier || '').toUpperCase();
  const billingCycle = body.billing_cycle === 'annual' ? 'annual' : 'monthly';

  if (!email) return json({ error: 'invalid_email' }, 400);
  if (!TIERS[tier] || tier === 'FREE') return json({ error: 'invalid_tier', valid_tiers: Object.keys(TIERS).filter(t => t !== 'FREE') }, 400);
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: 'razorpay_not_configured', fallback_url: 'https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html' }, 503);
  }
  const planId = planIdFor(env, tier, billingCycle);
  if (!planId) {
    return json({ error: 'plan_not_configured', message: `RAZORPAY_PLAN_ID_${tier}_${billingCycle.toUpperCase()} is not set -- this plan must be created in the Razorpay dashboard first.` }, 503);
  }

  try {
    const creds = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
    // Razorpay Subscriptions API: total_count is required even for
    // "until cancelled" billing -- 120 monthly / 10 annual cycles (10 years)
    // is Razorpay's own documented convention for effectively-unbounded
    // subscriptions; the customer is charged once per cycle, not once total.
    const totalCount = billingCycle === 'annual' ? 10 : 120;
    const resp = await fetch('https://api.razorpay.com/v1/subscriptions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${creds}` },
      body: JSON.stringify({
        plan_id: planId,
        customer_notify: 1,
        total_count: totalCount,
        notes: { email, tier, billing_cycle: billingCycle, platform: 'SENTINEL-APEX' },
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return json({ error: 'razorpay_subscription_create_failed', detail: errText }, 502);
    }
    const sub = await resp.json();

    // Local subscription record: status starts PENDING until the
    // subscription.activated webhook confirms the first payment succeeded --
    // entitlement is granted there (provisionCustomer), not here, so nobody
    // gets access before Razorpay confirms money actually moved.
    await env.REVENUE_CRM_KV.put(`razorpay_sub:${sub.id}`, JSON.stringify({
      razorpay_subscription_id: sub.id, email, tier, billing_cycle: billingCycle,
      status: 'created', created_at: new Date().toISOString(),
    }));
    await appendAuditLog(env, { action: 'razorpay_subscription_created', email, tier, razorpay_subscription_id: sub.id, ts: new Date().toISOString() });

    return json({
      subscription_id: sub.id,
      short_url: sub.short_url || null,
      key_id: env.RAZORPAY_KEY_ID,
      tier, billing_cycle: billingCycle,
      status: 'created',
    }, 201);
  } catch (e) {
    return json({ error: 'razorpay_api_unavailable', detail: e.message }, 503);
  }
}

// POST /api/v2/billing/webhooks/razorpay
export async function handleSubscriptionWebhook(request, env, ctx, rid) {
  const rawBody = await request.text();
  const sig = request.headers.get('X-Razorpay-Signature') || '';
  const secret = env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return json({ error: 'webhook_secret_not_configured' }, 500);

  const valid = await verifyRazorpayHmac(rawBody, sig, secret);
  if (!valid) {
    await appendAuditLog(env, { action: 'webhook_sig_fail', source: 'razorpay_subscriptions', ts: new Date().toISOString() });
    return json({ error: 'signature_mismatch' }, 401);
  }

  let payload = {};
  try { payload = JSON.parse(rawBody); } catch (_) { return json({ error: 'invalid_json' }, 400); }

  const event = payload.event || '';
  const subEntity = payload.payload?.subscription?.entity;
  const razorpaySubId = subEntity?.id;
  if (!razorpaySubId) return json({ status: 'ignored', reason: 'no_subscription_entity' });

  // Idempotency: Razorpay retries webhooks on non-2xx / timeout. Dedup on
  // (event, subscription id, current period end) so a retried delivery for
  // an already-processed cycle is a safe no-op, not a double-renewal.
  const dedupKey = `webhook_seen:${event}:${razorpaySubId}:${subEntity.current_end || subEntity.charge_at || ''}`;
  const alreadySeen = await env.REVENUE_CRM_KV.get(dedupKey);
  if (alreadySeen) return json({ status: 'already_processed' });
  await env.REVENUE_CRM_KV.put(dedupKey, '1', { expirationTtl: 86400 * 30 });

  const local = await env.REVENUE_CRM_KV.get(`razorpay_sub:${razorpaySubId}`, 'json');
  if (!local) {
    await appendAuditLog(env, { action: 'webhook_unknown_subscription', razorpay_subscription_id: razorpaySubId, event, ts: new Date().toISOString() });
    return json({ status: 'ignored', reason: 'unknown_subscription' });
  }
  const { email, tier, billing_cycle: billingCycle } = local;

  let result = { status: 'ignored', event };

  switch (event) {
    case 'subscription.activated': {
      // First successful charge -- this is the moment access should actually
      // be granted, not subscription-create above (Razorpay hasn't charged
      // anyone yet at create time).
      const provision = await provisionCustomer(env, { email, tier, billing_cycle: billingCycle, payment_id: razorpaySubId, payment_method: 'razorpay_subscription' });
      await env.REVENUE_CRM_KV.put(`razorpay_sub:${razorpaySubId}`, JSON.stringify({ ...local, status: 'active' }));
      result = { status: 'activated', ...provision };
      break;
    }
    case 'subscription.charged': {
      // Recurring renewal charge succeeded -- extend the period, do not
      // re-provision (provisionCustomer would overwrite/rotate the key
      // unnecessarily; renewCustomerSubscription only extends expiry).
      const renewal = await renewCustomerSubscription(env, email, { billing_cycle: billingCycle, payment_id: razorpaySubId });
      result = { status: 'renewed', ...renewal };
      break;
    }
    case 'subscription.pending':
    case 'subscription.halted': {
      // pending: a retry is scheduled by Razorpay, access continues through
      // the grace period. halted: Razorpay has exhausted its own retry
      // schedule -- same grace-period handling either way; the daily
      // expire-check (handleSubExpireCheck) cuts access once grace elapses.
      const suspend = await suspendCustomerSubscription(env, email, { reason: event });
      result = { status: 'past_due', ...suspend };
      break;
    }
    case 'subscription.cancelled':
    case 'subscription.completed': {
      // completed = total_count cycles finished naturally (should not
      // normally happen given the effectively-unbounded totalCount used at
      // create time, but handled the same as an explicit cancellation).
      const cancel = await cancelCustomerSubscription(env, email, { reason: event, immediate: false });
      result = { status: 'cancelled', ...cancel };
      break;
    }
    case 'payment.failed': {
      // Underlying payment entity failure (as opposed to the subscription-
      // level pending/halted events above) -- treat the same way: grace
      // period, not immediate revocation.
      const suspend = await suspendCustomerSubscription(env, email, { reason: 'payment_failed' });
      result = { status: 'past_due', ...suspend };
      break;
    }
    default:
      result = { status: 'ignored', event };
  }

  await appendAuditLog(env, { action: 'razorpay_subscription_webhook', event, email, tier, razorpay_subscription_id: razorpaySubId, ts: new Date().toISOString() });
  return json(result);
}

export async function dispatchBillingRoutes(path, method, request, env, ctx, rid) {
  if (path === '/api/v2/billing/subscriptions/create') return await handleSubscriptionCreate(request, env, rid);
  if (path === '/api/v2/billing/webhooks/razorpay') return await handleSubscriptionWebhook(request, env, ctx, rid);
  return null;
}
