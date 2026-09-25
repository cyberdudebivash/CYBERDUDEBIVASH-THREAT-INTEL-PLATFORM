// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: refunds + GST invoices
//
// Owner commercial policy (2026-09-24):
//   - 7-day conditional money-back guarantee on a customer's FIRST purchase,
//     merchant-approved. No automatic or self-service refund executes money
//     movement: a customer (or an admin on their behalf) files a request; an
//     admin approves or rejects it; only then does the server call Razorpay.
//   - The refund amount is never read from a request. It is the captured
//     amount on the ledger row written from Razorpay's signed webhook, and it
//     is re-checked against Razorpay's own payment record before refunding.
//   - Entitlement is revoked when Razorpay reports the refund (webhook), and
//     the subscription is cancelled so it cannot renew.
//   - No partial or pro-rata refunds, and none after the guarantee window.
//
// Routes (mounted in index.js before the admin gate; each checks its own auth):
//   POST /api/v2/billing/refunds/request   X-API-Key (customer) or X-Admin-Secret + {email}
//   GET  /api/v2/billing/refunds           X-Admin-Secret  [?status=]
//   POST /api/v2/billing/refunds/approve   X-Admin-Secret  {request_id, note}
//   POST /api/v2/billing/refunds/reject    X-Admin-Secret  {request_id, note}
//   POST /api/v2/billing/subscriptions/cancel  X-API-Key (customer): cancel at cycle end
//   GET  /api/v2/billing/invoices          X-API-Key (own) | X-Admin-Secret [?email=]
//   GET  /api/v2/billing/invoices/view     ?number=  X-API-Key (own) | X-Admin-Secret  [&format=html]
//   GET  /api/v2/billing/invoices/holds    X-Admin-Secret
//   POST /api/v2/billing/invoices/issue    X-Admin-Secret  {payment_id, billing_name?, billing_address?, billing_state?}
// =============================================================================

import { json, sanitizeEmail, trackEvent, isAdmin, slackNotify } from "./index.js";
import {
  firstPaymentFor, getPayment, insertRefundRequest, getRefundRequest, getRefundRequestByPayment,
  listRefundRequests, transitionRefundRequest, applyRefundToPayment, markDisputed,
  issueInvoiceForPayment, getInvoiceByNumber, listInvoicesFor, listInvoiceHolds, completeRecipientDetails,
} from "./billing-ledger.js";
import { normalizeBillingName, normalizeBillingState } from "./gst.js";

const RAZORPAY_API_BASE = "https://api.razorpay.com/v1";
export const REFUND_WINDOW_MS = 7 * 86400 * 1000;
const REASON_MAX = 1000;
const NOTE_MAX = 500;

function rzpAuth(env) {
  return "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
}

async function rzp(env, method, path, body) {
  const resp = await fetch(RAZORPAY_API_BASE + path, {
    method,
    headers: { "Authorization": rzpAuth(env), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await resp.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 300) }; }
  return { ok: resp.ok, status: resp.status, data };
}

/** Customer identity from their own API key (revenue-engine's key record). */
async function customerFromApiKey(request, env) {
  const key = request.headers.get("X-API-Key") || "";
  if (!key || key.length > 200 || !env.REVENUE_CRM_KV) return null;
  const rec = await env.REVENUE_CRM_KV.get(`apikey:${key}`, "json");
  if (!rec || !rec.email) return null;
  return { email: sanitizeEmail(rec.email), key_status: rec.status || null };
}

function plainText(v, max) {
  if (typeof v !== "string") return "";
  return v.normalize("NFKC").replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

function db(env) {
  if (!env.CRM_DB) throw Object.assign(new Error("billing database unavailable"), { status: 503 });
  return env.CRM_DB;
}

/**
 * Eligibility for the 7-day guarantee, evaluated at request time.
 * @returns {{ ok: true, payment } | { ok: false, code, message }}
 */
export async function refundEligibility(database, email, nowMs) {
  const first = await firstPaymentFor(database, email);
  if (!first) return { ok: false, code: "no_eligible_payment", message: "No subscription payment is on record for this account." };
  if (first.disputed) return { ok: false, code: "payment_disputed", message: "This payment is under dispute with the bank; it is resolved through the dispute process." };
  if (first.refund_status !== "none" || first.refunded_paise > 0) {
    return { ok: false, code: "already_refunded", message: "This payment has already been refunded." };
  }
  const age = nowMs - Date.parse(first.captured_at);
  if (!(age >= 0 && age <= REFUND_WINDOW_MS)) {
    return { ok: false, code: "outside_guarantee_window",
      message: "The 7-day money-back guarantee covers a first purchase for 7 days after payment. No partial or pro-rata refunds apply after that." };
  }
  return { ok: true, payment: first };
}

// POST /api/v2/billing/refunds/request
export async function handleRefundRequest(request, env, ctx, rid) {
  const body = await request.json().catch(() => ({}));
  let email = null;
  let actor = "customer";
  if (await isAdmin(request, env)) {
    email = sanitizeEmail(body.email);
    actor = "admin";
    if (!email) return json({ error: "email is required" }, 400);
  } else {
    const who = await customerFromApiKey(request, env);
    if (!who || !who.email) return json({ error: "unauthorized", message: "Send the X-API-Key of the subscription." }, 401);
    email = who.email;
  }
  const reason = plainText(body.reason, REASON_MAX);
  const database = db(env);
  const elig = await refundEligibility(database, email, Date.now());
  if (!elig.ok) {
    await trackEvent(env, "refund_request_ineligible", { email, code: elig.code, actor, rid });
    return json({ error: elig.code, message: elig.message }, 422);
  }
  const existing = await getRefundRequestByPayment(database, elig.payment.payment_id);
  if (existing) return json({ status: existing.status, request_id: existing.id, duplicate: true }, 200);
  const id = "rfr_" + crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  const created = await insertRefundRequest(database, {
    id, paymentId: elig.payment.payment_id, email, reason, amountPaise: elig.payment.amount_paise, now: new Date().toISOString(),
  });
  if (!created) {
    const raced = await getRefundRequestByPayment(database, elig.payment.payment_id);
    return json({ status: raced ? raced.status : "pending_review", request_id: raced ? raced.id : null, duplicate: true }, 200);
  }
  await trackEvent(env, "refund_requested", { request_id: id, payment_id: elig.payment.payment_id, email, actor, rid });
  ctx?.waitUntil?.(slackNotify(env, `REFUND REQUEST ${id} | ${email} | ${elig.payment.tier} | INR ${(elig.payment.amount_paise / 100).toFixed(2)} | awaiting approval`).catch(() => {}));
  return json({
    status: "pending_review", request_id: id,
    message: "Refund request received. It is reviewed under the 7-day money-back guarantee; you will be notified of the decision.",
  }, 202);
}

// GET /api/v2/billing/refunds
export async function handleRefundList(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const status = new URL(request.url).searchParams.get("status") || null;
  if (status && !/^[a-z_]{3,32}$/.test(status)) return json({ error: "invalid status" }, 400);
  return json({ requests: await listRefundRequests(db(env), status) });
}

// POST /api/v2/billing/refunds/reject
export async function handleRefundReject(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const body = await request.json().catch(() => ({}));
  const id = typeof body.request_id === "string" ? body.request_id : "";
  const note = plainText(body.note, NOTE_MAX);
  if (!id) return json({ error: "request_id is required" }, 400);
  const changed = await transitionRefundRequest(db(env), id, "pending_review", "rejected", { decided_at: new Date().toISOString(), decision_note: note });
  if (!changed) return json({ error: "not_pending", message: "Only a pending request can be rejected." }, 409);
  await trackEvent(env, "refund_rejected", { request_id: id, rid });
  return json({ status: "rejected", request_id: id });
}

/**
 * POST /api/v2/billing/refunds/approve
 *
 * pending_review -> approved (compare-and-set: one approver wins) -> Razorpay
 * refund -> refund_initiated. An `approved` request whose refund call failed
 * can be approved again: Razorpay's payment record is read first and an
 * existing refund is adopted instead of refunding twice.
 */
export async function handleRefundApprove(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) return json({ error: "Razorpay not configured on server" }, 503);
  const body = await request.json().catch(() => ({}));
  const id = typeof body.request_id === "string" ? body.request_id : "";
  if (!id) return json({ error: "request_id is required" }, 400);
  const database = db(env);
  const req = await getRefundRequest(database, id);
  if (!req) return json({ error: "not_found" }, 404);
  if (req.status === "pending_review") {
    const won = await transitionRefundRequest(database, id, "pending_review", "approved", {
      decided_at: new Date().toISOString(), decision_note: plainText(body.note, NOTE_MAX),
    });
    if (!won) return json({ error: "conflict", message: "The request changed state; reload it." }, 409);
  } else if (req.status !== "approved") {
    return json({ error: "not_approvable", status: req.status }, 409);
  }

  const payment = await getPayment(database, req.payment_id);
  const fail = async (code, message, status = 409) => {
    await transitionRefundRequest(database, id, "approved", "approved", { last_error: code });
    await trackEvent(env, "refund_blocked", { request_id: id, payment_id: req.payment_id, code, rid });
    return json({ error: code, message, request_id: id, status: "approved" }, status);
  };
  if (!payment) return fail("ledger_row_missing", "No ledger record for this payment.");
  if (payment.disputed) return fail("payment_disputed", "A dispute is open on this payment; refunding would double-return funds.");
  if (payment.amount_paise !== req.amount_paise) return fail("amount_mismatch", "Ledger amount differs from the request amount.");

  const live = await rzp(env, "GET", `/payments/${encodeURIComponent(payment.payment_id)}`);
  if (!live.ok) return fail("razorpay_payment_lookup_failed", "Could not read the payment from Razorpay; retry.", 502);
  const p = live.data || {};
  if (p.id !== payment.payment_id || p.status === "failed" || p.status === "created" || p.status === "authorized") {
    return fail("payment_not_captured", `Razorpay reports payment status ${p.status}.`);
  }
  if (p.amount !== payment.amount_paise) return fail("amount_mismatch", "Razorpay's captured amount differs from the ledger.");

  let refund = null;
  if ((p.amount_refunded || 0) > 0) {
    // A refund already exists (an earlier attempt whose response was lost, or
    // one made in the Razorpay Dashboard): adopt it, never refund twice.
    const list = await rzp(env, "GET", `/payments/${encodeURIComponent(payment.payment_id)}/refunds`);
    refund = list.ok && list.data && Array.isArray(list.data.items) ? list.data.items[0] || null : null;
    if (!refund) return fail("refund_state_unknown", "Razorpay shows a refunded amount but no refund could be read; check the Dashboard.", 502);
  } else {
    const created = await rzp(env, "POST", `/payments/${encodeURIComponent(payment.payment_id)}/refund`, {
      amount: payment.amount_paise, speed: "normal", receipt: id,
      notes: { refund_request_id: id, policy: "7-day-money-back-first-purchase" },
    });
    if (!created.ok || !created.data || !created.data.id) {
      return fail("razorpay_refund_failed", (created.data && created.data.error && created.data.error.description) || "Refund call failed; retry.", 502);
    }
    refund = created.data;
  }

  await transitionRefundRequest(database, id, "approved", "refund_initiated", { razorpay_refund_id: refund.id, last_error: "" });
  // Stop renewals. Access itself is revoked when Razorpay reports the refund.
  if (payment.provider_sub_id) {
    const cancel = await rzp(env, "POST", `/subscriptions/${encodeURIComponent(payment.provider_sub_id)}/cancel`, { cancel_at_cycle_end: 0 });
    if (!cancel.ok) await trackEvent(env, "refund_subscription_cancel_failed", { request_id: id, subscription_id: payment.provider_sub_id, rid });
  }
  await trackEvent(env, "refund_initiated", { request_id: id, payment_id: payment.payment_id, razorpay_refund_id: refund.id, amount_paise: refund.amount || payment.amount_paise, rid });
  return json({ status: "refund_initiated", request_id: id, razorpay_refund_id: refund.id, amount_paise: refund.amount || payment.amount_paise });
}

/**
 * Webhook side (called from handleBillingWebhook): refund.* and
 * payment.dispute.* for payments on the ledger. Returns true when handled.
 */
export async function applyBillingWebhookEvent(env, event, payload, { revokeEntitlementForSubscription, rid }) {
  const database = env.CRM_DB;
  if (!database) return false;
  if (event.startsWith("refund.")) {
    const r = payload.payload && payload.payload.refund && payload.payload.refund.entity;
    if (!r || !r.payment_id) return true;
    const payment = await getPayment(database, r.payment_id);
    if (!payment) {
      await trackEvent(env, "refund_webhook_payment_not_on_ledger", { payment_id: r.payment_id, refund_id: r.id, event, rid });
      return true;
    }
    if (event === "refund.failed") {
      const req = await getRefundRequestByPayment(database, r.payment_id);
      if (req) await transitionRefundRequest(database, req.id, ["refund_initiated", "approved"], "approved", { last_error: "razorpay_refund_failed" });
      await trackEvent(env, "refund_failed", { payment_id: r.payment_id, refund_id: r.id, rid });
      return true;
    }
    const processed = event === "refund.processed";
    await applyRefundToPayment(database, r.payment_id, {
      refundedPaise: Number.isInteger(r.amount) ? r.amount : payment.amount_paise,
      status: processed ? "refunded" : "refund_pending",
    });
    const req = await getRefundRequestByPayment(database, r.payment_id);
    if (req) {
      await transitionRefundRequest(database, req.id, ["approved", "refund_initiated"], processed ? "refunded" : "refund_initiated",
        { razorpay_refund_id: r.id, last_error: "" });
    }
    // Revoke as soon as Razorpay confirms the refund exists (created or
    // processed), including refunds made directly in the Dashboard.
    if (payment.provider_sub_id) await revokeEntitlementForSubscription(payment.provider_sub_id, "refunded");
    await trackEvent(env, processed ? "refund_processed" : "refund_created", { payment_id: r.payment_id, refund_id: r.id, rid });
    return true;
  }
  if (event.startsWith("payment.dispute.")) {
    const d = payload.payload && payload.payload.dispute && payload.payload.dispute.entity;
    const pid = (d && d.payment_id) || (payload.payload && payload.payload.payment && payload.payload.payment.entity && payload.payload.payment.entity.id);
    if (pid) {
      const changed = await markDisputed(database, pid);
      await trackEvent(env, "payment_disputed", { payment_id: pid, event, on_ledger: !!changed, rid });
    }
    return true;
  }
  return false;
}

// POST /api/v2/billing/subscriptions/cancel
// Contract: "Cancel any time; access runs to the end of the paid period. No
// pro-rata refund." Asks Razorpay to cancel at the end of the current cycle;
// access ends when Razorpay's subscription.cancelled webhook arrives then.
export async function handleSubscriptionCancel(request, env, ctx, rid) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) return json({ error: "Razorpay not configured on server" }, 503);
  const who = await customerFromApiKey(request, env);
  if (!who || !who.email) return json({ error: "unauthorized", message: "Send the X-API-Key of the subscription." }, 401);
  const row = await db(env).prepare(
    `SELECT provider_sub_id FROM billing_payments WHERE email = ? AND provider_sub_id IS NOT NULL
      ORDER BY captured_at DESC LIMIT 1`
  ).bind(who.email).first();
  if (!row || !row.provider_sub_id) {
    return json({ error: "no_subscription", message: "No Razorpay subscription is on record for this key. Contact support." }, 404);
  }
  const res = await rzp(env, "POST", `/subscriptions/${encodeURIComponent(row.provider_sub_id)}/cancel`, { cancel_at_cycle_end: 1 });
  if (!res.ok) {
    await trackEvent(env, "subscription_cancel_request_failed", { email: who.email, subscription_id: row.provider_sub_id, status: res.status, rid });
    return json({ error: "cancel_failed", message: "Cancellation could not be scheduled; retry or contact support." }, 502);
  }
  await trackEvent(env, "subscription_cancel_scheduled", { email: who.email, subscription_id: row.provider_sub_id, rid });
  return json({
    status: "cancel_scheduled", subscription_id: row.provider_sub_id,
    message: "Your subscription will not renew. Access continues to the end of the current paid period. No pro-rata refund applies.",
  });
}

// --- invoices ----------------------------------------------------------------

function paise(n) { return (n / 100).toFixed(2); }
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function renderInvoiceHtml(doc) {
  const t = doc.tax;
  const rows = doc.supply_type === "intra_state"
    ? `<tr><td>CGST @ ${esc(t.cgst_rate_percent)}%</td><td class="n">${paise(t.cgst_paise)}</td></tr>
       <tr><td>SGST @ ${esc(t.sgst_rate_percent)}%</td><td class="n">${paise(t.sgst_paise)}</td></tr>`
    : `<tr><td>IGST @ ${esc(t.igst_rate_percent)}%</td><td class="n">${paise(t.igst_paise)}</td></tr>`;
  const r = doc.recipient;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Tax Invoice ${esc(doc.invoice_number)}</title>
<meta name="robots" content="noindex"><style>
body{font:14px/1.5 system-ui,sans-serif;color:#111;background:#fff;max-width:820px;margin:24px auto;padding:0 16px}
h1{font-size:20px;margin:0 0 4px}table{width:100%;border-collapse:collapse;margin:12px 0}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}
.n{text-align:right;font-variant-numeric:tabular-nums}.muted{color:#555;font-size:12px}</style></head><body>
<h1>Tax Invoice</h1><div class="muted">Original for recipient</div>
<table><tr><th>Invoice No.</th><td>${esc(doc.invoice_number)}</td><th>Invoice date</th><td>${esc(doc.invoice_date)}</td></tr>
<tr><th>Place of supply</th><td>${esc(doc.place_of_supply.state_name)} (${esc(doc.place_of_supply.state_code)})</td><th>Reverse charge</th><td>No</td></tr></table>
<table><tr><th>Supplier</th><th>Recipient</th></tr><tr><td>${esc(doc.supplier.legal_name)}${doc.supplier.trade_name ? "<br>" + esc(doc.supplier.trade_name) : ""}<br>${esc(doc.supplier.address)}<br>GSTIN: ${esc(doc.supplier.gstin)}<br>State: ${esc(doc.supplier.state_name)} (${esc(doc.supplier.state_code)})</td>
<td>${esc(r.name || "")}${r.address ? "<br>" + esc(r.address) : ""}<br>${esc(r.email)}${r.gstin ? "<br>GSTIN: " + esc(r.gstin) : "<br>Unregistered"}</td></tr></table>
<table><tr><th>Description</th><th>SAC</th><th>Qty</th><th class="n">Taxable value (INR)</th></tr>
${doc.line_items.map((li) => `<tr><td>${esc(li.description)}</td><td>${esc(li.sac)}</td><td>${esc(li.quantity)}</td><td class="n">${paise(li.taxable_value_paise)}</td></tr>`).join("")}</table>
<table><tr><td>Taxable value</td><td class="n">${paise(t.taxable_paise)}</td></tr>${rows}
<tr><th>Total (INR, inclusive of GST)</th><th class="n">${paise(t.total_paise)}</th></tr></table>
<p class="muted">Payment ${esc(doc.payment.payment_id)} via Razorpay${doc.payment.subscription_id ? ", subscription " + esc(doc.payment.subscription_id) : ""}. ${esc(doc.amount_basis)}</p>
<p class="muted">This is a computer-generated invoice.</p></body></html>`;
}

async function invoiceViewer(request, env) {
  if (await isAdmin(request, env)) return { admin: true, email: null };
  const who = await customerFromApiKey(request, env);
  return who ? { admin: false, email: who.email } : null;
}

// GET /api/v2/billing/invoices
export async function handleInvoiceList(request, env) {
  const viewer = await invoiceViewer(request, env);
  if (!viewer) return json({ error: "unauthorized" }, 401);
  const email = viewer.admin ? sanitizeEmail(new URL(request.url).searchParams.get("email")) : viewer.email;
  if (!email) return json({ error: "email is required" }, 400);
  return json({ invoices: await listInvoicesFor(db(env), email) });
}

// GET /api/v2/billing/invoices/view?number=
export async function handleInvoiceView(request, env) {
  const viewer = await invoiceViewer(request, env);
  if (!viewer) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const number = url.searchParams.get("number") || "";
  if (!/^[A-Z0-9-]{1,6}\/\d{2}-\d{2}\/\d{6}$/.test(number)) return json({ error: "invalid invoice number" }, 400);
  const inv = await getInvoiceByNumber(db(env), number);
  // Same answer for "not yours" and "does not exist": no enumeration.
  if (!inv || (!viewer.admin && inv.email !== viewer.email)) return json({ error: "not_found" }, 404);
  if (url.searchParams.get("format") === "html") {
    return new Response(renderInvoiceHtml(inv.document), {
      headers: {
        "content-type": "text/html; charset=utf-8", "cache-control": "private, no-store",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
      },
    });
  }
  return json({ invoice: inv.document, status: inv.status });
}

// GET /api/v2/billing/invoices/holds
export async function handleInvoiceHolds(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  return json({ holds: await listInvoiceHolds(db(env)) });
}

// POST /api/v2/billing/invoices/issue
export async function handleInvoiceIssue(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const body = await request.json().catch(() => ({}));
  const pid = typeof body.payment_id === "string" ? body.payment_id : "";
  if (!pid) return json({ error: "payment_id is required" }, 400);
  const name = normalizeBillingName(body.billing_name);
  const state = normalizeBillingState(body.billing_state);
  const address = body.billing_address === undefined ? "" : plainText(body.billing_address, 300);
  if (!name.ok) return json({ error: name.reason }, 400);
  if (!state.ok) return json({ error: state.reason }, 400);
  if (body.billing_address !== undefined && address.length < 10) return json({ error: "billing_address must be 10-300 characters" }, 400);
  const database = db(env);
  if (!(await getPayment(database, pid))) return json({ error: "not_found" }, 404);
  if (name.value || address || state.value) {
    await completeRecipientDetails(database, pid, { billing_name: name.value, billing_address: address, billing_state: state.value });
  }
  const result = await issueInvoiceForPayment(database, env, pid);
  await trackEvent(env, result.status === "issued" ? "invoice_issued" : "invoice_held", { payment_id: pid, reason: result.reason || null, rid });
  return json(result.status === "issued"
    ? { status: "issued", invoice_number: result.invoice.invoice_number }
    : { status: "held", reason: result.reason }, result.status === "issued" ? 200 : 409);
}
