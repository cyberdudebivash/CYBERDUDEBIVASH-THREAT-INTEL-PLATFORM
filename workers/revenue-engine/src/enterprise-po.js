// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: enterprise PO workflow
//
// Owner commercial policy (2026-09-24): public manual payment proof is
// retired; an enterprise that pays by bank transfer does so only against an
// approved quote and its purchase order:
//
//   quote (sales, admin) -> PO (customer accepts with a PO number)
//     -> tax invoice (finance approves; the shared GST engine)
//     -> bank transfer -> reconciliation (finance: UTR, TDS, FIRC for exports)
//     -> entitlement (provisionCustomer, exactly once)
//
// Every step is a compare-and-set on enterprise_quotes.status, so a double
// click, a retry or two operators can never double-invoice, double-reconcile
// or double-provision. Prices come from the canonical commercial contract
// (drift-tested against config/commercial-contract.json); a different price
// needs a recorded reason. One bank transfer (UTR) settles one invoice only
// (UNIQUE bank_reference).
//
// Routes (index.js, before the admin gate; each authenticates itself):
//   POST /api/v2/billing/quotes              admin   create a quote
//   GET  /api/v2/billing/quotes              admin   list [?status=]
//   GET  /api/v2/billing/quotes/view         ?id=&token= customer (or admin)  [&format=html]
//   POST /api/v2/billing/quotes/accept       customer {id, token, po_number, po_date}
//   POST /api/v2/billing/quotes/cancel       admin   {id, note}
//   POST /api/v2/billing/quotes/invoice      admin   {id}: issue the tax invoice
//   POST /api/v2/billing/quotes/reconcile    admin   {id, amount_received_paise, tds_paise?, tds_section?,
//                                                     bank_reference, received_on, firc_reference?}
//   POST /api/v2/billing/quotes/provision    admin   {id}: retry provisioning after a failure
// =============================================================================

import { json, sanitizeEmail, trackEvent, isAdmin, provisionCustomer, timingSafeEqual } from "./index.js";
import { ensureBillingSchema, issueInvoiceCore, getInvoiceByPayment } from "./billing-ledger.js";
import {
  normalizeBuyerTaxId, normalizeBillingState, normalizeBillingName, normalizeBillingCountry,
} from "./gst.js";

/**
 * Canonical annual INR prices (GST-inclusive totals, as Razorpay charges them)
 * for the tiers sold by PO. Must equal config/commercial-contract.json
 * tiers.*.inr_annual; billing-export-po.test.js fails on drift.
 */
export const PO_ANNUAL_PRICE_INR = Object.freeze({ ENTERPRISE: 416000, MSSP: 833000 });
export const PO_TERM_MONTHS = 12; // provisionCustomer grants 365 days for "annual"
const QUOTE_VALID_DAYS_DEFAULT = 30;
const QUOTE_VALID_DAYS_MAX = 90;
const MAX_TDS_PERCENT = 20;

function db(env) {
  if (!env.CRM_DB) throw Object.assign(new Error("billing database unavailable"), { status: 503 });
  return env.CRM_DB;
}

function plainText(v, max) {
  if (typeof v !== "string") return "";
  return v.normalize("NFKC").replace(/[\u0000-\u001f\u007f<>{}]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

const isoDate = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v + "T00:00:00Z"));

/** HMAC-SHA256(REVENUE_ADMIN_SECRET, "quote:"+id): the customer's capability for one quote. */
export async function quoteToken(env, id) {
  if (!env || !env.REVENUE_ADMIN_SECRET) return null;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.REVENUE_ADMIN_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("quote:" + id));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function tokenValid(env, id, token) {
  if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) return false;
  const expected = await quoteToken(env, id);
  return !!expected && timingSafeEqual(token, expected);
}

export async function getQuote(database, id) {
  await ensureBillingSchema(database);
  return await database.prepare(`SELECT * FROM enterprise_quotes WHERE id = ?`).bind(id).first();
}

const QUOTE_PATCH_KEYS = new Set([
  "po_number", "po_date", "accepted_at", "invoice_number", "invoice_hold_reason", "bank_reference", "received_paise",
  "tds_paise", "tds_section", "received_on", "firc_reference", "reconciled_at", "api_key_hint", "provisioned_at", "cancel_note",
]);

/** Compare-and-set on status; returns rows changed (0 = someone else moved it, or wrong state). */
async function transitionQuote(database, id, from, to, patch = {}) {
  const fromList = Array.isArray(from) ? from : [from];
  const sets = ["status = ?", "updated_at = ?"];
  const vals = [to, new Date().toISOString()];
  for (const [k, v] of Object.entries(patch)) {
    if (!QUOTE_PATCH_KEYS.has(k)) throw new Error("bad quote patch key " + k);
    sets.push(`${k} = ?`);
    vals.push(v);
  }
  const r = await database.prepare(
    `UPDATE enterprise_quotes SET ${sets.join(", ")} WHERE id = ? AND status IN (${fromList.map(() => "?").join(",")})`
  ).bind(...vals, id, ...fromList).run();
  return (r.meta && r.meta.changes) || 0;
}

const isExport = (q) => q.billing_state === "OUTSIDE_INDIA";

/** The quote as the customer sees it (no internal reconciliation fields). */
function publicQuote(q) {
  return {
    id: q.id, status: q.status, company_name: q.company_name, email: q.email, billing_address: q.billing_address,
    billing_state: q.billing_state, billing_country: q.billing_country || null, buyer_gstin: q.buyer_gstin || null,
    plan: `SENTINEL APEX ${q.tier}`, tier: q.tier, term_months: q.term_months, amount_paise: q.amount_paise, currency: "INR",
    amount_basis: isExport(q)
      ? "Total payable in INR. A supply to a recipient outside India is invoiced as a zero-rated export under LUT."
      : "Total payable in INR, inclusive of GST.",
    valid_until: q.valid_until, po_number: q.po_number || null, po_date: q.po_date || null, invoice_number: q.invoice_number || null,
  };
}

// POST /api/v2/billing/quotes  (admin)
export async function handleQuoteCreate(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const b = await request.json().catch(() => ({}));
  const email = sanitizeEmail(b.email);
  if (!email) return json({ error: "valid email is required", field: "email" }, 400);
  const company = normalizeBillingName(b.company_name);
  if (!company.ok || !company.value) return json({ error: company.reason || "company_name is required", field: "company_name" }, 400);
  const address = plainText(b.billing_address, 300);
  if (address.length < 10) return json({ error: "billing_address must be 10-300 characters", field: "billing_address" }, 400);
  const tier = String(b.tier || "").toUpperCase();
  if (!PO_ANNUAL_PRICE_INR[tier]) return json({ error: "tier must be ENTERPRISE or MSSP", field: "tier" }, 400);
  const term = b.term_months === undefined ? PO_TERM_MONTHS : Number(b.term_months);
  if (term !== PO_TERM_MONTHS) return json({ error: `term_months must be ${PO_TERM_MONTHS}`, field: "term_months" }, 400);

  const taxId = normalizeBuyerTaxId(b.gstin);
  if (!taxId.ok) return json({ error: taxId.reason, field: "gstin" }, 400);
  const state = normalizeBillingState(b.billing_state);
  if (!state.ok) return json({ error: state.reason, field: "billing_state" }, 400);
  const country = normalizeBillingCountry(b.billing_country);
  if (!country.ok) return json({ error: country.reason, field: "billing_country" }, 400);
  let billingState = taxId.kind === "gstin" ? taxId.value.slice(0, 2) : state.value;
  if (!billingState) return json({ error: "billing_state (or a GSTIN) is required: it sets the place of supply", field: "billing_state" }, 400);
  if (billingState === "OUTSIDE_INDIA" && !country.value) return json({ error: "billing_country is required outside India", field: "billing_country" }, 400);
  if (billingState !== "OUTSIDE_INDIA" && country.value) return json({ error: "billing_country applies only outside India", field: "billing_country" }, 400);

  // Price: the canonical contract, unless sales records why not.
  let amountPaise = PO_ANNUAL_PRICE_INR[tier] * 100;
  let basis = "canonical_contract";
  const reason = plainText(b.price_reason, 300);
  if (b.custom_amount_inr !== undefined) {
    const custom = Number(b.custom_amount_inr);
    if (!Number.isFinite(custom) || custom <= 0 || Math.round(custom * 100) !== custom * 100) {
      return json({ error: "custom_amount_inr must be a positive amount with at most 2 decimals", field: "custom_amount_inr" }, 400);
    }
    if (reason.length < 10) return json({ error: "price_reason (10+ characters) is required for a custom price", field: "price_reason" }, 400);
    amountPaise = Math.round(custom * 100);
    basis = "custom";
  }
  const validDays = b.valid_days === undefined ? QUOTE_VALID_DAYS_DEFAULT : Number(b.valid_days);
  if (!Number.isInteger(validDays) || validDays < 1 || validDays > QUOTE_VALID_DAYS_MAX) {
    return json({ error: `valid_days must be 1-${QUOTE_VALID_DAYS_MAX}`, field: "valid_days" }, 400);
  }

  const database = db(env);
  await ensureBillingSchema(database);
  const id = "qt_" + crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  const now = new Date();
  const validUntil = new Date(now.getTime() + validDays * 86400000).toISOString();
  await database.prepare(
    `INSERT INTO enterprise_quotes (id, email, company_name, billing_address, billing_state, billing_country, buyer_gstin,
       tier, term_months, amount_paise, price_basis, price_reason, valid_until, status, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, email, company.value, address, billingState, country.value, taxId.kind === "gstin" ? taxId.value : "",
    tier, term, amountPaise, basis, reason, validUntil, "sent", now.toISOString(), now.toISOString()).run();
  await trackEvent(env, "quote_created", { quote_id: id, email, tier, amount_paise: amountPaise, price_basis: basis, rid });
  const token = await quoteToken(env, id);
  return json({
    status: "sent", quote: publicQuote(await getQuote(database, id)),
    // Send this link to the customer; it is their capability for this quote only.
    acceptance: { id, token, view_url: `/api/v2/billing/quotes/view?id=${id}&token=${token}&format=html` },
  }, 201);
}

// GET /api/v2/billing/quotes  (admin)
export async function handleQuoteList(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const status = new URL(request.url).searchParams.get("status");
  if (status && !/^[a-z_]{3,20}$/.test(status)) return json({ error: "invalid status" }, 400);
  const database = db(env);
  await ensureBillingSchema(database);
  const q = status
    ? database.prepare(`SELECT * FROM enterprise_quotes WHERE status = ? ORDER BY created_at DESC LIMIT 200`).bind(status)
    : database.prepare(`SELECT * FROM enterprise_quotes ORDER BY created_at DESC LIMIT 200`);
  return json({ quotes: (await q.all()).results || [] });
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function renderQuoteHtml(q) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Quotation ${esc(q.id)}</title>
<meta name="robots" content="noindex"><style>
body{font:14px/1.5 system-ui,sans-serif;color:#111;background:#fff;max-width:820px;margin:24px auto;padding:0 16px}
h1{font-size:20px;margin:0 0 4px}table{width:100%;border-collapse:collapse;margin:12px 0}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}
.muted{color:#555;font-size:12px}</style></head><body>
<h1>Quotation</h1><div class="muted">${esc(q.id)} &middot; status ${esc(q.status)} &middot; valid until ${esc(String(q.valid_until).slice(0, 10))}</div>
<table><tr><th>Customer</th><td>${esc(q.company_name)}<br>${esc(q.billing_address)}${q.billing_country ? "<br>Country: " + esc(q.billing_country) : ""}${q.buyer_gstin ? "<br>GSTIN: " + esc(q.buyer_gstin) : ""}<br>${esc(q.email)}</td></tr>
<tr><th>Plan</th><td>${esc(q.plan)}, ${esc(q.term_months)} months</td></tr>
<tr><th>Total (INR)</th><td>${(q.amount_paise / 100).toFixed(2)}</td></tr>
<tr><th>Basis</th><td>${esc(q.amount_basis)}</td></tr>
${q.po_number ? `<tr><th>Purchase order</th><td>${esc(q.po_number)} dated ${esc(q.po_date)}</td></tr>` : ""}
${q.invoice_number ? `<tr><th>Tax invoice</th><td>${esc(q.invoice_number)}</td></tr>` : ""}</table>
<p class="muted">To accept, send your purchase order number and date through the acceptance link you received. Payment is by bank transfer against our tax invoice; access is provisioned when the transfer is reconciled.</p>
</body></html>`;
}

// GET /api/v2/billing/quotes/view?id=&token=[&format=html]
export async function handleQuoteView(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id") || "";
  const admin = await isAdmin(request, env);
  // Same answer for a bad token and a missing quote: no enumeration.
  if (!/^qt_[0-9a-f]{20}$/.test(id) || (!admin && !(await tokenValid(env, id, url.searchParams.get("token"))))) {
    return json({ error: "not_found" }, 404);
  }
  const q = await getQuote(db(env), id);
  if (!q) return json({ error: "not_found" }, 404);
  const pub = publicQuote(q);
  if (url.searchParams.get("format") === "html") {
    return new Response(renderQuoteHtml(pub), {
      headers: {
        "content-type": "text/html; charset=utf-8", "cache-control": "private, no-store",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
      },
    });
  }
  return json({ quote: pub });
}

// POST /api/v2/billing/quotes/accept  (customer, with the quote token)
export async function handleQuoteAccept(request, env, ctx, rid) {
  const b = await request.json().catch(() => ({}));
  const id = typeof b.id === "string" ? b.id : "";
  if (!/^qt_[0-9a-f]{20}$/.test(id) || !(await tokenValid(env, id, b.token))) return json({ error: "not_found" }, 404);
  const po = plainText(b.po_number, 64);
  if (po.length < 1) return json({ error: "po_number is required", field: "po_number" }, 400);
  if (!isoDate(b.po_date)) return json({ error: "po_date must be YYYY-MM-DD", field: "po_date" }, 400);
  const database = db(env);
  const q = await getQuote(database, id);
  if (!q) return json({ error: "not_found" }, 404);
  if (q.status === "sent" && Date.parse(q.valid_until) < Date.now()) {
    await transitionQuote(database, id, "sent", "expired");
    return json({ error: "quote_expired", message: "This quotation has expired; ask us for a new one." }, 410);
  }
  const won = await transitionQuote(database, id, "sent", "accepted", { po_number: po, po_date: b.po_date, accepted_at: new Date().toISOString() });
  if (!won) {
    const cur = await getQuote(database, id);
    if (cur && cur.status !== "sent" && cur.po_number === po) return json({ status: cur.status, duplicate: true, quote: publicQuote(cur) });
    return json({ error: "not_acceptable", status: cur ? cur.status : null }, 409);
  }
  await trackEvent(env, "quote_accepted", { quote_id: id, po_number: po, rid });
  return json({ status: "accepted", quote: publicQuote(await getQuote(database, id)),
    message: "Purchase order received. Our tax invoice follows; access is provisioned when the bank transfer is reconciled." });
}

// POST /api/v2/billing/quotes/cancel  (admin; not after the invoice exists)
export async function handleQuoteCancel(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const b = await request.json().catch(() => ({}));
  const id = typeof b.id === "string" ? b.id : "";
  const changed = await transitionQuote(db(env), id, ["sent", "accepted"], "cancelled", { cancel_note: plainText(b.note, 300) });
  if (!changed) return json({ error: "not_cancellable", message: "Only a quote without a tax invoice can be cancelled." }, 409);
  await trackEvent(env, "quote_cancelled", { quote_id: id, rid });
  return json({ status: "cancelled", id });
}

/** The quote as an invoice subject for the shared GST engine (key "po:<id>"). */
function invoiceSubject(q) {
  return {
    email: q.email, tier: q.tier, billing_cycle: "annual", amount_paise: q.amount_paise, currency: "INR",
    captured_at: new Date().toISOString(), // invoice date = date of issue
    buyer_gstin: q.buyer_gstin, billing_state: q.billing_state, billing_country: q.billing_country,
    billing_name: q.company_name, billing_address: q.billing_address,
    payment_international: 0, export_basis: isExport(q) ? "bank_realisation_pending" : "", export_reference: "",
    description: `SENTINEL APEX ${q.tier} subscription, ${q.term_months} months (PO ${q.po_number} dated ${q.po_date})`,
    payment_block: { provider: "bank_transfer", purchase_order: q.po_number, purchase_order_date: q.po_date, quote_id: q.id, terms: "Payable by bank transfer against this invoice." },
  };
}

// POST /api/v2/billing/quotes/invoice  (admin: finance approves the PO)
export async function handleQuoteInvoice(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const b = await request.json().catch(() => ({}));
  const id = typeof b.id === "string" ? b.id : "";
  const database = db(env);
  const q = await getQuote(database, id);
  if (!q) return json({ error: "not_found" }, 404);
  if (q.status !== "accepted") {
    if (q.invoice_number) return json({ status: q.status, invoice_number: q.invoice_number, duplicate: true });
    return json({ error: "not_invoiceable", status: q.status, message: "Only an accepted quote (with a PO) can be invoiced." }, 409);
  }
  const key = "po:" + id;
  const result = await issueInvoiceCore(database, env, {
    key, row: invoiceSubject(q),
    onHold: (reason) => database.prepare(`UPDATE enterprise_quotes SET invoice_hold_reason = ?, updated_at = ? WHERE id = ? AND status = 'accepted'`)
      .bind(reason, new Date().toISOString(), id).run(),
    // Inside the issuing transaction: the quote moves to invoiced with the
    // invoice's number, or (if the invoice was not written) not at all.
    issuedStmt: database.prepare(
      `UPDATE enterprise_quotes SET status = 'invoiced', invoice_hold_reason = '', updated_at = ?,
         invoice_number = (SELECT invoice_number FROM invoices WHERE payment_id = ?)
       WHERE id = ? AND status = 'accepted' AND EXISTS (SELECT 1 FROM invoices WHERE payment_id = ?)`
    ).bind(new Date().toISOString(), key, id, key),
  });
  await trackEvent(env, result.status === "issued" ? "po_invoice_issued" : "po_invoice_held", { quote_id: id, reason: result.reason || null, rid });
  if (result.status !== "issued") return json({ status: "held", reason: result.reason }, 409);
  return json({ status: "invoiced", invoice_number: result.invoice.invoice_number, total_paise: result.invoice.document.tax.total_paise });
}

// POST /api/v2/billing/quotes/reconcile  (admin: finance matched the bank transfer)
export async function handleQuoteReconcile(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const b = await request.json().catch(() => ({}));
  const id = typeof b.id === "string" ? b.id : "";
  const database = db(env);
  const q = await getQuote(database, id);
  if (!q) return json({ error: "not_found" }, 404);
  if (q.status !== "invoiced") {
    if (["paid", "provisioning", "provisioned"].includes(q.status)) return json({ status: q.status, duplicate: true });
    return json({ error: "not_reconcilable", status: q.status }, 409);
  }
  const invoice = await getInvoiceByPayment(database, "po:" + id);
  if (!invoice) return json({ error: "invoice_missing" }, 409);
  const total = invoice.document.tax.total_paise;

  const received = b.amount_received_paise;
  const tds = b.tds_paise === undefined ? 0 : b.tds_paise;
  if (!Number.isInteger(received) || received <= 0) return json({ error: "amount_received_paise must be a positive integer", field: "amount_received_paise" }, 400);
  if (!Number.isInteger(tds) || tds < 0) return json({ error: "tds_paise must be a non-negative integer", field: "tds_paise" }, 400);
  const tdsSection = plainText(b.tds_section, 16).toUpperCase();
  if (tds > 0) {
    if (isExport(q)) return json({ error: "TDS does not apply to a recipient outside India", field: "tds_paise" }, 400);
    if (!/^19[0-9][A-Z]{0,3}$/.test(tdsSection)) return json({ error: "tds_section (e.g. 194J) is required with TDS", field: "tds_section" }, 400);
    if (tds * 100 > total * MAX_TDS_PERCENT) return json({ error: `TDS above ${MAX_TDS_PERCENT}% of the invoice needs manual review`, field: "tds_paise" }, 400);
  }
  if (received + tds !== total) {
    return json({ error: "amount_mismatch", invoice_total_paise: total, received_plus_tds_paise: received + tds,
      message: "Received amount plus TDS must equal the invoice total exactly." }, 409);
  }
  const bankRef = plainText(b.bank_reference, 40).toUpperCase();
  if (!/^[A-Z0-9][A-Z0-9/-]{3,39}$/.test(bankRef)) return json({ error: "bank_reference (UTR / transfer reference) is required", field: "bank_reference" }, 400);
  if (!isoDate(b.received_on) || Date.parse(b.received_on + "T00:00:00Z") > Date.now()) {
    return json({ error: "received_on must be a past or current date YYYY-MM-DD", field: "received_on" }, 400);
  }
  const firc = plainText(b.firc_reference, 60);
  if (isExport(q) && firc.length < 4) {
    return json({ error: "firc_reference (FIRC / e-BRC) is required for an export", field: "firc_reference" }, 400);
  }
  let won = 0;
  try {
    won = await transitionQuote(database, id, "invoiced", "paid", {
      bank_reference: bankRef, received_paise: received, tds_paise: tds, tds_section: tdsSection,
      received_on: b.received_on, firc_reference: firc, reconciled_at: new Date().toISOString(),
    });
  } catch (err) {
    if (/unique/i.test(String(err && err.message))) {
      return json({ error: "bank_reference_already_used", message: "This bank transfer already settled another invoice." }, 409);
    }
    throw err;
  }
  if (!won) return json({ error: "conflict", message: "The quote changed state; reload it." }, 409);
  await trackEvent(env, "po_payment_reconciled", { quote_id: id, bank_reference: bankRef, received_paise: received, tds_paise: tds, rid });
  return await provisionQuote(env, database, id, rid);
}

// POST /api/v2/billing/quotes/provision  (admin: retry after a provisioning failure)
export async function handleQuoteProvision(request, env, ctx, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  const b = await request.json().catch(() => ({}));
  const id = typeof b.id === "string" ? b.id : "";
  const database = db(env);
  if (!(await getQuote(database, id))) return json({ error: "not_found" }, 404);
  return await provisionQuote(env, database, id, rid);
}

/** paid -> provisioning (one winner) -> provisioned; a failure returns it to paid for a retry. */
async function provisionQuote(env, database, id, rid) {
  const won = await transitionQuote(database, id, "paid", "provisioning");
  const q = await getQuote(database, id);
  if (!won) {
    if (q && q.status === "provisioned") return json({ status: "provisioned", duplicate: true, api_key_hint: q.api_key_hint });
    return json({ error: "not_provisionable", status: q ? q.status : null }, 409);
  }
  let result;
  try {
    result = await provisionCustomer(env, {
      email: q.email, tier: q.tier, billing_cycle: "annual", payment_id: "po:" + id, payment_method: "bank_transfer",
      amount_paid: (q.received_paise + q.tds_paise) / 100, currency: "INR", trial: false,
    });
  } catch (err) {
    await transitionQuote(database, id, "provisioning", "paid");
    await trackEvent(env, "po_provisioning_failed", { quote_id: id, error: err?.message || String(err), rid }).catch(() => {});
    return json({ error: "provisioning_failed", message: "Payment is reconciled; provisioning failed. Retry with /quotes/provision." }, 502);
  }
  await transitionQuote(database, id, "provisioning", "provisioned", {
    provisioned_at: new Date().toISOString(), api_key_hint: String(result.api_key || "").slice(0, 12),
  });
  await trackEvent(env, "po_entitlement_provisioned", { quote_id: id, email: q.email, tier: q.tier, rid });
  // The key itself goes to the customer by provisionCustomer's welcome email, never in this response.
  return json({ status: "provisioned", id, tier: q.tier, api_key_hint: String(result.api_key || "").slice(0, 12), period_end: result.period_end });
}
