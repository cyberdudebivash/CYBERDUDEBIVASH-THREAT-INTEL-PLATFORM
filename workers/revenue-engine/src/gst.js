// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: GST rules (pure)
//
// Pure functions only (no I/O): buyer tax id validation, GST state codes,
// Indian financial year, place of supply, CGST/SGST vs IGST, invoice number
// format, and the invoice-activation config check. Used by the subscription
// checkout (buyer details) and by invoice-engine.js.
//
// Owner commercial policy (2026-09-24):
//   - Supplier details (legal name, GST-registered address, GSTIN) and SAC
//     come ONLY from the GST_INVOICE_CONFIG binding. Nothing legal is
//     hard-coded or inferred here; without a complete config no invoice is
//     issued (payments are still recorded, invoices are issued later).
//   - CGST+SGST when the supplier's state equals the place of supply,
//     otherwise IGST. The supplier state is the GSTIN's own state code.
//   - Place of supply for these B2B/B2C services: the recipient's GSTIN
//     state; else the recipient's declared billing state; else (no address
//     on record) the supplier's location (IGST Act s.12(2)). A recipient
//     outside India is never auto-invoiced: export treatment needs review.
// =============================================================================

// Buyer tax id rules are a direct copy of workers/intel-gateway/src/tax-id.js
// (same reason as verifyRazorpayHmac in subscription-engine.js: the two
// Workers deploy independently and share no module). Keep them identical.
const GSTIN_RE = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;
const VAT_RE = /^[A-Z0-9][A-Z0-9 .\/-]{2,18}[A-Z0-9]$/;
const CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export function gstinCheckChar(first14) {
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const v = CHARSET.indexOf(first14[i]) * (i % 2 ? 2 : 1);
    sum += Math.floor(v / 36) + (v % 36);
  }
  return CHARSET[(36 - (sum % 36)) % 36];
}

export function isValidGstin(v) {
  return typeof v === "string" && GSTIN_RE.test(v) && gstinCheckChar(v) === v[14] && !!GST_STATES[v.slice(0, 2)];
}

/** { ok, value, kind: "gstin" | "vat" | null, reason? } */
export function normalizeBuyerTaxId(raw) {
  if (raw === undefined || raw === null) return { ok: true, value: "", kind: null };
  if (typeof raw !== "string") return { ok: false, value: "", kind: null, reason: "Tax id must be text." };
  const v = raw.trim().toUpperCase();
  if (!v) return { ok: true, value: "", kind: null };
  if (v.length === 15) {
    if (!isValidGstin(v)) {
      return { ok: false, value: v, kind: null,
        reason: "Doesn't look like a valid 15-character GSTIN. Double-check it, or leave this blank." };
    }
    return { ok: true, value: v, kind: "gstin" };
  }
  if (!VAT_RE.test(v)) {
    return { ok: false, value: v, kind: null,
      reason: "Tax id must be 4-20 letters or digits (spaces, '-', '.', '/' allowed), or left blank." };
  }
  return { ok: true, value: v, kind: "vat" };
}

/** GST state / UT codes currently in use (25 and 28 are retired). 97 = Other Territory. */
export const GST_STATES = Object.freeze({
  "01": "Jammu and Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh",
  "05": "Uttarakhand", "06": "Haryana", "07": "Delhi", "08": "Rajasthan", "09": "Uttar Pradesh",
  "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh", "13": "Nagaland", "14": "Manipur",
  "15": "Mizoram", "16": "Tripura", "17": "Meghalaya", "18": "Assam", "19": "West Bengal",
  "20": "Jharkhand", "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat",
  "26": "Dadra and Nagar Haveli and Daman and Diu", "27": "Maharashtra", "29": "Karnataka", "30": "Goa",
  "31": "Lakshadweep", "32": "Kerala", "33": "Tamil Nadu", "34": "Puducherry",
  "35": "Andaman and Nicobar Islands", "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh",
  "97": "Other Territory",
});

/** Buyer billing location from checkout: a GST state code, "OUTSIDE_INDIA", or "" (not given). */
export function normalizeBillingState(raw) {
  if (raw === undefined || raw === null || raw === "") return { ok: true, value: "" };
  if (typeof raw !== "string") return { ok: false, value: "", reason: "Billing state must be text." };
  const v = raw.trim().toUpperCase();
  if (v === "OUTSIDE_INDIA" || GST_STATES[v]) return { ok: true, value: v };
  return { ok: false, value: "", reason: "Unknown billing state." };
}

/** Optional buyer/company name for the invoice: plain text, 2-120 chars, no markup. */
export function normalizeBillingName(raw) {
  if (raw === undefined || raw === null) return { ok: true, value: "" };
  if (typeof raw !== "string") return { ok: false, value: "", reason: "Billing name must be text." };
  const v = raw.normalize("NFKC").replace(/\s+/g, " ").trim();
  if (!v) return { ok: true, value: "" };
  if (v.length < 2 || v.length > 120 || /[<>{}\u0000-\u001f\u007f]/.test(v)) {
    return { ok: false, value: "", reason: "Billing name must be 2-120 characters of plain text." };
  }
  return { ok: true, value: v };
}

const IST_OFFSET_MS = 330 * 60 * 1000;

/** Indian financial year label ("26-27") for an instant, evaluated in IST (April-March). */
export function financialYear(isoOrMs) {
  const t = typeof isoOrMs === "number" ? isoOrMs : Date.parse(isoOrMs);
  if (!Number.isFinite(t)) throw new Error("financialYear: invalid date");
  const ist = new Date(t + IST_OFFSET_MS);
  const y = ist.getUTCFullYear();
  const start = ist.getUTCMonth() >= 3 ? y : y - 1;
  const yy = (n) => String(n % 100).padStart(2, "0");
  return `${yy(start)}-${yy(start + 1)}`;
}

/** IST calendar date (YYYY-MM-DD) of an instant: the invoice date. */
export function istDate(isoOrMs) {
  const t = typeof isoOrMs === "number" ? isoOrMs : Date.parse(isoOrMs);
  return new Date(t + IST_OFFSET_MS).toISOString().slice(0, 10);
}

/**
 * Place of supply for a service to this buyer.
 * @returns {{ code: string|null, basis: string, export: boolean }}
 */
export function placeOfSupply({ buyerGstin, billingState, supplierStateCode }) {
  if (buyerGstin && isValidGstin(buyerGstin)) {
    return { code: buyerGstin.slice(0, 2), basis: "recipient_gstin", export: false };
  }
  if (billingState === "OUTSIDE_INDIA") return { code: null, basis: "recipient_outside_india", export: true };
  if (billingState && GST_STATES[billingState]) return { code: billingState, basis: "recipient_billing_state", export: false };
  return { code: supplierStateCode, basis: "supplier_location_no_recipient_address", export: false };
}

/**
 * Tax split of an amount actually charged. Razorpay charges the plan amount
 * as the total, so the charged amount is always tax-inclusive: taxable value
 * = total / (1 + rate). All values in paise (integers); rounding stays exact.
 */
export function splitInclusiveTax(totalPaise, ratePercent, intraState) {
  if (!Number.isInteger(totalPaise) || totalPaise <= 0) throw new Error("splitInclusiveTax: total must be a positive integer (paise)");
  if (!(ratePercent > 0 && ratePercent < 100)) throw new Error("splitInclusiveTax: invalid rate");
  const taxable = Math.round((totalPaise * 100) / (100 + ratePercent));
  const tax = totalPaise - taxable;
  if (intraState) {
    const cgst = Math.floor(tax / 2);
    return { taxable_paise: taxable, cgst_paise: cgst, sgst_paise: tax - cgst, igst_paise: 0, tax_paise: tax, total_paise: totalPaise };
  }
  return { taxable_paise: taxable, cgst_paise: 0, sgst_paise: 0, igst_paise: tax, tax_paise: tax, total_paise: totalPaise };
}

// CGST Rules r.46(b): a consecutive serial number of at most 16 characters.
export const INVOICE_NUMBER_MAX_LENGTH = 16;

export function formatInvoiceNumber(prefix, fy, seq) {
  const n = `${prefix}/${fy}/${String(seq).padStart(6, "0")}`;
  if (n.length > INVOICE_NUMBER_MAX_LENGTH) throw new Error(`invoice number ${n} exceeds ${INVOICE_NUMBER_MAX_LENGTH} characters`);
  return n;
}

const SAC_RE = /^99\d{4}$/;
const PREFIX_RE = /^[A-Z0-9-]{1,6}$/;

/**
 * Parses and validates GST_INVOICE_CONFIG (a JSON binding). Every legal field
 * must be supplied by the operator; nothing defaults.
 *
 * {
 *   "supplier_legal_name": "...", "supplier_trade_name": "...",
 *   "supplier_gstin": "...", "supplier_address": "... as on the GST registration ...",
 *   "sac": { "subscription": "99xxxx" }, "gst_rate_percent": 18,
 *   "invoice_prefix": "CDB", "credit_note_prefix": "CN" (optional, default "CN"),
 *   "confirmed_by": "CA name / firm", "confirmed_on": "YYYY-MM-DD"
 * }
 * @returns {{ ok: true, config } | { ok: false, missing: string[] }}
 */
export function parseGstInvoiceConfig(raw) {
  let c = raw;
  if (typeof raw === "string") {
    try { c = JSON.parse(raw); } catch { return { ok: false, missing: ["GST_INVOICE_CONFIG (invalid JSON)"] }; }
  }
  if (!c || typeof c !== "object") return { ok: false, missing: ["GST_INVOICE_CONFIG"] };
  const missing = [];
  const str = (k, min = 2) => (typeof c[k] === "string" && c[k].trim().length >= min ? c[k].trim() : (missing.push(k), null));
  const legal = str("supplier_legal_name");
  const trade = typeof c.supplier_trade_name === "string" ? c.supplier_trade_name.trim() : "";
  const gstin = typeof c.supplier_gstin === "string" && isValidGstin(c.supplier_gstin.trim().toUpperCase())
    ? c.supplier_gstin.trim().toUpperCase() : (missing.push("supplier_gstin"), null);
  const address = str("supplier_address", 10);
  const sac = c.sac && typeof c.sac.subscription === "string" && SAC_RE.test(c.sac.subscription.trim())
    ? c.sac.subscription.trim() : (missing.push("sac.subscription"), null);
  const rate = Number(c.gst_rate_percent);
  if (!(rate > 0 && rate < 100)) missing.push("gst_rate_percent");
  const prefix = typeof c.invoice_prefix === "string" && PREFIX_RE.test(c.invoice_prefix) ? c.invoice_prefix : (missing.push("invoice_prefix"), null);
  if (prefix) {
    try { formatInvoiceNumber(prefix, "26-27", 1); } catch { missing.push("invoice_prefix (number would exceed 16 characters)"); }
  }
  // Credit notes (CGST Rules r.53) take their own consecutive series; the
  // prefix is a numbering choice, not a legal field, so it may default.
  const cnPrefix = c.credit_note_prefix === undefined ? "CN"
    : (typeof c.credit_note_prefix === "string" && PREFIX_RE.test(c.credit_note_prefix) ? c.credit_note_prefix : (missing.push("credit_note_prefix"), null));
  if (cnPrefix) {
    try { formatInvoiceNumber(cnPrefix, "26-27", 1); } catch { missing.push("credit_note_prefix (number would exceed 16 characters)"); }
    if (prefix && cnPrefix === prefix) missing.push("credit_note_prefix (must differ from invoice_prefix)");
  }
  const confirmedBy = str("confirmed_by");
  const confirmedOn = typeof c.confirmed_on === "string" && /^\d{4}-\d{2}-\d{2}$/.test(c.confirmed_on) ? c.confirmed_on : (missing.push("confirmed_on"), null);
  if (missing.length) return { ok: false, missing };
  return {
    ok: true,
    config: {
      supplier_legal_name: legal, supplier_trade_name: trade, supplier_gstin: gstin,
      supplier_state_code: gstin.slice(0, 2), supplier_state_name: GST_STATES[gstin.slice(0, 2)],
      supplier_address: address, sac_subscription: sac, gst_rate_percent: rate, invoice_prefix: prefix,
      credit_note_prefix: cnPrefix,
      confirmed_by: confirmedBy, confirmed_on: confirmedOn,
    },
  };
}

/**
 * CGST Act s.34(2): a credit note reduces output tax only if declared by
 * 30 November following the end of the financial year of the original
 * supply (or the annual return date, if earlier -- not modelled; the operator
 * files that). Returns that 30 November as YYYY-MM-DD for an FY like "26-27".
 */
export function creditNoteAdjustmentDeadline(fy) {
  const m = /^(\d{2})-(\d{2})$/.exec(String(fy || ""));
  if (!m) throw new Error("creditNoteAdjustmentDeadline: invalid financial year");
  return `20${m[2]}-11-30`;
}
