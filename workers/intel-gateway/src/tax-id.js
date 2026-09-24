/**
 * CYBERDUDEBIVASH SENTINEL APEX -- buyer tax id (GSTIN / VAT) validation.
 *
 * Server-side counterpart of SentinelCheckout.validateTaxId() in
 * js/checkout.js (same rules; the client check is a convenience, this one is
 * the boundary). Used by POST /api/payment/razorpay/create-order so a buyer's
 * GSTIN is recorded on the Razorpay order instead of being dropped.
 *
 *   - empty            -> ok, no tax id
 *   - 15 characters    -> must be a GSTIN: state code, PAN, entity, 'Z',
 *                         and a valid mod-36 check character
 *   - anything else    -> accepted as a foreign VAT/tax number when it is
 *                         4-20 characters of A-Z, 0-9, space, '-', '.', '/'
 */

const GSTIN_RE = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;
const VAT_RE = /^[A-Z0-9][A-Z0-9 .\/-]{2,18}[A-Z0-9]$/;
const CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/** GSTIN check character (GSTN mod-36 scheme) for the first 14 characters. */
export function gstinCheckChar(first14) {
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const v = CHARSET.indexOf(first14[i]) * (i % 2 ? 2 : 1);
    sum += Math.floor(v / 36) + (v % 36);
  }
  return CHARSET[(36 - (sum % 36)) % 36];
}

/** { ok, value, kind: "gstin" | "vat" | null, reason? } */
export function normalizeBuyerTaxId(raw) {
  if (raw === undefined || raw === null) return { ok: true, value: "", kind: null };
  if (typeof raw !== "string") return { ok: false, value: "", kind: null, reason: "Tax id must be text." };
  const v = raw.trim().toUpperCase();
  if (!v) return { ok: true, value: "", kind: null };
  if (v.length === 15) {
    if (!GSTIN_RE.test(v) || gstinCheckChar(v) !== v[14]) {
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
