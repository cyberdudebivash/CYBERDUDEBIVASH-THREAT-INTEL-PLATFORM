// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Gumroad product catalog (pure module)
//
// S16 config authority: the ONE list of Gumroad products that grant platform
// access, and what each grants. Before this, handleWebhookGumroad() guessed
// the tier from a substring of the product NAME and provisioned a paid key
// for ANY sale on the seller account -- a $5 e-book named "Enterprise SOC
// checklist" would have minted an ENTERPRISE key -- and never looked at the
// price paid (S19).
//
// Authority chain:
//   - usd prices: config/commercial-contract.json (usd_monthly / usd_annual);
//     __tests__/gumroad-products.test.js fails on drift.
//   - which products exist: this file. upgrade.html's GUMROAD_URLS /
//     GUMROAD_MEMBERSHIP_URLS must list exactly these permalinks (same test),
//     so the page can never sell a product the webhook would refuse.
//
// Adding a Gumroad membership product: add its entry here (kind
// "membership") AND its permalink to GUMROAD_MEMBERSHIP_URLS in upgrade.html.
//
// Zero imports (same reason as gumroad-lifecycle.js): loadable by both
// wrangler's esbuild and plain `node --test`.
// =============================================================================

export const GUMROAD_STORE_BASE = "https://cyberdudebivash.gumroad.com/l/";

/** Canonical USD price in cents per tier and cycle (config/commercial-contract.json). */
export const GUMROAD_CANONICAL_USD_CENTS = Object.freeze({
  PRO:        Object.freeze({ monthly: 4900,  annual: 49000 }),
  ENTERPRISE: Object.freeze({ monthly: 49900, annual: 499000 }),
  MSSP:       Object.freeze({ monthly: 99900, annual: 999000 }),
});

// Verified live against the Gumroad v2 /products API (2026-07-24; see
// upgrade.html). MSSP has no Gumroad product: MSSP is sold through Razorpay.
export const GUMROAD_PRODUCTS = Object.freeze([
  Object.freeze({ permalink: "pxyfcb", tier: "PRO",        cycle: "monthly", kind: "grant" }),
  Object.freeze({ permalink: "xtnzu",  tier: "PRO",        cycle: "annual",  kind: "grant" }),
  Object.freeze({ permalink: "cdedlo", tier: "ENTERPRISE", cycle: "monthly", kind: "grant" }),
  Object.freeze({ permalink: "vxoczs", tier: "ENTERPRISE", cycle: "annual",  kind: "grant" }),
]);

// Content products on the same Gumroad account (scripts/stripe_revenue.py,
// sentinel-blogger.yml STAGE 3.93.2): rule packs, PDF reports, the daily
// brief and the IOC download are delivered by Gumroad itself and grant no
// API access. Their sales are acknowledged without a key, a hold or an
// alert. (Before S16 each of them minted a paid API key by name inference.)
export const GUMROAD_CONTENT_PRODUCTS = Object.freeze([
  "detection-pack-essential", "detection-pack-pro", "sentinel-monthly-report",
  "sentinel-apex-daily-brief", "ioc-feed-annual",
]);

const SLUG_RE = /^[a-z0-9_-]{1,64}$/;

/** The permalink slug a Gumroad ping names ("permalink", or the last segment of "product_permalink"). */
export function gumroadPermalinkFrom(formData) {
  if (!formData) return "";
  for (const raw of [formData.permalink, formData.product_permalink]) {
    if (typeof raw !== "string" || !raw.trim()) continue;
    const seg = raw.trim().replace(/[?#].*$/, "").replace(/\/+$/, "").split("/").pop().toLowerCase();
    if (SLUG_RE.test(seg)) return seg;
  }
  return "";
}

/** The catalog entry for a ping's product, or null (not a platform product). */
export function resolveGumroadProduct(formData, catalog = GUMROAD_PRODUCTS) {
  const slug = gumroadPermalinkFrom(formData);
  if (!slug) return null;
  return catalog.find((p) => p.permalink === slug) || null;
}

/** Expected price in cents for a catalog entry. */
export function gumroadExpectedCents(entry) {
  return (GUMROAD_CANONICAL_USD_CENTS[entry.tier] || {})[entry.cycle] ?? null;
}

/**
 * S19 fail-closed price check. Gumroad's `price` is the amount paid in cents
 * of `currency`. Anything but USD, a missing/garbled price, or less than the
 * canonical price (a discount code, pay-what-you-want, a product re-priced in
 * the Gumroad dashboard) is held for an operator instead of granting access.
 */
export function checkGumroadSalePrice(entry, formData) {
  const expected = entry ? gumroadExpectedCents(entry) : null;
  if (!expected) return { ok: false, reason: "no_canonical_price", expected_cents: null, paid_cents: null };
  const currency = String(formData?.currency || "usd").toLowerCase();
  const paid = /^\d{1,9}$/.test(String(formData?.price ?? "").trim()) ? Number(String(formData.price).trim()) : null;
  if (currency !== "usd") return { ok: false, reason: "currency_not_usd", expected_cents: expected, paid_cents: paid };
  if (paid === null) return { ok: false, reason: "price_unreadable", expected_cents: expected, paid_cents: null };
  if (paid < expected) return { ok: false, reason: "price_below_catalog", expected_cents: expected, paid_cents: paid };
  return { ok: true, reason: null, expected_cents: expected, paid_cents: paid };
}

/** A product outside the catalog that is probably a plan (misconfiguration), not an unrelated product. */
export function looksLikePlatformProduct(productName) {
  return /sentinel|apex|threat\s*intel|api\s*access/i.test(String(productName || ""));
}
