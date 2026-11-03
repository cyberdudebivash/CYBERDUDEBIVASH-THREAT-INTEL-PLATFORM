# P0 Revenue Engine — Enterprise Quote Capability Key Isolation

**Security review:** The enterprise quotation capability was generated using an HMAC keyed by `REVENUE_ADMIN_SECRET`. This duplicates administrative authority inside externally shared customer links. Separating the quotation signing key limits the blast radius of an exposed quote link or administrator credential. This scope is complementary to (not a substitute for) the Access operator-identity boundary introduced in PR #958.

**Safety state:** Code-only, opt-in, no production deployment, no new metered Cloudflare service, no payment or customer-data changes.

## Behavior and compatibility

- Default/unset/`off`/`false` `REVENUE_QUOTE_V2_ENABLED` keeps the original legacy quote tokens and all already issued customer links working.
- At an **approved** cutover, `REVENUE_QUOTE_V2_ENABLED=true` uses the dedicated `REVENUE_QUOTE_HMAC_KEY` (minimum 32 UTF-8 bytes; must differ from `REVENUE_ADMIN_SECRET` and `REVENUE_PORTAL_HMAC_KEY`). Signed capabilities are still 64-character hexadecimal HMAC-SHA256 values to preserve all existing view/accept clients, with separate `quote:v2:` purpose binding.
- When enabled, an invalid or missing signing key produces 503 **before any quote insert or D1 schema access**. Existing customer quotes cannot silently be created with empty or unusable tokens.
- Legacy links are denied after cutover by default. Operators may explicitly configure **both** `REVENUE_QUOTE_LEGACY_CUTOVER_AT` and `REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL` as strict UTC seconds (e.g. `2026-11-03T12:00:00Z`); grace must not exceed 90 days after the exact recorded cutover and cannot auto-activate later when originally malformed. Existing quote validity, refund, invoice, GST and PO state machines remain unchanged.
- Existing `quoteToken(env,id)` public interface and token format are preserved. Incorrect IDs, foreign quote tokens, malformed values, unavailable v2 secrets and missing/overlong grace fail closed.
- There is **no token rotation or live expiry enforcement** at the quote-view handler in this change. Previously issued quote tokens can remain usable to view historical quotes unless the associated signing key is rotated or the new grace is closed.

## Production cutover gate — operator action required

1. Inventory currently issued quotations, expected 30–90 day response windows, expired/accepted quotes, accounting obligations and reissue/support process. Confirm that no pending enterprise quote would lose its acceptance capability.
2. Privately generate an independent random HMAC key (>=32 bytes). Store it through an approved Cloudflare encrypted Worker secret. Never place its value in GitHub, CI logs, documentation, chats or public issue trackers. Confirm absence of accidental key equality with both admin and customer portal keys.
3. Certify the exact head using `node --test workers/revenue-engine/src/__tests__/quote-token-v2.test.js`, existing `billing-export-po` and all payment/entitlement tests, Revenue Manual Payment Authority Gate, SAST, production entrypoint bundle and Wrangler dry-run. Run manually on an isolated checkout when CI is unavailable.
4. In staging, verify new quote create/view/accept, invalid/missing/other-quote HMAC rejection **before** D1 reads, malformed cutover fail-closed, legitimate existing quote link behavior and grace expiry. Test admin and operator-JWT positive/negative controls from PR #958.
5. Capture identity and environment provenance, staging acceptance, business continuity signoff, rollback strategy, Cloudflare plan usage and owner approval. Do **not** set the opt-in flag until this review is complete. Any Cloudflare Access product setup is a separate approved, cost-reviewed action.
6. At approved activation, monitor only aggregate denied/authenticated counts; never log full quote tokens, email addresses, raw JWTs or admin credentials. Verify customer quotations still convert and Razorpay checkout, refunds and invoices are unaffected. Preserve evidence for the coordinated Vishal Pawar VDP response.

## Residual risks / NON-GO conditions

- Existing quotation links still transmit the quote bearer capability in the URL query string; a copied URL or intermediary log may reveal it. The HTML response has an existing `Referrer-Policy: no-referrer` and CSP, but this **does not eliminate URL/log leakage**. A fragment-and-POST redesign requires coordinated frontend/backend migration and acceptance tests; **do not claim query-token confidentiality is solved**.
- No claim of a full Zero Trust perimeter or immediate revocation of previously issued quote capabilities. Original researcher issue remains OPEN until exact live Worker SHA, independent authorized/unauthorized retesting, any network-level protection and legitimate billing flows are verified.
- `REVENUE_ADMIN_SECRET` must not be rotated blindly; historical customer-portal URLs and any other live credentials must be inventoried and migrated safely first.
- A code merge is not a deployment. Activation is an explicit separate change with customer and financial rollback certification.
