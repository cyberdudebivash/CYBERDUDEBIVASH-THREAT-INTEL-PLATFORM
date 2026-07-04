# Phase 0 — Token & Credential Registry (Item 0.7)
## Template — canonical home: `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/security/token-registry.md`

This registry records the **existence, scope, and expiry** of every
machine credential in the ecosystem. It NEVER contains values, hashes of
values, or anything derivable into a value. Its purpose (Vol. 7 §2):
no orphaned tokens, no over-broad tokens, no surprise expiries.

**Procedure:**
1. Enumerate: Cloudflare dashboard → My Profile → API Tokens; GitHub →
   Settings → Developer settings → PATs; each repo → Settings → Secrets
   and variables (record which secrets exist per environment).
2. For each token found: register it below, then **re-scope or revoke**
   anything broader than its single purpose (one token = one function,
   Vol. 2 §5.1). Any token you can't attribute to a purpose: revoke first,
   see what breaks in the next scheduled run, re-issue scoped.
3. Commit to ENTERPRISE-CONFIG; review quarterly (RB-8 cadence).

---

## Registry

### Cloudflare API Tokens

| Token Name (as shown in dashboard) | Purpose (one) | Scopes | Used By (workflow/tool) | Stored In | Created | Expires / Rotate By | Status |
|---|---|---|---|---|---|---|---|
| `CF_API_TOKEN` (GH secret) | Deploy sentinel-apex-gateway | Workers Scripts:Edit + Workers Routes:Edit (zone cyberdudebivash.com) | deploy-worker.yml | GH Actions secret, prod repo | — | 90-day rotation | ⬜ verify scopes |
| (reports uploader token) | Upload to sentinel-apex-reports | R2: sentinel-apex-reports write-only | r2_upload.py CI step | GH Actions secret | — | 90-day rotation | ⬜ verify |
| *(add every other live token)* | | | | | | | |

### GitHub PATs / App Tokens

| Name | Purpose | Scope (fine-grained repos + permissions) | Used By | Stored In | Created | Expires | Status |
|---|---|---|---|---|---|---|---|
| `GITHUB_TOKEN` (worker secret) | Emergency GitHub fallback reads (grandfathered, Vol. 1 §3.2) | contents:read on prod repo ONLY | sentinel-apex-gateway | wrangler secret | — | 90 days | ⬜ verify it is fine-grained + read-only |
| *(pipeline push identity for NEXUS/Guardian cycles)* | Automated intel commits to main | contents:write prod repo | scheduled workflows | GH Actions | — | — | ⬜ enumerate |

### Worker Secrets (existence only — values live in Cloudflare)

`ADMIN_SECRET, GITHUB_TOKEN, CDB_JWT_SECRET, STRIPE_WEBHOOK_SECRET,
RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET, GUMROAD_WEBHOOK_SECRET,
STRIPE_PRO_PRICE_ID, STRIPE_ENT_PRICE_ID, TG_BOT_TOKEN, TG_CHAT_ID,
BSCSCAN_API_KEY` — per `workers/intel-gateway/wrangler.toml`.
⬜ Confirm each is still in use; retire unused ones via the deprecation
protocol (never silent removal).

### Google OAuth Grants (continuity plane — added in Phase 2)

| Remote | Account | Scope | Machine | Created | Last verified | Status |
|---|---|---|---|---|---|---|
| (none yet — rclone remotes are created in Phase 2, per-account) | | | | | | |

---

## Standing Rules

- New credential ⇒ new registry row in the same PR that introduces its use.
- Registry row without a live credential (revoked) ⇒ move to the
  "Retired" section below with revocation date; never delete rows (audit trail).
- Quarterly review = every row's Status column re-verified.

## Retired

| Name | Purpose | Revoked | Reason |
|---|---|---|---|
| — | | | |
