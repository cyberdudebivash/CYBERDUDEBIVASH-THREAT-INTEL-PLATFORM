# CYBERDUDEBIVASH SENTINEL APEX — MSSP Tenant Identity Semantics (v185)

**Mission:** SENTINEL APEX v185.0 Phase 6. Resolves the finding from
`docs/ENTITLEMENT_RESOURCE_INVENTORY_V185.md` §5: `GET
/api/mssp/tenants/{tenant_id}/feed` accepted any `tenant_id` string from any
Enterprise/MSSP-tier key with zero ownership check.

## 1. The choice: A (real ownership) vs. B (truthful correction)

The mission frames this as a choice between implementing real tenant
ownership or truthfully correcting the "tenant-scoped" claim if the data is
actually shared. **This implementation does both, in the specific way that
avoids breaking any real existing customer:**

- **Real ownership enforcement was built** (`managed_tenants` array on the
  API key record, checked in `handleMSSPFeed`).
- **It is opt-in, not fail-closed-by-default**, and the response's language
  was corrected to stop claiming per-tenant data isolation that doesn't
  exist.

## 2. Why opt-in instead of a fail-closed cutover

A fail-closed default (every key without an explicit `managed_tenants`
list denied for every `tenant_id`) would have been the "purer" security
posture, and is what a from-scratch design would do. But this is a *live
production endpoint* — this repository's own governance rules
(`CLAUDE.md`, Levels 2–3: Production Stability, Backward Compatibility)
require treating a behavior change that could silently cut off a real
paying MSSP customer's existing integration as exactly the kind of decision
that needs explicit confirmation before shipping, not a unilateral
default flip. There is no way from this codebase alone to know whether a
real MSSP customer today depends on querying a `tenant_id` that was never
explicitly "granted" (because nothing ever granted or denied one before).

The chosen middle path:

- `auth.managed_tenants === null` (every key provisioned before this
  change, and every non-MSSP key) → **unrestricted**, identical to today's
  live behavior. Zero risk of breaking an existing customer.
- `auth.managed_tenants` is an array (only true for a key explicitly
  provisioned or updated with one via `POST /api/admin/keys
  {"managed_tenants": [...]}`)  → **enforced**: the requested `tenant_id`
  must be in that list, or the request is denied with 403.

This means real isolation is available and enforced for every *new* MSSP
key going forward, and can be retrofitted onto an existing key by an
operator via the same endpoint, without any deploy-time behavior change for
customers nobody has explicitly reviewed.

## 3. The truthful correction (Option B, applied regardless of enforcement)

Independent of whether `managed_tenants` is enforced for a given key, the
underlying `items` returned by `handleMSSPFeed` are **still the same shared
global threat feed** for every tenant — filtered by the same
severity/industry query params any caller could pass. This codebase has no
per-tenant private data store anywhere. The response previously said:

> "Tenant-scoped feed. Configure industry and severity filters for
> relevant intelligence."

This overstated real per-customer data isolation. It now says:

> "Shared intelligence feed filtered by severity/industry, not private
> per-tenant data — no per-tenant data store exists in this platform
> today."

...and a new `_tenant_authorization` field (`"enforced"` or
`"unrestricted_legacy_key"`) makes which mode applied to a given response
explicit and auditable, rather than implicit.

## 4. What this does and doesn't fix

**Fixed:** *who* may request a given `tenant_id` string, for any key an
operator has explicitly scoped. *What* data comes back is honestly
described as shared, not claimed to be isolated.

**Not fixed this pass (real architecture work, out of scope):** actual
per-tenant private data storage. If a future product requirement needs
genuinely isolated per-tenant intelligence (not just per-tenant *access
control* over a shared feed), that is a real data-model change — a new R2
prefix or KV namespace per tenant, ingestion routing, etc. — and should go
through this repository's own Architecture Preservation Rule (documented
current/proposed architecture, compatibility assessment, migration plan)
rather than being bundled into this access-control fix.

## 5. Two-tenant BOLA verification (Mission Phase 7)

Not run live this pass — requires provisioning two real MSSP-tier test
keys with distinct `managed_tenants` via `POST /api/admin/keys`, which
needs `ADMIN_SECRET` (`BLOCKED_BY_SECRET`, confirmed absent via the
`commercial-customer-ops-certification.yml` presence gate run this pass).
The enforcement logic itself (`managedTenants.includes(tenant_id)`) is a
straightforward array-membership check with no code path that could return
true for a `tenant_id` outside the list — reviewable directly in
`workers/intel-gateway/src/enterprise-endpoints.js`'s `handleMSSPFeed`.
Live verification with two real provisioned identities remains a required
follow-up once `ADMIN_SECRET` is configured.

---
*CYBERDUDEBIVASH SENTINEL APEX — Mission v185.0 Phase 6 deliverable*

## 6. Self-service tenants (tenant_auth_version 2)

Paid MSSP activation used to issue keys with `managed_tenants` absent
(legacy unrestricted). Tenants could only be granted by an operator with
`ADMIN_SECRET`, so a paying MSSP customer could not use tenant-scoped
Cyber Watchdog without manual work. That gap is closed below.

**Who gets it.** Every new MSSP key is written with `managed_tenants: []`
and `tenant_auth_version: 2`, never null. That covers Razorpay verify and
webhook, Gumroad, `POST /api/admin/keys` without a list, and revenue-engine
provisioning. Two things are unchanged:
- An explicit admin list stays operator-managed.
- An explicit admin `managed_tenants: null` stays legacy.

Existing keys keep their mode.

**Routes** (customer's own MSSP key, `X-API-Key`; no `ADMIN_SECRET`):
`GET|POST /api/mssp/tenants`, `GET|DELETE /api/mssp/tenants/{tenant_id}`
(`workers/intel-gateway/src/mssp-tenants.js`).
- Legacy and operator-list keys receive `409
  tenant_self_service_unavailable_for_key`, and their access is unchanged.
- PRO and ENTERPRISE keys receive `403`.

**Ownership.** The owner is `auth.sub`, the key's `customer_id`.
- A body carrying `mssp_email`, `customer_id`, `owner_id`, `owner`,
  `email`, `sub`, `tenant_id` or `id` is rejected with `400`, as is any
  field other than `name`.
- Tenant ids are generated by the server as `tn_` plus 20 hex characters.
- Any other id in a path returns the same `404` as a foreign or missing
  tenant.
- Names are 1–80 printable characters with no control characters, `/`, `\`
  or `<>`. They are unique per owner after NFKC normalization and
  case-folding.

**Atomic membership.** Membership lives in the existing `WatchdogLedger`
Durable Object class: one instance per owner, named `"mssp:" + sub`, under
storage key `mssp_tenant_membership`. No new binding, class, migration or
paid service is involved.
- Each create or revoke is a get-then-put inside one instance with no
  other I/O in between, so the runtime serializes them.
- There is no KV read-modify-write.

**Authorization.** For a v2 key, the `managed_tenants` value used for
authorization is the store's active tenant list. It is read once per
tenant-scoped request: the tenant feed, or a Watchdog request with a tenant
header, query or session. Nothing else pays for the read.
- Revocation is immediate, including for existing Watchdog session tokens.
- If the store is unavailable, access fails closed to `[]`.
- The KV key record is deliberately not rewritten on tenant changes. A KV
  read can be up to 60 s stale, and writing a stale record back could undo
  a concurrent refund or suspension.

**Lifecycle.**
- Rotation (gateway admin and revenue-engine) carries the mode exactly. A
  v2 key keeps its `customer_id`, which is where its tenants live, so
  rotation preserves them.
- Refund, cancel and suspend deny the key (`evaluateKeyRecordAccess`,
  `jwt_deny`). Reactivation restores the same tenants.
- The Watchdog scheduler drops a revoked tenant from the registry on its
  next run.
- If the store cannot be reached, the scheduler skips the tenant for that
  run (`unverified`, the same handling #501 gives an unreadable denial
  marker) rather than evaluating or deregistering it.

**Limit.** There is a technical limit of 100 active tenants per owner,
matching the Watchdog session-claim cap. **It is not a commercial quota.**
`config/commercial-contract.json` defines none, and
`MSSP_PARTNER_PROGRAM.md` §1 quotes different figures ("up to 100 sub-tenant
API keys", "1–10 included", $1,999/mo) from the contract ($999/mo,
`api_keys: 100`). This is `OWNER_DECISION_REQUIRED_MSSP_TENANT_QUOTA`.

**Not changed.**
- Tenants still get the shared intelligence feed, filtered. There is no
  private per-tenant store.
- revenue-engine's admin-only CRM sub-tenant records
  (`revenue.intel.cyberdudebivash.com/api/mssp/tenants`, `X-Admin-Secret`,
  used by `mssp-tenant-dashboard.html`) are a separate operator console.
  They are not a gateway authorization source, and gateway authorization
  never reads them.
