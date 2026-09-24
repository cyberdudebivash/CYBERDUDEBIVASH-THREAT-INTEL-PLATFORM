# CYBER WATCHDOG v3 — P0 paid operations, autonomous evaluation, enterprise isolation

Base: `main` @ `6ac0385d6` (#495). Live Worker at audit time: deploy-worker run #340 on `0fb8665` (#494; #495 touched only `pricing.html`). Watchdog module live: 2.0.0.

## 1. What changed

| Gap (verified on main / live) | v3 |
|---|---|
| `COMMERCIAL_MIRROR` duplicated prices in `cyber-watchdog.js` | Prices come from `pricing.js` → `pricing-data.js` (Razorpay + `/api/pricing`). USD list prices were added there, checked against the contract by `verify_commercial_contract.py`. `COMMERCIAL_MIRROR` is kept as a deprecated **view** over the provider, not a second copy. |
| Feature quotas mixed into the Watchdog module | `watchdog-policy.js` is the one Watchdog feature authority (watches, webhooks, background evaluation, tenants), plus scheduler, delivery, webhook-contract and session policy. It contains no prices, and a test fails if one appears. |
| Events only created when a page, poller or events read ran | Cron-driven `WatchdogScheduler` (section 3). |
| Webhook URL checked only literally | DNS-over-HTTPS resolution checked at registration, verification and every attempt (section 4). |
| Unsigned, single attempt, no verification | Verified destinations, HMAC-signed contract, bounded retries, dead-letter, per-destination idempotent results (sections 5–7). |
| MSSP = higher plan only | Sub-tenant ledgers authorized by the key's `managed_tenants` (section 8). |
| Long-lived API key in `sessionStorage` | Exchanged once for a 15-minute scoped session (section 9). |
| `/api/feed.json` 200 with no freshness verdict (live: no `freshness_status` field) | Body plus `X-Sentinel-*` headers carry the verdict; a stale body is never edge-cached (section 10). |
| Homepage badge defaulted to `LIVE` and only changed on an explicit non-fresh state | Fail-closed: `LIVE` only when the contract proves FRESH (section 10). |

## 2. Authorities

* **Commercial price:** `workers/intel-gateway/src/pricing-data.json` / `.js` (parity-tested), validated against `config/commercial-contract.json`. Watchdog, Razorpay and `/api/pricing` all read it.
* **Watchdog entitlements:** `workers/intel-gateway/src/watchdog-policy.js`.
* **Freshness:** `freshness-contract.js` (`evaluatePublicIntelligence`, and the new `freshnessStatusFor` / `publicationEnvelope`).
* **MSSP tenant membership:** the API key record's `managed_tenants`, set through the admin key API. This is the same authority `/api/mssp/tenants/{id}/feed` uses.

## 3. Autonomous evaluation

```
Worker cron (existing */15, no new product)
  └─ WatchdogScheduler "peek"            idle → stop (0 R2, 0 writes)
  └─ R2 GET api/v1/intel/latest.json     1 per tick, never LIST
  └─ canonical freshness gate            not FRESH → 0 events, 0 ledger calls
  └─ "plan": ≤25 subjects due (new generation or changed watches), leased
  └─ per subject: KV jwt_deny check → WatchdogLedger "scheduled_evaluate"
        (store re-checks FRESH, dedupes, stores, arms delivery alarm if needed)
  └─ "report": outcomes, parks a subject after 5 consecutive failures
```

**Registry.** Only authenticated paid mutations register a subject: watch create, update or delete, and destination verification. A subject with zero enabled watches, a FREE/denied tier, an expired entitlement, or a `jwt_deny` marker is removed. Anonymous requests never reach the scheduler (tested).

**Why a coordinator, not per-customer alarms.** Per-customer alarms cost one R2 read per customer per cycle and keep firing for idle customers. The coordinator reads R2 once per tick for everyone, and costs nothing beyond one DO read while nobody has an enabled paid watch.

**Dedupe.** The key is `watch_id | item_id | material revision`. The revision is a hash of title, severity, CVEs and KEV. Re-processing an unchanged advisory (a new `processed_at` in a new generation) is not a new event. A severity escalation or a new KEV listing is. Events stored by v2 suppress any new event for the same watch and item, so the upgrade cannot replay old matches.

**Failure.** A scheduler failure never deletes events. A subject is retried until it has failed `max_consecutive_failures` (5) times in a row. It is then parked until its owner changes a watch.

## 4. FinOps (measured by the tests, per 15-minute tick)

| State | Scheduler DO | R2 GET | R2 LIST | Ledger DO | KV read | DO writes |
|---|---|---|---|---|---|---|
| No enabled paid watch | 1 request / 1 read | 0 | 0 | 0 | 0 | 0 |
| Active, generation unchanged | 2 | 1 | 0 | 0 | 0 | 0 |
| Active, new generation, N subjects (N ≤ 25) | 3 | 1 | 0 | N | N | ≤2 scheduler + 1 per ledger with new events |

Per day (96 ticks):

* **Idle:** 96 DO requests and nothing else.
* **Worst case at the batch cap:** 288 scheduler requests, 96 R2 Class B GETs, 2,400 ledger evaluations and 2,400 KV reads.
* **Evaluations per customer per day:** the number of feed generations (at most 96), plus one after each watch edit.
* **Writes per event:** 1 ledger put, amortized per batch.
* **Webhook attempts:** at most 4 per event per destination. Each attempt costs 2 DoH lookups and 1 POST. Runs are capped at 20 deliveries per alarm and 500 pending deliveries per ledger. A destination is disabled on 410, on a forbidden DNS answer, or after 5 consecutive failed events.

All of this fits in the Workers Paid included Durable Object and R2 allowances already in use. No Queue or other new product is used.

## 5. Webhook destination safety (SSRF / DNS rebinding)

Static rules:

* HTTPS only, port 443 only.
* No credentials in the URL.
* No IP-literal outside global unicast. WHATWG parsing turns decimal, hex and octal IPv4 forms into dotted quads before the check.
* No `localhost`, `.local`, `.internal`, `.arpa` or single-label names.

DNS rules (A **and** AAAA through `cloudflare-dns.com`), checked at registration, at verification, and immediately before **every** attempt. The whole answer set is refused if **any** answer is:

* loopback, RFC 1918, CGNAT or link-local/metadata;
* multicast, reserved, benchmarking or documentation;
* unspecified, IPv4-mapped, IPv4-compatible, NAT64 or 6to4;
* non-`2000::/3` IPv6 (which covers ULA, link-local and multicast);
* a CNAME to a forbidden name or address.

A mixed public + private set is refused. A forbidden answer at delivery time fails the attempt and marks the destination `failed`. Redirects use `redirect: "manual"` and a 3xx is recorded as failed, never followed.

**Limitation, stated plainly.** Workers `fetch()` resolves the hostname itself and cannot be pinned to the addresses we validated. A resolver that flips its answer in the milliseconds between our check and the connection is **narrowed, not eliminated**. What narrows it:

* re-resolution right before each attempt;
* HTTPS, so the endpoint must hold a valid certificate for the hostname;
* port 443 only and no redirects;
* mandatory proof of endpoint control before any intelligence is sent.

Workers egress also cannot reach this platform's private network or a cloud metadata service. We therefore do **not** claim absolute SSRF immunity for arbitrary domains.

## 6. Verified destinations and the signed contract

The lifecycle is `pending` → (verify) → `active`, with `disabled` (customer) and `failed` (policy) as the other states.

**Verification.** The gateway POSTs `{"type":"watchdog.verification","challenge":"<nonce>"}`, signed like a delivery. The endpoint must answer 2xx with `{"challenge":"<nonce>"}`.

**Stored per destination:** id, url and hostname, state, created_at, verified_at, last_delivery_at, failure_count, disabled_reason, last_verification_error. The signing secret is stored inside the ledger Durable Object only.

**Signing secret.** Format `whsec_` + 64 hex. It is shown once in the create response and never returned again: `WatchdogLedger.fetch` strips state from every response.

Headers on every delivery:

```
X-CDB-Watchdog-Event-ID      stable per event
X-CDB-Watchdog-Delivery-ID   <event_id>:<destination_id>  (idempotency key; same on every retry)
X-CDB-Watchdog-Timestamp     unix seconds of this attempt
X-CDB-Watchdog-Signature     v1=<hex(HMAC-SHA256(key = UTF-8 bytes of the full secret string,
                                                  msg = timestamp + "." + raw_request_body))>
X-CDB-Watchdog-Version       2026-09-24
X-CDB-Watchdog-Attempt       1..4
```

The body bytes are serialized once per attempt, then both signed and sent. They are identical across retries; only the timestamp and signature change. Receivers should:

1. reject a timestamp more than **300 s** from their own clock;
2. compare signatures in constant time;
3. deduplicate on `X-CDB-Watchdog-Delivery-ID`.

`deploy/cyber-watchdog/sink.mjs` is a reference receiver that does all three.

## 7. Retry and dead-letter policy (`DELIVERY_POLICY`)

* **Attempts:** 4, at +0 s, +60 s, +300 s and +1800 s. `Retry-After` on 429 or 503 is honored, but capped at 3600 s and never shorter than the backoff.
* **Retried:** 429, 408, 425, 5xx, timeouts (5 s), network errors and DNS failures.
* **Never retried:** 400, 401, 403, 404, 405, 410, 413, 422, and 3xx. A 410 also disables the destination.
* **After the final attempt:** the delivery is `failed`, it is recorded in the bounded log (50 entries), and it is shown in the inbox.
* **Destination auto-disable** (state `failed`): on 410, on a forbidden DNS answer, or after 5 consecutive events that ended failed. One success resets the count.

Status is kept per event **and per destination**. An event's aggregate status is `no_destinations`, `pending`, `delivered`, `failed` or `partial`. Deliveries run on the ledger's own DO alarm, armed only while pending work exists. Leases stop overlapping runs from sending twice, and bounded attempts mean the alarm chain always ends.

## 8. MSSP sub-tenants

Tenant selection uses `?tenant=` or the `X-CDB-Watchdog-Tenant` header, and is bound into the session token. Access requires all of the following:

* an MSSP tier;
* an explicit `managed_tenants` list on the key that contains the tenant;
* a session tenant (if any) that matches.

Each tenant has its own ledger (`wd:<sub>|t:<tenant>`). Every refusal is the same `403 {"error":"forbidden"}`, whether the tenant belongs to another customer or does not exist. A tenant named in a request body is ignored.

A legacy MSSP key with no `managed_tenants` gets **no** sub-tenant access. This is a deliberate fail-closed default for a new capability; the key's account-level ledger is unchanged. MSSP tenant isolation is proven by fixture tests only, until the live canary runs.

## 9. Browser authentication

`POST /api/watchdog/session` accepts an API key or an existing session and returns an HS256 JWT signed with the existing `CDB_JWT_SECRET`. The token carries:

* `aud: "cdb-watchdog"` and a scope list by tier: `watchdog:read`, `watchdog:watches:write`, `watchdog:events:read`, `watchdog:events:ack`, and `watchdog:destinations:write` for Enterprise and MSSP;
* `sub` (customer-bound);
* `exp` of 15 minutes, with `auth_time` capping refreshes at 4 hours;
* the optional tenant and `ent_exp`, the key's entitlement expiry.

Enforcement:

* **Audience:** `handleRequest` treats the token as invalid on any path outside `/api/watchdog` (401). Premium manifests refuse it too.
* **Scopes:** `routeWatchdog` returns `403 insufficient_scope` when a scope is missing.
* **Revocation:** `DELETE /api/watchdog/session` writes the existing `jwt_revoked:` marker. Subscription denial through the existing `jwt_deny:` marker is immediate.

Tier and tenant membership are read from the key only at exchange, so a membership change can lag by up to 4 hours. There are no cookies and no ambient credential, so a cross-site form has no identity and CSRF does not apply.

The page clears the key field before the exchange request, never stores the key, and removes the v2 `apex_watchdog_key` value. JWTs without `aud` (`/auth/login`, SSO) behave exactly as before.

## 10. Freshness truth

`/api/feed` and `/api/feed.json` keep HTTP 200 for existing clients and add:

* **Body fields:** `publication_state`, `freshness_status` (FRESH, STALE, EMPTY, INVALID or UNAVAILABLE), `freshness_reason`, `age_seconds`, `max_age_seconds` and `freshness_contract`.
* **Headers:** `X-Sentinel-Freshness`, `X-Sentinel-Publication-State`, `X-Sentinel-Feed-Generated-At` and `X-Sentinel-Feed-Age-Seconds`.

The edge TTL is 0 unless FRESH, and a fresh body is never cached past its window. A paid (ungated) body is now `private, no-store`. That also closes a pre-existing leak where a PRO response could be stored in the URL-keyed edge cache and served to anonymous callers. The reverse case is not closed: a paid caller can still be served an anonymous cached copy.

On the homepage, the badge starts as `CHECKING`. It shows `LIVE` only when `publication_state === "fresh"` **and** there is a valid ISO timestamp **and** a numeric age. Otherwise it shows `DEGRADED` (stale), `UNKNOWN` (missing or invalid evidence) or `UNAVAILABLE` (stats unreachable).

## 11. Operator observability

`GET /api/watchdog/ops` requires `X-Admin-Key` and answers 404 to everyone else. It reports only aggregates, over a bounded 24 h window of hourly buckets:

* active_watch_subjects, enabled_watches, parked_subjects, active_destinations;
* last_scheduler_run, last_successful_feed_generation, recent runs;
* events generated and deduped;
* delivery attempts, successes and failures;
* verification failures and scheduler failures.

It exposes no subject, tenant, URL, secret or DO id, and never scans a bucket. Public `/api/watchdog/health` adds only `autonomous_evaluation: configured|unavailable`.

## 12. Live canaries (operator-run)

```
cd workers/intel-gateway
CDB_WATCHDOG_CANARY_PRO_KEY=… npm run canary:watchdog -- pro          # Phase 14
CDB_WATCHDOG_CANARY_PRO_KEY=… npm run canary:watchdog -- autonomous   # waits ≤20 min for a scheduler event
CDB_WATCHDOG_CANARY_ENT_KEY=… CDB_WATCHDOG_SINK_URL=… \
  CDB_WATCHDOG_SINK_INSPECT_URL=… CDB_WATCHDOG_SINK_TOKEN=… npm run canary:watchdog -- enterprise
CDB_WATCHDOG_CANARY_MSSP_KEY=… npm run canary:watchdog -- mssp        # key must manage CANARY-A and CANARY-B
```

**Credentials** are read from the environment only and are never printed. Missing inputs return:

* `OPERATOR_CREDENTIAL_REQUIRED` (exit 10);
* `OPERATOR_WEBHOOK_SINK_REQUIRED` (exit 11);
* `OPERATOR_MSSP_FIXTURE_REQUIRED` (exit 12).

**Criteria** come from a real item on the current FRESH feed, chosen with the production matcher so that exactly one item matches. The canary refuses to run on a non-FRESH feed.

**The Enterprise sink** must be owner-controlled: run `deploy/cyber-watchdog/sink.mjs` behind HTTPS:443 **without** `WATCHDOG_SECRET`, because the canary verifies signatures itself with the once-shown secret. An internal canary key is not revenue.

## 13. Deploy and rollback

The deploy adds one binding (`WATCHDOG_SCHEDULER`), one migration (`v3-watchdog-scheduler`, `new_sqlite_classes`) and one variable (`WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true"`). `wrangler deploy --dry-run --env production` with the pinned wrangler 3.114.17 succeeds.

**Rollback: revert and redeploy. V3 signed destinations are inert under the previous implementation.**

### Why the rollback is safe

The previous implementation (main @ `6ac0385`) POSTs, unsigned, to the `url` of **every** element of `destinations` in the Durable Object storage key `"ledger"`. It reads no state or protocol field (`cyber-watchdog.js@6ac0385:957-960`). A state or protocol marker alone would therefore not stop it.

v3 persists signed destinations under a separate storage key, `watchdog_v3_signed_destinations`, which v2 never reads or writes. `"ledger".destinations` holds only legacy v2 rows. v3 also marks its rows `delivery_protocol: "signed-v3"` and treats anything without that marker and a `whsec_` secret as disabled. So compatibility holds in both directions:

| persisted destination | v3 | previous v2 |
|---|---|---|
| legacy v2 (`url`, no secret) | disabled, re-registration required | active (unchanged v2 behavior) |
| v3 pending | pending, never delivered | invisible, never delivered |
| v3 verified signed | **active** | **invisible, never delivered** |
| v3 disabled | disabled | invisible, never delivered |

`watchdog-rollback-compat.test.js` proves this with the real v2 router and v2 `WatchdogLedger` (vendored byte-for-byte in `__tests__/fixtures/watchdog-v2`, hash-checked) running over storage written by the real v3 ledger:

* v2 does run its delivery loop, and only ever POSTs to the legacy URL.
* A ledger holding only v3 destinations makes zero outbound requests under v2.
* v2 writes do not delete v3 destinations, so rolling forward again restores them.

Negative controls: `v3_verified_persisted_in_v2_readable_ledger` (put signed rows back into `"ledger"`) and `v3_accepts_unsigned_v2_destination` both turn the suite red.

### Destinations created by the first deployed v3 build

`6977abf` (#496) was merged and deployed before this fix, so its signed destinations sit in `"ledger"` with a secret but no `delivery_protocol`.

* `fromPersisted()` adopts any such row as signed-v3.
* The next v3 write on that ledger moves the row into the v3-only key. Any mutation, append or delivery run counts as a write.
* The test `migration: a destination persisted by the first deployed v3 build…` covers this, and the negative control `early_v3_rows_not_migrated` turns it red.
* **Remaining exposure:** until a ledger's first write under this fix, such a row is still in the v2-readable key. If you need a rollback during that window, turn the kill switch off first. v2 itself has no kill switch, so only a rollback that happens after these rows have moved is fully safe.

### Kill switch (secondary control)

`WATCHDOG_WEBHOOK_DELIVERY_ENABLED` is fail-closed: only the exact string `"true"` enables outbound webhook deliveries and verification challenges; absent or any other value disables them. It is set explicitly to `"true"` in `[vars]` and `[env.production.vars]`. When it is off, pending deliveries are kept, not attempted, and resume after delivery is re-enabled. It is exposed as `webhook_delivery_enabled` on `/api/watchdog/ops`. To stop all customer webhook traffic without a code rollback, set it to `"false"` and deploy (or change the variable in the Cloudflare dashboard).

### Operational notes for the revert commit (not code-proven here)

* **Keep the scheduler Durable Object class.** Cloudflare normally refuses to deploy a script that stops exporting a Durable Object class that has a namespace, unless a `deleted_classes` migration is added. The revert should therefore keep an inert `WatchdogScheduler` export, the `WATCHDOG_SCHEDULER` binding and the `v3-watchdog-scheduler` migration, or add a `deleted_classes` migration. I could not check this against the live account from CI.
* **Pending v3 ledger alarms.** Alarms armed by v3 may fire once more after a revert. The v2 `WatchdogLedger` has no alarm handler, so no request is made.
* **Browser sessions.** Sessions stop working after a revert, so the previous page returns with the revert.
* **Leftover data.** Existing ledgers keep their data. v2 ignores the v3 event fields (`deliveries`, `revision`, `metrics`).
