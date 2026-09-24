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

The v3 deploy adds one binding (`WATCHDOG_SCHEDULER`), one migration (`v3-watchdog-scheduler`, `new_sqlite_classes`) and one variable (`WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true"`).

### NORMAL ROLLBACK AFTER WATCHDOG V3

**DO NOT deploy raw pre-v3 commit 6ac0385.** Once Watchdog v3 has stored a signed destination (and #496 / `6977abf` has been live since 2026-09-24 11:06 UTC), raw `6ac0385` can POST unsigned intelligence to it. The rollback matrix test demonstrates that for states B, F and H below.

**Deploy the immutable SAFE ROLLBACK TARGET, `watchdog-v2-safe-rollback`.** It is the pre-v3 gateway (`6ac0385`, the last Worker before v3) with every outbound Watchdog webhook path removed. It intentionally disables Watchdog webhook delivery while keeping the rest of the pre-v3 platform: feeds, health, R2 paths, auth, payments, briefs and watches. Then investigate and remediate.

| | |
|---|---|
| Target | `watchdog-v2-safe-rollback` |
| Base | `6ac0385d658035ec53b98b5476dbc7af30887426` |
| Artifact | `deploy/cyber-watchdog/safe-rollback/` (`manifest.json` + a 4-file `overlay/`) |
| Artifact digest (SHA-256 over the built `workers/intel-gateway` tree) | `eefab60ffa564616d286b6e57c6180c47445d872ad65e0bf3c9a8c8031b99a2c` |

**Build and verify.** The build is deterministic, and it fails unless every base file, overlay file and the tree digest match `manifest.json`:

```
node deploy/cyber-watchdog/safe-rollback/build.mjs --out /tmp/wd-safe-rollback
# -> "result": "PASS", "artifact_digest": "eefab60ffa564616d286b6e57c6180c47445d872ad65e0bf3c9a8c8031b99a2c"
cd /tmp/wd-safe-rollback/workers/intel-gateway
npx wrangler@3.114.17 deploy --dry-run --env production    # must succeed
npx wrangler@3.114.17 deploy --env production               # the rollback itself
```

**What the overlay changes, and nothing else:**

* `cyber-watchdog.js`: the events webhook-delivery loop is removed; `deliverWebhook()` never calls fetch; `/api/watchdog/destinations` answers 503 for every method, so no unsigned row can be created and no stored secret can be listed; `module_version` is `2.0.0-safe-rollback`.
* `watchdog-ledger.js`: a no-op `alarm()` drops any alarm armed by v3, without making a request.
* `production-entry.js`: `WatchdogScheduler` stays exported as an inert stub. Cloudflare will not deploy a script that drops a Durable Object class that already exists.
* `wrangler.toml`: the `WATCHDOG_SCHEDULER` bindings and the `v3-watchdog-scheduler` migration are kept.

The rollback needs no ledger migration, no enumeration of Durable Objects and no control-plane change before it runs.

**Expected behavior after the rollback deploys:**

* `GET /api/watchdog/health` → `module_version: "2.0.0-safe-rollback"`, HTTP 200 while the feed is FRESH (503 when stale, as before).
* Any method on `/api/watchdog/destinations` → `503 webhook_delivery_disabled_safe_rollback`.
* Watchdog webhook state: **no outbound webhook requests at all**. Destinations are neither listed nor deleted. v3 signed destinations are preserved untouched in `watchdog_v3_signed_destinations`.
* Brief, watches and events keep working. Scheduled (browser-less) evaluation stops, because v2 has no scheduler.

**Roll forward safely:**

* Redeploy current main (the fixed v3). It reads both storage keys, adopts any early-v3 rows, and resumes signed delivery only for verified destinations, and only while `WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true"`.
* To roll forward with delivery still off, set that variable to `"false"` before deploying.

**Evidence (tests on this branch).** `watchdog-rollback-matrix.test.js` runs 8 persisted states × 3 implementations:

* A: genuine v2 unsigned destination.
* B: early-v3 (`6977abf`) signed row in `"ledger"`.
* C: corrected-v3 verified.
* D: corrected-v3 pending.
* E: corrected-v3 disabled.
* F: pending delivery on an early-v3 row.
* G: early-v3 row, zero enabled watches.
* H: early-v3 row in a ledger never accessed after the hotfix.

Results:

* **Corrected v3:** only B, C, F and H deliver, and every request is signed; A, D, E and G make none. With the flag absent, no state makes any request.
* **Raw v2** (evidence only): unsigned POSTs for A, B, F and H.
* **Safe target:** zero outbound Watchdog requests for all eight.

`watchdog-safe-rollback-artifact.test.js` pins the manifest and overlay. On a full `6ac0385` tree, the safe target passes 1244/1247 of v2's own tests. The 3 differences are v2's assertions that destination registration and delivery work, which is the behavior removed on purpose.

### Early-v3 data (defense in depth, not the rollback protection)

`6977abf` persisted signed destinations inside `"ledger"` with a `whsec_` secret and no `delivery_protocol`. The fixed v3 adopts them as signed-v3, and on **any** access to that ledger (reads included) moves them into `watchdog_v3_signed_destinations`. A ledger that is never accessed again (state H) keeps its row in `"ledger"` indefinitely. That is why the safe rollback target, not this migration, is what protects a rollback.

### Kill switch (secondary control)

`WATCHDOG_WEBHOOK_DELIVERY_ENABLED` is fail-closed: only `"true"` enables outbound deliveries and verification challenges. It is set explicitly in `[vars]` and `[env.production.vars]`. Pending deliveries are kept while it is off. It shows as `webhook_delivery_enabled` on `/api/watchdog/ops`.

Use it first for any delivery incident: set it to `"false"` and deploy, or change the variable in the dashboard. It does not protect a code rollback, because pre-v3 code ignores it. Only the safe target does.

### Current-production exposure until this hotfix deploys

Production runs `6977abf` (v3 before this fix). **Do not roll back Watchdog to raw 6ac0385** if any Enterprise or MSSP destination may have been registered after 2026-09-24 11:06 UTC. Use the safe rollback target.

## 14. Command center: priority, triage, inbox (PR A)

**Priority (`watchdog-priority.js`, `watchdog-priority-1`).** Every new match event stores an evidence-cited priority computed from the projected feed item. Points: CISA KEV 30, CVSS 25 (`cvss/10`), EPSS 20 (`epss`), feed severity 15, threat-activity signals 10 (attributed actor, "exploited in the wild"/ransomware/zero-day text). Bands: CRITICAL ≥ 70, HIGH ≥ 45, MEDIUM ≥ 20, else LOW. Cited floors: KEV plus CVSS ≥ 9 or CRITICAL severity gives CRITICAL; KEV, CVSS ≥ 9, EPSS ≥ 0.5 or CRITICAL severity gives at least HIGH; HIGH severity gives at least MEDIUM.

* A factor with no data is `known: false` and adds nothing. An item with no KEV/CVSS/EPSS/severity evidence scores `null` with band `INSUFFICIENT_EVIDENCE`, never 0/LOW.
* Events stored before this change report `INSUFFICIENT_EVIDENCE` with `legacy: true`. Their source fields were never stored, so they are not re-scored from partial data.
* It is not `computeActionabilityScore` (p23). That engine measures response-package completeness and assigns floor points to missing data.
* Stored form is compact (known factors only). 200 events at maximum history stay well under 1.5 MB, which the tests assert.

**Triage.** `NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED | IGNORED`. Any status may move to any other, so reopening is allowed. Nothing is resolved automatically. The last 20 changes are kept per event as `{from, to, at, by, note}`, with notes sanitized and capped at 280 characters. The legacy `acknowledged` flag stays in sync (true for every status except NEW), and `POST /events/ack` still works.

| Route | Scope | Notes |
|---|---|---|
| `POST /api/watchdog/events/status` | `watchdog:events:ack` | `{ids[≤50] \| id, status, note?}` → `{updated, unchanged, not_found}`. Refusals and no-op updates do not write. |
| `GET /api/watchdog/events/item?id=` | `watchdog:events:read` | Event, watch, and the current advisory only from a FRESH feed (`feed_item_status`: `current`, `revised_since_match`, `not_on_current_feed`, `feed_not_fresh`). |
| `GET /api/watchdog/events?…` | `watchdog:events:read` | Filters: `status`, `priority`, `severity` (CSV), `open=1`, `watch_id`, `q`, `since`, `sort=newest\|oldest\|priority`. Invalid filters return 400 before any evaluation. With no filters the list and order are exactly as before. New additive fields: `matched_total`, `filters`, and `analytics.by_status/by_priority/open/open_critical`. |

The webhook payload and contract version are unchanged. Rollback: the new event fields are ignored by earlier v3 code, and `acknowledged` stays accurate.

Proof: `watchdog-command-center.test.js` (15 tests), plus 7 negative controls in `scripts/watchdog-negative-controls.mjs` (45/45 caught).
