# P0 — Cloudflare shared-account zero-overage release control
**Scope:** all TEN CYBERDUDEBIVASH ECOSYSTEM platforms on ONE Cloudflare account.
**Posture:** no new paid resources, plan upgrades, recurring usage, or overage without separate explicit approval. Pre-revenue discretionary overage budget = **$0**.

## Scope and limits
Cloudflare quotas and billing apply **at their documented product and account scope**, not as ten independent, reusable allowances. Do not copy a per-account free allowance into each platform's budget. The source of truth for current allowance is the **actual connected Cloudflare account**; this repository does not contain its credentials or live billing metrics.

Existing defenses:
- `scripts/r2_cost_guard.py`: enforces local, per-run PUT/DELETE/LIST budgets before R2 mutation; NOT a billing-cycle/account-wide cap.
- `scripts/cloudflare_workload_guard.py`: pins the four checked Worker configuration inventories/routes/bindings/triggers against a reviewed repository baseline; NOT an account-wide consumption monitor.
- `tests/test_cloudflare_pre_revenue_guard.py`: blocks unauthorized bindings and freshness auto-dispatch activation; NOT billing proof.
- `ops/cloudflare_shared_account_release_gate.py`: NEW read-only offline decision gate for operator-verified account-level usage and ten-platform forecasts.

**Important:** a green CI test validates code/policy, not the remaining Cloudflare allowance. Cloudflare budget alerts are informational and usage is processed with delay; they do not turn off excess traffic or prevent charges.

## Owner-verified usage process (NO new Cloudflare workload)
1. From Cloudflare Dashboard → Manage Account → Billing → Billable Usage, record the actual **current plan**, **billing period**, product-level billed usage and usage-based charges. Also inspect Workers & Pages, R2, KV, D1, Durable Objects and every other enabled usage-billed product from their account analytics.
2. Inventory all ten actual applications/Workers, billing products, cron triggers, R2 buckets and writers. Any missing platform, undocumented paid feature, unknown storage class, unmetered-looking paid dimension or disconnected usage source = **BLOCK**.
3. Confirm the current Cloudflare account plan from dashboard/API and set `current_account_plan_verified=true` only after review. For each billing dimension, record `included`, `used_account_wide`, `forecast_all_platforms_until_reset`, `proposed_increment_until_reset`, unit, `usage_measured_through_utc` (the actual telemetry end time, NOT the screenshot/export time), and its accurate quota reset window. If telemetry data is older than six hours, BLOCK; a newly downloaded old billing report is not fresh evidence. Do NOT guess Workers-paid vs Workers-free or a monthly allowance for a daily-limited dimension. If a dimension has *no free included quota*, include 0; the gate blocks further metered activation.
4. Forecast **all ten platforms** through the end of EACH applicable allowance window, using observed rates, historical spikes and scheduled workloads. Account for paid Webhook, Durable Object, and Service Binding amplification, each R2 Class A/B operation, KV and D1 read/write costs, and additional public traffic. A forecast not supported by evidence is unverified → **BLOCK**.
5. Ensure account usage-based overage is **$0**, projected overage **$0**, and (account used + all-platform committed forecast + proposed increment) stays at or below **80% of each verified included allowance**. The remaining 20% is a safety reserve, NOT permission to incur an overage.
6. Store the reviewed snapshot **outside Git and outside R2**, with private access. Populate the schema consumed by `ops/cloudflare_shared_account_release_gate.py`; use exactly ten unique platform IDs, `source=cloudflare_account_billing_and_analytics`, all inventory booleans true only on actual review, every forbidden-change field false, and UTC clock windows. No billing credentials or customer data belong in that file.
7. Run offline: `python ops/cloudflare_shared_account_release_gate.py --attestation /secure/local/account-headroom.json`. Exit 0 is a **conditional operator-input release decision** valid for at most six hours, not a guarantee against sudden traffic, late-billed usage, or external changes. Exit 2 is **BLOCK**. No `--attestation` also returns BLOCK.
8. Review current Cloudflare usage before each new costly production change, plus during the billing cycle by a human or an **existing approved** monitoring system. Do not install new Cloudflare cron jobs just to monitor spend.
9. If any dimension approaches its budget, postpone new workloads, prioritize authoritative threat feeds and customer payment/entitlement service, reduce *optional* expensive polling/retention with customer-impact review, and verify live freshness and functional SLAs. Never silently delete R2/KV/D1 data or stop critical access controls.

### Data schema used for each billing dimension

```json
{
  "included": "verified current allowance in this dimension's units",
  "used_account_wide": "actual account-wide consumed units",
  "forecast_all_platforms_until_reset": "evidence-backed remaining consumption by all ten",
  "proposed_increment_until_reset": "incremental consumption from requested change",
  "unit": "matching documented Cloudflare billing unit",
  "usage_measured_through_utc": "ISO-8601 UTC telemetry end time (must be fresh)",
  "window_start_utc": "ISO-8601 UTC start",
  "window_end_utc": "ISO-8601 UTC reset time"
}
```

The strings above describe fields **only**; they are not values acceptable for release certification. Required metric IDs are listed in `config/cloudflare_shared_account_zero_overage.json`; add every other enabled usage-billed product metric as well. Signed/API-verifiable account evidence is preferable to manual transcription. The tool cannot independently verify the truth of a self-reported snapshot.

## Mandatory stop conditions
- Unknown plan, unknown account usage, unknown billing product, missing platform, stale snapshot, forecast missing, or exhausted safety reserve.
- Any proposal involving new paid resources, a plan upgrade, new cron triggers, unbounded R2 sync, or manual bypass.
- Re-enabling disabled high-frequency dispatches without explicit founder review and actual account headroom.
- Any increase to the established budget that relies on this repo's per-run ceilings instead of Cloudflare account-wide analytics.

**Hard constraint:** No code-only solution in a single repository can guarantee that other projects or external traffic in the same Cloudflare account will not consume metered resources. Enforce the budget at the shared account and at each platform's deployment/release pipelines, with a new reviewed snapshot on every change.
