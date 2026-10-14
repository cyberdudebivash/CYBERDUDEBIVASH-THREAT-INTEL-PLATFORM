# P0 — Deployment convergence 404 / shared-account request containment

**Incident:** GitHub Actions publisher run `38568824619` (14 October 2026) failed at `STAGE 5.8.1c`. A completed freshness check subsequently reported HTTP 200, 151 advisories and a fresh feed, but the convergence engine could not certify a large sample of report URLs (HTTP 404).

The convergence validator derived report paths from `dist/deployment_manifest.json` (91 HOT-tier report entries). Some 404s were confirmed by the authoritative publication-status API as expected `customer_ready=false` rejects; others were still non-exempt. **A fresh feed is NOT equivalent to a fully published report inventory.**

## Interim request conservation (draft change only)

- Preserve the report-path/authoritative publication-status checks and fail-closed convergence decision.
- Limit the wait for *only permanent* HTTP failures to one grace retry (two rounds total), instead of four rounds; do not reclassify genuine/unverified 404s as success.
- Preserve full retry for HTTP 429, 5xx, timeout, budget exhaustion and other explicitly transient responses under the existing global `MAX_TOTAL_REQUESTS=80` and `MAX_PROTOCOL_SECONDS=600`.
- Preserve 99/99 Watchdog negative controls, customer feed and paid entitlement checks.
- Do not add new Cloudflare probes, Worker routes, R2/KV/D1 writes, or schedules. CI tests use mocked HTTP with no network access.

**Scope note:** This bounds one GitHub workflow's synthetic readiness queries; it does not itself constrain customer traffic or certify actual shared Cloudflare headroom. Convergence is still a hard FAIL when an advertised report remains unverified.

## Required permanent root-cause correction

1. Reconcile each report referenced by the deployment manifest against the actual immutable Pages/R2 deployment outcome and authoritative publication-state record, without assuming HOT-tier implies customer-ready.
2. Distinguish `eligible-and-missing` (incident), `expected-gate-rejection` (not incident), and `status-unknown` (incident/unverified) using non-sensitive artifact IDs and checksums; reject partial or contradictory evidence. Preserve fail closed.
3. Repair the publisher to avoid advertising unreachable `customer_ready=true` artifacts. Do not simply remove records from catalogs to make the ratio greener.
4. Capture one authorized, bounded production proof of report access and a second successful publisher cycle after verifying current account-wide usage for **all ten** CYBERDUDEBIVASH platforms. No manual replay just to satisfy a check.
5. Require account-wide Cloudflare budget and remaining quota evidence, with a 20% reserve and zero projected overage, before merging a PR that changes `scripts/**.py` or the writer workflow: such a merge triggers a new R2-writing publisher.

## Operational hold

No merge, no `workflow_dispatch`, no Cloudflare API monitoring cron, and no new R2 writes from this candidate. Keep live serving unchanged and do not disable auth, anti-abuse, entitlement or data integrity controls.
