# P0 — Metered Cloudflare Backup Admission and Disaster-Recovery Tradeoff

**Scope:** optional Cloudflare KV-to-R2 and R2 inventory snapshots in `.github/workflows/automated-backup.yml`. Ten platforms share one Cloudflare billing account with **zero approved overage**.

## Confirmed historic risk

- `scripts/backup_r2.py` previously executed LIST/GET/COPY/PUT and only then emitted a `R2_COST_GUARD` report. No pre-request budget enforcement. Its inventory enumerated a bucket completely and the integrity sample permitted 2,000 GETs per day by default.
- `scripts/backup_kv_to_r2.py` previously listed up to 500 pages per namespace, performed one GET per returned key with up to five retries and 32 concurrent workers, and then wrote snapshot JSON to R2. The security KV namespace historically exceeded 92,000 keys. A failed PUT caused a plaintext `/tmp/kv_backup_*.json` fallback containing actual values. One key GET error could still yield a partial snapshot marked restorable.
- The `cf-data-backup` GitHub Actions job was triggered every day at 01:00 UTC; its `continue-on-error` does not mean zero Cloudflare charges. The separate `full-backup` job is not part of this code change.

## Cost-safe release behavior

The OPTIONAL Cloudflare backup job is **dormant by default**. It runs only if GitHub repository/organization variable `CDB_CF_METERED_BACKUP_APPROVED` is exactly `true` and a private secret `CDB_CF_ACCOUNT_ATTESTATION_JSON` holds a current, owner-verified billing/analytics snapshot across all ten platforms. The preflight validates the snapshot locally **before CF API calls**. The scripts repeat the same preflight, preventing casual manual invocations from bypassing CI. Never commit the attestation, Cloudflare tokens or real customer KV exports.

The shared account admission consumes the schema from `config/cloudflare_shared_account_zero_overage.json`: actual plan verified, all ten platforms and all billable products inventoried, no projected overage, all dimensions within the 80% utilization envelope and fresh underlying readings. This is an **operator claim check**, not cryptographic proof and not a Cloudflare hard spend cap; confirm source data independently.

A permitted single run is bounded by:

| Control | Hard limit |
|---|---:|
| R2 bucket inventory LIST attempts | 100 (99 pages + overflow detector) |
| R2 inventory integrity GET | 500 |
| R2 inventory manifest PUT body | 16 MiB |
| Additional R2 backup destination COPY | 0 (blocked) |
| KV keys per namespace | 500, complete-or-no-snapshot |
| KV listing requests per namespace | At most 2 |
| KV read attempts | Up to 2 per key (1 retry) |
| Parallel KV readers | 4 |
| KV snapshot PUT body | 10 MiB per namespace |

A permitted usage attestation must reserve **at least** 105 R2 Class A operations, 500 R2 Class B operations, 4,000 KV value reads, 8 KV list operations, and 0.1 GB-month of R2 standard storage in the change's `proposed_increment_until_reset` fields. Actual proposed usage must be larger if it will incur more than these conservative bounds, and must include *all* remaining runs to reset, not merely one planned run. If any allowance, telemetry coverage, usage, forecast or billing classification is uncertain, **do not approve**.

## Disaster-recovery integrity constraints

- A KV namespace with more than 500 keys is **not exported by this optional job**. This must be surfaced as a FAILED or SKIPPED supplemental snapshot, never as a successful/full backup.
- Any failed or missing KV value refuses the entire namespace snapshot; no partial JSON is advertised as complete.
- The fallback writing actual customer/credential KV values in plaintext under `/tmp` was removed.
- The unrelated primary encrypted-backup job continues, but its success **does not prove that all Cloudflare KV, R2 and D1 state is restorable**. An affordable, encrypted, independently restorable, incremental backup replacement is a separate P0 disaster-recovery acceptance requirement.
- The existing auto-scheduled GitHub workflow is **not** a recurring account usage monitor and no new Cloudflare Worker/cron/resource has been introduced.

## Required approval and rollback

1. Read Cloudflare account current plan, usage and measured-through timestamps for every enabled billing dimension, reconciled across ten platforms. Confirm an adequate reserve and that optional backup is actually necessary.
2. Review the fail-closed cost rules and recovery impact above. Do not blindly enable an incomplete DR export.
3. Only then set the private attestation secret, and set the GitHub variable to `true` for the intended controlled run. Attestation expires within six hours, so repeated automated execution cannot reuse stale approval.
4. Review the Actions results and account usage. Disable the variable immediately after the approved operation.
5. For emergency shutdown, remove or set `CDB_CF_METERED_BACKUP_APPROVED=false`; no Cloudflare deployment required.

Do **not** remove existing authoritative data, security controls, token revocation records, billing entitlements, or customer state to reduce storage bills. Escalate to the owner if data retention vs cost limits cannot be jointly satisfied.
