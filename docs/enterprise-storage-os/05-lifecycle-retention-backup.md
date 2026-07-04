# Volume 5 — Storage Lifecycle, Retention Policies & Backup Policies
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Lifecycle State Machine

Every cataloged asset is in exactly one state:

```
DRAFT → ACTIVE → SUPERSEDED → ARCHIVED → EXPIRED → (DESTROYED)
              ↘  DEPRECATED ↗
```

| State | Meaning | Tier |
|---|---|---|
| DRAFT | Being produced; not yet governed content | wherever produced |
| ACTIVE | Current, served/used | HOT |
| SUPERSEDED | Replaced by a newer version, still retrievable | HOT → WARM |
| DEPRECATED | Scheduled for archive, consumers notified (mirrors platform deprecation policy) | HOT/WARM |
| ARCHIVED | Retained for policy/compliance only | WARM/COLD |
| EXPIRED | Past retention; queued for destruction review | COLD |
| DESTROYED | Deleted after review; catalog record retained as tombstone with checksum | — (tombstone kept forever) |

Rules: transitions are executed only by the Storage Manager under Policy
Engine orders (or explicit human action, which is itself recorded). Nothing
skips SUPERSEDED/ARCHIVED to reach DESTROYED. Tombstones preserve the audit
trail after deletion — deletion of data, never deletion of history.

**Production carve-out:** objects that production Workers serve (HOT) are
lifecycle-*tracked* but only ever lifecycle-*moved* by adding archive copies —
the HOT key is removed only after the platform demonstrably no longer
references it (observed via existing analytics), honoring "deprecate, don't
delete."

## 2. Retention Policy Table (Policy-as-Code Master)

Lives at `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/policies/storage/retention.yaml`.
Initial table:

| Policy ID | Asset Classes | ACTIVE→ARCHIVE | Retain Until DESTROY | Rationale |
|---|---|---|---|---|
| `intel-feed-generational` | feed snapshots, STIX bundles | on supersession | 24 months | Historical feeds are a sellable lookback product; 24 mo covers enterprise contract cycles |
| `intel-report-standard` | advisories, HTML reports | 12 months after supersession | 7 years | Intelligence history = product moat; storage cost trivial |
| `mssp-deliverable` | customer deliverables, assessments | on engagement close | 7 years or contract terms (whichever the contract says) | Legal/professional-services norm; per-tenant override supported |
| `platform-artifact` | builds, SDKs, releases | 2 superseding releases | 36 months | Rollback capability + customer version support |
| `exec-record` | board, finance, legal | 24 months | 10 years | Statutory/company-record norms |
| `research-corpus` | datasets, external research | on project close | indefinite (review 24 mo) | Cheap to keep; research value compounds |
| `ops-telemetry` | run records, logs, inventories | 90 days | 13 months | Enough for YoY comparison; keeps catalog bucket lean |
| `backup-generations` | backup sets | n/a | per §5 GFS schedule | — |

Existing production retention behavior (the `intel-retention-engine` Worker
and platform `data/` conventions) is **not overridden**: where it already
governs an object class, its behavior is recorded here as the effective
policy, and changes to it follow the platform constitution, not this document.

## 3. Tier Transition Mechanics

- HOT → WARM: Storage Manager copies to `archive/<yyyy>/<qq>/` prefix, flips
  `locations[].role`, state → ARCHIVED/SUPERSEDED. Original HOT key handled
  per the production carve-out above.
- WARM → COLD: quarterly batch. Objects are bundled (tar), checksummed,
  **encrypted (AES-256, §6)**, uploaded to the role-matching Google vault,
  inventory written to `_CATALOG/` in the vault and to
  `cdb-knowledge-catalog/backups/inventory/`.
- COLD → DESTROYED: only via the Expiry Review runbook (Vol. 6 §6) — human
  sign-off, tombstone written, then deletion.

## 4. Backup Policy — What, Where, How Often

Strategy: **3-2-1 for governance-critical data** (original + R2 copy + Google
encrypted copy), risk-accepted single-copy-plus-checksum for bulk
reproducible data (documented as decision D-06, Vol. 10).

| Data Set | Primary | Backup Copy 1 | Backup Copy 2 | Frequency |
|---|---|---|---|---|
| GitHub repos (all 4) | GitHub | `git bundle` → `cdb-artifact-vault/github-backup/` | encrypted bundle → Control Tower + Cold Archive vaults | weekly full, daily for THREAT-INTEL-PLATFORM |
| Catalog + Global Index | `cdb-knowledge-catalog` | daily snapshot (same bucket, dated) | weekly encrypted → Control Tower | daily/weekly |
| `sentinel-apex-reports` | R2 | monthly manifest+checksum sweep | quarterly encrypted archive → Vault 1 | monthly/quarterly |
| `sentinel-apex-data` critical prefixes (feed, manifests, STIX) | R2 | weekly snapshot to `archive/` prefix | monthly encrypted → Vault 1 | weekly/monthly |
| KV namespaces (4 production) | Cloudflare | weekly JSON export → `cdb-knowledge-catalog/backups/kv/` (values only where exportable; API_KEYS_KV exported as *hashed* inventory — never plaintext credentials) | encrypted → Control Tower | weekly |
| Wrangler/infra config | ENTERPRISE-CONFIG repo | covered by repo backup | covered | with repo |
| MSSP deliverables | tenant-scoped R2 (Vol. 8) | catalog checksums | per-tenant encrypted archive → Vault 5 | on delivery + quarterly |
| Executive documents | Control Tower Drive | encrypted copy → Cold Archive vault | printed/offline for the few statutory ones | monthly |
| AI datasets / bulk media | `cdb-artifact-vault` | checksum manifest only (reproducible/licensed data) | — (risk-accepted, D-06) | quarterly verify |

**Generation schedule (GFS):** daily kept 14 days, weekly kept 8 weeks,
monthly kept 12 months, yearly kept per retention table. Applies to repo
bundles, catalog snapshots, and KV exports.

## 5. Backup Execution Architecture

- Runner: GitHub Actions in `CYBERDUDEBIVASH-KNOWLEDGE-OS` (scheduled
  workflows), using rclone with per-vault OAuth (tokens in GitHub
  Environments secrets — never in code, never in Claude env vars).
- Every run writes a run record (`runs/backup/<date>/<run-id>.json`): scope,
  object count, bytes, checksums, duration, result. Missed-run detection and
  KPIs in Vol. 9.
- **Verification is part of backup:** each run re-downloads a random sample
  (≥1 object per set), decrypts, and compares SHA-256. A backup that is never
  test-restored is a hope, not a backup.

## 6. Encryption Standard (Continuity Plane)

- Cipher: AES-256 via `age` or rclone crypt (decision D-05 defaults to
  **rclone crypt** for operational simplicity — one tool does transfer +
  crypto; `age` reserved for one-off executive archives).
- Keys: master key material stored in a password manager + printed sealed
  copy (founder-held); per-tenant derived keys for RESTRICTED archives
  (Vol. 8 §5). Key material is NEVER stored in any Google account it
  protects, any repo, or any CI variable visible in logs.
- Everything CONFIDENTIAL/RESTRICTED leaving Cloudflare/GitHub is encrypted
  **before** transfer. INTERNAL is encrypted by default; PUBLIC may go plain.
- Key-loss drill: quarterly decrypt test from sealed copy (Vol. 6 §5).

## 7. Consolidated Impact Assessment — Volume 5

| Dimension | Assessment |
|---|---|
| Business impact | Retention answers become contractual selling points (7-year deliverable retention for MSSP clients); intelligence history becomes a governed product asset |
| Technical impact | Batch jobs + prefix copies; no production write-path changes; existing retention engine's authority preserved |
| Security impact | Client-side encryption removes the consumer-account confidentiality gap; hashed-only export of credential KV avoids creating a new secret-sprawl risk |
| Operational impact | Backup becomes a scheduled, verified, observable process instead of an intention; GFS bounds storage growth |
| Revenue impact | Lookback feeds and long-retention deliverables are billable differentiators; verified backups reduce SLA breach exposure |
| Risk assessment | LOW-MEDIUM: Google API quotas and OAuth token expiry are the operational weak points — mitigated by run-record alerting and quarterly token health checks |
| Migration strategy | Start with the highest-value sets (repos, catalog, reports); expand per the Phase plan; no historical cleanup required before starting |
| Rollback strategy | Stop scheduled jobs; already-made backups remain valid and inert |
| Long-term governance | Retention table changes require CISO-role PR approval in ENTERPRISE-CONFIG; annual retention review (Vol. 10 cadence) |

---

*End of Volume 5.*
