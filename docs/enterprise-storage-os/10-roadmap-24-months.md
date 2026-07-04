# Volume 10 — Implementation Plan, Migration & Rollback, 24-Month Roadmap, Decision Register
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Implementation Strategy

Additive, phase-gated, production-first-do-no-harm. Each phase has an entry
gate, exit criteria, and an independent rollback. **At no phase does the
production platform acquire a runtime dependency on the Storage OS** — which
is why every rollback below is genuinely safe.

## 2. Phase Plan

### Phase 0 — Ratification & Foundations (Month 1, ~1 week effort)
- Ratify this PDS; mirror to `ENTERPRISE-CONFIG/docs/ENTERPRISE-OPERATING-SPEC/`.
- Harden the seven Google accounts (2FA/passkeys, recovery audit, password
  manager) — RB-8 baseline. Create the fixed folder skeletons (Vol. 4 §5.1).
- Enable secret scanning + push protection + branch protection on all four
  repos (where not already on).
- Stand up token registry; enumerate and re-scope existing tokens.
- **Exit criteria:** PDS merged in two repos; 7/7 accounts hardened; token
  registry complete. **Rollback:** none needed (all reversible settings).

### Phase 1 — Control Plane Online, Observe-Only (Months 1–3)
- Create `cdb-knowledge-catalog`, `cdb-artifact-vault`, `KNOWLEDGE_OS_KV`,
  deploy `cdb-knowledge-os` (health + catalog read APIs first).
- Implement asset schema, catalog write path, reconciliation jobs
  (R2 + repos), Global Asset Index, first policy files (classification,
  retention table) in observe-only mode.
- Write runbooks RB-1..RB-8. Begin repo backups (daily platform bundle).
- **Exit criteria:** index published daily; reconciliation diff runbook
  working; repo backups verified by sample restore; zero production changes
  (verified: platform regression suite untouched & passing).
- **Rollback:** disable Worker + Actions, delete new resources. Production
  identical to today.

### Phase 2 — Continuity & Enforcement on New Writes (Months 3–6)
- Google sync flows live (encrypted, per Vol. 5 §4 schedule) with
  verification; KV exports; vault inventories.
- Storage Manager upload path becomes the standard for **new** internal
  artifacts; policy enforcement on new writes (reject uncataloged/unclassified
  into governed prefixes).
- Tenancy scheme live for **new** customer deliverables (`tenants/` prefixes,
  per-tenant keys — key-derivation review is a hard gate).
- DR drill calendar starts (monthly report-restore, quarterly key drill).
- **Exit criteria:** 100% RESTRICTED/CONFIDENTIAL cataloged; backup KPIs
  green 4 consecutive weeks; first full DR drill cycle passed.
- **Rollback:** suspend sync jobs and enforcement flags; new-write brokering
  reverts to direct uploads (documented fallback in each job README).

### Phase 3 — Back-Catalog Governance & Platform Touchpoint (Months 6–12)
- Backfill classification for the long tail; enforce lifecycle transitions on
  back catalog (WARM moves per retention table, honoring the production
  carve-out in Vol. 5 §1).
- Optional additive CI step in the platform repo: fire-and-forget asset
  registration for pipeline outputs (the only production-repo change in the
  entire program; additive, non-blocking, appended after existing stages —
  with its own Proof-Before-Change table at implementation time).
- Knowledge Graph derivation + impact-analysis queries; internal search UX
  over the index.
- **Decision points D-07/D-08 evaluated (see register).**
- **Exit criteria:** ≥95% total catalog coverage; graph answering DR-scoping
  queries; quarterly governance review running on KPI scorecard.
- **Rollback:** the CI step is deletable in one commit (non-blocking by
  design); enforcement flags revert to observe.

### Phase 4 — Scale & Productization (Months 12–24)
- Execute D-08 outcome (Workspace/GCS migration of vault roles if triggered).
- MSSP scale-out per D-10 (bucket-per-tenant / D1 registry if tenant count
  demands). Historical-intelligence lookback product built on the governed
  archive (revenue feature). Evaluate customer-facing knowledge search (D-09).
- Annual full catalog-rebuild drill; PDS v2.0 review at Month 18.
- **Exit criteria (program complete):** the estate supports enterprise scale
  with the KPI scorecard green ≥ 2 consecutive quarters and zero
  architectural redesign required — the stated 24-month objective.

## 3. Consolidated Migration Strategy

- **No big-bang migrations anywhere.** Catalog backfills by reconciliation;
  archives accumulate by schedule; tenancy applies to new engagements first;
  back-catalog moves are batch, checksum-verified, additive-copy-then-cutover.
- **Order of value:** inventory → backups → enforcement → productization.
  If the program stops at any phase boundary, everything delivered so far
  remains fully useful.

## 4. Consolidated Rollback Strategy

| Layer | Rollback |
|---|---|
| Documentation/policies | git revert |
| New Cloudflare resources | delete; nothing references them from production |
| Scheduled jobs | disable workflows; idempotent resume later |
| Enforcement | flags → observe-only |
| Data moved to WARM/COLD | originals retained until verified (copy-then-cutover); restore = copy back per RB-1 |
| Platform CI touchpoint (Phase 3) | delete the appended step; zero impact on existing stages |

## 5. Decision Register (Open Decisions, Pre-Framed)

| ID | Decision | Default / Trigger |
|---|---|---|
| D-01 | Storage Manager runtime split (Worker vs Actions) | DECIDED: Worker = API/index; Actions = batch (Vol. 3 §3) |
| D-02 | Catalog store (R2 JSON vs D1) | DECIDED: R2 JSON + index snapshots for 24 mo; revisit at >2M assets |
| D-03 | Classification levels | DECIDED: 4 levels (Vol. 4 §3) |
| D-04 | Consumer Google accounts as continuity tier | DECIDED: yes, encrypted-only, with D-08 exit review |
| D-05 | Encryption tooling | DECIDED: rclone crypt primary, age for one-offs (Vol. 5 §6) |
| D-06 | Bulk reproducible data backup depth | DECIDED: checksum-manifest only (risk accepted, revisit if datasets become irreproducible) |
| D-07 | Cold bulk archive > 200 GB | DEFAULT: GCS Archive class; trigger: `cdb-artifact-vault` COLD-eligible > 200 GB |
| D-08 | Vault migration to Workspace/GCS | Evaluate Month 9–12; triggers: revenue supports ~$20+/mo tooling, OR any vault suspension incident, OR gov/enterprise contract requiring org-controlled storage |
| D-09 | Customer-facing knowledge search (Vectorize/D1) | Evaluate Phase 4; trigger: validated customer demand |
| D-10 | Tenant isolation upgrade (bucket-per-tenant) | Trigger: >50 active tenants or contractual bucket-policy requirement |

## 6. 24-Month Business Outcome Map

| Quarter | Storage OS Milestone | Business Capability Unlocked |
|---|---|---|
| Q1 | Phases 0–1 | Complete estate inventory; verified repo backups; procurement answers (inventory/classification) |
| Q2 | Phase 2 | 3-2-1 continuity for critical sets; tenant-grade deliverable handling; DR drills → SLA credibility |
| Q3–Q4 | Phase 3 | Full governance scorecard; provenance graph; audit-ready posture for MSSP/gov deals |
| Q5–Q6 | Phase 4 start | Enterprise-controlled continuity plane (post-D-08); MSSP scale-out |
| Q7–Q8 | Phase 4 complete | Historical-intel lookback product; PDS v2.0; estate proven at scale with zero redesign |

## 7. Final Word

The platform already earns; the P-layer stack already works; the repositories
already exist with the right boundaries. This program adds the one thing the
ecosystem lacks — a governing brain over its storage — without moving a single
byte the customers depend on. Ship Phase 0 this week.

---

*End of Volume 10. End of PDS v1.0.*
