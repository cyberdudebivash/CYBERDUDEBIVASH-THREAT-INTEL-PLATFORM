# Volume 3 — Knowledge OS Architecture (Enterprise Control Plane)
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Mission

`CYBERDUDEBIVASH-KNOWLEDGE-OS` becomes the **Enterprise Control Plane** — the
one system that knows about every asset in the ecosystem and enforces policy
over it. It is the Brain of the Platform. It stores almost nothing itself; it
catalogs, indexes, routes, schedules, verifies, and reports.

Sixteen mandated capabilities map to five services:

| Service | Capabilities Covered |
|---|---|
| Storage Manager | Enterprise Storage Manager, Upload/Download broker, Synchronization Engine, Backup Manager, Archive Manager |
| Asset Catalog | Metadata Catalog, Asset Inventory, Enterprise File Registry, Enterprise Asset Registry, Global Asset Index |
| Search & Graph | Search Engine, Enterprise/Global Search, Knowledge Graph |
| Policy Engine | Governance Engine, Lifecycle Manager, Retention Manager, Compliance Manager, Policy Engine |
| Observability | Health, run records, KPIs (detailed in Vol. 9) |

## 2. Gap Analysis (Reuse Before Build — Principle 4)

Before designing new engines, the existing estate was searched for equivalent
capability:

| Needed Capability | Existing Equivalent? | Decision |
|---|---|---|
| Object storage & serving | R2 + `sentinel-apex-gateway` | REUSE unchanged — the Storage OS never serves customer objects |
| Retention execution on intel data | `intel-retention-engine` Worker | REUSE — the Policy Engine *emits* retention decisions; where the existing engine already acts on intel data, it remains the executor. The Storage Manager only executes retention on NEW Storage-OS-owned prefixes/buckets |
| Report upload | existing `r2_upload.py` pattern | REUSE pattern (dedicated scoped token, CI-driven) for all new upload jobs |
| Metadata catalog / registry / search / graph / sync / policy | None exists anywhere in the estate | BUILD (new, justified) inside `knowledge-os/apps/storage-manager/` — which already has the skeleton (`auth/ download/ google/ health/ metadata/ sync/ upload/`) |

Duplicate engines introduced: **0**. The build list exists only where the gap
analysis shows no equivalent.

## 3. Deployment Model

- **Code home:** `CYBERDUDEBIVASH-KNOWLEDGE-OS/knowledge-os/apps/storage-manager/`
  (existing skeleton, extended — not restructured).
- **Runtime:** new Cloudflare Worker `cdb-knowledge-os` (Vol. 2 §3.2) for the
  API surface + scheduled reconciliation, and **GitHub Actions** in the
  KNOWLEDGE-OS repo for heavy batch jobs (bulk sync, encryption, Google
  uploads via rclone) that exceed Worker CPU/time limits.
- **Route:** internal admin surface only (e.g. `knowledge.cyberdudebivash.com`),
  auth-gated (Vol. 8 §3). It is **not** a customer product surface in Phase 1–3.
- **Isolation guarantee:** no production Worker imports from, calls, or waits
  on the Knowledge OS. If `cdb-knowledge-os` is down, production behavior is
  byte-identical to today.

## 4. Service Designs

### 4.1 Storage Manager

The single broker for all non-production object movement.

Responsibilities:
- **Upload broker:** internal tooling and CI upload artifacts through it (or
  through its CI job library), never raw to buckets — so every write produces
  a catalog record.
- **Sync engine:** scheduled one-way flows:
  `production R2 → archive prefixes` (WARM transitions),
  `catalog + governance-critical sets → Google vaults` (COLD, encrypted),
  `GitHub release artifacts → cdb-artifact-vault`.
- **Backup manager:** executes the backup schedule (Vol. 5 §5), writes an
  inventory record (`backups/inventory/...`) with SHA-256 checksums per run,
  and verifies restorability by sampled decrypt-and-checksum (Vol. 6 §4).
- **Archive manager:** applies lifecycle transitions from the Policy Engine
  (Vol. 5 §3).

Interface (Worker API, admin-authenticated; also invocable as CI library):

```
POST /api/v1/storage/assets            # register asset + optional upload URL
GET  /api/v1/storage/assets/{asset-id} # metadata + locations + lifecycle state
POST /api/v1/storage/sync/{flow}/run   # trigger a defined sync flow
GET  /api/v1/storage/runs?job=...      # run history
GET  /api/v1/storage/observability     # health + KPIs (Principle 7)
```

### 4.2 Asset Catalog (Registry + Inventory + Global Index)

- One JSON record per asset at
  `cdb-knowledge-catalog/catalog/assets/<asset-id>.json` (schema in Vol. 4).
- The **Global Asset Index** (`catalog/index/latest.json`) is a compact,
  queryable snapshot (id, name, class, tier, owner, locations, state, tags)
  rebuilt on every catalog change batch and snapshotted daily.
- **Reconciliation** (Vol. 9) lists real storage (R2, GitHub, Google
  inventories) and diffs against the catalog: orphans (objects with no record)
  and ghosts (records with no object) become work-queue items — this is how
  the existing uncataloged estate gets backfilled in Phase 1 without any
  big-bang migration.

### 4.3 Enterprise Search

Phase 1–2 implementation is deliberately boring and sufficient: the Global
Asset Index is small (even 1M assets ≈ 150–300 MB raw, minutes to scan in a CI
job, and servable in shards by the Worker). Search = filtered scans over the
index with an inverted tag/term map (`catalog/index/terms/<term>.json`).
Full-text search over *content* is deferred to the Phase 4 decision point
(D-09, Vol. 10) when customer-facing knowledge search becomes a product
feature — at which point Cloudflare Vectorize/D1 is evaluated. **We do not
build a search cluster in year one.**

### 4.4 Knowledge Graph

The graph is derived, not hand-maintained. Nodes: assets, repositories,
buckets, vaults, tenants, products, intel entities (campaign/actor/CVE IDs
already present in platform data). Edges from catalog fields:
`stored-in`, `derived-from`, `supersedes`, `belongs-to-tenant`,
`references-intel`, `backed-up-to`.

Storage: adjacency lists as JSON under `catalog/graph/`. Consumers: impact
analysis ("what breaks / what leaks if X is lost or exposed"), DR scoping,
and — commercially — the provenance chain that enterprise intelligence buyers
pay for. The platform's existing P31 knowledge-graph engine for *intel
entities* is not duplicated: the catalog graph links **to** intel entity IDs;
it never re-implements P31 logic.

### 4.5 Policy Engine

- Policies are YAML/JSON documents in
  `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/policies/storage/` — classification
  rules, retention tables (Vol. 5), routing rules (which class may live where),
  and encryption requirements. PR review = policy review.
- The engine evaluates policies against the catalog nightly and emits:
  lifecycle transition orders (to Storage Manager), violations (e.g.
  RESTRICTED asset present in a Google vault unencrypted — Sev-1 alert),
  and a compliance scorecard (Vol. 9 KPIs).
- **Enforcement is graduated:** Phase 1 observe-and-report only; Phase 2
  enforce on new writes; Phase 3 enforce transitions on the back catalog.
  This is how we avoid ever breaking a working flow with a new policy.

## 5. Consolidated Impact Assessment — Volume 3

| Dimension | Assessment |
|---|---|
| Business impact | The company gains a single control surface for its entire information estate; onboarding future team members stops depending on founder memory |
| Technical impact | New Worker + CI jobs in KNOWLEDGE-OS repo; existing skeleton directories are filled in, not restructured; zero production coupling |
| Security impact | Central policy evaluation catches misplaced/unencrypted assets automatically; single audited path for uploads |
| Operational impact | All storage operations become runbook-able API calls with run records; MTTR for "where is X / restore X" drops from hours to minutes |
| Revenue impact | Provenance graph and governed deliverable registry directly support enterprise/MSSP sales claims; Phase 4 option to productize knowledge search |
| Risk assessment | LOW to production (hard isolation). MEDIUM delivery risk (it's the largest build item) — mitigated by phase gating and observe-first enforcement |
| Migration strategy | Backfill via reconciliation, not migration; no object moves to satisfy the catalog |
| Rollback strategy | Disable Worker + Actions; catalog data remains as inert JSON; production unaffected |
| Long-term governance | Storage Manager API is versioned (`/api/v1/`); policy changes only via ENTERPRISE-CONFIG PRs; quarterly capability review |

---

*End of Volume 3.*
