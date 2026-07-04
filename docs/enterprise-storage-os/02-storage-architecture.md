# Volume 2 — Storage Architecture & Cloudflare Governance
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Design Goal

Support millions of threat-intelligence records, files, and reports — plus AI
datasets, customer deliverables, and platform artifacts — on the existing
Cloudflare estate, with no redesign of current buckets, namespaces, or Workers,
and no per-object cost surprises (R2 has zero egress fees, which is a strategic
advantage for a downloads-heavy intelligence business).

## 2. Storage Tier Model

| Tier | System | Latency | Contents | Access Path |
|---|---|---|---|---|
| HOT | R2 (existing buckets) + KV | ms | Live feeds, current reports, active datasets, API-served objects | Production Workers only |
| WARM | R2 `archive/` prefixes (same buckets) | ms (rarely read) | Superseded reports, previous feed generations, closed-quarter artifacts | Production Workers (on demand) + Storage Manager |
| COLD | Google Continuity Vaults | hours (manual/scheduled) | Encrypted long-term archives, compliance retention, executive records | Storage Manager only — never production |
| GOVERNANCE | GitHub repositories | n/a | Code, config, policies, schemas, metadata, small documents | CI/CD + humans |

Movement between tiers is policy-driven (Vol. 5) and executed by the Storage
Manager (Vol. 3). Existing production code needs **zero changes**: HOT objects
stay exactly where the Workers already read them.

## 3. Cloudflare Estate — Current + Target

### 3.1 Existing Resources (FROZEN — no renames, no restructures)

| Resource | Governance Status |
|---|---|
| `sentinel-apex-data` (INTEL_R2) | Frozen structure. New content only under new prefixes (§3.3) |
| `sentinel-apex-reports` (REPORTS_R2) | Frozen. Serves `/reports/*`. Archive prefix added, existing keys untouched |
| `cyberdudebivash-scan-results` | Frozen |
| `API_KEYS_KV`, `RATE_LIMIT_KV`, `ANALYTICS_KV`, `SECURITY_HUB_KV` | Frozen key structures per platform constitution |
| Workers `sentinel-apex-gateway`, `sentinel-apex-intel-gateway-prod`, `intel-retention-engine`, `revenue-engine` | Frozen; the Storage OS never modifies them |

### 3.2 New Resources (ADDITIVE — created for the Storage OS)

| Resource | Purpose | Justification |
|---|---|---|
| R2 bucket `cdb-knowledge-catalog` | Catalog manifests, asset index snapshots, sync run records, backup inventories | Keeps control-plane data out of production buckets (single responsibility); catalog can be rebuilt, so LOW criticality |
| R2 bucket `cdb-artifact-vault` | Large private binaries that don't belong in GitHub or production buckets: videos, datasets, SDK builds referenced by PRIVATE-ASSETS metadata | Enforces "GitHub is never a binary archive" without polluting customer-serving buckets |
| KV namespace `KNOWLEDGE_OS_KV` | Storage Manager operational state: job locks, cursors, health snapshots, policy cache | Isolates control-plane KV from the four frozen production namespaces |
| Worker `cdb-knowledge-os` | The Storage Manager service (Vol. 3), on its own route (e.g. `knowledge.cyberdudebivash.com` or an internal path), separate deployment pipeline | Production gateway stays untouched; independent blast radius |

**Impact assessment (new resources):** Business — control plane gets its own
cost/quota envelope, trivially attributable. Technical — zero coupling to
production bindings. Security — separate API tokens scoped per bucket (§5).
Operational — one more Worker to run, monitored like the others. Revenue —
none direct; enables Vol. 3 capabilities. Risk — LOW. Migration — create empty,
populate incrementally. Rollback — delete resources; production unaffected.

### 3.3 Prefix (Folder) Standards Inside Buckets

New content written by the Storage OS uses namespaced prefixes so it can never
collide with existing production keys:

```
sentinel-apex-data/
  (existing keys — untouched)
  archive/<yyyy>/<qq>/...          # WARM tier for superseded intel objects

sentinel-apex-reports/
  (existing keys — untouched)
  archive/<yyyy>/<qq>/...          # WARM tier for superseded HTML reports

cdb-knowledge-catalog/
  catalog/assets/<asset-id>.json   # one metadata record per asset (Vol. 4)
  catalog/index/latest.json        # global asset index snapshot
  catalog/index/<date>.json        # daily index snapshots (90-day retention)
  runs/<job>/<date>/<run-id>.json  # sync/backup run records
  backups/inventory/<vault>/<date>.json

cdb-artifact-vault/
  branding/... datasets/... videos/... sdk/... reports/internal/...
  (mirrors CYBERDUDEBIVASH-PRIVATE-ASSETS directory taxonomy — Vol. 4 §5)
```

## 4. Capacity & Scale Model (24 Months)

Planning assumptions (deliberately conservative, sized for "thousands of
enterprise customers"):

| Object Class | Year-2 Volume | Avg Size | Total | Tier |
|---|---|---|---|---|
| Intel records (IOC/CVE/actor JSON, STIX) | 10M records | 2 KB | ~20 GB | HOT R2 + aggregated feed objects |
| HTML advisory reports | 500K | 60 KB | ~30 GB | HOT → WARM |
| Customer deliverables (MSSP/enterprise) | 50K | 1 MB | ~50 GB | HOT (tenant-scoped, Vol. 8) |
| AI datasets & research corpora | — | — | 1–5 TB | `cdb-artifact-vault` + COLD |
| Platform artifacts, media, SDK builds | — | — | 200 GB | `cdb-artifact-vault` |
| Catalog metadata (at 1M cataloged assets) | 1M records | 1.5 KB | ~1.5 GB | `cdb-knowledge-catalog` |

Conclusions:

1. **R2 scales without redesign.** Multi-TB in R2 is routine; cost is
   ~$0.015/GB-month with zero egress. Even the 5 TB worst case is ~$75/month.
   No sharding, no re-architecture, no migration cliff within 24 months.
2. **KV stays small.** KV remains for keys/counters/state only — never bulk
   records. The Storage OS enforces this by policy (KV values > 100 KB are a
   catalog lint violation).
3. **Listing at millions of objects** is handled by the catalog index, not by
   R2 `list()` calls at request time. The index snapshot (`catalog/index/`) is
   the query surface; R2 listing is only used by reconciliation jobs (Vol. 9).
4. **Google free tiers (7 × 15 GB ≈ 105 GB)** cover encrypted archives of the
   *governance-critical* subset only (catalog snapshots, executive documents,
   deliverable archives, config backups). Bulk COLD data (AI datasets) stays in
   `cdb-artifact-vault`; the Google plane holds its *inventory + checksums*,
   not the bytes. If archive demand exceeds free tiers, the decision point is
   Google One on the primary account vs. GCS Archive class — pre-decided in
   Vol. 10 decision register (D-07) in favor of GCS for anything > 200 GB.

## 5. Cloudflare Governance Rules

1. **Token scoping.** One API token per function, least privilege:
   deploy tokens (Workers Scripts:Edit + Workers Routes:Edit, already
   documented in `workers/intel-gateway/wrangler.toml`), per-bucket R2 tokens
   (the reports uploader token pattern already in use is the model), and a
   read-only token for catalog reconciliation. No "God tokens."
2. **Config as code.** Every bucket, namespace, route, and cron is declared in
   `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/cloudflare/` (wrangler files, resource
   inventory JSON). Dashboard-only changes are prohibited after Phase 1;
   a weekly drift-check job (Vol. 9) compares live estate vs. declared estate.
3. **Naming standard.** New resources: `cdb-<domain>-<function>` (buckets),
   `<DOMAIN>_<FUNCTION>_KV` (namespaces), `cdb-<service>` (workers). Existing
   names are grandfathered — never renamed (backward compatibility, Level 3).
4. **No cross-plane bindings.** The production gateway never gets bindings to
   `cdb-knowledge-catalog`/`KNOWLEDGE_OS_KV`; the Knowledge OS Worker never
   gets write bindings to production KV. Read-only R2 access for cataloging is
   the single allowed cross-link, and it is read-only by token scope.
5. **Budget guardrails.** R2 storage and Class A/B operations reviewed monthly
   against the KPI dashboard (Vol. 9 §5); alert at 2× trailing-month baseline.

## 6. Consolidated Impact Assessment — Volume 2

| Dimension | Assessment |
|---|---|
| Business impact | Storage estate becomes enumerable and quotable in sales/procurement contexts; predictable low cost preserves gross margin at scale |
| Technical impact | Two new buckets, one KV namespace, one Worker; zero production changes; capacity validated to 24-month targets |
| Security impact | Least-privilege tokens per bucket; control/production separation eliminates the risk of a catalog bug corrupting customer-serving data |
| Operational impact | Prefix standards make every object's tier and vintage self-describing; drift detection replaces tribal knowledge |
| Revenue impact | Zero-egress R2 keeps intelligence downloads (a paid feature) margin-positive at any volume |
| Risk assessment | LOW — additive resources; the only MEDIUM item is operator discipline on token scoping, mitigated by config-as-code review |
| Migration strategy | Create resources empty (Phase 1); backfill catalog via read-only reconciliation; no data moves until Phase 2 |
| Rollback strategy | Remove new resources and tokens; grandfathered estate is untouched by design |
| Long-term governance | Estate inventory in ENTERPRISE-CONFIG is the single source of truth; quarterly review (Vol. 10) |

---

*End of Volume 2.*
