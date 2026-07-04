# Volume 4 — Metadata Architecture, Asset Catalog, Naming & Classification
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Asset Identity Standard

Every governed object gets a permanent, location-independent identifier:

```
cdb:<domain>:<class>:<yyyy>:<slug>[:v<N>]

Examples:
cdb:intel:report:2026:apt-x-campaign-briefing:v2
cdb:mssp:deliverable:2026:acme-corp-q2-assessment
cdb:platform:artifact:2026:sdk-python-1.4.0
cdb:brand:video:2026:dashboard-overview-live
cdb:exec:document:2026:board-q3-strategy
```

- `domain` ∈ `intel | mssp | platform | brand | exec | research | ai | legal | finance | config`
- `class` ∈ `report | deliverable | dataset | artifact | document | video | image | feed | backup | template | playbook`
- IDs are immutable; locations change, IDs never do. Supersession is expressed
  with `supersedes` edges, not ID reuse.

The asset ID (URL-encoded) is the catalog key:
`cdb-knowledge-catalog/catalog/assets/<asset-id>.json`.

## 2. Metadata Record Schema (v1)

Schema file lives at `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/schemas/asset-record.v1.json`.
Records are versioned by `schema_version`; v1 fields are never removed or
repurposed (deprecation-only evolution, same rule as the platform).

```json
{
  "schema_version": "1.0",
  "asset_id": "cdb:intel:report:2026:apt-x-campaign-briefing:v2",
  "title": "APT-X Campaign Briefing (Q2 2026)",
  "domain": "intel",
  "class": "report",
  "classification": "CONFIDENTIAL",
  "tenant": null,
  "owner": "iambivash.bn@gmail.com",
  "created_at": "2026-06-11T09:30:00Z",
  "updated_at": "2026-07-01T14:00:00Z",
  "lifecycle_state": "ACTIVE",
  "retention_policy": "intel-report-standard",
  "content": {
    "media_type": "text/html",
    "size_bytes": 61440,
    "sha256": "…"
  },
  "locations": [
    {"plane": "production", "system": "r2", "bucket": "sentinel-apex-reports", "key": "reports/2026/apt-x-campaign-briefing.html", "role": "primary"},
    {"plane": "continuity", "system": "gdrive", "vault": "bivashnayak.ai007@gmail.com", "path": "CyberDudeBivash/Sentinel APEX/Threat Reports/2026/…", "role": "archive", "encrypted": true}
  ],
  "relations": [
    {"type": "supersedes", "target": "cdb:intel:report:2026:apt-x-campaign-briefing:v1"},
    {"type": "references-intel", "target": "actor:APT-X"}
  ],
  "tags": ["apt-x", "campaign", "q2-2026", "premium"],
  "provenance": {"produced_by": "sentinel_blogger.py", "pipeline_run": "…", "source_repo": "CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"}
}
```

Design notes:
- `tenant` is null for non-customer assets and **mandatory** for any
  `mssp`/customer deliverable (Vol. 8 tenancy).
- `sha256` makes every backup verifiable and every deliverable tamper-evident —
  a sellable property for enterprise intelligence.
- `locations[].role` ∈ `primary | replica | archive | backup`; exactly one
  primary per asset.

## 3. Data Classification Standard

Four levels — few enough to be applied consistently, mapped to concrete
handling rules the Policy Engine can enforce mechanically:

| Level | Definition | Examples | Handling Rules (enforced) |
|---|---|---|---|
| PUBLIC | Intended for unrestricted distribution | Published advisories, blog assets, marketing | Any plane; no encryption requirement; CDN-cacheable |
| INTERNAL | Business information, not secret | Runbooks, internal reports, templates, non-sensitive datasets | GitHub/R2/Google allowed; Google copies encrypted by default |
| CONFIDENTIAL | Damaging if leaked | Premium intel, unreleased research, financials, executive documents | Production R2 (auth-gated) or private repos; Google copies **must** be client-side encrypted; access logged |
| RESTRICTED | Customer/tenant data, secrets-adjacent, legal/compliance | MSSP deliverables, customer configs, pentest reports, contracts | Tenant-scoped prefixes only (Vol. 8); Google copies only in Vault 5/Control Tower, client-side encrypted, per-tenant keys; **never** in a shared/public path; secrets themselves NEVER in storage — secret stores only |

Default when unlabeled: **CONFIDENTIAL** (fail closed). Classification is a
required field — the catalog rejects records without it.

## 4. Naming Standards

| Object | Standard | Example |
|---|---|---|
| Asset IDs | §1 URN format | `cdb:mssp:deliverable:2026:acme-corp-q2-assessment` |
| Files | `<yyyy-mm-dd>_<domain>_<slug>_v<N>.<ext>` — lowercase, hyphenated slug, no spaces | `2026-07-04_intel_apt-x-campaign-briefing_v2.html` |
| R2 buckets (new) | `cdb-<domain>-<function>` | `cdb-knowledge-catalog` |
| R2 prefixes | `<function>/<yyyy>/[<qq>/]…` | `archive/2026/q2/` |
| KV namespaces (new) | `<DOMAIN>_<FUNCTION>_KV` | `KNOWLEDGE_OS_KV` |
| Workers (new) | `cdb-<service>` | `cdb-knowledge-os` |
| Google Drive folders | Fixed taxonomy (§5) | `CyberDudeBivash/Sentinel APEX/Threat Reports/2026/` |
| Git branches | existing conventions (unchanged) | — |

Existing production names are grandfathered permanently. Renaming a live name
to satisfy a standard is prohibited (Level 3 backward compatibility beats
Level 8 cleanliness).

## 5. Folder Standards

### 5.1 Google Drive (all seven accounts — identical skeleton)

```
CyberDudeBivash/
├── _CATALOG/            # per-vault inventory JSON, written by Storage Manager
├── Sentinel APEX/       # Threat Reports / IOC / Malware / CVE / YARA / Sigma / ATT&CK
├── AI Security Hub/
├── Products/
├── MSSP/                # Vault 5 + Control Tower only; encrypted archives only
├── Marketing/
├── Research/
├── GitHub Backup/       # encrypted repo bundles (Vol. 5 §5)
├── Executive/           # Control Tower only: Finance / Legal / HR / Board
└── Archive/             # cold, superseded material
```

Each vault actively uses only the folders matching its assigned role (Vol. 1
§2.3); the identical skeleton means any vault can absorb another's role in a
recovery scenario without inventing structure.

### 5.2 `CYBERDUDEBIVASH-PRIVATE-ASSETS` (existing taxonomy — kept as-is)

The existing directories (`automation/ branding/ datasets/ playbooks/ prompts/
reports/ scripts/ sdk/ templates/ videos/`) are the canonical asset taxonomy.
Rule: files ≤ 25 MB and text-diffable live in the repo; anything larger or
binary lives in `cdb-artifact-vault/<same-path>` with a small `*.asset.json`
pointer file (containing the asset ID) committed in its place. The repo remains
the organization and metadata layer; bytes live in object storage.

## 6. Catalog Population Strategy (No Big Bang)

1. **New assets** (Phase 2 onward): cataloged at creation via Storage Manager
   upload path — coverage is automatic.
2. **Existing estate** (Phase 1–3): reconciliation jobs walk R2 buckets, repo
   trees, and Google vault inventories, emitting draft records with inferred
   domain/class from path conventions; a human (or reviewed batch rule)
   confirms classification. Target: 100% of RESTRICTED/CONFIDENTIAL assets
   cataloged by end of Phase 2; long tail of PUBLIC/INTERNAL by Phase 3.
3. **Quality gates:** catalog lints — missing classification, missing checksum
   on non-HOT assets, tenant missing on `mssp` domain, KV-oversize — run in CI
   in KNOWLEDGE-OS and appear on the KPI dashboard (Vol. 9).

## 7. Consolidated Impact Assessment — Volume 4

| Dimension | Assessment |
|---|---|
| Business impact | Every enterprise security questionnaire question about data inventory/classification becomes answerable from one index; deliverables gain verifiable integrity (checksums) |
| Technical impact | One JSON schema + prefix conventions; no database; no production change |
| Security impact | Fail-closed classification; mechanical detection of misplaced RESTRICTED data; tamper-evidence on deliverables |
| Operational impact | Predictable names/paths end "which folder?" decisions; reconciliation replaces manual inventory |
| Revenue impact | Provenance + integrity metadata upgrades premium intel and MSSP deliverables from "files" to auditable products |
| Risk assessment | LOW; main risk is classification fatigue — mitigated by inference rules + only 4 levels |
| Migration strategy | Additive cataloging; zero object moves required for compliance with this volume |
| Rollback strategy | Catalog records are inert JSON; abandoning them changes nothing in production |
| Long-term governance | Schema evolves additively (`schema_version`); classification table owned by CISO role, changed only via ENTERPRISE-CONFIG PR |

---

*End of Volume 4.*
