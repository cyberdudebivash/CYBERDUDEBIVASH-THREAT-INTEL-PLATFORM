# Volume 1 — Enterprise Architecture
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Executive Summary

Sentinel APEX is a live, customer-facing, revenue-generating threat intelligence
platform served from Cloudflare at `intel.cyberdudebivash.com`. The business is
entering a global scaling phase targeting enterprise customers, SOC teams,
MSSPs, and government buyers.

Today, the platform's storage footprint is functional but implicit: intelligence
data, reports, artifacts, documentation, and business assets are spread across
one production repository, three private repositories, three R2 buckets, four
KV namespaces, and seven Google accounts — with no unified catalog, no formal
classification, no lifecycle policy, and no single system that can answer
"where is asset X, who owns it, how is it protected, and when does it expire?"

This specification introduces the **Enterprise Storage Operating System
(Storage OS)**: a control-plane architecture, centered on the Knowledge OS
repository, that turns those existing systems into a governed, observable,
recoverable enterprise storage estate — without redesigning any of them.

**The core architectural move:** every plane keeps doing exactly what it does
today; a new control plane (Knowledge OS) is layered around them to provide
catalog, policy, lifecycle, search, sync, and continuity.

---

## 2. Current-State Inventory (Verified, Fixed Architecture)

Nothing in this section may be redesigned. It is the baseline that the Storage
OS is built around.

### 2.1 Repositories

| Repository | Role | Status |
|---|---|---|
| `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM` | Main production platform: customer-facing pages, production Workers (P16–P38 stack), CI/CD, releases, production data under `data/`, docs | PRODUCTION — DO NOT REDESIGN |
| `CYBERDUDEBIVASH-ENTERPRISE-CONFIG` | Enterprise infrastructure configuration: `cloudflare/`, `github/`, `google/`, `knowledge/`, `policies/`, `routing/`, `schemas/`, `security/`, `workers/`, `prompts/` | PRIVATE — Enterprise Infrastructure Repository |
| `CYBERDUDEBIVASH-KNOWLEDGE-OS` | Enterprise control plane: `knowledge-os/apps/storage-manager/` (auth, download, google, health, metadata, sync, upload), `configs/`, `docs/`, `packages/`, `scripts/`, `tests/`, `tools/` | PRIVATE — Brain of the Platform |
| `CYBERDUDEBIVASH-PRIVATE-ASSETS` | Private enterprise assets: `automation/`, `branding/`, `datasets/`, `playbooks/`, `prompts/`, `reports/`, `scripts/`, `sdk/`, `templates/`, `videos/` | PRIVATE — Asset Organization & Metadata |

### 2.2 Cloudflare Production Infrastructure

| Resource | Name | Function (today) |
|---|---|---|
| Worker | `sentinel-apex-gateway` | Production API gateway on `intel.cyberdudebivash.com` (`/api/*`, `/reports/*`, `/taxii/*`, `/auth/*`), 15-minute cron |
| Worker | `sentinel-apex-intel-gateway-prod` | Production intel gateway |
| Worker | `intel-retention-engine` | Retention processing |
| Worker | `revenue-engine` | Revenue processing |
| R2 bucket | `sentinel-apex-data` (binding `INTEL_R2`) | Primary intel storage: feed, STIX, manifests, CTI data |
| R2 bucket | `sentinel-apex-reports` (binding `REPORTS_R2`) | Advisory HTML reports served at `/reports/*` |
| R2 bucket | `cyberdudebivash-scan-results` | Scan results |
| KV | `API_KEYS_KV` | API key store |
| KV | `RATE_LIMIT_KV` | Rate limiting |
| KV | `ANALYTICS_KV` | Analytics counters |
| KV | `SECURITY_HUB_KV` | JWT revocation, error tracking, SIEM webhooks |
| Domains | `intel.cyberdudebivash.com`, `api.cyberdudebivash.com` | Customer-facing entry points |
| Pages | Static platform hosting | Dashboards and HTML surfaces |

### 2.3 Google Storage Accounts (Business Continuity Plane)

| Account | Assigned Role (this PDS) |
|---|---|
| `iambivash.bn@gmail.com` (PRIMARY) | Control Tower: master inventory mirror, executive documents, business/financial records, recovery coordination |
| `bivashnayak.ai007@gmail.com` | Continuity Vault 1 — Threat Intelligence archives (Sentinel APEX intel, IOC/CVE/malware report archives, CTI PDFs) |
| `cyberdudebivashpro@gmail.com` | Continuity Vault 2 — AI Security research and datasets (AI Security Hub, OWASP LLM, red-team artifacts) |
| `bivashnayak.ai07@gmail.com` | Continuity Vault 3 — Product artifacts (release archives, source snapshots, SDK builds, images, documentation) |
| `bivashkumar521@gmail.com` | Continuity Vault 4 — Marketing & brand (blogs, graphics, videos, logos, social assets) |
| `bivashan127001@gmail.com` | Continuity Vault 5 — MSSP & consulting deliverable archives (**client-side encrypted only** — see Vol. 8 §5) |
| `bivash.kmr007@gmail.com` | Cold Archive — external research library, standards documents (NIST/MITRE/ISO), deep offline backups |

**CISO constraint (binding):** these are consumer accounts. They are a
continuity tier, not an enterprise storage tier. They never appear in a
customer-facing path, never hold plaintext customer data or secrets, and their
enterprise-grade replacement path is defined in Volume 7 §4 and Volume 10.

---

## 3. Target Architecture — The Four Planes

```
                        ┌────────────────────────────────────────────────┐
                        │            CUSTOMERS / SOC / MSSP / GOV        │
                        └───────────────────────┬────────────────────────┘
                                                │  HTTPS only
                                                ▼
 PLANE 2 — PRODUCTION   ┌────────────────────────────────────────────────┐
 (Cloudflare)           │  intel.cyberdudebivash.com  api.cyberdudebivash.com
                        │  Workers: sentinel-apex-gateway (P16–P38),     │
                        │           intel-retention-engine, revenue-engine
                        │  R2: sentinel-apex-data | sentinel-apex-reports│
                        │      cyberdudebivash-scan-results              │
                        │  KV: API_KEYS / RATE_LIMIT / ANALYTICS /       │
                        │      SECURITY_HUB                              │
                        └───────────────▲────────────────┬───────────────┘
                                        │ deploys        │ catalog events,
                                        │ (CI/CD)        │ manifests, backups
 PLANE 1 — ENGINEERING  ┌───────────────┴──────┐  ┌──────▼───────────────┐
 GOVERNANCE (GitHub)    │ THREAT-INTEL-PLATFORM│  │ PLANE 3 — CONTROL    │
                        │ ENTERPRISE-CONFIG    │  │ KNOWLEDGE-OS         │
                        │ PRIVATE-ASSETS       │◄─┤  Storage Manager     │
                        │ KNOWLEDGE-OS (code)  │  │  Asset Registry      │
                        └──────────────────────┘  │  Metadata Catalog    │
                                                  │  Search + Graph      │
                                                  │  Policy + Lifecycle  │
                                                  │  Backup + Sync       │
                                                  └──────────┬───────────┘
                                                             │ encrypted,
                                                             │ scheduled, one-way
 PLANE 4 — CONTINUITY   ┌────────────────────────────────────▼───────────┐
 (Google, 7 accounts)   │  Control Tower + 5 Continuity Vaults + Cold    │
                        │  Archive — AES-256 client-side encrypted,      │
                        │  never in any customer request path            │
                        └────────────────────────────────────────────────┘
```

### 3.1 Plane Responsibilities (Single-Responsibility, Never Mixed)

| Plane | Owns | Explicitly Does NOT Own |
|---|---|---|
| GitHub (Engineering Governance) | Source code, IaC, policies, schemas, metadata definitions, documentation, automation workflows | Large binaries, production objects, customer data, backups |
| Cloudflare (Production) | Everything a customer can touch: APIs, reports, downloads, feeds, datasets, platform assets | Business documents, executive records, archives, backup copies of itself |
| Knowledge OS (Control) | Knowing about everything: catalog, registry, index, search, graph, lifecycle, retention, policy, sync orchestration | Serving customer traffic; storing bulk data itself |
| Google (Continuity) | Encrypted backups, long-term archives, executive/business documents, external research | Anything production depends on at request time |

### 3.2 Data Flow Rules (Binding)

1. **Production reads only from Cloudflare.** No Worker ever calls Google
   storage. (The existing `GITHUB_TOKEN` emergency-fallback read in the gateway
   is grandfathered and unchanged.)
2. **Everything flows through Knowledge OS.** Any file that matters gets a
   catalog entry; any copy to the continuity plane is executed or recorded by
   the Storage Manager. Ad-hoc manual uploads to Google Drive are a policy
   violation once Phase 2 (Vol. 10) completes.
3. **One-way continuity flow.** Cloudflare/GitHub → Knowledge OS → Google.
   Restores from Google are deliberate, runbook-driven operations (Vol. 6),
   never automatic.
4. **GitHub is never an archive for large binaries.** Binary artifacts > 25 MB
   go to R2 (production) or Google (continuity), with metadata in the catalog.

---

## 4. Why This Architecture (Executive Rationale)

Modeled on how the referenced leaders actually operate:

- **Microsoft / Google:** a control plane (Purview / Dataplex) catalogs data it
  does not itself store. Knowledge OS is that catalog.
- **Cloudflare:** production data lives at the edge in R2/KV with Workers as
  the only access path. We keep this exactly as-is.
- **CrowdStrike / Recorded Future / Mandiant:** intelligence is a product;
  provenance, classification, and lifecycle are what make it sellable to
  enterprises. The metadata layer (Vol. 4) is a sales asset, not overhead.
- **Microsoft Sentinel:** separates hot analytics storage from archive tiers
  with policy-driven movement. Our hot (R2) → archive (R2 prefix) → cold
  (Google) tiers in Vol. 5 mirror that.

### 4.1 Impact Assessment — Adopting the Four-Plane Model

| Dimension | Assessment |
|---|---|
| Business impact | Single authoritative answer to "where is our data"; unblocks enterprise security questionnaires and procurement (they always ask for data inventory, classification, retention, DR) |
| Technical impact | Zero change to production request paths; adds one new Worker deployment (Knowledge OS Storage Manager) and scheduled automation |
| Security impact | Net positive: classification, encryption-before-archive, and removal of ad-hoc consumer-storage usage from sensitive flows |
| Operational impact | New scheduled jobs to operate (catalog sync, backup runs); offset by eliminating manual, undocumented file management |
| Revenue impact | Enterprise trust enablement (procurement pass-rate), MSSP deliverable governance (Vol. 8), and archive-backed premium intelligence history as a sellable capability |
| Risk assessment | LOW to production (additive); MEDIUM execution risk on continuity plane (consumer accounts) — mitigated in Vol. 7 §4 |
| Migration strategy | Phased, additive (Vol. 10): catalog first, then sync, then enforcement; production untouched throughout |
| Rollback strategy | Each phase independently reversible; the platform never gains a runtime dependency on the Storage OS, so disabling it restores today's state exactly |
| Long-term governance | Quarterly architecture review, decision register, and policy-as-code in ENTERPRISE-CONFIG (Vol. 7, Vol. 10) |

---

## 5. Architecture Principles (Storage OS Constitution)

1. **Additive-first.** The Storage OS wraps production; it never rewires it.
2. **Catalog before copy.** No object moves anywhere until it has a catalog
   identity (Vol. 4).
3. **Policy as code.** Retention, classification, and routing policies live in
   `CYBERDUDEBIVASH-ENTERPRISE-CONFIG` as versioned files; the Storage Manager
   reads them, humans review them via PR.
4. **Encrypt before it leaves the production plane.** Anything written to the
   continuity plane is AES-256 client-side encrypted first (Vol. 5 §6, Vol. 8).
5. **Production independence.** The platform must run for 30+ days with the
   entire Storage OS offline, losing only catalog freshness and backup recency.
6. **Deprecate, never delete.** Inherited from the platform constitution and
   applied to storage: objects transition through lifecycle states (Vol. 5);
   hard deletion happens only at retention expiry under policy.
7. **Observable everything.** Every Storage OS component exposes health and
   emits structured run records (Vol. 9).
8. **Boring technology.** rclone, GitHub Actions, Workers, JSON manifests —
   no new databases, no new vendors, no exotic dependencies in year one.

---

## 6. Capability Map (What the Business Gains, by Volume)

| Business Capability | Delivered By | Volume |
|---|---|---|
| "Where is every asset?" | Global Asset Index + Registry | 3, 4 |
| "Is customer data separated and protected?" | Classification + tenancy model | 4, 8 |
| "Can we survive account loss / bucket loss / region loss?" | Backup + DR tiers | 5, 6 |
| "Can we pass an enterprise security review?" | Governance pack + policies | 7, 8 |
| "Does this scale to millions of records?" | Tiered storage + capacity model | 2 |
| "Is it automated or does it depend on one person?" | Automation architecture | 9 |
| "What does the next 24 months look like?" | Roadmap + decision register | 10 |

---

*End of Volume 1.*
