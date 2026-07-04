# Volume 8 — Enterprise Security Model, Customer Data Separation & MSSP Multi-Tenancy
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Security Objectives

1. Customer/tenant data is provably separated — by construction, not by
   convention.
2. No storage change weakens any existing authentication path (platform
   constitution: auth is frozen).
3. Secrets never live in storage systems; encrypted data never travels with
   its keys.
4. Every access to RESTRICTED material is attributable.

## 2. Identity & Access Model (Storage OS Scope)

| Actor | Authenticates Via | May Access |
|---|---|---|
| Customers | Existing platform auth (JWT/API keys — unchanged) | Production plane only, through existing gateway routes |
| Storage Manager Worker | Its own admin bearer auth (`apps/storage-manager/auth/`, extended not replaced) + scoped Cloudflare tokens | Catalog bucket RW; production buckets **read-only**; KNOWLEDGE_OS_KV |
| CI jobs (sync/backup) | GitHub Environments secrets: per-job R2 tokens, per-vault OAuth | Exactly the buckets/vaults their flow touches |
| Founder/operators | Password manager + hardware 2FA everywhere | Human surfaces; break-glass documented in RB-8 |

Rule: **the production gateway and the Storage Manager share no credentials,
no KV, and no writable buckets.** The only intersection is the Storage
Manager's read-only visibility into production buckets for cataloging.

## 3. Storage Manager API Security

- Admin-only surface; bearer token (rotated 90 days) + IP allowlist where
  practical; all mutating calls logged to run records with actor identity.
- Input validation at the boundary (asset IDs, prefixes, policy names are
  strictly pattern-validated — no caller-supplied raw bucket paths).
- Secure defaults: unknown classification → CONFIDENTIAL; unknown tenant →
  reject; sync flows must be pre-declared in config — the API can trigger
  flows, never define arbitrary ones at request time.

## 4. Customer Data Separation (All Customers)

- **Namespace separation:** every customer-scoped object lives under
  `tenants/<tenant-id>/...` in R2. Tenant IDs are opaque slugs registered in
  the catalog (`cdb:mssp:...` assets carry mandatory `tenant`).
- **Catalog enforcement:** Policy Engine flags any `mssp`/customer-domain
  asset outside a `tenants/` prefix (Sev-1 violation).
- **Serving isolation:** customer downloads continue to flow through existing
  gateway auth; the Storage OS adds no new customer-facing data path.
- **Cross-tenant reads are structurally impossible in the continuity plane:**
  per-tenant archives are individually encrypted (per-tenant derived keys),
  so even a fully compromised Vault 5 yields nothing across tenants.

## 5. MSSP Multi-Tenant Strategy

Aligned with the platform's existing MSSP direction (tenant engines and MSSP
surfaces already exist in the production repo); the Storage OS supplies the
data-layer half:

| Layer | Mechanism |
|---|---|
| Tenant registry | Catalog-held tenant records (id, name, contract retention override, key reference, status) — single source of truth for storage tenancy |
| Hot data | `tenants/<id>/` prefixes in production buckets; existing per-key API auth continues to gate access |
| Deliverables | Registered assets (`domain=mssp`, `tenant` set, checksummed) — every deliverable is inventoried, integrity-verifiable, and lifecycle-tracked from delivery to contractual destruction |
| Archives | Per-tenant encrypted bundles in Vault 5; per-tenant keys derived from master (HKDF w/ tenant ID salt) |
| Offboarding | Runbook: freeze tenant prefix → deliver final archive to customer → retention clock per contract → Expiry Review destruction with tombstone + destruction certificate (a sellable compliance artifact) |
| Scale path | At MSSP scale (>50 tenants or per-tenant bucket-policy needs), decision D-10 evaluates R2 bucket-per-tenant and/or D1-backed tenant registry — the prefix scheme migrates mechanically because tenant ID is already in every path and record |

## 6. Secrets Doctrine (Restated for Storage)

- Secrets live in: Cloudflare Worker secrets (`wrangler secret put` — existing
  practice), GitHub Environments, and the password manager. Nowhere else.
- Storage systems (R2, Drive, repos) carry **references** to secrets, never
  values. KV API-key material follows existing platform design (unchanged);
  its backup is hash-inventory only (Vol. 5 §4).
- Encryption keys for the continuity plane are held outside the continuity
  plane (Vol. 5 §6). Key rotation: annual or on suspicion; old keys retained
  (sealed) until every archive they protect is re-encrypted or destroyed.

## 7. Threat Model Summary (Storage OS Additions)

| Threat | Vector | Control |
|---|---|---|
| Catalog poisoning | Compromised CI writes false records | Catalog bucket writable only by Storage Manager token; run records + daily snapshots enable diff/rollback (RB-6) |
| Backup exfiltration | Vault compromise | AES-256 client-side; per-tenant keys; nothing plaintext above INTERNAL |
| Token sprawl | Many scoped tokens | Token registry + expiry (Vol. 7 §2); quarterly audit |
| Ransomware on operator machine | Local rclone configs/keys | Keys in password manager (not on disk); vault OAuth revocable per-account; R2 originals unaffected (one-way flows) |
| Insider/AI-agent overreach | Automation given broad writes | Least-privilege per flow; production buckets read-only to the entire Storage OS; policy engine can only *order* transitions the Storage Manager validates against declared flows |

## 8. Consolidated Impact Assessment — Volume 8

| Dimension | Assessment |
|---|---|
| Business impact | "Show us your tenant isolation" becomes a one-page answer with mechanical proof — a recurring MSSP/enterprise deal blocker removed |
| Technical impact | Prefix + catalog + key-derivation conventions; no changes to existing auth or payment logic (frozen per constitution) |
| Security impact | Structural (not procedural) tenant separation in the continuity plane; bounded blast radius for every credential in the system |
| Operational impact | Tenant onboarding/offboarding become runbooks with artifacts; destruction certificates close engagements cleanly |
| Revenue impact | Direct: tenancy + retention + destruction certificates are billable enterprise/MSSP contract terms |
| Risk assessment | LOW additional risk; the model only adds controls. Watch item: key-derivation implementation must be reviewed before first RESTRICTED archive (Phase 2 gate) |
| Migration strategy | New tenants onboard under the scheme immediately (Phase 2); existing customer objects backfilled into `tenants/` prefixes only via additive copy + gateway-verified cutover, never in-place moves |
| Rollback strategy | Prefixes and encrypted archives are additive; reverting to pre-tenancy layout = stop enforcing, originals untouched |
| Long-term governance | Tenant registry reviewed monthly; threat model revisited semi-annually; D-10 at MSSP scale |

---

*End of Volume 8.*
