# Volume 7 — Repository, GitHub & Google Storage Governance
## CYBERDUDEBIVASH® Enterprise Storage Operating System — PDS v1.0

---

## 1. Repository Governance (Fixed Architecture)

The four-repository architecture is **permanent** for the 24-month horizon.

| Repository | Charter | May Contain | Must NOT Contain |
|---|---|---|---|
| `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM` | Production platform | Platform code, Workers, CI/CD, customer-facing pages, production docs, platform data | Infrastructure config for other planes, business records, large binaries, secrets |
| `CYBERDUDEBIVASH-ENTERPRISE-CONFIG` | Enterprise infrastructure & policy | Cloudflare/GitHub/Google config-as-code, storage policies, schemas, security policies, routing, governance docs, the canonical PDS mirror | Production application code, customer data, secrets (references only), binaries |
| `CYBERDUDEBIVASH-KNOWLEDGE-OS` | Control plane | Storage Manager code, catalog tooling, sync/backup workflows, runbooks, control-plane tests | Production platform code, bulk data, customer deliverable content |
| `CYBERDUDEBIVASH-PRIVATE-ASSETS` | Asset organization & metadata | Templates, playbooks, prompts, small assets, `*.asset.json` pointers to large binaries | Binaries > 25 MB (pointer rule, Vol. 4 §5.2), customer data, secrets |

**Prohibited permanently:** merging repositories; renaming repositories;
moving production code into storage repos; storing infra config in the
production repo; using any repo as a binary archive.

**Cross-repository references** are one-directional and explicit:
KNOWLEDGE-OS reads policies from ENTERPRISE-CONFIG; nothing imports code
across repos at runtime.

## 2. GitHub Governance

| Control | Standard |
|---|---|
| Branch protection | Default branches protected on all four repos: PR required, no force-push, linear history preferred |
| Reviews | Production repo: existing constitution rules apply (evidence tables, regression gates). Other repos: 1 review (self-review allowed while team = 1, with PR description discipline as the record) |
| Secrets | GitHub Actions Environments with scoped secrets per workflow; secret scanning + push protection enabled on all repos; no secrets in code, wrangler vars, or Claude environment variables |
| Actions hygiene | Workflows pinned to major versions; `permissions:` block mandatory (least privilege, default `contents: read`); third-party actions allowlisted |
| Tokens/PATs | Fine-grained PATs only, per-purpose, 90-day max expiry, registered in ENTERPRISE-CONFIG `security/token-registry.md` (names/scopes/expiry only — never values) |
| Repo settings as code | `github/` directory in ENTERPRISE-CONFIG records intended settings; quarterly drift check against live settings |
| Backups | All four repos bundled per Vol. 5 §4 — GitHub itself is not the backup |

## 3. Google Storage Governance

### 3.1 Role Charter (restates Vol. 1 §2.3 as policy)

The seven accounts form the **continuity plane**: Control Tower (primary),
five role-scoped Continuity Vaults, one Cold Archive. Folder skeleton is
fixed (Vol. 4 §5.1). All programmatic access goes through the Storage
Manager's sync jobs; ad-hoc manual uploads are permitted only in `Executive/`
on the Control Tower (human workspace), and even those get cataloged by the
weekly inventory sweep.

### 3.2 CISO Risk Assessment — Consumer Accounts (Honest and Binding)

Using personal Gmail accounts as an enterprise storage tier carries risks
that must be stated plainly and managed, not wished away:

| Risk | Severity | Mitigation (mandatory) |
|---|---|---|
| Account suspension/lockout (consumer ToS, automated abuse detection) | HIGH | Nothing production-facing ever depends on these accounts; every vault's contents are copies, reconstructible from R2/GitHub (DR-6); inventory-with-checksums held outside the vault |
| Credential compromise (7 separate consumer identities) | HIGH | 2-Step Verification with hardware/passkey factors on all seven; unique passwords in a password manager; recovery emails/phones audited quarterly (RB-8) |
| No org-level control (no admin console, no DLP, no audit logs) | MEDIUM | Client-side encryption makes Google a dumb encrypted disk; catalog provides the audit trail Google can't |
| Confidential/customer data exposure | CRITICAL if unmanaged | Classification policy (Vol. 4 §3): CONFIDENTIAL/RESTRICTED **must** be client-side encrypted before upload; RESTRICTED only in Vault 5/Control Tower with per-tenant keys; plaintext customer data in any Google account is a Sev-1 policy violation |
| ToS friction on automated access | MEDIUM | Official Drive API via OAuth (rclone), conservative rate limits, no service-account impersonation tricks |
| Data residency/compliance questions from gov/enterprise buyers | MEDIUM | Honest posture: Google plane holds only encrypted archives; contractual customer data residency claims reference Cloudflare only |

**Governance verdict:** acceptable as a *continuity* tier now (cost-efficient,
better than no offsite copies), with a defined exit: **decision point D-08
(Vol. 10, Month 9–12)** evaluates migrating the vault roles to Google
Workspace (identity consolidation) and/or GCS/R2-secondary (bulk archive)
once revenue supports it. The architecture makes that migration mechanical:
vault roles + fixed skeletons + catalog `locations` mean "move the vault" is
a re-point, not a redesign.

### 3.3 Account Operations Standard

- Quarterly access review: login test, 2FA device check, recovery info check,
  storage quota check — recorded as a run record.
- The Control Tower's master inventory is generated (not hand-maintained):
  weekly export of the Global Asset Index filtered to `plane=continuity`,
  written as a Sheet/JSON to `_CATALOG/`.
- Sharing between accounts: folder-level, minimum necessary, reviewed
  quarterly; no "anyone with link" on anything above PUBLIC.

## 4. Long-Term Governance Machinery

| Mechanism | Cadence | Output |
|---|---|---|
| Architecture Review Board (founder wearing CEO/CTO/CISO hats now; real board later) | Quarterly | Decision register updates (Vol. 10 §5), architectural-event approvals |
| Policy review (retention, classification) | Annual + on regulation/contract change | ENTERPRISE-CONFIG PRs |
| Estate drift check (Cloudflare, GitHub settings) | Weekly automated | Drift report; violations become issues |
| Compliance scorecard | Monthly automated | KPI dashboard (Vol. 9) |
| PDS amendment process | As needed | PR against the PDS with an entry in the decision register — AI assistants and humans alike must amend, never fork, this spec |

## 5. Consolidated Impact Assessment — Volume 7

| Dimension | Assessment |
|---|---|
| Business impact | Governance pack (charters, policies, registers) is reusable in every enterprise procurement and eventual due-diligence/funding process |
| Technical impact | Config-as-code + drift checks; no production change |
| Security impact | The consumer-account risk is explicitly bounded (encrypted-only, continuity-only) instead of implicit; token and secret hygiene formalized |
| Operational impact | Quarterly review calendar ~4 h/quarter; everything else automated |
| Revenue impact | Indirect but decisive: governance maturity is a gating criterion for MSSP/gov contracts |
| Risk assessment | Residual MEDIUM on consumer accounts until D-08 executes; all other governance risks LOW after Phase 2 |
| Migration strategy | Charters effective immediately (Phase 0); drift checks Phase 1; D-08 evaluation Month 9–12 |
| Rollback strategy | Governance artifacts are documents; reverting any control is a PR |
| Long-term governance | This volume *is* the long-term governance definition; it self-amends via §4 |

---

*End of Volume 7.*
