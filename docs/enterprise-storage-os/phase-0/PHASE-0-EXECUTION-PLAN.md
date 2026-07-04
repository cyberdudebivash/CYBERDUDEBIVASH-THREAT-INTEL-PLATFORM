# Phase 0 — Ratification & Foundations: Execution Plan & Status Tracker
## Enterprise Storage OS — PDS v1.0 | Target: complete within 1 week of ratification

**Ratification status:** PDS v1.0 merged to production `main` — Phase 0 is ACTIVE.

Phase 0 changes **no production code and no production infrastructure**. It is
governance, account hardening, and preparation. Every item below is safe to
execute independently and requires no downtime.

---

## Execution Tracker

| # | Item | Owner | How | Status | Verification Evidence |
|---|---|---|---|---|---|
| 0.1 | Ratify PDS v1.0 and merge to production `main` | Claude (this session) | Validation gates + merge | ✅ DONE | Regression 21/21 PASS; P33 WORLDWIDE_RELEASE, 0 blockers; docs-only diff |
| 0.2 | Mirror PDS to `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/docs/ENTERPRISE-OPERATING-SPEC/` | Bivash (or Claude session with repo added) | [pds-mirror-package.md](pds-mirror-package.md) | ⬜ PENDING | Mirror commit SHA recorded here |
| 0.3 | Harden all 7 Google accounts (2FA/passkeys, recovery info, unique passwords in password manager) | Bivash | [runbook-google-account-hardening.md](runbook-google-account-hardening.md) | ⬜ PENDING | Hardening checklist table completed per account |
| 0.4 | Create fixed Drive folder skeleton in all 7 accounts (Vol. 4 §5.1) | Bivash | [setup-google-drive-skeleton.sh](setup-google-drive-skeleton.sh) (rclone) or manual per runbook | ⬜ PENDING | `_CATALOG/skeleton-created.json` present in each account |
| 0.5 | Enable secret scanning + push protection on all 4 repos | Bivash (repo admin required) | [github-hardening-checklist.md](github-hardening-checklist.md) §1 | ⬜ PENDING | Settings screenshots or `gh api` output attached |
| 0.6 | Enable branch protection on default branches of all 4 repos | Bivash (repo admin required) | [github-hardening-checklist.md](github-hardening-checklist.md) §2 | ⬜ PENDING | `gh api` output per repo |
| 0.7 | Stand up token registry; enumerate ALL live Cloudflare tokens + GitHub PATs; re-scope or revoke any broad token | Bivash | [token-registry-template.md](token-registry-template.md) | ⬜ PENDING | Registry file committed to ENTERPRISE-CONFIG `security/` |
| 0.8 | Secret scan of all Storage OS documents before production merge | Claude (this session) | Pattern scan (API keys, PATs, AWS keys, private keys, live payment keys) over all 17 PDS files; GitHub Advanced Security API confirmed unavailable on this private repo → §1b gitleaks fallback in the hardening checklist applies | ✅ DONE | 0 findings, 2026-07-04 |
| 0.9 | Seal continuity dossier v1 (credential list locations, key material plan, PDS version, contacts) | Bivash | Runbook RB-8 (Vol. 6 §3) | ⬜ PENDING | Sealed package existence + location noted (not contents) |

## Exit Criteria (from Vol. 10, Phase 0)

- [x] PDS merged (production repo) — **met**
- [ ] PDS mirrored (ENTERPRISE-CONFIG) — pending 0.2
- [ ] 7/7 accounts hardened — pending 0.3–0.4
- [ ] Token registry complete — pending 0.7
- [ ] Repo protections enabled — pending 0.5–0.6

When all boxes are checked, update this file's status line and open Phase 1
(control plane online, observe-only) per Vol. 10 §2.

## Rules of Engagement (restated)

- No item in Phase 0 touches Workers, R2, KV, routes, schemas, auth, or CI
  stages of the production platform.
- Items marked "Bivash" require account owner or repo admin authority that
  automation deliberately does not hold — do not delegate them to tokens.
- Record completion evidence in this file via normal PRs; this tracker is the
  auditable Phase 0 record.
