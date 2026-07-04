# Phase 0 Runbook — GitHub Hardening (Items 0.5 / 0.6)
## Applies to all four repositories | Requires repo-admin authority

Repos in scope:

1. `cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM` (production)
2. `cyberdudebivash/CYBERDUDEBIVASH-ENTERPRISE-CONFIG`
3. `cyberdudebivash/CYBERDUDEBIVASH-KNOWLEDGE-OS`
4. `cyberdudebivash/CYBERDUDEBIVASH-PRIVATE-ASSETS`

These are **settings changes only** — no code, no CI, no workflow files are
modified. All are instantly reversible from the same settings pages, which is
the rollback strategy for this runbook.

> Note: secret scanning + push protection on **private** repos requires
> GitHub Advanced Security (paid) or an org plan that includes it. If
> unavailable, apply the fallback in §1b — it provides equivalent pre-push
> protection using free tooling.

---

## §1 Secret Scanning + Push Protection (item 0.5)

Per repo, UI path: **Settings → Code security and analysis** →
enable "Secret scanning" and "Push protection".

CLI equivalent (run as repo admin with `gh` authenticated):

```bash
for R in CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM CYBERDUDEBIVASH-ENTERPRISE-CONFIG \
         CYBERDUDEBIVASH-KNOWLEDGE-OS CYBERDUDEBIVASH-PRIVATE-ASSETS; do
  gh api -X PATCH "repos/cyberdudebivash/$R" \
    -f 'security_and_analysis[secret_scanning][status]=enabled' \
    -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
done
```

Verify:

```bash
gh api repos/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM \
  --jq '.security_and_analysis'
```

### §1b Fallback if Advanced Security is not available (free path)

Add a gitleaks pre-push scan as a local git hook on the operator machine and
as a CI job in the three **non-production** repos (the production repo's CI
is frozen; its protection comes from the hook + review discipline):

```bash
# one-time, per clone:
pipx install gitleaks || brew install gitleaks
printf '#!/bin/sh\nexec gitleaks protect --staged\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## §2 Branch Protection (item 0.6)

Per repo, protect the default branch (`main`): require PRs, block force
pushes and deletions. Admin bypass stays available for solo-founder
emergency operations — the protection's purpose is preventing accidents and
compromised-token pushes, not blocking the owner.

```bash
for R in CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM CYBERDUDEBIVASH-ENTERPRISE-CONFIG \
         CYBERDUDEBIVASH-KNOWLEDGE-OS CYBERDUDEBIVASH-PRIVATE-ASSETS; do
  gh api -X PUT "repos/cyberdudebivash/$R/branches/main/protection" \
    --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false
}
JSON
done
```

Notes:
- `required_approving_review_count: 0` = PR required, self-merge allowed —
  correct for a team of one; raise to 1 when the first engineer joins
  (pre-logged as a governance change in Vol. 7 §2).
- **Production repo caution:** existing automated pipelines
  (intelligence-cycle/guardian commits) push directly to `main`. Before
  enabling on the production repo, confirm those pushes use a PAT/App
  identity that is either exempted via a bypass list or migrated to PRs.
  If they push as the owner with admin rights and `enforce_admins=false`,
  they will continue to work unchanged. **Verify on a low-activity window.**
  If a cycle commit fails after enabling, the rollback is the single API
  call: `gh api -X DELETE repos/cyberdudebivash/<repo>/branches/main/protection`.

Verify:

```bash
gh api repos/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/branches/main/protection \
  --jq '{force: .allow_force_pushes.enabled, del: .allow_deletions.enabled}'
```

## §3 Completion Record

| Repo | Secret scanning | Push protection | Branch protection | Automation verified post-change | Date |
|---|---|---|---|---|---|
| THREAT-INTEL-PLATFORM | ⬜ | ⬜ | ⬜ | ⬜ | — |
| ENTERPRISE-CONFIG | ⬜ | ⬜ | ⬜ | n/a | — |
| KNOWLEDGE-OS | ⬜ | ⬜ | ⬜ | n/a | — |
| PRIVATE-ASSETS | ⬜ | ⬜ | ⬜ | n/a | — |

Record intended settings in `CYBERDUDEBIVASH-ENTERPRISE-CONFIG/github/` as
config-as-code (Vol. 7 §2) so the Phase 1 drift check has a baseline.
