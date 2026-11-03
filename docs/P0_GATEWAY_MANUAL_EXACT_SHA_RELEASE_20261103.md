# P0 Intel Gateway production release authorization — manual-only, exact main SHA

Date: 2026-11-03. Repo scope: `.github/workflows/deploy-worker.yml`. **Draft source change only**. Neither GitHub source merges nor successful offline regression tests certify a live Cloudflare deployment or customer readiness.

## Confirmed source-level release risk

The pre-change gateway deployment workflow triggers on **push to main** touching `workers/intel-gateway/src/**`, `wrangler.toml`, `config/version.json`, or the deployment workflow itself. The job invokes live `wrangler deploy --env production`, then if that fails uses a bare `wrangler deploy` without an environment argument; it also sets `cancel-in-progress: true`.

Three failure modes conflict with the no-unapproved-production-deployment charter:

1. A normal merge may launch a live Cloudflare write, despite the operator not approving a production release. Source merges must not be equated with release authorization.
2. The default-environment retry can deploy a different Worker environment after a failed named production attempt. A misleading success may mask an incomplete or incorrect release.
3. A newer workflow run may cancel an in-flight upload after it has begun and before exact-commit post-deploy acceptance finishes, leaving release state uncertain.

The previous workflow has a six-attempt public `/api/health/live` SHA gate, which is preserved. The old route-permission exception accepts a provisional HTTP 200 within its upload step, but the later exact SHA check is still mandatory; it does not prove customer authorization or commercial acceptance.

## Isolated source correction

- Remove all `push` triggers. Production releases are only `workflow_dispatch` with explicit `approved_commit_sha` and on `refs/heads/main`.
- Job-level gate requires `inputs.approved_commit_sha == github.sha`. Before the **only** production write, verify that the checkout's `git rev-parse HEAD` and the latest `git ls-remote --exit-code origin refs/heads/main` equal the approved 40-character SHA. Network failure, stale approval, malformed SHA, wrong branch or wrong commit **deny deployment**.
- Keep `concurrency.group: worker-deploy` but set `cancel-in-progress: false`, so an upload cannot be canceled by a newer dispatch before its health acceptance completes.
- Attempt `wrangler deploy --env production` only, once, with no bare `wrangler deploy` retry. Preserve the existing route-permission detection but label the result **provisional** until the existing six-attempt exact public SHA assertion and source/version governance succeed.
- A preexisting step labeled "CDB_JWT_SECRET presence check (HARD FAIL)" actually tolerated an absent production signing secret and fell back to the default environment. Replace it with **one named-production-only metadata lookup** and a minimal, nonlogging JSON validator. Any API/read failure, malformed listing or missing exact secret name aborts deployment before the production write. No secret values are read or printed.
- Add mandatory offline workflow contract tests for the dispatch-only trigger, commit approval, fresh-main proof, no-interrupt policy, production-only target, mandatory JWT signing-secret lookup, and post-deploy exact SHA gate. Run them in the existing pull-request Intel Gateway Regression Gate **and** in the manual release workflow before Cloudflare calls.

## Commercial and Cloudflare cost guard

No additional Workers, R2, D1, KV, Access policies, secrets, metered resources or quota changes. Manual-only releases avoid unnecessary Cloudflare writes on code merges, reduce accidental usage, and preserve a reviewable preflight. Requiring `git ls-remote` only once at the last write checkpoint adds a repository read, not a Cloudflare operation. Gate failure is safe and leaves production unchanged when it occurs before the deploy step.

A normal merge can still trigger **other** independent workflows and public Pages artifacts; audit other deployment pathways before merging this sensitive workflow change. Historical commits and in-progress runs might already have invoked the old trigger. A merged source change does not retroactively cancel those runs. Do not claim that a prior merge did not deploy without actual GitHub run logs and Cloudflare deployment identity.

## Release procedure — only after separately authorized GO

1. Confirm current GitHub branch, open PRs and required green checks. Inspect all workflows and account deployment history to establish the known-good production baseline.
2. Confirm Cloudflare Workers usage/headroom is within the existing paid/free plan allowance. Do not request new paid resources or increase quotas.
3. Authorize a specific reviewed main commit SHA and obtain the production release owner’s explicit GO.
4. Manually dispatch **deploy-worker** on main with `approved_commit_sha=<exact 40-char main SHA>`. Never dispatch a shortened or stale SHA. Do not manually run a separate Wrangler deployment at the same time.
5. Require prewrite current-main verification, the named production deployment step and postdeploy public `deploy_commit_sha == approved SHA` check. Inspect provider deployments/route mapping and billing.
6. Run independently authorized customer acceptance: authentication, free/paid quota, quota-warning queue acknowledgment, operator Access identity OFF/required compatibility, payment verification/webhooks, report download, and upgrade checkout. Record results, error rates, rollback and incident evidence.
7. If any acceptance fails, **NO-GO**. Only an authorized release owner may execute a documented rollback to the last known-good reviewed source/configuration and reverify.

## Explicit limitations

There is no fresh live Cloudflare API access/credential verification in this source-only PR. Existing workflow's routes-only fallback may still report a provisional live HTTP 200 before the later strict SHA check, and the production route can change between the last main check and the upload. Exact SHA health checks certify observed source identity, not payment success, reliability, customer delivery or cryptographic binary attestation.

**Do not merge/deploy automatically on the assumption that editing the deployment workflow is harmless.** The old workflow itself has a push-based trigger, so merging must be coordinated with the actual repo Actions settings, existing queued jobs, Cloudflare authorization, and approved production release process. The intent is to *eliminate* involuntary future production uploads, but controlled rollout still requires authorization.
