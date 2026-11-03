# Revenue Engine P0 — exact approved source-SHA release identity

Date: 2026-11-03. Scope: production release workflow and public health identity. No production deployment or Cloudflare configuration mutation during implementation.

## Confirmed gap

The currently merged Revenue Engine release workflow validates `status=ok`, service name and `ENGINE.VERSION` when probing `/api/health` after deployment. A stale Worker can return the same version after a GitHub source change. Therefore HTTP 200 and version parity alone cannot substantiate that the exact approved commit is live.

## Control

- The manual release workflow remains restricted to explicit `workflow_dispatch` on `main`, with `inputs.approved_commit_sha == github.sha`. It independently verifies `git rev-parse HEAD == GITHUB_SHA`.
- `scripts/stamp-release-sha.mjs` inserts the exact 40-character lowercase Git SHA as `ENGINE_RELEASE_SHA` **only under `[env.production.vars]` of the ephemeral checked-out Wrangler config**. It fails for malformed SHAs, an absent/duplicated production-vars table, missing engine version or an already declared `ENGINE_RELEASE_SHA`. No secrets, environment variables, KV/D1 IDs, routes, plan IDs or cron schedules are changed by the script.
- A mandatory *post-stamp* `wrangler deploy --env production --dry-run` checks the same generated config used for the explicitly approved production release.
- Both authenticated and unauthenticated health responses add a bounded, non-secret `release_sha` field, which is the validated 40-hex `env.ENGINE_RELEASE_SHA` or null. Existing API fields and the detailed operator-only health checks remain unchanged. An unset/malformed identity is never represented as a valid SHA.
- The hard post-deploy public health acceptance requires HTTP 200, exact engine, version and **`release_sha == GITHUB_SHA`**. Wrong commit, missing stamp, malformed response, another service and stale routing fail closed. It sends no operator secret to the public endpoint.
- Synthetic Node tests cover the CLI, input/duplicate rejection, no-changes to checked-in TOML or existing bindings, stale-source denial, correct health identity, and ongoing prior commercial regressions. Authority and manual deployment workflows both execute them.

## Source of truth and limits

This is **Worker-reported deployment configuration identity**, correlated to the reviewed GitHub checkout. It is stronger than a version-only smoke test, but not cryptographic proof that the compiled Worker binary equals a particular Git commit. Maintain a separate post-release Cloudflare deployment-ID/version check when authenticated provider access is available. Repository CI also does not attest a live route.

The release approval flow remains human-gated. No automatic production deployment, secret rotations, new services, Cloudflare quota increase or paid resource is authorized by this PR. `REVENUE_OPERATOR_ACCESS_MODE` and `REVENUE_QUOTE_V2_ENABLED` remain opt-in; cutover requires dedicated keys, compatibility review, operator-access policy, and positive/negative business acceptance. The revenue and security-researcher incident tickets must remain open pending independent production tests.

## Risk and rollback

Adding a public `release_sha` field is an additive API change, but it reveals a public repository revision identifier. Do not use for private repository secrets. The mandatory SHA requirement intentionally **blocks deployment** until the new Worker code is served by the expected production route. A missing route, stale cache, or propagation delay beyond six bounded health attempts yields NO-GO, never false success. The stamp exists only in an ephemeral GitHub Actions checkout.

Rollback for this source-only change: revert the PR (no production state to restore). If a future production deployment is approved and fails the SHA health gate, review its Cloudflare deployment/version logs and route configuration before deciding whether to roll back to the last proven-good script. Do not bypass the exact-target or authenticated operator controls.
