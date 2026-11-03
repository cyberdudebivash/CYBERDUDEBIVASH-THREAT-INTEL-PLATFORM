# Revenue Engine P0 — exact-environment deploy guard and fail-closed health

## Confirmed source-level release safety defect

The previous manual deployment workflow executed `wrangler deploy --env production`, but on failure retried `wrangler deploy` **without an environment selector**. The default and named environment are separately declared in `workers/revenue-engine/wrangler.toml` and can diverge. A separately permitted SHA-based approval for `main` does not authorize changing the target environment after a failed deploy.

Its public health smoke step also used `continue-on-error: true` and treated malformed/unreachable responses as informational. An HTTP 200 from an older Worker cannot attest a newly approved SHA.

## Proposed isolated source-only remediation

- Keep the existing exact-main-SHA `workflow_dispatch` guard. Remove the default-environment fallback entirely.
- Treat **any** nonzero named-environment Wrangler exit code as a failed release, including suspected routes/DNS permission problems. Emit diagnostic instructions; never reinterpret a 200 from an existing route as proof that the intended binary was uploaded.
- Require post-deploy public health to respond HTTP 200 with JSON `status=ok`, `engine=SENTINEL-REVENUE-ENGINE`, and the version declared under `env.production.vars.ENGINE_VERSION`. Six bounded GET retries; failure is a hard release blocker. No admin credentials sent or health response logged.
- Check the health predicate using deterministic offline Node tests; statically guard the workflow against restored default fallback and nonblocking smoke.
- Gate these tests on changes to both the release workflow and its verification script.

## Explicit remaining limitations

- **Still no deployed-SHA attestation:** endpoint version is a release identity check, not a code hash. Exact deployed Worker build/version must be independently obtained from Cloudflare before researcher closure or release certification.
- The manual workflow currently installs `wrangler@3`, whereas the CI dry-run uses pinned `wrangler@4.127.0`. Do not call CLI parity verified; separately pin and validate the same toolchain after an authorized compatibility assessment. This proposal does not change CLI major versions.
- A successful protected workflow run is not approval to activate the opt-in `REVENUE_OPERATOR_ACCESS_MODE` or `REVENUE_QUOTE_V2_ENABLED`. Those still require explicit secrets, Cloudflare Access policy, operator and customer migration, budget review and end-to-end sales acceptance.
- The existing public health URL may lack DNS or route permissions; in that case a rollout must fail safely and remain BLOCKED until an authorized operator resolves the environment, not silently publish to another target.

No production deployment, secret rotation, new metered Cloudflare resources, or customer database mutation is made in this branch.
