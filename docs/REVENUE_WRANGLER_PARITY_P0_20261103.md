# Revenue Engine P0 — exact deploy toolchain and CI parity (2026-11-03)

## Observed source drift

The manual production deployment workflow installs the **floating** legacy `wrangler@3`, while the mandatory Revenue Manual Payment Authority Gate only dry-ran `wrangler@4.127.0`. The deploy workflow also installs unpinned `esbuild` while CI bundles with `esbuild@0.25.9`. This discrepancy lets a green CI result certify a different Cloudflare CLI and bundler from the production release executable.

Cloudflare's published Wrangler v3-to-v4 migration guide identifies bundled esbuild changes, command-default behavior changes, and deprecated flags. Major-version differences require explicit parity verification rather than an assumption that a v4 dry-run validates a v3 deployment. Source: https://developers.cloudflare.com/workers/wrangler/migration/update-v3-to-v4/ . NPM currently tags `wrangler@3.114.17` as `legacy`; source: https://www.npmjs.com/package/wrangler?activeTab=versions .

## Proposed release-gate changes

- Keep the production CLI in its existing v3 major series; pin it to `wrangler@3.114.17` instead of silently upgrading production to v4.
- Pin the production pre-bundle `esbuild@0.25.9`, the version already used by the exact production entrypoint authority-gate preflight.
- Run mandatory offline `wrangler@3.114.17 deploy --env production --dry-run` against the same config as the actual release executable. Preserve the existing v4.127.0 dry-run as a separate forward-compatibility safeguard.
- Execute the existing release-guard regression in both the authority gate and guarded manual release gate, with new static checks that exact versions and approved target-selection constraints remain pinned.
- No DNS/Worker changes, environment variable changes, secret changes, new metered services, or deployment in this PR.

## Remaining production NO-GO

Do not trigger deploy until exact-head gates pass, the billing regression and customer/authorization matrix are reviewed, manual Cloudflare account permissions are confirmed, and the **exact deployed Worker SHA** can be verified independently. HTTP health engine/version is not a SHA attestation. Never activate `REVENUE_OPERATOR_ACCESS_MODE=required` or `REVENUE_QUOTE_V2_ENABLED=true` without an approved cutover, independent keys, and authorized post-deploy negative/positive testing.

Rollback: revert this source-only CI/toolchain PR; no runtime state or customer data requires rollback. If a future release's v3 dry-run is incompatible, block the release and evaluate a separately tested v4 migration rather than weakening the gate.
