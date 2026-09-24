# watchdog-v2-safe-rollback

The only supported rollback target for the Intel Gateway once Cyber Watchdog v3
has stored a signed webhook destination. Raw `6ac0385` is **not** supported:
it can send unsigned intelligence to destinations written by v3.

* `manifest.json`: base commit, SHA-256 of the replaced base files and of each overlay file, and the digest of the built worker tree.
* `overlay/`: the four reviewed files that replace their `6ac0385` versions.
* `build.mjs`: deterministic build; fails on any hash mismatch.

```
node deploy/cyber-watchdog/safe-rollback/build.mjs --out /tmp/wd-safe-rollback
cd /tmp/wd-safe-rollback/workers/intel-gateway && npx wrangler@3.114.17 deploy --env production
```

Runbook, expected behavior and roll-forward: `docs/CYBER_WATCHDOG_P3.md`, section 13.
Do not edit the overlay without re-recording the manifest (`build.mjs --record`) and
re-running `watchdog-rollback-matrix.test.js` and the negative controls.
