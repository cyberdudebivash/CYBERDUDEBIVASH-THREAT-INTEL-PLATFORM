# Cyber Watchdog v2 (rollback-compatibility fixture)

Verbatim copies of the implementation on `main` @ `6ac0385d6` (#495), the code
a rollback of PR #496 returns to:

| file | git source | sha256 of the original |
|---|---|---|
| cyber-watchdog.js | `6ac0385:workers/intel-gateway/src/cyber-watchdog.js` | `58b9ea6e7ea9d34ef18a331e0e34e38266e0182d6d108d73dfa58cc23580fb70` |
| watchdog-ledger.js | `6ac0385:workers/intel-gateway/src/watchdog-ledger.js` | `56dabb71b7bfb49f3d1c61ee7bf0b591fd6699274ac9e90ed59e7e9134ada0ec` |

The only edit is the relative path of the `freshness-contract.js` import in
`cyber-watchdog.js` (line 16). `watchdog-rollback-compat.test.js` restores that
line and checks both hashes, so the fixture cannot drift from v2. Do not edit.
