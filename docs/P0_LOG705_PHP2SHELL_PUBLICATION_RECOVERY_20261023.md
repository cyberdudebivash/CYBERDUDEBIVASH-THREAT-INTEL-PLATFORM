# P0 log-705 — PHP2Shell customer-publication recovery (23 Oct 2026)

**Decision:** Source-code P0 PASS; **live customer coverage NO-GO**. No remote data write or deployment authorized.

## 1. Evidence: precisely which gate failed

An isolated Windows operator checkout of `2a63842b0a09b65fda3c0c3b5bf1af3e5150c357` (PR #892) passed Python syntax, **20/20 PHP2Shell tests + 16 subtests**, and the expanded offline P0 gate (**80/80 + 16 subtests**, `passed=true`). The merged `main` commit is `2f27c65e1652447f7950e03566e31f40ff3fd685`; its Git tree `98f946f6653c3fc195b3f09424f513ccf0ff1e93` is **identical** to the certified checkout.

The next operator command, a single bounded read-only request to
`https://intel.cyberdudebivash.com/api/v1/intel/latest.json`, correctly returned `passed=false` from
`scripts/php2shell_coverage_gate.py`:
```json
{"errors": [
 "CVE-2026-109618:missing_authoritative_source",
 "CVE-2026-109618:not_verified_in_public_feed",
 "CVE-2026-109619:missing_authoritative_source",
 "CVE-2026-109619:not_verified_in_public_feed"
], "gate": "php2shell_public_coverage", "passed": false}
```
Prior live snapshot inspection found *both* CVE IDs in an existing **BleepingComputer** record, but without the now-curated PHP vendor reference. The gate's `not_verified` error means authoritative source coverage failed, **not** that both CVE identifiers are necessarily absent.

The reviewed PHP Security Team vendor advisory is
`https://www.php.net/archive/2026.php#2026-10-21-5`. Original news `source`/`source_url` must be retained, not rewritten.

## 2. True publication architecture and hazards

- `scripts/generate_api_manifests.py` generates `api/v1/intel/latest.json` from `api/feed.json`, with a mandatory TLP partition, R44 publication boundary, deduplication, public field projection, and a **1 MiB** output cap. PR #892 adds the vetted vendor reference only after the original source, both exact CVE IDs and `TLP:CLEAR` match.
- `.github/workflows/sentinel-apex.yml` first executes `scripts/r2_upload.py` during Stage 3.5, then **regenerates** manifests after enrichment at Stage 3.93.19, validates them at Stage 3.93.5, and finally runs `scripts/r2_resync_manifests.py` at Stage 3.93.6. The workflow treats some R2 resync failures as **nonfatal**, so a later nominal pipeline continuation is not proof that the public R2 object changed.
- `r2_resync_manifests.py` lists multiple R2 destinations, including `api/feed.json`, `api/v1/intel/{latest,top10,apex,manifest,ai_summary}.json` and certification artifacts. **Do NOT run it to fix a single CVE without a whole-batch cost/consistency review.**
- Before writing `latest.json`, `r2_resync_manifests.py::assert_worker_deliverable_latest` runs the Worker boundary diagnostic (`scripts/p0_r2_public_feed_diagnostic.mjs`) on a TLP-sanitized temporary copy. This must PASS. Some deployment workflow error branches only warn; an operator must inspect actual exit codes and remote objects.
- The committed `api/v1/intel/latest.json` in Git historically predates the live R2 snapshots (not authoritative). **NEVER upload the old checkout JSON or simply copy the public latest.json back into a canonical feed**. Anonymous public JSON is projected and may omit the full canonical and PRO data.
- GitHub Actions billing has previously blocked automation; do not assume merge, push, cron or workflow scheduling published anything. Do not enable cloud CI deployment merely to remediate this issue.

## 3. Required preflight — read-only first, then local-only rehearsal

1. **Freeze evidence without mutation:** record UTC observation time, the live endpoint's reported `generated_at`, `count`, both CVE records' `source_url` and `references` (redact user/session data), HTTP headers, and the current deployed Worker version. Record the current *R2* object version/ETag/LastModified for `api/feed.json`, `api/v1/intel/latest.json`, `manifest.json`, `top10.json` and the paired paid manifest. Do not paste credentials.
2. **Account-wide budget:** inspect combined Cloudflare Workers, D1, KV, R2, and any other enabled billable feature usage for ALL ecosystem platforms. Confirm upload/read request budget and existing object version retention; no new Cloudflare plan, scheduler, quota overage or unbounded replay.
3. **Acquire actual canonical source:** obtain an authorized, proven recent snapshot from the R2/pipeline state authority with captured SHA-256 and object identity, **not** an August Git manifest or the anonymous `latest.json`. Confirm the full source has the exact BleepingComputer article URL, both exact CVE identifiers, and reviewed TLP eligibility. Distinguish a source record's real timestamp from a newly assigned manifest `generated_at`: **a freshly generated manifest does not prove the underlying intelligence is fresh**.
4. **Rehearse in a new detached local worktree** at the merged code snapshot `2f27c65e1652447f7950e03566e31f40ff3fd685`; preserve dirty operator workspaces and all prior audit folders. Copy the verified canonical `api/feed.json` into this disposable worktree **only**. Run the existing local generator `python scripts/generate_api_manifests.py` there; this writes local outputs and can rewrite the local canonical file, so never run it in the original checkout or against mounted production state.
5. Verify offline outputs with `python scripts/validate_api_manifests.py`, `python scripts/php2shell_coverage_gate.py --file api/v1/intel/latest.json`, and `node scripts/p0_r2_public_feed_diagnostic.mjs api/v1/intel/latest.json`. Require **all commands exit 0**; inspect the diagnostic JSON verdict, freshness and public TLP boundary. Confirm that the vetted `references` survives the TLP/R2 sanitizer, not merely the in-memory projection.
6. Confirm JSON byte length **<= 1,048,576**, absence of paid/internal fields in public output, stable original news attribution, both required identifiers, valid vendor advisory link, consistent `count`/manifest hashes, usable PRO output, no unexpected source losses, and no restricted record leakage. Compare to the frozen live baseline and collect an actionable diff. Do not pad or overwrite timestamps to force success.
7. **Release authorization checkpoint:** record exact candidate SHA/tree, canonical feed source and checksum, generated manifest hashes, any backup/version/rollback identifiers and expected R2 PUT count/cost. Get explicit operator approval of the coordinated publication batch and its customer cutover before any Cloudflare write.

### Local-only operator commands AFTER a reviewed canonical feed is staged

From the **new disposable worktree root only**, and only after verifying that its `api/feed.json` is the reviewed complete canonical source:

```powershell
$ErrorActionPreference = "Stop"
python scripts/generate_api_manifests.py
if ($LASTEXITCODE -ne 0) { throw "Local manifest generation blocked" }
python scripts/validate_api_manifests.py
if ($LASTEXITCODE -ne 0) { throw "Manifest integrity blocked" }
python scripts/php2shell_coverage_gate.py --file api/v1/intel/latest.json
if ($LASTEXITCODE -ne 0) { throw "PHP2Shell projected public feed blocked" }
node scripts/p0_r2_public_feed_diagnostic.mjs api/v1/intel/latest.json
if ($LASTEXITCODE -ne 0) { throw "Worker delivery simulator blocked" }
$bytes = (Get-Item -LiteralPath "api/v1/intel/latest.json").Length
if ($bytes -gt 1048576) { throw "Public latest exceeds 1 MiB: $bytes" }
Write-Host "LOCAL REHEARSAL PASSED; NO REMOTE PUBLICATION AUTHORIZED"
```

This preview creates **local** generated files; it is not a remote deployment, does not automatically update R2, and is **not** sufficient evidence of actual feed freshness or of the remote paid-tier boundary.

## 4. Controlled coordinated release — only after separate authorization

When the owner has approved a verified and complete release manifest set, use only the established guarded/manual publisher procedure after inspecting its exact PUT plan and cost limit. **Do not invoke the multi-key `r2_resync_manifests.py` blindly** or perform a single-object write that leaves `manifest.json`/paid-tier hashes inconsistent.

Fail closed on any upload, version, integrity, premium/TLP, freshness or cache error. Preserve the prior R2 object versions and exact rollback steps **before** modifying a key. Confirm new R2 versions, Worker readback, and any natural cache TTL before evaluating HTTP output. Never claim success because the script printed a nominal summary after a nonfatal workflow warning.

After the approved publish, check the live URL with:
```powershell
python scripts/php2shell_coverage_gate.py --url "https://intel.cyberdudebivash.com/api/v1/intel/latest.json"
```
Then check response freshness, dashboard/API agreement, premium authorization, negative controls and rollback readiness. Live check **must** return `passed:true`. A successful source test does not certify end-to-end commercial production release.

## 5. Current GO / NO-GO ledger

| Gate | State |
| --- | --- |
| PR #892 source P0 (20/20 target, 80/80 expanded) | PASS |
| Main SHA source-tree identity to certified commit | PASS |
| Live PHP2Shell authoritative public-feed provenance | **FAIL** (log-705) |
| Current full canonical source and mutation-safe rehearsal | NOT VERIFIED |
| R2 object baselines, version/rollback, and shared Cloudflare quota | NOT VERIFIED |
| Coordinated publication/Worker readback | NOT PERFORMED |
| Global customer release and paid features E2E | **NO-GO** |

**Never turn a red gate green by inventing intelligence, loosening the source allowlist, changing the CVE IDs, or manufacturing `generated_at`.**