# PHP2Shell P0 — offline coordinated-bundle preflight

**Status:** REVIEW ONLY. **PRODUCTION NO-GO.** This tool cannot approve any Cloudflare R2 publication.

## Origin of this change

The 23 Oct 2026 operator live-gate result in `log-705.txt` was `passed:false`, with `missing_authoritative_source` and `not_verified_in_public_feed` for both `CVE-2026-109618` and `CVE-2026-109619`. The authenticated customer endpoint continued serving a public item with the CVEs and the original BleepingComputer `source_url`, but **without** the manually reviewed PHP vendor advisory reference. Merged PR #892 fixed the **source projection**; it did not independently publish a new R2 manifest. Source `main` at this change's base: `6e941de6fc7e1dd8d3e2f125f6300f79ac31cee9` (merged previous publication-recovery runbook #893).

This PR adds **offline-only code and synthetic tests**; it does not trigger CI, a GitHub Actions publisher, R2, D1, KV, or remote Worker traffic.

## How to run safely

First retrieve a complete **authorized canonical feed** using the existing read-only R2/operator export process, recording bucket/key, remote version or ETag, `LastModified`, byte length and independently captured SHA-256 in your private evidence store. **Do not** upload a Git-committed August-era manifest, copy the anonymous API response into `api/feed.json`, or silently repair a missing source record by inventing a CVE.

From a **NEW isolated worktree**, using the PR candidate's **exact commit** (not an active or dirty working checkout), stage the verified canonical JSON in its `api/feed.json`. The existing `scripts/generate_api_manifests.py` is a **local writer** that may rewrite the staged canonical feed during the R44 publication filter; it is authorized for the isolated rehearsal only. It is **not** authorized to upload, resync, trigger CI or change production.

Once a complete local manifest bundle is generated with no errors, and before changing files again, run:

```powershell
$ErrorActionPreference = "Stop"
# Run ONLY from the isolated checkout root with a reviewed, complete canonical feed.
$Feed = "api/feed.json"
$Bundles = "api/v1/intel"

$CanonicalDigest = (Get-FileHash -LiteralPath $Feed -Algorithm SHA256).Hash.ToLowerInvariant()
# Compare $CanonicalDigest with the expected digest for this exact post-generator
# canonical snapshot in your operator's protected evidence. A locally computed
# digest alone does NOT prove that the source was retrieved from current R2.

python scripts/p0_php2shell_bundle_preflight.py `
  --canonical $Feed `
  --bundle-dir $Bundles `
  --expected-canonical-sha256 $CanonicalDigest

if ($LASTEXITCODE -ne 0) {
    throw "OFFLINE BUNDLE PREFLIGHT NO-GO"
}
Write-Host "OFFLINE BUNDLE PREFLIGHT PASS — REMOTE PUBLICATION NOT AUTHORIZED"
```

**Do not run `r2_resync_manifests.py`, `r2_upload.py`, a Cloudflare CLI migration/deploy, or a GitHub publisher from these instructions.**

For Python regression tests (synthetic fixtures, no Cloudflare):
```powershell
python -m pytest -q tests/test_p0_php2shell_bundle_preflight.py
python scripts/p0_release_certify.py
```
Both must exit 0. The legacy P0 suite does **not** automatically include this new test; run it separately.

### What is checked

- Exact **source URL** and **both structured CVEs**, no duplicate canonical news records, explicitly `TLP:CLEAR` and real upstream TLP-policy authorization.
- Canonical SHA-256 byte identity (relative to operator-pinned post-generator evidence), and the internal **manifest source canonical JSON hash**.
- All `latest`, `latest_pro`, `top10`, `apex` and `manifest` siblings exist; registry and per-object content checksums, counts and `generated_at` agree.
- Public `latest.json` actual byte length **<= 1,048,576**; freshness uses the canonical contract; full existing PHP2Shell gate passes.
- Public projection contains only allowlisted fields and a **single fixed**, curated vendor reference on the exact reviewed article; no arbitrary nested references or paid/enterprise properties; `latest_pro` does not carry ENTERPRISE-only fields.
- **Real Worker** `p0_r2_public_feed_diagnostic.mjs` is invoked as a read-only local Node subprocess with Cloudflare/R2 credentials omitted. It must return `DELIVERABLE`, TLP PASS and FRESH.
- JSON output contains only counts, digests and safe codes; no article text, private URLs, user data, or credentials.

### Limits and mandatory external gates

This script neither authenticates the **remote origin** of the provided canonical file nor proves that the underlying sources are recently published; `generated_at` is a snapshot timestamp, not a CVE observation or reporting date. It does not perform R2 version verification, Cloudflare shared-account cost calculations, live customer paid-tier authentication, end-to-end payment/fulfillment, live feed R2 promotion, or rollback. Those remain independent blockers.

If a source item is missing, the public reference is missing, the archive is stale, checksums diverge, TLP denies, or Worker cannot run, the tool returns `passed:false` and a nonzero exit. **Never modify this gate to make the log green.**

Before any future authorized release, preserve current live R2 object versions for all affected keys, confirm account-wide included-plan limits and the exact bounded PUT plan, generate the *complete* coordinated manifest set, and plan a verified rollback. Only then explicitly approve the guarded publication and independently rerun the live `php2shell_coverage_gate.py --url` plus real customer acceptance.