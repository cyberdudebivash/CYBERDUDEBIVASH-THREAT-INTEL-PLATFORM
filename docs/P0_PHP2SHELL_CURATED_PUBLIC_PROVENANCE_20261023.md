# P0 — PHP2Shell curated vendor provenance in the public CTI snapshot
**Review date:** 2026-10-23
**Status:** CODE REVIEW / OFFLINE TESTING REQUIRED — NOT DEPLOYED

## Verified evidence
The official [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5), dated 21 October 2026, explicitly covers **CVE-2026-109618 and CVE-2026-109619**. PHP's own 8.2.35, 8.3.36, 8.4.27 and 8.5.12 announcements link to it. The authoritative vendor statement is independent of the original story's source attribution.

A bounded, read-only check on 23 October 2026 of
`https://intel.cyberdudebivash.com/api/v1/intel/latest.json` reported `generated_at=2026-10-23T06:22:19Z`, **119** records. A **BleepingComputer**-sourced item at
`https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/` contained both CVEs, but its public fields had no independently verified vendor, NVD or CVE reference. The strict `php2shell_coverage_gate.py` therefore could not establish authoritative public-feed provenance from that record.

## Root cause
`scripts/generate_api_manifests.py` runs the mandatory TLP/public sanitizer, then
`project_feed_for_public_latest(sorted_feed_public)`. The explicit
`PUBLIC_LATEST_FIELDS` projection rightly blocks arbitrary `references` keys:
untrusted upstream collections can include private, oversized, incorrect or premium links.
Opening `references` globally would weaken the anonymous API's strict 1 MiB budget and tier boundary.

## Scoped remediation (no production mutation)
`scripts/public_api_sanitizer.py` emits one new `references` entry **only** when:
1. `tlp` is exactly `TLP:CLEAR`;
2. `source_url` equals the full, reviewed BleepingComputer story URL;
3. `cve_id` and/or a bounded list `cve_ids` structurally contains **both** exact CVE identifiers.

It publishes **only the manually reviewed PHP vendor advisory URL** plus fixed attribution and CVE keys. It never copies upstream `references` into the public API. It does not infer IDs from titles, touch risk/CVSS/KEV/exploitation status, upgrade a TLP label, replace `source`/`source_url`, modify canonical feed records, or alter paid manifests.

The reviewed new public reference is:
```json
{
  "references": [{
    "url": "https://www.php.net/archive/2026.php#2026-10-21-5",
    "type": "vendor_advisory",
    "publisher": "PHP Security Team",
    "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"]
  }]
}
```
This is a **curated, explicitly verified linkage for one known advisory**, not general automatic source verification and not evidence the currently deployed feed has already changed.

## Offline verification / acceptance
Run from a clean isolated Git checkout at the reviewed PR SHA:
```powershell
python -m pytest -q tests/test_php2shell_coverage_gate.py
python -m unittest discover -s tests -p 'test_php2shell_coverage_gate.py' -v
```
The added cases check: source attribution preservation, expected gate acceptance, strict exact source and TLP matching, CVE-structured-identity matching, rejection of arbitrary news/attacker URLs, public premium-field exclusion, and no raw-reference leakage.

After merging this change, run the *broader* relevant offline P0 checks on the merged source tree using the reviewed `scripts/p0_release_certify.py` when available (separately proposed in PR #891). Both PRs require source-tree parity review and explicit test results. Do not interpret successful isolated tests as a full production certificate.

For any eventual approved publish: check original feed provenance and TLP; regenerate manifests in a scratch/output-isolated environment; verify public JSON under **1 MiB** before upload; validate exact expected fields and byte-check no private references or premium artifacts; check snapshot timestamp contract (**6 hours**), authenticated PRO/ENTERPRISE payload isolation, and deployment/rollback version; run the live customer PHP2Shell gate after publication. **Do not** edit the 119-item public snapshot in place or invent a new `generated_at` solely to turn a test green.

## Cloudflare and operational cost constraints
This change requires **no API calls at publish time** and stores **one bounded static URL only in a qualifying existing item**. No scheduled polling, paid provider, D1 migration, new Worker binding, remote ingestion replay, CI deployment, or Cloudflare infrastructure change is required by the code diff.

Actual deployment is still gated by the shared Cloudflare account's included-plan Workers, D1, R2 and KV usage; backups and rollback; freshness and collector health; and end-to-end customer acceptance.

**Current release decision: NO-GO.** Code is isolated to a draft PR until audited tests and operator approval.
