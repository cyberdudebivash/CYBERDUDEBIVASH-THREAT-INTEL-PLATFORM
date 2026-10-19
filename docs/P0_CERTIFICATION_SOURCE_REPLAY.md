# P0 — Offline certification registry replay (read-only)

**Purpose:** Distinguish source-window coverage gaps from persisted certification outcomes using **the production Worker's existing** `resolveCertification()` function. This is a source-state reproduction, **not an independently verified R2 attestation** and **not customer release approval**.

## Inputs — six local JSON snapshots

Use copies already exported through an **approved read-only** operator process, all collected from the **same environment and consistent point in time**. The command makes zero HTTP, R2, Worker, or Cloudflare API requests; no credentials belong in the snapshots.

| CLI option | R2 object represented |
| --- | --- |
| `--catalog` | `api/reports/index.json` (canonical ungated source) |
| `--certification-index` | `certification/index.json` |
| `--latest-pro` | `api/v1/intel/latest_pro.json` |
| `--latest` | `api/v1/intel/latest.json` |
| `--top10` | `api/v1/intel/top10.json` |
| `--apex` | `api/v1/intel/apex.json` |

**Never substitute the public** `/api/reports/index.json` **v2 customer-ready projection for the ungated catalog:** when all reports are withheld, that projection contains no report IDs and would fabricate an empty source inventory.

Example, from your local repository checkout:

```powershell
node scripts/certification_registry_replay.mjs `
  --catalog C:\CDB\evidence\catalog.json `
  --certification-index C:\CDB\evidence\certification-index.json `
  --latest-pro C:\CDB\evidence\latest-pro.json `
  --latest C:\CDB\evidence\latest.json `
  --top10 C:\CDB\evidence\top10.json `
  --apex C:\CDB\evidence\apex.json
```

The script validates document shape, report-ID uniqueness, policy version, source completeness, local size bounds, and then enumerates aggregate states. It emits **no report IDs, full text, raw indicators, tokens or entitlement data**. Persisted records that are trusted in this replay remain *unverified against independent R2/object delivery*; even `LOCAL_ALL_READY_NOT_DELIVERY_CERTIFIED` is **not a production release result**.

Exit 2 means withheld, not evaluated, missing or invalid evidence. Exit 0 means local replay completed with all candidate states ready, **never** customer release. The actual Worker version, R2 object integrity, TLP policy, tenant authorization, paid checkout and 2-cycle publishing gates are all separate mandatory checks.

**Budget:** zero new Cloudflare operations. No PUT, upload, purge, cron, charges or policy-threshold modification. **Do not automate collection or run unknown account-wide reads** without confirming shared-account headroom.

Offline regression test:

```powershell
node --test tests/certification-registry-replay.test.mjs
```

Historical 2026-08-26 repository sources had 500 catalog entries, with 421 outside the four rolling feed windows. This audit allows operators to check whether those historical entries have *valid cached certification evidence*; the 500-entry repository result **cannot be extrapolated to the current live 52 withheld**.
