# Intelligence Writer Ownership

Authoritative writer/reader map for the platform's core intelligence artifacts.
Written as part of the P0.2 report-continuity root-cause elimination
(2026-08-22). Sourced from direct production log correlation and full script
reads, not estimated -- see `data/quality/post_pipeline_writer_graph.json`
for the exhaustive step-by-step evidence trail this table summarizes.

## Canonical envelope key

`data/stix/feed_manifest.json` is a dict shaped `{"advisories": [...], ...}`.
**`"advisories"` is the one canonical key.** Every script in the table below
that reads or writes this file must check `"advisories"` first. A script that
checks a different key list (`"data"`, `"items"`, `"entries"`, `"intel"`,
...) risks either reading the file as empty when it is not, or writing its
result into an orphaned key nothing else looks at -- this is the exact defect
this PR fixes in `field_preserving_merge.py` (see below).

## Ownership table

| Artifact | Authoritative writer(s) | Secondary readers | Allowed mutators | Forbidden mutators |
|---|---|---|---|---|
| `data/stix/feed_manifest.json` (`"advisories"` key) | `run_pipeline.py` (initial population, Stage 2.2), `report_generator.py` (report_url assignment), `manifest_reconciler.py` (additive sync from `api/feed.json`), `field_preserving_merge.py` (field-preserving merge/sync -- **fixed in this PR** to target `"advisories"`, not an orphaned `"data"` key), `enterprise_scoring_engine.py` (additive `apex_score` block), `ioc_quality_hardener.py` (additive IOC hardening) | `validate_reports.py`, `report_existence_validator.py`, `sync_report_urls.py`, `manifest_sanity_guard.py`, `api_dashboard_contract_validator.py`, and the ~30 P20-P30 certification gates (read-only; see writer graph) | Any script that reads `"advisories"` first, preserves protected fields, and never assigns a `/reports/` `report_url` without verifying the file exists on disk | A script that silently orphans updates into a non-canonical key; a script that copies a `report_url` forward from another source without re-verifying the file survived into the current run's working tree (see "report_url resurrection" below) |
| `api/feed.json` | `run_pipeline.py` (initial), the ~15 `FEED_PATH`-driven enrichers (STAGE 3.1.1b-3.1.22), `field_preserving_merge.py` (`--sync-apex` mode reads it as the merge source) | `sync_report_urls.py`, `generate_api_manifests.py`, most certification gates | Any enricher writing additive fields; must remain a bare JSON list (not a dict envelope) | A writer that promotes `source_url` to `report_url` for an external item (this is a previously-fixed defect class -- see `sync_report_urls.py`'s own history) |
| `reports/*.html` | `report_generator.py` (primary, STAGE 3.2), `generate_intel_reports.py` (repair/materialization pass, STAGE 5.4.0b and `run_pipeline.py`'s `apply_report_materialization_barrier()`) | `validate_reports.py`, `report_existence_validator.py`, `r2_reports_verifier.py`, `build_reports_index.py` | Either of the two writers above, both of which share the same atomic write + minimum-size + HTML-signature validation contract before ever assigning a `report_url` | Any script that assigns/preserves a `/reports/...` `report_url` without first proving the file exists at that exact path in the current working tree |
| `report_url` field (on manifest/feed items) | `report_generator.py`, `generate_intel_reports.py` (both via the shared render+write+validate+assign sequence) | everything else | The two writers above only, and only after file-existence verification | Any reconciliation/merge/dedup step that carries a `report_url` forward from an incoming or previous-run source without re-verifying the file. `field_preserving_merge.py`'s `PROTECTED_FIELDS` list includes `report_url` specifically so it is *preserved* when already-valid, never fabricated when absent -- this is a preservation guarantee, not a materialization one; it must never be read as license to invent one. |
| `dist/` (deploy artifact) | `build_dist_artifact.py` (STAGE 5.4.6) | `dist_artifact_verifier.py`, GitHub Pages deploy action | `build_dist_artifact.py` only, from the certified post-barrier state | Any step after `dist/` is built that mutates `reports/` or the manifest without rebuilding `dist/` |
| R2 report objects (`sentinel-apex-reports` bucket) | `r2_report_publisher.py` (STAGE 3.5a, and STAGE 5.4.0c for reports rendered late in the run). `generate_intel_reports.py --upload-r2` is DEPRECATED (2026-09-26; no caller; removal at P39) | `r2_upload_verifier.py`, `r2_reports_integrity.py`, `r2_reports_verifier.py` | The two writers above; both upload only files that already passed local validation | A writer that uploads to R2 before the corresponding local file has been validated |

## report_url resurrection -- the mechanism this PR closes

A dangling `report_url` (pointing at a file that does not exist) can only
enter `"advisories"` through one of two paths:

1. **A writer assigns a new `/reports/...` `report_url` without verifying
   the file** -- ruled out for `report_generator.py` and
   `generate_intel_reports.py` (both verify before assigning; see the
   `_MIN_REPORT_BYTES`/HTML-signature check in `generate_intel_reports.py`).
2. **A writer preserves/carries forward an existing `report_url` without
   re-verifying it, while operating on a stale or wrongly-keyed view of the
   manifest** -- this is what `field_preserving_merge.py` did before this
   fix. It never carried forward the *wrong* `report_url`, but its inability
   to recognize `"advisories"` meant its careful field-preservation and
   `--cap` logic operated on an orphaned `"data"` key nothing else read,
   while `"advisories"` (the field everything else, including
   `report_existence_validator.py`, actually checks) went stale across runs
   with no mechanism keeping it synchronized with what the rest of the
   pipeline believed was current.

Two defense-in-depth barriers remain in production regardless (per the
mandate's explicit direction not to remove them): `apply_report_
materialization_barrier()` inside `run_pipeline.py`, and STAGE 5.4.0b
immediately before the STAGE 5.4.1 hard-fail gate. Both should report zero
repairs in steady state after this fix (`data/health/report_continuity_
barrier.json`); a persistently non-zero repair count on a clean run is the
signal that a *new* resurrection path has been introduced somewhere and this
document + the writer graph need to be revisited.

## Known-audited, not the drift source

The following were read in full or log-traced during this investigation and
confirmed NOT to contribute to `report_url` staleness or the manifest-shrink
question:

- `manifest_reconciler.py` -- purely additive (`updated_manifest =
  manifest_items + missing`); reads/writes `"advisories"` correctly.
- `ioc_quality_hardener.py` -- reads/writes `"advisories"` correctly on both
  sides (unlike `field_preserving_merge.py`, its read and write key lists
  agree and both check `"advisories"` first).
- `r2_upload.py`, `r2_reports_verifier.py` -- upload/verify R2 state only;
  neither rewrites `feed_manifest.json`.

## Out of scope for this document

The `1356 -> 1115` manifest-count observation traced to `run_pipeline.py`'s
own internal execution (its Stage 2.2 through Stage 3.6c), which sits
entirely before the post-pipeline surface this document and the writer graph
cover. See `data/quality/manifest_shrink_forensics.json` for the full
evidence chain; it is documented there as a candidate for a future,
separately-scoped investigation, not folded into this fix.
