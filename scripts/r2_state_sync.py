#!/usr/bin/env python3
"""
scripts/r2_state_sync.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Cross-Run Intel State R2 Sync (P0 FIX)
================================================================================
Root cause fixed: main's branch ruleset now requires "Changes must be made
through a pull request", so multi-source-intel.yml's and sentinel-apex.yml's
direct `git push origin main` for these three files has been rejected on
every scheduled run since ~2026-08-26 -- silently, until the companion fix in
this same effort made both push-exhaustion paths loud (see
tests/test_git_publish_no_silent_push_failure.py). true_intel_ingestor.py was
genuinely fetching fresh intelligence every run (confirmed live: 227 new RSS
items in one run alone) but every byte of the resulting state was discarded
before reaching main, so every run started from the same frozen 2026-08-26
state -- this is the direct mechanism behind api/feed.json's generated_at
staying frozen despite dozens of "green" pipeline runs in between.

Extends the pattern already reviewed and approved for issue #274 / PR #293
(api/ai/{tracker,health,executive-brief,monetization}.json moved off git onto
R2) to the four files true_intel_ingestor.py's and sentinel-apex.yml's
own pipeline's cross-run state actually depends on:

  data/cache/feed_state.json    -- per-source last_seen timestamps + reason
                                    codes. Read+written every run by
                                    true_intel_ingestor.py; also read by
                                    scripts/source_fabric_health.py (invoked
                                    from sentinel-apex.yml) and
                                    scripts/intel_dedup_engine.py.
  data/processed_intel.json     -- SHA256 dedup fingerprint store. Read+
                                    written every run by
                                    true_intel_ingestor.py; prevents
                                    reprocessing already-seen items.
  data/stix/feed_manifest.json  -- the raw accumulated intel items. Written
                                    (additive merge) by true_intel_ingestor.py;
                                    read AND further enriched (MITRE tags, IOC
                                    hardening, quality scoring, dedup) by
                                    dozens of call sites throughout
                                    scripts/run_pipeline.py, which is the
                                    Single Source of Truth this file's own
                                    docstring at line 2168 describes it as.
  data/feed_manifest.json       -- the EII-enriched manifest (distinct file,
                                    NOT the same as data/stix/feed_manifest.json
                                    above). Read-then-patched in place by
                                    run_pipeline.py, apex_quality_field_backfill.py,
                                    cve_id_backfill.py, actor_attribution_enricher.py,
                                    generate_advisory_pdfs.py and
                                    threat_graph_engine.py, all within
                                    sentinel-apex.yml -- and, like the
                                    three files above, one of
                                    safe_git_commit.py's CRITICAL files whose
                                    git push was being silently rejected by
                                    the same root cause.

Unlike issue #274's AI-tracker files (pure output, regenerated fresh every
run, no need to read prior state back in), these four are genuinely
bidirectional cross-run state that multi-source-intel.yml and/or
sentinel-apex.yml read at the START of their run and write back at the
END -- so this is a download-before/upload-after wrapper around each
workflow's existing processing, not a one-way "stop committing, start
uploading" change. Every consumer above keeps reading/writing the exact same
local file paths it always has; this script's only job is making sure the
freshest cross-workflow copy is sitting at that path before those consumers
run, and that whatever they leave there gets published back to R2 after.

Concurrency note: R2 objects are plain last-write-wins storage, not
transactional. multi-source-intel.yml (cron '45 1,5,9,13,17,21') and
sentinel-apex.yml (cron '0,4,8,12,16,20') are deliberately staggered by
the workflows' own existing schedule comments specifically to avoid
overlapping writes to this same state -- this script does not add its own
locking on top of that existing mitigation, and does not claim to. If a run
overruns into the next window, last-write-wins is the accepted risk; there
is no stronger coordination primitive available from plain R2 object storage
without introducing a new dependency this fix's scope doesn't justify.

Usage:
  python3 scripts/r2_state_sync.py --download   # run BEFORE ingestion/pipeline
  python3 scripts/r2_state_sync.py --upload     # run AFTER ingestion/pipeline

Environment variables (same names already used by scripts/r2_upload.py):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  AWS_ACCESS_KEY_ID        -- R2 access key   (mapped from CF_R2_ACCESS_KEY_ID)
  AWS_SECRET_ACCESS_KEY    -- R2 secret key   (mapped from CF_R2_SECRET_ACCESS_KEY)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import pathlib
import sys
import time

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from r2_upload import (  # noqa: E402
    BUCKET_DATA,
    get_credentials,
    install_awscli,
    s3_cp,
    s3_get,
    s3_sync,
    s3_sync_download,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2-state-sync] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("r2-state-sync")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Single source of truth for which local paths are R2-authoritative state,
# and what key each lives under.
#
# data/stix/feed_manifest.json MUST use the key "intel/feed_manifest.json" --
# NOT a path-mirrored key -- because scripts/r2_upload.py's STAGE 3.5 upload
# (sentinel-apex.yml) already publishes this exact file under that exact
# key, every run, and workers/intel-gateway/src/index.js's handleFeedJson
# already reads it from there. Using a different key here would silently
# fork this platform's manifest state into two R2 objects that never see
# each other's writes -- confirmed by reading both the existing upload call
# site and the Worker's read call site, not assumed.
#
# feed_state.json / processed_intel.json have no pre-existing R2 presence
# (confirmed: no reference to either anywhere in r2_upload.py or the Worker),
# so their keys mirror their local relative path, matching this codebase's
# existing convention for genuinely-new R2 objects (e.g. r2_upload.py's
# "api/feed.json" -> R2 key "api/feed.json").
#
# data/feed_manifest.json (top-level -- the EII-enriched manifest, distinct
# from data/stix/feed_manifest.json's raw ingestion bundle) belongs in this
# list for the same reason as the three above: it is bidirectional cross-run
# state, not a fresh-every-run output. Confirmed by reading every writer:
# run_pipeline.py, apex_quality_field_backfill.py, cve_id_backfill.py,
# actor_attribution_enricher.py, generate_advisory_pdfs.py and
# threat_graph_engine.py all read-then-patch this same file in place, and
# every one of those steps in sentinel-apex.yml runs between this
# workflow's "Download Intel State from R2" step and its "Upload Intel State
# to R2 (final, post-enrichment)" step -- so no wiring change is needed
# there, only this entry. It has no pre-existing R2 key of its own (r2_upload.py
# and r2-data-sync.yml only ever touch data/stix/feed_manifest.json), so its
# key mirrors its local path, same convention as feed_state.json /
# processed_intel.json above. This file is also independently subject to the
# exact same P0 push-rejection root cause this script fixes for the other
# three (it is in safe_git_commit.py's CRITICAL file list) -- its
# generated_at was frozen at the same 2026-08-26 incident date before this
# fix, for the same reason.
STATE_FILES: list[tuple[str, str]] = [
    ("data/cache/feed_state.json", "data/cache/feed_state.json"),
    ("data/processed_intel.json", "data/processed_intel.json"),
    # P0 production-architecture-transformation mission (2026-09-08): the
    # dedup primary index -- intel_dedup_engine.py's sibling file to
    # feed_state.json above, written by the same engine with the same
    # atomic tmp/fsync/os.replace() write contract, loaded at the start of
    # every run ("Loaded intel_index: N seen items") and rebuilt from the
    # archive if missing/corrupt. Its own module docstring documents the
    # identical "committed to git (persists forever)" assumption that
    # caused the 2026-08-26 staleness incident this migration fixes for
    # feed_state.json/processed_intel.json above -- confirmed via full
    # trace of intel_dedup_engine.py before adding, not assumed from the
    # filename. No pre-existing R2 key (confirmed: no reference anywhere in
    # r2_upload.py or the Worker), so its key mirrors its local path per
    # this module's established convention.
    ("data/cache/intel_index.json", "data/cache/intel_index.json"),
    ("data/stix/feed_manifest.json", "intel/feed_manifest.json"),
    ("data/feed_manifest.json", "data/feed_manifest.json"),
    # CodeRabbit review finding on this migration (verified, not taken on
    # faith): multi-source-intel.yml's "Commit Intel State & Manifest" step
    # still `git add -f`'d these 5 append-only registry files after the
    # STATE_FILES above were pulled off that same push -- but main's branch
    # ruleset rejects ANY direct push, not just pushes of specific files, so
    # that push was always going to keep failing regardless of which files
    # remained on it. Since PR #330 made push exhaustion hard-fail the job
    # (deliberately, to stop it silently discarding real state), leaving
    # these 5 on the git path meant this job would now hard-fail on every
    # run that touched any of them -- confirmed by reading
    # intel_persistence_engine.py's own docstring, which describes all 5 as
    # written every run. Same root cause, same fix, same file family as the
    # entries above: no pre-existing R2 key for any of them (confirmed: no
    # reference anywhere in r2_upload.py or the Worker), so keys mirror
    # local paths per this module's established convention.
    ("data/intelligence_repository/intelligence_index.json", "data/intelligence_repository/intelligence_index.json"),
    ("data/intelligence_repository/advisory_registry.json", "data/intelligence_repository/advisory_registry.json"),
    ("data/intelligence_repository/intel_retention_registry.json", "data/intelligence_repository/intel_retention_registry.json"),
    ("data/intelligence_repository/intel_lifecycle_registry.json", "data/intelligence_repository/intel_lifecycle_registry.json"),
    ("data/intelligence_repository/historical_feed_registry.json", "data/intelligence_repository/historical_feed_registry.json"),
    # P0 R2 COST AUDIT FIX (post-merge forensic review of PR #369): this is
    # scripts/r2_report_publisher.py's own incremental-publish state
    # (sha256-per-id, keyed by intel id -- see that script's STATE_PATH).
    # Its "write-only-on-change" cost-reduction architecture depends
    # entirely on this file surviving between runs; without it, every run
    # would see an empty state and re-PUT every in-window candidate as
    # "new" (still bounded by MAX_REPORT_UPLOADS_PER_RUN, but genuinely
    # redundant every single run -- defeating the incremental design this
    # file exists for). PR #369 as merged never staged this file anywhere
    # (not in safe_git_commit.py's JSON_GUARDED, files_to_stage, or
    # _GENERATED_ARTIFACT_PATHS), so on every fresh CI checkout it silently
    # reverted to empty. Same root cause this module's own docstring
    # documents for feed_state.json et al -- main's branch ruleset rejects
    # a direct git push for this class of file -- so it gets the same fix,
    # not a second attempt at git-based persistence. No pre-existing R2 key
    # (confirmed: no reference anywhere in r2_upload.py, r2_report_publisher.py
    # itself, or the Worker), so its key mirrors its local path, matching
    # every other entry in this list.
    ("data/cache/r2_report_publish_state.json", "data/cache/r2_report_publish_state.json"),
    # ------------------------------------------------------------------
    # AI PLANE STATE (2026-09-09 post-merge verification of PR #388/#389).
    #
    # Same root cause as every entry above, found the same way: the AI
    # prediction producers were wired into ai-predictions.yml, which persists
    # via `git push origin main` -- rejected since 2026-08-26 by the branch
    # ruleset, and swallowed by that workflow's own retry loop
    # ("Push deferred.", step still exits 0). Verified empirically before
    # adding: ZERO runtime commits on main since 2026-08-26 (all 52 commits
    # in that window are PR merges), and data/ai_predictions/ + data/ai/ have
    # only ever been changed by PR #388 and #389 themselves -- never by a
    # scheduled run. So these engines execute, produce correct output, and
    # the output dies with the runner.
    #
    # sector_history.json is the one that makes this urgent rather than
    # cosmetic: it is genuinely bidirectional cross-run state (the accumulated
    # daily observation series the forecast is fitted on). Without durable
    # persistence it can never accumulate past a single run, so
    # sector_forecast_model.py's 35-observed-day threshold is unreachable and
    # the forecast declines forever. The other three are single-run outputs
    # that a DIFFERENT workflow consumes: ai_brain_publisher.py runs inside
    # sentinel-apex.yml and reads all three, so they must survive the
    # hand-off between workflows, which only R2 now does.
    #
    # DELIBERATELY NOT ADDED (each costs ops on every sync pass):
    #   data/ai_predictions/predictions_summary.json -- traced every
    #     reference: written by ai_predictions_engine.py, read by nothing.
    #   data/ai_predictions/apex_forecast_latest.json -- its producer
    #     (agent/v30_apex/predictive_cortex.py) is orphaned, so the object
    #     would be a permanently-EXPIRED file that ai_freshness_guard.py
    #     already excludes on age. Syncing a dead file buys nothing.
    #
    # COST (measured against this module's actual call sites, not estimated):
    # 4 files x (sentinel-blogger 1 download + 2 uploads, 4 runs/day;
    # multi-source-intel 1+1, 6/day; dashboard-feeds-sync 1+0, 4/day;
    # ai-predictions 1+1, 4/day) = 72 GET/day + 72 PUT/day
    #   = 2,160 Class A + 2,160 Class B per month
    #   = 0.216% of R2's 1M/month Class A allowance, 0.022% of the 10M Class B.
    # Storage: sector_history.json ~1 KB/day pruned at 400 days (~400 KB
    # steady state); the other three overwrite in place (~60 KB, no growth).
    # Total ~460 KB against a 10 GB allowance.
    # ------------------------------------------------------------------
    ("data/ai_predictions/sector_history.json", "data/ai_predictions/sector_history.json"),
    ("data/ai_predictions/anomalies.json",      "data/ai_predictions/anomalies.json"),
    ("data/ai_predictions/forecasts.json",      "data/ai_predictions/forecasts.json"),
    ("data/ai/anomaly_radar.json",              "data/ai/anomaly_radar.json"),
    # ------------------------------------------------------------------
    # NEXUS/CORTEX/QUANTUM/SOVEREIGN/GENESIS CUSTOMER INTELLIGENCE PLANE
    # (P0 RUNTIME INTELLIGENCE STATE RECOVERY mission, 2026-09-10).
    #
    # Same root cause as every entry above: genesis-powerhouse.yml and
    # sovereign-platform.yml persisted via `git push origin main`, rejected
    # every run since ~2026-08-26 by the branch ruleset and swallowed by
    # `|| echo "... cycle complete"` / a push-retry loop that still exits 0
    # ("push deferred"). Verified live: last real commit to any of
    # data/{nexus,cortex,quantum,sovereign,genesis}/ was 2026-09-03
    # (75d3027e2), 7 days of "successful" runs producing nothing durable.
    #
    # A second, independent bug compounded this: MANIFEST_PATH
    # (data/stix/feed_manifest.json) is gitignored and neither workflow ever
    # populated it from R2, so _entries() returned [] every run regardless
    # of the push failure -- see the new "download BEFORE engines run" step
    # this mission adds to both workflows, reusing this same STATE_FILES
    # entry (the pre-existing "data/stix/feed_manifest.json" row above) via
    # `--only data/stix/feed_manifest.json`. Confirmed live via
    # scripts/p0_r2_stix_manifest_diagnostic.py (run 34493014038,
    # 2026-09-10T15:03Z): R2's intel/feed_manifest.json is a valid 39-record
    # flat-list manifest, last_modified ~1h before that check -- kept fresh
    # by sentinel-apex.yml's own existing STAGE 3.5 upload, needing no
    # new producer, only a new (read-only, from this workflow pair's
    # perspective) consumer.
    #
    # Scope, decided per-file (not per-directory) against real consumers,
    # traced by an exhaustive producer/consumer forensic pass:
    #   - The 5 files below are exactly index.html's initEngineLoader()
    #     ENGINE_URLS set for these engines (nexus/cortex/quantum/sovereign/
    #     genesis) -- the customer-facing dashboard's own current-state read.
    #     Each engine's *_output.json is a same-run aggregate of that
    #     engine's own sub-computations (confirmed: none of the sub-files
    #     read their own or another sub-file's PRIOR run output), so only
    #     the aggregate needs cross-workflow-run persistence.
    #   - data/cortex/stream_events.json is CORTEX's one sub-file with a
    #     real consumer beyond its own aggregate: agent/sdk/cdb_apex_streamer.py
    #     treats it as "the live predictive event bus."
    #   - data/genesis/detection_pack.json is GENESIS's one sub-file with a
    #     real consumer beyond its own aggregate: agent/product_factory/
    #     detection_pack_builder.py packages it into a sellable detection ZIP.
    #
    # DELIBERATELY NOT ADDED:
    #   data/sovereign/tenants.json -- holds customer-shaped API-key values
    #     (SEC-2026-07-25/2026-08-28 incidents); already excluded from every
    #     git commit this workflow makes and MUST NEVER be persisted to R2
    #     either (see tests/test_r2_state_migration_wiring.py's dedicated
    #     assertion against this exact key ever entering STATE_FILES).
    #   data/sovereign/{mrr_report,invoices,stripe_config}.json -- billing-
    #     adjacent state with a pre-existing, independent duplicate-writer
    #     (scripts/stripe_webhook.py writes mrr_report.json from real Stripe
    #     events on its own trigger). Migrating sovereign_engine.py's
    #     fake-tenant recompute of these to R2 would propagate that
    #     collision into R2 rather than resolve it -- a billing-architecture
    #     decision (CLAUDE.md: payment logic frozen unless explicitly in
    #     scope) out of bounds for this intelligence-persistence mission.
    #     Not read by any customer intelligence panel this mission targets
    #     (dashboard/revenue_dashboard.html is a separate, internal surface).
    #   data/sovereign/{onboarding_flow,whitelabel_config,soc2_report,
    #     nist_csf_report}.json -- 100% same-run-regenerable demo/compliance
    #     output with no external reader traced; nothing to persist FOR.
    #   All other NEXUS/CORTEX/QUANTUM sub-files (exposure_score.json,
    #     campaigns.json, threat_hunts.json, knowledge_graph.json,
    #     anomaly_detection.json, feed_guard.json, etc.) -- confirmed
    #     same-run-only intermediates feeding solely their own engine's
    #     aggregate; no cross-run or cross-workflow reader exists.
    #
    # COST (measured against the exact steps this mission adds, not
    # estimated): download side adds 1 GET/run (feed_manifest.json only,
    # via --only) to each of the 2 workflows x 4 runs/day = 8 GET/day.
    # Upload side: sovereign-platform.yml uploads 5 files x 4 runs/day = 20
    # PUT/day; genesis-powerhouse.yml uploads 2 files x 4 runs/day = 8
    # PUT/day. Total added: 28 PUT/day + 8 GET/day = 840 Class A + 240
    # Class B per month = 0.084% of R2's 1M/month Class A allowance, 0.0024%
    # of the 10M Class B allowance. No LIST operations added (--only
    # bypasses STATE_DIRS' advisories sync for these 2 new call sites).
    # Storage: all 7 files are overwritten in place every run (no
    # accumulation), combined well under 1 MB against a 10 GB allowance.
    ("data/nexus/nexus_output.json",         "data/nexus/nexus_output.json"),
    ("data/cortex/cortex_output.json",       "data/cortex/cortex_output.json"),
    ("data/cortex/stream_events.json",       "data/cortex/stream_events.json"),
    ("data/quantum/quantum_output.json",     "data/quantum/quantum_output.json"),
    ("data/sovereign/sovereign_output.json", "data/sovereign/sovereign_output.json"),
    ("data/genesis/genesis_output.json",     "data/genesis/genesis_output.json"),
    ("data/genesis/detection_pack.json",     "data/genesis/detection_pack.json"),
    # F26 (2026-10-02): api/feed.baseline.json, the premium baseline that
    # scripts/generate_tiered_feeds.py turns into the four Enterprise/MSSP
    # premium feeds (/api/v1/premium/feed/*), the detection pack and the
    # trial preview. Same root cause as the entries above: only STAGE 4's
    # git push persisted it, refused since 2026-08-26, so every publisher
    # run read the 26 August copy back. Its key sits under the private
    # premium/ prefix: no gateway route serves premium/state/
    # (/api/v1/premium/feed/ maps a fixed tier allowlist to premium/feeds/).
    # Owner-only (BROAD_SWEEP_EXCLUDED_PATHS below): sentinel-apex.yml
    # downloads it explicitly before STAGE 3.1.19 and uploads it after a
    # successful run of that stage, so no broad sweep can re-publish a stale
    # copy. COST (computed from the observed run count, not measured): at
    # most 14 publisher runs/day (2026-09-29); per run one download (a HEAD
    # plus up to 2 ranged GETs while the object is above the AWS CLI's 8 MB
    # multipart threshold, 11.2 MB today) and at most one upload (up to 4
    # multipart calls above that threshold, 1 PUT below). Worst case 1,680
    # Class A + 1,260 Class B per month = 0.168% / 0.0126% of R2's
    # allowances. No LIST. Storage: one object, overwritten in place.
    ("api/feed.baseline.json",               "premium/state/feed.baseline.json"),
]

# Local relative paths that must NEVER be added to STATE_FILES/STATE_DIRS --
# enforced by tests/test_r2_state_migration_wiring.py so this can't silently
# regress if a future edit adds a convenience entry without re-reading this
# comment block's reasoning above.
NEVER_PERSIST_PATHS = frozenset({
    "data/sovereign/tenants.json",
})
_leaked = NEVER_PERSIST_PATHS & {local_rel for local_rel, _ in STATE_FILES}
assert not _leaked, f"NEVER_PERSIST_PATHS entries found in STATE_FILES: {_leaked}"

# P0 RUNTIME INTELLIGENCE STATE RECOVERY mission follow-up (2026-09-10,
# second-order fix): confirmed live via this mission's own fail-closed
# r2_round_trip_verifier.py -- a fresh sovereign-platform.yml dispatch's
# genuinely successful upload (confirmed via its own "OK: Uploaded" log
# lines) was found, ~10 seconds later in the SAME job's own round-trip
# check, to have already been overwritten in R2 by different content.
# Root cause: PR #409 stopped regenerate_engine_data.py from GENERATING
# fresh (wrong) content for these 5 canonical paths, but did nothing about
# a plain, unchanged echo -- sentinel-apex.yml's own broad (no --only)
# `--download` call (line ~409) still pulls these paths onto local disk at
# the START of its run, reflecting whatever R2 held AT THAT MOMENT; with
# nothing left to regenerate them mid-job, that downloaded snapshot sits
# untouched on disk for the rest of a run documented elsewhere in this repo
# as taking 2-3+ hours, and its own later broad `--upload` calls (lines
# ~3204/~4356) blindly re-publish that byte-identical, hours-stale snapshot
# -- silently reverting any newer write sovereign-platform.yml/
# genesis-powerhouse.yml made to the SAME R2 keys in the meantime, even
# with zero code left that produces wrong content. A "did nothing new" step
# is not the same as "touched nothing" when it re-asserts old state on top
# of newer state.
#
# Fixed at the single shared source (this module), not by chasing every
# existing or future broad-sweep caller individually: these paths remain in
# STATE_FILES (so sovereign-platform.yml's/genesis-powerhouse.yml's own
# explicit `--only <these-paths>` calls are completely unaffected -- an
# explicit request always wins) but a caller doing a BROAD sweep (only is
# None, e.g. sentinel-apex.yml/multi-source-intel.yml/ai-predictions.yml's
# existing, unchanged invocations) now skips them in both download() and
# upload(), exactly like NEVER_PERSIST_PATHS above except these ARE meant to
# reach R2 -- just only via the one pair of workflows that own them.
BROAD_SWEEP_EXCLUDED_PATHS = frozenset({
    "data/nexus/nexus_output.json",
    "data/cortex/cortex_output.json",
    "data/cortex/stream_events.json",
    "data/quantum/quantum_output.json",
    "data/sovereign/sovereign_output.json",
    "data/genesis/genesis_output.json",
    "data/genesis/detection_pack.json",
    # F26 (2026-10-02): owned by sentinel-apex.yml's STAGE 3.1.19 steps.
    "api/feed.baseline.json",
})
_not_tracked = BROAD_SWEEP_EXCLUDED_PATHS - {local_rel for local_rel, _ in STATE_FILES}
assert not _not_tracked, f"BROAD_SWEEP_EXCLUDED_PATHS entries missing from STATE_FILES: {_not_tracked}"

# data/intelligence_repository/advisories/ is a directory of monthly chunk
# files (registry_<YYYYMM>.json, "never overwritten" per
# intel_persistence_engine.py's own docstring) -- not a single JSON object,
# so it needs sync (prefix-level) rather than cp (key-level) semantics.
# Same root cause and fix as STATE_FILES above; kept as a separate list
# because s3_sync()/s3_sync_download()'s directory contract genuinely
# differs from s3_cp()/s3_get()'s single-object OK/NOT_FOUND/ERROR one (see
# s3_sync_download()'s docstring: without --delete, sync is inherently
# additive/bootstrap-safe, so it doesn't need the same three-way branching).
STATE_DIRS: list[tuple[str, str]] = [
    ("data/intelligence_repository/advisories", "data/intelligence_repository/advisories"),
]

UPLOAD_RETRY_ATTEMPTS = 4


def _is_recognized_state_shape(data) -> bool:
    """True unless `data` is a bare JSON scalar (string/number/bool/null).

    Every file in STATE_FILES is documented as a list or an object (a dict
    keyed by source/fingerprint/registry entries) -- never a lone scalar.
    This is deliberately a coarse, file-shape-agnostic check rather than a
    per-file schema validator: the 9 files in STATE_FILES have 9 different
    internal shapes, and hand-encoding each one's exact schema here would be
    both a maintenance burden and a second, competing source of truth for
    a contract each file's own real consumer (true_intel_ingestor.py,
    run_pipeline.py, intel_persistence_engine.py, ...) already enforces by
    construction. What every one of them agrees on, unconditionally, is that
    a bare scalar is never a valid top-level value -- so that's the one
    invariant checked here, closing the "valid JSON, wrong shape" gap
    without inventing a second schema authority.
    """
    return isinstance(data, (list, dict))


def download(root: pathlib.Path, endpoint: str, only: frozenset[str] | None = None) -> int:
    """
    Populate each local state path from its R2-authoritative copy.

    `only`, when given, restricts processing to STATE_FILES/STATE_DIRS rows
    whose local_rel is in the set -- e.g. a workflow that only ever reads
    data/stix/feed_manifest.json has no reason to pay for (or wait on) a
    LIST+download pass over the unrelated advisories directory sync or the
    other 18 unrelated state files this module also tracks. `None` (the
    default) preserves this function's original all-rows behavior exactly,
    so every pre-existing caller (ai-predictions.yml, multi-source-intel.yml,
    sentinel-apex.yml, dashboard-feeds-sync.yml,
    report-generator-regression-gate.yml) is unaffected.

    Three-way outcome per file, per s3_get()'s contract:
      OK        -> local path now holds the R2 copy.
      NOT_FOUND -> one-time bootstrap: leave whatever's already on disk (the
                   current git-checkout copy, on the first run after this
                   migration lands) in place if present; if nothing is on
                   disk either (a genuinely brand-new environment), that's
                   fine too -- the downstream consumer (true_intel_ingestor.py
                   / run_pipeline.py) already handles a missing/absent file
                   as "start empty", which is what a real first-ever run is.
      ERROR     -> hard fail immediately. Silently proceeding as if this were
                   NOT_FOUND would risk the downstream consumer treating a
                   transient R2 outage as "nothing has ever been seen before",
                   discarding real dedup history and reintroducing duplicates
                   into the customer-facing feed.

    PRODUCTION-VERIFICATION HARDENING (2026-09-02): s3_get() writes directly
    to its destination path, so validating local_path in place (as this
    function used to) meant a malformed or wrong-shape download had already
    overwritten a good local copy by the time validation ran -- the ERROR
    log line and had_error=True were accurate, but the damage to the file
    on disk was already done, and nothing here restored it. Downloads now
    go to a `.tmp` sibling first, validated, and only promoted onto
    local_path via an atomic replace on success -- mirroring the write-tmp/
    verify/replace pattern true_intel_ingestor.py's own _save_manifest()
    already uses for several of these same files on the write side. A
    failed validation now leaves whatever was already at local_path
    (git-checkout copy or a prior successful download) untouched, and is
    reported the same way a NOT_FOUND-with-no-local-copy case already was.
    """
    had_error = False
    for local_rel, r2_key in STATE_FILES:
        if only is not None and local_rel not in only:
            continue
        if only is None and local_rel in BROAD_SWEEP_EXCLUDED_PATHS:
            # See BROAD_SWEEP_EXCLUDED_PATHS' own comment: a broad sweep must
            # not even DOWNLOAD these onto local disk, or a long-running
            # caller (sentinel-apex.yml) sits on an hours-stale snapshot
            # that its own later broad upload then blindly re-publishes,
            # reverting whatever sovereign-platform.yml/genesis-powerhouse.yml
            # wrote to the same R2 keys in the meantime. Only an explicit
            # `--only` naming one of these paths may touch it.
            continue
        local_path = root / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = local_path.with_name(local_path.name + ".r2sync.tmp")
        outcome = s3_get(str(tmp_path), BUCKET_DATA, r2_key, endpoint)

        if outcome == "OK":
            try:
                with open(tmp_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if not _is_recognized_state_shape(data):
                    raise ValueError(f"top-level JSON value is a bare {type(data).__name__}, not a list/object")
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                # A malformed or wrong-shape download is at least as dangerous
                # as an outright read error: a downstream consumer that trusts
                # this file (true_intel_ingestor.py's dedup state,
                # run_pipeline.py's Single Source of Truth manifest) could
                # crash mid-run or, worse, silently misbehave on partially-
                # parseable content. Fail loudly rather than handing corrupt
                # state downstream -- and, unlike before this hardening,
                # leave the existing local_path (if any) untouched rather
                # than having already overwritten it.
                log.error(
                    "FATAL: downloaded %s but it is not valid, recognized-shape JSON (%s) -- "
                    "refusing to hand corrupt state to downstream consumers. Existing local "
                    "copy of %s (if any) is untouched.",
                    r2_key, exc, local_rel,
                )
                had_error = True
                tmp_path.unlink(missing_ok=True)
                continue
            try:
                tmp_path.replace(local_path)
            except OSError as exc:
                # Promotion itself failing (disk full, permission error, a
                # cross-device tmp dir) is the one failure mode the write-tmp/
                # verify/replace pattern doesn't self-heal -- without this
                # handler it would propagate out of download() uncaught,
                # skipping every remaining STATE_FILES entry instead of
                # degrading one file at a time like every other outcome here.
                log.error(
                    "FATAL: validated download for %s but could not promote it onto %s (%s) -- "
                    "existing local copy (if any) is untouched.",
                    r2_key, local_path, exc,
                )
                had_error = True
                tmp_path.unlink(missing_ok=True)
            continue
        tmp_path.unlink(missing_ok=True)
        if outcome == "NOT_FOUND":
            if local_path.exists():
                log.info(
                    "BOOTSTRAP: %s not yet in R2 -- keeping existing local copy "
                    "(%d bytes) as the one-time bootstrap source.",
                    r2_key, local_path.stat().st_size,
                )
            else:
                log.info(
                    "BOOTSTRAP: %s not yet in R2 and no local copy exists -- "
                    "this consumer's own first-run-empty handling applies.",
                    r2_key,
                )
            continue
        # outcome == "ERROR"
        log.error(
            "FATAL: could not determine R2 state for %s -- refusing to guess "
            "whether this is a fresh environment or a transient outage. "
            "See the ERROR log line above for the underlying cause.",
            r2_key,
        )
        had_error = True

    for local_rel, r2_prefix in STATE_DIRS:
        if only is not None and local_rel not in only:
            continue
        local_dir = root / local_rel
        local_dir.mkdir(parents=True, exist_ok=True)
        if not s3_sync_download(str(local_dir), BUCKET_DATA, r2_prefix, endpoint):
            log.error(
                "FATAL: could not sync %s from R2 -- see the WARN log line "
                "above for the underlying cause. Existing local copy (if "
                "any) is left untouched.",
                r2_prefix,
            )
            had_error = True

    return 1 if had_error else 0


def upload(root: pathlib.Path, endpoint: str, only: frozenset[str] | None = None) -> int:
    """Publish each local state path back to its R2-authoritative key, with
    the same 4-attempt retry budget already established for git-push
    exhaustion elsewhere in this pipeline (see safe_git_commit.py /
    multi-source-intel.yml's "Commit Intel State & Manifest" step) for
    consistency. A file that was never present locally (nothing to publish,
    e.g. an ingestion run that legitimately produced no output) is skipped,
    not an error.

    R2 has no cross-object transactions (see this module's docstring's
    Concurrency note), so a run where some of STATE_FILES' 4 uploads succeed
    and others exhaust their retries leaves R2 in a genuinely MIXED state --
    e.g. a freshly-uploaded data/stix/feed_manifest.json paired with a
    stale, previous-run data/feed_manifest.json that failed to publish.
    Building real cross-file atomicity (stage-then-promote) is out of scope
    for a last-write-wins object store this fix doesn't otherwise depend on;
    instead this function tracks succeeded vs. failed files explicitly so a
    genuinely partial run is loudly distinguishable from a total failure --
    the previous per-file-only message wrongly implied 'NOT persisted' even
    when other files in the same run *had* persisted.

    `only`, see download()'s docstring -- same filtering contract, same
    `None`-preserves-original-behavior default.
    """
    had_error = False
    succeeded: list[str] = []
    failed: list[str] = []
    for local_rel, r2_key in STATE_FILES:
        if only is not None and local_rel not in only:
            continue
        if only is None and local_rel in BROAD_SWEEP_EXCLUDED_PATHS:
            # See BROAD_SWEEP_EXCLUDED_PATHS' own comment: a broad sweep must
            # not blindly re-publish whatever happens to be sitting locally
            # for these paths (whether never downloaded, or a stale snapshot
            # from this same job's own earlier broad download) -- only an
            # explicit `--only` naming one of these paths may upload it.
            continue
        local_path = root / local_rel
        if not local_path.exists():
            log.info("SKIP: %s has no local copy to publish (nothing changed?).", local_rel)
            continue

        for attempt in range(1, UPLOAD_RETRY_ATTEMPTS + 1):
            if s3_cp(str(local_path), BUCKET_DATA, r2_key, endpoint):
                succeeded.append(r2_key)
                break
            if attempt < UPLOAD_RETRY_ATTEMPTS:
                sleep_secs = attempt * 15
                log.warning("Retrying %s upload in %ds...", r2_key, sleep_secs)
                time.sleep(sleep_secs)
        else:
            failed.append(r2_key)
            log.error(
                "FATAL: %s failed to upload to R2 after %d attempts -- this "
                "file's state was NOT persisted; the next scheduled run will "
                "read it stale again.",
                r2_key, UPLOAD_RETRY_ATTEMPTS,
            )
            had_error = True

    for local_rel, r2_prefix in STATE_DIRS:
        if only is not None and local_rel not in only:
            continue
        local_dir = root / local_rel
        if not local_dir.exists() or not any(local_dir.iterdir()):
            log.info("SKIP: %s has no local content to publish.", local_rel)
            continue

        for attempt in range(1, UPLOAD_RETRY_ATTEMPTS + 1):
            if s3_sync(str(local_dir), BUCKET_DATA, r2_prefix, endpoint, content_type="application/json"):
                succeeded.append(r2_prefix)
                break
            if attempt < UPLOAD_RETRY_ATTEMPTS:
                sleep_secs = attempt * 15
                log.warning("Retrying %s sync in %ds...", r2_prefix, sleep_secs)
                time.sleep(sleep_secs)
        else:
            failed.append(r2_prefix)
            log.error(
                "FATAL: %s failed to sync to R2 after %d attempts -- this "
                "run's additions were NOT persisted; the next scheduled run "
                "will read it stale again.",
                r2_prefix, UPLOAD_RETRY_ATTEMPTS,
            )
            had_error = True

    if failed and succeeded:
        log.error(
            "MIXED STATE WARNING: this run partially published its R2 state -- "
            "%d file(s) now fresh (%s), %d file(s) still stale from a previous "
            "run (%s). These files are no longer guaranteed mutually "
            "consistent; if downstream behavior looks wrong, check whether it "
            "correlates with this run.",
            len(succeeded), ", ".join(succeeded), len(failed), ", ".join(failed),
        )

    return 1 if had_error else 0


KNOWN_LOCAL_RELS = frozenset(local_rel for local_rel, _ in STATE_FILES) | frozenset(
    local_rel for local_rel, _ in STATE_DIRS
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--download", action="store_true", help="Populate local state from R2 before processing.")
    mode.add_argument("--upload", action="store_true", help="Publish local state to R2 after processing.")
    parser.add_argument("--root", type=pathlib.Path, default=REPO_ROOT, help="Repository root (default: auto-detected).")
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help=(
            "Comma-separated subset of STATE_FILES/STATE_DIRS local paths to process "
            "(e.g. 'data/stix/feed_manifest.json'). Omit to process every entry "
            "(original, unfiltered behavior). Use this when a caller genuinely only "
            "needs a handful of the tracked files -- e.g. a workflow that reads only "
            "the STIX manifest has no reason to also pay for the unrelated advisories "
            "directory sync or the AI-plane files this module also tracks."
        ),
    )
    args = parser.parse_args()

    only = None
    if args.only is not None:
        only = frozenset(p.strip() for p in args.only.split(",") if p.strip())
        unknown = only - KNOWN_LOCAL_RELS
        if unknown:
            parser.error(
                f"--only references path(s) not in STATE_FILES/STATE_DIRS: {sorted(unknown)}. "
                f"A typo here would otherwise silently download/upload nothing."
            )

    cf_account, _, _ = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    if args.download:
        return download(args.root, endpoint, only=only)
    return upload(args.root, endpoint, only=only)


if __name__ == "__main__":
    sys.exit(main())
