#!/usr/bin/env python3
"""
scripts/r2_report_publisher.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Bounded 24h Report Publisher (P0 COST FIX)
================================================================================
INCIDENT: Cloudflare R2 billed 3,004,147 Class A operations in one cycle.
Root cause: scripts/r2_upload.py ran `aws s3 sync reports/ ->
s3://sentinel-apex-reports/reports/` (full LIST + full content comparison,
no bound) on every scheduled pipeline run, against a local reports/ tree
that scripts/generate_intel_reports.py regenerated in FULL (entire
historical manifest) every run, with every regenerated file's SIGMA/YARA/
KQL/SPL blocks carrying a fresh minute-granularity timestamp -- so content
differed from the prior run even when the underlying intel item had not
changed. Full evidence chain: docs/P0_R2_COST_CONTAINMENT.md.

This script REPLACES that sync path entirely (not a flag around it -- the
whole-corpus sync no longer exists in this codebase; see scripts/
r2_upload.py). It is the sole normal-operation writer/retirer for the
sentinel-apex-reports keyspace and the reports/pdf/ prefix of
sentinel-apex-data.

ARCHITECTURE (hardening requirement: no whole-bucket sync in normal
operation, regardless of retention window; zero LIST required to publish):

  1. DETERMINISTIC KEYS ONLY. Every key this script touches is derived
     from the CURRENT manifest via generate_intel_reports.rel_report_path()
     (HTML: reports/{yyyy}/{mm}/{id}.html) and the established flat PDF
     convention (reports/pdf/{id}.pdf) -- never discovered via a bucket
     LIST. list_calls is 0 by construction in the normal path.

  2. 24-HOUR ROLLING WINDOW. Only items whose canonical intelligence
     timestamp (scripts/canonical_timestamp.py; timestamp -> processed_at
     -> published_at precedence -- the same precedence already used in
     production by scripts/intelligence_quality_scorer.py::_compute_age_days)
     falls within the last REPORT_WINDOW_HOURS (default 24) are eligible to
     be published. A missing/unparseable timestamp is treated as OUT of
     window (fail safe = do not publish something we cannot prove is
     fresh; scripts/generate_intel_reports.py's existing --only-missing
     repair pass remains the backstop once/if the timestamp is fixed).

  3. INCREMENTAL, WRITE-ONLY-ON-CHANGE. "Did I already publish this exact
     content?" is answered from this script's OWN local state file
     (data/cache/r2_report_publish_state.json via sha256 comparison) --
     never by asking R2. new/changed -> PUT. unchanged -> zero PUT.

  4. BOUNDED RETIREMENT. An id this script previously published, whose
     canonical timestamp (recorded in the state file at publish time, so
     this does not depend on the id still being present in the manifest's
     own rolling window) has aged past the window, gets DELETEd -- bounded
     by construction, since the state file only ever holds what THIS
     script itself published within roughly the last window. Every
     retired id's report_url / internal_report_url / pdf_url is cleared to
     "" in the manifests that carry it (report_url_integrity_gate.py's
     existing, already-established contract: empty is a valid, truthful
     "no report published" state -- never a dangling link).

  5. FAIL-CLOSED BUDGET. The complete PUT/DELETE plan is computed BEFORE a
     single R2 call is issued; scripts/r2_cost_guard.py aborts the entire
     run before any mutation if a ceiling is exceeded. No partial
     execution, no warning-and-continue.

This script does NOT render HTML/PDF content -- scripts/
generate_intel_reports.py and scripts/generate_advisory_pdfs.py remain the
sole renderers (Constitution Principle 3). This script only decides, from
the manifest and its own publish-state, what R2 needs a PUT or DELETE this
run, and performs exactly that.

Usage:
  python3 scripts/r2_report_publisher.py             # publish + retire
  python3 scripts/r2_report_publisher.py --dry-run    # compute + print the plan, mutate nothing

Environment variables:
  R2_REPORT_PUBLISHING_ENABLED  -- "false" disables this script entirely
                                    (emergency kill switch). Default "true"
                                    -- the architecture is safe-by-construction
                                    (bounded, no LIST, budget-enforced), and
                                    the dashboard must keep showing current
                                    reports per the platform's business
                                    requirement.
  PRE_REVENUE_COST_MODE         -- see scripts/r2_cost_guard.py. Default "true".
  REPORT_WINDOW_HOURS           -- rolling hot-report window. Default 24.
  MAX_REPORT_UPLOADS_PER_RUN, MAX_REPORT_DELETIONS_PER_RUN,
  MAX_R2_LIST_CALLS_PER_RUN     -- see scripts/r2_cost_guard.py.
  CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY -- same as r2_upload.py
  CF_R2_REPORTS_KEY_ID, CF_R2_REPORTS_SECRET_KEY -- dedicated sentinel-apex-reports
                                    token (optional, same precedence as r2_upload.py)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from r2_upload import (  # noqa: E402
    BUCKET_DATA,
    BUCKET_REPORTS,
    get_credentials,
    install_awscli,
    s3_cp,
    s3_delete,
)
from r2_cost_guard import (  # noqa: E402
    R2Budgets,
    R2BudgetExceeded,
    R2OperationPlan,
    emit_summary,
    enforce_budget,
)
from canonical_timestamp import parse_timestamp  # noqa: E402
from generate_intel_reports import rel_report_path, report_future_skew_hours  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2-report-publisher] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_report_publisher")

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_JSON = REPO_ROOT / "api" / "feed.json"

# Every manifest file known to carry report_url/internal_report_url/pdf_url
# fields that must be cleared, not left dangling, when this script retires
# an id. Matches scripts/report_existence_validator.py's own DEFAULT_FEEDS
# (api/feed.json, data/stix/feed_manifest.json) plus the top-level
# data/feed_manifest.json (the EII-enriched manifest -- see scripts/
# r2_state_sync.py's STATE_FILES docstring for why that file also carries
# these fields). Reused, not reinvented: same file set the existing gate
# already treats as authoritative for report_url.
REPORT_URL_MANIFESTS = [
    REPO_ROOT / "api" / "feed.json",
    REPO_ROOT / "data" / "stix" / "feed_manifest.json",
    REPO_ROOT / "data" / "feed_manifest.json",
]

STATE_PATH = REPO_ROOT / "data" / "cache" / "r2_report_publish_state.json"

PDF_DIR = REPO_ROOT / "reports" / "pdf"


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def report_publishing_enabled() -> bool:
    return os.environ.get("R2_REPORT_PUBLISHING_ENABLED", "true").strip().lower() != "false"


def report_window_hours() -> int:
    return _int_env("REPORT_WINDOW_HOURS", 24)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not parse %s (%s) -- treating as %r", path, exc, default)
        return default


def _get_items(data) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("advisories", "items", "reports"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def load_publish_state() -> dict:
    """Loads the incremental-publish state (synced cross-run via
    scripts/r2_state_sync.py -- see its STATE_FILES entry for this path).

    P0 R2 COST AUDIT FIX: missing state (first-ever run, or r2_state_sync.py's
    own documented one-time-bootstrap case) is expected and silent. A file
    that EXISTS but fails to parse or has the wrong shape is a genuine
    anomaly -- previously indistinguishable in the logs from the routine
    bootstrap case, silently discarding real publish history. Both fall back
    to an empty state, which is fail-safe by construction: build_plan()'s
    retirement pass only ever deletes ids the state file itself already
    tracks, so an empty state can cause redundant-but-budget-capped PUTs
    (every in-window candidate looks "new"), never an uncontrolled DELETE,
    never a LIST, never reconstruction by enumerating R2. The corrupt case
    is now logged loudly so it is never mistaken for ordinary bootstrap.
    """
    existed = STATE_PATH.exists()
    # A deliberately invalid default (None), not the well-shaped empty state:
    # _load_json() returns its `default` verbatim on a parse failure too, so
    # passing the well-shaped dict here would make a genuine JSON syntax
    # error indistinguishable from "file legitimately empty" below -- the
    # isinstance check must be able to catch BOTH failure modes, not just
    # "parsed fine but wrong shape".
    state = _load_json(STATE_PATH, None)
    if not isinstance(state, dict) or not isinstance(state.get("items"), dict):
        if existed:
            log.error(
                "%s exists but is not a recognized publish-state shape (a valid JSON "
                "object with an 'items' dict) -- DISCARDING it and starting from an "
                "empty state this run. Fail-safe (never causes an uncontrolled DELETE, "
                "LIST, or whole-corpus reconstruction), but every in-window candidate "
                "will look 'new' this run (bounded by MAX_REPORT_UPLOADS_PER_RUN) and "
                "real prior publish history was just lost -- investigate why this file "
                "was corrupted.",
                STATE_PATH,
            )
        state = {"schema_version": "1.0", "items": {}}
    return state


def save_publish_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_PATH)


def canonical_age(item: dict, now: datetime) -> tuple[Optional[datetime], Optional[float]]:
    """Returns (normalized_timestamp, age_hours) using the platform's
    established canonical-timestamp precedence (timestamp -> processed_at
    -> published_at -- scripts/intelligence_quality_scorer.py::
    _compute_age_days), parsed via scripts/canonical_timestamp.py so a
    malformed value is explicitly FAILED rather than silently coerced.
    Returns (None, None) when no field is present or parsing failed --
    callers must treat that as "cannot prove this is in-window", never as
    "assume fresh" or "assume stale".
    """
    raw = item.get("timestamp") or item.get("processed_at") or item.get("published_at")
    if not raw:
        return None, None
    result = parse_timestamp(raw)
    if result.parse_status != "SUCCESS" or result.normalized is None:
        return None, None
    age_hours = (now - result.normalized).total_seconds() / 3600.0
    return result.normalized, age_hours


def build_publish_candidates(items: list[dict], window_hours: int, now: datetime) -> list[dict]:
    """Items within the rolling window whose id/canonical-timestamp we can
    prove -- the ONLY items this run is allowed to touch in the reports
    keyspace. Does not check disk/hash yet (that happens in plan building)."""
    candidates = []
    skipped_unparseable = 0
    # Same bounded future-skew tolerance generate_intel_reports.py renders
    # with (single definition there) -- see its P0 STAGE 3.3 WINDOW RACE FIX
    # comment. A report that was rendered must also be publishable.
    future_skew = report_future_skew_hours()
    for item in items:
        intel_id = item.get("id")
        if not intel_id:
            continue
        ts, age_hours = canonical_age(item, now)
        if ts is None:
            skipped_unparseable += 1
            continue
        if age_hours is not None and -future_skew <= age_hours <= window_hours:
            candidates.append({"item": item, "id": intel_id, "canonical_ts": ts})
        # Future-dated beyond the skew tolerance is still excluded -- not
        # provably "current" (e.g. a mis-parsed far-future timestamp).
    if skipped_unparseable:
        log.warning(
            "%d manifest item(s) had no parseable canonical timestamp -- "
            "excluded from this run's publish window (fail-safe, not an error).",
            skipped_unparseable,
        )
    return candidates


def build_plan(
    candidates: list[dict],
    state: dict,
    window_hours: int,
    now: datetime,
    max_deletes: Optional[int] = None,
) -> tuple[R2OperationPlan, list[dict], list[dict]]:
    """Returns (plan, put_ops, delete_ops). put_ops/delete_ops carry
    everything execute_plan() needs -- no re-derivation, no second pass
    over the manifest or disk after budget enforcement."""
    plan = R2OperationPlan(label="r2_report_publisher", bucket=f"{BUCKET_REPORTS} (+reports/pdf/ in {BUCKET_DATA})")
    put_ops: list[dict] = []
    delete_ops: list[dict] = []

    state_items: dict = state["items"]
    seen_ids: set[str] = set()

    for cand in candidates:
        intel_id = cand["id"]
        item = cand["item"]
        seen_ids.add(intel_id)
        prior = state_items.get(intel_id, {})

        html_path = rel_report_path(item)
        html_rel_key = None
        if html_path.exists() and html_path.is_file():
            html_sha = _sha256_file(html_path)
            html_rel_key = str(html_path.relative_to(REPO_ROOT))
            if prior.get("html_sha256") == html_sha:
                plan.record_unchanged()
            else:
                is_new = "html_sha256" not in prior
                plan.record_new() if is_new else plan.record_changed()
                put_ops.append({
                    "id": intel_id, "kind": "html", "local_path": html_path,
                    "key": html_rel_key, "sha256": html_sha, "size": html_path.stat().st_size,
                })
        # else: not yet rendered on disk -- generate_intel_reports.py's own
        # earlier pipeline stage owns rendering; this script never renders.

        pdf_path = PDF_DIR / f"{intel_id}.pdf"
        pdf_rel_key = None
        if pdf_path.exists() and pdf_path.is_file():
            pdf_sha = _sha256_file(pdf_path)
            pdf_rel_key = str(pdf_path.relative_to(REPO_ROOT))
            if prior.get("pdf_sha256") != pdf_sha:
                put_ops.append({
                    "id": intel_id, "kind": "pdf", "local_path": pdf_path,
                    "key": pdf_rel_key, "sha256": pdf_sha, "size": pdf_path.stat().st_size,
                })
            # PDFs are a secondary artifact of the same report candidate --
            # contribute to PUT/bytes_uploaded when they need publishing,
            # but intentionally do not get their own new/changed/unchanged
            # slot: "report candidates" is an item-level count keyed off
            # the HTML dossier above, and double-counting per artifact
            # would make new+changed+unchanged stop summing to the
            # candidate count in the telemetry -- exactly the kind of
            # imprecise number this module exists to avoid.

        # Stage the (possibly unchanged) state entry now; execute_plan()
        # overwrites html_sha256/pdf_sha256 only for ids actually PUT.
        state_items.setdefault(intel_id, {})
        state_items[intel_id]["canonical_ts"] = cand["canonical_ts"].isoformat().replace("+00:00", "Z")
        if html_rel_key:
            state_items[intel_id]["html_key"] = html_rel_key
        if pdf_rel_key:
            state_items[intel_id]["pdf_key"] = pdf_rel_key

    # Retirement pass: bounded by the state file's own size, never a bucket
    # scan. Any id the state file knows about that (a) wasn't just seen as
    # an in-window candidate, and (b) whose recorded canonical_ts has aged
    # past the window, is retired.
    #
    # P0 RETIREMENT-BACKLOG DEADLOCK FIX: retirement is capped at
    # `max_deletes` operations per run, oldest first, whole items only (an
    # item's html+pdf are never split). Previously every expired id was
    # planned at once, so any gap between successful runs long enough to
    # expire >~250 items (2 objects each) produced a plan over
    # MAX_REPORT_DELETIONS_PER_RUN. enforce_budget() then (correctly)
    # blocked the WHOLE plan -- including every new-report PUT -- and since
    # nothing was retired the backlog only grew: a permanent deadlock.
    # Confirmed on runs 35910500527 / 35919409972 / 35955730472 (2026-09-23/24):
    # "new: 61 ... expired: 320 ... DELETE: 623 ... budget 500 ... BLOCKED",
    # then STAGE 3.5.1 found all 61 new reports missing and failed.
    # Deferred ids stay in the state file untouched and are retired on the
    # next run(s). The ceiling itself is unchanged and enforce_budget()
    # still fails closed on anything over it; None keeps the old unbounded
    # planning for callers that do not pass a cap.
    expired: list[tuple[datetime, str, dict]] = []
    for intel_id, entry in list(state_items.items()):
        if intel_id in seen_ids:
            continue
        stored_ts_raw = entry.get("canonical_ts")
        parsed = parse_timestamp(stored_ts_raw) if stored_ts_raw else None
        if not parsed or parsed.parse_status != "SUCCESS" or parsed.normalized is None:
            # Cannot prove age -- fail safe means do NOT delete on unproven age.
            continue
        age_hours = (now - parsed.normalized).total_seconds() / 3600.0
        if age_hours <= window_hours:
            continue
        if not entry.get("html_key") and not entry.get("pdf_key"):
            # Nothing was ever actually published for this id (e.g. it aged
            # out before generate_intel_reports.py rendered it) -- no R2
            # object to delete, so nothing to add to delete_ops/`expired`.
            # Still drop the now-useless tracking entry so the state file
            # doesn't accumulate dead weight indefinitely.
            state_items.pop(intel_id, None)
            continue
        expired.append((parsed.normalized, intel_id, entry))

    expired.sort(key=lambda t: (t[0], t[1]))  # oldest first, deterministic
    deferred = 0
    for _ts, intel_id, entry in expired:
        needed = (1 if entry.get("html_key") else 0) + (1 if entry.get("pdf_key") else 0)
        if max_deletes is not None and len(delete_ops) + needed > max_deletes:
            deferred += 1
            continue
        # `expired` counts the RETIRED ITEM once, regardless of whether it
        # has one or two backing objects (html/pdf); `delete` counts the
        # actual R2 delete operations, one per object -- these are
        # deliberately different units (item-level vs. operation-level).
        plan.record_expired()
        if entry.get("html_key"):
            delete_ops.append({"id": intel_id, "kind": "html", "bucket": BUCKET_REPORTS, "key": entry["html_key"]})
            plan.record_delete(expired=False)
        if entry.get("pdf_key"):
            delete_ops.append({"id": intel_id, "kind": "pdf", "bucket": BUCKET_DATA, "key": entry["pdf_key"]})
            plan.record_delete(expired=False)

    if deferred:
        plan.note(
            f"retirement backlog: {deferred} expired item(s) deferred to a later run "
            f"(MAX_REPORT_DELETIONS_PER_RUN={max_deletes})"
        )
        log.warning(
            "Retirement backlog: %d expired item(s) deferred to the next run(s) to stay within "
            "MAX_REPORT_DELETIONS_PER_RUN=%s (oldest retired first; new-report publishing proceeds).",
            deferred, max_deletes,
        )

    return plan, put_ops, delete_ops


def execute_plan(
    put_ops: list[dict],
    delete_ops: list[dict],
    state: dict,
    endpoint: str,
) -> tuple[int, int]:
    """Issues the actual R2 calls. Only reachable after enforce_budget()
    has passed -- callers must not call this speculatively."""
    reports_key_id = os.environ.get("CF_R2_REPORTS_KEY_ID", "").strip()
    reports_secret = os.environ.get("CF_R2_REPORTS_SECRET_KEY", "").strip()
    orig_key_id = os.environ.get("AWS_ACCESS_KEY_ID", "")
    orig_secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

    put_ok = 0
    put_failed = 0

    def _use_reports_creds():
        if reports_key_id and reports_secret:
            os.environ["AWS_ACCESS_KEY_ID"] = reports_key_id
            os.environ["AWS_SECRET_ACCESS_KEY"] = reports_secret

    def _restore_creds():
        os.environ["AWS_ACCESS_KEY_ID"] = orig_key_id
        os.environ["AWS_SECRET_ACCESS_KEY"] = orig_secret

    state_items = state["items"]

    try:
        for op in put_ops:
            bucket = BUCKET_REPORTS if op["kind"] == "html" else BUCKET_DATA
            content_type = "text/html; charset=utf-8" if op["kind"] == "html" else "application/pdf"
            cache_control = "public, max-age=300" if op["kind"] == "html" else "public, max-age=3600"
            if op["kind"] == "html":
                _use_reports_creds()
            try:
                ok = s3_cp(str(op["local_path"]), bucket, op["key"], endpoint,
                           content_type=content_type, cache_control=cache_control)
            finally:
                if op["kind"] == "html":
                    _restore_creds()
            if ok:
                put_ok += 1
                sha_field = "html_sha256" if op["kind"] == "html" else "pdf_sha256"
                state_items.setdefault(op["id"], {})[sha_field] = op["sha256"]
            else:
                put_failed += 1
                log.error("PUT failed for %s (%s) -- state left un-updated so next run retries.", op["key"], op["id"])

        delete_ok = 0
        delete_failed = 0
        # Tracked per (id, kind) -- a partial failure (e.g. html delete
        # succeeds, pdf delete for the SAME id fails) must never wipe the
        # sibling key's still-pending state, and must never clear the
        # url field for the object that is still live in R2.
        cleared_html_ids: set[str] = set()
        cleared_pdf_ids: set[str] = set()
        # P0 PRODUCTION ASSURANCE FIX (post-#369 audit): remembers exactly
        # what each popped key/entry held, so a manifest-write failure below
        # can restore state to "not yet retired" for every id this batch
        # touched -- see the restoration block after clear_report_urls().
        _pre_clear_snapshot: dict[str, dict] = {}
        for op in delete_ops:
            if op["bucket"] == BUCKET_REPORTS:
                _use_reports_creds()
            try:
                ok = s3_delete(op["bucket"], op["key"], endpoint)
            finally:
                if op["bucket"] == BUCKET_REPORTS:
                    _restore_creds()
            if ok:
                delete_ok += 1
                entry = state_items.get(op["id"])
                if entry is not None:
                    _pre_clear_snapshot.setdefault(op["id"], dict(entry))
                if op["kind"] == "html":
                    cleared_html_ids.add(op["id"])
                    if entry is not None:
                        entry.pop("html_key", None)
                else:
                    cleared_pdf_ids.add(op["id"])
                    if entry is not None:
                        entry.pop("pdf_key", None)
            else:
                delete_failed += 1
                log.error("DELETE failed for %s (%s) -- left in state so next run retries.", op["key"], op["id"])

        # An id's state entry is only fully retired once BOTH its keys (if
        # it ever had both) are gone -- never pop on a partial failure.
        for intel_id in list(cleared_html_ids | cleared_pdf_ids):
            entry = state_items.get(intel_id)
            if entry is not None and not entry.get("html_key") and not entry.get("pdf_key"):
                state_items.pop(intel_id, None)

        failed_manifests = clear_report_urls(html_ids=cleared_html_ids, pdf_ids=cleared_pdf_ids)
        if failed_manifests:
            # Cannot tell from here which specific ids live in the manifest(s)
            # that failed to write -- restoring the WHOLE batch (rather than
            # guessing) means the next run's retirement pass reconsiders
            # every id touched this run: it re-issues s3_delete (idempotent
            # -- see s3_delete()'s own docstring: deleting an already-absent
            # key returns True) and retries clear_report_urls for all of
            # them, including the ones whose manifest write actually
            # succeeded this time (redundant but harmless -- clearing an
            # already-"" field is a no-op). The alternative -- leaving the
            # successfully-cleared ids fully popped from state -- would
            # mean the one id whose manifest write failed silently drops
            # out of retirement tracking forever, leaving that manifest's
            # dangling report_url/pdf_url unfixed permanently rather than
            # just until the next run.
            for intel_id, snapshot in _pre_clear_snapshot.items():
                state_items[intel_id] = snapshot
            log.warning(
                "%d manifest(s) failed to write while clearing retired report URLs: %s -- "
                "restored %d id(s) to pending-retirement state so the next run retries the "
                "full retirement (delete + manifest clear) for all of them; non-fatal, "
                "publish-state save below still proceeds.",
                len(failed_manifests), ", ".join(str(p) for p in failed_manifests),
                len(_pre_clear_snapshot),
            )
    finally:
        _restore_creds()

    if put_failed or delete_failed:
        log.warning("PUT failed=%d, DELETE failed=%d -- non-fatal, retried next run via state diff.", put_failed, delete_failed)

    return put_ok, delete_ok


def clear_report_urls(html_ids: set[str], pdf_ids: set[str]) -> list[Path]:
    """Clears report_url/internal_report_url (for html_ids) and pdf_url
    (for pdf_ids) to "" across every manifest file known to carry those
    fields, split per-field so a partial delete failure (html gone, pdf
    delete failed, or vice versa) never clears the URL for an object that
    is still actually live in R2. Bounded by construction: both sets are
    at most this run's DELETE count (budget-capped), never a full-manifest
    rescan. "" is the already-established, already-CI-gated valid state
    for "no report published" (scripts/report_url_integrity_gate.py's
    is_malformed() treats empty as truthful, not malformed; scripts/
    report_existence_validator.py skips empty report_url entirely) -- so
    this keeps both existing gates green with zero changes to either.

    P0 PRODUCTION ASSURANCE FIX (post-#369 audit): each manifest file is
    now written in its own try/except -- previously a single manifest's
    write failure (e.g. a disk error) raised out of this function, which
    (since this is called from inside execute_plan()'s try/finally, with
    no except of its own) propagated all the way past main()'s call to
    save_publish_state(state). That skipped the state save entirely, so
    the in-memory record of *every* id retired this run -- including
    manifests that DID write successfully -- was lost, not just the one
    that failed. The next run would then re-discover all of them via the
    unaffected retirement path (never an uncontrolled DELETE or LIST --
    still bounded by the state file's own prior size), but any manifest
    that failed to update would carry a dangling report_url/pdf_url
    pointing at an already-deleted R2 object for a full pipeline cycle
    (hours) rather than self-healing on the very next run. Isolating each
    manifest's write means one file's failure never blocks the others,
    and the caller can still call save_publish_state() afterward to
    persist every retirement that DID succeed. Returns the list of
    manifest paths that failed to write, for the caller to log/report --
    empty list means every manifest that needed an update got it.
    """
    failed: list[Path] = []
    if not html_ids and not pdf_ids:
        return failed
    for manifest_path in REPORT_URL_MANIFESTS:
        if not manifest_path.exists():
            continue
        data = _load_json(manifest_path, None)
        if data is None:
            continue
        items = _get_items(data)
        if not items:
            continue
        touched = 0
        for item in items:
            item_id = item.get("id")
            if item_id in html_ids:
                for field in ("report_url", "internal_report_url"):
                    if item.get(field):
                        item[field] = ""
                        touched += 1
            if item_id in pdf_ids:
                if item.get("pdf_url"):
                    item["pdf_url"] = ""
                    touched += 1
        if not touched:
            continue
        try:
            _display_path = manifest_path.relative_to(REPO_ROOT)
        except ValueError:
            _display_path = manifest_path  # e.g. a test fixture outside REPO_ROOT -- log the absolute path rather than crashing
        try:
            tmp = manifest_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, manifest_path)
        except Exception:
            log.error(
                "Failed to write %s while clearing %d dangling report/PDF URL field(s) "
                "(html retired=%d, pdf retired=%d) -- this manifest still has a dangling "
                "reference to an already-deleted R2 object until the next run retries it. "
                "Other manifests and the publish-state save are NOT affected.",
                _display_path, touched, len(html_ids), len(pdf_ids), exc_info=True,
            )
            failed.append(manifest_path)
            continue
        log.info("Cleared %d dangling report/PDF URL field(s) in %s (html retired=%d, pdf retired=%d).",
                  touched, _display_path, len(html_ids), len(pdf_ids))
    return failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Compute and print the plan; mutate nothing.")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX -- Bounded 24h Report Publisher")
    log.info("=" * 70)

    if not report_publishing_enabled():
        log.warning("R2_REPORT_PUBLISHING_ENABLED=false -- skipping report publish/retire entirely "
                     "(emergency kill switch active). No R2 calls of any kind will be made.")
        plan = R2OperationPlan(label="r2_report_publisher", bucket=BUCKET_REPORTS)
        plan.note("R2_REPORT_PUBLISHING_ENABLED=false -- publisher disabled")
        emit_summary(plan, R2Budgets.from_env(), status="PASS", is_report_plan=True)
        return 0

    window_hours = report_window_hours()
    now = _utc_now()
    items = _get_items(_load_json(FEED_JSON, []))
    log.info("Loaded %d item(s) from %s; rolling window = %dh", len(items), FEED_JSON, window_hours)

    candidates = build_publish_candidates(items, window_hours, now)
    log.info("%d item(s) within the %dh window are publish candidates.", len(candidates), window_hours)

    state = load_publish_state()
    budgets = R2Budgets.from_env()
    plan, put_ops, delete_ops = build_plan(
        candidates, state, window_hours, now,
        max_deletes=budgets.max_report_deletes_per_run,
    )

    try:
        enforce_budget(plan, budgets, is_report_plan=True)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=True,
                      extra={"reason": str(exc), "dry_run": args.dry_run})
        return 1

    if args.dry_run:
        log.info("[DRY-RUN] Plan computed, budget OK -- no R2 mutation performed.")
        emit_summary(plan, budgets, status="PASS", is_report_plan=True, extra={"dry_run": True})
        return 0

    if not put_ops and not delete_ops:
        log.info("Nothing to publish or retire this run (all candidates unchanged, no expirations).")
        emit_summary(plan, budgets, status="PASS", is_report_plan=True)
        return 0

    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    put_ok, delete_ok = execute_plan(put_ops, delete_ops, state, endpoint)
    save_publish_state(state)

    log.info("Publish complete: PUT %d/%d ok, DELETE %d/%d ok.", put_ok, len(put_ops), delete_ok, len(delete_ops))
    emit_summary(plan, budgets, status="PASS", is_report_plan=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical("Unhandled exception in r2_report_publisher.py:\n%s\n%s", e, traceback.format_exc())
        sys.exit(1)
