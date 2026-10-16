#!/usr/bin/env python3
"""
scripts/r2_reports_verifier.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- RX-PUB-A0 Reports Artifact Identity Verifier

RX-PUB-A0 Phase 9 / Sections 19-25: closes the gap documented in
docs/RX_PUB_A0_INCIDENT_ROOT_CAUSE.md and docs/RX_PUB_A0_EXECUTION_PATH.md --
scripts/r2_upload_verifier.py (STAGE 3.6) already does exactly this kind of
authenticated, hash-based, HARD FAIL post-upload verification, but is scoped
exclusively to the single data-bucket manifest object
(sentinel-apex-data/intel/feed_manifest.json). It never checks a single
reports/*.html object. This script is the same verification pattern --
reused via direct import, not reimplemented -- applied to the actual
customer-facing report artifacts.

Per the mission's Section 3 correction: a clean `aws s3 sync` exit code is a
transfer-decision fact (missing / size differs / mtime newer), never a
content-identity proof. This script supplies the missing proof directly:
SHA-256 of the exact bytes on both sides.

SCOPE (bounded, not the full ~15k+ historical corpus -- see Section 36 cost
governance): verifies reports whose CANONICAL intelligence timestamp
(scripts/canonical_timestamp.py; timestamp -> processed_at -> published_at
precedence -- the exact same precedence and window scripts/
r2_report_publisher.py's canonical_age()/build_publish_candidates() use to
decide what is actually live in R2) falls within the last
REPORT_WINDOW_HOURS (default 24h, env-configurable, single source of truth
shared with the publisher). A missing/unparseable timestamp is excluded
(fail-safe -- cannot prove it is in-window, matches the publisher's own
convention). Historical reports outside this window were never re-published
by r2_report_publisher.py's 24h retention policy, so verifying them here
would be pure historical-corpus enumeration -- exactly what this cost
incident exists to eliminate.

P0 R2 COST AUDIT FIX (post-merge forensic review): this docstring previously
claimed the above scope was already bounded "not the full historical
corpus" -- that claim was FALSE. The prior implementation of
_load_in_window_entries() loaded and verified EVERY entry in
feed_manifest.json unconditionally, with no time filter and no count cap.
Since feed_manifest.json is the append-only, ever-growing core intelligence
record (report retention does not remove entries from it -- see
docs/P0_R2_COST_CONTAINMENT.md Section 4.2), this script's real-world R2
HEAD+GET cost scaled directly with total historical corpus size, not with
"changed this run" -- historical evidence showed 150-1040 calls/run. Fixed
by (1) the genuine time-window filter above, reusing r2_report_publisher.py's
own canonical-age logic rather than reimplementing it, and (2)
MAX_VERIFY_ITEMS below as a hard, independent ceiling so a bug in (1) alone
can never again let this script's cost scale with manifest size.

For each in-window report:
  Layer A (cheap, always): S3 API head-object -- existence, size, ETag.
  Layer B (SHA-256, always for in-window reports): S3 API get-object -> SHA-256
    of the exact remote bytes, compared against the local file's SHA-256.

Writes data/quality/rx_pub_a0_reports_artifact_manifest.json (Phase 9 schema)
and HARD FAILS (nonzero exit) if any in-window report's remote SHA-256 does
not match its local SHA-256, or does not exist in R2 at all.

Environment variables consumed (same names r2_upload.py already uses):
  CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  CF_R2_REPORTS_KEY_ID, CF_R2_REPORTS_SECRET_KEY (optional, preferred if set --
    same dedicated-token swap pattern as r2_upload.py's reports-upload phase)

No secrets are logged.

RX-PUB-A0.4 Phase 2 extension (Sections 12-16): also fetches the
customer-facing public HTTP URL for each in-window report and computes its
SHA-256, closing the R2-vs-CUSTOMER half of the identity chain PR #183 left
open (it only closed LOCAL-vs-R2). Per Section 4's reuse mandate this is an
extension of this same script/manifest, not a new parallel verifier --
public fetches need no R2 credentials at all, so they run independently of
whether the R2 credential-gated checks above ran. Distinguishes "R2 object
correct but customer response stale" from "R2 object itself wrong" by
capturing both facts per report rather than conflating them into one
pass/fail bit.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import math
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# RX-PUB-A0: swap in the dedicated reports-bucket credentials (if configured)
# BEFORE importing r2_upload_verifier, whose R2 connection helpers
# (_s3api_head_object / _boto3_head_object) read CF_ACCOUNT_ID / ACCESS_KEY /
# SECRET_KEY as module-level constants captured at import time -- same
# swap-then-restore pattern r2_upload.py's main() already uses for its own
# reports-bucket upload phase.
_reports_key_id = os.environ.get("CF_R2_REPORTS_KEY_ID", "").strip()
_reports_secret = os.environ.get("CF_R2_REPORTS_SECRET_KEY", "").strip()
_orig_key_id    = os.environ.get("AWS_ACCESS_KEY_ID", "")
_orig_secret    = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
if _reports_key_id and _reports_secret:
    os.environ["AWS_ACCESS_KEY_ID"]     = _reports_key_id
    os.environ["AWS_SECRET_ACCESS_KEY"] = _reports_secret

import r2_upload_verifier as _verifier  # noqa: E402 -- reuse, not reimplement
import r2_upload as _r2_upload  # noqa: E402 -- BUCKET_REPORTS, get_credentials()
from canonical_timestamp import parse_timestamp  # noqa: E402 -- reuse, not reimplement
from r2_cost_guard import R2Budgets, R2OperationPlan, emit_summary  # noqa: E402

# Restore whatever the job-level credentials were, now that the reports-scoped
# constants have been captured inside _verifier's module globals.
os.environ["AWS_ACCESS_KEY_ID"]     = _orig_key_id
os.environ["AWS_SECRET_ACCESS_KEY"] = _orig_secret

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rx-pub-a0-reports-verify] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.rx_pub_a0_reports_verifier")

MANIFEST_PATH   = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
OUTPUT_PATH     = REPO_ROOT / "data" / "quality" / "rx_pub_a0_reports_artifact_manifest.json"
BUCKET_REPORTS  = _r2_upload.BUCKET_REPORTS
GENERATOR_NAME  = "generate_intel_reports.py"
PUBLIC_BASE_URL = os.environ.get("RX_PUB_A0_PUBLIC_BASE_URL", "https://intel.cyberdudebivash.com")
PUBLIC_TIMEOUT  = 15
PUBLIC_MAX_RETRIES = 3
PUBLIC_RETRY_DELAY = 3

# RX-PUB-A0.6D follow-up: real production evidence (sentinel-blogger.yml run
# 31786632126, the first run with 6D's bounded R2-layer concurrency) showed
# VERIFY_MAX_WORKERS=8 driving public-origin HTTP 429s from 3.2% (5/155,
# baseline rate observed even at the old ~1-at-a-time sequential pacing --
# run 31773568022) up to 36% (184/507) -- an order-of-magnitude increase
# from bursting up to 16 simultaneous requests (8 workers x up to 2 calls
# each: one publication-status lookup, one report-body fetch) at the same
# shared origin. The R2 layer's own 8-way concurrency is NOT implicated --
# that run's R2 summary was 495/507 REMOTE_VERIFIED, 0 mismatches -- R2 and
# the public origin are different hosts/services entirely. This constant
# throttles ONLY the public-HTTP layer via a semaphore inside _fetch_public
# (shared by both call sites: report-body fetches and
# _fetch_publication_status, which itself calls _fetch_public), independent
# of VERIFY_MAX_WORKERS, rather than reducing R2-layer concurrency that is
# already proven to work cleanly at 8. 2 is a deliberately conservative
# choice pending confirmation on a subsequent bake-in run -- not a tuned
# optimum, just a large, evidenced cut from the ~16-way burst that caused
# the regression.
PUBLIC_FETCH_MAX_CONCURRENCY = 2
_public_fetch_semaphore = threading.Semaphore(PUBLIC_FETCH_MAX_CONCURRENCY)

# P0 R2 COST AUDIT FIX: this script issues real R2 HEAD/GET (Class B) calls
# every run but, before this audit, never reported them through
# scripts/r2_cost_guard.py's shared cost ledger -- the only R2-mutating/
# -reading scripts visible in data/quality/r2_cost_guard_report.json were
# r2_upload.py and r2_report_publisher.py's Class A operations. Counted at
# the call site (verify_one() runs inside a bounded thread pool -- see
# VERIFY_MAX_WORKERS) rather than reconstructed after the fact from result
# dicts, which cannot unambiguously distinguish every HEAD/GET sub-case.
_op_count_lock = threading.Lock()
_head_call_count = 0
_get_call_count = 0


def _count_head_call() -> None:
    global _head_call_count
    with _op_count_lock:
        _head_call_count += 1


def _count_get_call() -> None:
    global _get_call_count
    with _op_count_lock:
        _get_call_count += 1
# CodeRabbit finding: worst case (every report exhausts retries) is
# PUBLIC_MAX_RETRIES * (PUBLIC_TIMEOUT + PUBLIC_RETRY_DELAY) per report --
# at 150+ in-window reports that can exceed STAGE 3.6a's workflow timeout
# (deploy-worker.yml / sentinel-blogger.yml, 15 min) before this script ever
# reaches its own manifest write, losing ALL results for the run rather than
# just the unreachable ones. RUN_DEADLINE_SECONDS bounds total wall-clock
# time across the whole in-window loop (both R2 and public layers) well
# under that limit; any report not yet started when the deadline is hit is
# recorded explicitly (not silently dropped) and the manifest is still
# written with everything processed so far.
RUN_DEADLINE_SECONDS = 600

# P0 R2 COST AUDIT FIX: shared with scripts/r2_report_publisher.py -- one env
# var, one source of truth for what "in-window" means across every script
# that touches the reports keyspace. Default 24h.
def _report_window_hours() -> int:
    raw = os.environ.get("REPORT_WINDOW_HOURS", "").strip()
    if not raw:
        return 24
    try:
        return int(raw)
    except ValueError:
        return 24


REPORT_WINDOW_HOURS = _report_window_hours()

# P0 R2 COST AUDIT FIX: hard, independent ceiling on how many reports this
# script will ever verify in one run -- deliberately separate from the
# time-window filter above (belt AND suspenders), matching this codebase's
# own established convention (scripts/r2_reports_integrity.py's
# MAX_CHECK=200) rather than inventing a new one. Each verified item costs
# up to 1 HEAD + 1 GET against R2 plus up to 2 public-HTTP fetches (+ an
# optional cache-purge round trip), run inside VERIFY_MAX_WORKERS threads
# under RUN_DEADLINE_SECONDS -- this is the single most expensive
# per-item operation in the whole reports pipeline, so it gets the same
# conservative cap as its cheaper sibling, not a larger one.
MAX_VERIFY_ITEMS = int(os.environ.get("MAX_VERIFY_ITEMS", "200"))

# RX-PUB-A0.6D: real production evidence (sentinel-blogger.yml run
# 31761997953, 2026-08-14, pre-6D code) showed this deadline being hit hard
# under real load -- sequential processing covered only 170 of 518 in-window
# reports (~3.53s/report: one R2 head + one R2 get-object + a Worker
# publication-status fetch + a public HTTPS GET, each independent
# subprocess/HTTP I/O) before RUN_DEADLINE_SECONDS cut it off, leaving 348
# reports (67%) as LIVE_NOT_PROCESSED_DEADLINE every single run -- not a
# tail case, the normal case. Each report's checks are independent (no
# shared mutable state between them; verify_one() reads only the read-only
# module-level R2 credential constants captured once at import time), so
# they parallelize safely with a bounded worker pool -- same
# ThreadPoolExecutor(max_workers=...) + future-map idiom
# scripts/r2_reports_integrity.py's own parallel R2 existence-check loop
# already established (Reuse Before Build / Single Source of Truth for the
# concurrency pattern, not just the R2 primitives). 8 workers keeps this a
# small, bounded number of concurrent connections against this platform's
# own production origin and Cloudflare/R2 endpoints -- nowhere near load or
# rate-limit territory -- while cutting the ~1830s sequential-equivalent
# cost for 518 reports (518 * 3.53s) to a projected ~230s, leaving
# substantial margin under RUN_DEADLINE_SECONDS instead of running the full
# budget out on every single run.
VERIFY_MAX_WORKERS = 8
_SAFE_RESPONSE_HEADERS = (
    "cf-ray", "cache-control", "age", "etag", "last-modified",
    "cf-cache-status", "content-length", "content-type",
    # RX-PUB-A0.6D follow-up: needed so _retry_after_seconds() can read a
    # 429 response's own backoff hint instead of always using the fixed
    # PUBLIC_RETRY_DELAY.
    "retry-after",
)

# RX-PUB-A0.6B: same Cloudflare zone-level cache-purge secrets
# .github/workflows/dashboard-feeds-sync.yml already uses for its own static
# URL list (Section 4 reuse mandate) -- not a new credential. Both optional:
# if unset, purge is skipped (never attempted, never a hard failure) exactly
# like that workflow's own "[SKIP] CF_ZONE_ID or CF_CACHE_PURGE_TOKEN not
# configured" behavior.
CF_ZONE_ID          = os.environ.get("CF_ZONE_ID", "").strip()
CF_CACHE_PURGE_TOKEN = os.environ.get("CF_CACHE_PURGE_TOKEN", "").strip()
CACHE_PURGE_TIMEOUT = 15


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_age_hours(entry: dict, now: datetime) -> float | None:
    """Same field precedence and parser as r2_report_publisher.py's
    canonical_age(): timestamp -> processed_at -> published_at, via
    canonical_timestamp.parse_timestamp(). Returns None (never a bare
    exception) when no field is present or parsing failed -- callers must
    treat that as "cannot prove this is in-window", exactly matching the
    publisher's own fail-safe convention, not "assume fresh" or "assume
    stale"."""
    raw = entry.get("timestamp") or entry.get("processed_at") or entry.get("published_at")
    if not raw:
        return None
    result = parse_timestamp(raw)
    if result.parse_status != "SUCCESS" or result.normalized is None:
        return None
    return (now - result.normalized).total_seconds() / 3600.0


def _load_in_window_entries(window_hours: int, now: datetime) -> list[dict]:
    """P0 R2 COST AUDIT FIX: this function's name has always promised
    "in window" entries, but until this fix it returned the ENTIRE manifest
    unconditionally -- see the module docstring's "P0 R2 COST AUDIT FIX"
    note above. Now genuinely filters to REPORT_WINDOW_HOURS via the same
    canonical-timestamp precedence r2_report_publisher.py uses, so this
    script's scope tracks what is actually live in R2 rather than the
    manifest's total historical size."""
    if not MANIFEST_PATH.exists():
        return []
    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Cannot parse %s: %s", MANIFEST_PATH, e)
        return []
    if isinstance(data, list):
        all_entries = data
    else:
        all_entries = []
        for key in ("advisories", "items", "data", "entries"):
            if isinstance(data.get(key), list):
                all_entries = data[key]
                break

    in_window: list[dict] = []
    skipped_out_of_window = 0
    skipped_unparseable = 0
    for entry in all_entries:
        age_hours = _canonical_age_hours(entry, now)
        if age_hours is None:
            skipped_unparseable += 1
            continue
        if 0 <= age_hours <= window_hours:
            in_window.append(entry)
        else:
            skipped_out_of_window += 1

    if skipped_out_of_window or skipped_unparseable:
        log.info(
            "Manifest has %d total entries; %d outside the %dh verification window, "
            "%d with no parseable canonical timestamp (both excluded -- fail-safe, "
            "matches r2_report_publisher.py's own in-window contract) -- %d in-window.",
            len(all_entries), skipped_out_of_window, window_hours, skipped_unparseable, len(in_window),
        )
    return in_window


def _local_report_path(entry: dict) -> Path | None:
    ru = (entry.get("internal_report_url") or entry.get("report_url") or "").strip()
    if ru.startswith("/"):
        p = REPO_ROOT / ru.lstrip("/")
        return p if p.exists() else None
    intel_id = entry.get("id") or entry.get("stix_id")
    if not intel_id:
        return None
    matches = sorted((REPO_ROOT / "reports").rglob(f"{intel_id}.html"))
    return matches[0] if matches else None


def _r2_key_for(local_path: Path) -> str:
    return str(local_path.relative_to(REPO_ROOT)).replace(os.sep, "/")


class PublicFetchConfigError(ValueError):
    """PUBLIC_BASE_URL (or RX_PUB_A0_PUBLIC_BASE_URL override) failed the
    scheme/host allowlist check. Raised at call time, not import time, so a
    bad override fails the specific fetch loudly rather than silently
    falling through to an unrestricted request."""


def _validate_public_url(url: str) -> None:
    """CodeRabbit SSRF finding (CWE-918): RX_PUB_A0_PUBLIC_BASE_URL is
    CI-environment-controlled, not end-user input, so the practical exposure
    is low -- but urlopen() with a request-influenced URL and no host/scheme
    restriction is exactly the ast-grep urlopen-unsanitized-data pattern, and
    costs nothing to close. HTTPS-only, plus an explicit allowlist covering
    the real production host and RX_PUB_A0_PUBLIC_ALLOWED_HOSTS-provided test
    hosts (comma-separated, e.g. for local/dev overrides) -- never a wildcard
    fallback that would defeat the allowlist's purpose."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise PublicFetchConfigError(f"public fetch URL must be https, got scheme={parsed.scheme!r}: {url}")
    extra_hosts = {
        h.strip().lower() for h in os.environ.get("RX_PUB_A0_PUBLIC_ALLOWED_HOSTS", "").split(",") if h.strip()
    }
    allowed_hosts = {"intel.cyberdudebivash.com"} | extra_hosts
    if (parsed.hostname or "").lower() not in allowed_hosts:
        raise PublicFetchConfigError(
            f"public fetch host {parsed.hostname!r} not in allowlist {sorted(allowed_hosts)} "
            f"(set RX_PUB_A0_PUBLIC_ALLOWED_HOSTS to add test hosts): {url}"
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disables following redirects entirely for the public fetch opener --
    simpler and strictly safer than validating each redirect hop against the
    allowlist, and this endpoint family has no legitimate reason to redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_PUBLIC_OPENER = urllib.request.build_opener(_NoRedirect)



# RX-PUB-A0 STAGE 3.6a timeout postmortem (sentinel-blogger.yml run
# 33630720481, 2026-09-02): the step was force-killed by its 15-minute
# timeout-minutes budget at 13:39:09Z, but main()'s own RUN_DEADLINE_SECONDS
# (600s) budgeting had already completed and logged the full run summary at
# 13:34:00Z -- 309s earlier. Root cause: pool.shutdown(wait=False,
# cancel_futures=True) below only cancels not-yet-started futures; an
# in-flight verify_one() call keeps running on its ThreadPoolExecutor worker
# thread, and those threads are non-daemon, so the OS process (and thus this
# step) cannot actually exit until every one of them returns, however long
# that takes -- sys.exit(0) in the main thread does not preempt them. An
# origin-supplied Retry-After value was previously accepted unbounded, so a
# single 429 response naming a large delay (e.g. 300s) could hold one worker
# thread -- and therefore the whole process -- alive well past
# RUN_DEADLINE_SECONDS, long enough to collide with the external
# timeout-minutes kill. Capping the honored delay below closes that specific
# gap: no single retry sleep can ever run long enough to matter, so every
# worker thread is guaranteed to finish within a small, bounded time after
# the main thread's own deadline logic already gave up on it.
RETRY_AFTER_CAP_SECONDS = PUBLIC_TIMEOUT


def _retry_after_seconds(headers: dict) -> float | None:
    """Parses a Retry-After header value (seconds form only -- the HTTP-date
    form exists but every 429 observed from this origin has used the seconds
    form, and misparsing a date as garbage is worse than falling back to the
    fixed delay). Returns None if absent, unparseable, negative, or
    non-finite -- CodeRabbit finding: float() accepts "-1" and "inf", and
    the prior max(0.0, ...) clamp turned a negative value into an immediate
    retry (worse than the fixed delay it was meant to replace) while an
    infinite value would reach time.sleep() and hang that worker thread
    indefinitely. Also capped at RETRY_AFTER_CAP_SECONDS: an origin is free
    to name any delay it likes, but honoring an arbitrarily large one verbatim
    can keep a non-daemon worker thread (and therefore this whole process)
    alive well past main()'s own RUN_DEADLINE_SECONDS budget -- see the
    STAGE 3.6a timeout postmortem above. Still always at least as cooperative
    as the fixed PUBLIC_RETRY_DELAY this replaces."""
    raw = headers.get("retry-after")
    if not raw:
        return None
    try:
        delay = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(delay) or delay < 0:
        return None
    return min(delay, RETRY_AFTER_CAP_SECONDS)


def _fetch_public(url: str) -> dict:
    """GET the customer-facing public URL. Returns a dict with 'bytes' (or
    None on failure), 'status', and safe response headers only -- never logs
    or returns the raw response body beyond what the caller hashes in
    memory. Bounded retries, matching the R2 helpers' retry policy. Redirects
    are not followed (see _NoRedirect) and the target is validated against an
    HTTPS+host allowlist before every attempt (see _validate_public_url).

    RX-PUB-A0.6D follow-up: every network attempt is gated by
    _public_fetch_semaphore (see PUBLIC_FETCH_MAX_CONCURRENCY above) so the
    bounded worker pool's parallelism doesn't translate into a burst of
    simultaneous requests against the shared public origin -- confirmed root
    cause of a real HTTP 429 spike on the first 6D-inclusive production run.
    A 429 response also backs off using the origin's own Retry-After header
    when present, rather than always waiting the fixed PUBLIC_RETRY_DELAY."""
    _validate_public_url(url)
    last_status = None
    last_error = None
    last_headers: dict = {}
    for attempt in range(1, PUBLIC_MAX_RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelApex-RX-PUB-A0-Verifier/1.0"})
        with _public_fetch_semaphore:
            try:
                with _PUBLIC_OPENER.open(req, timeout=PUBLIC_TIMEOUT) as resp:
                    body = resp.read()
                    headers = {k.lower(): v for k, v in resp.getheaders() if k.lower() in _SAFE_RESPONSE_HEADERS}
                    return {"bytes": body, "status": resp.status, "headers": headers, "error": None}
            except urllib.error.HTTPError as e:
                last_status = e.code
                last_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else []) if k.lower() in _SAFE_RESPONSE_HEADERS}
                if e.code == 404:
                    return {"bytes": None, "status": 404, "headers": last_headers, "error": "HTTP 404"}
                last_error = f"HTTP {e.code}"
            except Exception as e:
                last_error = str(e)
        if attempt < PUBLIC_MAX_RETRIES:
            delay = PUBLIC_RETRY_DELAY
            if last_status == 429:
                retry_after = _retry_after_seconds(last_headers)
                if retry_after is not None:
                    delay = retry_after
            time.sleep(delay)
    return {"bytes": None, "status": last_status, "headers": last_headers, "error": last_error or "fetch failed"}


# RX-PUB-A0.6A: publication-gate awareness. Calls the platform's own,
# already-live /api/v1/reports/{id}/publication-status endpoint -- the same
# HTTP-boundary-reuse pattern _fetch_public already uses for report bodies --
# rather than re-deriving a P20/P21/P23/P25/P26 verdict in Python (mission
# Section 5's explicit prohibition on duplicating that logic).
PUBLICATION_STATUS_PATH_TEMPLATE = "api/v1/reports/{intel_id}/publication-status"


def _fetch_publication_status(intel_id: str) -> dict:
    """Returns {"customer_ready": bool|None, "state": str|None,
    "reason_codes": list, "fetch_error": str|None}. A None customer_ready
    always means "we could not determine this," never "false" -- callers
    must not treat a fetch failure as an implicit denial verdict."""
    url = f"{PUBLIC_BASE_URL}/{PUBLICATION_STATUS_PATH_TEMPLATE.format(intel_id=intel_id)}"
    try:
        resp = _fetch_public(url)
    except PublicFetchConfigError as e:
        return {"customer_ready": None, "state": None, "reason_codes": [], "fetch_error": str(e)}
    if resp["bytes"] is None:
        return {
            "customer_ready": None, "state": None, "reason_codes": [],
            "fetch_error": resp.get("error") or f"HTTP {resp.get('status')}",
        }
    try:
        data = json.loads(resp["bytes"])
    except Exception as e:
        return {"customer_ready": None, "state": None, "reason_codes": [], "fetch_error": f"invalid JSON: {e}"}
    return {
        "customer_ready": data.get("customer_ready"),
        "state":          data.get("state"),
        "reason_codes":   data.get("reason_codes") or [],
        "fetch_error":    None,
    }


def _expected_live_behavior(pub_status: dict) -> str:
    """Maps a publication-status result to what the public HTTP layer SHOULD
    do, per mission Section 6. PENDING_PUBLICATION / HISTORICAL_POLICY are
    reserved for future extension -- the live publication-status API does not
    yet return either, so they are never produced here; adding them later is
    additive (new elif branch), not a breaking change to this function."""
    if pub_status.get("fetch_error"):
        return "UNKNOWN_EXPECTATION"
    customer_ready = pub_status.get("customer_ready")
    if customer_ready is True:
        return "SERVE_CANONICAL_ARTIFACT"
    if customer_ready is False:
        if "ITEM_NOT_RESOLVABLE" in (pub_status.get("reason_codes") or []):
            return "UNKNOWN_EXPECTATION"
        return "DENY_PUBLICATION_GATE"
    return "UNKNOWN_EXPECTATION"


def _unresolvable_live_state(pub_status: dict) -> str:
    """Distinguishes, within UNKNOWN_EXPECTATION, a platform-side resolver
    gap (LIVE_RESOLUTION_FAILED -- RX-PUB-A0.6C's target) from this
    verifier's own inability to reach/parse publication-status
    (LIVE_UNKNOWN -- a verifier-side transient, not a platform defect)."""
    if pub_status.get("fetch_error"):
        return "LIVE_UNKNOWN"
    if "ITEM_NOT_RESOLVABLE" in (pub_status.get("reason_codes") or []):
        return "LIVE_RESOLUTION_FAILED"
    return "LIVE_UNKNOWN"


def _purge_public_url(url: str) -> bool:
    """RX-PUB-A0.6B: precise, single-URL Cloudflare cache purge -- never a
    zone-wide purge (mission Section 14). Reuses the exact CF_ZONE_ID /
    CF_CACHE_PURGE_TOKEN secrets and purge_cache API call
    .github/workflows/dashboard-feeds-sync.yml already uses for its own
    static URL list; this is the same mechanism applied to a dynamically
    detected stale report URL instead of a fixed list.

    Returns True only on a confirmed-successful Cloudflare API response.
    Never raises -- a purge failure must never crash STAGE 3.6a or be
    confused with an R2/identity failure. Never logs the token.

    Ordering contract (mission Section 15): callers MUST only invoke this
    after the R2 layer has confirmed remote_sha256 == artifact_sha256 for
    this exact report -- never purge toward a canonical object that has not
    been verified. verify_one() below enforces this by construction (this
    function is only reachable from the SERVE_CANONICAL_ARTIFACT branch,
    which runs after the R2-layer check)."""
    if not (CF_ZONE_ID and CF_CACHE_PURGE_TOKEN):
        return False
    try:
        _validate_public_url(url)
    except PublicFetchConfigError:
        # Same host/scheme allowlist as every other outbound call in this
        # script (mission Section 36) -- never purge an unvalidated target.
        return False
    try:
        body = json.dumps({"files": [url]}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/purge_cache",
            data=body, method="POST",
            headers={
                "Authorization": f"Bearer {CF_CACHE_PURGE_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=CACHE_PURGE_TIMEOUT) as resp:
            result = json.loads(resp.read())
            return bool(result.get("success"))
    except Exception as e:
        log.warning("Cache purge request failed for %s: %s", url, e)
        return False


def _attempt_purge_and_reverify(result: dict, public_url: str, local_sha256: str) -> None:
    """RX-PUB-A0.6B: mutates `result` in place. Only ever called for a
    report the publication gate expects to serve, and only from call sites
    that have already confirmed `publication_state == "REMOTE_VERIFIED"`
    (mission Section 15 -- never purge toward an unverified canonical
    object). Purges the exact URL once, then re-fetches once (bounded, not
    a retry loop -- a purge either takes effect promptly or it did not
    succeed) to check whether the edge has converged with R2."""
    result["cache_purge_attempted"] = True
    purged = _purge_public_url(public_url)
    result["cache_purge_succeeded"] = purged
    if not purged:
        result["public_still_stale"] = True
        return
    try:
        recheck = _fetch_public(public_url)
    except PublicFetchConfigError:
        result["public_still_stale"] = True
        return
    if recheck["bytes"] is not None and _sha256_bytes(recheck["bytes"]) == local_sha256:
        result["live_state"] = "LIVE_VERIFIED"
        result["public_sha256"] = local_sha256
        result["public_verified_at"] = _verifier._utc_now()
        result["public_verified_after_invalidation"] = True
        result["public_response_headers"] = recheck["headers"]
        result.pop("public_error", None)
    else:
        result["public_still_stale"] = True


def verify_one(local_path: Path, r2_key: str, skip_public: bool = False) -> dict:
    local_bytes = local_path.read_bytes()
    local_sha256 = _sha256_bytes(local_bytes)
    result = {
        "r2_key":         r2_key,
        "size_bytes":     len(local_bytes),
        "generator":      GENERATOR_NAME,
        "artifact_sha256": local_sha256,
        "remote_sha256":  None,
        "remote_verified_at": None,
        "publication_state": "PENDING",
        "public_sha256":  None,
        "public_verified_at": None,
        "live_state":     "PENDING",
        "public_response_headers": {},
        # RX-PUB-A0.6A: publication-gate-aware fields (see _fetch_publication_status /
        # _expected_live_behavior below). None until the public-HTTP layer runs.
        "publication_gate_state": None,
        "customer_ready": None,
        "expected_live_behavior": None,
        "publication_gate_bypass": False,
        # RX-PUB-A0.6B
        "cache_purge_attempted": False,
        "cache_purge_succeeded": None,
        "public_verified_after_invalidation": False,
        "public_still_stale": False,
    }

    # -- R2 layer (LOCAL vs R2) -----------------------------------------
    _count_head_call()
    head = _verifier._s3api_head_object(BUCKET_REPORTS, r2_key)
    if head is None:
        _count_head_call()
        head = _verifier._boto3_head_object(BUCKET_REPORTS, r2_key)

    if head is None:
        result["publication_state"] = "UNKNOWN"
        result["error"] = "head-object failed via both awscli and boto3"
    elif head["status"] == 404:
        result["publication_state"] = "FAILED"
        result["error"] = "R2 object does not exist"
    else:
        _count_get_call()
        remote_bytes = _get_object_bytes(BUCKET_REPORTS, r2_key)
        if remote_bytes is None:
            result["publication_state"] = "UNKNOWN"
            result["error"] = "get-object failed -- could not fetch remote bytes for SHA-256 comparison"
        else:
            remote_sha256 = _sha256_bytes(remote_bytes)
            result["remote_sha256"] = remote_sha256
            result["remote_verified_at"] = _verifier._utc_now()
            if remote_sha256 == local_sha256:
                result["publication_state"] = "REMOTE_VERIFIED"
            else:
                result["publication_state"] = "STALE_OR_DIVERGENT"
                result["error"] = (
                    f"artifact_sha256 ({local_sha256[:16]}...) != remote_sha256 "
                    f"({remote_sha256[:16]}...) -- local and R2 bytes diverge"
                )

    # -- Public HTTP layer (R2 vs CUSTOMER) -- runs independently of the --
    # R2 credential-gated checks above; needs no R2 credentials at all.
    if skip_public:
        return result

    # RX-PUB-A0.6A: before judging byte identity, determine what the
    # platform's own publication gate says SHOULD happen for this report.
    # Reuses the already-live, already-authoritative
    # /api/v1/reports/{id}/publication-status endpoint (wrapping
    # evaluatePublicationGate) -- per mission Section 5, never reimplements
    # P20/P21/P23/P25/P26 logic in Python. RX-PUB-A0.5 Run 1 (PR #192) and
    # RX-PUB-A0.6's Phase 0 (docs/RX_PUB_A0_6_PROOF_BEFORE_CHANGE.md) showed
    # that treating every non-matching byte comparison as "divergence" was
    # wrong: most of them were the gate correctly denying a below-threshold
    # report, or a resolver miss the gate never got to evaluate at all.
    intel_id = Path(r2_key).stem
    pub_status = _fetch_publication_status(intel_id)
    result["publication_gate_state"] = pub_status.get("state")
    result["customer_ready"] = pub_status.get("customer_ready")
    expected = _expected_live_behavior(pub_status)
    result["expected_live_behavior"] = expected

    public_url = f"{PUBLIC_BASE_URL}/{r2_key}"
    try:
        public = _fetch_public(public_url)
    except PublicFetchConfigError as e:
        result["live_state"] = "LIVE_FETCH_FAILED"
        result["public_error"] = f"public fetch target rejected by allowlist: {e}"
        return result
    result["public_response_headers"] = public["headers"]
    served_is_html = "text/html" in (public["headers"].get("content-type") or "")

    if public["status"] == 404:
        if expected == "DENY_PUBLICATION_GATE":
            result["live_state"] = "LIVE_EXPECTED_DENIAL"
        elif expected == "SERVE_CANONICAL_ARTIFACT":
            result["live_state"] = "LIVE_MISSING_UNEXPECTED"
            result["public_error"] = (
                "publication gate says customer_ready=true but public HTTP GET returned 404"
            )
            # RX-PUB-A0.6B: a 404 for a gate-approved report whose R2 copy
            # is independently confirmed correct could be a stale/negative
            # cache entry (mission Section 13) -- try a precise purge and
            # one re-fetch before accepting this as a genuine defect. Never
            # purges toward an object R2 itself hasn't verified.
            if result["publication_state"] == "REMOTE_VERIFIED":
                _attempt_purge_and_reverify(result, public_url, local_sha256)
        else:
            result["live_state"] = _unresolvable_live_state(pub_status)
            result["public_error"] = "public HTTP GET returned 404; publication gate could not evaluate this report"
    elif public["bytes"] is None:
        result["live_state"] = "LIVE_FETCH_FAILED"
        result["public_error"] = public.get("error") or "public HTTP GET failed"
    else:
        public_sha256 = _sha256_bytes(public["bytes"])
        result["public_sha256"] = public_sha256
        result["public_verified_at"] = _verifier._utc_now()
        served_matches_canonical = public_sha256 == local_sha256

        if expected == "DENY_PUBLICATION_GATE" and public["status"] == 200 and served_is_html:
            # HARD DEFECT (mission RX-PUB-A0.6 Section 9, verbatim): the
            # publication gate says this report must not be served, but the
            # public route returned a real HTML body anyway -- regardless of
            # whether that body happens to match the canonical artifact.
            # Never silently folded into LIVE_STALE_OR_DIVERGENT.
            result["live_state"] = "PUBLICATION_GATE_BYPASS"
            result["publication_gate_bypass"] = True
            result["public_error"] = (
                "HARD DEFECT: publication gate says customer_ready=false but the public "
                "route served an HTML body -- publication gate bypass"
            )
        elif expected == "DENY_PUBLICATION_GATE":
            # 200 but not an HTML body (e.g. the gate's own JSON denial
            # response) -- correct, expected behavior.
            result["live_state"] = "LIVE_EXPECTED_DENIAL"
        elif expected == "SERVE_CANONICAL_ARTIFACT":
            if served_matches_canonical:
                result["live_state"] = "LIVE_VERIFIED"
            else:
                result["live_state"] = "LIVE_STALE_OR_DIVERGENT"
                result["public_error"] = (
                    f"artifact_sha256 ({local_sha256[:16]}...) != public_sha256 "
                    f"({public_sha256[:16]}...) -- local and customer-served bytes diverge"
                )
                # RX-PUB-A0.6B: the confirmed root cause (docs/RX_PUB_A0_6_
                # PROOF_BEFORE_CHANGE.md Phase 0) -- a gate-approved,
                # R2-verified-correct report can still be served stale
                # bytes by a lagging Cloudflare edge POP. Purge the exact
                # URL and re-check once before accepting this as terminal.
                if result["publication_state"] == "REMOTE_VERIFIED":
                    _attempt_purge_and_reverify(result, public_url, local_sha256)
        else:
            # UNKNOWN_EXPECTATION: the gate never evaluated this report (a
            # resolver miss / ITEM_NOT_RESOLVABLE), or our own fetch of its
            # verdict failed -- byte equality is not a meaningful question
            # when we don't know what SHOULD be served (mission Section 30,
            # Question B unanswerable). Never counted as a hash match or a
            # divergence either way.
            result["live_state"] = _unresolvable_live_state(pub_status)
            result["public_error"] = (
                "publication gate could not evaluate this report -- serving status not "
                "verifiable against an expectation"
            )

    return result


def _get_object_bytes(bucket: str, key: str) -> bytes | None:
    """get-object via the same awscli s3api pattern _s3api_head_object uses.
    Not present in r2_upload_verifier.py (it only ever needed head-object) --
    this is the one genuinely new primitive this script adds, kept as small
    and consistent with the existing helper's style as possible."""
    import subprocess
    import tempfile

    if not (_verifier.CF_ACCOUNT_ID and _verifier.ACCESS_KEY and _verifier.SECRET_KEY):
        return None

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = _verifier.ACCESS_KEY
    env["AWS_SECRET_ACCESS_KEY"] = _verifier.SECRET_KEY
    env["AWS_DEFAULT_REGION"]    = "auto"

    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "obj"
        cmd = [
            "aws", "s3api", "get-object",
            "--bucket", bucket, "--key", key,
            "--endpoint-url", _verifier.R2_ENDPOINT,
            str(out_path),
        ]
        for attempt in range(1, _verifier.MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=_verifier.REQUEST_TIMEOUT, env=env,
                )
                if result.returncode == 0 and out_path.exists():
                    return out_path.read_bytes()
                log.warning(
                    "get-object failed (attempt %d/%d) for s3://%s/%s: rc=%d stderr=%s",
                    attempt, _verifier.MAX_RETRIES, bucket, key,
                    result.returncode, result.stderr.strip()[:200],
                )
            except Exception as e:
                log.warning(
                    "get-object error (attempt %d/%d) for s3://%s/%s: %s",
                    attempt, _verifier.MAX_RETRIES, bucket, key, e,
                )
            if attempt < _verifier.MAX_RETRIES:
                time.sleep(_verifier.RETRY_DELAY)
    return None


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enforce", action="store_true",
        help="Hard-fail (nonzero exit) on any STALE_OR_DIVERGENT/FAILED R2 report or "
             "LIVE_STALE_OR_DIVERGENT public report. Not passed in CI yet -- "
             "observability-only bake-in period, matching the same rollout pattern "
             "scripts/report_engine_consistency_gate.py already established for a new "
             "gate on this exact keyspace. Once a run history exists showing zero "
             "false positives, add --enforce to the STAGE 3.6a workflow step to make "
             "this a real HARD FAIL gate (RX-PUB-A0 Section 25 requires this eventually)."
    )
    parser.add_argument(
        "--skip-public", action="store_true",
        help="Skip the public HTTP fetch/SHA-256 layer (R2-only, PR #183's original "
             "scope). Escape hatch for cost governance (Section 37) if public "
             "verification duration becomes a measured problem; not used by default."
    )
    args = parser.parse_args()

    r2_creds_present = bool(_verifier.CF_ACCOUNT_ID and _verifier.ACCESS_KEY and _verifier.SECRET_KEY)

    log.info("=" * 70)
    log.info("RX-PUB-A0 Reports Artifact Identity Verifier")
    log.info("Bucket: %s  |  in-window manifest: %s", BUCKET_REPORTS, MANIFEST_PATH)
    log.info("Public base URL: %s  |  public checks: %s", PUBLIC_BASE_URL, "OFF" if args.skip_public else "ON")
    log.info("R2 credentials: %s", "configured" if r2_creds_present else "missing")
    log.info("Mode: %s", "ENFORCE (hard fail on mismatch)" if args.enforce else "observability-only (bake-in)")
    log.info("=" * 70)
    t0 = time.time()

    if not r2_creds_present and args.skip_public:
        log.warning(
            "R2 credentials absent and --skip-public set -- nothing to verify. "
            "Trusting Stage 3.5 exit code as source of truth for this run (same "
            "soft-pass posture as r2_upload_verifier.py's own credential-absent path)."
        )
        return 0
    if not r2_creds_present:
        log.warning(
            "R2 credentials absent (CF_ACCOUNT_ID / AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY) -- R2 layer will classify every report UNKNOWN. "
            "Public HTTP layer needs no R2 credentials and still runs."
        )

    now = datetime.now(timezone.utc)
    entries = _load_in_window_entries(REPORT_WINDOW_HOURS, now)
    log.info("In-window (%dh) manifest entries: %d (MAX_VERIFY_ITEMS=%d)",
             REPORT_WINDOW_HOURS, len(entries), MAX_VERIFY_ITEMS)

    manifest_out: dict = {
        "schema_version": "2",
        "generated_at":   _verifier._utc_now(),
        "pipeline_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "release_sha":    os.environ.get("GITHUB_SHA", "unknown"),
        "bucket":         BUCKET_REPORTS,
        "public_base_url": PUBLIC_BASE_URL,
        "reports":        {},
    }

    verified = 0
    mismatched = 0
    missing_local = 0
    unknown = 0
    live_verified = 0
    live_mismatched = 0
    live_unknown = 0
    # RX-PUB-A0.6A: distinct counters per mission Section 32 -- an expected
    # denial must never be combined with a genuine failure, and a bypass
    # must never be silently absorbed into either.
    live_expected_denial = 0
    live_resolution_failed = 0
    live_fetch_failed = 0
    live_not_processed_deadline = 0
    live_not_processed_budget = 0
    publication_gate_bypass = 0
    # RX-PUB-A0.6B: mission Section 35 -- event-derived only, counted from
    # what _attempt_purge_and_reverify actually recorded per report.
    cache_invalidations_attempted = 0
    cache_invalidations_succeeded = 0
    cache_invalidations_failed = 0
    public_verified_after_invalidation = 0
    public_still_stale = 0

    def _classify_result(intel_id: str, result: dict) -> None:
        # RX-PUB-A0.6D: unchanged classification logic, only relocated so it
        # can run once per completed future below instead of once per loop
        # iteration -- every branch and counter here is identical to the
        # pre-6D sequential version.
        nonlocal verified, mismatched, unknown, live_verified, live_mismatched
        nonlocal live_unknown, live_expected_denial, live_resolution_failed
        nonlocal live_fetch_failed, publication_gate_bypass
        nonlocal cache_invalidations_attempted, cache_invalidations_succeeded
        nonlocal cache_invalidations_failed, public_verified_after_invalidation
        nonlocal public_still_stale

        if result.get("cache_purge_attempted"):
            cache_invalidations_attempted += 1
            if result.get("cache_purge_succeeded"):
                cache_invalidations_succeeded += 1
            else:
                cache_invalidations_failed += 1
            if result.get("public_verified_after_invalidation"):
                public_verified_after_invalidation += 1
            elif result.get("public_still_stale"):
                public_still_stale += 1

        state = result["publication_state"]
        if state == "REMOTE_VERIFIED":
            verified += 1
        elif state == "STALE_OR_DIVERGENT" or state == "FAILED":
            mismatched += 1
            log.error("[%s] %s: %s", state, intel_id, result.get("error", ""))
        else:
            unknown += 1
            log.warning("[%s] %s: %s", state, intel_id, result.get("error", ""))

        live_state = result["live_state"]
        if live_state == "LIVE_VERIFIED":
            live_verified += 1
        elif live_state == "PUBLICATION_GATE_BYPASS":
            # Never combined with any other counter (mission Section 32) --
            # this is the single most severe outcome this verifier can
            # observe: a report the platform's own gate says must not be
            # served was served anyway.
            publication_gate_bypass += 1
            log.error("[PUBLICATION_GATE_BYPASS] %s: %s", intel_id, result.get("public_error", ""))
        elif live_state == "LIVE_EXPECTED_DENIAL":
            # Correct, intended behavior -- the gate denied and the public
            # route correctly withheld the body. Not a failure; tracked
            # separately so it can never inflate a failure count.
            live_expected_denial += 1
        elif live_state in ("LIVE_STALE_OR_DIVERGENT", "LIVE_MISSING_UNEXPECTED"):
            live_mismatched += 1
            log.error("[%s] %s: %s", live_state, intel_id, result.get("public_error", ""))
        elif live_state == "LIVE_RESOLUTION_FAILED":
            # Gate never evaluated this report (resolver miss) -- a real,
            # separate defect class (RX-PUB-A0.6C), but not evidence of
            # divergent bytes, since there is no expectation to compare
            # against yet.
            live_resolution_failed += 1
            log.warning("[LIVE_RESOLUTION_FAILED] %s: %s", intel_id, result.get("public_error", ""))
        elif live_state == "LIVE_FETCH_FAILED":
            live_fetch_failed += 1
            log.warning("[LIVE_FETCH_FAILED] %s: %s", intel_id, result.get("public_error", ""))
        elif live_state != "PENDING":
            live_unknown += 1
            log.warning("[%s] %s: %s", live_state, intel_id, result.get("public_error", ""))

    # RX-PUB-A0.6D: build the work list first (cheap, local-only checks --
    # no network I/O), then dispatch every report's verify_one() call to a
    # bounded worker pool instead of one report at a time. See
    # VERIFY_MAX_WORKERS above for the measured evidence driving this.
    work_items: list[tuple[str, dict, Path, str]] = []
    for entry in entries:
        intel_id = entry.get("id") or entry.get("stix_id")
        if not intel_id:
            continue
        local_path = _local_report_path(entry)
        if not local_path:
            missing_local += 1
            manifest_out["reports"][intel_id] = {
                "publication_state": "FAILED",
                "live_state": "UNKNOWN",
                "error": "no local HTML artifact found for an in-window manifest entry",
            }
            continue
        work_items.append((intel_id, entry, local_path, _r2_key_for(local_path)))

    # P0 R2 COST AUDIT FIX: hard, independent ceiling -- deliberately checked
    # AFTER the time-window filter above, not instead of it, so a defect in
    # that filter can never again let this script's R2/public-HTTP call
    # volume scale with feed_manifest.json's total size (historical evidence:
    # 150-1040 calls/run before this fix). Keeps the most recently-timestamped
    # items (most relevant to verify freshness for) and records the rest
    # explicitly -- never silently dropped, matching this script's own
    # established NOT_PROCESSED_DEADLINE convention below.
    budget_overflow_count = 0
    if len(work_items) > MAX_VERIFY_ITEMS:
        budget_overflow_count = len(work_items) - MAX_VERIFY_ITEMS
        log.warning(
            "In-window work items (%d) exceed MAX_VERIFY_ITEMS=%d -- verifying only the "
            "%d most recently-timestamped and recording the rest as "
            "NOT_PROCESSED_BUDGET (never silently dropped).",
            len(work_items), MAX_VERIFY_ITEMS, MAX_VERIFY_ITEMS,
        )

        def _entry_sort_key(item: tuple[str, dict, Path, str]) -> str:
            _iid, _entry, _lp, _rk = item
            return _entry.get("timestamp") or _entry.get("processed_at") or _entry.get("published_at") or ""

        work_items.sort(key=_entry_sort_key, reverse=True)
        overflow_items = work_items[MAX_VERIFY_ITEMS:]
        work_items = work_items[:MAX_VERIFY_ITEMS]
        for intel_id, _entry, _local_path, _r2_key in overflow_items:
            manifest_out["reports"][intel_id] = {
                "publication_state": "NOT_PROCESSED_BUDGET",
                "live_state": "LIVE_NOT_PROCESSED_BUDGET",
                "error": f"MAX_VERIFY_ITEMS ({MAX_VERIFY_ITEMS}) exceeded -- not verified this "
                         f"run (cost-governance hard cap, independent of the time-window filter)",
            }
            unknown += 1
            live_not_processed_budget += 1

    deadline_hit = False
    if work_items:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=VERIFY_MAX_WORKERS)
        future_map = {
            pool.submit(verify_one, local_path, r2_key, skip_public=args.skip_public): (intel_id, entry, local_path)
            for intel_id, entry, local_path, r2_key in work_items
        }
        remaining_budget = max(0.0, RUN_DEADLINE_SECONDS - (time.time() - t0))
        done, not_done = concurrent.futures.wait(future_map.keys(), timeout=remaining_budget)
        # Stop any not-yet-started work immediately and don't block on it --
        # already-running threads (bounded by their own internal per-call
        # timeouts) finish on their own after this function returns; we
        # simply don't wait for or use their results (mission Section 26/27:
        # "not yet started" and "started but unresolved" are both honestly
        # NOT_PROCESSED_DEADLINE, never silently dropped or misread as PASS).
        pool.shutdown(wait=False, cancel_futures=True)

        for future in done:
            intel_id, entry, local_path = future_map[future]
            try:
                result = future.result()
            except Exception as e:
                # A report whose own check crashed must never silently read
                # as verified (same "never fail-open" posture as every other
                # error path in this script) -- record it as unresolved
                # rather than letting one bad report abort the whole run.
                result = {
                    "publication_state": "UNKNOWN",
                    "live_state": "LIVE_UNKNOWN",
                    "error": f"verify_one raised: {e!r}",
                }
            result["source_record_id"] = intel_id
            result["source_updated_at"] = entry.get("processed_at") or entry.get("timestamp") or ""
            result["path"] = str(local_path.relative_to(REPO_ROOT))
            manifest_out["reports"][intel_id] = result
            _classify_result(intel_id, result)

        if not_done:
            deadline_hit = True
            log.error(
                "Run deadline (%ds) exceeded -- %d/%d in-window reports finished, "
                "%d did not (still in flight or never started) -- stopping and "
                "recording the rest as NOT_PROCESSED_DEADLINE rather than "
                "silently dropping them or letting the workflow step timeout "
                "kill this process before it writes the manifest.",
                RUN_DEADLINE_SECONDS, len(done), len(work_items), len(not_done),
            )
        for future in not_done:
            intel_id, _entry, _local_path = future_map[future]
            # RX-PUB-A0.6A: explicit deadline classification (mission Section
            # 26/27) -- distinct from a genuine fetch/resolution failure so a
            # future --enforce pass can treat "never reached" differently
            # from "reached and failed" if that distinction ever matters,
            # and so this never silently reads as an ordinary UNKNOWN.
            manifest_out["reports"][intel_id] = {
                "publication_state": "NOT_PROCESSED_DEADLINE",
                "live_state": "LIVE_NOT_PROCESSED_DEADLINE",
                "error": f"run deadline ({RUN_DEADLINE_SECONDS}s) exceeded before this "
                         f"report finished processing -- not processed this run",
            }
            unknown += 1
            live_not_processed_deadline += 1

    elapsed = round(time.time() - t0, 2)
    manifest_out["summary"] = {
        "total_in_window":  len(entries),
        "remote_verified":  verified,
        "stale_or_divergent_or_failed": mismatched,
        "unknown":          unknown,
        "missing_local":    missing_local,
        # Unchanged names/semantics -- scripts/ci_stats_extract.py's existing
        # "rx_pub_a0" extractor and any other consumer keep working exactly
        # as before (Backward Compatibility principle). live_verified is
        # unaffected by this PR's changes; live_stale_or_divergent_or_missing
        # and live_unknown now mean something narrower and more correct than
        # before (gate-expected-denials and gate-unresolvable reports are no
        # longer folded into them -- see the new fields below), which can
        # only ever make these two numbers smaller, never larger, for the
        # same underlying data.
        "live_verified":    live_verified,
        "live_stale_or_divergent_or_missing": live_mismatched,
        "live_unknown":     live_unknown,
        # RX-PUB-A0.6A: new, distinct semantic classes (mission Section 32) --
        # never combined with the failure counters above.
        "live_expected_denial":   live_expected_denial,
        "live_resolution_failed": live_resolution_failed,
        "live_fetch_failed":      live_fetch_failed,
        "live_not_processed_deadline": live_not_processed_deadline,
        # P0 R2 COST AUDIT FIX: items excluded by MAX_VERIFY_ITEMS, distinct
        # from live_not_processed_deadline (a wall-clock cutoff) -- this one
        # is a fixed count ceiling, hit regardless of how much time remained.
        "live_not_processed_budget": live_not_processed_budget,
        "max_verify_items": MAX_VERIFY_ITEMS,
        "report_window_hours": REPORT_WINDOW_HOURS,
        "publication_gate_bypass": publication_gate_bypass,
        # RX-PUB-A0.6B (mission Section 35)
        "cache_invalidations_attempted": cache_invalidations_attempted,
        "cache_invalidations_succeeded": cache_invalidations_succeeded,
        "cache_invalidations_failed":    cache_invalidations_failed,
        "public_verified_after_invalidation": public_verified_after_invalidation,
        "public_still_stale": public_still_stale,
        "elapsed_seconds":  elapsed,
        "run_deadline_exceeded": deadline_hit,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest_out, indent=2, default=str), encoding="utf-8")
    tmp.replace(OUTPUT_PATH)
    log.info("Wrote %s", OUTPUT_PATH)

    # Sync the manifest to R2 (BUCKET_DATA, intel/ prefix) so it's observable
    # via GitHub issue #185's /api/v1/rx-pub-a0/reports-identity endpoint
    # (workers/intel-gateway/src/rx-pub-a0-handlers.js reads this exact key)
    # without waiting for the *next* pipeline run's STAGE 3.5 pass -- this
    # stage runs AFTER STAGE 3.5, so nothing else would upload it this run
    # otherwise. Same "generated late, needs its own sync" situation
    # scripts/r2_upload.py's upload_p40_artifacts() exists for. Uses the
    # current (DATA-bucket-scoped, already restored above) os.environ
    # credentials directly rather than r2_upload.get_credentials(), which
    # sys.exit(1)s on absence -- unacceptable here, this stage must never
    # crash over a missing/wrong credential; best-effort only, and local
    # file + git history remain the source of truth either way.
    _data_account = os.environ.get("CF_ACCOUNT_ID", "").strip()
    _data_key_id  = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    _data_secret  = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if _data_account and _data_key_id and _data_secret:
        try:
            _endpoint = f"https://{_data_account}.r2.cloudflarestorage.com"
            if _r2_upload.s3_cp(
                str(OUTPUT_PATH), _r2_upload.BUCKET_DATA,
                "intel/rx_pub_a0_reports_artifact_manifest.json", _endpoint,
            ):
                log.info("Synced manifest to R2 (intel/rx_pub_a0_reports_artifact_manifest.json)")
            else:
                log.warning("Manifest R2 sync failed -- local file/git history remain authoritative")
        except Exception as e:
            log.warning("Manifest R2 sync raised %r -- local file/git history remain authoritative", e)
    else:
        log.warning("DATA-bucket R2 credentials absent -- manifest not synced to R2 this run")

    log.info(
        "R2 summary: %d in-window, %d REMOTE_VERIFIED, %d STALE_OR_DIVERGENT/FAILED, "
        "%d UNKNOWN, %d missing-local, %d budget-excluded, %.2fs",
        len(entries), verified, mismatched, unknown, missing_local, budget_overflow_count, elapsed,
    )
    log.info(
        "Public HTTP summary: %d LIVE_VERIFIED, %d LIVE_EXPECTED_DENIAL (gate-correct, "
        "not a failure), %d LIVE_STALE_OR_DIVERGENT/MISSING_UNEXPECTED, "
        "%d LIVE_RESOLUTION_FAILED, %d LIVE_FETCH_FAILED, %d LIVE_NOT_PROCESSED_DEADLINE, "
        "%d LIVE_NOT_PROCESSED_BUDGET, %d UNKNOWN",
        live_verified, live_expected_denial, live_mismatched,
        live_resolution_failed, live_fetch_failed, live_not_processed_deadline,
        live_not_processed_budget, live_unknown,
    )

    # P0 R2 COST AUDIT FIX: report this script's own real R2 HEAD/GET (Class
    # B) call volume through the same shared cost ledger r2_upload.py and
    # r2_report_publisher.py already use, instead of leaving it entirely
    # unaccounted (see scripts/r2_cost_guard.py's new head/get fields).
    # Read-only observability only -- never fail-closed here (this script
    # has its own MAX_VERIFY_ITEMS/RUN_DEADLINE_SECONDS bounds already; a
    # cost-guard hiccup must never crash an otherwise-successful run).
    try:
        _cost_plan = R2OperationPlan(label="r2_reports_verifier", bucket=BUCKET_REPORTS)
        _cost_plan.record_head(_head_call_count)
        _cost_plan.record_get(_get_call_count)
        _cost_plan.note(
            f"read-only verification pass: {len(work_items)} item(s) processed, "
            f"{budget_overflow_count} excluded by MAX_VERIFY_ITEMS={MAX_VERIFY_ITEMS}, "
            f"window={REPORT_WINDOW_HOURS}h"
        )
        emit_summary(_cost_plan, R2Budgets.from_env(), status="PASS", is_report_plan=True)
    except Exception as _cost_exc:
        log.warning("R2_COST_GUARD emit_summary failed (non-fatal, observability only): %s", _cost_exc)
    if cache_invalidations_attempted:
        log.info(
            "Cache purge summary: %d attempted, %d succeeded, %d failed | "
            "%d converged after purge (now LIVE_VERIFIED), %d still stale after purge",
            cache_invalidations_attempted, cache_invalidations_succeeded, cache_invalidations_failed,
            public_verified_after_invalidation, public_still_stale,
        )

    # RX-PUB-A0.6A / mission Section 9: a publication-gate bypass is the
    # single most severe outcome this verifier can observe -- a report the
    # platform's own gate says must not be served was served anyway. Always
    # surfaced with its own block, distinct from and in addition to the
    # general failure summary below, and never silently folded into an
    # ordinary mismatch count (mission Section 52 lists this as an automatic
    # mission blocker).
    if publication_gate_bypass > 0:
        log.error("!" * 70)
        log.error(
            "PUBLICATION_GATE_BYPASS x%d -- a report the platform's publication gate "
            "denied (customer_ready=false) was served with a real HTML body at its "
            "public URL. This is a customer-facing access-control defect, not a byte "
            "divergence (RX-PUB-A0.6 mission Section 9).",
            publication_gate_bypass,
        )
        log.error("!" * 70)

    # RX-PUB-A0.6A / mission Section 9: a publication-gate bypass is the
    # single most severe outcome this verifier can observe -- a report the
    # platform's own gate says must not be served was served anyway. Always
    # surfaced with its own block, distinct from and in addition to the
    # general failure summary below, and never silently folded into an
    # ordinary mismatch count (mission Section 52 lists this as an automatic
    # mission blocker).
    if publication_gate_bypass > 0:
        log.error("!" * 70)
        log.error(
            "PUBLICATION_GATE_BYPASS x%d -- a report the platform's publication gate "
            "denied (customer_ready=false) was served with a real HTML body at its "
            "public URL. This is a customer-facing access-control defect, not a byte "
            "divergence (RX-PUB-A0.6 mission Section 9).",
            publication_gate_bypass,
        )
        log.error("!" * 70)

    # CodeRabbit finding (RX-PUB-A0 Section 27 "do not fail-open"): an
    # unverifiable report (retries exhausted, auth/config error) is NOT the
    # same claim as a verified-matching report. "could not verify" must
    # never silently read as "verified" -- so every failure/unresolved/
    # unprocessed class below blocks a PASS claim, exactly as before this
    # PR. LIVE_EXPECTED_DENIAL is deliberately excluded: it is the gate
    # working correctly, not a failure (mission Section 32).
    total_failures = (
        mismatched + unknown
        + live_mismatched + live_unknown
        + live_resolution_failed + live_fetch_failed + live_not_processed_deadline
        + live_not_processed_budget
        + publication_gate_bypass
    )
    if total_failures > 0:
        log.error("=" * 70)
        log.error(
            "%s -- %d R2 mismatch/missing + %d R2 unverifiable + %d public HTTP "
            "mismatch/missing + %d public resolution-failed + %d public fetch-failed + "
            "%d not-processed-by-deadline + %d not-processed-by-budget + "
            "%d publication-gate bypass(es). A changed, "
            "certified commercial artifact must be remotely AND publicly "
            "verified before this run can be treated as production-certified "
            "(RX-PUB-A0 Sections 12, 25, 27; RX-PUB-A0.6 Sections 9, 26-27).",
            "HARD FAIL" if args.enforce else "WOULD HARD FAIL (--enforce not set)",
            mismatched, unknown, live_mismatched, live_resolution_failed,
            live_fetch_failed, live_not_processed_deadline, live_not_processed_budget,
            publication_gate_bypass,
        )
        log.error("=" * 70)
        return 1 if args.enforce else 0

    if args.skip_public:
        log.info("PASS (R2-only -- --skip-public was set) -- every in-window report's R2 SHA-256 matches its local artifact.")
    else:
        log.info(
            "PASS -- every in-window report's R2 SHA-256 matches its local artifact, and "
            "every public HTTP response matches either the canonical artifact "
            "(LIVE_VERIFIED) or the publication gate's expected denial (LIVE_EXPECTED_DENIAL)."
        )
    return 0


if __name__ == "__main__":
    # PRODUCTION-VERIFICATION FIX (2026-09-02): sys.exit() raises SystemExit,
    # which unwinds normally into CPython's interpreter shutdown -- and
    # concurrent.futures registers an atexit hook (_python_exit) that joins
    # *every* thread any ThreadPoolExecutor in this process ever started,
    # with no timeout. RUN_DEADLINE_SECONDS (600s, above) only bounds how
    # long main()'s own concurrent.futures.wait() blocks; futures still
    # running when that wait times out are recorded as
    # NOT_PROCESSED_DEADLINE and abandoned by main(), but their underlying
    # threads keep running in the background. On process exit, that atexit
    # hook then blocks -- with no bound -- until every one of those
    # abandoned threads finishes on its own (each can retry for
    # PUBLIC_MAX_RETRIES * (PUBLIC_TIMEOUT + PUBLIC_RETRY_DELAY) or longer
    # per report). Confirmed live: sentinel-blogger.yml's STAGE 3.6a step
    # (workflow timeout-minutes: 15) was hitting that external 15-minute
    # kill at the same ~15:13 wall-clock duration on every single run
    # (2026-09-02 07:09-07:24, 10:57-11:12, 13:23-13:39 UTC), never its own
    # 600s deadline -- the external SIGKILL was arriving before the
    # interpreter's own atexit thread-join ever returned. Because that step
    # has no continue-on-error, the kill cascaded into skipping ~50
    # downstream steps every run, including "Generate Immutable API
    # Manifests" -- the actual cause of api/v1/intel/latest.json being
    # frozen at generated_at=2026-08-26 for a week. By the time we reach
    # this line, main() has already written the full output manifest and
    # logged every summary; any thread still running belongs to a report
    # already classified NOT_PROCESSED_DEADLINE and intentionally
    # disregarded, so terminating immediately loses no information this
    # script reports on. os._exit() skips the atexit machinery entirely,
    # so the process can no longer stall past its own intended budget.
    try:
        _rc = main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical("Unhandled exception: %s\n%s", e, traceback.format_exc())
        _rc = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc)
