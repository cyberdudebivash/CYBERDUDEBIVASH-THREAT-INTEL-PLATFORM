#!/usr/bin/env python3
"""
scripts/r2_cost_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- R2 Operation Cost Guard (P0 COST INCIDENT)
================================================================================
INCIDENT: Cloudflare R2 billed 3,004,147 Class A operations in one cycle
($18 pre-tax). Root cause (see docs/P0_R2_COST_CONTAINMENT.md): scripts/
r2_upload.py ran `aws s3 sync reports/ -> s3://sentinel-apex-reports/reports/`
on every scheduled pipeline run (3x/day + push-triggered) against a local
reports/ tree that scripts/generate_intel_reports.py regenerated in FULL
(entire historical manifest, no time filter) every run -- and every
regenerated file embeds a live minute-granularity timestamp into its SIGMA/
YARA/KQL/SPL blocks, so its content differs from the prior run's copy even
when the underlying intel item never changed. `aws s3 sync` therefore
re-uploaded (and, to build its comparison map, LISTed) essentially the
entire ~193K-object historical corpus every single run.

PURPOSE: single, shared source of truth (Constitution Principle 3) for
R2 operation accounting across every script that mutates R2 in the normal
scheduled pipeline (scripts/r2_upload.py, scripts/r2_report_publisher.py).
Two responsibilities:

  1. FAIL-CLOSED BUDGET ENFORCEMENT -- a caller builds its full operation
     plan (how many PUT/DELETE/LIST/COPY it INTENDS to issue) before
     issuing a single one, then calls enforce_budget(). If any ceiling is
     exceeded, enforce_budget() raises R2BudgetExceeded and the caller
     MUST abort before performing any R2 mutation. There is no
     warning-only mode and no continue-on-error path here -- a caller
     that catches R2BudgetExceeded and proceeds anyway is violating this
     module's contract.

  2. OBSERVABILITY -- emit_summary() prints the R2_COST_GUARD telemetry
     block (fixed format, grep-able in CI logs), writes
     data/quality/r2_cost_guard_report.json (this platform's standard
     data/quality/*.json certification-report convention), and appends a
     Markdown summary to $GITHUB_STEP_SUMMARY when running in Actions.

BILLING NOTE (accuracy, not a "fake cost estimate"): Cloudflare R2 bills
PutObject / ListObjects / CopyObject / multipart operations as Class A.
DeleteObject is NOT billed as a Class A operation on R2 (Cloudflare's
documented pricing explicitly does not charge for deletes, unlike LIST/PUT)
-- so `estimated_class_a` intentionally excludes `delete` from the sum.
Delete count is still tracked, reported, and budget-capped (Phase 8 /
MAX_REPORT_DELETIONS_PER_RUN) for blast-radius safety, not for cost.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = REPO_ROOT / "data" / "quality" / "r2_cost_guard_report.json"


class R2BudgetExceeded(Exception):
    """Raised by enforce_budget() when a planned operation count exceeds its
    hard ceiling. The caller MUST treat this as fail-closed: abort before
    issuing any R2 mutation for this plan. Never caught-and-continued."""


def is_pre_revenue_cost_mode() -> bool:
    """Single source of truth (Principle 3) for the platform-wide cost
    posture. CYBERDUDEBIVASH is pre-revenue with an effectively $0
    discretionary Cloudflare overage budget shared across multiple
    platforms -- PRE_REVENUE_COST_MODE=true is therefore the default, not
    an opt-in. Every script that makes a bucket-scope or feature-scope
    decision based on cost posture (scripts/backup_r2.py excluding
    sentinel-apex-reports from its daily full-bucket verify, scripts/
    r2_report_publisher.py's 24h window) reads this one function rather
    than re-parsing the env var itself, so the posture can never drift
    between call sites. Flip to "false" only once real revenue changes the
    cost calculus -- never as a workaround for a budget ceiling being hit;
    a hit ceiling means the plan itself is wrong, not the mode.
    """
    return os.environ.get("PRE_REVENUE_COST_MODE", "true").strip().lower() != "false"


@dataclass
class R2OperationPlan:
    """Tracks planned/executed R2 operations for one script's run, so budget
    enforcement and telemetry always see the exact same numbers (Principle 3:
    single source of truth for R2 op accounting -- no script hand-rolls its
    own counters).

    Usage contract: populate counts by calling the record_* helpers while
    BUILDING the plan (before issuing any real R2 call), then call
    enforce_budget(plan, budgets) once the full plan is known. Only after
    that call returns without raising may the caller start issuing the
    actual PUT/DELETE/LIST/COPY calls the plan describes.
    """
    label: str
    bucket: str = ""
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    expired: int = 0          # candidates aged out of the retention window (subset of `delete`)
    put: int = 0
    delete: int = 0
    list_calls: int = 0
    copy: int = 0
    multipart: int = 0        # CreateMultipartUpload/UploadPart/CompleteMultipartUpload calls;
    # always 0 in this platform's current R2 paths (no file crosses the multipart threshold via
    # this module's callers) -- tracked explicitly so a future large-file path can't silently
    # reintroduce Class A volume without showing up here.
    head: int = 0             # HeadObject calls (Class B). Read-only verification scripts
    # (r2_reports_verifier.py, r2_reports_integrity.py) issue these every run but, before the
    # R2 cost-containment audit that added this field, never appeared in this ledger at all --
    # this platform's cost accounting only ever showed Class A (PUT/LIST). Additive field,
    # defaults to 0, so every existing R2OperationPlan(...) construction is unaffected.
    get: int = 0              # GetObject calls (Class B). Same rationale as `head` above.
    bytes_uploaded: int = 0
    notes: list[str] = field(default_factory=list)

    def record_new(self, n: int = 1) -> None:
        self.new += n

    def record_changed(self, n: int = 1) -> None:
        self.changed += n

    def record_unchanged(self, n: int = 1) -> None:
        self.unchanged += n

    def record_put(self, n: int = 1, nbytes: int = 0) -> None:
        self.put += n
        self.bytes_uploaded += nbytes

    def record_delete(self, n: int = 1, expired: bool = True) -> None:
        self.delete += n
        if expired:
            self.expired += n

    def record_expired(self, n: int = 1) -> None:
        """Increments the item-level `expired` counter without touching
        `delete` (the operation-level counter) -- use this when one expired
        item retires via more than one delete operation (e.g. html + pdf),
        so `expired` stays an item count while `delete` stays an operation
        count. Call this once per retired item, then record_delete(expired=False)
        for each actual delete operation it triggers."""
        self.expired += n

    def record_list(self, n: int = 1, reason: str = "") -> None:
        self.list_calls += n
        if reason:
            self.notes.append(f"LIST x{n}: {reason}")

    def record_copy(self, n: int = 1) -> None:
        self.copy += n

    def record_multipart(self, n: int = 1) -> None:
        self.multipart += n

    def record_head(self, n: int = 1) -> None:
        self.head += n

    def record_get(self, n: int = 1) -> None:
        self.get += n

    def note(self, text: str) -> None:
        self.notes.append(text)

    def estimated_class_a(self) -> int:
        """PUT + LIST + COPY + multipart. Excludes `delete` -- see module
        docstring's BILLING NOTE: Cloudflare R2 does not bill DeleteObject
        as Class A."""
        return self.put + self.list_calls + self.copy + self.multipart

    def estimated_class_b(self) -> int:
        """HEAD + GET -- Cloudflare R2 Class B operations. Tracked separately
        from estimated_class_a() (Class A/B bill at different rates); added
        so read-mostly verification scripts have a place to report their
        operation cost in the same shared ledger instead of going
        unaccounted entirely."""
        return self.head + self.get


@dataclass
class R2Budgets:
    """Evidence-based hard ceilings. Defaults documented at each field --
    see docs/P0_R2_COST_CONTAINMENT.md for the underlying evidence (observed
    api/feed.json rolling-window volume: 51-109 items across a ~24h span at
    incident time; reports/ HOT tier: tens of thousands of historical files
    already on disk pre-fix). Ceilings are set at a wide (~5-10x) margin
    above observed normal volume so a legitimate traffic spike does not
    false-close the pipeline, while still sitting orders of magnitude below
    the ~193K-object full-corpus scenario that caused this incident.
    """
    max_report_writes_per_run: int = 500       # MAX_REPORT_UPLOADS_PER_RUN
    max_report_deletes_per_run: int = 500       # MAX_REPORT_DELETIONS_PER_RUN
    max_list_calls_per_run: int = 0             # MAX_R2_LIST_CALLS_PER_RUN -- the
    # normal incremental-publish path is designed to need ZERO LIST calls
    # (deterministic keys derived from the manifest, not bucket discovery).
    # Kept at 0, not "very small", so any LIST call at all in this path is
    # an immediate, loud budget failure -- not a silently-tolerated norm.
    # No sanctioned recurring COPY or multipart uploader exists in the normal
    # publisher path. Explicit zero caps prevent unaccounted Class A growth.
    max_copy_calls_per_run: int = 0
    max_multipart_calls_per_run: int = 0
    # The existing bounded verifier uses HEAD and GET, so allow a bounded
    # read-only operation count while forbidding whole-bucket enumerations.
    max_class_b_calls_per_run: int = 2000
    max_data_writes_per_run: int = 200          # MAX_R2_DATA_WRITES_PER_RUN --
    # bounds scripts/r2_upload.py's existing manifest/AI/endpoint uploads to
    # sentinel-apex-data (observed: well under 100 discrete files per run).

    @classmethod
    def from_env(cls) -> "R2Budgets":
        def _int_env(name: str, default: int) -> int:
            raw = os.environ.get(name, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError:
                return default

        return cls(
            max_report_writes_per_run=_int_env("MAX_REPORT_UPLOADS_PER_RUN", cls.max_report_writes_per_run),
            max_report_deletes_per_run=_int_env("MAX_REPORT_DELETIONS_PER_RUN", cls.max_report_deletes_per_run),
            max_list_calls_per_run=_int_env("MAX_R2_LIST_CALLS_PER_RUN", cls.max_list_calls_per_run),
            max_data_writes_per_run=_int_env("MAX_R2_DATA_WRITES_PER_RUN", cls.max_data_writes_per_run),
        )


def enforce_budget(plan: R2OperationPlan, budgets: R2Budgets, *, is_report_plan: bool = True) -> None:
    """Fail-closed budget check. Raises R2BudgetExceeded if ANY ceiling is
    exceeded. Callers MUST call this after building the full plan and
    BEFORE issuing a single real R2 mutation -- see class docstring.

    is_report_plan selects which write ceiling applies: the reports-bucket
    write budget (MAX_REPORT_UPLOADS_PER_RUN) for scripts/
    r2_report_publisher.py, or the data-bucket write budget
    (MAX_R2_DATA_WRITES_PER_RUN) for scripts/r2_upload.py's remaining
    bounded sentinel-apex-data uploads.
    """
    violations: list[str] = []

    # Reject malformed or negative plans: a negative count must never
    # satisfy a less-than ceiling and conceal actual billable operations.
    for key in ("put", "delete", "list_calls", "copy", "multipart", "head", "get"):
        count = getattr(plan, key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            violations.append(f"INVALID_R2_OPERATION_COUNT: {key}={count!r}")

    for name in ("max_copy_calls_per_run", "max_multipart_calls_per_run",
                 "max_class_b_calls_per_run", "max_report_writes_per_run",
                 "max_report_deletes_per_run", "max_list_calls_per_run",
                 "max_data_writes_per_run"):
        cap = getattr(budgets, name)
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
            violations.append(f"INVALID_R2_BUDGET_CEILING: {name}={cap!r}")

    if plan.copy > budgets.max_copy_calls_per_run:
        violations.append(
            f"MAX_R2_COPY_CALLS_PER_RUN exceeded: COPY={plan.copy} > {budgets.max_copy_calls_per_run}"
        )
    if plan.multipart > budgets.max_multipart_calls_per_run:
        violations.append(
            f"MAX_R2_MULTIPART_CALLS_PER_RUN exceeded: multipart={plan.multipart} > "
            f"{budgets.max_multipart_calls_per_run}"
        )
    if plan.estimated_class_b() > budgets.max_class_b_calls_per_run:
        violations.append(
            f"MAX_R2_CLASS_B_CALLS_PER_RUN exceeded: HEAD+GET={plan.estimated_class_b()} > "
            f"{budgets.max_class_b_calls_per_run}"
        )

    write_ceiling = budgets.max_report_writes_per_run if is_report_plan else budgets.max_data_writes_per_run
    write_ceiling_name = "MAX_REPORT_UPLOADS_PER_RUN" if is_report_plan else "MAX_R2_DATA_WRITES_PER_RUN"
    if plan.put > write_ceiling:
        violations.append(f"{write_ceiling_name} exceeded: planned PUT={plan.put} > ceiling={write_ceiling}")

    if plan.delete > budgets.max_report_deletes_per_run:
        violations.append(
            f"MAX_REPORT_DELETIONS_PER_RUN exceeded: planned DELETE={plan.delete} "
            f"> ceiling={budgets.max_report_deletes_per_run}"
        )

    if plan.list_calls > budgets.max_list_calls_per_run:
        violations.append(
            f"MAX_R2_LIST_CALLS_PER_RUN exceeded: planned LIST={plan.list_calls} "
            f"> ceiling={budgets.max_list_calls_per_run}"
        )

    if violations:
        raise R2BudgetExceeded(
            f"[{plan.label}] R2 operation plan exceeds hard budget -- ABORTING BEFORE ANY R2 "
            f"MUTATION (fail-closed, no partial execution, no warning-only fallback): "
            + "; ".join(violations)
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _format_summary_block(plan: R2OperationPlan, budgets: R2Budgets, status: str, is_report_plan: bool) -> str:
    write_ceiling = budgets.max_report_writes_per_run if is_report_plan else budgets.max_data_writes_per_run
    # Utilization against whichever ceiling is closest to being exhausted --
    # the single number that answers "how close did this run come to
    # BLOCKED", not just "did PUT alone stay under budget".
    ratios = []
    if write_ceiling > 0:
        ratios.append(plan.put / write_ceiling)
    if budgets.max_report_deletes_per_run > 0:
        ratios.append(plan.delete / budgets.max_report_deletes_per_run)
    utilization_pct = round(max(ratios) * 100, 1) if ratios else 0.0

    lines = [
        "R2_COST_GUARD (CLOUDFLARE COST GUARD)",
        "--------------------------------------",
        f"mode: {'PRE_REVENUE_COST_MODE' if is_pre_revenue_cost_mode() else 'STANDARD'}",
        f"stage/workflow-run: {plan.label} / {os.environ.get('GITHUB_RUN_ID', 'local')}",
        f"bucket: {plan.bucket or 'n/a'}",
        "report candidates:",
        f"  new: {plan.new}",
        f"  changed: {plan.changed}",
        f"  unchanged: {plan.unchanged}",
        f"  expired (>window, retired): {plan.expired}",
        f"PUT: {plan.put}",
        f"DELETE: {plan.delete}",
        f"LIST: {plan.list_calls}",
        f"COPY: {plan.copy}",
        f"multipart: {plan.multipart}",
        f"HEAD: {plan.head}",
        f"GET: {plan.get}",
        f"bytes_uploaded: {plan.bytes_uploaded}",
        f"estimated Class A operations: {plan.estimated_class_a()}",
        f"estimated Class B operations: {plan.estimated_class_b()}",
        f"budget (PUT/DELETE/LIST): {write_ceiling}/{budgets.max_report_deletes_per_run}/{budgets.max_list_calls_per_run}",
        f"budget utilization: {utilization_pct}%",
        f"status: {status}",
    ]
    if plan.notes:
        lines.append("notes:")
        lines.extend(f"  - {n}" for n in plan.notes)
    return "\n".join(lines)


def emit_summary(
    plan: R2OperationPlan,
    budgets: R2Budgets,
    *,
    status: str,
    is_report_plan: bool = True,
    extra: Optional[dict] = None,
) -> dict:
    """Prints the R2_COST_GUARD block to stdout, merges it into
    data/quality/r2_cost_guard_report.json (keyed by plan.label, so multiple
    stages in one pipeline run -- r2_upload.py's data-bucket uploads and
    r2_report_publisher.py's report publish/delete -- each get their own
    entry without clobbering the other), and appends a Markdown summary to
    $GITHUB_STEP_SUMMARY when set. Returns the full merged report dict.
    """
    block = _format_summary_block(plan, budgets, status, is_report_plan)
    print(block, flush=True)

    write_ceiling = budgets.max_report_writes_per_run if is_report_plan else budgets.max_data_writes_per_run
    ratios = []
    if write_ceiling > 0:
        ratios.append(plan.put / write_ceiling)
    if budgets.max_report_deletes_per_run > 0:
        ratios.append(plan.delete / budgets.max_report_deletes_per_run)
    utilization_pct = round(max(ratios) * 100, 1) if ratios else 0.0

    entry = {
        "generated_at": _utc_now(),
        "mode": "PRE_REVENUE_COST_MODE" if is_pre_revenue_cost_mode() else "STANDARD",
        "label": plan.label,
        "bucket": plan.bucket,
        "new": plan.new,
        "changed": plan.changed,
        "unchanged": plan.unchanged,
        "expired": plan.expired,
        "put": plan.put,
        "delete": plan.delete,
        "list_calls": plan.list_calls,
        "copy": plan.copy,
        "multipart": plan.multipart,
        "head": plan.head,
        "get": plan.get,
        "bytes_uploaded": plan.bytes_uploaded,
        "estimated_class_a": plan.estimated_class_a(),
        "estimated_class_b": plan.estimated_class_b(),
        "budget_write_ceiling": write_ceiling,
        "budget_delete_ceiling": budgets.max_report_deletes_per_run,
        "budget_list_ceiling": budgets.max_list_calls_per_run,
        "budget_utilization_pct": utilization_pct,
        "status": status,
        "notes": list(plan.notes),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    }
    if extra:
        entry["extra"] = extra

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {"schema_version": "1.0", "plans": {}}
    if REPORT_PATH.exists():
        try:
            existing = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("plans"), dict):
                report = existing
        except Exception:
            pass  # corrupt/legacy report -- start fresh rather than crash the pipeline

    report["generated_at"] = _utc_now()
    report["plans"][plan.label] = entry
    statuses = [p.get("status") for p in report["plans"].values()]
    report["overall_status"] = "PASS" if all(s == "PASS" for s in statuses) else "BLOCKED"

    tmp_path = REPORT_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(tmp_path, REPORT_PATH)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as fh:
                fh.write(f"\n### R2_COST_GUARD -- {plan.label}\n\n```\n{block}\n```\n")
        except Exception:
            pass  # step summary is best-effort observability, never fatal

    return report


if __name__ == "__main__":
    # Smoke-test / CLI helper: print the current on-disk report (if any) so
    # a human or CI step can inspect it without writing ad-hoc jq/python.
    if REPORT_PATH.exists():
        print(REPORT_PATH.read_text(encoding="utf-8"))
    else:
        print(json.dumps({"schema_version": "1.0", "plans": {}, "overall_status": "NO_RUNS_YET"}, indent=2))
    sys.exit(0)
