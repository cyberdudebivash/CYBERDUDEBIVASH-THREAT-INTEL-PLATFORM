#!/usr/bin/env python3
"""
tests/test_pipeline_staleness_thresholds.py

P0 regression guard (2026-09-10): scripts/check_pipeline_staleness.py's
MONITORED_WORKFLOWS entries for sentinel-blogger.yml and status-monitor.yml
had alert thresholds tighter than -- in status-monitor's case, less than
half of -- the actual cron cadence of the workflow they monitor. That
guarantees the alert fires on a healthy platform: status-monitor.yml runs
3x/day (nominal 8h gaps) against a 3h threshold, so it read "STALE" for
5+ of every 8 hours, every day, regardless of whether anything was
actually wrong. sentinel-blogger.yml shared the same cron with a 8h
threshold -- zero margin for the scheduling jitter GitHub's own docs
warn cron workflows are subject to under load (confirmed empirically:
observed real gaps of 6h21m-9h31m against a nominal 8h).

This test parses each monitored workflow's OWN `.github/workflows/*.yml`
cron schedule (the same file check_pipeline_staleness.py names in
MONITORED_WORKFLOWS -- read directly, not duplicated by hand) and fails
if any configured max_age_hours provides less than a 1.3x safety margin
over that workflow's real maximum possible gap between scheduled fires.
This is deliberately mechanical rather than a fixed pin on today's values:
running it is what found that Automated Backup's existing 26h/24h margin
was equally undersized, alongside the two thresholds the original alert
named, and it also catches the same mistake being reintroduced later for
any of these rows, or made fresh for any row added in the future.
"""
import pathlib
import re
import sys
import unittest

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import check_pipeline_staleness as cps  # noqa: E402

# How much headroom a threshold must have over the real max scheduled gap.
# 1.3x tolerates real observed GitHub Actions scheduling jitter (see module
# docstring) without being so loose it stops catching genuine outages.
SAFETY_FACTOR = 1.3

# A "daily, fires at these UTC hours" cron: minute and hour fixed/listed,
# day-of-month/month/weekday all wildcards. Deliberately narrow: this is
# the only shape every workflow in MONITORED_WORKFLOWS actually uses for
# its recurring cadence (some also carry an additional monthly-only cron,
# e.g. sentinel-blogger's '0 0 1 * *' -- skipped here since an extra rarer
# firing can only shorten real-world gaps, never lengthen the recurring
# day-to-day one staleness detection cares about, so ignoring it is
# conservative, not a blind spot).
_DAILY_CRON_RE = re.compile(r"^(\d{1,2})\s+([\d,]+)\s+\*\s+\*\s+\*$")

# A "fixed minute, every N hours" cron (e.g. '15 */6 * * *') -- the shape
# P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10) added
# sovereign-platform.yml/genesis-powerhouse.yml under, a genuinely new
# schedule shape not covered by _DAILY_CRON_RE above (no workflow in this
# list used step syntax before). A '*/N' step fires evenly every N hours by
# construction, so its own max gap is exactly N hours -- no minute-set
# math needed the way the hour-list shape requires.
_STEP_CRON_RE = re.compile(r"^(\d{1,2})\s+\*/(\d{1,2})\s+\*\s+\*\s+\*$")


def _daily_fire_minutes(cron_expr: str) -> "set[int] | None":
    """Every minutes-since-midnight this 'M H,H,H * * *' entry fires at, or
    None if cron_expr isn't that shape.

    CodeRabbit review (PR #393): an earlier version of this returned bare
    hours, dropping the minute entirely. That's exact as long as every
    daily entry for a workflow shares one minute (true for every row in
    MONITORED_WORKFLOWS today), but silently understates the true gap the
    moment two entries differ -- e.g. '30 0 * * *' + '0 8 * * *' is really
    a 16.5h max gap, not the 16h an hours-only union would report, which
    could let an insufficient threshold clear the 1.3x safety check below.
    Keeping the minute makes the gap math exact regardless.
    """
    m = _DAILY_CRON_RE.match(cron_expr.strip())
    if not m:
        return None
    minute = int(m.group(1))
    return {int(h) * 60 + minute for h in m.group(2).split(",")}


def _step_cron_gap_hours(cron_expr: str) -> "float | None":
    """Max gap (hours) for a '*/N' step cron, or None if cron_expr isn't
    that shape. A fixed minute offset (the '15' in '15 */6 * * *') shifts
    every fire time equally, so it never changes the gap BETWEEN fires --
    only N (how many hours between steps) matters."""
    m = _STEP_CRON_RE.match(cron_expr.strip())
    if not m:
        return None
    return float(m.group(2))


def _max_gap_hours(fire_minutes: "set[int]") -> float:
    """Largest gap (hours), with wraparound across midnight, between a set
    of daily fire-times expressed as minutes-since-midnight."""
    ordered = sorted(fire_minutes)
    gaps_minutes = [
        (ordered[i + 1] - ordered[i]) if i + 1 < len(ordered)
        else (1440 - ordered[-1] + ordered[0])
        for i in range(len(ordered))
    ]
    return max(gaps_minutes) / 60.0


def max_gap_hours_for_workflow(workflow_file: str) -> float:
    """The largest possible gap (hours) between this workflow's own
    scheduled fires, unioning every 'daily' cron entry it declares, or --
    for a workflow using '*/N' step syntax instead -- that step's own gap.
    No workflow in MONITORED_WORKFLOWS today mixes both shapes across
    multiple schedule entries, so this doesn't attempt to combine them."""
    path = WORKFLOWS_DIR / workflow_file
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    on_block = doc.get(True, doc.get("on"))  # PyYAML parses bare `on:` as bool True
    schedules = (on_block or {}).get("schedule") or []

    fire_minutes: set[int] = set()
    step_gaps: list[float] = []
    for entry in schedules:
        cron = entry.get("cron", "")
        found = _daily_fire_minutes(cron)
        if found:
            fire_minutes |= found
            continue
        step_gap = _step_cron_gap_hours(cron)
        if step_gap is not None:
            step_gaps.append(step_gap)

    assert fire_minutes or step_gaps, (
        f"{workflow_file}: no recognisable daily 'M H,H,H * * *' or step "
        f"'M */N * * *' cron schedule found (schedules seen: {schedules}) -- "
        f"this test's cron parser needs extending before it can validate "
        f"this workflow's threshold"
    )

    if fire_minutes:
        return _max_gap_hours(fire_minutes)
    return max(step_gaps)


class TestPipelineStalenessThresholds(unittest.TestCase):
    def test_threshold_has_real_safety_margin(self):
        for wf in cps.MONITORED_WORKFLOWS:
            if wf["max_age_hours"] == 0:
                continue  # deliberately exempt (push-triggered, not scheduled)

            max_gap = max_gap_hours_for_workflow(wf["file"])
            required = max_gap * SAFETY_FACTOR
            self.assertGreaterEqual(
                wf["max_age_hours"], required,
                f"{wf['name']} ({wf['file']}): max_age_hours={wf['max_age_hours']}h "
                f"gives less than the required {SAFETY_FACTOR}x margin over its own "
                f"real max scheduled gap ({max_gap}h, needs >= {required}h) -- this "
                f"threshold will false-alarm on a healthy pipeline, exactly the "
                f"2026-09-10 status-monitor/sentinel-blogger incident this test "
                f"guards against.",
            )

    def test_incident_values_fixed(self):
        """Pins this specific incident's three corrected values (found by
        running the general mechanical check above, not hand-picked), in
        addition to that general check."""
        by_file = {wf["file"]: wf for wf in cps.MONITORED_WORKFLOWS}
        self.assertEqual(by_file["status-monitor.yml"]["max_age_hours"], 16)
        self.assertEqual(by_file["sentinel-blogger.yml"]["max_age_hours"], 16)
        self.assertEqual(by_file["automated-backup.yml"]["max_age_hours"], 32)

    def test_cron_parser_reproduces_the_known_8h_cadence(self):
        """Sanity check on the parser itself, independent of the thresholds
        it is about to judge: both incident workflows share the exact cron
        this test's own analysis is built on."""
        self.assertEqual(max_gap_hours_for_workflow("status-monitor.yml"), 8.0)
        # P0 2026-09-26: sentinel-blogger moved to every 4h ('17 */4 * * *')
        # to meet the 6h public freshness contract (repo is public: free runners).
        self.assertEqual(max_gap_hours_for_workflow("sentinel-blogger.yml"), 4.0)


class TestMixedMinuteCronEntries(unittest.TestCase):
    """CodeRabbit review (PR #393)'s exact worked example: two daily entries
    on different minutes -- '30 0 * * *' and '0 8 * * *' -- are really a
    16.5h max gap (00:30 -> 08:00), not the 16h an hours-only union would
    report. No row in MONITORED_WORKFLOWS mixes minutes today (verified:
    every entry uses a single shared minute across its listed hours), so
    this couldn't yet under-approve a real threshold -- but it is exactly
    the shape a future row could take, which is what this class pins
    against regressing back to hours-only math."""

    def test_daily_fire_minutes_keeps_the_minute_component(self):
        self.assertEqual(_daily_fire_minutes("30 6,18 * * *"), {6 * 60 + 30, 18 * 60 + 30})

    def test_non_matching_cron_shape_returns_none(self):
        self.assertIsNone(_daily_fire_minutes("*/15 * * * *"))

    def test_mixed_minute_entries_report_the_true_fractional_gap(self):
        fire_minutes = _daily_fire_minutes("30 0 * * *") | _daily_fire_minutes("0 8 * * *")
        self.assertEqual(_max_gap_hours(fire_minutes), 16.5)

    def test_hours_only_threshold_would_have_wrongly_passed_this_case(self):
        """The exact false-negative CodeRabbit named: a 21h threshold clears
        an hours-only-computed 16h*1.3=20.8h bar but not the true
        16.5h*1.3=21.45h one -- proving this isn't just a cosmetic precision
        difference, it changes which thresholds the safety-margin test
        would accept."""
        fire_minutes = _daily_fire_minutes("30 0 * * *") | _daily_fire_minutes("0 8 * * *")
        true_max_gap = _max_gap_hours(fire_minutes)
        self.assertEqual(true_max_gap, 16.5)
        candidate_threshold = 21.0
        self.assertLess(candidate_threshold, true_max_gap * SAFETY_FACTOR)


class TestStepCronEntries(unittest.TestCase):
    """P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10): the
    '*/N' step shape sovereign-platform.yml/genesis-powerhouse.yml use,
    added alongside the pre-existing 'M H,H,H * * *' shape."""

    def test_step_cron_gap_equals_the_step_interval(self):
        self.assertEqual(_step_cron_gap_hours("15 */6 * * *"), 6.0)
        self.assertEqual(_step_cron_gap_hours("45 */6 * * *"), 6.0)
        self.assertEqual(_step_cron_gap_hours("0 */8 * * *"), 8.0)

    def test_minute_offset_does_not_change_the_gap(self):
        """A fixed minute shifts every fire time equally -- it cannot widen
        or narrow the gap BETWEEN fires, only when in the hour they land."""
        self.assertEqual(_step_cron_gap_hours("15 */6 * * *"), _step_cron_gap_hours("45 */6 * * *"))

    def test_non_step_cron_returns_none(self):
        self.assertIsNone(_step_cron_gap_hours("0 0,8,16 * * *"))

    def test_sovereign_and_genesis_recognised_as_step_cron(self):
        self.assertEqual(max_gap_hours_for_workflow("sovereign-platform.yml"), 6.0)
        self.assertEqual(max_gap_hours_for_workflow("genesis-powerhouse.yml"), 6.0)


if __name__ == "__main__":
    unittest.main()
