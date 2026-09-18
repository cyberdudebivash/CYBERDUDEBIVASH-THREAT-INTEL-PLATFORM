"""
tests/test_pipeline_staleness_diagnostics.py

P0 regression guard (2026-09-18, Telegram staleness-alert incident):
scripts/check_pipeline_staleness.py's alert message, when a workflow reads
STALE, previously linked only to the last SUCCESSFUL run. During the
automated-backup.yml incident that meant every alert pointed at an 8-day-old
green checkmark (run #415) -- exactly what made a real, ongoing failure
(cf-data-backup cancelling every day since) look like a false alarm on
inspection: the thing actually broken right now (the most recent run) was
never shown.

get_latest_run() + _latest_run_suffix() (added alongside the
automated-backup.yml timeout-isolation fix in the same incident) fetch the
single most recent run of ANY status and append its outcome to the alert,
so "click the link, see a green check, assume it's a false alarm" can't
recur for a DIFFERENT underlying cause either -- this is a diagnostics
improvement to the alert text, not a change to the staleness decision
itself (get_last_success()'s status=success query remains the sole
threshold source of truth; test_pipeline_staleness_thresholds.py continues
to guard that).

Uses a mocked gh_get() throughout -- no network/GitHub token required.
"""
import pathlib
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_pipeline_staleness as cps  # noqa: E402


def _run(status="completed", conclusion="cancelled", updated_at=None, html_url="https://example/run/1"):
    return {
        "status": status,
        "conclusion": conclusion,
        "updated_at": updated_at or cps.datetime.datetime.now(cps.datetime.timezone.utc).isoformat(),
        "html_url": html_url,
    }


class TestGetLatestRun(unittest.TestCase):
    def test_parses_the_most_recent_run_regardless_of_status(self):
        payload = {"workflow_runs": [_run(conclusion="cancelled", html_url="https://x/runs/9")]}
        with patch.object(cps, "gh_get", return_value=payload) as mock_get:
            result = cps.get_latest_run("automated-backup.yml")
        mock_get.assert_called_once()
        # No status filter -- unlike get_last_success(), this must see every
        # conclusion, not just successes.
        self.assertNotIn("status=success", mock_get.call_args[0][0])
        self.assertEqual(result["conclusion"], "cancelled")
        self.assertEqual(result["html_url"], "https://x/runs/9")

    def test_returns_none_when_no_runs_exist(self):
        with patch.object(cps, "gh_get", return_value={"workflow_runs": []}):
            self.assertIsNone(cps.get_latest_run("automated-backup.yml"))

    def test_returns_none_when_gh_get_itself_returns_none(self):
        """Matches get_last_success()'s own established handling of a failed
        gh_get() call (e.g. HTTP error) -- see gh_get()'s except branch."""
        with patch.object(cps, "gh_get", return_value=None):
            self.assertIsNone(cps.get_latest_run("automated-backup.yml"))


class TestLatestRunSuffix(unittest.TestCase):
    def test_appends_outcome_age_and_link_for_a_non_success_run(self):
        payload = {"workflow_runs": [_run(
            conclusion="cancelled",
            updated_at="2020-01-01T00:00:00Z",
            html_url="https://x/runs/42",
        )]}
        with patch.object(cps, "gh_get", return_value=payload):
            suffix = cps._latest_run_suffix("automated-backup.yml")
        self.assertIn("cancelled", suffix)
        self.assertIn("https://x/runs/42", suffix)
        self.assertIn("Most recent run:", suffix)

    def test_falls_back_to_status_when_conclusion_is_null(self):
        """An in-progress run has conclusion: null in the real GitHub API --
        must still produce a readable suffix, not 'None'."""
        payload = {"workflow_runs": [_run(status="in_progress", conclusion=None,
                                           updated_at="2020-01-01T00:00:00Z")]}
        with patch.object(cps, "gh_get", return_value=payload):
            suffix = cps._latest_run_suffix("automated-backup.yml")
        self.assertIn("in_progress", suffix)
        self.assertNotIn("None", suffix)

    def test_empty_string_when_no_runs_found_at_all(self):
        with patch.object(cps, "gh_get", return_value={"workflow_runs": []}):
            self.assertEqual(cps._latest_run_suffix("automated-backup.yml"), "")

    def test_never_raises_even_if_the_lookup_itself_errors(self):
        """A diagnostics-only lookup must never be able to break primary
        alerting -- confirmed by making the underlying call raise."""
        with patch.object(cps, "gh_get", side_effect=RuntimeError("network blip")):
            self.assertEqual(cps._latest_run_suffix("automated-backup.yml"), "")


if __name__ == "__main__":
    unittest.main()
