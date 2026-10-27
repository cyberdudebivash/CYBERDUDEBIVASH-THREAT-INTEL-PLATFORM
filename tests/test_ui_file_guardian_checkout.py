"""Offline regression controls for the scheduled UI File Guardian checkout.

The guardian validates files at HEAD and creates a lightweight baseline tag;
neither operation requires downloading the complete repository history.
"""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ui-file-guardian.yml"


def checkout_block(source: str) -> str:
    match = re.search(
        r"(?ms)^      - name: Checkout main\n(.*?)(?=^      - name: |\Z)",
        source,
    )
    if match is None:
        raise AssertionError("UI guardian checkout step missing")
    return match.group(1)


class UiGuardianCheckoutRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def assert_bounded_checkout(self, source: str):
        block = checkout_block(source)
        self.assertRegex(block, r"(?m)^\s+fetch-depth:\s*1\s*$")
        self.assertNotRegex(block, r"(?m)^\s+fetch-depth:\s*0\s*$")
        self.assertIn('ref: "${{ github.ref }}"', block)

    def test_guardian_fetches_only_head(self):
        self.assert_bounded_checkout(self.source)

    def test_full_history_regression_is_rejected(self):
        altered = self.source.replace("fetch-depth: 1", "fetch-depth: 0", 1)
        self.assertNotEqual(altered, self.source)
        with self.assertRaises(AssertionError):
            self.assert_bounded_checkout(altered)

    def test_integrity_checks_and_no_auto_cancel_are_preserved(self):
        for check in (
            "Check — Files present",
            "Check — JS syntax (node --check)",
            "Check — safe_git_commit.py syntax",
            "Check — Symbol and version integrity",
            "Check — File size minimums",
            "Check — EMBEDDED_INTEL populated in index.html",
        ):
            with self.subTest(check=check):
                self.assertIn(check, self.source)
        self.assertIn("cancel-in-progress: false", self.source)

    def test_lightweight_baseline_tag_behavior_is_preserved(self):
        self.assertIn("git tag -f sentinel-apex-v147-baseline HEAD", self.source)
        self.assertIn("git push origin sentinel-apex-v147-baseline --force", self.source)


if __name__ == "__main__":
    unittest.main()
