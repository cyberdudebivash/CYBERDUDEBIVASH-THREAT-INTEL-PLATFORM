"""
tests/test_python_governance_smart_quotes.py

Regression test for a P0 defect in scripts/python_governance_immunity_engine.py
(STAGE 0.06b of sentinel-apex.yml): the SMART_QUOTES dict's literal
Unicode key characters (U+2018/U+2019/U+201C/U+201D) had been silently
collapsed to plain ASCII apostrophe/quote by some earlier normalization
pass over this file. Confirmed live via runtime introspection before the
fix: SMART_QUOTES had only 6 entries instead of 8, the U+2018/U+2019
entries had both collapsed to a no-op "'" -> "'" self-map (a Python dict
literal keeps only the last of duplicate keys), and the U+201C/U+201D
entries were gone entirely (their source text was three consecutive
double-quote characters, which got re-parsed as a Python triple-quoted
string spanning both lines instead of two separate one-character dict
keys).

Impact: every ordinary ASCII apostrophe in every scanned script -- e.g.
scripts/report_generator.py's single-quoted HTML string literals -- was
misreported as a "smart/curly quote", while real curly double quotes
(U+201C/U+201D) went completely undetected. Confirmed via live GitHub
Actions job logs (run predating this fix): dozens of
"Smart/curly quote U+0027 (\"'\") found - replace with \"'\"" WARN findings
for ordinary code across the repo.

Fix: rewrite the dict with explicit \\uXXXX escapes (matching this same
file's own INVISIBLE_CHARS dict, which was never affected because it
already used escapes) so the key characters render as plain ASCII in the
source and cannot be silently mangled by a future encoding-normalization
pass the same way again.

This finding was WARN-severity only (see check_smart_quotes() feeding
result["warnings"], never result["failures"]) so it never hard-failed
STAGE 0.06b -- but it was actively corrupting the tool's diagnostic
output and its ability to catch the real defect it exists for.
"""
import pathlib
import sys
import unicodedata
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import python_governance_immunity_engine as pgie  # noqa: E402


class TestSmartQuotesDictIntegrity(unittest.TestCase):
    def test_all_eight_entries_present_with_correct_codepoints(self):
        expected = {
            0x2018: 0x0027,  # LEFT SINGLE QUOTATION MARK -> APOSTROPHE
            0x2019: 0x0027,  # RIGHT SINGLE QUOTATION MARK -> APOSTROPHE
            0x201C: 0x0022,  # LEFT DOUBLE QUOTATION MARK -> QUOTATION MARK
            0x201D: 0x0022,  # RIGHT DOUBLE QUOTATION MARK -> QUOTATION MARK
            0x2032: 0x0027,  # PRIME -> APOSTROPHE
            0x2033: 0x0022,  # DOUBLE PRIME -> QUOTATION MARK
            0x00AB: 0x0022,  # LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
            0x00BB: 0x0022,  # RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
        }
        self.assertEqual(len(pgie.SMART_QUOTES), 8)
        actual = {ord(k): ord(v) for k, v in pgie.SMART_QUOTES.items()}
        self.assertEqual(actual, expected)

    def test_no_ascii_apostrophe_or_quote_key(self):
        """The exact regression: U+0027/U+0022 must never be dict KEYS."""
        for k in pgie.SMART_QUOTES:
            self.assertNotEqual(ord(k), 0x0027, "ASCII apostrophe must not be a SMART_QUOTES key")
            self.assertNotEqual(ord(k), 0x0022, "ASCII quote must not be a SMART_QUOTES key")


class TestCheckSmartQuotesBehaviour(unittest.TestCase):
    def test_ascii_apostrophe_is_accepted(self):
        findings = pgie.check_smart_quotes(
            "t.py", ["x = 'hello world'\n", "y = 'it\\'s fine'\n"]
        )
        self.assertEqual(findings, [])

    def test_ascii_double_quote_is_accepted(self):
        findings = pgie.check_smart_quotes("t.py", ['y = "double quoted"\n'])
        self.assertEqual(findings, [])

    def test_real_curly_single_quotes_still_detected(self):
        findings = pgie.check_smart_quotes("t.py", ["x = ‘hello’\n"])
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["check"] == "SMART_QUOTE" for f in findings))

    def test_real_curly_double_quotes_still_detected(self):
        findings = pgie.check_smart_quotes("t.py", ["y = “world”\n"])
        self.assertEqual(len(findings), 2)

    def test_full_repo_scripts_scan_has_zero_smart_quote_regressions(self):
        """
        End-to-end guard: run the real check against every scripts/*.py file
        the way STAGE 0.06b does, and assert the previously-observed
        false-positive flood (WARN on ordinary apostrophes) is gone.
        Real curly-quote corruption, if any is ever introduced, still
        surfaces as a WARN finding here -- this only asserts none exists
        *today*, not that the check is disabled.
        """
        import glob
        total_smart_quote_warnings = 0
        for filepath in sorted(glob.glob(str(REPO_ROOT / "scripts" / "*.py"))):
            with open(filepath, "rb") as fh:
                raw = fh.read()
            try:
                source = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            lines = source.splitlines(keepends=True)
            total_smart_quote_warnings += len(pgie.check_smart_quotes(filepath, lines))
        self.assertEqual(
            total_smart_quote_warnings, 0,
            "Unexpected real smart-quote findings across scripts/*.py -- "
            "either genuine corruption was introduced, or the detector "
            "regressed back to matching ASCII punctuation.",
        )


if __name__ == "__main__":
    unittest.main()
