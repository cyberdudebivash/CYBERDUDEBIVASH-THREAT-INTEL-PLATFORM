"""
tests/test_frontend_api_coverage_gate.py

Covers scripts/frontend_api_coverage_gate.py -- the new STAGE 3.92b
observability gate that classifies every top-level *.html page as
dynamic (calls the platform's own API) or static. Evidence for why this
gate exists: cves.html and ransomware.html both shipped zero client-side
API calls despite the backend already serving their data elsewhere (both
fixed this session); a manual page count taken earlier in the same
session ("246 top-level pages") did not match a direct, repeatable count
taken later (144, confirmed twice) -- proof a one-time manual sweep
drifts and this needed to become a script, not a memory.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import frontend_api_coverage_gate as gate  # noqa: E402


class TestIsDynamic(unittest.TestCase):
    def test_inline_fetch_of_api_path_is_dynamic(self):
        html = '<script>fetch("/api/v1/intel/ransomware").then(r=>r.json())</script>'
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)
        self.assertIn("fetch", reason)

    def test_fetch_of_non_api_path_is_static(self):
        html = '<script>fetch("/js/some-lib.js")</script>'
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)

    def test_known_live_data_script_include_is_dynamic(self):
        html = '<script src="js/sentinel-live-feeds.js"></script>'
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)
        self.assertIn("sentinel-live-feeds.js", reason)

    def test_unrelated_script_include_is_static(self):
        html = '<script src="js/some-analytics-lib.js"></script>'
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)

    def test_plain_marketing_page_is_static(self):
        html = "<html><body><h1>Pricing</h1><p>Contact sales.</p></body></html>"
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)
        self.assertEqual(reason, "")

    def test_fetch_with_single_quotes_is_detected(self):
        html = "<script>fetch('/api/health')</script>"
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)

    def test_fetch_with_variable_concatenation_is_detected(self):
        # Real false negative caught during this script's own build: both
        # cves.html and ransomware.html (this session's own verified-live
        # fixes) build the URL as `API_BASE + "/api/..."` rather than a
        # literal string starting with /api/ -- an earlier, stricter
        # version of this regex missed both.
        html = '<script>fetch(API_BASE + "/api/v1/intel/ransomware", {cache:"no-cache"})</script>'
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)
        self.assertIn("fetch", reason)

    def test_fetch_with_template_literal_concatenation_is_detected(self):
        html = "<script>fetch(`${API_BASE}/api/v1/cve/live`)</script>"
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)

    def test_fetch_via_helper_function_far_from_api_literal_is_detected(self):
        # Second real false negative caught while building this script:
        # threats.html's fetchJSON(path) helper calls fetch(API_BASE + path, ...)
        # with no /api/ text anywhere near that call -- the actual
        # "/api/v1/intel/stats" literal is 40 lines away, at the call site.
        # A windowed "fetch( followed within N chars by /api/" regex misses
        # this; whole-file co-occurrence does not.
        html = (
            "<script>\n"
            "  function fetchJSON(path) { return fetch(API_BASE + path, {cache:'no-cache'}); }\n"
            "  // ... 40 lines of unrelated code here in the real file ...\n"
            "  fetchJSON(\"/api/v1/intel/stats\");\n"
            "</script>"
        )
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)
        self.assertIn("fetch", reason)

    def test_fetch_with_api_literal_containing_query_string_is_detected(self):
        # Third real regression caught while building this script: an
        # over-restrictive first attempt at the path-literal regex allowed
        # only [a-zA-Z0-9/_.-] after "/api/", which excludes "?" and "=" --
        # so it silently stopped matching cves.html's own
        # '/api/v1/cve/detail?id=' and vulnerabilities.html's
        # '/api/v1/cve/live?limit=8' literals (both real, both this
        # session's own verified-live fixes) the moment this change was
        # made, without any test catching it until a full re-run against
        # the real repo. Any non-quote character is valid inside a query
        # string, so the tail must accept anything up to the closing quote.
        html = "<script>fetch(API_BASE + '/api/v1/cve/detail?id=' + encodeURIComponent(cveId), {cache:'no-store'})</script>"
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)

    def test_prose_mentioning_fetch_and_api_outside_script_is_static(self):
        # Real false positive CodeRabbit caught on PR #336 (verified against
        # the actual file, not taken on faith): SENTINEL_APEX_ENTERPRISE_
        # AUDIT_v145.html is a prose audit report discussing this platform's
        # /api/ endpoints in plain English -- the sentence "daily public
        # JSON fetch (no API key needed)" alone satisfied a whole-raw-file
        # version of this check (fetch\s*\( matched "fetch (", an /api/
        # path literal appeared elsewhere in the document), misclassifying
        # a static document as dynamic. Neither signal is inside a
        # <script> tag here, so this must classify static.
        html = (
            "<html><body>"
            "<div class='finding-body'>Integrate with the Worker to fetch "
            "/api/health in real-time and display actual service status.</div>"
            "<li>CISA KEV cross-reference &mdash; daily public JSON fetch "
            "(no API key needed)</li>"
            "</body></html>"
        )
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertFalse(is_dynamic, f"expected static, got dynamic with reason: {reason!r}")

    def test_json_ld_block_is_excluded_from_the_script_pool(self):
        # JSON-LD structured-data blocks hold JSON text, not executable JS,
        # and every real product page in this repo carries one (SEO
        # metadata) -- a JSON-LD "description" field mentioning /api/ must
        # not combine with an unrelated real <script>'s fetch() call to
        # produce a false dynamic classification. Note: this checks the
        # JSON-LD exclusion specifically, not per-block isolation -- two
        # genuine inline <script> tags on the same page are still pooled
        # together (a page's own inline scripts are all "this page's code",
        # just not raw HTML prose or structured data).
        html = (
            "<script>fetch('https://analytics.example.com/beacon')</script>"
            '<script type="application/ld+json">{"description": "See /api/docs for details"}</script>'
        )
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)

    def test_fetch_with_no_api_literal_anywhere_is_static(self):
        # The whole-file co-occurrence check still requires BOTH signals --
        # a fetch() call alone, with no /api/ literal anywhere in the file,
        # must not be misclassified as dynamic.
        html = "<script>fetch('/js/some-lib.js'); fetch('https://fonts.googleapis.com/css');</script>"
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)

    def test_malformed_script_close_tag_still_terminates_the_block(self):
        # GitHub Advanced Security / CodeQL finding on PR #336 ("Bad HTML
        # filtering regexp"): a real browser closes <script> on "</script"
        # followed by ANY characters up to the next ">", not just
        # whitespace -- CodeQL's own flagged example is a close tag with a
        # stray attribute-like tail, "</script\t\n bar>". Before the fix,
        # _SCRIPT_BLOCK_RE's `</script\s*>` half did not match that, so the
        # non-greedy body capture skipped straight past it looking for a
        # plain `</script>`, pulling the next unrelated <script> block's
        # code into this one's "body" text. Two independent script blocks
        # here -- only the second one has both signals -- must classify as
        # two separate blocks, not get merged into one by the malformed
        # close tag on the first.
        html = (
            "<script>fetch('/js/some-lib.js')</script bar>"
            "<script>var x = 1;</script>"
        )
        is_dynamic, _ = gate._is_dynamic(html)
        self.assertFalse(is_dynamic)

        parts = gate._inline_script_text(html).split("\n")
        self.assertEqual(parts, ["fetch('/js/some-lib.js')", "var x = 1;"])

    def test_malformed_close_tag_on_json_ld_block_does_not_hide_a_real_api_call(self):
        # Proves the bug was a genuine false negative, not just a cosmetic
        # mis-split: verified directly (old vs. new regex, side by side)
        # that with a malformed close tag on a JSON-LD block, the OLD
        # pattern's non-greedy body capture skips straight past it and
        # merges the JSON-LD block with the *next* real <script> block into
        # ONE match -- whose attrs still say type="application/ld+json", so
        # _inline_script_text's JSON-LD exclusion (see its docstring) then
        # discards the WHOLE merged body, including the second block's
        # genuine fetch()+/api/ call, via `continue`. A real dynamic page
        # would silently classify as static. The fix's `[^>]*` closes the
        # JSON-LD block exactly at its own (malformed) end tag, leaving the
        # following real <script> block intact and separately captured.
        html = (
            '<script type="application/ld+json">{"a":1}</script\t\n bar>'
            "<script>fetch(API_BASE + '/api/v1/cve/live')</script>"
        )
        is_dynamic, reason = gate._is_dynamic(html)
        self.assertTrue(is_dynamic)
        self.assertIn("fetch", reason)
        self.assertEqual(gate._inline_script_text(html), "fetch(API_BASE + '/api/v1/cve/live')")


class TestLoadAllowlist(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="facg_allowlist_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_allowlist_file_returns_empty_set(self):
        with patch.object(gate, "ALLOWLIST_PATH", self.tmp / "nope.json"):
            self.assertEqual(gate._load_allowlist(), set())

    def test_present_allowlist_returns_static_pages_as_set(self):
        path = self.tmp / "allow.json"
        path.write_text(json.dumps({"static_pages": ["privacy.html", "terms.html"]}), encoding="utf-8")
        with patch.object(gate, "ALLOWLIST_PATH", path):
            self.assertEqual(gate._load_allowlist(), {"privacy.html", "terms.html"})

    def test_malformed_allowlist_never_raises(self):
        path = self.tmp / "bad.json"
        path.write_text("{not valid json", encoding="utf-8")
        with patch.object(gate, "ALLOWLIST_PATH", path):
            self.assertEqual(gate._load_allowlist(), set())


class TestMainIntegration(unittest.TestCase):
    """
    A gate that could ever fail CI over an unclassified static page (before
    a human-curated allowlist exists) would be worse than no gate at all --
    it would just be pure noise blocking deploys. These tests prove main()
    always exits 0 (observability-only) regardless of what it finds, while
    still writing a fully accurate classification.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="facg_main_test_"))
        (self.tmp / "dynamic-inline.html").write_text(
            '<script>fetch("/api/v1/intel/ransomware")</script>', encoding="utf-8"
        )
        (self.tmp / "dynamic-shared-script.html").write_text(
            '<script src="js/sentinel-live-feeds.js"></script>', encoding="utf-8"
        )
        (self.tmp / "static-allowlisted.html").write_text("<h1>Privacy Policy</h1>", encoding="utf-8")
        (self.tmp / "static-unclassified.html").write_text("<h1>Some Product Page</h1>", encoding="utf-8")
        # Not top-level -- must never be scanned (scope is repo-root *.html only).
        (self.tmp / "reports").mkdir()
        (self.tmp / "reports" / "nested.html").write_text(
            '<script>fetch("/api/should/not/be/scanned")</script>', encoding="utf-8"
        )
        self.allowlist_path = self.tmp / "allow.json"
        self.allowlist_path.write_text(
            json.dumps({"static_pages": ["static-allowlisted.html"]}), encoding="utf-8"
        )
        self.output_path = self.tmp / "out.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self):
        with patch.object(gate, "REPO_ROOT", self.tmp), \
             patch.object(gate, "OUTPUT_PATH", self.output_path), \
             patch.object(gate, "ALLOWLIST_PATH", self.allowlist_path):
            return gate.main()

    def test_exits_zero_even_with_unclassified_static_pages(self):
        self.assertEqual(self._run(), 0)

    def test_report_counts_and_scope_are_correct(self):
        self._run()
        report = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(report["total_pages"], 4, "must not scan reports/nested.html -- top-level only")
        self.assertEqual(report["dynamic_count"], 2)
        self.assertEqual(report["static_allowlisted_count"], 1)
        self.assertEqual(report["static_unclassified_count"], 1)
        dynamic_names = {p["file"] for p in report["dynamic_pages"]}
        self.assertEqual(dynamic_names, {"dynamic-inline.html", "dynamic-shared-script.html"})

    def test_unclassified_static_page_is_named_not_silently_dropped(self):
        self._run()
        report = json.loads(self.output_path.read_text(encoding="utf-8"))
        unclassified = [p for p in report["static_pages"] if not p["allowlisted"]]
        self.assertEqual([p["file"] for p in unclassified], ["static-unclassified.html"])

    def test_report_written_even_with_no_allowlist_file(self):
        self.allowlist_path.unlink()
        code = self._run()
        self.assertEqual(code, 0)
        report = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertFalse(report["allowlist_present"])
        self.assertEqual(report["static_allowlisted_count"], 0)
        self.assertEqual(report["static_unclassified_count"], 2)


class TestWorkflowStepConfiguration(unittest.TestCase):
    def test_stage_3_92b_step_exists_and_is_non_blocking(self):
        import yaml

        workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
        with open(workflow_path, encoding="utf-8") as f:
            workflow = yaml.safe_load(f)

        job = next(iter(workflow["jobs"].values()))
        steps = job["steps"]
        matches = [s for s in steps if "STAGE 3.92b" in s.get("name", "")]
        self.assertEqual(len(matches), 1, "expected exactly one STAGE 3.92b step")
        step = matches[0]
        self.assertIs(
            step.get("continue-on-error"), True,
            "STAGE 3.92b is observability-only (no allowlist curated yet) and must "
            "never be able to fail the pipeline"
        )
        self.assertIn("frontend_api_coverage_gate.py", step.get("run", ""))

    def test_stage_3_92b_never_presents_a_stale_or_missing_report_as_fresh(self):
        # CodeRabbit finding on PR #336 (verified, not taken on faith): the
        # original step swallowed the script's exit code unconditionally
        # (`|| true`) and read whatever report happened to already be on
        # disk, so a script crash before its own atomic write would print a
        # normal-looking coverage notice instead of visibly failing.
        import yaml

        workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
        with open(workflow_path, encoding="utf-8") as f:
            workflow = yaml.safe_load(f)

        job = next(iter(workflow["jobs"].values()))
        steps = job["steps"]
        step = next(s for s in steps if "STAGE 3.92b" in s.get("name", ""))
        run = step.get("run", "")

        self.assertIn(
            "rm -f data/quality/frontend_api_coverage_report.json", run,
            "must remove any pre-existing report before running so a stale "
            "copy can never be read as this run's own output"
        )
        self.assertNotIn(
            "frontend_api_coverage_gate.py || true", run,
            "must not unconditionally swallow the script's exit code -- a "
            "crash needs to produce a visibly different log line than success"
        )
        self.assertIn(
            "::warning::", run,
            "a failed run must emit a warning, not the same ::notice:: a "
            "successful run does"
        )


if __name__ == "__main__":
    unittest.main()
