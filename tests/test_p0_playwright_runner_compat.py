"""Offline regression contract for Playwright Chromium GitHub Actions runners.

Playwright 1.56.1 fails to install Chromium on GitHub-hosted Ubuntu 26.04
(runner image observed 2026-10-30). Keep browser-dependent workflows on the
supported Ubuntu 24.04 image until the Playwright version and its browser
dependencies are independently certified on a newer image.
No network, browser download, Cloudflare access, or deployment is performed.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    "report": ROOT / ".github/workflows/report-generator-regression-gate.yml",
    "pages": ROOT / ".github/workflows/pages-fast-publish.yml",
}


class PlaywrightRunnerCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {
            name: path.read_text(encoding="utf-8")
            for name, path in WORKFLOWS.items()
        }

    def test_browser_workflows_pin_supported_runner(self):
        for name, source in self.sources.items():
            with self.subTest(workflow=name):
                runners = re.findall(
                    r"(?m)^\s*runs-on:\s*([^\s#]+)", source
                )
                self.assertEqual(runners, ["ubuntu-24.04"])

    def test_browser_install_commands_remain_pinned_and_required(self):
        for name, source in self.sources.items():
            with self.subTest(workflow=name):
                self.assertIn("npm install --no-save playwright@1.56.1", source)
                self.assertIn("npx playwright install --with-deps chromium", source)
                self.assertNotIn("continue-on-error: true", source)

    def test_report_customer_rendering_gates_remain_enabled(self):
        source = self.sources["report"]
        self.assertIn("node render-test/verify_watchdog_stale_state.js", source)
        self.assertIn("node render-test/verify_ai_threat_feed.js", source)
        self.assertIn("node render-test/verify_threat_map_chrome_render.js .", source)

    def test_pages_smoke_test_and_release_authorization_remain_enabled(self):
        source = self.sources["pages"]
        self.assertIn(
            "node render-test/verify_pages_fast_publish_smoke.js dist", source
        )
        self.assertIn("github.event.pull_request.merged == true", source)
        self.assertIn("github.ref == 'refs/heads/main'", source)

    def test_report_gate_executes_this_contract(self):
        self.assertIn(
            "python -m unittest discover -s tests "
            "-p 'test_p0_playwright_runner_compat.py' -v",
            self.sources["report"],
        )


if __name__ == "__main__":
    unittest.main()
