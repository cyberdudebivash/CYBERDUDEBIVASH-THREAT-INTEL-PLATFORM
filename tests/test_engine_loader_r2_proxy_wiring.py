#!/usr/bin/env python3
"""
tests/test_engine_loader_r2_proxy_wiring.py

P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10) regression guard.

Root cause this pins against regressing: index.html's initEngineLoader()
previously fetched nexus/genesis/cortex/quantum/sovereign_output.json
directly from raw.githubusercontent.com/.../main/ -- a frozen git blob that
never changed regardless of how many times the producing workflows "ran
successfully", because those workflows' git-push persistence was silently
rejected by main's branch ruleset every run since ~2026-08-26. The fix moves
these 5 engines onto the same-origin /api/v1/intel/*_output.json Worker
routes (workers/intel-gateway/src/intel-static-proxy.js), which read
Cloudflare R2 first (kept fresh by the new upload step in
genesis-powerhouse.yml/sovereign-platform.yml) and fall back to the exact
same raw-GitHub-main URL if R2 is ever empty or errors -- zero removal of
the existing fallback, matching this mission's explicit constraint.

bughunter/incidents/responses/hunts are unrelated to this mission's scope
and must keep reading straight from the raw-GitHub-main mirror, unchanged.
"""
import pathlib
import re
import unittest
from scripts.homepage_source import read_homepage_source  # index.html + extracted css/js

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX_HTML = REPO_ROOT / "index.html"


def _engine_urls_block() -> str:
    html = read_homepage_source()
    match = re.search(r"const ENGINE_URLS = \{(.*?)\};", html, re.DOTALL)
    assert match, "ENGINE_URLS object literal not found in index.html"
    return match.group(1)


class TestEngineLoaderR2ProxyWiring(unittest.TestCase):
    def setUp(self):
        self.block = _engine_urls_block()

    def test_five_migrated_engines_use_same_origin_proxy_paths(self):
        for name, path in (
            ("nexus", "/api/v1/intel/nexus_output.json"),
            ("genesis", "/api/v1/intel/genesis_output.json"),
            ("cortex", "/api/v1/intel/cortex_output.json"),
            ("quantum", "/api/v1/intel/quantum_output.json"),
            ("sovereign", "/api/v1/intel/sovereign_output.json"),
        ):
            pattern = re.compile(re.escape(name) + r":\s*'" + re.escape(path) + r"'")
            self.assertRegex(
                self.block, pattern,
                f"ENGINE_URLS.{name} must point at the same-origin proxy path {path}, "
                f"not a raw-GitHub URL -- R2 freshness cannot reach the browser otherwise.",
            )

    def test_five_migrated_engines_no_longer_use_raw_base_directly(self):
        for name in ("nexus", "genesis", "cortex", "quantum", "sovereign"):
            pattern = re.compile(re.escape(name) + r":\s*RAW_BASE")
            self.assertNotRegex(
                self.block, pattern,
                f"ENGINE_URLS.{name} must not read directly from RAW_BASE (raw.githubusercontent.com/"
                f"main) any more -- that path is frozen forever once the producing workflow's git push "
                f"is replaced with R2 upload (nothing commits to main for this data any more).",
            )

    def test_four_out_of_scope_engines_still_use_raw_base_unchanged(self):
        """This mission is scoped to NEXUS/CORTEX/QUANTUM/SOVEREIGN/GENESIS only
        (mission Section 18's explicit 'do not expand to all 34 workflows' /
        'one production failure class per PR'). bughunter/incidents/responses/
        hunts must be left exactly as they were."""
        for name in ("bughunter", "incidents", "responses", "hunts"):
            pattern = re.compile(re.escape(name) + r":\s*RAW_BASE")
            self.assertRegex(
                self.block, pattern,
                f"ENGINE_URLS.{name} is out of this mission's scope and must keep reading "
                f"from RAW_BASE unchanged.",
            )

    def test_raw_base_constant_itself_is_not_removed(self):
        """This mission's explicit non-negotiable: no removal of GitHub Raw
        runtime fallbacks. RAW_BASE must still exist -- it's now the proxy's
        server-side fallback source (unchanged URL) as well as the 4
        out-of-scope engines' only source."""
        html = read_homepage_source()
        self.assertIn(
            "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNL21haW4v",
            html,
        )


if __name__ == "__main__":
    unittest.main()
