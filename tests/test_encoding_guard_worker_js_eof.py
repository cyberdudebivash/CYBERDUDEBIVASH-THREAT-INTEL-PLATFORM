"""
tests/test_encoding_guard_worker_js_eof.py

Regression test for a P0 defect that hard-failed STAGE 0.0 - Encoding Guard
on every sentinel-apex.yml run since workers/intel-gateway/src/
intel-static-proxy.js became reachable from index.js's import graph
(introduced in PR #323).

Root cause: scripts/encoding_guard.py's _check_worker_js_eof() is documented
("Reads the last non-empty line and verifies it ends with a known valid JS
closing token") and messaged ("Fix: ensure the file ends with '};'") as a
SUFFIX check, but was implemented as an EXACT match: `last_line in
WORKER_JS_VALID_EOF_TOKENS`. intel-static-proxy.js's real, complete,
non-truncated last line is `export { handleIntelStaticProxy,
INTEL_STATIC_PROXY };` -- it ends with the valid token "};" but is not
*equal* to "};", so it was misclassified TRUNCATED and encoding_guard.py
exited 1, cascading into STAGE 0.1 onward being skipped for the rest of the
run (confirmed live via GitHub Actions job logs for run #2210: "FATAL: 1
Worker JS file(s) are TRUNCATED ... last='export { handleIntelStaticProxy,
INTEL_STATIC_PROXY };'" followed by "Process completed with exit code 1").

Fix: match on suffix (any(last_line.endswith(tok) for tok in
WORKER_JS_VALID_EOF_TOKENS)) instead of exact equality, so any statement
that legitimately *ends with* a valid closing token is accepted, while a
genuinely truncated file (cut off mid-identifier/mid-string) -- which does
not coincidentally end in one of these closing-bracket tokens -- is still
correctly flagged.
"""
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import encoding_guard as eg  # noqa: E402


class TestWorkerJsEofSuffixMatch(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="eg_eof_test_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, content: str) -> pathlib.Path:
        p = self.tmp / name
        p.write_text(content, encoding="ascii")
        return p

    def test_named_export_statement_is_not_truncated(self):
        """The exact regression case: a multi-symbol named-export line."""
        p = self._write(
            "intel-static-proxy.js",
            "function handleIntelStaticProxy() { return 1; }\n"
            "const INTEL_STATIC_PROXY = true;\n"
            "export { handleIntelStaticProxy, INTEL_STATIC_PROXY };\n",
        )
        self.assertTrue(eg._check_worker_js_eof(p, self.tmp))

    def test_export_default_object_is_not_truncated(self):
        p = self._write(
            "index.js",
            "export default {\n"
            "  async fetch(req, env) { return new Response('ok'); },\n"
            "};\n",
        )
        self.assertTrue(eg._check_worker_js_eof(p, self.tmp))

    def test_bare_closing_brace_still_accepted(self):
        p = self._write("bare.js", "function f() {\n  return 1;\n}\n")
        self.assertTrue(eg._check_worker_js_eof(p, self.tmp))

    def test_object_freeze_array_close_still_accepted(self):
        p = self._write(
            "frozen.js",
            "const DEFINITIONS = Object.freeze([\n  { id: 1 },\n  { id: 2 },\n]);\n",
        )
        self.assertTrue(eg._check_worker_js_eof(p, self.tmp))

    def test_genuinely_truncated_file_is_still_detected(self):
        """A file cut off mid-statement must still be flagged TRUNCATED."""
        p = self._write(
            "truncated.js",
            "export default {\n"
            "  async fetch(req, env) {\n"
            "    const url = new URL(req.url",  # cut off mid-call, no closer
        )
        self.assertFalse(eg._check_worker_js_eof(p, self.tmp))

    def test_empty_file_is_truncated(self):
        p = self._write("empty.js", "")
        self.assertFalse(eg._check_worker_js_eof(p, self.tmp))

    def test_real_production_file_passes(self):
        """Direct check against the actual file that triggered the P0 outage."""
        real = REPO_ROOT / "workers" / "intel-gateway" / "src" / "intel-static-proxy.js"
        if not real.exists():
            self.skipTest("intel-static-proxy.js not present in this checkout")
        self.assertTrue(eg._check_worker_js_eof(real, REPO_ROOT))


if __name__ == "__main__":
    unittest.main()
