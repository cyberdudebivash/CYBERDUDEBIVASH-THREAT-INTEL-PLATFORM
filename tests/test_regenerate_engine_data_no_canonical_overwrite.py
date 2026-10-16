#!/usr/bin/env python3
"""
tests/test_regenerate_engine_data_no_canonical_overwrite.py

P0 RUNTIME INTELLIGENCE STATE RECOVERY mission follow-up (2026-09-10):
regression guard for the duplicate-writer bug found via this mission's own
required live-production verification. scripts/regenerate_engine_data.py
(run every sentinel-apex.yml cycle) used to unconditionally recompute
AND WRITE data/{nexus,genesis,cortex,quantum,sovereign}/*_output.json from
its own independent algorithm, stamping one shared module-level NOW_UTC
into every output. Before this mission, that was harmless -- those paths
were gitignored and never uploaded anywhere, so the write was discarded at
the end of every job. The moment this mission registered those same 5
paths in scripts/r2_state_sync.py's STATE_FILES (to give NEXUS/CORTEX/
QUANTUM/SOVEREIGN/GENESIS a real, fresh, R2-persisted canonical producer
via sovereign-platform.yml/genesis-powerhouse.yml), sentinel-apex.yml's
own PRE-EXISTING, unchanged `r2_state_sync.py --upload` calls (broad, no
--only) started picking up whatever this script last wrote locally and
publishing it to the SAME R2 keys -- a second, differently-computed writer
silently racing and overwriting the canonical one. Confirmed live: a
production curl caught all 5 R2 objects holding one shared, older
generated_at (this module's own NOW_ISO) that had overwritten a
freshly-verified, newer canonical write from genesis-powerhouse.yml
minutes earlier.

Fix: this script no longer writes to those 5 canonical paths (still
computes generate_nexus()/generate_genesis() in-memory, since
generate_engines_api() depends on their return values). This test proves
the 5 paths are never created/touched by main(), while api/engines.json
(which has no other canonical producer and must keep working) still is.
"""
import importlib
import json
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import regenerate_engine_data as regen  # noqa: E402

CANONICAL_PATHS = [
    ("nexus", "nexus_output.json"),
    ("genesis", "genesis_output.json"),
    ("cortex", "cortex_output.json"),
    ("quantum", "quantum_output.json"),
    ("sovereign", "sovereign_output.json"),
]


class TestRegenerateEngineDataDoesNotOverwriteCanonicalOutputs(unittest.TestCase):
    """Runs the real main() against the real local feed data (read-only --
    _load_feed() only reads api/feed.baseline.json/api/feed.json, never
    writes), but redirects every WRITE to an isolated tmp directory by
    monkeypatching the module's ROOT global, so this test can never touch
    the real repo tree regardless of outcome."""

    def setUp(self):
        self._orig_root = regen.ROOT
        self._tmp = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        regen.ROOT = self._tmp

    def tearDown(self):
        regen.ROOT = self._orig_root

    def test_main_does_not_write_any_of_the_5_canonical_engine_files(self):
        try:
            regen.main()
        except SystemExit as exc:
            self.assertIn(exc.code, (0, 1), f"unexpected exit code {exc.code}")

        for subdir, filename in CANONICAL_PATHS:
            path = pathlib.Path(self._tmp) / "data" / subdir / filename
            self.assertFalse(
                path.exists(),
                f"regenerate_engine_data.py must not write {subdir}/{filename} -- "
                f"that path now has a dedicated, fresher, R2-persisted canonical "
                f"producer (sovereign-platform.yml / genesis-powerhouse.yml); this "
                f"script writing it too silently races and can overwrite the "
                f"canonical writer once both are picked up by sentinel-apex.yml's "
                f"own broad `r2_state_sync.py --upload`.",
            )

    def test_main_does_not_touch_a_pre_existing_canonical_engine_file(self):
        """CodeRabbit review (PR #409): the absent-file case above proves
        main() doesn't CREATE these 5 files, but not that it leaves an
        already-present one untouched -- a future regression reintroducing
        a conditional write ("only if missing"/"only if stale") would slip
        past that test alone. Pre-populates each canonical path with sentinel
        content before running main(), then asserts it's still byte-identical
        afterward -- covering the case a real production checkout is
        actually in (sentinel-apex.yml's own r2_state_sync.py --download
        step, or a leftover from a prior job, may well have left these files
        present locally before this script ever runs)."""
        sentinel_content = b'{"sentinel": "PRE-EXISTING-CONTENT-MUST-SURVIVE"}'
        for subdir, filename in CANONICAL_PATHS:
            path = pathlib.Path(self._tmp) / "data" / subdir / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(sentinel_content)

        try:
            regen.main()
        except SystemExit as exc:
            self.assertIn(exc.code, (0, 1), f"unexpected exit code {exc.code}")

        for subdir, filename in CANONICAL_PATHS:
            path = pathlib.Path(self._tmp) / "data" / subdir / filename
            self.assertEqual(
                path.read_bytes(), sentinel_content,
                f"regenerate_engine_data.py must not modify a pre-existing "
                f"{subdir}/{filename} -- it has a dedicated canonical producer now "
                f"and this script must leave it alone whether it's present or absent.",
            )

    def test_main_still_writes_engines_api_which_has_no_other_producer(self):
        """Guards against the fix accidentally breaking the one output this
        script remains the sole legitimate source for."""
        try:
            regen.main()
        except SystemExit as exc:
            self.assertIn(exc.code, (0, 1), f"unexpected exit code {exc.code}")

        engines_path = pathlib.Path(self._tmp) / "api" / "engines.json"
        self.assertTrue(engines_path.exists(), "api/engines.json must still be written")
        with open(engines_path, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIn("engines_ok", payload)
        self.assertIn("engines_total", payload)

    def test_generate_nexus_and_generate_genesis_functions_are_not_removed(self):
        """Deprecation Instead of Deletion: generate_engines_api() still
        depends on these two functions' return values as direct inputs --
        this pins that the fix kept the compute, only dropped the write."""
        self.assertTrue(callable(regen.generate_nexus))
        self.assertTrue(callable(regen.generate_genesis))
        self.assertTrue(callable(regen.generate_cortex))
        self.assertTrue(callable(regen.generate_quantum))
        self.assertTrue(callable(regen.generate_sovereign))


if __name__ == "__main__":
    unittest.main()
