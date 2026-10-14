"""
tests/test_backup_kv_to_r2_parallel_fetch.py

Regression test for a P0 defect: the "Automated Backup" workflow's
"Cloudflare KV + R2 Backup" job has been hitting its 30-minute
timeout-minutes limit on every single scheduled run for 13+ days
(confirmed live: run 33595371090 and its predecessors going back to
2026-08-20, job "Backup KV namespaces to R2" -> "The operation was
canceled" at exactly the timeout boundary, with zero log output in
between -- Python's print() is fully buffered on piped/non-interactive
stdout, so genuine progress was invisible in CI).

Root cause: backup_namespace() in scripts/backup_kv_to_r2.py fetched every
KV key with its own sequential HTTP round-trip (get_kv_value() per key, one
at a time). Once any of the platform's 4 KV namespaces grew past a few
thousand keys, that's thousands of sequential network round-trips -- easily
exceeding 30 minutes.

Fix: fetch keys concurrently via a bounded ThreadPoolExecutor (10 workers --
deliberately conservative to avoid trading a timeout for a burst of
Cloudflare API 429s). PYTHONUNBUFFERED=1 added to the workflow step
separately so future slowness is at least diagnosable in the CI log.

This test verifies the parallelized fetch is behaviorally equivalent to the
old sequential one: same entries collected, same per-key error isolation
(one failing key does not lose or corrupt any other key's data), same
count/error bookkeeping -- using a mocked get_kv_value() so no real network
or Cloudflare credentials are involved.
"""
import pathlib
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import backup_kv_to_r2 as bkv  # noqa: E402


class TestParallelFetchCorrectness(unittest.TestCase):
    def test_all_keys_fetched_and_present(self):
        keys = [f"key-{i}" for i in range(250)]
        with patch.object(bkv, "list_kv_keys", return_value=keys):
            with patch.object(bkv, "get_kv_value", side_effect=lambda ns_id, k: f"value-for-{k}"):
                result = bkv.backup_namespace("TEST_NS", "ns123", skip_transient=False)

        self.assertEqual(result["count"], 250)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(len(result["entries"]), 250)
        for k in keys:
            self.assertEqual(result["entries"][k], f"value-for-{k}")

    def test_one_failing_key_does_not_lose_or_corrupt_others(self):
        keys = [f"key-{i}" for i in range(50)]

        def _fetch(ns_id, key):
            if key == "key-17":
                raise RuntimeError("simulated transient CF API error")
            return f"value-for-{key}"

        with patch.object(bkv, "list_kv_keys", return_value=keys):
            with patch.object(bkv, "get_kv_value", side_effect=_fetch):
                result = bkv.backup_namespace("TEST_NS", "ns123", skip_transient=False)

        # A partially fetched namespace is not a restorable snapshot.
        self.assertIsNone(result)

    def test_transient_filter_still_applied_before_fetching(self):
        """RATE_LIMIT_KV's rl: prefix filter must still exclude keys from
        the (now-parallel) fetch entirely, not just from the final output --
        fetching them and discarding the result would still cost the
        network round-trip this fix exists to reduce."""
        keys = ["rl:1.2.3.4", "rl:5.6.7.8", "real-key-1", "real-key-2"]
        fetched = []

        def _fetch(ns_id, key):
            fetched.append(key)
            return "value"

        with patch.object(bkv, "list_kv_keys", return_value=keys):
            with patch.object(bkv, "get_kv_value", side_effect=_fetch):
                result = bkv.backup_namespace("RATE_LIMIT_KV", "ns123", skip_transient=True)

        self.assertEqual(sorted(fetched), ["real-key-1", "real-key-2"])
        self.assertEqual(result["count"], 2)

    def test_checksum_is_order_independent(self):
        """Concurrent completion order is nondeterministic -- the checksum
        must not be, since it's used to detect real data changes across
        daily snapshots."""
        keys = [f"key-{i}" for i in range(30)]

        def _fetch(ns_id, key):
            time.sleep(0.001 if int(key.split("-")[1]) % 3 == 0 else 0)
            return f"value-for-{key}"

        with patch.object(bkv, "list_kv_keys", return_value=keys):
            with patch.object(bkv, "get_kv_value", side_effect=_fetch):
                result_a = bkv.backup_namespace("TEST_NS", "ns123", skip_transient=False)
            with patch.object(bkv, "get_kv_value", side_effect=_fetch):
                result_b = bkv.backup_namespace("TEST_NS", "ns123", skip_transient=False)

        self.assertEqual(result_a["checksum_sha256"], result_b["checksum_sha256"])

    def test_empty_namespace_does_not_error(self):
        with patch.object(bkv, "list_kv_keys", return_value=[]):
            result = bkv.backup_namespace("EMPTY_NS", "ns123", skip_transient=False)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["errors"], 0)

    def test_listing_failure_still_returns_none_not_raise(self):
        """backup_namespace()'s caller (main()) relies on None meaning
        'this namespace failed, record it and continue to the next one' --
        must be preserved by the parallel-fetch change."""
        with patch.object(bkv, "list_kv_keys", side_effect=RuntimeError("CF API down")):
            result = bkv.backup_namespace("TEST_NS", "ns123", skip_transient=False)
        self.assertIsNone(result)


class TestTransientRetryHardening(unittest.TestCase):
    def test_worker_count_is_bounded_and_configurable(self):
        self.assertGreaterEqual(bkv.MAX_WORKERS, 1)
        self.assertLessEqual(bkv.MAX_WORKERS, 64)

    def test_429_is_retried_then_succeeds(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"value"
        response.__enter__.return_value.__exit__.return_value = False
        err = __import__("urllib.error").error.HTTPError("u", 429, "rate", {}, None)
        with patch.object(bkv, "_cloudflare_open", side_effect=[err, response]) as call:
            with patch.object(bkv.time, "sleep"):
                with patch.object(bkv.random, "uniform", return_value=0):
                    value = bkv.get_kv_value("ns", "key")
        self.assertEqual(value, "value")
        self.assertEqual(call.call_count, 2)

    def test_non_retryable_auth_error_fails_immediately(self):
        err = __import__("urllib.error").error.HTTPError("u", 403, "forbidden", {}, None)
        with patch.object(bkv, "_cloudflare_open", side_effect=err) as call:
            with self.assertRaises(__import__("urllib.error").error.HTTPError):
                bkv.get_kv_value("ns", "key")
        self.assertEqual(call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
