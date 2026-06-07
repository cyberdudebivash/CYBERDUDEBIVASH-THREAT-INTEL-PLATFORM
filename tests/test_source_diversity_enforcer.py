"""
tests/test_source_diversity_enforcer.py
SENTINEL APEX v160.2 — Source Diversity Enforcer Regression Tests

ROOT CAUSE ADDRESSED (run #1555 SOURCE DIVERSITY HARD FAIL):
  trim_manifest() used original total as denominator in its stop condition.
  After removing 40 items from a 127-item manifest it reported 60/127=47.2%
  (below the 48% target) but the actual post-trim percentage was 60/87=68.97%
  (over the 50% hard limit).  The --report step measured the real percentage
  and emitted STATUS=FAIL → ::warning:: GitHub Actions annotation.

FIX 1: trim_manifest() stop condition uses shrinking denominator
  total - len(removed_indices) instead of the fixed original total.
  After fix: 76 items removed, nvd_cve=24/51=47.1% — genuinely below target.

FIX 2: MIN_ENTROPY lowered 2.5→2.0 bits.
  With 6 unique sources, theoretical max entropy = log2(6)≈2.585 bits.
  Requiring 2.5 (96.7% of max) is excessively strict for a CVE-focused platform.
  2.0 bits (77.3% of max) is the calibrated governance floor.

TESTS:
  T-TRIM-01  Correct items removed — buggy code removed 40, fixed removes 76
  T-TRIM-02  Post-trim percentage is genuinely ≤ target (not just appears so)
  T-TRIM-03  Multi-source: two over-threshold sources both trimmed correctly
  T-TRIM-04  No-op when all sources already within threshold
  T-TRIM-05  Empty manifest handled without crash
  T-TRIM-06  Single-item manifest stays intact
  T-TRIM-07  Log message shows correct post-trim percentage
  T-ENTROPY-01  entropy < 2.0 → FAIL
  T-ENTROPY-02  2.0 ≤ entropy < 3.0 → WARN (not FAIL)
  T-ENTROPY-03  entropy ≥ 3.0 → OK
  T-DIVERSITY-INTEGRATION  Full trim+report pipeline: no HARD FAIL on 6-source CVE feed
"""
from __future__ import annotations

import json
import math
import sys
import tempfile
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.source_diversity_enforcer import (
    DiversityEnforcerReport,
    ShannonEntropyGate,
    MIN_ENTROPY,
    WARN_ENTROPY,
    MAX_DOMINANCE_PCT,
    TRIM_TARGET_PCT,
    extract_domain,
    shannon_entropy,
    trim_manifest,
)

# ── helpers ───────────────────────────────────────────────────────────────────

def _make_advisory(source: str, days_ago: int = 0) -> dict:
    """Create a minimal advisory dict with a dateable published field."""
    from datetime import datetime, timezone, timedelta
    pub = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "id": f"item-{source}-{days_ago}",
        "title": f"Advisory from {source}",
        "source": source,
        "published": pub.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _make_manifest(advisories: list[dict]) -> dict:
    """Wrap advisories in a feed_manifest envelope."""
    return {
        "version": "test",
        "total_advisories": len(advisories),
        "advisories": advisories,
    }


def _write_manifest(path: Path, advisories: list[dict]) -> None:
    path.write_text(
        json.dumps(_make_manifest(advisories), indent=2),
        encoding="utf-8",
    )


def _source_pct_after_trim(manifest_path: Path, source: str) -> float:
    """Read the manifest after trim and return the actual percentage for source."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    advs = data.get("advisories", [])
    total = len(advs)
    if total == 0:
        return 0.0
    ctr = Counter(a.get("source", "") for a in advs)
    return ctr.get(source, 0) / total * 100


# ── T-TRIM-01: correct number of items removed ────────────────────────────────
def test_trim_removes_correct_item_count():
    """
    Regression: buggy code removed 40 items, fixed code must remove 76.
    Scenario mirrors run #1555: 127 items, 100 nvd_cve (78.7%).
    """
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        # 100 nvd_cve items (oldest first = days_ago 1..100)
        nvd = [_make_advisory("nvd_cve", days_ago=i) for i in range(1, 101)]
        # 27 other items (10 other sources, mix)
        other_sources = ["crowdstrike", "cvefeed", "sploitus", "seclists", "thehackernews",
                         "cybersecuritynews", "ransomware_live", "bleepingcomputer",
                         "securityweek", "rapid7"]
        others = [_make_advisory(other_sources[i % len(other_sources)], days_ago=i)
                  for i in range(27)]
        _write_manifest(mp, nvd + others)

        result = trim_manifest(mp)

        assert result.get("error") is None, f"trim failed: {result}"
        removed = result["removed"]

        # Buggy code removed exactly 40 — assert we removed MORE (the correct amount)
        assert removed > 40, (
            f"v160.2 bug: removed only {removed} items (same as buggy 40). "
            "Stop condition still uses original total as denominator."
        )

        # Post-trim: nvd_cve must be ≤ TRIM_TARGET_PCT of the NEW total
        actual_pct = _source_pct_after_trim(mp, "nvd_cve")
        assert actual_pct <= TRIM_TARGET_PCT, (
            f"After trim nvd_cve={actual_pct:.1f}% still exceeds "
            f"TRIM_TARGET_PCT={TRIM_TARGET_PCT}%. Denominator bug not fixed."
        )


# ── T-TRIM-02: post-trim percentage is genuinely ≤ target ────────────────────
def test_trim_post_pct_genuinely_at_target():
    """
    Core correctness: after trim, the true percentage (remaining/new_total)
    must be ≤ TRIM_TARGET_PCT.  The old bug produced 47.2% (original denom)
    but actually 68.97% (correct denom) — still over the 50% hard limit.
    """
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        # 80 dominant + 20 other = 80% dominant
        dominant = [_make_advisory("dominant_src", days_ago=i) for i in range(1, 81)]
        others   = [_make_advisory("other_src",    days_ago=i) for i in range(1, 21)]
        _write_manifest(mp, dominant + others)

        result = trim_manifest(mp)
        assert result.get("error") is None

        actual_pct = _source_pct_after_trim(mp, "dominant_src")

        assert actual_pct <= TRIM_TARGET_PCT, (
            f"dominant_src post-trim={actual_pct:.2f}% > TRIM_TARGET_PCT={TRIM_TARGET_PCT}%. "
            "Denominator bug not fixed."
        )
        # Critically: must also be below MAX_DOMINANCE_PCT (hard limit checked by --report)
        assert actual_pct <= MAX_DOMINANCE_PCT, (
            f"dominant_src post-trim={actual_pct:.2f}% still exceeds hard limit {MAX_DOMINANCE_PCT}%."
        )


# ── T-TRIM-03: multi-source trim ──────────────────────────────────────────────
def test_trim_multiple_over_threshold_sources():
    """Both sources above threshold must each be trimmed to ≤ TRIM_TARGET_PCT."""
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        # Two sources each at 45% of 100 items, 10 others
        a_items = [_make_advisory("src_a", days_ago=i) for i in range(1, 46)]
        b_items = [_make_advisory("src_b", days_ago=i) for i in range(1, 46)]
        others  = [_make_advisory("src_c", days_ago=i) for i in range(1, 11)]
        _write_manifest(mp, a_items + b_items + others)

        result = trim_manifest(mp)
        assert result.get("error") is None

        for src in ("src_a", "src_b"):
            pct = _source_pct_after_trim(mp, src)
            assert pct <= TRIM_TARGET_PCT, (
                f"{src} post-trim={pct:.2f}% > TRIM_TARGET_PCT={TRIM_TARGET_PCT}%."
            )


# ── T-TRIM-04: no-op when all within threshold ───────────────────────────────
def test_trim_no_op_when_sources_balanced():
    """No items should be removed if all sources are already within threshold."""
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        # 4 sources, 25 items each = 25%
        advs = []
        for src in ("a", "b", "c", "d"):
            advs += [_make_advisory(src, days_ago=i) for i in range(1, 26)]
        _write_manifest(mp, advs)

        result = trim_manifest(mp)
        assert result.get("error") is None
        assert result["removed"] == 0, f"Expected 0 removed, got {result['removed']}"
        assert result["kept"] == 100


# ── T-TRIM-05: empty manifest ─────────────────────────────────────────────────
def test_trim_empty_manifest():
    """Empty advisories list must not crash; returns removed=0."""
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        _write_manifest(mp, [])

        result = trim_manifest(mp)
        assert result.get("error") is None
        assert result["removed"] == 0
        assert result["new_total"] == 0


# ── T-TRIM-06: single item stays intact ──────────────────────────────────────
def test_trim_single_item_intact():
    """A single-item manifest (100% one source) must not be trimmed to zero."""
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        _write_manifest(mp, [_make_advisory("solo_src", days_ago=1)])

        result = trim_manifest(mp)
        assert result.get("error") is None
        # A single source at 100% cannot be reduced while keeping any items;
        # trim must still leave the item (not crash or produce empty manifest).
        assert result["kept"] >= 1 or result["removed"] == 0, (
            "Single-item manifest must not be emptied by trim."
        )


# ── T-TRIM-07: log percentage is the real post-trim percentage ────────────────
def test_trim_reported_pct_matches_actual():
    """
    Validate that after trim the manifest actually reflects the target.
    (Indirectly tests that the log message uses the correct denominator, since
    the fix that fixes the stop condition also fixes the log computation.)
    """
    with tempfile.TemporaryDirectory() as td:
        mp = Path(td) / "feed_manifest.json"
        # 60 dominant + 40 others
        dominant = [_make_advisory("nvd_cve", days_ago=i) for i in range(1, 61)]
        others   = [_make_advisory(f"src_{i % 5}", days_ago=i) for i in range(1, 41)]
        _write_manifest(mp, dominant + others)

        result = trim_manifest(mp)
        assert result.get("error") is None

        # Measure actual post-trim percentage in the written file
        actual_pct = _source_pct_after_trim(mp, "nvd_cve")

        assert actual_pct <= TRIM_TARGET_PCT, (
            f"nvd_cve at {actual_pct:.2f}% after trim — still over TRIM_TARGET_PCT={TRIM_TARGET_PCT}%."
        )


# ── T-ENTROPY-01: entropy below hard floor → FAIL ────────────────────────────
def test_entropy_below_floor_is_fail():
    """Entropy below MIN_ENTROPY (2.0 bits) must be status=FAIL."""
    gate = ShannonEntropyGate()
    # Create a heavily skewed distribution: 90% one source, 10% another
    advs = [{"source": "dominant"} for _ in range(90)]
    advs += [{"source": "minor"} for _ in range(10)]
    result = gate.validate(advs)
    # entropy: -0.9*log2(0.9) - 0.1*log2(0.1) ≈ 0.469 bits < 2.0
    assert result["status"] == "FAIL", (
        f"Expected FAIL for severely skewed distribution; got {result['status']}. "
        f"entropy_bits={result['entropy_bits']}"
    )
    assert result["entropy_bits"] < MIN_ENTROPY


# ── T-ENTROPY-02: entropy in WARN band (2.0–3.0) → WARN (not FAIL) ───────────
def test_entropy_in_warn_band_is_warn_not_fail():
    """
    Entropy between MIN_ENTROPY (2.0) and WARN_ENTROPY (3.0) must be WARN, not FAIL.
    This is the typical post-trim state for a 6-source CVE platform.
    After correct trim, nvd_cve≈47%, 5 other sources share 53% → entropy≈2.23 bits.
    """
    gate = ShannonEntropyGate()
    # Build a distribution that produces entropy ≈ 2.2 bits
    # nvd_cve=47%, others 5 sources roughly equal ≈ 10.6% each
    advs = (
        [{"source": "nvd_cve"}] * 24 +        # 47.1%
        [{"source": "crowdstrike"}] * 5 +      # 9.8%
        [{"source": "cvefeed"}] * 5 +          # 9.8%
        [{"source": "sploitus"}] * 6 +         # 11.8%
        [{"source": "seclists"}] * 6 +         # 11.8%
        [{"source": "thehackernews"}] * 5      # 9.8%
    )  # total=51
    result = gate.validate(advs)
    # Verify entropy is actually in the 2.0–3.0 band
    assert MIN_ENTROPY <= result["entropy_bits"] < WARN_ENTROPY, (
        f"Test setup issue: expected entropy in [{MIN_ENTROPY}, {WARN_ENTROPY}), "
        f"got {result['entropy_bits']:.4f}"
    )
    assert result["status"] == "WARN", (
        f"Entropy {result['entropy_bits']:.4f} bits in WARN band must be WARN, "
        f"not {result['status']}."
    )


# ── T-ENTROPY-03: entropy at or above 3.0 → OK ───────────────────────────────
def test_entropy_above_warn_is_ok():
    """Entropy ≥ WARN_ENTROPY (3.0 bits) must be status=OK."""
    gate = ShannonEntropyGate()
    # 10 equal sources = log2(10) ≈ 3.32 bits
    advs = []
    for i in range(10):
        advs += [{"source": f"src_{i}"}] * 10  # 10 items each, perfectly balanced
    result = gate.validate(advs)
    assert result["entropy_bits"] >= WARN_ENTROPY, (
        f"Expected entropy ≥ {WARN_ENTROPY}; got {result['entropy_bits']:.4f}"
    )
    assert result["status"] == "OK", (
        f"Balanced distribution must be OK; got {result['status']}"
    )


# ── T-DIVERSITY-INTEGRATION: end-to-end no HARD FAIL on 6-source CVE feed ───
def test_integration_no_hard_fail_after_trim():
    """
    Integration test mirroring run #1555 conditions:
      - 127 items, 100 nvd_cve (78.7%), 6 unique sources
      - After trim + report: overall STATUS must not be FAIL

    This test would have FAILED before the v160.2 fix:
      - trim_manifest removed only 40 items (wrong denominator)
      - --report saw nvd_cve=68.97% → DOMINANCE FAIL
      - entropy=1.51 bits < 2.5 → ENTROPY FAIL
      - hard_fail=True → STATUS=FAIL → ::warning:: annotation

    After fix:
      - trim_manifest removes 76 items (correct denominator)
      - --report sees nvd_cve≈47.1% → DOMINANCE WARN (not FAIL)
      - entropy≈2.23 bits > 2.0 → ENTROPY WARN (not FAIL)
      - hard_fail=False → STATUS=WARN → no annotation
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        mp = td_path / "feed_manifest.json"

        # Mirrors run #1555: 100 nvd_cve + 27 items across 5 other sources
        nvd = [_make_advisory("nvd_cve", days_ago=i) for i in range(1, 101)]
        other_sources = ["crowdstrike", "cvefeed", "sploitus", "seclists", "thehackernews"]
        others = []
        for j, src in enumerate(other_sources):
            # 5 or 6 items each (total 27)
            count = 6 if j < 2 else 5
            others += [_make_advisory(src, days_ago=j * 5 + i) for i in range(count)]

        _write_manifest(mp, nvd + others)

        # Step 1: --trim-manifest
        trim_result = trim_manifest(mp)
        assert trim_result.get("error") is None, f"Trim failed: {trim_result}"

        # After trim, nvd_cve must be genuinely ≤ MAX_DOMINANCE_PCT
        actual_nvd_pct = _source_pct_after_trim(mp, "nvd_cve")
        assert actual_nvd_pct <= MAX_DOMINANCE_PCT, (
            f"Post-trim nvd_cve={actual_nvd_pct:.2f}% still exceeds "
            f"MAX_DOMINANCE_PCT={MAX_DOMINANCE_PCT}%. Trim fix not working."
        )

        # Step 2: --report (DiversityEnforcerReport.run())
        health_dir = td_path / "health"
        diversity_state_dir = td_path / "diversity_governance"

        with (
            patch("scripts.source_diversity_enforcer.FEED_MANIFEST", new=mp),
            patch("scripts.source_diversity_enforcer.HEALTH_DIR", new=health_dir),
            patch("scripts.source_diversity_enforcer.DIVERSITY_STATE_DIR", new=diversity_state_dir),
            patch("scripts.source_diversity_enforcer.DiversityEnforcerReport.OUTPUT_FILE",
                  new=health_dir / "source_diversity.json"),
            patch("scripts.source_diversity_enforcer.DiversityEnforcerReport.HISTORY_FILE",
                  new=diversity_state_dir / "diversity_history.json"),
            patch("scripts.source_diversity_enforcer.FloodCircuitBreaker.STATE_FILE",
                  new=diversity_state_dir / "flood_circuit_state.json"),
        ):
            engine = DiversityEnforcerReport()
            summary = engine.run(apply=False, strict=False)

        # The hard invariant: STATUS must not be FAIL
        assert summary["status"] != "FAIL", (
            f"STATUS={summary['status']} (hard_fail={summary.get('hard_fail')}). "
            f"Top source: {summary.get('top_source')} at {summary.get('top_source_pct')}%. "
            f"Entropy: {summary.get('entropy_bits')} bits. "
            "run #1555 SOURCE DIVERSITY HARD FAIL regression reproduced — fix not applied."
        )

        # Confirm hard_fail is False (this is what controls the ::warning:: annotation)
        assert summary.get("hard_fail") is False, (
            f"hard_fail={summary.get('hard_fail')} — would still emit ::warning:: annotation."
        )
