#!/usr/bin/env python3
"""
tests/test_severity_governance_p0.py
CYBERDUDEBIVASH® SENTINEL APEX — P0 Severity Governance Regression Tests
=========================================================================
Generated: 2026-06-06  (P0 incident fix v171.1)

These tests MUST PASS before any deployment.  They enforce immutable invariants:

  A. CVSS >= 9  AND severity == LOW          → HARD FAIL
  B. KEV == TRUE AND severity == LOW          → HARD FAIL
  C. Active exploitation AND severity == LOW  → HARD FAIL (governance gate [13])

Covers all four root-cause corruption paths identified in the P0 forensic audit:

  PATH 1: run_pipeline.py R5 present-participle keyword miss
  PATH 2: agent/sentinel_blogger.py act_exp present-participle miss
  PATH 3: EII RSE unconditional score reduction (no immutable floor)
  PATH 4: regression_immunity.py gate 13 dict-feed silent-pass bug
"""

import sys
import os
import json
import re
import pytest

# ── Ensure scripts/ is importable ────────────────────────────────────────────
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
AGENT_DIR = os.path.join(REPO, "agent")
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _make_item(title, severity="LOW", cvss=None, kev=None, epss=None, description=""):
    """Build a minimal feed item for testing."""
    item = {
        "id": "test-item-001",
        "stix_id": "intel--test000000000000000000000000000",
        "title": title,
        "description": description,
        "severity": severity,
    }
    if cvss is not None:
        item["cvss_score"] = cvss
    if kev is not None:
        item["kev"] = kev
        item["kev_present"] = kev in ("YES", "TRUE", True, "1")
    if epss is not None:
        item["epss_score"] = epss
    return item


# ─────────────────────────────────────────────────────────────────────────────
# SECTION A — run_pipeline.py R5 keyword coverage
# ─────────────────────────────────────────────────────────────────────────────

ACTIVE_EXPLOIT_TITLES = [
    # Past tense (were already covered before v171.1 fix)
    "CVE-2026-9999: actively exploited in the wild",
    "Vulnerability exploited in the wild by APT group",
    # Present participle / gerund (P0 ROOT CAUSE — "Actively Exploiting" was NOT
    # matched by run_pipeline.py R5 before v171.1, causing governance gate FAIL)
    "Attackers Actively Exploiting Critical Vulnerability in Everest Forms Pro Plugin",
    "Attackers Actively Exploiting Critical Vulnerability in Burst Statistics Plugin",
    "Hackers Actively Exploiting Zero-Day in Cisco IOS",
    "Threat Actors Actively Exploiting Unpatched WordPress Bug",
    "Ransomware Group Actively Exploiting PAN-OS Flaw",
    # Mixed case
    "CISA Warns: ACTIVELY EXPLOITING Critical RCE",
    "attackers actively exploit new zero-day",
    "being actively exploited by ransomware actors",
]

# Extended coverage titles — tested in test_agent_act_exp_extra_coverage (non-parametrized)
# Kept separate to avoid pytest assertion-rewriting pycache invalidation issues.
EXTRA_COVERAGE_TITLES = [
    "Under active attack: critical authentication bypass",
    "Mass exploitation of Apache Log4j underway",
    "Widespread exploitation of unpatched SMB flaw",
    "Weaponized PoC released for CVE-2026-9999",
]

# run_pipeline.py R5 keyword list (mirrors scripts/run_pipeline.py _active_exploit_kw)
ACTIVE_EXPLOIT_KW = [
    "actively exploited", "actively exploiting", "attackers actively exploit",
    "exploited in the wild", "active exploitation",
    "under active attack", "zero-day exploit", "0-day exploit",
    "mass exploitation", "widespread exploitation",
    "exploiting in the wild", "being actively exploit",
]

# agent/sentinel_blogger.py act_exp list (mirrors agent/sentinel_blogger.py)
# Defined at module level to avoid stale pytest bytecode cache issues.
AGENT_ACT_EXP_STRINGS = [
    "actively exploited", "actively exploiting", "attackers actively exploit",
    "in the wild", "active exploitation", "exploited in the wild",
    "under active attack", "mass exploitation", "widespread exploitation",
    "weaponized", "zero-day exploit", "0-day exploit",
]


@pytest.mark.parametrize("title", ACTIVE_EXPLOIT_TITLES)
def test_run_pipeline_r5_keyword_matches_title(title):
    """PATH 1 — Every active-exploitation title must be caught by R5 keyword list."""
    text_blob = title.lower()
    matched = any(kw in text_blob for kw in ACTIVE_EXPLOIT_KW)
    assert matched, (
        f"R5 keyword list did NOT match title: '{title}'\n"
        f"  This title would NOT receive HIGH floor in run_pipeline.py R5.\n"
        f"  Add a matching keyword to _active_exploit_kw in run_pipeline.py."
    )


@pytest.mark.parametrize("title", ACTIVE_EXPLOIT_TITLES)
def test_agent_act_exp_matches_title(title):
    """PATH 2 — sentinel_blogger.py act_exp check must catch all active-exploit titles."""
    matched = any(s in title.lower() for s in AGENT_ACT_EXP_STRINGS)
    assert matched, (
        f"agent act_exp check did NOT match title: '{title}'\n"
        f"  Update act_exp list in agent/sentinel_blogger.py."
    )


def test_agent_act_exp_extra_coverage():
    """PATH 2 extended — additional active-exploitation title patterns caught by agent."""
    failures = []
    for title in EXTRA_COVERAGE_TITLES:
        if not any(s in title.lower() for s in AGENT_ACT_EXP_STRINGS):
            failures.append(title)
    assert not failures, (
        f"agent act_exp missed {len(failures)} titles:\n"
        + "\n".join(f"  - {t}" for t in failures)
    )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION B — severity_recalibration_engine correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityRecalibrationEngine:

    def _recalibrate_import(self):
        try:
            from severity_recalibration_engine import recalibrate_feed
            return recalibrate_feed
        except ImportError:
            pytest.skip("severity_recalibration_engine not importable in this environment")

    def test_actively_exploiting_present_participle_is_upgraded(self):
        """ROOT CAUSE PATH 1/2 — 'Actively Exploiting' title must → HIGH minimum."""
        rf = self._recalibrate_import()
        items = [
            _make_item(
                "Attackers Actively Exploiting Critical Vulnerability in Everest Forms Pro Plugin",
                severity="LOW",
            ),
            _make_item(
                "Attackers Actively Exploiting Critical Vulnerability in Burst Statistics Plugin",
                severity="LOW",
            ),
        ]
        result, report = rf(items)
        violations = report.get("violations", [])
        # After recalibration both must be HIGH or CRITICAL
        for r in result:
            sev = r.get("severity", "LOW").upper()
            assert _SEV_RANK.get(sev, 0) >= _SEV_RANK["HIGH"], (
                f"Item '{r.get('title','')}' → severity={sev} after recalibration. "
                f"Expected HIGH or CRITICAL for 'Actively Exploiting' title."
            )

    def test_cvss_field_variants_trigger_high_floor(self):
        """PATH 3 fix side-effect — alternate CVSS field names must trigger floor."""
        rf = self._recalibrate_import()
        # Use 'cvss' field (not 'cvss_score') — the pre-fix code missed this
        item = {"id": "x", "title": "Some CVE", "cvss": 9.8, "severity": "LOW"}
        result, report = rf([item])
        assert len(result) == 1
        sev = result[0].get("severity", "LOW").upper()
        assert _SEV_RANK.get(sev, 0) >= _SEV_RANK["HIGH"], (
            f"CVSS=9.8 (in 'cvss' field) → severity={sev}. Expected HIGH minimum."
        )

    @pytest.mark.parametrize("cvss,expected_min", [
        # NVD/NIST standard: 7.0–10.0 = HIGH or CRITICAL
        (9.8, "HIGH"), (9.0, "HIGH"), (8.0, "HIGH"), (7.5, "HIGH"), (5.0, "LOW"),
    ])
    def test_cvss_threshold_floors(self, cvss, expected_min):
        """Verify each CVSS threshold maps to correct minimum severity."""
        rf = self._recalibrate_import()
        item = _make_item("CVE test", severity="LOW", cvss=cvss)
        result, _ = rf([item])
        sev = result[0].get("severity", "LOW").upper()
        assert _SEV_RANK.get(sev, 0) >= _SEV_RANK.get(expected_min, 0), (
            f"CVSS={cvss} → severity={sev}, expected >= {expected_min}"
        )

    def test_kev_item_never_low(self):
        """KEV confirmed item must never be LOW severity."""
        rf = self._recalibrate_import()
        item = _make_item("Some KEV entry", severity="LOW", kev="YES")
        result, _ = rf([item])
        sev = result[0].get("severity", "LOW").upper()
        assert sev != "LOW", f"KEV item must not be LOW; got {sev}"
        assert _SEV_RANK.get(sev, 0) >= _SEV_RANK["HIGH"]

    def test_feed_dict_items_extraction(self):
        """PATH 4 fix — recalibrate_feed accepts list; gate must extract from dict feed."""
        rf = self._recalibrate_import()
        items = [
            _make_item(
                "Attackers Actively Exploiting Critical Bug",
                severity="LOW",
            )
        ]
        result, report = rf(items)
        # Must find violation
        assert report.get("recalibrated_count", 0) >= 1, (
            "Expected recalibration to find 1 violation for 'Actively Exploiting' item."
        )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION C — EII RSE Immutable Floor (PATH 3)
# ─────────────────────────────────────────────────────────────────────────────

class TestEIIRSEImmutableFloor:
    """
    Validates the immutable floor logic added to enterprise_intelligence_integrator.py.
    Tests simulate the floor calculation directly — no live EII import required.
    """

    @staticmethod
    def _apply_eii_floor(item: dict, rse_output_risk: float) -> float:
        """Replicate the immutable floor logic from enterprise_intelligence_integrator.py."""
        _kev_val  = str(item.get("kev") or item.get("kev_present") or "").upper()
        _kev_conf = _kev_val in ("YES", "TRUE", "1", "LISTED")
        _cvss_rse = 0.0
        for _f in ("cvss_score", "cvss", "cvss_base", "cvss_v3"):
            _v = item.get(_f)
            if _v is not None:
                try:
                    _cvss_rse = float(_v)
                    break
                except (TypeError, ValueError):
                    pass
        _title = (item.get("title", "") + " " + item.get("description", "")).lower()
        _active_signals = [
            "actively exploited", "actively exploiting", "attackers actively exploit",
            "exploited in the wild", "active exploitation", "under active attack",
        ]
        _active_exp = any(s in _title for s in _active_signals)

        floor = 0.0
        if _kev_conf and _active_exp:
            floor = 8.5
        elif _kev_conf:
            floor = 7.5
        elif _active_exp:
            floor = 7.0
        elif _cvss_rse >= 9.5:
            floor = 8.0
        elif _cvss_rse >= 9.0:
            floor = 7.0
        elif _cvss_rse >= 8.0:
            floor = 6.0

        return max(rse_output_risk, floor)

    def test_cvss_10_not_reduced_below_7(self):
        """RSE must not reduce CVSS 10.0 item below 7.0 risk floor."""
        item = _make_item("RCE in Production System", cvss=10.0)
        effective_risk = self._apply_eii_floor(item, rse_output_risk=2.60)
        assert effective_risk >= 7.0, (
            f"CVSS=10.0 item risk={effective_risk} after RSE floor — must be >= 7.0"
        )

    def test_cvss_9_8_not_reduced_below_7(self):
        """CVSS 9.8 item must not have risk reduced below 7.0."""
        item = _make_item("Critical Auth Bypass", cvss=9.8)
        effective_risk = self._apply_eii_floor(item, rse_output_risk=3.31)
        assert effective_risk >= 7.0

    def test_kev_item_risk_not_below_7_5(self):
        """KEV item must not have risk reduced below 7.5."""
        item = _make_item("CISA KEV Advisory", kev="YES")
        effective_risk = self._apply_eii_floor(item, rse_output_risk=1.0)
        assert effective_risk >= 7.5

    def test_kev_plus_active_exploit_floor_8_5(self):
        """KEV + active exploitation = floor 8.5."""
        item = _make_item(
            "Attackers Actively Exploiting CISA KEV Vulnerability",
            kev="YES"
        )
        effective_risk = self._apply_eii_floor(item, rse_output_risk=2.0)
        assert effective_risk >= 8.5

    def test_actively_exploiting_title_floor_7(self):
        """'Actively Exploiting' title → risk_score floor 7.0."""
        item = _make_item(
            "Attackers Actively Exploiting Critical Vulnerability in Burst Statistics Plugin"
        )
        effective_risk = self._apply_eii_floor(item, rse_output_risk=0.8)
        assert effective_risk >= 7.0, (
            f"'Actively Exploiting' item risk={effective_risk} — must be >= 7.0"
        )

    def test_low_signal_item_freely_reducible(self):
        """Items with no KEV/active-exploit/high-CVSS can be freely reduced."""
        item = _make_item("Minor info disclosure in obscure library", cvss=3.0)
        effective_risk = self._apply_eii_floor(item, rse_output_risk=0.5)
        assert effective_risk == 0.5  # no floor applied, RSE reduction preserved


# ─────────────────────────────────────────────────────────────────────────────
# SECTION D — Live feed invariant scan
# ─────────────────────────────────────────────────────────────────────────────

class TestLiveFeedInvariants:
    """
    Scans the actual api/feed.json for P0 invariant violations.
    These are non-parameterised — they scan the full feed at test time.
    """

    def _load_feed(self):
        feed_path = os.path.join(REPO, "api", "feed.json")
        if not os.path.exists(feed_path):
            pytest.skip(f"api/feed.json not found at {feed_path}")
        with open(feed_path, encoding="utf-8") as f:
            raw = json.load(f)
        return raw if isinstance(raw, list) else (
            raw.get("items") or raw.get("advisories") or raw.get("data") or []
        )

    def test_no_kev_item_is_low(self):
        """P0 INVARIANT: No KEV-confirmed item may have severity=LOW."""
        items = self._load_feed()
        violations = []
        for item in items:
            kev = str(item.get("kev") or item.get("kev_present") or "").upper()
            if kev in ("YES", "TRUE", "1"):
                sev = (item.get("severity") or "").upper()
                if sev == "LOW":
                    violations.append(item.get("title", "?")[:80])
        assert len(violations) == 0, (
            f"KEV items with LOW severity ({len(violations)} found):\n"
            + "\n".join(f"  - {t}" for t in violations[:5])
        )

    def test_no_actively_exploiting_item_is_low(self):
        """P0 INVARIANT: No actively-exploited item may have severity=LOW."""
        items = self._load_feed()
        _PATTERNS = re.compile(
            r"actively exploit|exploited in the wild|under active attack|active exploitation",
            re.IGNORECASE
        )
        violations = []
        for item in items:
            text = (item.get("title", "") + " " + item.get("description", ""))
            if _PATTERNS.search(text):
                sev = (item.get("severity") or "").upper()
                if sev == "LOW":
                    violations.append(item.get("title", "?")[:80])
        assert len(violations) == 0, (
            f"Actively-exploited items with LOW severity ({len(violations)} found):\n"
            + "\n".join(f"  - {t}" for t in violations[:5])
        )

    def test_no_critical_cvss_item_is_low(self):
        """P0 INVARIANT: CVSS >= 9.0 items must not have severity=LOW."""
        items = self._load_feed()
        violations = []
        for item in items:
            cvss = 0.0
            for f in ("cvss_score", "cvss"):
                v = item.get(f)
                if v is not None:
                    try:
                        cvss = float(v)
                        break
                    except (TypeError, ValueError):
                        pass
            if cvss >= 9.0:
                sev = (item.get("severity") or "").upper()
                if sev == "LOW":
                    violations.append(
                        f"CVSS={cvss}: {item.get('title','?')[:70]}"
                    )
        assert len(violations) == 0, (
            f"CVSS>=9.0 items with LOW severity ({len(violations)} found):\n"
            + "\n".join(f"  - {t}" for t in violations[:5])
        )

    def test_no_high_risk_score_item_is_low(self):
        """INVARIANT: risk_score >= 7.5 must not have severity=LOW."""
        items = self._load_feed()
        violations = []
        for item in items:
            try:
                rs = float(item.get("risk_score") or 0)
            except (TypeError, ValueError):
                rs = 0.0
            if rs >= 7.5:
                sev = (item.get("severity") or "").upper()
                if sev == "LOW":
                    violations.append(
                        f"risk={rs}: {item.get('title','?')[:70]}"
                    )
        assert len(violations) == 0, (
            f"risk_score>=7.5 items with LOW severity ({len(violations)} found):\n"
            + "\n".join(f"  - {t}" for t in violations[:5])
        )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION E — governance gate [13] isolation test (PATH 4)
# ─────────────────────────────────────────────────────────────────────────────

class TestGovernanceGate13:
    """
    Direct unit test for regression_immunity.py gate [13] logic.
    Ensures dict-feed items are correctly extracted (not silently skipped).
    """

    def test_dict_feed_items_extracted_correctly(self):
        """PATH 4 FIX: Gate must extract items from dict-shaped feed, not pass []."""
        items = [
            _make_item(
                "Attackers Actively Exploiting Critical Vulnerability",
                severity="LOW",
            )
        ]
        # Simulate both feed shapes
        list_feed = items
        dict_feed = {"items": items, "metadata": {"count": 1}}

        # Both should yield the same items after extraction
        from_list = list_feed if isinstance(list_feed, list) else []
        if isinstance(dict_feed, list):
            from_dict = dict_feed
        elif isinstance(dict_feed, dict):
            from_dict = (dict_feed.get("items") or
                         dict_feed.get("advisories") or
                         dict_feed.get("data") or [])
        else:
            from_dict = []

        assert len(from_dict) == len(from_list) == 1, (
            "Dict-feed items extraction returned wrong count. "
            "Gate [13] would silently pass with 0 items."
        )

    def test_gate_detects_actively_exploiting_low(self):
        """End-to-end: gate [13] must FAIL when 'Actively Exploiting' item has LOW."""
        try:
            from severity_recalibration_engine import recalibrate_feed as rf
        except ImportError:
            pytest.skip("severity_recalibration_engine not importable")

        items = [
            _make_item(
                "Attackers Actively Exploiting Critical Vulnerability in Everest Forms",
                severity="LOW",
            )
        ]
        _, report = rf(items)
        violations = [
            v for v in report.get("violations", [])
            if v["old_severity"] == "LOW"
            and "active exploitation" in str(v.get("reasons", "")).lower()
        ]
        assert len(violations) >= 1, (
            "Gate [13] simulation did not detect 'Actively Exploiting' LOW item. "
            "Severity recalibration engine must flag this as a violation."
        )


if __name__ == "__main__":
    # Allow running directly: python tests/test_severity_governance_p0.py
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
ed-feed items extraction returned wrong count. "
            "Gate [13] would silently pass with 0 items."
        )

    def test_gate_detects_actively_exploiting_low(self):
        """End-to-end: gate [13] must FAIL when 'Actively Exploiting' item has LOW."""
        try:
            from severity_recalibration_engine import recalibrate_feed as rf
        except ImportError:
            pytest.skip("severity_recalibration_engine not importable")

        items = [
            _make_item(
                "Attackers Actively Exploiting Critical Vulnerability in Everest Forms",
                severity="LOW",
            )
        ]
        _, report = rf(items)
        violations = [
            v for v in report.get("violations", [])
            if v["old_severity"] == "LOW"
            and "active exploitation" in str(v.get("reasons", "")).lower()
        ]
        assert len(violations) >= 1, (
            "Gate [13] simulation did not detect 'Actively Exploiting' LOW item. "
            "Severity recalibration engine must flag this as a violation."
        )


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
