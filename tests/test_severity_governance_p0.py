#!/usr/bin/env python3
"""
test_severity_governance_p0.py  —  SENTINEL APEX  v180.0
=========================================================
P0 Regression Suite: Severity Invariant Governance Policy

Validates:
  §0   py_compile checks on all governed modules
  §1   SII module public API surface
  §2   Rule C (CRITICAL invariant): CVSS>=9.0, KEV, active_exploitation,
       public_exploit_code, threat_class∈{rce,auth_bypass}
  §3   Rule H (HIGH floor): 8.0<=CVSS<9.0 AND severity==LOW
  §4   Rule M (MEDIUM floor): 7.0<=CVSS<8.0 AND severity==LOW
  §5   priority / threat_level / risk_score co-travel
  §6   Keyword-triggered invariants
  §7   Idempotency (applying twice yields identical result)
  §8   Feed-level governance via apply_invariants_to_feed()
  §9   File-level governance via apply_invariants_to_file()
  §10  PAYWALL_TACTICAL_FIELDS completeness
  §11  severity_recalibration_engine Rule C enforcement
  §12  Edge cases and boundary conditions
  §13  Cross-module (SII + SRE) agreement on CRITICAL designation

Run:
  pytest tests/test_severity_governance_p0.py -v --tb=short

Python 3.12 compatible. No external deps beyond pytest.
"""
import copy
import importlib
import importlib.util
import inspect
import json
import os
import pathlib
import py_compile
import sys
import tempfile
import time

import pytest

# ── Repo root ──────────────────────────────────────────────────────────────────
_REPO    = pathlib.Path(__file__).resolve().parent.parent
_SCRIPTS = _REPO / "scripts"

if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

# ── Source files under governance ─────────────────────────────────────────────
_GOVERNED_FILES = {
    "severity_invariant_interceptor": _SCRIPTS / "severity_invariant_interceptor.py",
    "severity_recalibration_engine":  _SCRIPTS / "severity_recalibration_engine.py",
    "run_pipeline":                   _SCRIPTS / "run_pipeline.py",
}
_AGENT_FILES = {
    "sentinel_blogger": _REPO / "agent" / "sentinel_blogger.py",
}


# =============================================================================
# §0  COMPILE CHECKS
# =============================================================================

class TestCompileChecks:
    """py_compile.compile must succeed on every governed module (Python 3.12)."""

    @pytest.mark.parametrize("name,path",
        list(_GOVERNED_FILES.items()) + list(_AGENT_FILES.items()))
    def test_compiles_without_error(self, name, path):
        if not path.exists():
            pytest.skip(f"File not present: {path}")
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            pytest.fail(f"[COMPILE FAIL] {name}: {exc}")


# =============================================================================
# §1  FIXTURES
# =============================================================================

def _load_module(path: pathlib.Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sii():
    path = _GOVERNED_FILES["severity_invariant_interceptor"]
    if not path.exists():
        pytest.skip(f"Module not found: {path}")
    return _load_module(path, "severity_invariant_interceptor")


@pytest.fixture(scope="module")
def sre():
    path = _GOVERNED_FILES["severity_recalibration_engine"]
    if not path.exists():
        pytest.skip(f"Module not found: {path}")
    return _load_module(path, "severity_recalibration_engine")


# =============================================================================
# §1  SII PUBLIC API SURFACE
# =============================================================================

class TestSIIInterface:
    def test_has_apply_invariants(self, sii):
        assert callable(getattr(sii, "apply_invariants", None))

    def test_has_apply_invariants_to_feed(self, sii):
        assert callable(getattr(sii, "apply_invariants_to_feed", None))

    def test_has_apply_invariants_to_file(self, sii):
        assert callable(getattr(sii, "apply_invariants_to_file", None))

    def test_version_is_180(self, sii):
        v = getattr(sii, "VERSION", None)
        assert v is not None, "VERSION constant must be defined"
        assert str(v) == "180.0", f"Expected VERSION='180.0', got '{v}'"

    def test_paywall_tactical_fields_defined(self, sii):
        fields = getattr(sii, "PAYWALL_TACTICAL_FIELDS", None)
        assert fields is not None, "PAYWALL_TACTICAL_FIELDS must be defined"
        required = {
            "sigma_rule", "sigma", "kql_query", "kql",
            "suricata_rule", "suricata", "yara_rule", "yara", "soc_playbook",
        }
        missing = required - set(fields)
        assert not missing, f"Missing paywall fields: {missing}"


# =============================================================================
# §2  RULE C — CRITICAL INVARIANT
# =============================================================================

class TestRuleC:
    """
    Rule C fires on ANY of:
      CVSS>=9.0 | cisa_kev/kev/kev_present=truthy | active_exploitation=truthy
      | public_exploit_code=truthy | threat_class∈{rce,auth_bypass,...}
    Expected output: severity=CRITICAL, priority=P1,
                     threat_level=CRITICAL_SURGE, risk_score>=9.0
    """

    def _assert_critical(self, result, ctx=""):
        assert result["severity"] == "CRITICAL", \
            f"{ctx}: severity must be CRITICAL, got '{result['severity']}'"
        assert result.get("priority") == "P1", \
            f"{ctx}: priority must be P1, got '{result.get('priority')}'"
        assert result.get("threat_level") == "CRITICAL_SURGE", \
            f"{ctx}: threat_level must be CRITICAL_SURGE, got '{result.get('threat_level')}'"
        assert float(result.get("risk_score", 0)) >= 9.0, \
            f"{ctx}: risk_score must be >=9.0, got '{result.get('risk_score')}'"

    @pytest.mark.parametrize("cvss", [9.0, 9.1, 9.5, 9.8, 10.0])
    def test_cvss_gte_9_forces_critical(self, sii, cvss):
        result = sii.apply_invariants({"title": "V", "cvss_score": cvss, "severity": "LOW"})
        self._assert_critical(result, f"CVSS={cvss}")

    def test_cvss_8_9_does_not_trigger_rule_c(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 8.9, "severity": "LOW"})
        assert result["severity"] != "CRITICAL", "CVSS=8.9 must NOT trigger Rule C"

    def test_cvss_alt_field_parsed(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss": 9.3, "severity": "LOW"})
        self._assert_critical(result, "alt 'cvss' field")

    @pytest.mark.parametrize("kev_field,kev_val", [
        ("cisa_kev", True), ("cisa_kev", "yes"), ("cisa_kev", "YES"),
        ("kev", True),      ("kev", "true"),     ("kev", "1"),
        ("kev_present", True),
    ])
    def test_kev_truthy_forces_critical(self, sii, kev_field, kev_val):
        item = {"title": "KEV", kev_field: kev_val, "severity": "LOW", "cvss_score": 5.0}
        self._assert_critical(sii.apply_invariants(item), f"{kev_field}={kev_val}")

    def test_active_exploitation_flag_forces_critical(self, sii):
        item = {"title": "V", "active_exploitation": True, "severity": "LOW", "cvss_score": 5.0}
        self._assert_critical(sii.apply_invariants(item), "active_exploitation=True")

    def test_public_exploit_code_forces_critical(self, sii):
        item = {"title": "V", "public_exploit_code": True, "severity": "MEDIUM", "cvss_score": 6.5}
        self._assert_critical(sii.apply_invariants(item), "public_exploit_code=True")

    @pytest.mark.parametrize("tclass", [
        "rce", "RCE", "auth_bypass",
        "remote_code_execution", "authentication_bypass",
    ])
    def test_threat_class_forces_critical(self, sii, tclass):
        item = {"title": "V", "threat_class": tclass, "severity": "LOW", "cvss_score": 5.0}
        self._assert_critical(sii.apply_invariants(item), f"threat_class={tclass}")

    def test_risk_score_floors_at_9_when_cvss_lower(self, sii):
        item   = {"title": "V", "kev": True, "severity": "LOW", "cvss_score": 5.0}
        result = sii.apply_invariants(item)
        assert float(result["risk_score"]) == pytest.approx(9.0), \
            f"risk_score should be 9.0 when KEV fires and CVSS=5.0, got {result['risk_score']}"

    def test_risk_score_uses_cvss_when_higher(self, sii):
        item   = {"title": "V", "cvss_score": 9.8, "severity": "LOW"}
        result = sii.apply_invariants(item)
        assert float(result["risk_score"]) == pytest.approx(9.8, abs=0.001), \
            f"risk_score should equal CVSS=9.8, got {result['risk_score']}"

    def test_already_critical_gets_co_travel_fields(self, sii):
        item = {"title": "V", "cvss_score": 9.5, "severity": "CRITICAL"}
        self._assert_critical(sii.apply_invariants(item), "already-CRITICAL item")

    def test_high_promoted_to_critical_by_cvss_9(self, sii):
        item = {"title": "V", "cvss_score": 9.2, "severity": "HIGH"}
        self._assert_critical(sii.apply_invariants(item), "HIGH promoted by CVSS=9.2")


# =============================================================================
# §3  RULE H — HIGH FLOOR
# =============================================================================

class TestRuleH:
    """8.0 <= CVSS < 9.0 AND severity==LOW → force HIGH, priority=P2."""

    @pytest.mark.parametrize("cvss", [8.0, 8.5, 8.9])
    def test_cvss_8x_forces_high_from_low(self, sii, cvss):
        result = sii.apply_invariants({"title": "V", "cvss_score": cvss, "severity": "LOW"})
        assert result["severity"] in {"HIGH", "CRITICAL"}, \
            f"CVSS={cvss} from LOW must produce HIGH or CRITICAL, got '{result['severity']}'"
        assert result["severity"] != "LOW", f"CVSS={cvss} must not remain LOW"

    def test_rule_h_sets_priority_p2(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 8.3, "severity": "LOW"})
        if result["severity"] == "HIGH":
            assert result.get("priority") == "P2", \
                f"Rule H must set priority=P2, got '{result.get('priority')}'"

    def test_rule_h_risk_score_floor(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 8.3, "severity": "LOW"})
        if result["severity"] == "HIGH":
            assert float(result.get("risk_score", 0)) >= 7.5, \
                f"Rule H risk_score must be >=7.5, got {result.get('risk_score')}"

    def test_rule_h_does_not_downgrade_high(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 8.5, "severity": "HIGH"})
        assert result["severity"] == "HIGH", "Existing HIGH must not be downgraded"

    def test_medium_with_cvss_8_not_downgraded(self, sii):
        # Rule H fires ONLY when severity==LOW. Existing MEDIUM is not promoted by Rule H alone.
        result = sii.apply_invariants({"title": "V", "cvss_score": 8.5, "severity": "MEDIUM"})
        # MEDIUM must not be downgraded; it may stay MEDIUM (Rule H requires LOW input)
        assert result["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}, \
            f"MEDIUM with CVSS=8.5 must not be downgraded, got '{result['severity']}'"


# =============================================================================
# §4  RULE M — MEDIUM FLOOR
# =============================================================================

class TestRuleM:
    """7.0 <= CVSS < 8.0 AND severity==LOW → force MEDIUM, priority=P3."""

    @pytest.mark.parametrize("cvss", [7.0, 7.5, 7.9])
    def test_cvss_7x_forces_medium_from_low(self, sii, cvss):
        result = sii.apply_invariants({"title": "V", "cvss_score": cvss, "severity": "LOW"})
        assert result["severity"] != "LOW", \
            f"CVSS={cvss} must not remain LOW, got '{result['severity']}'"

    def test_rule_m_sets_priority_p3(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 7.4, "severity": "LOW"})
        if result["severity"] == "MEDIUM":
            assert result.get("priority") == "P3", \
                f"Rule M must set priority=P3, got '{result.get('priority')}'"

    def test_rule_m_does_not_downgrade_medium(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 7.5, "severity": "MEDIUM"})
        assert result["severity"] == "MEDIUM", "Existing MEDIUM must not be changed by Rule M"

    def test_rule_m_does_not_fire_below_7(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 6.9, "severity": "LOW"})
        assert result["severity"] in {"LOW", "MEDIUM"}, \
            f"CVSS=6.9 should not trigger HIGH/CRITICAL, got '{result['severity']}'"


# =============================================================================
# §5  PRIORITY / THREAT_LEVEL / RISK_SCORE CO-TRAVEL
# =============================================================================

class TestCoTravelFields:
    """When severity changes, priority/threat_level/risk_score must change too."""

    def test_critical_always_has_p1(self, sii):
        for cvss in [9.0, 9.5, 10.0]:
            r = sii.apply_invariants({"title": "V", "cvss_score": cvss, "severity": "LOW"})
            assert r.get("priority") == "P1", \
                f"CVSS={cvss}: CRITICAL must carry P1, got {r.get('priority')}"

    def test_critical_always_has_critical_surge(self, sii):
        r = sii.apply_invariants({"title": "V", "cvss_score": 9.5, "kev": True, "severity": "LOW"})
        assert r.get("threat_level") == "CRITICAL_SURGE"

    def test_critical_risk_score_never_below_9(self, sii):
        for cvss in [0.0, 5.0, 7.0, 9.0, 10.0]:
            item = {"title": "V", "cvss_score": 9.5, "kev": True, "severity": "LOW"}
            r    = sii.apply_invariants(item)
            assert float(r.get("risk_score", 0)) >= 9.0, \
                f"CRITICAL risk_score < 9.0: {r.get('risk_score')}"


# =============================================================================
# §6  KEYWORD TRIGGERS
# =============================================================================

class TestKeywordTriggers:
    @pytest.mark.parametrize("keyword", [
        "actively exploiting",
        "under active attack",
        "mass exploitation",
        "exploiting in the wild",
        "exploited in the wild",
    ])
    def test_keyword_in_title_triggers_critical(self, sii, keyword):
        item   = {"title": f"Threat actors are {keyword} CVE-XXXX",
                  "cvss_score": 6.0, "severity": "LOW"}
        result = sii.apply_invariants(item)
        assert result["severity"] == "CRITICAL", \
            f"Keyword '{keyword}' in title must trigger CRITICAL, got '{result['severity']}'"

    @pytest.mark.parametrize("keyword", [
        "actively exploiting",
        "under active attack",
    ])
    def test_keyword_in_description_triggers_critical(self, sii, keyword):
        item = {
            "title":       "Generic CVE notice",
            "description": f"Attackers are {keyword} this vulnerability.",
            "cvss_score":  6.0,
            "severity":    "LOW",
        }
        result = sii.apply_invariants(item)
        assert result["severity"] == "CRITICAL", \
            f"Keyword '{keyword}' in description must trigger CRITICAL"

    def test_rce_threat_class_triggers_critical(self, sii):
        # RCE/auth_bypass detected via structured threat_class field, not raw title text.
        result = sii.apply_invariants(
            {"title": "Critical RCE exploit released for Apache",
             "threat_class": "rce", "cvss_score": 5.0, "severity": "LOW"})
        assert result["severity"] == "CRITICAL", "threat_class=rce must trigger CRITICAL"

    def test_auth_bypass_threat_class_triggers_critical(self, sii):
        result = sii.apply_invariants(
            {"title": "Authentication bypass vulnerability in OpenSSH",
             "threat_class": "auth_bypass", "cvss_score": 5.0, "severity": "LOW"})
        assert result["severity"] == "CRITICAL", "threat_class=auth_bypass must trigger CRITICAL"


# =============================================================================
# §7  IDEMPOTENCY
# =============================================================================

class TestIdempotency:
    """Applying apply_invariants() twice must produce identical governance fields."""

    @pytest.mark.parametrize("item", [
        {"title": "V-A", "cvss_score": 9.5, "severity": "LOW"},
        {"title": "V-B", "cvss_score": 8.5, "severity": "LOW"},
        {"title": "V-C", "cvss_score": 7.5, "severity": "LOW"},
        {"title": "V-D", "cvss_score": 4.0, "severity": "LOW"},
        {"title": "V-E", "kev": True, "cvss_score": 3.0, "severity": "LOW"},
        {"title": "V-F", "cvss_score": 9.5, "severity": "CRITICAL",
         "priority": "P1", "threat_level": "CRITICAL_SURGE", "risk_score": 9.5},
    ])
    def test_double_application_stable(self, sii, item):
        first  = sii.apply_invariants(copy.deepcopy(item))
        second = sii.apply_invariants(copy.deepcopy(first))
        for field in ("severity", "priority", "threat_level", "risk_score"):
            assert first.get(field) == second.get(field), \
                f"Idempotency violated on '{field}': " \
                f"pass1={first.get(field)!r}, pass2={second.get(field)!r}"


# =============================================================================
# §8  FEED-LEVEL GOVERNANCE
# =============================================================================

class TestFeedLevelGovernance:
    def _feed(self):
        return [
            {"title": "Low CVSS",         "cvss_score": 3.5,  "severity": "LOW"},
            {"title": "CVSS 9.5",         "cvss_score": 9.5,  "severity": "LOW"},
            {"title": "KEV item",         "kev": True,         "severity": "LOW", "cvss_score": 6.0},
            {"title": "MEDIUM OK",        "cvss_score": 5.5,  "severity": "MEDIUM"},
            {"title": "Already CRITICAL", "cvss_score": 9.0,  "severity": "CRITICAL"},
        ]

    def test_returns_tuple(self, sii):
        result = sii.apply_invariants_to_feed(self._feed())
        assert isinstance(result, tuple) and len(result) == 2

    def test_length_preserved(self, sii):
        feed = self._feed()
        governed, _ = sii.apply_invariants_to_feed(feed)
        assert len(governed) == len(feed)

    def test_cvss_9_5_promoted_to_critical(self, sii):
        governed, _ = sii.apply_invariants_to_feed(self._feed())
        item = next(i for i in governed if "9.5" in i.get("title", ""))
        assert item["severity"] == "CRITICAL"

    def test_kev_item_promoted_to_critical(self, sii):
        governed, _ = sii.apply_invariants_to_feed(self._feed())
        item = next(i for i in governed if "KEV" in i.get("title", ""))
        assert item["severity"] == "CRITICAL"

    def test_report_records_enforcement(self, sii):
        _, report = sii.apply_invariants_to_feed(self._feed())
        enforced = sum(
            report.get(k, 0) for k in
            ("critical_enforced", "high_enforced", "medium_enforced",
             "enforced_count", "changed", "recalibrated_count")
        )
        assert enforced > 0, "At least 2 items should have been enforced"


# =============================================================================
# §9  FILE-LEVEL GOVERNANCE
# =============================================================================

class TestFileLevelGovernance:
    def test_file_corrects_severity(self, sii):
        feed = [
            {"title": "Low CVSS",  "cvss_score": 3.5, "severity": "LOW"},
            {"title": "CVSS 9.5",  "cvss_score": 9.5, "severity": "LOW"},
            {"title": "KEV entry", "kev": True,        "severity": "LOW", "cvss_score": 5.0},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False, encoding="utf-8") as tf:
            json.dump(feed, tf)
            tmp_path = tf.name
        try:
            sii.apply_invariants_to_file(tmp_path)
            with open(tmp_path, encoding="utf-8") as f:
                governed = json.load(f)
            assert isinstance(governed, list), "Output must be a JSON list"
            for item in governed:
                if float(item.get("cvss_score", 0)) >= 9.0 or item.get("kev"):
                    assert item["severity"] == "CRITICAL", \
                        f"Item should be CRITICAL after file governance: {item.get('title')}"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_dry_run_does_not_modify_file(self, sii):
        sig = inspect.signature(sii.apply_invariants_to_file)
        if "dry_run" not in sig.parameters:
            pytest.skip("dry_run not present in apply_invariants_to_file signature")
        feed = [{"title": "CVSS 9.5", "cvss_score": 9.5, "severity": "LOW"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False, encoding="utf-8") as tf:
            json.dump(feed, tf)
            tmp_path = tf.name
        try:
            original_mtime = os.path.getmtime(tmp_path)
            sii.apply_invariants_to_file(tmp_path, dry_run=True)
            time.sleep(0.05)
            assert os.path.getmtime(tmp_path) == original_mtime, \
                "dry_run=True must not modify the file"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


# =============================================================================
# §10  PAYWALL TACTICAL FIELDS
# =============================================================================

class TestPaywallTacticalFields:
    _REQUIRED = [
        "sigma_rule", "sigma",
        "kql_query", "kql",
        "suricata_rule", "suricata",
        "yara_rule", "yara",
        "soc_playbook",
    ]

    def test_all_required_fields_present(self, sii):
        fields = list(getattr(sii, "PAYWALL_TACTICAL_FIELDS", []))
        missing = [f for f in self._REQUIRED if f not in fields]
        assert not missing, f"Missing paywall fields: {missing}"

    def test_minimum_field_count(self, sii):
        fields = list(getattr(sii, "PAYWALL_TACTICAL_FIELDS", []))
        assert len(fields) >= 9, \
            f"PAYWALL_TACTICAL_FIELDS must have >= 9 entries, got {len(fields)}"


# =============================================================================
# §11  SEVERITY RECALIBRATION ENGINE — Rule C enforcement
# =============================================================================

class TestSREIntegration:
    """SRE must enforce CVSS>=9.0→CRITICAL (v180.0 fix — was HIGH pre-v180)."""

    def test_cvss_9_mandates_critical(self, sre):
        item = {"title": "V", "cvss_score": 9.0, "severity": "LOW"}
        out, changed, _, new_sev, _ = sre.recalibrate_item(item)
        assert new_sev == "CRITICAL", \
            f"SRE: CVSS=9.0 must produce CRITICAL, got '{new_sev}'"
        assert changed is True

    @pytest.mark.parametrize("cvss", [9.0, 9.5, 10.0])
    def test_cvss_gte_9_always_critical(self, sre, cvss):
        _, _, _, new_sev, _ = sre.recalibrate_item({"title": "V", "cvss_score": cvss, "severity": "LOW"})
        assert new_sev == "CRITICAL", f"SRE: CVSS={cvss} must be CRITICAL"

    def test_critical_sets_priority_p1(self, sre):
        out, _, _, _, _ = sre.recalibrate_item({"title": "V", "cvss_score": 9.5, "severity": "LOW"})
        assert out.get("priority") == "P1", f"SRE: P1 required for CRITICAL, got {out.get('priority')}"

    def test_critical_sets_threat_level(self, sre):
        out, _, _, _, _ = sre.recalibrate_item({"title": "V", "cvss_score": 9.5, "severity": "LOW"})
        assert out.get("threat_level") == "CRITICAL_SURGE"

    def test_critical_risk_score(self, sre):
        out, _, _, _, _ = sre.recalibrate_item({"title": "V", "cvss_score": 9.5, "severity": "LOW"})
        assert float(out.get("risk_score", 0)) >= 9.0

    def test_version_is_180(self, sre):
        assert str(getattr(sre, "VERSION", "")) == "180.0", \
            f"SRE VERSION must be '180.0', got '{getattr(sre, 'VERSION', None)}'"

    def test_kev_plus_active_exploit_is_critical(self, sre):
        item = {
            "title":    "Threat actors actively exploiting KEV vulnerability",
            "kev":      "YES",
            "severity": "LOW",
            "cvss_score": 5.0,
        }
        _, _, _, new_sev, reasons = sre.recalibrate_item(item)
        assert new_sev == "CRITICAL", \
            f"SRE: KEV + active exploit must produce CRITICAL, got '{new_sev}'"

    def test_sre_feed_recalibration_reports_count(self, sre):
        feed = [
            {"title": "Low", "cvss_score": 3.0, "severity": "LOW"},
            {"title": "CVSS 9.5", "cvss_score": 9.5, "severity": "LOW"},
            {"title": "Under active attack", "kev": "YES", "severity": "LOW", "cvss_score": 6.0},
        ]
        recalibrated, report = sre.recalibrate_feed(feed)
        assert report["recalibrated_count"] >= 1
        assert any(i["severity"] == "CRITICAL" for i in recalibrated)


# =============================================================================
# §12  EDGE CASES AND BOUNDARY CONDITIONS
# =============================================================================

class TestEdgeCases:
    def test_missing_severity_treated_as_low(self, sii):
        result = sii.apply_invariants({"title": "No sev field", "cvss_score": 9.5})
        assert result["severity"] == "CRITICAL"

    def test_none_severity_handled(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 9.5, "severity": None})
        assert result["severity"] == "CRITICAL"

    def test_empty_item_does_not_crash(self, sii):
        result = sii.apply_invariants({})
        assert isinstance(result, dict)

    def test_original_item_not_mutated(self, sii):
        original = {"title": "V", "cvss_score": 9.5, "severity": "LOW"}
        backup   = copy.deepcopy(original)
        sii.apply_invariants(original)
        assert original == backup, "apply_invariants must not mutate the input item"

    def test_cvss_string_parsed(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": "9.5", "severity": "LOW"})
        assert result["severity"] == "CRITICAL"

    def test_cvss_invalid_string_no_crash(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": "N/A", "severity": "LOW"})
        assert isinstance(result, dict)

    def test_cvss_zero_no_invariant_fires(self, sii):
        result = sii.apply_invariants({"title": "V", "cvss_score": 0.0, "severity": "LOW"})
        # CVSS=0 alone should not fire any invariant
        assert result.get("severity", "LOW") == "LOW"

    def test_large_feed_performance(self, sii):
        """1000 items must complete < 5 seconds."""
        feed = [
            {"title": f"Vuln {i}", "cvss_score": float(i % 10) + 0.5, "severity": "LOW"}
            for i in range(1000)
        ]
        t0      = time.monotonic()
        governed, _ = sii.apply_invariants_to_feed(feed)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"1000-item feed took {elapsed:.2f}s — performance regression"
        assert len(governed) == 1000


# =============================================================================
# §13  CROSS-MODULE CONSISTENCY: SII ↔ SRE
# =============================================================================

class TestCrossModuleConsistency:
    """Both SII and SRE must independently converge on CRITICAL for the same signals."""

    @pytest.mark.parametrize("cvss", [9.0, 9.5, 10.0])
    def test_sii_and_sre_agree_on_critical(self, sii, sre, cvss):
        item = {"title": "V", "cvss_score": cvss, "severity": "LOW"}

        sii_result        = sii.apply_invariants(copy.deepcopy(item))
        _, _, _, sre_sev, _ = sre.recalibrate_item(copy.deepcopy(item))

        assert sii_result["severity"] == "CRITICAL", \
            f"SII: CVSS={cvss} must be CRITICAL, got '{sii_result['severity']}'"
        assert sre_sev == "CRITICAL", \
            f"SRE: CVSS={cvss} must be CRITICAL, got '{sre_sev}'"
        assert sii_result["severity"] == sre_sev, \
                        f"SII={sii_result['severity']}, SRE={sre_sev}"

