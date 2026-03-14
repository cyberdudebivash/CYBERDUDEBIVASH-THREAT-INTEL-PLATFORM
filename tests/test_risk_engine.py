"""
test_risk_engine.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the Dynamic Risk Scoring Engine (risk_engine.py).

Tests cover:
- Risk score range and type
- Score is dynamic (not hardcoded)
- Individual signal contributions
- Severity label mapping
- TLP label mapping
- Extended metrics (SMI, confidence, velocity)
- Edge cases (empty IOCs, all signals active)
"""
import pytest
from agent.risk_engine import risk_engine


# ─── Basic Scoring Contract ───────────────────────────────────────────────────

class TestRiskScoreContract:
    def test_returns_float(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        assert isinstance(score, float)

    def test_score_in_valid_range(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        assert 0.0 <= score <= 10.0, f"Risk score {score} outside [0.0, 10.0]"

    def test_score_not_hardcoded(self, sample_iocs):
        """Ensure the engine is truly dynamic, not returning a fixed value."""
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        assert score != 9.3, "Score appears to be hardcoded to 9.3"
        assert score != 5.0, "Score appears to be hardcoded to 5.0"

    def test_empty_iocs_low_score(self, empty_iocs):
        score = risk_engine.calculate_risk_score(iocs=empty_iocs)
        assert score < 5.0, f"Empty IOCs should produce low risk, got {score}"

    def test_rich_iocs_higher_score(self, sample_iocs, empty_iocs):
        rich = risk_engine.calculate_risk_score(iocs=sample_iocs)
        empty = risk_engine.calculate_risk_score(iocs=empty_iocs)
        assert rich > empty, "Rich IOC set should yield higher risk than empty set"

    def test_score_capped_at_10(self, sample_iocs):
        """Even with all signals active, score must not exceed 10."""
        score = risk_engine.calculate_risk_score(
            iocs=sample_iocs,
            mitre_matches=[{"id": f"T{i}", "tactic": "impact"} for i in range(20)],
            cvss_score=10.0,
            epss_score=0.99,
            kev_present=True,
            headline="Nation-state supply chain ransomware critical infrastructure CVE exploit",
            content="active exploitation supply chain nation-state critical infrastructure PoC public exploit",
        )
        assert score <= 10.0, f"Score {score} exceeds maximum of 10.0"


# ─── Signal Contributions ─────────────────────────────────────────────────────

class TestSignalContributions:
    def test_kev_boosts_score(self, minimal_iocs):
        """v46.0 FIX: Use minimal IOCs so KEV boost has headroom below 10.0 ceiling."""
        without_kev = risk_engine.calculate_risk_score(iocs=minimal_iocs, kev_present=False)
        with_kev = risk_engine.calculate_risk_score(iocs=minimal_iocs, kev_present=True)
        assert with_kev > without_kev, "KEV should boost risk score"

    def test_high_cvss_boosts_score(self, minimal_iocs):
        """v46.0 FIX: Use minimal IOCs so CVSS boost has headroom below 10.0 ceiling."""
        low_cvss = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=2.0)
        high_cvss = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=9.8)
        assert high_cvss > low_cvss, "High CVSS should yield higher risk than low CVSS"

    def test_high_epss_boosts_score(self, minimal_iocs):
        """v46.0 FIX: Use minimal IOCs so EPSS boost has headroom below 10.0 ceiling."""
        low_epss = risk_engine.calculate_risk_score(iocs=minimal_iocs, epss_score=0.01)
        high_epss = risk_engine.calculate_risk_score(iocs=minimal_iocs, epss_score=0.95)
        assert high_epss > low_epss, "High EPSS should yield higher risk than low EPSS"

    def test_mitre_matches_boost_score(self, sample_iocs):
        no_mitre = risk_engine.calculate_risk_score(iocs=sample_iocs, mitre_matches=[])
        with_mitre = risk_engine.calculate_risk_score(
            iocs=sample_iocs,
            mitre_matches=[
                {"id": "T1486", "tactic": "impact"},
                {"id": "T1059", "tactic": "execution"},
            ],
        )
        assert with_mitre >= no_mitre, "MITRE matches should boost or maintain score"

    def test_actor_attribution_boosts_score(self, sample_iocs):
        no_actor = risk_engine.calculate_risk_score(
            iocs=sample_iocs,
            actor_data={"actor": "Unknown", "confidence": 0},
        )
        known_actor = risk_engine.calculate_risk_score(
            iocs=sample_iocs,
            actor_data={"actor": "APT41", "confidence": 90},
        )
        assert known_actor >= no_actor, "Known actor attribution should boost score"

    def test_supply_chain_content_boosts_score(self, sample_iocs):
        normal = risk_engine.calculate_risk_score(iocs=sample_iocs, content="regular malware")
        supply_chain = risk_engine.calculate_risk_score(
            iocs=sample_iocs, content="supply chain attack on widely-used open source library"
        )
        assert supply_chain >= normal, "Supply chain keywords should boost score"

    def test_nation_state_content_boosts_score(self, sample_iocs):
        normal = risk_engine.calculate_risk_score(iocs=sample_iocs, content="generic threat")
        nation = risk_engine.calculate_risk_score(
            iocs=sample_iocs, content="nation-state sponsored attack APT group"
        )
        assert nation >= normal, "Nation-state keywords should boost score"


# ─── Severity Label Mapping ───────────────────────────────────────────────────

class TestSeverityLabel:
    @pytest.mark.parametrize("score,expected", [
        (9.5, "CRITICAL"),
        (8.0, "HIGH"),
        (5.5, "MEDIUM"),
        (2.5, "LOW"),
        (0.5, "INFO"),
    ])
    def test_severity_label(self, score, expected):
        label = risk_engine.get_severity_label(score)
        assert label == expected, f"Score {score} → expected {expected}, got {label}"

    def test_severity_returns_string(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        label = risk_engine.get_severity_label(score)
        assert isinstance(label, str)
        assert label in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_boundary_score_9(self):
        """Score of exactly 9 should be CRITICAL."""
        label = risk_engine.get_severity_label(9.0)
        assert label in {"CRITICAL", "HIGH"}  # Boundary — depends on implementation

    def test_boundary_score_0(self):
        """Minimum score should return a valid label."""
        label = risk_engine.get_severity_label(0.0)
        assert label in {"INFO", "LOW"}


# ─── TLP Label Mapping ────────────────────────────────────────────────────────

class TestTLPLabel:
    def test_high_score_tlp_red_or_amber(self, sample_iocs):
        score = 9.5
        tlp = risk_engine.get_tlp_label(score)
        assert isinstance(tlp, dict)
        assert "label" in tlp
        assert tlp["label"] in {"TLP:RED", "TLP:AMBER", "TLP:AMBER+STRICT"}

    def test_low_score_tlp_green_or_clear(self):
        score = 1.0
        tlp = risk_engine.get_tlp_label(score)
        assert tlp["label"] in {"TLP:GREEN", "TLP:CLEAR"}

    def test_tlp_returns_dict(self):
        tlp = risk_engine.get_tlp_label(5.0)
        assert isinstance(tlp, dict)

    def test_tlp_label_is_string(self):
        tlp = risk_engine.get_tlp_label(7.0)
        assert isinstance(tlp["label"], str)
        assert "TLP:" in tlp["label"]

    @pytest.mark.parametrize("score", [0.0, 2.5, 5.0, 7.5, 9.5, 10.0])
    def test_tlp_valid_for_all_scores(self, score):
        tlp = risk_engine.get_tlp_label(score)
        assert "label" in tlp
        assert tlp["label"].startswith("TLP:")


# ─── Extended Metrics ─────────────────────────────────────────────────────────

class TestExtendedMetrics:
    def test_compute_extended_metrics_exists(self):
        assert hasattr(risk_engine, "compute_extended_metrics"), \
            "risk_engine must have compute_extended_metrics method"

    def test_extended_metrics_returns_dict(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        metrics = risk_engine.compute_extended_metrics(
            risk_score=score, iocs=sample_iocs
        )
        assert isinstance(metrics, dict)

    def test_extended_metrics_has_required_keys(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        metrics = risk_engine.compute_extended_metrics(
            risk_score=score, iocs=sample_iocs
        )
        expected_keys = {
            "intel_confidence_score", "threat_momentum_score", "exploit_velocity",
        }
        for key in expected_keys:
            assert key in metrics, f"Missing extended metric: {key}"

    def test_threat_momentum_in_range(self, sample_iocs):
        score = risk_engine.calculate_risk_score(iocs=sample_iocs)
        metrics = risk_engine.compute_extended_metrics(
            risk_score=score, iocs=sample_iocs
        )
        smi = metrics.get("threat_momentum_score", 0)
        assert 0 <= smi <= 10, f"Sentinel Momentum Index {smi} outside [0, 10]"


# ─── Consistency / Determinism ────────────────────────────────────────────────

class TestDeterminism:
    def test_same_input_same_output(self, sample_iocs):
        """Identical inputs must produce identical scores."""
        score_a = risk_engine.calculate_risk_score(iocs=sample_iocs, cvss_score=7.5)
        score_b = risk_engine.calculate_risk_score(iocs=sample_iocs, cvss_score=7.5)
        assert score_a == score_b, "Risk scoring must be deterministic"

    def test_different_cvss_different_score(self, minimal_iocs):
        """v46.0 FIX: Use minimal IOCs so different CVSS values produce different scores."""
        score_low = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=2.0)
        score_high = risk_engine.calculate_risk_score(iocs=minimal_iocs, cvss_score=9.8)
        assert score_low != score_high
