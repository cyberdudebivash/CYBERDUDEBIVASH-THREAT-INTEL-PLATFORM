"""Customer-facing product claims must distinguish available evidence from unverified forecasts."""
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "index.html").read_text(encoding="utf-8")

def test_no_unmeasured_prediction_or_installation_sla():
    for claim in (
        "30-day exploitation forecasts",
        "30-second integration · no lock-in",
        "ML-powered threat forecasting engine using Gradient Boosting, Isolation Forest, and DBSCAN clustering.",
    ):
        assert claim not in HTML

def test_detection_packs_require_customer_validation():
    assert "Production-ready Sigma rules, YARA signatures" not in HTML
    assert "deploy in minutes to your existing SIEM/EDR stack" not in HTML
    assert "Validate rule syntax, data mappings and deployment safety" in HTML
    assert "CUSTOMER VALIDATION REQUIRED" in HTML

def test_existing_sales_and_differentiated_value_remain_visible():
    assert "Evidence-linked prioritization" in HTML
    assert "source-linked vulnerability and exploitation signals" in HTML
    assert "Documented onboarding; setup time varies" in HTML
    assert "/upgrade.html?plan=pro" in HTML
    assert "SOC Automation Bundle" in HTML
    assert "AI Threat Prediction API" in HTML
