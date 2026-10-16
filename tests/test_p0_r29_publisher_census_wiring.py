"""P0 R29 workflow wiring regression: diagnostic runs but never authorizes publishing."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows/sentinel-apex.yml"

def test_forensic_census_order_and_read_only_execution():
    source = WF.read_text(encoding="utf-8")
    orchestrator = source.index('- name: "STAGE 1-3 - Master Pipeline Orchestrator"')
    diagnostic = source.index('- name: "P0 R29 - Read-only public-feed provenance census"')
    status = source.index('- name: "STAGE 1-3 STATUS GATE', diagnostic)
    assert orchestrator < diagnostic < status
    block = source[diagnostic:status]
    assert "p0_r28_provenance_diagnostic.py --feed api/feed.json" in block
    assert "--output data/quality/p0_r28_provenance_census.json" in block
    assert "always() && !cancelled()" in block
    assert "git push" not in block
    assert "r2_upload" not in block
    assert "PIPELINE_HEALTH=HEALTHY" not in block
