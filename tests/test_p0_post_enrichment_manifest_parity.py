"""P0 upstream evidence, IOC persistence and signed manifest ordering.

No network, Cloudflare account access, production R2 writes or credentials.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts import p20_evidence_chain_enricher as evidence
from scripts import p20_ioc_hardener as ioc
from scripts.public_api_sanitizer import sanitize_for_pro
from scripts import verify_post_enrichment_manifest_parity as parity
from scripts.verify_post_enrichment_manifest_parity import (
    ParityError,
    verify_post_enrichment_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
ID = "intel--" + "a" * 24


def item():
    return {
        "id": ID,
        "tlp": "TLP:CLEAR",
        "source": "CISA",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "processed_at": "2026-11-12T18:00:00Z",
        "published_at": "2026-11-12T13:00:00Z",
        "title": "Synthetic CISA sourced vulnerability",
        "description": "Test description supplied by an illustrative source",
        "severity": "CRITICAL",
        "iocs": [{"type": "domain", "value": "synthetic-evil.example.net", "confidence": 71}],
        "ioc_count": 1,
    }


def test_both_enrichers_target_the_actual_publisher_stix_manifest():
    canonical = ROOT / "data" / "stix" / "feed_manifest.json"
    assert evidence.MANIFEST_PATH == canonical
    assert ioc.MANIFEST_PATH == canonical
    assert evidence.MANIFEST_PATH != ROOT / "data" / "feed_manifest.json"


def test_ioc_context_only_changes_are_written_without_any_false_positive(tmp_path, monkeypatch):
    path = tmp_path / "api-feed.json"
    path.write_text(json.dumps([item()]), encoding="utf8")
    monkeypatch.setattr(ioc, "DRY_RUN", False)
    n, false_positives = ioc.process_feed(path)
    assert n == 1 and false_positives == 0
    saved = json.loads(path.read_text(encoding="utf8"))[0]
    assert saved["ioc_count"] == 1
    assert saved["iocs"][0]["p20_hardened"] is True
    assert saved["iocs"][0]["value"] == item()["iocs"][0]["value"]
    assert saved["iocs"][0].get("response_guidance"), "must persist real operational context"
    # Second execution must be idempotent when the same upstream facts are used.
    once = path.read_bytes()
    n2, fp2 = ioc.process_feed(path)
    assert (n2, fp2) == (1, 0)
    assert path.read_bytes() == once


def test_canonical_enrichment_is_persisted_to_envelope_and_paid_projection(tmp_path, monkeypatch):
    path = tmp_path / "stix-manifest.json"
    path.write_text(json.dumps({"advisories": [item()]}), encoding="utf8")
    monkeypatch.setattr(evidence, "DRY_RUN", False)
    monkeypatch.setattr(ioc, "DRY_RUN", False)
    assert evidence.process_feed(path) == 1
    assert ioc.process_feed(path) == (1, 0)
    enriched = json.loads(path.read_text(encoding="utf8"))["advisories"][0]
    assert enriched["evidence_chain"]["source_url"] == item()["source_url"]
    assert enriched["evidence_chain"]["analyst_review"].startswith("Automated")
    assert enriched["iocs"][0]["p20_hardened"] is True
    paid = sanitize_for_pro(enriched)
    assert "apex_ai" not in paid, "do not open ENTERPRISE-only premium content"
    status = verify_post_enrichment_manifest([enriched], {"items": [paid], "count": 1})
    assert status["pro_records_with_evidence_chain"] == 1
    assert status["pro_records_with_hardened_iocs"] == 1
    assert status["production_delivery_verified"] is False


def test_paid_source_must_match_actual_final_evidence_and_iocs():
    raw = item()
    raw["evidence_chain"] = {"reliability_code": "A", "source_url": raw["source_url"]}
    paid = sanitize_for_pro(raw)
    assert verify_post_enrichment_manifest([raw], {"items": [paid], "count": 1})["pro_records"] == 1
    for mutation in (
        lambda x: x.pop("evidence_chain"),
        lambda x: x.update({"iocs": []}),
        lambda x: x.update({"tlp": "TLP:RED"}),
        lambda x: x.update({"processed_at": "2026-09-01T00:00:00Z"}),
    ):
        altered = copy.deepcopy(paid)
        mutation(altered)
        with pytest.raises(ParityError, match="MANIFEST_NOT_ALIGNED_TO_ENRICHED_SOURCE"):
            verify_post_enrichment_manifest([raw], {"items": [altered], "count": 1})


def test_fail_closed_for_orphan_pro_row_duplicate_conflicts_and_wrong_count():
    raw = item()
    good = sanitize_for_pro(raw)
    with pytest.raises(ParityError, match="PRO_REPORT_SOURCE_UNRESOLVABLE"):
        verify_post_enrichment_manifest([raw], {"items": [{**good, "id": ID[:-1] + "b"}], "count": 1})
    duplicate = copy.deepcopy(raw)
    duplicate["severity"] = "LOW"
    with pytest.raises(ParityError, match="CONFLICTING_SOURCE_DUPLICATES"):
        verify_post_enrichment_manifest([raw, duplicate], {"items": [good], "count": 1})
    with pytest.raises(ParityError, match="PRO_COUNT_INCONSISTENT"):
        verify_post_enrichment_manifest([raw], {"items": [good], "count": 2})


def test_workflow_final_manifest_is_mandatory_and_after_both_enrichers():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf8")
    initial = workflow.index('name: "STAGE 3.93 - Generate Immutable API Manifests')
    evidence_step = workflow.index('name: "STAGE 3.93.15b - P20.1 Evidence Chain Enricher"')
    ioc_step = workflow.index('name: "STAGE 3.93.15c - P20.2 IOC Hardener"')
    p21_step = workflow.index('name: "STAGE 3.93.15d - P21.0 Enterprise Certification Gate"')
    rebuild = workflow.index('name: "STAGE 3.93.19 - Re-generate Immutable API Manifests (post-enrichment)"')
    next_step = workflow.index('name: "STAGE 3.93.2 - Daily Brief Generator (v184.0)"')
    # Existing post-enrichment regeneration must remain the only later one.
    # Do not add a third invocation or silently raise runner usage.
    assert initial < evidence_step < ioc_step < p21_step < rebuild < next_step
    assert workflow.count("python3 scripts/generate_api_manifests.py") == 2
    final_block = workflow[rebuild:next_step]
    assert "continue-on-error: true" not in final_block
    assert "python3 scripts/verify_post_enrichment_manifest_parity.py" in final_block
    assert final_block.index("generate_api_manifests.py") < final_block.index("verify_post_enrichment_manifest_parity.py")


def test_manifest_file_loader_rejects_nonregular_empty_or_oversized_inputs(tmp_path, monkeypatch):
    """Exercise the exact Stage 3.93.19 file path, not just in-memory parity."""
    path = tmp_path / "manifest.json"
    payload = json.dumps([item()]).encode("utf-8")
    monkeypatch.setattr(parity, "MAX_INPUT_BYTES", len(payload))
    path.write_bytes(payload)
    assert parity._read_bounded_json(path) == [item()]

    for invalid in (b"", payload + b"x"):
        path.write_bytes(invalid)
        with pytest.raises(ParityError, match="MISSING_OR_OVERSIZED_INPUT"):
            parity._read_bounded_json(path)
    with pytest.raises(ParityError, match="MISSING_OR_OVERSIZED_INPUT"):
        parity._read_bounded_json(tmp_path)
    with pytest.raises(FileNotFoundError):
        parity._read_bounded_json(tmp_path / "missing.json")


def test_manifest_parity_cli_returns_opaque_nonzero_on_invalid_input(tmp_path, monkeypatch, capsys):
    source_path = tmp_path / "source.json"
    paid_path = tmp_path / "paid.json"
    row = item()
    source_path.write_text(json.dumps([row]), encoding="utf-8")
    paid_path.write_text(json.dumps({"items": [sanitize_for_pro(row)], "count": 1}), encoding="utf-8")
    monkeypatch.setattr(parity, "SOURCE_PATH", source_path)
    monkeypatch.setattr(parity, "PRO_PATH", paid_path)
    assert parity.main() == 0
    assert json.loads(capsys.readouterr().out)["production_delivery_verified"] is False

    sensitive_input = "P0_DO_NOT_PRINT_PRIVATE_EVIDENCE"
    paid_path.write_text(sensitive_input, encoding="utf-8")
    assert parity.main() == 2
    diagnostic = capsys.readouterr().out
    result = json.loads(diagnostic)
    assert result["verdict"] == "BLOCKED_POST_ENRICHMENT_SOURCE_PARITY"
    assert result["reason"] == "INPUT_UNAVAILABLE_OR_INVALID"
    assert sensitive_input not in diagnostic
    assert result["production_delivery_verified"] is False
