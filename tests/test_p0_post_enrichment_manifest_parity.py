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
    rebuild = workflow.index('name: "STAGE 3.93.15c.1 - Rebuild signed manifests after P20 final enrichment (P0)"')
    next_gate = workflow.index('name: "STAGE 3.93.15d - P21.0 Enterprise Certification Gate"')
    assert initial < evidence_step < ioc_step < rebuild < next_gate
    assert workflow.count("python3 scripts/generate_api_manifests.py") == 2
    final_block = workflow[rebuild:next_gate]
    assert "continue-on-error: true" not in final_block
    assert "python3 scripts/verify_post_enrichment_manifest_parity.py" in final_block
    assert final_block.index("generate_api_manifests.py") < final_block.index("verify_post_enrichment_manifest_parity.py")
