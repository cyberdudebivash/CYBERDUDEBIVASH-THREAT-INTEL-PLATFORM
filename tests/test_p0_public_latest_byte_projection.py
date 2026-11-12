"""P0 #788: bounded public latest listing keeps customer contract, TLP and source truth.

Fixtures synthetic only; never uploads, touches live R2, or fabricates
production evidence. Worker remains the final public read authority.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from scripts.public_api_sanitizer import (
    PREMIUM_FIELDS,
    PUBLIC_LATEST_FIELDS,
    project_feed_for_public_latest,
    project_for_public_latest,
    sanitize_feed,
    sanitize_feed_pro,
)

ROOT = Path(__file__).resolve().parents[1]
WORKER_CHECK = ROOT / "scripts/p0_r2_public_feed_diagnostic.mjs"


def example(i):
    return {
        "id": f"intel--fixture-{i}", "title": f"Verified fixture #{i}",
        "tlp": "TLP:CLEAR", "risk_score": 8.4,
        "severity": "HIGH", "published_at": datetime.now(timezone.utc).isoformat(),
        "source": "Test data", "source_url": "https://example.org/advisory",
        "description": "Public, attributed description",
        "summary": "Public summary", "cve_ids": [f"CVE-2026-{10000+i}"],
        "apex": {"internal_vector": "DO_NOT_EXPOSE"} ,
        "apex_score": {"internal_evidence": ["x" * 2000] * 3},
        "evidence_chain": [{"source": "internal", "blob": "x" * 4000}],
        "sigma_rule": "selection: secret" * 100,
        "kql_query": "PRIVATE" * 700,
        "ioc_hashes": ["internal-value"],
        "technical_analysis": "PRIVATE",
        "detailed_analysis": "PRIVATE",
    }


def test_100_full_rich_advisories_fit_same_worker_without_record_or_identity_loss(tmp_path):
    canonical = [example(i) for i in range(100)]
    pristine = copy.deepcopy(canonical)
    full_size = len(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode())
    assert full_size > 1024 * 1024, "synthetic fixture must reproduce size regression"
    public_items = project_feed_for_public_latest(sanitize_feed(canonical))
    assert len(public_items) == len(canonical)
    assert [x["id"] for x in public_items] == [x["id"] for x in canonical]
    assert [x["tlp"] for x in public_items] == [x["tlp"] for x in canonical]
    assert [x["risk_score"] for x in public_items] == [x["risk_score"] for x in canonical]
    assert all(x["source_url"] == "https://example.org/advisory" for x in public_items)
    assert all(x["description"] == "Public, attributed description" for x in public_items)
    assert all(not (set(x) & PREMIUM_FIELDS) for x in public_items)
    assert all("evidence_chain" not in x and "apex_score" not in x and "sigma_rule" not in x for x in public_items)
    assert canonical == pristine  # canonical/pro data never mutated
    assert sanitize_feed_pro(canonical)[0]["description"] == "Public, attributed description"
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(),
                "count": len(public_items), "items": public_items}
    path = tmp_path / "latest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    assert path.stat().st_size <= 1024 * 1024
    result = subprocess.run(["node", str(WORKER_CHECK), str(path)], cwd=ROOT,
                            capture_output=True, text=True, timeout=25, check=False)
    assert result.returncode == 0, result.stderr
    verdict = json.loads(result.stdout)
    assert verdict["verdict"] == "DELIVERABLE"
    assert verdict["worker_body_budget_exceeded"] is False
    assert verdict["worker_node_budget_exceeded"] is False


def test_projection_is_allowlist_not_delete_only_and_keeps_explicit_tlp():
    row = example(1)
    row["future_proprietary_ai_property"] = {"hidden": True}
    row["report_url"] = "/reports/private.html"
    row["internal_report_url"] = "/reports/private.html"
    row["tlp"] = "TLP:GREEN"
    allowed = project_for_public_latest(sanitize_feed([row])[0])
    assert set(allowed) <= PUBLIC_LATEST_FIELDS
    assert allowed["id"] == row["id"]
    assert allowed["tlp"] == "TLP:GREEN"  # never upgrade to CLEAR
    assert "future_proprietary_ai_property" not in allowed
    assert "report_url" not in allowed
    assert "internal_report_url" not in allowed
    assert "evidence_chain" not in allowed


def test_free_public_latest_strips_paid_nested_detection_evidence_without_pro_loss():
    """A top-level allowlist is insufficient: legitimate ATT&CK lists carry premium children."""
    original = example(42)
    private_technique = {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "confidence": "high",
        "justification": "premium analyst justification",
        "observed_behavior": "premium private telemetry",
        "detection_hint": "private detection playbook",
        "sigma_tag": "private sigma rule",
        "kql_example": "DeviceProcessEvents | where AccountName == 'private'",
        "evidence_chain": [{"ioc_payload": "PRIVATE_IOC", "tlp": "TLP:RED"}],
        "mapping_engine": "internal",
    }
    original["mitre_techniques"] = [copy.deepcopy(private_technique)]
    original["ttps"] = [copy.deepcopy(private_technique), "T1059"]
    original["mitre_tactics"] = [
        {"id": "TA0002", "name": "Execution", "tactic": "execution",
         "justification": "private paid attribution", "evidence_chain": ["private"]}
    ]
    original["ioc_paywall"] = {
        "locked": True, "count": 3, "confidence": 0.8,
        "threat_level": "high", "primary_types": ["domain"],
        "upgrade_url": "/upgrade.html?plan=pro", "message": "Upgrade to access",
        "kql_example": "PRIVATE", "evidence_chain": [{"secret": "PRIVATE"}],
    }
    canonical = copy.deepcopy(original)
    anonymous = project_for_public_latest(sanitize_feed([original])[0])

    expected_technique = {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
    }
    assert anonymous["mitre_techniques"] == [expected_technique]
    assert anonymous["ttps"] == [expected_technique, "T1059"]
    assert anonymous["mitre_tactics"] == [
        {"id": "TA0002", "name": "Execution", "tactic": "execution"}
    ]
    assert anonymous["ioc_paywall"] == {
        "locked": True, "count": 3, "confidence": 0.8,
        "threat_level": "high", "primary_types": ["domain"],
        "upgrade_url": "/upgrade.html?plan=pro", "message": "Upgrade to access",
    }
    serialized = json.dumps(anonymous, ensure_ascii=False)
    for forbidden in ("kql_example", "evidence_chain", "justification",
                      "observed_behavior", "detection_hint", "sigma_tag",
                      "PRIVATE_IOC", "private paid attribution", "private telemetry"):
        assert forbidden not in serialized
    assert original == canonical, "projection must never mutate canonical records"
    pro = sanitize_feed_pro([original])[0]
    assert pro["ttps"][0]["kql_example"] == canonical["ttps"][0]["kql_example"]
    assert pro["mitre_techniques"][0]["evidence_chain"] == canonical["mitre_techniques"][0]["evidence_chain"]


def test_free_public_latest_rejects_unreviewed_nested_shape_under_allowed_fields():
    item = example(43)
    item["description"] = {"text": "Public title", "internal_report_url": "PRIVATE"}
    item["summary"] = ["Public summary", {"stix_bundle": "PRIVATE"}]
    item["tags"] = ["alpha", {"ioc_payload": "PRIVATE"}, "beta"]
    item["mitre_techniques"] = [
        "DeviceProcessEvents | where PrivateField == true",
        "T1059",
        {"technique_id": "T1059", "kql_example": "PRIVATE"},
        {"kql_example": "PRIVATE_ONLY"},
        {"technique_id": {"value": "UNREVIEWED_NESTED"}},
    ]
    item["ioc_paywall"] = {"locked": True, "primary_types": [
        "domain", {"ioc_payload": "PRIVATE"}], "internal_report_url": "PRIVATE"}
    projected = project_for_public_latest(item)
    assert "description" not in projected
    assert "summary" not in projected
    assert projected["tags"] == ["alpha", "beta"]
    assert projected["mitre_techniques"] == ["T1059", {"technique_id": "T1059"}]
    assert projected["ioc_paywall"] == {"locked": True, "primary_types": ["domain"]}
    assert "PRIVATE" not in json.dumps(projected)
    assert item["description"]["internal_report_url"] == "PRIVATE"


def test_worker_still_denies_nested_restricted_record_in_allowed_field(tmp_path):
    record = project_for_public_latest(sanitize_feed([example(2)])[0])
    record["ttps"] = [{"id": "intel--restricted", "title": "Not public", "tlp": "TLP:RED"}]
    doc = {"generated_at": datetime.now(timezone.utc).isoformat(), "count": 1, "items": [record]}
    f = tmp_path / "latest.json"
    f.write_text(json.dumps(doc, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    result = subprocess.run(["node", str(WORKER_CHECK), str(f)], cwd=ROOT,
                            capture_output=True, text=True, timeout=25, check=False)
    assert result.returncode == 1
    answer = json.loads(result.stdout)
    assert answer["verdict"] == "BLOCKED"
    assert answer["worker_public_tlp_gate"] == "BLOCKED"
    assert "Not public" not in result.stdout
