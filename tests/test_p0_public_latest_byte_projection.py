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
