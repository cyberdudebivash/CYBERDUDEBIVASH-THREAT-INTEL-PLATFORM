"""P0 public projection: preserve source evidence without inventing provenance."""
from scripts.public_api_sanitizer import project_for_public_latest


def test_existing_authoritative_evidence_survives_projection():
    item = {"id": "news-1", "cve_ids": ["CVE-2026-109618"],
            "source_url": "https://example.org/news",
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"}],
            "source_urls": ["https://www.php.net/archive/2026.php#2026-10-21-5"],
            "detailed_analysis": "paid-only"}
    out = project_for_public_latest(item)
    assert out["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2026-109618"]
    assert out["source_urls"] == ["https://www.php.net/archive/2026.php#2026-10-21-5"]
    assert out["source_url"] == "https://example.org/news"
    assert "detailed_analysis" not in out


def test_no_evidence_is_invented_from_cve_ids():
    out = project_for_public_latest({"id": "news-1", "cve_ids": ["CVE-2026-109618"],
                                     "source_url": "https://example.org/news"})
    assert "references" not in out
    assert "source_urls" not in out


def test_invalid_or_unbounded_evidence_not_projected():
    out = project_for_public_latest({"references": ["http://insecure.test", "https://ok.test"]})
    assert out["references"] == ["https://ok.test"]
    out = project_for_public_latest({"references": ["https://ok.test"] * 17})
    assert "references" not in out
