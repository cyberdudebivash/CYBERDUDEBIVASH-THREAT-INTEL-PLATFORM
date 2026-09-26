"""P0 2026-09-26 (evidence truth): scripts/p20_evidence_chain_enricher.py.

Production /api/feed.json: 26 of 54 items carried kev == "NO" and every one
read "CISA KEV status: CONFIRMED active exploitation" (bool("NO") is True);
EPSS 0.29 (FIRST.org: 0.29%) read "29.0%", 53 (FIRST.org: 0.53%) "5300.0%".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import p20_evidence_chain_enricher as e  # noqa: E402


def coc(item):
    return e.build_evidence_chain(item)["chain_of_custody"]


BASE = {"id": "intel--abc", "source_url": "https://github.com/advisories/GHSA-87mg-5grr-rhwh",
        "source": "GitHub Security Advisories", "cve_ids": ["CVE-2026-57232"],
        "processed_at": "2026-09-24T19:59:16Z"}


def test_kev_string_no_is_not_a_kev_confirmation():
    for val in ("NO", "no", "False", "0", "none", "", None, False):
        item = dict(BASE, kev=val, kev_present=None)
        assert not any("KEV" in c for c in coc(item)), val
        assert e.build_evidence_chain(item)["accuracy_code"] != "1", val


def test_affirmative_kev_is_confirmed():
    for item in (dict(BASE, kev_present=True), dict(BASE, kev=True), dict(BASE, kev="YES")):
        assert "CISA KEV status: CONFIRMED active exploitation" in coc(item)
        assert e.build_evidence_chain(item)["accuracy_code"] == "1"


def test_epss_stated_only_when_the_scale_is_proven():
    assert "EPSS score 0.29% assigned by FIRST.org model" in coc(dict(BASE, epss_score=0.29, epss="0.29%"))
    # double-scaled, no percent string: never "5300.0%" and never "53%"
    assert not any(c.startswith("EPSS") for c in coc(dict(BASE, epss_score=53)))
    # fraction with no string is ambiguous with the percent convention
    assert not any(c.startswith("EPSS") for c in coc(dict(BASE, epss_score=0.29)))
    # disagreeing string and score
    assert not any(c.startswith("EPSS") for c in coc(dict(BASE, epss_score=29, epss="0.29%")))


def test_chains_from_earlier_runs_are_rebuilt():
    item = dict(BASE, kev="NO", evidence_chain={"evidence_version": "P20.1",
                "chain_of_custody": ["CISA KEV status: CONFIRMED active exploitation"]})
    assert e.enrich_items([item]) == 1
    assert item["evidence_chain"]["evidence_version"] == "P20.1.1"
    assert not any("KEV" in c for c in item["evidence_chain"]["chain_of_custody"])
