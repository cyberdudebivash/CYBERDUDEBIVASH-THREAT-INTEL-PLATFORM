"""Severity & EPSS truth (scripts/severity_epss_truth.py and its readers).

Fixtures are production /api/feed.json items (2026-09-26) checked against
FIRST.org and each item's own CVSS vector:
  * 11 of 34 CVSS-rated items were LOW at CVSS 4.3-6.7 (composite risk score
    read through the CVSS bands); a CVSS 3.1 SSRF was CRITICAL.
  * CVE-2026-15583: FIRST.org 0.00529 (0.529%), feed epss_score 53, reports
    "53.00%" / "53%".
No network: FIRST.org responses are passed in.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import severity_epss_truth as t  # noqa: E402

OPENCLAW = {"id": "intel--4ac4", "severity": "LOW", "risk_score": 0.53, "cvss_score": 6.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
            "cve_id": "CVE-2026-100592", "cve_ids": ["CVE-2026-100592"], "kev": "NO"}
CONTAO = {"id": "intel--58a8", "severity": "CRITICAL", "risk_score": 2.5, "cvss_score": 3.1,
          "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", "kev": "NO",
          "cve_id": "CVE-2026-57232", "cve_ids": ["CVE-2026-57232"], "epss_score": 0.29, "epss": "0.29%"}
VULNERS = {"id": "intel--16c1", "severity": "HIGH", "cvss_score": 8.6, "epss_score": 53,
           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "cve_ids": ["CVE-2026-15583"],
           "title": "Exploit for CVE-2026-15583"}
FIRST = {"CVE-2026-15583": {"epss": 0.00529, "date": "2026-09-25"},
         "CVE-2026-57232": {"epss": 0.0029, "date": "2026-09-25"},
         "CVE-2026-5430": {"epss": 0.0058, "date": "2026-09-25"}}


def fresh(item):
    return {k: (list(v) if isinstance(v, list) else v) for k, v in item.items()}


# ── CVSS ────────────────────────────────────────────────────────────────────
def test_cvss31_base_scores_match_the_specification():
    cases = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L": 6.3,
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N": 3.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N": 8.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L": 8.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }
    for vec, score in cases.items():
        assert t.cvss3_base_score(vec) == score, vec
    for bad in ("", None, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "CVSS:3.1/AV:N/AC:L", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
        assert t.cvss3_base_score(bad) is None


def test_medium_cvss_is_medium_not_the_composite_risk_band():
    item = fresh(OPENCLAW)
    assert t.apply_severity(item) == ("LOW", "MEDIUM")
    assert item["severity"] == "MEDIUM" and item["severity_basis"] == "cvss_v3_base"
    assert item["severity_pre_truth"] == "LOW"


def test_low_cvss_ssrf_is_not_critical():
    item = fresh(CONTAO)
    assert t.apply_severity(item) == ("CRITICAL", "LOW")


def test_kev_confirmed_severity_is_kept():
    item = dict(fresh(CONTAO), kev_present=True)
    assert t.apply_severity(item) is None
    assert item["severity"] == "CRITICAL" and item["severity_basis"] == "cisa_kev"


def test_unverifiable_cvss_never_changes_severity():
    for cvss_vector in ("", None, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):  # 9.8 != 9.5
        item = {"severity": "CRITICAL", "cvss_score": 9.5, "cvss_vector": cvss_vector}
        assert t.apply_severity(item) is None
        assert item["severity"] == "CRITICAL" and item["severity_basis"] == "source"
    item = {"severity": "HIGH", "title": "news, no CVSS"}
    assert t.apply_severity(item) is None and item["severity"] == "HIGH"


# ── EPSS ────────────────────────────────────────────────────────────────────
def test_epss_comes_from_first_org_as_a_percentage():
    item = fresh(VULNERS)
    assert t.apply_epss(item, FIRST) == "first"
    assert item["epss_score"] == 0.529 and item["epss_pct"] == 0.529
    assert item["epss"] == "0.529%" and item["epss_cve"] == "CVE-2026-15583"
    assert item["epss_source"] == "FIRST.org" and item["epss_date"] == "2026-09-25"
    assert t.epss_percent(item) == 0.529


def test_several_cves_take_the_highest_and_name_it():
    item = {"cve_ids": ["CVE-2026-57232", "CVE-2026-5430", "CVE-2099-0001"]}
    t.apply_epss(item, FIRST)
    assert item["epss_score"] == 0.58 and item["epss_cve"] == "CVE-2026-5430"


def test_no_cve_or_no_first_record_means_no_epss():
    news = {"title": "U.S. Soldier Gets 70 Months in Prison", "epss_score": 1.46}
    assert t.apply_epss(news, FIRST) == "removed_no_first_record"
    assert news["epss_score"] is None and "epss" not in news and t.epss_percent(news) is None
    new_cve = {"cve_ids": ["CVE-2026-100592"], "epss_score": 0.5, "epss": "0.5%"}
    t.apply_epss(new_cve, FIRST)
    assert new_cve["epss_score"] is None and "epss" not in new_cve


def test_first_unreachable_keeps_only_self_verified_values():
    assert t.apply_epss(fresh(CONTAO), None) == "kept_string_verified"
    item = fresh(VULNERS)
    assert t.apply_epss(item, None) == "removed_unverifiable"
    assert item["epss_score"] is None
    canon = fresh(VULNERS)
    t.apply_epss(canon, FIRST)
    assert t.apply_epss(canon, None) == "kept_first_previous" and canon["epss_score"] == 0.529


def test_epss_reader_never_guesses_a_scale():
    assert t.epss_percent({"epss_score": 53}) is None
    assert t.epss_percent({"epss_score": 0.29}) is None
    assert t.epss_percent({"epss_score": 0.29, "epss": "0.29%"}) == 0.29
    assert t.epss_percent({"epss_score": 29, "epss": "0.29%"}) is None
    assert t.epss_percent({"epss_source": "FIRST.org", "epss_pct": 150}) is None
    assert t.fmt_pct(0.529) == "0.529" and t.fmt_pct(53.0) == "53" and t.fmt_pct(0.0004) == "0.0004"


def test_process_reports_every_change():
    items = [fresh(OPENCLAW), fresh(CONTAO), fresh(VULNERS)]
    stats = t.process(items, FIRST)
    assert stats["severity_changes"] == {"LOW->MEDIUM": 1, "CRITICAL->LOW": 1}
    assert stats["epss"]["first"] == 2
    assert [i["severity"] for i in items] == ["MEDIUM", "LOW", "HIGH"]


def test_evidence_chain_states_the_canonical_value():
    import p20_evidence_chain_enricher as e
    item = fresh(VULNERS)
    t.apply_epss(item, FIRST)
    coc = e.build_evidence_chain(item)["chain_of_custody"]
    assert "EPSS score 0.529% assigned by FIRST.org model" in coc


# ── readers ────────────────────────────────────────────────────────────────
def test_report_generator_renders_percent_not_53():
    import generate_intel_reports as gir
    item = fresh(VULNERS)
    t.apply_epss(item, FIRST)
    cvss, epss = gir._resolve_cvss_epss(item)
    assert epss == 0.529
    html = gir._render_financial_impact("HIGH", 3.2, [], "", cvss=cvss, epss=epss, kev=False)
    assert "0.53%" in html and "52.90%" not in html
    # an unproven raw value is not rendered
    assert gir._resolve_cvss_epss({"epss_score": 53, "cve_ids": []})[1] is None


def test_agent_narrative_does_not_multiply_a_percentage():
    from agent import apex_intelligence_upgrade as au
    text = au._render_no_kev_paragraph(0.529, 7)
    assert "0.53%" in text and "52.90%" not in text


def test_premium_baseline_keeps_verified_severity_and_fraction_contract():
    import premium_feed_baseline as pb
    item = fresh(OPENCLAW)
    t.apply_severity(item)
    item["risk_score"] = 3.0  # above the baseline's floor; composite band would say LOW
    pb._quality_gate(item)
    assert item["severity"] == "MEDIUM"
    v = fresh(VULNERS)
    v["risk_score"] = 3.0
    t.apply_epss(v, FIRST)
    pb._quality_gate(v)
    assert v["epss_score"] == 0.00529  # the baseline's documented 0-1 fraction
    assert "EPSS exploitation probability: 0.529%." in pb._synthesize_exec_summary(dict(fresh(VULNERS), **{
        "epss_score": 0.529, "epss_pct": 0.529, "epss_source": "FIRST.org"}))


def test_github_word_severity_is_not_published_as_a_cvss_score(monkeypatch):
    import osv_cvss_enricher as osv
    monkeypatch.setattr(osv, "_get", lambda *a, **k: [{"severity": "critical"}])
    assert osv._fetch_github_advisory("CVE-2026-0001") is None
    monkeypatch.setattr(osv, "_get", lambda *a, **k: [{"severity": "moderate", "cvss": {
        "score": 6.3, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"}}])
    r = osv._fetch_github_advisory("CVE-2026-0001")
    assert r["cvss_score"] == 6.3 and r["severity"] == "MEDIUM"


def _threat_priority_key():
    """threat_priority_key from generate_api_manifests.py without running the
    script (it generates and writes the API manifests at import)."""
    import ast
    import datetime
    src = (ROOT / "scripts" / "generate_api_manifests.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    keep = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name == "threat_priority_key")
            or (isinstance(n, ast.Assign) and any(getattr(x, "id", "") == "_SEV_SCORE" for x in n.targets))]
    assert len(keep) == 2
    ns = {"datetime": datetime, "_epss_percent": t.epss_percent}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "generate_api_manifests.py", "exec"), ns)
    assert "from severity_epss_truth import epss_percent as _epss_percent" in src
    return ns["threat_priority_key"]


def test_top10_ranking_reads_epss_on_one_scale():
    class gam:  # noqa: N801
        threat_priority_key = staticmethod(_threat_priority_key())
    low = fresh(VULNERS)
    t.apply_epss(low, FIRST)  # 0.529%
    high = {"epss_source": "FIRST.org", "epss_pct": 5.0, "epss_score": 5.0}
    assert gam.threat_priority_key(high)[1] > gam.threat_priority_key(low)[1]
    assert gam.threat_priority_key({"epss_score": 53})[1] == 0.0
