#!/usr/bin/env python3
"""
tests/test_p0_report_evidence_quality.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- P0 evidence-quality regression guards.

Every analytical assertion in a customer report must trace to evidence.
These tests pin the removal of each fabrication path found in the
production pipeline (confirmed in sentinel-blogger run 35818582480 logs):

  1. core/intelligence/ioc_enforcer.py invented random public IPv4s,
     domains, URLs and hashes labelled "C2"/"malware_sample" at 68-96%
     confidence ("Fallback IOCs generated: 2 added ... (was 5)").
  2. scripts/report_enhancer.py emitted "c2.example.com" SIEM targets, a
     generic YARA rule, "Block all 0 IOCs", "CVSS N/A" instructions and
     severity-keyed cost / stock-impact / dwell-time / ROI figures.
  3. scripts/context_aware_narrative_engine.py emitted "Block all 0 IOCs".
  4. scripts/generate_intel_reports.py printed per-advisory "FAIR" loss
     ranges, an invented "Risk Multiplier" column, unsourced class figures,
     severity-keyed dollar ranges credited to IBM, and a "<0.1% false
     positive" detection claim with no telemetry behind it.
  5. scripts/apply_v131_upgrades.py injected fabricated advisories when the
     feed held fewer than 3 items.
"""
import html as _html
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
for p in (REPO, REPO / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import context_aware_narrative_engine as narr  # noqa: E402
import generate_intel_reports as gir  # noqa: E402
import report_enhancer as enh  # noqa: E402
from core.intelligence.ioc_enforcer import IOCEnforcer  # noqa: E402


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", _html.unescape(re.sub(r"<[^>]+>", " ", html)))


ZERO_IOC_CVE = {
    "id": "intel--evq-cve", "title": "CVE-2026-11111 Apache ActiveMQ frame size validation bypass",
    "description": "A denial of service in Apache ActiveMQ.", "severity": "HIGH",
    "cve_id": "CVE-2026-11111", "cvss_score": 7.5, "epss_score": 0.0123,
    "timestamp": "2026-09-23T10:00:00Z", "iocs": [], "risk_score": 7.1,
}
ZERO_IOC_RANSOM = {
    "id": "intel--evq-ransom", "title": "LockBit ransomware campaign targets healthcare",
    "description": "Ransomware operators encrypt hospital systems.", "severity": "CRITICAL",
    "timestamp": "2026-09-23T10:00:00Z", "iocs": [], "risk_score": 8.8, "tags": ["healthcare"],
}

FABRICATION_PATTERNS = [
    # A factual count ("0 indicators of compromise recorded") is fine; an
    # instruction to act on zero indicators is not.
    r"example\.com", r"\bBlock all 0\b", r"\ball 0 IOCs\b", r"\b0 indicators? (provided|represent)",
    r"Stock Price", r"\bROI\b", r"127 days", r"Loss Range", r"Risk Multiplier",
    r"35% probability", r"below 0\.1%", r"\(CVSS (None|N/A)\)",
]


# ── 1. IOC enforcer ──────────────────────────────────────────────────────────

def test_evidence_only_enforcer_never_invents_and_never_drops():
    enf = IOCEnforcer(auto_generate_fallback=False, block_on_shortfall=False)
    res = enf.enforce(dict(ZERO_IOC_CVE, actor_tag="APT-X"))
    assert not res.blocked
    assert res.fallback_added == 0
    assert res.item.get("iocs", []) == []
    assert res.item["ioc_shortfall"] is True

    real = [{"type": "ipv4", "value": "198.51.100.7", "confidence": 40}]
    res = enf.enforce(dict(ZERO_IOC_CVE, actor_tag="APT-X", iocs=real))
    assert res.item["iocs"] == real, "real IOCs must never be padded with invented ones"

    manifest = {"advisories": [dict(ZERO_IOC_CVE, actor_tag="APT-X")]}
    out = enf.enforce_manifest(manifest)
    assert len(out["advisories"]) == 1, "a zero-IOC advisory is valid intel and must not be dropped"


def test_enforcer_defaults_unchanged_for_backward_compatibility():
    res = IOCEnforcer().enforce(dict(ZERO_IOC_CVE, actor_tag="APT-X"))
    assert res.fallback_added > 0  # deprecated behaviour still available to any external caller


@pytest.mark.parametrize("path", ["scripts/generate_intel_reports.py", "scripts/apply_v131_upgrades.py"])
def test_production_callers_use_evidence_only_mode(path):
    src = (REPO / path).read_text(encoding="utf-8")
    calls = re.findall(r"IOCEnforcer\(([^)]*)\)", src)
    assert calls, f"{path} no longer constructs IOCEnforcer -- update this test"
    for args in calls:
        assert "auto_generate_fallback=False" in args and "block_on_shortfall=False" in args, (path, args)


def test_synthetic_advisory_injection_disabled():
    src = (REPO / "scripts/apply_v131_upgrades.py").read_text(encoding="utf-8")
    assert "augment_with_synthetic(" not in src


# ── 2. generate_intel_reports.py (authoritative HTML writer) ─────────────────

@pytest.mark.parametrize("item", [ZERO_IOC_CVE, ZERO_IOC_RANSOM], ids=["cve", "ransomware"])
def test_rendered_report_has_no_fabricated_content(item):
    html = gir.render_report(dict(item), "https://intel.cyberdudebivash.com")
    txt = _text(html)
    for pat in FABRICATION_PATTERNS:
        assert not re.search(pat, txt), f"fabricated content {pat!r} in {item['id']}"
    assert '"generated": true' not in html.replace("'", '"')
    assert re.search(r"IOCs: <strong>0</strong>", html), "zero IOCs must render as zero"
    assert len(html.encode()) >= 60_000, "must stay above report_generator's GODMODE_MIN_SIZE_BYTES"
    if not item.get("cve_id"):
        assert "PATCH IMMEDIATELY" not in txt, "no patch directive on a record with nothing to patch"


def test_business_impact_section_is_evidence_only():
    html = gir._render_financial_impact("CRITICAL", 9.6, ["healthcare"], "ransomware",
                                        cvss=9.8, epss=None, kev=True, exploit_maturity=None)
    txt = _text(html)
    assert "$" not in txt, "no dollar figure without organisation-specific inputs"
    assert "CUSTOMER EXPOSURE: UNKNOWN" in txt
    assert "CVSS base score 9.8" in txt
    assert "EPSS (30-day exploitation probability) Not available" in txt
    assert "CISA KEV Listed" in txt
    assert "Exploit maturity Not established from available evidence" in txt


def test_business_impact_legacy_positional_signature_still_works():
    assert "CUSTOMER EXPOSURE: UNKNOWN" in gir._render_financial_impact("HIGH", 7.0, [])


def test_executive_financial_line_has_no_severity_keyed_dollar_figures():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        html = gir.build_report_sections(dict(ZERO_IOC_CVE, severity=sev))
        i = html.find("FINANCIAL EXPOSURE")
        row = _text(html[i:i + 800])
        assert "$" not in row.split("REGULATORY EXPOSURE")[0], sev


# ── 3. Narrative engine ──────────────────────────────────────────────────────

_NARRATIVES = sorted(a for a in dir(narr) if a.startswith("_narrative_"))


@pytest.mark.parametrize("fn", _NARRATIVES)
@pytest.mark.parametrize("n", [0, 1, 2])
def test_narratives_never_instruct_on_zero_or_misplural_iocs(fn, n):
    item = {"id": "x", "title": "CVE-2026-1234 test threat", "description": "d", "severity": "CRITICAL",
            "iocs": [{"type": "ipv4", "value": f"198.51.100.{i}"} for i in range(n)], "cvss_score": 9.0}
    txt = _text(getattr(narr, fn)(item))
    assert not re.search(r"\b0 (network )?IOCs?\b|\ball 0\b|\b0 indicators?\b|\b1 IOCs\b", txt), txt


# ── 4. report_enhancer.py (in-place HTML enhancement, v131 STEP 7) ───────────

def test_enhancer_detection_never_uses_placeholder_targets_or_generic_yara():
    item = dict(ZERO_IOC_CVE, sigma_rule="title: real rule\nlogsource: {}\ndetection: {}")
    txt = _text(enh.build_detection_rules_section(item))
    assert "example.com" not in txt
    assert "YARA Rule" not in txt
    assert "real rule" in txt
    assert "no IOC-based SIEM queries are generated" in txt


def test_enhancer_detection_uses_real_domains_when_present():
    item = dict(ZERO_IOC_CVE, sigma_rule="title: r", iocs=[{"type": "domain", "value": "bad.test"}])
    txt = _text(enh.build_detection_rules_section(item))
    assert 'dest="bad.test"' in txt and "example.com" not in txt


def test_enhancer_playbook_zero_iocs_and_missing_cvss():
    txt = _text(enh.build_soc_playbook_section(dict(ZERO_IOC_RANSOM, cvss_score="N/A")))
    assert "Block all" not in txt and "CVSS" not in txt
    txt = _text(enh.build_soc_playbook_section(dict(ZERO_IOC_CVE, iocs=[{"v": 1}] * 3, ioc_count=3)))
    assert "3 published IOCs" in txt and "(CVSS 7.5)" in txt


@pytest.mark.parametrize("sev", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_enhancer_business_impact_has_no_fixed_figures(sev):
    txt = _text(enh.build_business_impact_section(dict(ZERO_IOC_CVE, severity=sev)))
    for pat in (r"\$", r"Stock", r"\bROI\b", r"127 days", r"\d+x ROI"):
        assert not re.search(pat, txt), (sev, pat)
    assert "UNKNOWN" in txt


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
