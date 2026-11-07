"""P0: never sell HTML as PDF; keep binary files, links and manifests truthful.

All artifact writes in these tests occur in pytest tmp_path; no network, R2,
production feed, customer artifact or credential is accessed.
"""
from __future__ import annotations

import builtins
import json
import os
import sys
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import report_enhancer as legacy
import generate_advisory_pdfs as active

VALID_PDF = b"%PDF-1.7\n" + b"0" * 700 + b"\n%%EOF\n"
INVALID_HTML = b"<!DOCTYPE html><html><body>not a PDF</body></html>" + b"x" * 700
ITEM = {"id": "intel--p0-synthetic", "title": "Synthetic advisory", "tlp": "TLP:CLEAR",
        "severity": "HIGH", "pdf_url": "/reports/pdf/intel--p0-synthetic.pdf",
        "pdf_available": True}


def _fake_renderer(monkeypatch, value):
    module = types.ModuleType("weasyprint")

    class HTML:
        def __init__(self, string):
            assert "<html" in string
        def write_pdf(self):
            if isinstance(value, Exception):
                raise value
            return value

    module.HTML = HTML
    monkeypatch.setitem(sys.modules, "weasyprint", module)


def _active_manifest(tmp_path, monkeypatch, data=ITEM):
    manifest = tmp_path / "feed.json"
    manifest.write_text(json.dumps([dict(data)]), encoding="utf-8")
    monkeypatch.setattr(active, "MANIFEST_CANDIDATES", [manifest])
    monkeypatch.setattr(active, "PDF_DIR", tmp_path / "pdf")
    monkeypatch.setattr(active, "REPO_ROOT", tmp_path)
    (tmp_path / "pdf").mkdir(exist_ok=True)
    return manifest, tmp_path / "pdf" / (data["id"] + ".pdf")


def _active_pdf_generator(monkeypatch, value):
    module = types.ModuleType("generate_premium_pdf")
    def generate_pdf(_report):
        if isinstance(value, Exception):
            raise value
        return value
    module.generate_pdf = generate_pdf
    monkeypatch.setitem(sys.modules, "generate_premium_pdf", module)


def test_legacy_missing_converter_never_writes_html_under_pdf_suffix(tmp_path, monkeypatch):
    out = tmp_path / "intel.pdf"
    existing = VALID_PDF
    out.write_bytes(existing)
    original_import = builtins.__import__

    def deny_weasy(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("simulated missing optional converter")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny_weasy)
    assert legacy.generate_pdf_report(dict(ITEM), "<html>printable</html>", out) is False
    assert out.read_bytes() == existing


@pytest.mark.parametrize("bad_value", [INVALID_HTML, b"%PDF" + b"0" * 900,
                                        b"%PDF-" + b"0" * 8,
                                        RuntimeError("simulated rendering failure")])
def test_legacy_invalid_or_failed_render_preserves_original_bytes(tmp_path, monkeypatch, bad_value):
    out = tmp_path / "intel.pdf"
    out.write_bytes(VALID_PDF)
    _fake_renderer(monkeypatch, bad_value)
    assert legacy.generate_pdf_report(dict(ITEM), "<html>printable</html>", out) is False
    assert out.read_bytes() == VALID_PDF


def test_legacy_real_pdf_is_atomic_and_format_checked(tmp_path, monkeypatch):
    out = tmp_path / "intel.pdf"
    out.write_bytes(INVALID_HTML)
    _fake_renderer(monkeypatch, VALID_PDF)
    assert legacy.generate_pdf_report(dict(ITEM), "<html>printable</html>", out)
    assert out.read_bytes() == VALID_PDF
    assert legacy._is_real_pdf_artifact(out)


def test_legacy_report_download_action_requires_verified_manifest(tmp_path):
    # Directly inspect a real sanitized fixture instead of inventing IOC/ATT&CK context.
    fixture = json.loads((ROOT / "tests" / "fixtures" / "dossier_p0_721_real_records.json").read_text(encoding="utf-8"))
    item = dict(fixture["records"][0])
    item["tlp"] = "TLP:CLEAR"
    item["pdf_available"] = False
    item.pop("pdf_url", None)
    html = "<html><body><p>Preserve actual source content.</p></body></html>"
    first = legacy.enhance_report_html(html, item, "free")
    assert "Download PDF" not in first
    assert "Preserve actual source content." in first
    item["pdf_available"] = True
    later = legacy.enhance_report_html(html, item, "free")
    assert "Download PDF" in later


def test_active_generator_clears_fake_download_metadata_on_failure(tmp_path, monkeypatch):
    manifest, path = _active_manifest(tmp_path, monkeypatch)
    path.write_bytes(INVALID_HTML)
    _active_pdf_generator(monkeypatch, INVALID_HTML)
    active.main()
    saved = json.loads(manifest.read_text(encoding="utf-8"))[0]
    assert saved["pdf_available"] is False
    assert "pdf_url" not in saved
    assert path.read_bytes() == INVALID_HTML  # no unauthorised bulk clean/delete
    assert not list(path.parent.glob("*.tmp"))


def test_active_generator_writes_real_pdf_and_repairs_manifest(tmp_path, monkeypatch):
    manifest, path = _active_manifest(tmp_path, monkeypatch)
    path.write_bytes(INVALID_HTML)
    _active_pdf_generator(monkeypatch, VALID_PDF)
    active.main()
    saved = json.loads(manifest.read_text(encoding="utf-8"))[0]
    assert path.read_bytes() == VALID_PDF
    assert saved["pdf_available"] is True
    assert saved["pdf_url"] == "/reports/pdf/intel--p0-synthetic.pdf"
    assert not list(path.parent.glob("*.tmp"))


def test_active_generator_preserves_valid_old_pdf_if_regeneration_fails(tmp_path, monkeypatch):
    manifest, path = _active_manifest(tmp_path, monkeypatch)
    path.write_bytes(VALID_PDF)
    old = time.time() - 86400 * 2
    os.utime(path, (old, old))
    _active_pdf_generator(monkeypatch, RuntimeError("test renderer unavailable"))
    active.main()
    assert path.read_bytes() == VALID_PDF
    saved = json.loads(manifest.read_text(encoding="utf-8"))[0]
    assert saved["pdf_available"] is True
    assert saved["pdf_url"] == "/reports/pdf/intel--p0-synthetic.pdf"


def test_active_generator_reconciles_valid_existing_pdf_without_regeneration(tmp_path, monkeypatch):
    manifest, path = _active_manifest(tmp_path, monkeypatch,
                                     {**ITEM, "pdf_available": False, "pdf_url": ""})
    path.write_bytes(VALID_PDF)
    _active_pdf_generator(monkeypatch, RuntimeError("must not regenerate fresh PDF"))
    active.main()
    saved = json.loads(manifest.read_text(encoding="utf-8"))[0]
    assert saved["pdf_available"] is True
    assert saved["pdf_url"] == "/reports/pdf/intel--p0-synthetic.pdf"
    assert path.read_bytes() == VALID_PDF


def test_pdf_renderer_source_claims_require_customer_evidence():
    """New P0 PDF source-claim checks run in the existing mandatory PDF job.

    AST validation avoids introducing ReportLab into the lightweight CI
    environment; real PDF rendering remains a separate release gate.
    """
    import ast
    source = (ROOT / "scripts" / "generate_premium_pdf.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    funcs = {n.name: ast.get_source_segment(source, n) for n in tree.body
             if isinstance(n, ast.FunctionDef)}
    fin = funcs["_section_financial"]
    det = funcs["_section_detection"]
    assert "FINANCIAL LOSS: NOT ASSESSED" in fin
    assert "_get_financial(" not in fin and "$" not in fin
    assert "IBM Cost of Breach" not in fin
    assert "syntax_tested" in det and "scenario_tested" in det
    assert 'obj["source_url"].startswith("https://")' in det
    assert "NOT VALIDATED" in det and "_SIGMA_TEMPLATES" not in det
    assert "Deploy the Sigma detection rule" not in funcs["_normalize"]
    assert "Deploy Sigma and KQL detection rules" not in funcs["_section_playbook"]
    assert "Rotate all API keys" not in funcs["_section_playbook"]


def test_pdf_report_never_promotes_unverified_prose_to_observed_attack_mapping():
    import ast
    source = (ROOT / "scripts" / "generate_premium_pdf.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    funcs = {n.name: ast.get_source_segment(source, n) for n in tree.body
             if isinstance(n, ast.FunctionDef)}
    normalized = funcs["_normalize"]
    assert "Auto-derive from title if still empty" not in normalized
    assert "Only structured upstream mappings enter this report." in normalized
    assert "Techniques observed:" not in funcs["_section_mitre"]
    assert "v15 Mapping" not in funcs["_section_mitre"]
    assert '("ATT&CK Version", "v15")' not in funcs["_section_appendix"]


def test_store_enterprise_report_promises_remain_evidence_gated():
    """Customer-facing product claims must agree with premium PDF evidence gates."""
    html = (ROOT / "store.html").read_text(encoding="utf-8")
    section = html.split('<section id="reports">', 1)[1].split("</section>", 1)[0]
    for forbidden in ("FAIR MODEL", "FAIR financial impact", "$1M", "ready-to-deploy",
                      "Top 10 risks prioritized by financial impact", "MITRE v15",
                      "Organization risk posture score"):
        assert forbidden not in section, forbidden
    for required in ("EVIDENCE-LINKED",
                     "Customer financial impact and exposure not assessed",
                     "Detection logic only when validation evidence is attached",
                     "Customer exposure marked unknown until assets and controls are assessed",
                     "PDF download offered only when a genuine PDF exists"):
        assert required in section, required


def test_store_report_buyer_journey_preserves_plan_prices_and_permissioned_leads():
    html = (ROOT / "store.html").read_text(encoding="utf-8")
    section = html.split('<section id="reports">', 1)[1].split("</section>", 1)[0]
    assert '/upgrade.html?plan=pro&amp;feature=premium-reports' in section
    assert '<span class="curr">$</span>49' in section
    assert '<span class="curr">$</span>299' in section
    assert '<span class="curr">$</span>99' in section
    assert '<span style="font-size:28px;">$599</span>' in section
    assert "mailto:contact@cyberdudebivash.in?subject=Enterprise+CTI+Report+Scope+Request" in section
    assert "mailto:contact@cyberdudebivash.in?subject=Executive+Risk+Report+Scope" in section
    assert "Technology+stack%3A" in section
    assert "Procurement+timeline%3A" in section
    assert "subject=Custom+Intel+Package+Request" in section
    assert "Budget+approval%3A" in section
    assert "Required+deliverables%3A" in section
    assert "confirm deliverables and availability before a separate engagement" in section



def test_pro_lead_modal_displays_canonical_paid_offer_without_unverified_promises():
    """Homepage lead popup must not sell phantom advisories or deployable rules."""
    import json
    root = ROOT
    contract = json.loads((root / "config/commercial-contract.json").read_text(encoding="utf-8"))
    pro = contract["tiers"]["pro"]
    assert (pro["usd_monthly"], pro["requests_per_day"],
            pro["requests_per_minute"], pro["api_keys"], pro["seats"]) == (49, 5000, 120, 10, 1)
    html = (root / "index.html").read_text(encoding="utf-8")
    assert '<div id="apex-lead-modal"' in html
    dialog = html.split('<div id="apex-lead-modal"', 1)[1].split("<script>", 1)[0]
    for unsupported in ("500 advisories/day", "Deploy-ready Sigma",
                        "MITRE ATT&amp;CK v15 mapping",
                        "START FREE 7-DAY TRIAL"):
        assert unsupported not in dialog, unsupported
    for verified in ("5,000 API requests/day", "120 requests/min",
                     "10 API keys", "1 seat", "$49 due at checkout",
                     "validate against your telemetry before deployment",
                     "This is not a free trial."):
        assert verified in dialog, verified


def test_pro_lead_submit_preserves_verified_checkout_without_premature_payment_claims():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "window.location.href = '/upgrade.html?plan=pro&utm_source=lead-modal&utm_medium=timed-popup';" in html
    assert "sessionStorage.setItem('apex_lead_email', email)" in html
    assert "UPGRADE NOW" in html or "CONTINUE TO PRO" in html
    # A lead referral does not itself establish captured payment or active access.
    modal = html.split('<div id="apex-lead-modal"', 1)[1].split("<script>", 1)[0]
    assert "Instant activation" not in modal
    assert "Activates on payment confirmation" not in modal or "This is not a free trial." in modal



def test_assisted_detection_bundle_does_not_promise_instant_fulfillment():
    """A mailto lead is not an automated paid checkout/download."""
    html = (ROOT / "store.html").read_text(encoding="utf-8")
    packs = html.split('<section id="detection-packs">', 1)[1].split("</section>", 1)[0]
    bundle = packs.split('<div class="product-name">APT Intelligence Full Bundle</div>', 1)[1]
    assert '<div class="product-price"><span class="curr">$</span>499</div>' in bundle
    assert "save $128" in bundle
    assert "instant download" not in bundle
    assert "assisted order &middot; delivery after confirmation" in bundle
    assert "subject=APT+Full+Bundle+Purchase&amp;body=" in bundle
    assert "Target+SIEM%2FEDR%3A" in bundle
    assert "Approval+to+receive+a+quote%3A" in bundle
    assert "Request Full Bundle Quote" in bundle



def test_default_pdf_recommendations_do_not_order_unverified_disruptive_changes():
    """Generic severity must not trigger forced credential rotations or blind patching."""
    import ast
    source = (ROOT / "scripts" / "generate_premium_pdf.py").read_text(encoding="utf-8")
    mod = ast.parse(source)
    normalize = next(n for n in mod.body
                     if isinstance(n, ast.FunctionDef) and n.name == "_normalize")
    code = ast.get_source_segment(source, normalize)
    assert "Rotate credentials and API keys for any services co-located" not in code
    assert "Apply vendor patch for {title} immediately" not in code
    assert "rotate only when compromise evidence or vendor guidance supports it" in code
    assert "vendor-approved remediation" in code
    assert "customer change process" in code



def test_pdf_ioc_confidence_is_unknown_without_explicit_evidence():
    """Source-specific confidence scales are explicit and missing stays unknown."""
    import ast
    import math
    source = (ROOT / "scripts" / "generate_premium_pdf.py").read_text(encoding="utf-8")
    parsed = ast.parse(source)
    funcs = {n.name: n for n in parsed.body if isinstance(n, ast.FunctionDef)}
    normalized = ast.get_source_segment(source, funcs["_normalize"])
    iocs = ast.get_source_segment(source, funcs["_section_iocs"])
    assert 'i.get("confidence")' in normalized
    assert 'i.get("confidence", 0.7)' not in normalized
    assert '"confidence_scale": i.get("confidence_scale") or i.get("confidence_unit")' in normalized
    assert 'ioc.get("confidence_scale") or ioc.get("confidence_unit")' in iocs
    assert "Ingest directly into your SIEM" not in iocs
    assert "No IOC values were supplied with this report" in iocs
    # Execute only the side-effect-free formatter; optional ReportLab is not
    # installed in this lightweight gate.
    namespace = {"Any": object, "Optional": __import__("typing").Optional, "math": math}
    code = compile(ast.Module(body=[funcs["_ioc_confidence_display"]],
                              type_ignores=[]), "<synthetic-ioc-contract>", "exec")
    exec(code, namespace)
    fmt = namespace["_ioc_confidence_display"]
    cases = [
        (None, None, "Not assessed"), (True, None, "Not assessed"),
        (False, None, "Not assessed"), ("invalid", None, "Not assessed"),
        (float("nan"), None, "Not assessed"),
        (float("inf"), None, "Not assessed"),
        (-1, None, "Not assessed"), (101, None, "Not assessed"),
        (0, None, "0%"), (1, None, "Not assessed"),
        (0.7, None, "Not assessed"), (1.0, None, "Not assessed"),
        (85, None, "85%"), (85.0, None, "85%"),
        (85.5, None, "Not assessed"), ("85", None, "Not assessed"),
        (0.7, "fraction", "70%"), (0.7, "percent", "0.7%"),
        (1, "stix", "1%"), (1, "fraction", "100%"),
        ("85", "stix", "85%"), ("85", None, "Not assessed"),
        (99.9, "0-100", "99.9%"), (0.85, "0-1", "85%"),
        (105, "0-100", "Not assessed"), (2, "fraction", "Not assessed"),
        (0.8, "unknown", "Not assessed"), (100, "stix", "100%"),
    ]
    for value, scale, expected in cases:
        assert fmt(value, scale) == expected, (value, scale, expected)


def test_pdf_report_empty_ioc_state_does_not_promise_unproved_delivery():
    import ast
    source = (ROOT / "scripts" / "generate_premium_pdf.py").read_text(encoding="utf-8")
    nodes = ast.parse(source).body
    method = next(n for n in nodes
                  if isinstance(n, ast.FunctionDef) and n.name == "_section_iocs")
    text = ast.get_source_segment(source, method)
    assert "No IOC values were supplied" in text
    assert "approved, entitled exports" in text
    assert "customer-applicable telemetry" in text
    for unsupported in ("real-time IOC push", "Ingest directly into",
                        "Full IOC packages include"):
        assert unsupported not in text
