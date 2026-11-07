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
    assert "confirm deliverables and availability before a separate engagement" in section
