"""P0: weekly summary must never advertise report URLs rejected by /reports/**."""
import copy
import pytest

from scripts import reconcile_weekly_report_links as gate

OK = "https://intel.cyberdudebivash.com/reports/2026/10/intel--7298190f5e14921363b1fece.html"
NO = "https://intel.cyberdudebivash.com/reports/2026/10/intel--64f2aa61d697e19ee6b23fcb.html"
ALLOWED = "intel--7298190f5e14921363b1fece"


def payload(*links):
    return {
        "_schema": "sentinel-apex-weekly-brief-v1",
        "week": "Week 42 2026",
        "top_threats": [
            {"title": f"Verified public briefing item {i}", "tlp": "TLP:CLEAR", "report_url": url}
            for i, url in enumerate(links)
        ],
        "kev_additions": [],
    }


def test_customer_approved_report_is_linked_without_mutating_source():
    doc = payload(OK)
    clone = copy.deepcopy(doc)
    got, stats = gate.reconcile(doc, approve=lambda slug: slug == ALLOWED)
    assert got["top_threats"][0]["report_url"] == OK
    assert stats == {"linked": 1, "withheld": 0, "unlinked": 0}
    assert got["report_link_verification"]["policy"] == "CUSTOMER_READY_ONLY"
    assert doc == clone


def test_publication_rejected_report_is_text_only_not_broken_link():
    got, stats = gate.reconcile(payload(NO), approve=lambda _: False)
    assert got["top_threats"][0]["report_url"] == ""
    assert stats["withheld"] == 1
    assert got["top_threats"][0]["title"]


@pytest.mark.parametrize("link", [
    "javascript:alert(1)",
    "http://intel.cyberdudebivash.com/reports/2026/10/intel--7298190f5e14921363b1fece.html",
    "https://evil.example/reports/2026/10/intel--7298190f5e14921363b1fece.html",
    "https://intel.cyberdudebivash.com/reports/2026/10/../admin.html",
    "https://intel.cyberdudebivash.com/reports/2026/10/intel--7298190f5e14921363b1fece.html?admin=1",
])
def test_untrusted_or_malformed_links_never_trigger_remote_checks(link):
    checked = []
    got, stats = gate.reconcile(payload(link), approve=lambda slug: checked.append(slug) or True)
    assert checked == []
    assert stats["withheld"] == 1
    assert not got["top_threats"][0]["report_url"]


def test_status_endpoint_requires_true_ready_and_exact_id(monkeypatch):
    class Fake:
        status_code = 200

        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    calls = []

    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        return Fake({"report_id": ALLOWED, "state": "REJECTED", "customer_ready": False})

    monkeypatch.setattr(gate.requests, "get", fetch)
    assert gate._approved(ALLOWED) is False
    assert calls[0][0] == f"{gate.BASE_URL}/api/v1/reports/{ALLOWED}/publication-status"
    assert calls[0][1]["allow_redirects"] is False
    monkeypatch.setattr(
        gate.requests, "get",
        lambda *_a, **_k: Fake({"report_id": "wrong", "state": "CUSTOMER_READY", "customer_ready": True}),
    )
    assert gate._approved(ALLOWED) is False
    monkeypatch.setattr(
        gate.requests, "get",
        lambda *_a, **_k: Fake({"report_id": ALLOWED, "state": "CUSTOMER_READY", "customer_ready": True}),
    )
    assert gate._approved(ALLOWED) is True


def test_status_network_errors_fail_closed(monkeypatch):
    def broken(*_args, **_kwargs):
        raise gate.requests.Timeout("simulated timeout")

    monkeypatch.setattr(gate.requests, "get", broken)
    assert gate._approved(ALLOWED) is False


def test_dedupes_report_status_checks_for_top_and_kev():
    doc = payload(OK, OK)
    doc["kev_additions"] = [{"title": "One KEV", "report_url": OK, "tlp": "TLP:CLEAR"}]
    calls = []
    out, stats = gate.reconcile(doc, approve=lambda slug: calls.append(slug) or True)
    assert calls == [ALLOWED]
    assert stats["linked"] == 3
    assert out["kev_additions"][0]["report_url"] == OK


def test_absent_links_stay_absent():
    out, stats = gate.reconcile(payload(""), approve=lambda _: (_ for _ in ()).throw(AssertionError("must not call")))
    assert out["top_threats"][0]["report_url"] == ""
    assert stats["unlinked"] == 1


@pytest.mark.parametrize("broken", [
    {}, {"top_threats": []}, {"top_threats": "not array"},
    {"top_threats": [{"title": "x"}], "kev_additions": "invalid"},
    {"top_threats": [None]}, {"top_threats": [{"title": "x"}]*11},
])
def test_invalid_shapes_fail_closed_without_any_remote_call(broken):
    with pytest.raises(ValueError):
        gate.reconcile(broken, approve=lambda _: (_ for _ in ()).throw(AssertionError("unexpected call")))


def test_workflow_reconciles_links_before_verify_and_r2_put():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / ".github/workflows/weekly-threat-brief.yml").read_text(encoding="utf-8")
    check = text.index("python3 scripts/reconcile_weekly_report_links.py")
    verify = text.index("python3 scripts/check_weekly_brief.py")
    upload = text.index("scripts/r2_upload.py --weekly-brief-only")
    assert check < verify < upload


def test_customer_frontend_fail_closes_on_pre_gate_weekly_payloads():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "weekly-brief.html").read_text(encoding="utf-8")
    assert "const link = linkVerified ? safeReportLink(item.report_url) : null;" in text
    assert "brief.report_link_verification.policy === 'CUSTOMER_READY_ONLY'" in text
    assert 'id="report-links-status"' in text
