"""
Customer-visible release label governance (v201 convergence).

#503 unified the version SSOT and governed surfaces on v201.0, but 22 root
pages still showed "SENTINEL APEX v184.0" / "v200.0" in visible titles,
footers and banners, which scripts/version_governance.py does not cover.
scripts/customer_release_label.py closes that gap; these tests keep it
closed and prove the checker is not vacuous.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("crl", REPO / "scripts" / "customer_release_label.py")
crl = importlib.util.module_from_spec(_spec)
sys.modules["crl"] = crl
_spec.loader.exec_module(crl)


def test_every_page_shows_the_current_release():
    ver = crl.current()
    bad = {p.name: crl.drift(p, ver) for p in sorted(REPO.glob("*.html"))}
    assert {k: v for k, v in bad.items() if v} == {}


def test_release_is_the_version_ssot():
    assert crl.current() == (REPO / "config" / "platform_version.json").read_text().split('"version": "')[1].split('"')[0]


def _page(tmp_path, body):
    p = tmp_path / "x.html"
    p.write_text(body, encoding="utf-8")
    return crl.drift(p, "201.0")


def test_stale_visible_labels_are_caught(tmp_path):
    assert _page(tmp_path, "<footer>SENTINEL APEX v184.0</footer>")
    assert _page(tmp_path, "<title>X &mdash; SENTINEL APEX&trade; v200.0</title>")
    assert _page(tmp_path, '<span>LIVE INTEL API &mdash; v200.0</span>')
    assert _page(tmp_path, '<meta content="CYBERDUDEBIVASH® SENTINEL APEX v184.0 — Hub">')
    assert _page(tmp_path, '<script type="application/ld+json">{"name":"SENTINEL APEX v184.0"}</script>')


def test_invisible_text_and_component_versions_are_ignored(tmp_path):
    assert not _page(tmp_path, "<!-- SENTINEL APEX v184.0 history -->")
    assert not _page(tmp_path, "<style>/* SENTINEL APEX v184.0 card system */</style>")
    assert not _page(tmp_path, "<script>const note='SENTINEL APEX v184.0';</script>")
    assert not _page(tmp_path, "<p>Cyber Watchdog v3.0.0, webhook contract 2026-09</p>")
    assert not _page(tmp_path, "<footer>SENTINEL APEX v201.0</footer>")


def test_apply_rewrites_only_the_version(tmp_path):
    p = tmp_path / "x.html"
    p.write_text("<b>SENTINEL APEX v184.0</b><!-- SENTINEL APEX v184.0 -->", encoding="utf-8")
    assert crl.apply(p, "201.0") == 1
    assert p.read_text() == "<b>SENTINEL APEX v201.0</b><!-- SENTINEL APEX v184.0 -->"
