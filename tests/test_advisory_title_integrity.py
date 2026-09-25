"""Advisory titles come from the advisory, never from a pipeline label.

Live 2026-09-25: 3 of 5 dashboard "campaigns" had titles the pipeline wrote
("Phishing Campaign -- Credential Harvesting Operation", "CDB-MOB-02
Campaign") over headlines about an Ethereum bridge hack, smart-TV proxies
and streaming sticks. Two layers produced them:

  * run_pipeline.py re-ingests the platform's own STIX bundles and used the
    intrusion-set name -- an actor-cluster label -- as the title;
  * intelligence_quality_hardener.py rewrote those labels into invented
    headlines, some naming actors (APT41, Sandworm) the advisory never
    mentions.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hardener = _load("intelligence_quality_hardener")
pipeline = _load("run_pipeline")


def test_stix_reingest_uses_the_headline_not_the_cluster_label():
    t = pipeline.stix_advisory_title
    assert t("CDB-UNATTR-PHI Campaign", "OpenAI Pauses Astra Model Over Critical Cybersecurity Risk Concerns") == \
        "OpenAI Pauses Astra Model Over Critical Cybersecurity Risk Concerns"
    assert t("CDB-MOB-02 Campaign", "Read This Before You Buy That TV Streaming Stick\nmore text") == \
        "Read This Before You Buy That TV Streaming Stick"
    assert t("UNC-CDB-99", "Headline") == "Headline"
    # Real names and CVE ids are kept; nothing is invented without a description.
    assert t("Konni Malware Campaign", "x") == "Konni Malware Campaign"
    assert t("CVE-2026-1234", "x") == "CVE-2026-1234"
    assert t("CDB-UNATTR-APT Campaign", "") == "CDB-UNATTR-APT Campaign"
    assert len(t("CDB-UNATTR-APT Campaign", "A" * 500)) == 200


def test_reingest_path_calls_the_title_guard():
    src = (ROOT / "scripts" / "run_pipeline.py").read_text(encoding="utf-8")
    assert 'raw_title = stix_advisory_title(raw_title, intset.get("description", ""))' in src


def test_hardener_never_invents_a_title():
    templates = {replacement for _, replacement in hardener.TITLE_PATTERNS}
    for pattern, replacement in hardener.TITLE_PATTERNS:
        label = pattern.pattern.strip("^$").replace("\\", "")
        with_desc = {"title": label, "description": "Real source headline"}
        assert hardener._improve_title(with_desc) is True
        assert with_desc["title"] == "Real source headline"
        assert with_desc["_orig_title"] == label
        no_desc = {"title": label, "description": ""}
        hardener._improve_title(no_desc)
        assert no_desc["title"] not in templates, "no template is ever written"


def test_hardener_restores_titles_fabricated_by_earlier_runs():
    item = {
        "title": "Phishing Campaign — Credential Harvesting Operation",
        "_orig_title": "CDB-UNATTR-PHI Campaign",
        "description": "Hackers Exploited Ethereum Bridge Contract to Drain Full Balance from Payy Network",
    }
    assert hardener._improve_title(item) is True
    assert item["title"].startswith("Hackers Exploited Ethereum Bridge")
    assert item["_orig_title"] == "CDB-UNATTR-PHI Campaign", "earliest label kept for lineage"


def test_hardener_leaves_real_titles_alone():
    for title in ["Fake PDF Files Hide Konni Malware Campaign Targeting Ukraine Organizations",
                  "CISA: Ransomware gangs now exploiting critical TeamCity flaw"]:
        item = {"title": title, "description": "something else"}
        assert hardener._improve_title(item) is False
        assert item["title"] == title


def test_worker_recognises_the_same_template_titles():
    """dashboard-contract.js pins the hardener's templates; keep them in sync."""
    js = (ROOT / "workers" / "intel-gateway" / "src" / "dashboard-contract.js").read_text(encoding="utf-8")
    block = js[js.index("const HARDENER_TEMPLATE_TITLES"):js.index("]);", js.index("const HARDENER_TEMPLATE_TITLES"))]
    pinned = {json.loads('"' + s + '"') for s in re.findall(r'"((?:[^"\\]|\\.)*)"', block)}
    assert pinned == {replacement for _, replacement in hardener.TITLE_PATTERNS}
