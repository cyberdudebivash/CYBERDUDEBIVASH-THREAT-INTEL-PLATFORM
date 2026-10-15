"""GENESIS shows measured figures only, from one engine.

The homepage GENESIS grid and api/engines.json used to show an 8-region
sensor network, 8/18 honeypots, 9 monitored dark-web sources, 4 TAXII
collections, attack flows with a random source country and rule counts
padded with constants -- none of it measured. Two implementations produced
it (agent/v43_genesis/genesis_engine.py and a second GENESIS inside
scripts/regenerate_engine_data.py), and the homepage recomputed its own tiles
on every poll on top of both. These checks keep one engine, computing from
feed items only, with the capabilities the platform does not operate
reported as such. No network.
"""
from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

ENGINE_SRC = (REPO / "agent/v43_genesis/genesis_engine.py").read_text(encoding="utf-8")
REGEN_SRC = (REPO / "scripts/regenerate_engine_data.py").read_text(encoding="utf-8")
WORKER = (REPO / "workers/intel-gateway/src/index.js").read_text(encoding="utf-8")
DETECT_REG = (REPO / "workers/intel-gateway/src/detection-registry.js").read_text(encoding="utf-8")
FRONT = (REPO / "js/homepage-dashboard-engine.js").read_text(encoding="utf-8")

ITEMS = [
    {"title": "CVE-2026-0001 RCE in Cisco by APT28", "risk_score": 9.4, "actor_tag": "APT28",
     "kev_present": True, "feed_source": "CISA", "attck_technique_ids": ["T1190"],
     "sigma_rule": "title: x", "published_at": "2026-09-20T00:00:00Z"},
    {"title": "LockBit ransomware leak", "risk_score": 7.0, "actor_tag": "UNC-CDB-INGEST",
     "feed_source": "BleepingComputer", "actor_country": "Unknown"},
    {"title": "Generic advisory", "risk_score": 3.0, "actor_tag": "CDB-UNATTR-CVE", "feed_source": "nvd_cve"},
]


def _genesis():
    from agent.v43_genesis import genesis_engine
    return importlib.reload(genesis_engine)


def _code(src: str) -> str:
    """Source without comments/docstrings, so explanations of removed values don't count."""
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return "\n".join(l for l in src.splitlines() if not l.strip().startswith(("#", "//")))


def test_engine_has_no_random_or_invented_telemetry():
    code = _code(ENGINE_SRC)
    assert not re.search(r"^\s*import .*\brandom\b|\brandom\.", code, re.M)
    assert not re.search(r"(?<![\w.])hash\(", code), "Python hash() is randomised per process"
    for banned in ("amplification", "uptime_pct", "SENSOR_REGIONS", "HONEYPOT_TYPES", "MONITORED_SOURCES",
                   "api.cyberdudebivash.com", "wss://", "sandbox_config", "scan_capabilities",
                   "monitoring_capabilities", "_infer_source", "top_credentials"):
        assert banned not in code, banned


def test_not_operated_capabilities_say_so():
    g = _genesis()
    s = g.GlobalCyberSensorNetwork().generate_telemetry(ITEMS)
    h = g.HoneypotGrid().generate_grid_telemetry(ITEMS)
    d = g.DarkWebIntelligence().generate_darkweb_report(ITEMS)
    assert (s["operated"], s["sensors_operated"], s["source_count"]) == (False, 0, 3)
    assert (h["operated"], h["honeypots_operated"], h["kev_confirmed"]) == (False, 0, 1)
    assert (d["operated"], d["sources_monitored"], d["relevant_advisories"]) == (False, 0, 1)
    for r in (s, h, d):
        assert "not operated" in r["note"].lower() or "no " in r["note"].lower()


def test_placeholder_actor_tags_are_not_actors_or_campaigns():
    g = _genesis()
    reg = g.ThreatActorIntelRegistry().build_registry(ITEMS)
    assert [a["name"] for a in reg["actors"]] == ["APT28"]
    assert reg["unattributed_advisories"] == 2
    camp = g.CampaignCorrelationEngine().correlate(ITEMS * 2)
    assert {c["actor"] for c in camp["campaigns"]} == {"APT28"}


def test_attack_map_never_produces_flows_or_guessed_origins():
    g = _genesis()
    for _ in range(5):
        m = g.GlobalAttackMap().generate_map_data(ITEMS)
        assert (m["total_flows"], m["attack_flows"], m["origin_countries"]) == (0, [], {})
    body = _code(ENGINE_SRC)
    body = body[body.index("def generate_map_data"):body.index("class AIThreatHuntingEngine")]
    assert "source_country" not in body
    assert 'e.get("actor_country")' in body
    assert 'e.get("target_country") or e.get("victim_country")' in body


def test_detection_counts_only_rules_attached_to_items():
    g = _genesis()
    p = g.AutoDetectionGenerator().generate_full_pack(ITEMS)
    assert p["total_rules"] == 1 and p["sigma_count"] == 1
    # Same field map as the Worker's detection registry.
    for kind, field in g.DETECTION_FIELDS.items():
        assert f"{kind}: '{field}'" in DETECT_REG


def test_taxii_collections_match_what_the_worker_serves():
    g = _genesis()
    ids = [c["id"] for c in g.TAXIIServer.COLLECTIONS]
    served = [re.search(rf'const {name}\s*=\s*"([^"]+)"', WORKER).group(1)
              for name in ("TAXII_COLLECTION_ID", "TAXII_KEV_COLL")]
    assert ids == served
    assert "dark web findings" not in WORKER


def test_regenerate_engine_data_delegates_to_the_canonical_engine():
    body = REGEN_SRC[REGEN_SRC.index("def generate_genesis("):REGEN_SRC.index("# CORTEX")]
    assert "GenesisOrchestrator().compute(items)" in body
    for banned in ("honeypot_count", "sources_monitored", "min(9999", "+ 280", "+ 480", "122.3", "HUNT_TEMPLATES"):
        assert banned not in _code(body), banned
    import regenerate_engine_data as regen
    regen = importlib.reload(regen)
    out = regen.generate_genesis(ITEMS)
    m = out["metrics"]
    assert (m["sensor_count"], m["honeypots"], m["darkweb_sources"], m["total_flows"]) == (0, 0, 0, 0)
    assert m["taxii_collections"] == 2 and m["feed_sources"] == 3 and m["actors_tracked"] == 1
    canon, _ = _genesis().GenesisOrchestrator().compute(ITEMS)
    strip = lambda e: {k: {kk: vv for kk, vv in v["summary"].items() if not kk.endswith("_id") and kk != "generated_at"}
                       for k, v in e.items()}
    assert strip(out["engines"]) == strip(canon["engines"])


def test_published_engines_json_is_honest():
    api = json.loads((REPO / "api/engines.json").read_text(encoding="utf-8"))
    ph = api["platform_health"]
    assert (ph["sensor_count"], ph["honeypots"], ph["darkweb_sources"], ph["total_flows"]) == (0, 0, 0, 0)
    assert ph["taxii_collections"] == 2
    for key in ("G01_SensorNetwork", "G02_HoneypotGrid", "G09_DarkWebIntel"):
        assert api["engines"][key]["summary"]["operated"] is False, key


def test_homepage_tiles_come_from_the_engine_only():
    code = _code(FRONT)
    for banned in ("'8 REGIONS'", "'8 TRAPS'", "'4 FEEDS'", "'9 SOURCES'", "ENGINES LIVE",
                   "s.sensor_count", "s.honeypot_count", "s.sources_monitored", "|| '4'", "|| '9'",
                   "Samples analyzed", "Rules generated", "Monitored darkweb", "Known APT Groups", "Newly Discovered"):
        assert banned not in code, banned
    fallback = FRONT[FRONT.index("function renderGenesis(data) {"):FRONT.index("const _origCM3 = computeMetrics;")]
    assert "if (window.__CDB_GENESIS_RENDERED) return;" in fallback
    assert not re.search(r"\bval\s*:", _code(fallback)), "fallback must not compute tile values"
    loader = FRONT[FRONT.index("function renderGenesisEngine(data) {"):FRONT.index("function renderCortexEngine(data)")]
    assert "window.__CDB_GENESIS_RENDERED = true;" in loader
    for label in ("Feed Sources", "Exploitation", "Detection Rules", "Ransomware & Leaks", "dark-web monitoring not operated"):
        assert label in loader, label
    assert "${esc(val)}" in loader and "${esc(desc)}" in loader
    assert FRONT.count("getElementById('nexus-rules-count')") == 1
    assert "else if (g7) paintAttachedRules(null, g7);" in FRONT


def test_deprecated_v2_engine_is_not_run():
    v2 = (REPO / "agent/v43_genesis/genesis_engine_v2.py").read_text(encoding="utf-8")
    assert "DEPRECATED" in v2[:400]
    for wf in (REPO / ".github/workflows").glob("*.yml"):
        assert "genesis_engine_v2" not in wf.read_text(encoding="utf-8"), wf.name
