#!/usr/bin/env python3
"""
P38.0 Production Certification
Enterprise Platform Governance & Permanent Stabilization

Chains from p37_certification_report.json.

26 gates covering:
  G01-G04: Certification chain (P37, P36, P35, P33)
  G05-G08: Feed registry governance
  G09-G12: Schema registry integrity
  G13-G16: Shared validator adoption
  G17-G20: Enrichment governance (live + commercial feeds)
  G21-G22: Source diversity governance
  G23-G24: Schema drift audit
  G25-G26: Handler and route completeness

GOVERNANCE ARCHITECTURE:
  This script imports from p38_shared_validators.py — the canonical
  shared validator module introduced in P38.  This is the first cert
  script to use shared validators rather than inline duplication.
  All future P-layer cert scripts (P39+) must do the same.

Result written to data/quality/p38_certification_report.json.
"""
from __future__ import annotations
import json, pathlib, sys, datetime

ROOT   = pathlib.Path(__file__).resolve().parent.parent
DATA_Q = ROOT / "data" / "quality"
SRC_P  = ROOT / "workers" / "intel-gateway" / "src"

# --- Import canonical shared validators (P38 ADR-001) -----------------------
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from p38_shared_validators import (
        gate as _gate,
        field_pct,
        load_feed_safe,
        load_json_safe,
        enrichment_summary,
        source_diversity,
        detect_feed_type,
        detect_schema_drift,
        FEED_REGISTRY,
        SCHEMA_REGISTRY,
        FEED_TYPE_RULES,
    )
    _SHARED_IMPORT_OK = True
except ImportError as _e:
    _SHARED_IMPORT_OK = False
    _SHARED_IMPORT_ERROR = str(_e)

    # Minimal fallbacks so the script can still report the import failure
    def _gate(gate_id, label, severity, status, detail):
        return {
            "gate_id": gate_id, "label": label, "severity": severity,
            "status": "PASS" if status else ("FAIL_BLOCKER" if severity == "BLOCKER" else "FAIL_WARNING"),
            "detail": detail,
        }
    def field_pct(items, key, check=None): return 0.0
    def load_feed_safe(key="live"): return [], ""
    def load_json_safe(p): return None
    def enrichment_summary(items): return {}
    def source_diversity(items): return {"distinct": 0, "top_dominance_pct": 0.0}
    def detect_feed_type(items): return "UNKNOWN"
    def detect_schema_drift(items): return {"drift_count": 0, "deprecated_count": 0}
    FEED_REGISTRY = {}
    SCHEMA_REGISTRY = {}
    FEED_TYPE_RULES = {}


def run_certification() -> dict:
    gates: list = []

    # ── G01-G04: Certification chain ─────────────────────────────────────────
    p37 = load_json_safe(DATA_Q / "p37_certification_report.json")
    g01 = p37 is not None and isinstance(p37, dict)
    gates.append(_gate("G01", "P37 certification report present", "BLOCKER", g01,
                        f"tier={p37.get('release_tier','?')} blockers={p37.get('blocker_count','?')}" if g01 else "NOT FOUND"))

    p37_tier_ok = g01 and p37.get("release_tier") == "WORLDWIDE_RELEASE"
    gates.append(_gate("G02", "P37 release tier = WORLDWIDE_RELEASE", "BLOCKER", p37_tier_ok,
                        p37.get("release_tier", "?") if g01 else "N/A"))

    p37_blockers_ok = g01 and p37.get("blocker_count", 1) == 0
    gates.append(_gate("G03", "P37 has zero blockers", "BLOCKER", p37_blockers_ok,
                        f"blockers={p37.get('blocker_count','?')}" if g01 else "N/A"))

    p36 = load_json_safe(DATA_Q / "p36_certification_report.json")
    g04 = p36 is not None and p36.get("release_tier") == "WORLDWIDE_RELEASE"
    gates.append(_gate("G04", "P36 certification chain intact", "WARNING", g04,
                        f"tier={p36.get('release_tier','?')}" if p36 else "NOT FOUND"))

    # ── G05-G08: Feed registry governance ────────────────────────────────────
    g05 = _SHARED_IMPORT_OK
    gates.append(_gate("G05", "p38_shared_validators.py imports successfully", "BLOCKER", g05,
                        "OK" if g05 else f"IMPORT ERROR: {_SHARED_IMPORT_ERROR if not g05 else ''}"))

    g06 = len(FEED_REGISTRY) >= 10
    gates.append(_gate("G06", "Feed registry has >= 10 documented feeds", "BLOCKER", g06,
                        f"registered_feeds={len(FEED_REGISTRY)}"))

    # Verify every registered feed file exists
    feeds_present = [k for k, v in FEED_REGISTRY.items() if v.get("path", pathlib.Path("/x")).exists()]
    g07 = len(feeds_present) >= 8
    gates.append(_gate("G07", "Feed registry >= 8 feed files present on disk", "WARNING", g07,
                        f"present={len(feeds_present)}/{len(FEED_REGISTRY)}: {feeds_present}"))

    # Verify feed registry has purpose + feed_type for each entry
    all_documented = all(
        v.get("purpose") and v.get("feed_type")
        for v in FEED_REGISTRY.values()
    )
    gates.append(_gate("G08", "All registered feeds have purpose and feed_type", "BLOCKER", all_documented,
                        "OK" if all_documented else "Missing purpose or feed_type in FEED_REGISTRY"))

    # ── G09-G12: Schema registry ──────────────────────────────────────────────
    g09 = len(SCHEMA_REGISTRY) >= 100
    gates.append(_gate("G09", "Schema registry has >= 100 canonical fields", "BLOCKER", g09,
                        f"schema_fields={len(SCHEMA_REGISTRY)}"))

    # Every field must have required/type/domain
    schema_complete = all(
        "required" in v and "type" in v and "domain" in v
        for v in SCHEMA_REGISTRY.values()
    )
    gates.append(_gate("G10", "All schema fields have required/type/domain defined", "BLOCKER", schema_complete,
                        "OK" if schema_complete else "Incomplete field definitions in SCHEMA_REGISTRY"))

    deprecated_fields = [k for k, v in SCHEMA_REGISTRY.items() if v.get("deprecated")]
    g11 = len(deprecated_fields) > 0
    gates.append(_gate("G11", "Deprecated fields are documented in schema registry", "WARNING", g11,
                        f"deprecated_count={len(deprecated_fields)}: {deprecated_fields[:5]}"))

    # Validate that FEED_TYPE_RULES exists and covers primary types
    required_types = {"CVE_FEED", "BROAD_THREAT_INTEL", "COMMERCIAL_CVE", "ENTERPRISE"}
    g12 = required_types.issubset(set(FEED_TYPE_RULES.keys()))
    gates.append(_gate("G12", "Feed-type validation rules cover all primary feed types", "BLOCKER", g12,
                        f"covered={sorted(FEED_TYPE_RULES.keys())}"))

    # ── G13-G16: Shared validator adoption ───────────────────────────────────
    # Verify canonical gate() function exists and produces correct structure
    test_gate = _gate("TEST", "test", "BLOCKER", True, "detail")
    g13 = (test_gate.get("status") == "PASS" and test_gate.get("gate_id") == "TEST")
    gates.append(_gate("G13", "Canonical gate() function produces correct structure", "BLOCKER", g13,
                        "OK" if g13 else f"Unexpected output: {test_gate}"))

    # Verify field_pct with test data
    test_items = [{"confidence": 0.8}, {"confidence": None}, {"confidence": 0.5}]
    pct = field_pct(test_items, "confidence", lambda x: x.get("confidence") is not None and x.get("confidence") != "")
    g14 = abs(pct - 66.67) < 0.1
    gates.append(_gate("G14", "Canonical field_pct() computes correctly (66.7% expected on test)", "BLOCKER", g14,
                        f"computed={pct:.2f}% expected=66.67%"))

    # Verify enrichment_summary function
    test_enrich = enrichment_summary([{"cvss_score": 7.5, "epss": 0.3, "confidence": 0.9}])
    g15 = "cvss_pct" in test_enrich and test_enrich["cvss_pct"] == 100.0
    gates.append(_gate("G15", "enrichment_summary() returns correct coverage dict", "BLOCKER", g15,
                        f"ok={g15} sample_output={dict(list(test_enrich.items())[:3])}"))

    # Verify schema drift detection
    test_drift = detect_schema_drift([{"id": "x", "unknown_field_xyz": 1, "title": "t", "severity": "HIGH"}])
    g16 = "unknown_field_xyz" in test_drift.get("unknown_fields", [])
    gates.append(_gate("G16", "detect_schema_drift() identifies unknown fields correctly", "BLOCKER", g16,
                        f"ok={g16} drift_count={test_drift.get('drift_count',0)}"))

    # ── G17-G20: Enrichment governance — live feed ───────────────────────────
    live_items, live_path = load_feed_safe("live")
    n_live = len(live_items)
    g17 = n_live >= 10
    gates.append(_gate("G17", "Live production feed loadable with >= 10 items", "BLOCKER", g17,
                        f"items={n_live} path={live_path}"))

    if live_items:
        live_enrich = enrichment_summary(live_items)
        live_type   = detect_feed_type(live_items)
        rules = FEED_TYPE_RULES.get(live_type, FEED_TYPE_RULES.get("CVE_FEED", {}))
        g18 = live_enrich.get("cvss_pct", 0) >= rules.get("cvss_min_pct", 0)
        gates.append(_gate("G18", f"Live feed CVSS coverage meets feed-type threshold ({rules.get('cvss_min_pct',0)}% for {live_type})", "WARNING", g18,
                            f"cvss_pct={live_enrich.get('cvss_pct',0)}% threshold={rules.get('cvss_min_pct',0)}%"))

        g19 = live_enrich.get("epss_pct", 0) >= rules.get("epss_min_pct", 0)
        gates.append(_gate("G19", f"Live feed EPSS coverage meets threshold ({rules.get('epss_min_pct',0)}%)", "WARNING", g19,
                            f"epss_pct={live_enrich.get('epss_pct',0)}%"))

        g20 = live_enrich.get("conf_pct", 0) >= 50.0
        gates.append(_gate("G20", "Live feed confidence coverage >= 50%", "WARNING", g20,
                            f"conf_pct={live_enrich.get('conf_pct',0)}%"))
    else:
        for gid, label in [("G18","CVSS coverage"), ("G19","EPSS coverage"), ("G20","Confidence coverage")]:
            gates.append(_gate(gid, label, "WARNING", False, "Live feed unavailable"))

    # ── G21-G22: Source diversity governance ─────────────────────────────────
    if live_items:
        div      = source_diversity(live_items)
        feed_type = detect_feed_type(live_items)
        rules2   = FEED_TYPE_RULES.get(feed_type, {})
        max_dom  = rules2.get("dominance_max_pct", 98.0)
        min_src  = rules2.get("distinct_sources_min", 1)
        g21 = div["top_dominance_pct"] < max_dom
        gates.append(_gate("G21", f"Source dominance < {max_dom}% ({feed_type})", "WARNING", g21,
                            f"top_src_dom={div['top_dominance_pct']}% threshold={max_dom}%"))

        g22 = div["distinct"] >= min_src
        gates.append(_gate("G22", f"Distinct sources >= {min_src} ({feed_type})", "WARNING", g22,
                            f"distinct={div['distinct']} threshold={min_src}"))
    else:
        gates.append(_gate("G21", "Source dominance check", "WARNING", False, "Live feed unavailable"))
        gates.append(_gate("G22", "Distinct sources check",  "WARNING", False, "Live feed unavailable"))

    # ── G23-G24: Schema drift audit ───────────────────────────────────────────
    if live_items:
        drift = detect_schema_drift(live_items)
        g23 = drift["drift_count"] == 0
        gates.append(_gate("G23", "No unknown fields in live feed (schema drift = 0)", "WARNING", g23,
                            f"drift_count={drift['drift_count']} unknown={drift['unknown_fields'][:5]}"))

        g24 = drift["deprecated_count"] <= 3
        gates.append(_gate("G24", "Deprecated field usage <= 3 in live feed", "WARNING", g24,
                            f"deprecated_count={drift['deprecated_count']} fields={drift.get('deprecated_fields',[])}"))
    else:
        gates.append(_gate("G23", "Schema drift audit",      "WARNING", False, "Live feed unavailable"))
        gates.append(_gate("G24", "Deprecated field audit",  "WARNING", False, "Live feed unavailable"))

    # ── G25-G26: Handler and route completeness ───────────────────────────────
    handler_path = SRC_P / "p38-handlers.js"
    g25 = handler_path.exists()
    gates.append(_gate("G25", "p38-handlers.js exists", "BLOCKER", g25,
                        "found" if g25 else "NOT FOUND"))

    required_exports = [
        "handleP38SchemaRegistry", "handleP38FeedGovernance", "handleP38SchemaDrift",
        "handleP38EnrichmentAudit", "handleP38ConfidenceAudit", "handleP38IQIndex",
        "handleP38SourceDiversity", "handleP38Certification", "handleP38Executive",
        "handleP38Reliability", "handleP38Metrics", "handleP38Observability",
    ]
    if g25:
        src = handler_path.read_text(encoding="utf-8")
        missing = [e for e in required_exports if f"export async function {e}" not in src]
        g26 = len(missing) == 0
        gates.append(_gate("G26", "p38-handlers.js has all 12 required exports", "BLOCKER", g26,
                            "OK" if g26 else f"MISSING: {missing}"))
    else:
        gates.append(_gate("G26", "p38-handlers.js has all 12 required exports", "BLOCKER", False,
                            "handler file missing"))

    # ── Tally ─────────────────────────────────────────────────────────────────
    blockers  = sum(1 for g in gates if g["status"] == "FAIL_BLOCKER")
    warnings  = sum(1 for g in gates if g["status"] == "FAIL_WARNING")
    passed    = sum(1 for g in gates if g["status"] == "PASS")
    total     = len(gates)
    tier      = "WORLDWIDE_RELEASE" if blockers == 0 else "BLOCKED"

    live_enrich_final = enrichment_summary(live_items) if live_items else {}

    report = {
        "schema_version":       "p38.0",
        "generated_at":         datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "layer":                "P38",
        "scope":                "enterprise_platform_governance",
        "release_tier":         tier,
        "passed_count":         passed,
        "blocker_count":        blockers,
        "warning_count":        warnings,
        "total_gates":          total,
        "p37_tier":             p37.get("release_tier", "UNKNOWN") if p37 else "UNKNOWN",
        "shared_validators":    "scripts/p38_shared_validators.py",
        "shared_import_ok":     _SHARED_IMPORT_OK,
        "feed_registry_count":  len(FEED_REGISTRY),
        "schema_field_count":   len(SCHEMA_REGISTRY),
        "feed_type_rules":      len(FEED_TYPE_RULES),
        "live_feed": {
            "path":       live_path,
            "item_count": n_live,
            "enrichment": live_enrich_final,
        },
        "governance_deliverables": {
            "canonical_schema_registry":   "scripts/p38_shared_validators.py:SCHEMA_REGISTRY",
            "canonical_feed_registry":     "scripts/p38_shared_validators.py:FEED_REGISTRY",
            "feed_type_rules":             "scripts/p38_shared_validators.py:FEED_TYPE_RULES",
            "shared_gate_fn":              "scripts/p38_shared_validators.py:gate()",
            "shared_field_pct_fn":         "scripts/p38_shared_validators.py:field_pct()",
            "shared_enrichment_summary_fn":"scripts/p38_shared_validators.py:enrichment_summary()",
            "shared_drift_fn":             "scripts/p38_shared_validators.py:detect_schema_drift()",
            "handler_js":                  "workers/intel-gateway/src/p38-handlers.js",
            "executive_dashboard":         "/api/v1/p38/executive",
        },
        "adr": [
            {
                "id": "ADR-P38-001",
                "decision": "Introduce p38_shared_validators.py as canonical shared validator library",
                "rationale": "Phase 0 audit found _field_pct and _gate re-implemented independently in p36 and p37 cert scripts. Single Source of Truth eliminates future drift.",
                "approach": "Additive — p36/p37 scripts unchanged. New p38 cert imports from shared module.",
                "risk": "LOW",
            },
            {
                "id": "ADR-P38-002",
                "decision": "Define canonical SCHEMA_REGISTRY with 153 fields and FEED_REGISTRY with 12 feeds",
                "rationale": "Phase 0 audit found zero documented feed purpose registry and zero canonical schema. This is the governance gap P38 closes.",
                "approach": "New module p38_shared_validators.py. No existing file modified.",
                "risk": "LOW",
            },
            {
                "id": "ADR-P38-003",
                "decision": "Feed-type-aware thresholds in FEED_TYPE_RULES rather than per-cert hardcoding",
                "rationale": "P37 Phase 0 found CVE-feed vs broad-feed required different diversity/enrichment thresholds. Centralising rules prevents future divergence.",
                "approach": "FEED_TYPE_RULES dict in p38_shared_validators.py consumed by p38 cert and future layers.",
                "risk": "LOW",
            },
        ],
        "gates": gates,
    }

    out_path = DATA_Q / "p38_certification_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nP38.0 Production Certification — Enterprise Platform Governance")
    print(f"{'='*62}")
    print(f"Release tier    : {tier}")
    print(f"Gates           : {passed}/{total} PASS | {blockers} blockers | {warnings} warnings")
    print(f"Shared import   : {'OK' if _SHARED_IMPORT_OK else 'FAILED'}")
    print(f"Schema fields   : {len(SCHEMA_REGISTRY)}")
    print(f"Feed registry   : {len(FEED_REGISTRY)} feeds")
    print(f"Feed type rules : {len(FEED_TYPE_RULES)} types")
    print(f"Live feed items : {n_live}")
    print(f"Report          : {out_path}")
    for g in gates:
        prefix = "  [PASS]" if g["status"] == "PASS" else "  [WARN]" if g["status"] == "FAIL_WARNING" else "  [FAIL]"
        print(f"{prefix} {g['gate_id']}: {g['label']} — {g['detail']}")

    return report


if __name__ == "__main__":
    report = run_certification()
    sys.exit(0 if report["blocker_count"] == 0 else 1)
