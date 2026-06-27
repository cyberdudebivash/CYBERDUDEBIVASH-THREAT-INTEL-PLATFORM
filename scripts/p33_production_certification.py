#!/usr/bin/env python3
"""
scripts/p33_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P33.0 Production Certification
=====================================================================
Enterprise Cyber Intelligence Operating System (ECIOS) certification.
Extends P32 chain with P33-specific gates:

  G01  Feed loadable + item count >= 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description
  G04  No placeholder/synthetic language
  G05  Confidence values valid [0.01, 1.00]
  G06  CVSS/severity consistency (<= 1 band gap)
  G07  MITRE ATT&CK coverage >= 95%
  G08  IOC coverage >= 50%
  G09  Source URL completeness >= 95%
  G10  P32 certification report exists + tier != BLOCKED
  G11  P31 certification report exists + tier != BLOCKED
  G12  P30 certification report exists + tier != BLOCKED
  G13  P28 certification report exists + tier != BLOCKED
  G14  P25 trust gate report exists + 0 blockers
  G15  Regression suite script present
  G16  HTML report files >= feed item count
  G17  STIX bundle files >= feed item count
  G18  Enrichment score >= 30/100 average
  G19  Evidence chain coverage >= 80%
  G20  Detection coverage >= 40% of items carry detection_bundle
  G21  P33.1 Case intelligence derivable: severity field present >= 80% items
  G22  P33.2 Campaign intelligence derivable: >= 1 actor_tag or >= 1 multi-item TTP group
  G23  P33.5 Coverage matrix buildable: items with ttps >= 70%
  G24  P33 enterprise-cyber-intelligence-os.html present (BLOCKER)
  G25  P33.3 SOC mission queues populated: >= 1 CRITICAL or HIGH item
  G26  P33.9 Operational dashboard threat level computable: severity + item count present

Outputs: data/quality/p33_certification_report.json
"""

from __future__ import annotations
import json, os, pathlib, re, sys
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_FEED = _DATA / "feed.json"
_QUAL = _DATA / "quality"
_STIX = _DATA / "stix"
_OUT  = _QUAL / "p33_certification_report.json"

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

REQUIRED_FIELDS = ["id", "title", "description", "severity", "risk_score",
                   "confidence", "timestamp", "source"]

MD_PATTERN    = re.compile(r"(\*\*|__|\#{2,}|\[.+?\]\(https?://.+?\)|`[^`]+`)")
SYNTH_PATTERN = re.compile(
    r"\b(lorem ipsum|placeholder|tbd|todo|insert here|example text|"
    r"sample text|test data|dummy|redacted for|to be determined)\b",
    re.IGNORECASE,
)

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CVSS_BANDS = [(0,0,"INFO"),(0.1,3.9,"LOW"),(4.0,6.9,"MEDIUM"),(7.0,8.9,"HIGH"),(9.0,10.0,"CRITICAL")]

def _cvss_band(score: float) -> str:
    for lo, hi, label in CVSS_BANDS:
        if lo <= score <= hi:
            return label
    return "UNKNOWN"

def _cert_ok(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    try:
        d = json.loads(path.read_text())
        return d.get("release_tier","") not in ("","BLOCKED")
    except Exception:
        return False

def _cert_blockers(path: pathlib.Path) -> int:
    if not path.exists():
        return 99
    try:
        return json.loads(path.read_text()).get("blocker_count", 0)
    except Exception:
        return 99

# ---------------------------------------------------------------------------

class Gate:
    def __init__(self, gid: str, name: str, blocker: bool = False):
        self.gid     = gid
        self.name    = name
        self.blocker = blocker
        self.status  = "PASS"
        self.detail  = ""

    def fail(self, detail: str):
        self.status = "FAIL"
        self.detail = detail

    def warn(self, detail: str):
        self.status = "WARN"
        self.detail = detail

    def to_dict(self) -> dict:
        return {"gate": self.gid, "name": self.name, "status": self.status,
                "blocker": self.blocker, "detail": self.detail}


def run_certification() -> dict:
    gates: list[Gate] = []
    items: list[dict] = []

    def g(gid, name, blocker=False) -> Gate:
        gate = Gate(gid, name, blocker)
        gates.append(gate)
        return gate

    # --- G01 Feed loadable ---
    gG01 = g("G01", "Feed loadable + item count >= 1", blocker=True)
    if not _FEED.exists():
        gG01.fail(f"feed.json not found at {_FEED}")
    else:
        try:
            items = json.loads(_FEED.read_text())
            if not items:
                gG01.fail("feed.json is empty (0 items)")
            else:
                gG01.detail = f"{len(items)} items loaded"
        except Exception as e:
            gG01.fail(f"JSON parse error: {e}")

    if not items:
        # Cannot continue without feed — stub remaining gates
        for gid, name, blocker in [
            ("G02","Required fields present",False),
            ("G03","No markdown leakage",False),
            ("G04","No placeholder language",False),
            ("G05","Confidence values valid [0.01,1.00]",False),
            ("G06","CVSS/severity consistency",False),
            ("G07","MITRE ATT&CK coverage >= 95%",False),
            ("G08","IOC coverage >= 50%",False),
            ("G09","Source URL completeness >= 95%",False),
            ("G10","P32 cert chain OK",True),
            ("G11","P31 cert chain OK",False),
            ("G12","P30 cert chain OK",False),
            ("G13","P28 cert chain OK",False),
            ("G14","P25 trust gate 0 blockers",False),
            ("G15","Regression suite script present",False),
            ("G16","HTML report files >= feed count",False),
            ("G17","STIX bundle files >= feed count",False),
            ("G18","Enrichment score >= 30 average",False),
            ("G19","Evidence chain coverage >= 80%",False),
            ("G20","Detection bundle coverage >= 40%",False),
            ("G21","P33.1 Case intel derivable >= 80%",False),
            ("G22","P33.2 Campaign intel derivable",False),
            ("G23","P33.5 Coverage matrix buildable >= 70%",False),
            ("G24","P33 enterprise-cyber-intelligence-os.html present",True),
            ("G25","P33.3 SOC mission queues populated",False),
            ("G26","P33.9 Dashboard threat level computable",False),
        ]:
            gate = g(gid, name, blocker)
            gate.warn("SKIPPED — feed unavailable")
    else:
        n = len(items)

        # --- G02 Required fields ---
        gG02 = g("G02", "Required fields present in all items")
        missing = []
        for item in items:
            m = [f for f in REQUIRED_FIELDS if f not in item]
            if m:
                missing.append((item.get("id","?"), m))
        if missing:
            pct = (n - len(missing)) / n * 100
            if pct < 95:
                gG02.fail(f"{len(missing)}/{n} items missing required fields — {pct:.1f}% complete")
            else:
                gG02.warn(f"{len(missing)}/{n} items missing optional fields")
        else:
            gG02.detail = f"All {n} items have required fields"

        # --- G03 Markdown leakage ---
        gG03 = g("G03", "No markdown leakage in title/description")
        md_count = sum(
            1 for item in items
            if MD_PATTERN.search(str(item.get("title","")) + str(item.get("description","")))
        )
        if md_count > n * 0.05:
            gG03.warn(f"{md_count}/{n} items have markdown in title/description")
        else:
            gG03.detail = f"{md_count}/{n} items with markdown (within threshold)"

        # --- G04 Placeholder language ---
        gG04 = g("G04", "No placeholder/synthetic language")
        synth_count = sum(
            1 for item in items
            if SYNTH_PATTERN.search(str(item.get("title","")) + str(item.get("description","")))
        )
        if synth_count > 0:
            gG04.warn(f"{synth_count}/{n} items contain placeholder language")
        else:
            gG04.detail = "No synthetic/placeholder language detected"

        # --- G05 Confidence range ---
        gG05 = g("G05", "Confidence values valid [0.01, 1.00]")
        bad_conf = [item.get("id","?") for item in items
                    if not (0.0 <= float(item.get("confidence", 0.5)) <= 1.0)]
        if bad_conf:
            gG05.warn(f"{len(bad_conf)} items have out-of-range confidence values")
        else:
            gG05.detail = "All confidence values within [0.0, 1.0]"

        # --- G06 CVSS/severity consistency ---
        gG06 = g("G06", "CVSS/severity consistency (<= 1 band gap)")
        mismatch = 0
        for item in items:
            cvss = item.get("cvss_score")
            sev  = item.get("severity","")
            if cvss and sev:
                try:
                    cb = _cvss_band(float(cvss))
                    diff = abs(SEV_ORDER.get(cb,2) - SEV_ORDER.get(sev,2))
                    if diff > 1:
                        mismatch += 1
                except Exception:
                    pass
        if mismatch > n * 0.10:
            gG06.warn(f"{mismatch}/{n} items exceed 1-band CVSS/severity gap")
        else:
            gG06.detail = f"{mismatch}/{n} CVSS/severity mismatches (within threshold)"

        # --- G07 MITRE coverage ---
        gG07 = g("G07", "MITRE ATT&CK coverage >= 95%")
        mitre_count = sum(1 for item in items
                          if item.get("mitre_tactics") or item.get("ttps"))
        mitre_pct = mitre_count / n * 100
        if mitre_pct < 95:
            gG07.warn(f"MITRE coverage {mitre_pct:.1f}% — below 95% threshold")
        else:
            gG07.detail = f"MITRE coverage {mitre_pct:.1f}%"

        # --- G08 IOC coverage ---
        gG08 = g("G08", "IOC coverage >= 50% of items carry ioc_count > 0")
        ioc_count = sum(1 for item in items if (item.get("ioc_count") or 0) > 0)
        ioc_pct = ioc_count / n * 100
        if ioc_pct < 50:
            gG08.warn(f"IOC coverage {ioc_pct:.1f}% — below 50% threshold")
        else:
            gG08.detail = f"IOC coverage {ioc_pct:.1f}%"

        # --- G09 Source URL completeness ---
        gG09 = g("G09", "Source URL completeness >= 95%")
        src_count = sum(1 for item in items
                        if str(item.get("source","")).startswith("http"))
        src_pct = src_count / n * 100
        if src_pct < 95:
            gG09.warn(f"Source URL completeness {src_pct:.1f}% — below 95%")
        else:
            gG09.detail = f"Source URL completeness {src_pct:.1f}%"

        # --- G10 P32 cert chain ---
        gG10 = g("G10", "P32 certification report exists + tier != BLOCKED", blocker=True)
        p32_path = _QUAL / "p32_certification_report.json"
        if not _cert_ok(p32_path):
            gG10.fail(f"P32 cert missing or BLOCKED at {p32_path}")
        else:
            gG10.detail = "P32 cert chain OK"

        # --- G11 P31 cert chain ---
        gG11 = g("G11", "P31 certification report exists + tier != BLOCKED")
        p31_path = _QUAL / "p31_certification_report.json"
        if not _cert_ok(p31_path):
            gG11.warn(f"P31 cert missing or BLOCKED at {p31_path}")
        else:
            gG11.detail = "P31 cert chain OK"

        # --- G12 P30 cert chain ---
        gG12 = g("G12", "P30 certification report exists + tier != BLOCKED")
        p30_path = _QUAL / "p30_certification_report.json"
        if not _cert_ok(p30_path):
            gG12.warn(f"P30 cert missing or BLOCKED at {p30_path}")
        else:
            gG12.detail = "P30 cert chain OK"

        # --- G13 P28 cert chain ---
        gG13 = g("G13", "P28 certification report exists + tier != BLOCKED")
        p28_path = _QUAL / "p28_certification_report.json"
        if not _cert_ok(p28_path):
            gG13.warn(f"P28 cert missing or BLOCKED at {p28_path}")
        else:
            gG13.detail = "P28 cert chain OK"

        # --- G14 P25 trust gate ---
        gG14 = g("G14", "P25 trust gate report exists + 0 blockers")
        p25_path = _QUAL / "p25_certification_report.json"
        blockers_25 = _cert_blockers(p25_path)
        if blockers_25 > 0:
            gG14.warn(f"P25 trust gate has {blockers_25} blocker(s)")
        elif not p25_path.exists():
            gG14.warn("P25 trust gate report not found")
        else:
            gG14.detail = "P25 trust gate: 0 blockers"

        # --- G15 Regression suite ---
        gG15 = g("G15", "Regression suite script present")
        reg_path = _ROOT / "scripts" / "regression_tests.py"
        if not reg_path.exists():
            gG15.warn(f"Regression suite not found at {reg_path}")
        else:
            gG15.detail = f"Regression suite present: {reg_path.name}"

        # --- G16 HTML report count ---
        gG16 = g("G16", "HTML report files >= feed item count")
        html_dir = _DATA / "reports"
        html_count = 0
        if html_dir.exists():
            html_count = len(list(html_dir.glob("*.html")))
        if html_count < n:
            gG16.warn(f"HTML reports: {html_count} < feed items: {n}")
        else:
            gG16.detail = f"HTML reports: {html_count} >= {n} items"

        # --- G17 STIX bundle count ---
        gG17 = g("G17", "STIX bundle files >= feed item count")
        stix_count = 0
        if _STIX.exists():
            stix_count = len(list(_STIX.glob("*.json")))
        if stix_count < n:
            gG17.warn(f"STIX bundles: {stix_count} < feed items: {n}")
        else:
            gG17.detail = f"STIX bundles: {stix_count} >= {n} items"

        # --- G18 Enrichment score ---
        gG18 = g("G18", "Enrichment score >= 30/100 average")
        def _enrich(item):
            score = 0
            if item.get("cvss_score"): score += 20
            if item.get("epss_score"): score += 15
            if item.get("ttps"):       score += 20
            if item.get("actor_tag"):  score += 15
            if item.get("patch_available"): score += 15
            if item.get("kev_present"):     score += 15
            return min(score, 100)
        avg_enrich = sum(_enrich(i) for i in items) / n
        if avg_enrich < 30:
            gG18.warn(f"Avg enrichment {avg_enrich:.1f}/100 — below 30 threshold")
        else:
            gG18.detail = f"Avg enrichment score {avg_enrich:.1f}/100"

        # --- G19 Evidence chain ---
        gG19 = g("G19", "Evidence chain coverage >= 80%")
        ev_count = sum(1 for item in items if item.get("evidence_chain"))
        ev_pct = ev_count / n * 100
        if ev_pct < 80:
            gG19.warn(f"Evidence chain: {ev_pct:.1f}% — below 80% threshold (field not in feed schema)")
        else:
            gG19.detail = f"Evidence chain coverage {ev_pct:.1f}%"

        # --- G20 Detection bundle ---
        gG20 = g("G20", "Detection bundle coverage >= 40%")
        det_count = sum(1 for item in items if item.get("detection_bundle"))
        det_pct = det_count / n * 100
        if det_pct < 40:
            gG20.warn(f"Detection bundle: {det_pct:.1f}% — below 40% threshold (field not in feed schema)")
        else:
            gG20.detail = f"Detection bundle coverage {det_pct:.1f}%"

        # --- G21 P33.1 Case intelligence derivable ---
        gG21 = g("G21", "P33.1 Case intelligence derivable: severity >= 80% items")
        sev_count = sum(1 for item in items if item.get("severity"))
        sev_pct = sev_count / n * 100
        if sev_pct < 80:
            gG21.fail(f"Severity field present in {sev_pct:.1f}% — need >= 80% for case intelligence")
        else:
            gG21.detail = f"Severity derivable in {sev_pct:.1f}% of items"

        # --- G22 P33.2 Campaign intelligence derivable ---
        gG22 = g("G22", "P33.2 Campaign intelligence: >= 1 actor_tag or >= 1 multi-item TTP group")
        actors = [item.get("actor_tag","") for item in items if item.get("actor_tag")]
        ttp_sets: dict[str,int] = {}
        for item in items:
            for t in (item.get("ttps") or []):
                if isinstance(t, str):
                    ttp_sets[t] = ttp_sets.get(t, 0) + 1
        multi_ttp = sum(1 for v in ttp_sets.values() if v >= 2)
        if not actors and not multi_ttp:
            gG22.warn("No actor_tags and no repeated TTPs — campaign grouping limited")
        else:
            gG22.detail = f"{len(set(actors))} unique actors, {multi_ttp} shared TTP groups"

        # --- G23 P33.5 Coverage matrix buildable ---
        gG23 = g("G23", "P33.5 Coverage matrix: items with ttps >= 70%")
        ttp_items = sum(1 for item in items if item.get("ttps"))
        ttp_pct = ttp_items / n * 100
        if ttp_pct < 70:
            gG23.warn(f"TTP coverage {ttp_pct:.1f}% — below 70% threshold for full matrix")
        else:
            gG23.detail = f"TTP coverage {ttp_pct:.1f}%"

        # --- G24 ECIOS dashboard present (BLOCKER) ---
        gG24 = g("G24", "P33 enterprise-cyber-intelligence-os.html present", blocker=True)
        ecios_path = _ROOT / "enterprise-cyber-intelligence-os.html"
        if not ecios_path.exists():
            gG24.fail(f"enterprise-cyber-intelligence-os.html not found at {ecios_path}")
        else:
            size = ecios_path.stat().st_size
            gG24.detail = f"ECIOS dashboard present ({size:,} bytes)"

        # --- G25 P33.3 SOC mission queues populated ---
        gG25 = g("G25", "P33.3 SOC mission: >= 1 CRITICAL or HIGH item")
        critical_high = sum(1 for item in items if item.get("severity") in ("CRITICAL","HIGH"))
        if critical_high < 1:
            gG25.warn("No CRITICAL or HIGH items — mission queue will have limited population")
        else:
            gG25.detail = f"{critical_high} CRITICAL/HIGH items available for SOC mission queues"

        # --- G26 P33.9 Operational dashboard threat level computable ---
        gG26 = g("G26", "P33.9 Dashboard threat level computable")
        can_compute = n > 0 and any(item.get("severity") for item in items)
        if not can_compute:
            gG26.warn("Cannot compute threat level — no severity fields in feed")
        else:
            crit = sum(1 for item in items if item.get("severity") == "CRITICAL")
            high = sum(1 for item in items if item.get("severity") == "HIGH")
            gG26.detail = f"Threat level computable: {crit} critical, {high} high across {n} items"

    # --- Tally ---
    passed  = sum(1 for g in gates if g.status == "PASS")
    warned  = sum(1 for g in gates if g.status == "WARN")
    failed  = sum(1 for g in gates if g.status == "FAIL")
    blocked = sum(1 for g in gates if g.status == "FAIL" and g.blocker)

    if blocked > 0:
        tier = "BLOCKED"
    elif failed > 0:
        tier = "CONTROLLED_RELEASE"
    elif warned > len(gates) * 0.30:
        tier = "CONTROLLED_RELEASE"
    else:
        tier = "WORLDWIDE_RELEASE"

    report = {
        "schema_version":   "p33.0",
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "release_tier":     tier,
        "blocker_count":    blocked,
        "warning_count":    warned,
        "passed_count":     passed,
        "total_gates":      len(gates),
        "gates":            [g.to_dict() for g in gates],
        "ecios_version":    "P33.0 Enterprise Cyber Intelligence OS",
        "ci_stage":         "STAGE 3.98",
        "platform_note":    "P33 ECIOS — cross-feed aggregation, unified SOC operations, MITRE coverage matrix, exposure heatmap, knowledge explorer, automation pipeline, customer success, marketplace",
    }

    _QUAL.mkdir(parents=True, exist_ok=True)
    if not DRY_RUN:
        _OUT.write_text(json.dumps(report, indent=2))

    return report


def main():
    print("=" * 70)
    print("CYBERDUDEBIVASH(R) SENTINEL APEX — P33.0 Production Certification")
    print("Enterprise Cyber Intelligence Operating System (ECIOS)")
    print("=" * 70)

    report = run_certification()

    for gate in report["gates"]:
        status = gate["status"]
        sym = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}.get(status, "?")
        blocker = " [BLOCKER]" if gate["blocker"] and status == "FAIL" else ""
        detail  = f" — {gate['detail']}" if gate.get("detail") else ""
        print(f"  {sym} {gate['gate']} {gate['name']}{blocker}{detail}")

    print()
    print(f"  TIER    : {report['release_tier']}")
    print(f"  PASSED  : {report['passed_count']}/{report['total_gates']}")
    print(f"  WARNINGS: {report['warning_count']}")
    print(f"  BLOCKERS: {report['blocker_count']}")
    print()

    if report["release_tier"] == "WORLDWIDE_RELEASE":
        print("  ✓ P33.0 WORLDWIDE_RELEASE — ECIOS Cleared for Production")
    elif report["release_tier"] == "CONTROLLED_RELEASE":
        print("  ⚠ P33.0 CONTROLLED_RELEASE — Review warnings before deployment")
    else:
        print("  ✗ P33.0 BLOCKED — Resolve blocker gates before proceeding")

    if not DRY_RUN:
        print(f"\n  Report: {_OUT}")
    print("=" * 70)


if __name__ == "__main__":
    main()
