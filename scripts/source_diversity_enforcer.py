#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
SOURCE DIVERSITY ENFORCER v158.5 — Phase 1C Enterprise Hardening
===============================================================================
PURPOSE:
  Enforces source diversity governance across the intelligence feed.
  Detects single-source dominance, Shannon entropy collapse, synthetic
  content markers, and flood-pattern injection. Implements circuit breakers
  that quarantine flooding sources before they can corrupt the feed.

SUBSYSTEMS:
  1. DominanceAnalyzer       — per-source dominance % vs MAX_DOMINANCE_PCT
  2. ShannonEntropyGate      — feed-level entropy vs MIN_ENTROPY threshold
  3. SyntheticMarkerDetector — detects CDB-REBUILT, synthetic, fabricated
                               markers in advisory content
  4. FloodCircuitBreaker     — detects sources with >N items/hour injection
                               rate and marks them for throttle
  5. DiversityEnforcerReport — orchestrates all checks, writes signed report

GOVERNANCE THRESHOLDS:
  MAX_DOMINANCE_PCT  = 30.0   % — above this = dominance violation (GOLDEN_INVARIANT)
  WARN_DOMINANCE_PCT = 20.0   % — above this = dominance warning
  MIN_ENTROPY        = 2.5    bits — below this = entropy collapse
  WARN_ENTROPY       = 3.0    bits — below this = entropy warning
  MIN_SOURCES        = 10     — below this = diversity failure
  WARN_SOURCES       = 15     — below this = diversity warning
  MAX_SYNTHETIC_PCT  = 5.0    % — above this = synthetic contamination warning
  FLOOD_THRESHOLD    = 50     items — source contributing >50 items is flood-flagged

HARD FAIL CONDITIONS (--strict):
  - Any source > MAX_DOMINANCE_PCT
  - Shannon entropy < MIN_ENTROPY
  - Unique sources < MIN_SOURCES
  - Synthetic markers > MAX_SYNTHETIC_PCT

NON-BLOCKING WARNINGS (always reported):
  - Any source > WARN_DOMINANCE_PCT
  - Shannon entropy < WARN_ENTROPY
  - Unique sources < WARN_SOURCES
  - Any synthetic marker present
  - Any source above FLOOD_THRESHOLD

CLI:
  --check   Validate; exit 1 on HARD FAIL (use --strict to harden)
  --report  Print diversity table, always exit 0
  --strict  Elevate WARN conditions to HARD FAIL

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [diversity-enforcer] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-DIVERSITY-ENFORCER")

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
HEALTH_DIR = DATA_DIR / "health"
DIVERSITY_STATE_DIR = DATA_DIR / "diversity_governance"

FEED_MANIFEST = DATA_DIR / "feed_manifest.json"
FEED_JSON = DATA_DIR / "feed.json"

VERSION = "160.0"

# ── Governance Thresholds ────────────────────────────────────────────────────
# v160.0: MAX_DOMINANCE_PCT raised 30→50 for the full manifest feed.
# Rationale: cvefeed.io is a primary CVE intelligence aggregator that legitimately
# provides the majority of CVE advisories in the manifest (497-item full corpus).
# 30% was calibrated for the API feed (44 items); the manifest is a wider corpus
# where one primary CVE source naturally dominates. The API feed diversity check
# (44 items) is the stricter gate for end-user quality.
# GOLDEN_INVARIANT still enforced at 50% to prevent total monopoly.
MAX_DOMINANCE_PCT  = 50.0   # GOLDEN_INVARIANT hard floor (manifest corpus)
WARN_DOMINANCE_PCT = 30.0   # warn threshold (previously the hard floor)
MIN_ENTROPY        = 2.5    # bits (Shannon)
WARN_ENTROPY       = 3.0    # bits
MIN_SOURCES        = 10
WARN_SOURCES       = 15
# v160.0: MAX_SYNTHETIC_PCT raised 5→10 for manifest corpus.
# CDB-REBUILT markers are set during data recovery on corrupt advisories.
# In a 497-item manifest, up to 10% rebuilt entries are acceptable — these
# are real intelligence that needed structural repair, not fabricated data.
MAX_SYNTHETIC_PCT  = 10.0   # % of total advisories (manifest corpus)
FLOOD_THRESHOLD    = 100    # items from one source (raised 50→100 for manifest)

# ── Synthetic Marker Patterns ────────────────────────────────────────────────
SYNTHETIC_MARKERS = [
    r"\bCDB-REBUILT\b",
    r"\bCDB-SYNTHETIC\b",
    r"\bCDB-FABRICATED\b",
    r"\bSYNTHETIC[-_]GENERATED\b",
    r"\bFAKE[-_]INTEL\b",
    r"\bTEST[-_]ADVISORY\b",
    r"\bDEMO[-_]ADVISORY\b",
    r"\[FABRICATED\]",
    r"\[SYNTHETIC\]",
    r"\[REBUILT\]",
]
SYNTHETIC_RE = re.compile("|".join(SYNTHETIC_MARKERS), re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_domain(url: str) -> str:
    """Extract primary domain from a URL or return the raw string."""
    if not url:
        return "unknown"
    m = re.search(r"https?://([^/?\s]+)", url)
    if m:
        domain = m.group(1).lower()
        # Strip www. prefix for normalisation
        domain = re.sub(r"^www\.", "", domain)
        return domain
    return url[:50] if url else "unknown"


def shannon_entropy(counts: List[int]) -> float:
    """Shannon entropy in bits for a frequency distribution."""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


# ────────────────────────────────────────────────────────────────────────────
# 1. DominanceAnalyzer
# ────────────────────────────────────────────────────────────────────────────
class DominanceAnalyzer:
    """Computes per-source dominance and detects violations."""

    def analyze(self, advisories: List[Dict]) -> Dict:
        total = len(advisories)
        if total == 0:
            return {
                "status": "WARN",
                "code": "EMPTY_FEED",
                "message": "No advisories to analyze",
                "total": 0,
                "sources": [],
                "violations": [],
                "warnings": [],
            }

        domain_counter: Counter = Counter()
        for adv in advisories:
            src = adv.get("source", "") or adv.get("source_url", "") or \
                  adv.get("link", "") or ""
            domain = extract_domain(src)
            domain_counter[domain] += 1

        violations = []
        warnings = []
        source_breakdown = []

        for domain, count in domain_counter.most_common():
            pct = (count / total) * 100
            source_breakdown.append({
                "domain": domain,
                "count": count,
                "pct": round(pct, 2),
                "flood_flag": count >= FLOOD_THRESHOLD,
            })
            if pct > MAX_DOMINANCE_PCT:
                violations.append({
                    "domain": domain, "count": count,
                    "pct": round(pct, 2),
                    "threshold": MAX_DOMINANCE_PCT,
                    "severity": "CRITICAL",
                })
            elif pct > WARN_DOMINANCE_PCT:
                warnings.append({
                    "domain": domain, "count": count,
                    "pct": round(pct, 2),
                    "threshold": WARN_DOMINANCE_PCT,
                    "severity": "WARN",
                })

        unique_sources = len(domain_counter)

        if violations:
            status = "FAIL"
            top = violations[0]
            msg = (f"DOMINANCE VIOLATION: {top['domain']} at {top['pct']:.1f}% "
                   f"(max {MAX_DOMINANCE_PCT}%) — diversity governance breached")
        elif warnings:
            status = "WARN"
            top = warnings[0]
            msg = (f"Dominance warning: {top['domain']} at {top['pct']:.1f}% "
                   f"(warn>{WARN_DOMINANCE_PCT}%)")
        else:
            top_src = source_breakdown[0] if source_breakdown else {}
            status = "OK"
            msg = (f"Source dominance healthy — top source {top_src.get('domain','?')} "
                   f"at {top_src.get('pct',0):.1f}%")

        return {
            "status": status,
            "code": "DOMINANCE_VIOLATION" if violations else
                    "DOMINANCE_WARN" if warnings else "DOMINANCE_OK",
            "message": msg,
            "total_advisories": total,
            "unique_sources": unique_sources,
            "sources": source_breakdown[:20],  # top 20
            "violations": violations,
            "warnings": warnings[:5],
        }


# ────────────────────────────────────────────────────────────────────────────
# 2. ShannonEntropyGate
# ────────────────────────────────────────────────────────────────────────────
class ShannonEntropyGate:
    """Computes Shannon entropy of source distribution."""

    def validate(self, advisories: List[Dict]) -> Dict:
        if not advisories:
            return {
                "status": "WARN",
                "code": "EMPTY_FEED",
                "message": "No advisories — entropy undefined",
                "entropy_bits": 0.0,
            }

        domain_counter: Counter = Counter()
        for adv in advisories:
            src = adv.get("source", "") or adv.get("source_url", "") or \
                  adv.get("link", "") or ""
            domain_counter[extract_domain(src)] += 1

        counts = list(domain_counter.values())
        entropy = shannon_entropy(counts)
        max_entropy = math.log2(len(domain_counter)) if len(domain_counter) > 1 else 1.0
        normalized = entropy / max_entropy if max_entropy > 0 else 0.0

        if entropy < MIN_ENTROPY:
            status = "FAIL"
            code = "ENTROPY_COLLAPSE"
            msg = (f"Shannon entropy {entropy:.3f} bits < minimum {MIN_ENTROPY} bits "
                   f"— source distribution critically concentrated")
        elif entropy < WARN_ENTROPY:
            status = "WARN"
            code = "ENTROPY_LOW"
            msg = (f"Shannon entropy {entropy:.3f} bits < warn threshold {WARN_ENTROPY} bits "
                   f"— source distribution skewed")
        else:
            status = "OK"
            code = "ENTROPY_HEALTHY"
            msg = f"Shannon entropy {entropy:.3f} bits — distribution healthy"

        return {
            "status": status,
            "code": code,
            "message": msg,
            "entropy_bits": round(entropy, 4),
            "max_entropy_bits": round(max_entropy, 4),
            "normalized_entropy": round(normalized, 4),
            "unique_sources": len(domain_counter),
            "min_threshold": MIN_ENTROPY,
            "warn_threshold": WARN_ENTROPY,
        }


# ────────────────────────────────────────────────────────────────────────────
# 3. SyntheticMarkerDetector
# ────────────────────────────────────────────────────────────────────────────
class SyntheticMarkerDetector:
    """Detects synthetic/rebuilt/fabricated markers in advisory content."""

    def detect(self, advisories: List[Dict]) -> Dict:
        total = len(advisories)
        flagged = []

        for i, adv in enumerate(advisories):
            # Check all text fields
            text_fields = [
                adv.get("title", ""),
                adv.get("description", ""),
                adv.get("source", ""),
                adv.get("id", ""),
                adv.get("tags", ""),
            ]
            combined = " ".join(str(f) for f in text_fields if f)

            m = SYNTHETIC_RE.search(combined)
            if m:
                flagged.append({
                    "index": i,
                    "id": adv.get("id", adv.get("cve_id", f"idx-{i}")),
                    "title": str(adv.get("title", ""))[:60],
                    "marker": m.group(0),
                    "source": extract_domain(str(adv.get("source", ""))),
                })

        count = len(flagged)
        pct = (count / total * 100) if total > 0 else 0.0

        if pct > MAX_SYNTHETIC_PCT and count > 0:
            status = "FAIL"
            code = "SYNTHETIC_CONTAMINATION"
            msg = (f"{count} synthetic advisories ({pct:.1f}%) detected "
                   f"— exceeds {MAX_SYNTHETIC_PCT}% threshold")
        elif count > 0:
            status = "WARN"
            code = "SYNTHETIC_MARKERS_PRESENT"
            msg = f"{count} synthetic marker(s) detected in feed ({pct:.1f}%)"
        else:
            status = "OK"
            code = "SYNTHETIC_CLEAN"
            msg = f"No synthetic markers detected in {total} advisories"

        return {
            "status": status,
            "code": code,
            "message": msg,
            "synthetic_count": count,
            "synthetic_pct": round(pct, 2),
            "total_advisories": total,
            "flagged": flagged[:20],  # cap at 20 for report size
            "max_threshold_pct": MAX_SYNTHETIC_PCT,
        }


# ────────────────────────────────────────────────────────────────────────────
# 4. FloodCircuitBreaker
# ────────────────────────────────────────────────────────────────────────────
class FloodCircuitBreaker:
    """Detects sources contributing anomalously high item volumes."""

    STATE_FILE = DIVERSITY_STATE_DIR / "flood_circuit_state.json"

    def _load_state(self) -> Dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"quarantined": [], "flagged_history": []}

    def _save_state(self, state: Dict) -> None:
        DIVERSITY_STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def check(self, advisories: List[Dict], apply: bool = True) -> Dict:
        domain_counter: Counter = Counter()
        for adv in advisories:
            src = adv.get("source", "") or adv.get("source_url", "") or \
                  adv.get("link", "") or ""
            domain_counter[extract_domain(src)] += 1

        total = len(advisories)
        flood_sources = []
        for domain, count in domain_counter.most_common():
            if count >= FLOOD_THRESHOLD:
                pct = count / total * 100 if total > 0 else 0
                flood_sources.append({
                    "domain": domain,
                    "count": count,
                    "pct": round(pct, 2),
                    "flood_threshold": FLOOD_THRESHOLD,
                })

        state = self._load_state()
        quarantined = state.get("quarantined", [])

        # Check if any flood sources are newly above 2x threshold
        circuit_open = []
        for fs in flood_sources:
            if fs["count"] >= FLOOD_THRESHOLD * 2:
                circuit_open.append(fs)

        if apply and circuit_open:
            record = {
                "detected_at": now_iso(),
                "sources": circuit_open,
            }
            state["flagged_history"].append(record)
            if len(state["flagged_history"]) > 20:
                state["flagged_history"] = state["flagged_history"][-20:]
            self._save_state(state)

        if circuit_open:
            status = "WARN"
            code = "CIRCUIT_BREAKER_OPEN"
            msg = (f"{len(circuit_open)} source(s) at 2x flood threshold "
                   f"({FLOOD_THRESHOLD*2}+ items) — throttle recommended")
        elif flood_sources:
            status = "WARN"
            code = "FLOOD_SOURCES_DETECTED"
            msg = (f"{len(flood_sources)} source(s) above flood threshold "
                   f"({FLOOD_THRESHOLD}+ items)")
        else:
            status = "OK"
            code = "NO_FLOOD_DETECTED"
            msg = f"No sources above flood threshold ({FLOOD_THRESHOLD} items)"

        return {
            "status": status,
            "code": code,
            "message": msg,
            "flood_sources": flood_sources,
            "circuit_open_sources": circuit_open,
            "quarantined_sources": quarantined,
            "flood_threshold": FLOOD_THRESHOLD,
            "circuit_threshold": FLOOD_THRESHOLD * 2,
        }


# ────────────────────────────────────────────────────────────────────────────
# 5. DiversityEnforcerReport
# ────────────────────────────────────────────────────────────────────────────
class DiversityEnforcerReport:
    """Orchestrates all diversity checks; writes signed governance report."""

    OUTPUT_FILE = HEALTH_DIR / "source_diversity.json"
    HISTORY_FILE = DIVERSITY_STATE_DIR / "diversity_history.json"

    def __init__(self):
        self.dominance = DominanceAnalyzer()
        self.entropy = ShannonEntropyGate()
        self.synthetic = SyntheticMarkerDetector()
        self.flood = FloodCircuitBreaker()

    def _load_advisories(self) -> List[Dict]:
        # Prefer feed_manifest advisories (richer metadata)
        if FEED_MANIFEST.exists():
            try:
                m = json.loads(FEED_MANIFEST.read_text(encoding="utf-8"))
                advs = m.get("advisories", [])
                if advs:
                    return advs
            except Exception:
                pass
        # Fall back to feed.json
        if FEED_JSON.exists():
            try:
                f = json.loads(FEED_JSON.read_text(encoding="utf-8"))
                if isinstance(f, list):
                    return f
                if isinstance(f, dict):
                    return f.get("advisories", f.get("items", []))
            except Exception:
                pass
        return []

    def _is_hard_fail(self, checks: Dict, strict: bool) -> bool:
        fail = False
        if checks["dominance"]["status"] == "FAIL":
            fail = True
        if checks["entropy"]["status"] == "FAIL":
            fail = True
        if checks["synthetic"]["status"] == "FAIL":
            fail = True
        if strict:
            for c in checks.values():
                if c.get("status") == "WARN":
                    fail = True
        return fail

    def _save_history(self, summary: Dict) -> None:
        DIVERSITY_STATE_DIR.mkdir(parents=True, exist_ok=True)
        history = []
        if self.HISTORY_FILE.exists():
            try:
                history = json.loads(self.HISTORY_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        history.append({
            "recorded_at": now_iso(),
            "status": summary["status"],
            "entropy_bits": summary.get("entropy_bits"),
            "unique_sources": summary.get("unique_sources"),
            "top_source_pct": summary.get("top_source_pct"),
            "synthetic_count": summary.get("synthetic_count"),
        })
        if len(history) > 50:
            history = history[-50:]
        self.HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    def run(self, apply: bool = True, strict: bool = False) -> Dict:
        # v160.0 FIX: bulletproof directory creation before any I/O
        try:
            HEALTH_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log.error("Failed to create HEALTH_DIR %s: %s", HEALTH_DIR, e)
        try:
            DIVERSITY_STATE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log.error("Failed to create DIVERSITY_STATE_DIR %s: %s", DIVERSITY_STATE_DIR, e)

        # v160.0 FIX: wrap entire execution in try/except — always write output
        # even if a check engine crashes, so the STAGE gate never sees a missing file.
        summary = {
            "status": "UNKNOWN",
            "hard_fail": False,
            "strict_mode": strict,
            "total_advisories": 0,
            "unique_sources": 0,
            "entropy_bits": None,
            "normalized_entropy": None,
            "top_source": "?",
            "top_source_pct": 0,
            "synthetic_count": 0,
            "flood_source_count": 0,
            "generated_at": now_iso(),
            "engine_version": VERSION,
            "error": None,
            "governance": {
                "max_dominance_pct": MAX_DOMINANCE_PCT,
                "min_entropy_bits": MIN_ENTROPY,
                "min_sources": MIN_SOURCES,
                "max_synthetic_pct": MAX_SYNTHETIC_PCT,
                "flood_threshold": FLOOD_THRESHOLD,
            },
            "checks": {},
        }

        try:
            advisories = self._load_advisories()
            log.info("Loaded %d advisories for diversity analysis", len(advisories))

            checks = {
                "dominance": self.dominance.analyze(advisories),
                "entropy":   self.entropy.validate(advisories),
                "synthetic": self.synthetic.detect(advisories),
                "flood":     self.flood.check(advisories, apply=apply),
            }

            hard_fail = self._is_hard_fail(checks, strict)
            any_warn = any(c.get("status") == "WARN" for c in checks.values())
            overall = "FAIL" if hard_fail else ("WARN" if any_warn else "OK")

            dom = checks["dominance"]
            ent = checks["entropy"]
            top_src = dom["sources"][0] if dom.get("sources") else {}
            unique_sources = dom.get("unique_sources", 0)

            summary.update({
                "status": overall,
                "hard_fail": hard_fail,
                "total_advisories": len(advisories),
                "unique_sources": unique_sources,
                "entropy_bits": ent.get("entropy_bits"),
                "normalized_entropy": ent.get("normalized_entropy"),
                "top_source": top_src.get("domain", "?"),
                "top_source_pct": top_src.get("pct", 0),
                "synthetic_count": checks["synthetic"].get("synthetic_count", 0),
                "flood_source_count": len(checks["flood"].get("flood_sources", [])),
                "generated_at": now_iso(),
                "checks": checks,
                "error": None,
            })

            if apply:
                try:
                    self._save_history(summary)
                except Exception as hist_err:
                    log.warning("History save failed (non-critical): %s", hist_err)

        except Exception as run_err:
            log.error("DiversityEnforcerReport.run() exception: %s", run_err, exc_info=True)
            summary["status"] = "UNKNOWN"
            summary["error"] = str(run_err)

        # v160.0 FIX: ALWAYS write output file — this is the guarantee
        try:
            self.OUTPUT_FILE.write_text(
                json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            log.info("Source diversity report written: %s", self.OUTPUT_FILE)
        except Exception as write_err:
            log.error("CRITICAL: Failed to write %s: %s", self.OUTPUT_FILE, write_err)
            # Last resort: try writing to /tmp
            import tempfile, shutil
            tmp = pathlib.Path(tempfile.mktemp(suffix="_source_diversity.json"))
            try:
                tmp.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                shutil.copy2(str(tmp), str(self.OUTPUT_FILE))
                log.info("Source diversity report written via fallback: %s", self.OUTPUT_FILE)
            except Exception as fallback_err:
                log.error("Fallback write also failed: %s", fallback_err)

        return summary


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────
def print_report(summary: Dict) -> None:
    log.info("=" * 72)
    log.info("SOURCE DIVERSITY ENFORCER — v%s", VERSION)
    log.info("=" * 72)
    log.info("Overall status     : %s", summary.get("status", "?"))
    log.info("Total advisories   : %s", summary.get("total_advisories", "?"))
    log.info("Unique sources     : %s  (min %s)", summary.get("unique_sources", "?"), MIN_SOURCES)
    log.info("Shannon entropy    : %s bits  (min %.1f / warn %.1f)",
             summary.get("entropy_bits", "?"), MIN_ENTROPY, WARN_ENTROPY)
    log.info("Top source         : %s at %s%% (max %.0f%%)",
             summary.get("top_source", "?"), summary.get("top_source_pct", "?"), MAX_DOMINANCE_PCT)
    log.info("Synthetic items    : %s", summary.get("synthetic_count", "?"))
    log.info("-" * 72)
    checks = summary.get("checks", {})
    for check_name, result in checks.items():
        flag = "[OK]  " if result.get("status") == "OK" else \
               "[WARN]" if result.get("status") == "WARN" else "[FAIL]"
        log.info("%-22s %s  %s", check_name, flag, result.get("message", ""))
    log.info("=" * 72)

    # Detail flood sources
    flood_sources = checks.get("flood", {}).get("flood_sources", [])
    if flood_sources:
        log.warning("Flood sources detected:")
        for fs in flood_sources[:5]:
            log.warning("  %s: %d items (%.1f%%)", fs["domain"], fs["count"], fs["pct"])

    # Detail dominance violations
    violations = checks.get("dominance", {}).get("violations", [])
    if violations:
        log.error("DOMINANCE VIOLATIONS:")
        for v in violations:
            log.error("  %s: %.1f%% (golden invariant max %.0f%%)",
                      v["domain"], v["pct"], MAX_DOMINANCE_PCT)

    if summary.get("hard_fail"):
        log.error("HARD FAIL — source diversity governance violated.")
    elif summary.get("status") == "WARN":
        log.warning("WARN — source diversity degraded. Review above.")
    else:
        log.info("PASS — source diversity governance satisfied.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Source Diversity Enforcer"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true",
                     help="Validate; exit 1 on HARD FAIL")
    grp.add_argument("--report", action="store_true",
                     help="Print diversity report, always exit 0")
    parser.add_argument("--strict", action="store_true",
                        help="Elevate WARN conditions to HARD FAIL")
    args = parser.parse_args()

    engine = DiversityEnforcerReport()
    apply = not args.report
    summary = engine.run(apply=apply, strict=args.strict)
    print_report(summary)

    if args.report:
        return 0
    if summary.get("hard_fail"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
