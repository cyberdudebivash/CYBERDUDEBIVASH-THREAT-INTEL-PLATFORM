#!/usr/bin/env python3
"""
scripts/sentinel_convergence_certifier.py
CYBERDUDEBIVASH(R) SENTINEL APEX v174.0 -- Convergence Certifier
====================================================================
Single authoritative, stdlib-only, idempotent integrity gate that runs LATE in
the pipeline (immediately before publish) and GUARANTEES the customer-facing
feed satisfies every production-certification invariant. It does not trust
upstream stages -- it ENFORCES. Deterministic, lossless fixes self-heal; the
rest HARD-FAIL.

Invariants:
  I1 RISK       risk_score = MAX(weighted CVSS model, CVSS-band floor, threat lens)
  I2 SEVERITY   derived from risk_score; never below CVSS base-severity band
  I3 CONFIDENCE evidence-weighted (source tier x corroboration x signals); no 0.2 uniformity
  I4 DEDUP      canonical key (primary CVE | title slug); keep most-enriched
  I5 REPORTS    every report_url must resolve to a reports/ artifact, else stripped + unpublished
  I6 IOC        actionable (non-CVE) IOC count recomputed + flagged
  I7 LEDGER     tamper-evident sha256 ledger written unconditionally (apply)
  I8 COUNT      feed_count emitted as dashboard single source of truth

Modes: --check (exit 1 on violation) | --apply (heal+rewrite) | --report (always 0)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CONVERGENCE-CERT] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.convergence_certifier")

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_VERSION = "174.0"

DEFAULT_FEED = REPO_ROOT / "api" / "feed.json"
REPORTS_DIR = REPO_ROOT / "reports"
LEDGER_PATH = REPO_ROOT / "data" / "health" / "advisory_immutability.json"
CERT_PATH = REPO_ROOT / "data" / "quality" / "convergence_certification.json"

W_CVSS, W_EPSS, W_KEV, W_MATURITY, W_EXPOSURE, W_CHAIN = 0.22, 0.22, 0.18, 0.14, 0.22, 0.02


def cvss_band_floor(cvss: Optional[float]) -> float:
    if cvss is None:
        return 0.0
    if cvss >= 9.0:
        return 9.0
    if cvss >= 7.0:
        return 7.0
    if cvss >= 4.0:
        return 4.0
    if cvss > 0.0:
        return 0.1
    return 0.0


def severity_from_risk(risk: float) -> str:
    if risk >= 9.0:
        return "CRITICAL"
    if risk >= 7.0:
        return "HIGH"
    if risk >= 4.0:
        return "MEDIUM"
    return "LOW"


def load_feed(path: Path) -> List[Dict[str, Any]]:
    raw = path.read_bytes()
    nul = raw.count(b"\x00")
    if nul:
        log.warning("Feed contains %d NUL byte(s) -- stripping corruption padding", nul)
        raw = raw.rstrip(b"\x00").replace(b"\x00", b"")
    data = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(data, list):
        raise ValueError("Feed root is not a JSON array")
    return data


def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _num(*vals) -> Optional[float]:
    for v in vals:
        if v is None or v == "":
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    return None


def extract_cvss(item: Dict) -> Optional[float]:
    c = _num(item.get("cvss_score"), item.get("cvss"), item.get("cvss3_score"), item.get("cvss_v3"))
    if c is None:
        return None
    return max(0.0, min(10.0, c))


def extract_epss(item: Dict) -> float:
    e = _num(item.get("epss_score"), item.get("epss"), item.get("epss_normalized"))
    if e is None:
        return 0.0
    if e > 1.0:
        e = e / 100.0
    return max(0.0, min(1.0, e))


def extract_kev(item: Dict) -> float:
    for key in ("kev", "cisa_kev", "kev_listed", "kev_present"):
        v = item.get(key)
        if isinstance(v, bool):
            if v:
                return 1.0
            continue
        if str(v).strip().upper() in ("YES", "TRUE", "1", "LISTED"):
            return 1.0
    return 0.0


_MATURITY_MAP = [
    (r"activ(e|ely)|in.the.wild|\bitw\b|exploited", 1.00),
    (r"weaponi[sz]ed|metasploit|framework", 0.90),
    (r"functional", 0.70),
    (r"poc|proof.of.concept", 0.50),
    (r"unproven|theoret|none", 0.10),
]


def extract_maturity(item: Dict) -> float:
    text = " ".join(str(item.get(k, "")) for k in ("exploit_maturity", "exploit_status", "exploit_stage")).lower()
    if str(item.get("metasploit_available")).upper() == "TRUE":
        return 0.90
    poc_n = _num(item.get("poc_github_count"), item.get("exploit_count"))
    for pat, val in _MATURITY_MAP:
        if re.search(pat, text):
            return val
    if poc_n and poc_n > 0:
        return 0.50
    return 0.10


def extract_exposure(item: Dict) -> float:
    vec = str(item.get("cvss_vector") or "")
    av = str(item.get("attack_vector") or "").upper()
    if "AV:N" in vec or av == "NETWORK":
        return 0.90
    if "AV:A" in vec or av == "ADJACENT":
        return 0.50
    if "AV:L" in vec or av == "LOCAL":
        return 0.20
    if "AV:P" in vec or av == "PHYSICAL":
        return 0.10
    blob = (str(item.get("title", "")) + str(item.get("description", ""))).lower()
    if re.search(r"remote|unauthenticated|internet.facing|pre.auth", blob):
        return 0.75
    return 0.40


def extract_chain(item: Dict) -> float:
    blob = (str(item.get("title", "")) + str(item.get("description", ""))).lower()
    return 1.0 if re.search(r"chain|privilege.escal|zero.click|0.click|wormable", blob) else 0.0


# Threat-signal lens: scores non-CVE editorial intel and CVE items lacking CVSS
# (e.g. published exploits) so they are NOT forced to LOW. Bounded [0,1].
_THREAT_SIGNALS = [
    (r"activ(e|ely)\s+exploit|in.the.wild|\bitw\b|zero.day\s+exploit|emergency\s+directive", 0.90),
    (r"\bkev\b|cisa\s+(adds|warns|alert)|known\s+exploited", 0.85),
    (r"ransomware|wiper|\brat\b|backdoor|botnet|rootkit|cryptominer|infostealer", 0.75),
    (r"rce|remote\s+code\s+execution|unauthenticated|pre.auth|auth(entication)?\s+bypass", 0.72),
    (r"apt\b|nation.state|state.sponsored|espionage|threat\s+actor", 0.66),
    (r"supply.chain|data\s+breach|exfiltrat|sanction|takedown|exposed\s+credentials", 0.55),
    (r"vulnerab|advisory|patch|flaw|cve-", 0.45),
]


def threat_signal_score(item: Dict, maturity: float, exposure: float) -> float:
    blob = " ".join(str(item.get(k, "")) for k in ("title", "description", "threat_type", "tags")).lower()
    best = 0.0
    for pat, val in _THREAT_SIGNALS:
        if re.search(pat, blob):
            best = max(best, val)
            break
    best = max(best, maturity * 0.95, exposure * 0.70)
    if best == 0.0:
        best = 0.30
    return min(1.0, best)


def compute_risk_and_severity(item: Dict) -> Tuple[float, str, Dict[str, Any]]:
    cvss = extract_cvss(item)
    cvss_n = (cvss / 10.0) if cvss is not None else 0.0
    epss = extract_epss(item)
    kev = extract_kev(item)
    maturity = extract_maturity(item)
    exposure = extract_exposure(item)
    chain = extract_chain(item)

    risk01 = (W_CVSS * cvss_n + W_EPSS * epss + W_KEV * kev
              + W_MATURITY * maturity + W_EXPOSURE * exposure + W_CHAIN * chain)
    threat = threat_signal_score(item, maturity, exposure)
    risk_model = risk01 * 10.0
    risk_floor = cvss_band_floor(cvss)
    risk_threat = threat * 10.0
    risk = round(min(10.0, max(risk_model, risk_floor, risk_threat)), 2)
    severity = severity_from_risk(risk)
    breakdown = {
        "cvss": cvss, "epss": epss, "kev": kev, "maturity": maturity,
        "exposure": exposure, "chain": chain,
        "cvss_model": round(risk_model, 2), "cvss_band_floor": risk_floor,
        "threat_lens": round(risk_threat, 2),
        "lens_used": "threat" if risk_threat >= max(risk_model, risk_floor)
                     else ("floor" if risk_floor >= risk_model else "cvss_model"),
    }
    return risk, severity, breakdown


_SOURCE_TIER = {
    "nvd.nist.gov": 0.95, "cisa.gov": 0.95, "first.org": 0.90,
    "github.com": 0.70, "vulners.com": 0.65, "cvefeed.io": 0.60,
    "bleepingcomputer.com": 0.75, "thehackernews.com": 0.70,
}


def source_reliability(item: Dict) -> float:
    explicit = _num(item.get("source_reliability"), item.get("source_trust_score"))
    if explicit is not None:
        return max(0.0, min(1.0, explicit if explicit <= 1.0 else explicit / 100.0))
    dom = str(item.get("source_domain") or item.get("source") or "").lower()
    url = str(item.get("source_url") or "").lower()
    for k, v in _SOURCE_TIER.items():
        if k in dom or k in url:
            return v
    return 0.55


def compute_confidence(item: Dict, breakdown: Dict) -> Tuple[float, int]:
    rel = source_reliability(item)
    corro = _num(item.get("corroboration_count"), item.get("evidence_count")) or 1
    corro_factor = min(1.0, 0.2 + (corro - 1) * 0.2)
    signals = 0.0
    if breakdown["cvss"] is not None:
        signals += 0.20
    if breakdown["epss"] > 0:
        signals += 0.20
    if breakdown["kev"] > 0:
        signals += 0.20
    ioc_n = _num(item.get("ioc_count"), item.get("real_ioc_count")) or 0
    if ioc_n > 0:
        signals += 0.20
    ttps = item.get("ttps") or item.get("attck_technique_ids") or []
    if isinstance(ttps, list) and ttps:
        signals += min(0.20, len(ttps) * 0.07)
    conf01 = 0.35 * rel + 0.25 * corro_factor + 0.40 * min(1.0, signals)
    conf01 = round(max(0.05, min(1.0, conf01)), 3)
    return conf01, int(round(conf01 * 100))


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def canonical_key(item: Dict) -> str:
    for field in (item.get("cve_id"), item.get("title"), item.get("description")):
        if field:
            m = _CVE_RE.search(str(field))
            if m:
                return m.group(0).upper()
    cves = item.get("cve_ids")
    if isinstance(cves, list) and cves:
        m = _CVE_RE.search(str(cves[0]))
        if m:
            return m.group(0).upper()
    title = str(item.get("title", "")).lower().strip()
    return "title::" + _SLUG_RE.sub("-", title)[:80]


def enrichment_rank(item: Dict) -> Tuple:
    return (
        1 if item.get("report_url") else 0,
        _num(item.get("real_ioc_count"), item.get("ioc_count")) or 0,
        1 if extract_cvss(item) is not None else 0,
        1 if extract_epss(item) > 0 else 0,
        len(str(item.get("description", ""))),
        str(item.get("processed_at") or item.get("generated_at") or ""),
    )


def dedup(items: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    best: Dict[str, Dict] = {}
    removed: List[Dict] = []
    for it in items:
        k = canonical_key(it)
        if k not in best:
            best[k] = it
        elif enrichment_rank(it) > enrichment_rank(best[k]):
            removed.append(best[k])
            best[k] = it
        else:
            removed.append(it)
    return list(best.values()), removed


_SOFT404_MARKERS = ("report_not_found", "report not found", "page not found", "404 not found")


def report_artifact_exists(report_url: str) -> bool:
    """P0-1 fail-closed gate: a report_url is publishable ONLY if its artifact
    exists, is readable, and carries a VALID report body (size + <html> + no
    soft-404 marker). A file that exists but is a stub/soft-404 is treated as
    MISSING -> the url is stripped and the item unpublished."""
    m = re.search(r"/reports/(.+\.html)$", str(report_url))
    if not m:
        return False
    disk = REPORTS_DIR / m.group(1)
    if not disk.exists():
        return False
    try:
        body = disk.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if len(body) < 512:
        return False
    low = body.lower()
    if "<html" not in low and "<!doctype" not in low:
        return False
    return not any(mk in low for mk in _SOFT404_MARKERS)


def build_ledger(items: List[Dict]) -> Dict[str, Any]:
    advisories = []
    hasher = hashlib.sha256()
    for it in sorted(items, key=canonical_key):
        content = json.dumps(
            {k: it.get(k) for k in ("title", "risk_score", "severity", "cvss_score", "report_url")},
            sort_keys=True, ensure_ascii=False,
        )
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        advisories.append({"canonical_key": canonical_key(it), "id": it.get("id"), "content_sha256": digest})
        hasher.update(digest.encode("utf-8"))
    return {
        "ledger_version": GATE_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisory_count": len(advisories),
        "ledger_digest": hasher.hexdigest(),
        "advisories": advisories,
    }


def certify(items: List[Dict], apply: bool) -> Tuple[List[Dict], Dict[str, Any]]:
    violations: List[str] = []
    healed = {
        "risk_recomputed": 0, "severity_corrected": 0, "confidence_recalibrated": 0,
        "duplicates_removed": 0, "dangling_report_urls_stripped": 0,
    }

    deduped, removed = dedup(items)
    healed["duplicates_removed"] = len(removed)
    if removed and not apply:
        violations.append(f"I4 DEDUP: {len(removed)} duplicate advisory record(s) present")

    confidences = []
    for it in deduped:
        new_risk, new_sev, bd = compute_risk_and_severity(it)
        if abs((_num(it.get("risk_score")) or -1) - new_risk) > 0.01:
            if not apply:
                violations.append(f"I1 RISK: '{str(it.get('title',''))[:38]}' {it.get('risk_score')} != model {new_risk}")
            healed["risk_recomputed"] += 1
        if str(it.get("severity", "")).upper() != new_sev:
            if not apply:
                violations.append(f"I2 SEVERITY: '{str(it.get('title',''))[:38]}' {it.get('severity')} vs band {new_sev}")
            healed["severity_corrected"] += 1
        cvss = bd["cvss"]
        if cvss is not None and cvss >= 9.0 and new_sev == "LOW":
            violations.append(f"I2 HARD: CVSS {cvss} computed LOW -- floor failed")
        if apply:
            it["risk_score"] = new_risk
            it["severity"] = new_sev
            it["risk_score_reasoning"] = bd
            it["_cert_scored_by"] = f"convergence_certifier_v{GATE_VERSION}"

        conf01, conf100 = compute_confidence(it, bd)
        confidences.append(conf01)
        if abs((_num(it.get("confidence")) or -1) - conf01) > 0.001:
            healed["confidence_recalibrated"] += 1
        if apply:
            it["confidence"] = conf01
            it["confidence_score"] = conf100

        ru = it.get("report_url")
        if ru and not report_artifact_exists(ru):
            healed["dangling_report_urls_stripped"] += 1
            if not apply:
                violations.append(f"I5 REPORT: dangling report_url for '{str(it.get('title',''))[:38]}'")
            else:
                it["_quarantined_report_url"] = ru
                it["report_url"] = None
                it["is_published"] = False
                it["publication_decision"] = "BLOCKED_REPORT_ARTIFACT_MISSING"

        iocs = it.get("iocs") or []
        actionable = 0
        if isinstance(iocs, list):
            actionable = sum(1 for x in iocs if isinstance(x, dict)
                             and str(x.get("type", "")).lower() not in ("cve", ""))
        if apply:
            it["actionable_ioc_count"] = actionable
            it["ioc_non_actionable"] = actionable == 0

    if confidences:
        c = Counter(confidences)
        top_val, top_n = c.most_common(1)[0]
        ratio = top_n / len(confidences)
        if ratio > 0.60:
            violations.append(f"I3 CONFIDENCE: value {top_val} in {top_n}/{len(confidences)} ({ratio*100:.1f}%) > 60%")

    ledger = build_ledger(deduped)
    if apply:
        atomic_write_json(LEDGER_PATH, ledger)
        log.info("I7 immutability ledger written: %s (%d advisories)", LEDGER_PATH, ledger["advisory_count"])

    report = {
        "certifier_version": GATE_VERSION,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "apply" if apply else "check",
        "feed_count": len(deduped),
        "duplicates_removed": len(removed),
        "healed": healed,
        "violations": violations,
        "hard_fail": len(violations) > 0 and not apply,
        "ledger_digest": ledger["ledger_digest"],
    }
    return deduped, report


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL APEX Convergence Certifier")
    ap.add_argument("--feed", default=str(DEFAULT_FEED))
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true")
    grp.add_argument("--apply", action="store_true")
    grp.add_argument("--report", action="store_true")
    args = ap.parse_args()

    feed_path = Path(args.feed)
    apply = bool(args.apply)
    mode = "apply" if apply else ("report" if args.report else "check")

    log.info("=" * 70)
    log.info("SENTINEL APEX Convergence Certifier v%s | mode=%s | feed=%s", GATE_VERSION, mode.upper(), feed_path)
    log.info("=" * 70)

    items = load_feed(feed_path)
    log.info("Loaded %d feed item(s)", len(items))

    deduped, report = certify(items, apply=apply)

    if apply:
        atomic_write_json(feed_path, deduped)
        log.info("Feed atomically rewritten: %d item(s) (was %d)", len(deduped), len(items))
        _, recheck = certify(json.loads(json.dumps(deduped)), apply=False)
        report["post_apply_violations"] = recheck["violations"]
        report["hard_fail"] = len(recheck["violations"]) > 0

    atomic_write_json(CERT_PATH, report)
    log.info("Certification report: %s", CERT_PATH)
    log.info("-" * 70)
    log.info("feed_count=%d duplicates_removed=%d", report["feed_count"], report["duplicates_removed"])
    log.info("healed=%s", json.dumps(report["healed"]))
    vlist = report.get("post_apply_violations", report["violations"])
    if vlist:
        log.error("RESIDUAL VIOLATIONS: %d", len(vlist))
        for v in vlist[:40]:
            log.error("  - %s", v)
    else:
        log.info("INVARIANTS: ALL CLEAR (0 violations)")
    log.info("=" * 70)

    if mode == "report":
        return 0
    return 1 if report["hard_fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
