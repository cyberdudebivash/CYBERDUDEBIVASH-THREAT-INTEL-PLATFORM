#!/usr/bin/env python3
"""
scripts/severity_governance_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Severity Governance Engine
Full KEV→CVSS→EPSS→Context hierarchy with mandatory floors.
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.severity_governance")
REPO_ROOT = Path(__file__).resolve().parent.parent

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_REVERSE = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}

def _sev_max(a, b):
    return SEVERITY_REVERSE[max(SEVERITY_ORDER.get(a,0), SEVERITY_ORDER.get(b,0))]

class SeverityGovernanceEngine:
    """
    Severity hierarchy:
      KEV → Active Exploitation → Ransomware → Zero Day → EPSS → CVSS → Threat Context → Business Impact
    Mandatory floors:
      kev=true/YES            → HIGH minimum
      actively exploited       → HIGH minimum
      ransomware               → HIGH minimum
      zero-day / 0-day         → HIGH minimum
      KEV + Active Exploit     → CRITICAL
      CVSS >= 9.0              → HIGH minimum
      EPSS >= 0.7              → HIGH minimum
    """

    # Regex patterns for text signals
    ACTIVE_EXPLOIT_RE = re.compile(
        r"actively exploit|exploited in the wild|in-the-wild|wild exploit|under active attack",
        re.IGNORECASE
    )
    RANSOMWARE_RE = re.compile(r"ransomware|ransom", re.IGNORECASE)
    ZERO_DAY_RE = re.compile(r"zero.?day|0.?day", re.IGNORECASE)
    KEV_RE = re.compile(r"\bkev\b", re.IGNORECASE)

    def __init__(self):
        self.now_utc = datetime.now(timezone.utc)
        self.rules_fired = []
        self.upgrades = 0
        self.downgrades = 0

    def _text_signals(self, item):
        """Concatenate all textual fields for pattern matching."""
        return " ".join(str(item.get(f,"")) for f in (
            "title","description","tags","threat_type","ttps",
            "actor_tag","notes","summary","analysis"
        ))

    def _is_kev(self, item):
        kev_field = item.get("kev") or item.get("kev_present") or item.get("in_kev")
        if kev_field:
            if isinstance(kev_field, bool):
                return kev_field
            if str(kev_field).upper() in ("TRUE","YES","1"):
                return True
        # Check text signals
        text = self._text_signals(item)
        return bool(self.KEV_RE.search(text) and ("known exploited" in text.lower() or "kev" in text.lower()))

    def _is_actively_exploited(self, item):
        text = self._text_signals(item)
        return bool(self.ACTIVE_EXPLOIT_RE.search(text))

    def _is_ransomware(self, item):
        text = self._text_signals(item)
        return bool(self.RANSOMWARE_RE.search(text))

    def _is_zero_day(self, item):
        text = self._text_signals(item)
        return bool(self.ZERO_DAY_RE.search(text))

    def _get_cvss(self, item):
        for f in ("cvss_score","cvss","cvss_v3","cvss_base_score","risk_score"):
            v = item.get(f)
            if v is not None:
                try:
                    score = float(v)
                    if 0 <= score <= 10:
                        return score
                except (ValueError, TypeError):
                    pass
        return None

    def _get_epss(self, item):
        for f in ("epss_score","epss"):
            v = item.get(f)
            if v is not None:
                try:
                    score = float(v)
                    if 0 <= score <= 1:
                        return score
                except (ValueError, TypeError):
                    pass
        return None

    def score_item(self, item):
        """
        Returns (new_severity, reason, score_details) tuple.
        Applies full hierarchy of governance rules.
        """
        original_sev = (item.get("severity") or "MEDIUM").upper()
        if original_sev not in SEVERITY_ORDER:
            original_sev = "MEDIUM"

        new_sev = original_sev
        rules = []
        score_details = {}

        kev = self._is_kev(item)
        active_exploit = self._is_actively_exploited(item)
        ransomware = self._is_ransomware(item)
        zero_day = self._is_zero_day(item)
        cvss = self._get_cvss(item)
        epss = self._get_epss(item)

        score_details["kev"] = kev
        score_details["active_exploit"] = active_exploit
        score_details["ransomware"] = ransomware
        score_details["zero_day"] = zero_day
        score_details["cvss"] = cvss
        score_details["epss"] = epss

        # Rule 1: KEV + Active Exploit → CRITICAL
        if kev and active_exploit:
            new_sev = _sev_max(new_sev, "CRITICAL")
            rules.append("KEV+ACTIVE_EXPLOIT→CRITICAL")

        # Rule 2: KEV alone → HIGH minimum
        if kev:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append("KEV→HIGH_FLOOR")

        # Rule 3: Actively exploited → HIGH minimum
        if active_exploit:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append("ACTIVE_EXPLOIT→HIGH_FLOOR")

        # Rule 4: Ransomware → HIGH minimum
        if ransomware:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append("RANSOMWARE→HIGH_FLOOR")

        # Rule 5: Zero-day → HIGH minimum
        if zero_day:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append("ZERO_DAY→HIGH_FLOOR")

        # Rule 6: CVSS >= 9.0 → HIGH minimum
        if cvss is not None and cvss >= 9.0:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append(f"CVSS={cvss}>=9.0→HIGH_FLOOR")

        # Rule 7: EPSS >= 0.7 → HIGH minimum
        if epss is not None and epss >= 0.7:
            new_sev = _sev_max(new_sev, "HIGH")
            rules.append(f"EPSS={epss}>=0.7→HIGH_FLOOR")

        # Rule 8: CVSS >= 7.0 → MEDIUM minimum
        if cvss is not None and 7.0 <= cvss < 9.0:
            new_sev = _sev_max(new_sev, "MEDIUM")
            rules.append(f"CVSS={cvss}>=7.0→MEDIUM_FLOOR")

        # Rule 9: EPSS >= 0.4 → MEDIUM minimum
        if epss is not None and 0.4 <= epss < 0.7:
            new_sev = _sev_max(new_sev, "MEDIUM")
            rules.append(f"EPSS={epss}>=0.4→MEDIUM_FLOOR")

        reason = "; ".join(rules) if rules else "NO_GOVERNANCE_RULES_FIRED"
        return new_sev, reason, score_details

    def run_governance(self, feed_path):
        feed_path = Path(feed_path)
        if not feed_path.exists():
            return {"error": f"File not found: {feed_path}", "status": "FAIL"}

        raw = json.loads(feed_path.read_text(encoding="utf-8"))
        is_dict = isinstance(raw, dict)
        if is_dict:
            items = raw.get("items", raw.get("advisories", raw.get("data", [])))
        else:
            items = raw

        before_dist = {}
        for i in items:
            s = (i.get("severity") or "UNKNOWN").upper()
            before_dist[s] = before_dist.get(s,0)+1

        governed_items = []
        kev_violations = []
        rules_fired_counts = {}
        upgrades = 0

        for item in items:
            item = dict(item)
            orig_sev = (item.get("severity") or "MEDIUM").upper()
            new_sev, reason, score_details = self.score_item(item)

            if SEVERITY_ORDER.get(new_sev,0) > SEVERITY_ORDER.get(orig_sev,0):
                upgrades += 1
                item["_severity_upgraded_from"] = orig_sev
                item["_severity_governance_reason"] = reason

            # KEV violation check: KEV items must not be LOW
            if score_details.get("kev") and new_sev == "LOW":
                kev_violations.append({"id": item.get("id","?"), "severity_assigned": new_sev, "issue": "KEV_item_assigned_LOW"})

            item["severity"] = new_sev
            item["_governance_rules"] = reason
            item["_score_details"] = score_details

            for rule in reason.split("; "):
                if rule != "NO_GOVERNANCE_RULES_FIRED":
                    rules_fired_counts[rule] = rules_fired_counts.get(rule,0)+1

            governed_items.append(item)

        after_dist = {}
        for i in governed_items:
            s = i.get("severity","UNKNOWN")
            after_dist[s] = after_dist.get(s,0)+1

        if is_dict:
            for key in ("items","advisories","data"):
                if key in raw:
                    raw[key] = governed_items; break
            else:
                raw["items"] = governed_items
            output = raw
        else:
            output = governed_items

        # v173.0 FIX: atomic write via temp file to prevent null-byte corruption.
        # Direct write_text on large files can leave old content past the new EOF on
        # some filesystems (GitHub Actions runner NTFS/ext4 under high I/O load).
        import tempfile
        _out_json = json.dumps(output, indent=2, ensure_ascii=False)
        _tmp = feed_path.with_suffix(".gov_tmp")
        _tmp.write_text(_out_json, encoding="utf-8")
        _tmp.replace(feed_path)

        return {
            "validator": "SeverityGovernanceEngine",
            "feed_path": str(feed_path),
            "run_at": self.now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "before_distribution": before_dist,
            "after_distribution": after_dist,
            "upgrades": upgrades,
            "kev_violations": kev_violations,
            "rules_fired": rules_fired_counts,
            "status": "PASS" if not kev_violations else "WARN"
        }


def run_severity_governance_stage(feed_paths=None):
    if feed_paths is None:
        feed_paths = [REPO_ROOT/"api"/"feed.json", REPO_ROOT/"feed.json"]
    combined = {"stage": "severity_governance", "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {}, "total_upgrades": 0, "kev_violations": 0, "overall_status": "PASS"}
    for path in feed_paths:
        eng = SeverityGovernanceEngine()
        r = eng.run_governance(path)
        combined["files"][str(path)] = r
        combined["total_upgrades"] += r.get("upgrades",0)
        combined["kev_violations"] += len(r.get("kev_violations",[]))
        if r.get("status") == "FAIL":
            combined["overall_status"] = "FAIL"
    rp = REPO_ROOT/"reports"/"severity_validation_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")
    return combined

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    r = run_severity_governance_stage([path] if path else None)
    print(json.dumps(r, indent=2))
