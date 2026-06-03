#!/usr/bin/env python3
"""
scripts/metrics_service.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Authoritative Metrics Service
Single source of truth for all dashboard metrics. Writes to api/stats.json.
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

log = logging.getLogger("sentinel.metrics_service")
REPO_ROOT = Path(__file__).resolve().parent.parent
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def _load_items(path):
    path = Path(path)
    if not path.exists(): return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        for key in ("items","advisories","data","feed"):
            if key in raw and isinstance(raw[key],list):
                return raw[key]
        return []
    return raw if isinstance(raw, list) else []

class MetricsService:
    def __init__(self):
        self.now_utc = datetime.now(timezone.utc)

    def compute_metrics(self, feed_path):
        """Single authoritative metric computation from a feed file."""
        items = _load_items(feed_path)
        if not items:
            return {"error": f"No items found in {feed_path}", "advisory_count": 0}

        sev_dist = defaultdict(int)
        ioc_total = 0
        sources = set()
        kev_count = 0
        cve_ids = set()
        risk_scores = []

        for item in items:
            sev = (item.get("severity") or "UNKNOWN").upper()
            sev_dist[sev] += 1

            ioc_count = item.get("ioc_count",0)
            try: ioc_total += int(ioc_count)
            except: pass

            src = item.get("source") or item.get("source_name") or item.get("feed_source")
            if src: sources.add(src)

            kev = item.get("kev") or item.get("kev_present") or item.get("in_kev")
            if kev and str(kev).upper() in ("TRUE","YES","1","TRUE"):
                kev_count += 1

            # Collect CVEs
            for f in ("cve","cve_ids"):
                v = item.get(f,"")
                if isinstance(v, list):
                    for c in v: cve_ids.add(c.upper())
                else:
                    cve_ids.update(c.upper() for c in CVE_RE.findall(str(v)))
            for f in ("title","description"):
                cve_ids.update(c.upper() for c in CVE_RE.findall(str(item.get(f,""))))

            rs = item.get("risk_score")
            if rs is not None:
                try: risk_scores.append(float(rs))
                except: pass

        risk_avg = round(sum(risk_scores)/len(risk_scores),2) if risk_scores else 0.0

        return {
            "advisory_count": len(items),
            "ioc_total": ioc_total,
            "critical_count": sev_dist.get("CRITICAL",0),
            "high_count": sev_dist.get("HIGH",0),
            "medium_count": sev_dist.get("MEDIUM",0),
            "low_count": sev_dist.get("LOW",0),
            "risk_avg": risk_avg,
            "source_count": len(sources),
            "kev_count": kev_count,
            "unique_cve_count": len(cve_ids),
            "severity_distribution": dict(sev_dist),
            "sources": sorted(sources),
        }

    def save_metrics(self, metrics, output_path=None):
        """Write metrics to api/stats.json."""
        if output_path is None:
            output_path = REPO_ROOT / "api" / "stats.json"
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing stats and merge
        existing = {}
        if output_path.exists():
            try:
                existing = json.loads(output_path.read_text(encoding="utf-8"))
            except: pass

        stats = {**existing, **metrics,
                 "generated_at": self.now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "source": "MetricsService"}
        output_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
        return stats

    def detect_mismatches(self, computed, stats_path=None):
        """Detect mismatches between computed metrics and stored stats.json."""
        if stats_path is None:
            stats_path = REPO_ROOT / "api" / "stats.json"
        stats_path = Path(stats_path)
        if not stats_path.exists():
            return {"error": "stats.json not found", "mismatches": []}
        stored = json.loads(stats_path.read_text(encoding="utf-8"))
        mismatches = []
        for key in ("advisory_count","high_count","medium_count","low_count","kev_count"):
            stored_val = stored.get(key)
            computed_val = computed.get(key)
            if stored_val is not None and computed_val is not None and stored_val != computed_val:
                mismatches.append({"field": key, "stored": stored_val, "computed": computed_val, "delta": computed_val - stored_val})
        return {"mismatches": mismatches, "mismatch_count": len(mismatches)}


def run_metrics_stage():
    svc = MetricsService()
    feed_path = REPO_ROOT / "api" / "feed.json"
    metrics = svc.compute_metrics(feed_path)

    # Also check latest.json
    latest_path = REPO_ROOT / "api" / "latest.json"
    latest_items = _load_items(latest_path)
    latest_metrics = svc.compute_metrics(latest_path) if latest_items else {"advisory_count": 0}

    # Save to api/stats.json
    saved = svc.save_metrics(metrics)

    # Detect mismatches
    mismatch = svc.detect_mismatches(metrics)

    # Build dashboard consistency report
    report = {
        "service": "MetricsService",
        "run_at": svc.now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feed_metrics": metrics,
        "latest_metrics": latest_metrics,
        "stats_written_to": str(REPO_ROOT/"api"/"stats.json"),
        "mismatches": mismatch,
        "status": "PASS" if mismatch["mismatch_count"] == 0 else "WARN"
    }
    rp = REPO_ROOT / "reports" / "dashboard_consistency_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_metrics_stage()
    print(json.dumps(r, indent=2))
