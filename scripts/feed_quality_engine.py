#!/usr/bin/env python3
"""
scripts/feed_quality_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Feed Quality Engine
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

log = logging.getLogger("sentinel.feed_quality")
REPO_ROOT = Path(__file__).resolve().parent.parent

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def _cve_ids(item):
    cve_field = item.get("cve") or item.get("cve_ids") or ""
    if isinstance(cve_field, list):
        cves = set(c.upper() for c in cve_field if c)
    else:
        cves = set(CVE_RE.findall(str(cve_field)))
    # also scan title/description
    for f in ("title","description"):
        cves.update(c.upper() for c in CVE_RE.findall(str(item.get(f,""))))
    return cves

def _title_key(title):
    """Normalize title for similarity comparison."""
    t = re.sub(r"CVE-\d{4}-\d+", "", str(title).lower())
    t = re.sub(r"[^a-z0-9 ]", " ", t)
    return " ".join(t.split()[:8])

class FeedQualityEngine:
    def __init__(self):
        self.now_utc = datetime.now(timezone.utc)

    def detect_duplicates(self, items):
        """Detect duplicates by ID, CVE ID, and title similarity."""
        seen_ids = {}
        seen_cves = defaultdict(list)
        seen_titles = {}
        id_dups, cve_dups, title_dups = [], [], []

        for i, item in enumerate(items):
            item_id = item.get("id","")
            # ID duplicates
            if item_id and item_id in seen_ids:
                id_dups.append({"item_index": i, "id": item_id, "first_seen": seen_ids[item_id]})
            else:
                seen_ids[item_id] = i

            # CVE duplicates
            cves = _cve_ids(item)
            for cve in cves:
                seen_cves[cve].append(i)

            # Title duplicates
            tk = _title_key(item.get("title",""))
            if tk and len(tk) > 10:
                if tk in seen_titles:
                    title_dups.append({"item_index": i, "title_key": tk, "first_seen": seen_titles[tk]})
                else:
                    seen_titles[tk] = i

        for cve, indices in seen_cves.items():
            if len(indices) > 1:
                cve_dups.append({"cve": cve, "item_indices": indices, "count": len(indices)})

        return {"id_duplicates": id_dups, "cve_duplicates": cve_dups, "title_duplicates": title_dups}

    def detect_source_duplication(self, items):
        """Same CVE from multiple sources."""
        cve_sources = defaultdict(set)
        for item in items:
            src = item.get("source") or item.get("source_name","?")
            for cve in _cve_ids(item):
                cve_sources[cve].add(src)
        multi_source = {cve: list(srcs) for cve,srcs in cve_sources.items() if len(srcs) > 1}
        return {"multi_source_cves": multi_source, "count": len(multi_source)}

    def detect_campaign_duplication(self, items):
        """Items with identical actor_tag and threat_type within short time window."""
        campaign_map = defaultdict(list)
        for i, item in enumerate(items):
            actor = item.get("actor_tag","")
            threat = item.get("threat_type","")
            if actor and threat:
                key = f"{actor}::{threat}"
                campaign_map[key].append({"index": i, "id": item.get("id","?"), "title": item.get("title","")[:60]})
        dups = {k: v for k,v in campaign_map.items() if len(v) > 1}
        return {"duplicate_campaigns": dups, "count": len(dups)}

    def score_quality(self, items):
        """Compute overall quality score 0-100."""
        if not items:
            return 0
        n = len(items)
        scores = []

        # Field completeness (30 pts)
        required = ["id","title","severity","published_at","source"]
        completeness = sum(1 for i in items if all(i.get(f) for f in required)) / n
        scores.append(("field_completeness", completeness * 30))

        # Source diversity (20 pts)
        sources = set(i.get("source","?") for i in items)
        diversity = min(len(sources) / 10, 1.0)
        scores.append(("source_diversity", diversity * 20))

        # No future timestamps (15 pts)
        now = self.now_utc
        future_count = 0
        for item in items:
            pub = item.get("published_at","")
            if pub:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(str(pub).replace("Z","+00:00"))
                    if dt.tzinfo is None:
                        from datetime import timezone as tz
                        dt = dt.replace(tzinfo=tz.utc)
                    if dt > now:
                        future_count += 1
                except: pass
        ts_score = max(0, 1 - future_count/n)
        scores.append(("timestamp_integrity", ts_score * 15))

        # Dedup ratio (15 pts)
        dup_data = self.detect_duplicates(items)
        dup_count = len(dup_data["id_duplicates"]) + len(dup_data["title_duplicates"])
        dedup_score = max(0, 1 - dup_count/n)
        scores.append(("dedup_ratio", dedup_score * 15))

        # Severity distribution health (10 pts)
        sev_dist = {}
        for i in items:
            s = (i.get("severity") or "UNKNOWN").upper()
            sev_dist[s] = sev_dist.get(s,0)+1
        low_pct = sev_dist.get("LOW",0)/n
        sev_health = 1.0 if low_pct < 0.4 else max(0, 1 - (low_pct - 0.4)*2)
        scores.append(("severity_health", sev_health * 10))

        # Attribution completeness (10 pts)
        attr_fields = ["source_name","source_url","publisher_trust_score"]
        attr_complete = sum(1 for i in items if any(i.get(f) for f in attr_fields))/n
        scores.append(("attribution", attr_complete * 10))

        total = sum(v for _,v in scores)
        breakdown = {k: round(v,2) for k,v in scores}
        return {"total_score": round(total,1), "breakdown": breakdown, "grade": "A" if total>=90 else "B" if total>=75 else "C" if total>=60 else "D" if total>=50 else "F"}

    def run_quality_check(self, feed_path):
        feed_path = Path(feed_path)
        if not feed_path.exists():
            return {"error": f"File not found: {feed_path}", "status": "FAIL"}
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
        is_dict = isinstance(raw, dict)
        if is_dict:
            items = raw.get("items", raw.get("advisories", raw.get("data", [])))
        else:
            items = raw

        dups = self.detect_duplicates(items)
        src_dups = self.detect_source_duplication(items)
        camp_dups = self.detect_campaign_duplication(items)
        quality = self.score_quality(items)

        return {
            "validator": "FeedQualityEngine",
            "feed_path": str(feed_path),
            "run_at": self.now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "item_count": len(items),
            "duplicates": {"id_dups": len(dups["id_duplicates"]), "cve_dups": len(dups["cve_duplicates"]), "title_dups": len(dups["title_duplicates"])},
            "source_duplication": {"multi_source_cve_count": src_dups["count"]},
            "campaign_duplication": {"count": camp_dups["count"]},
            "quality_score": quality,
            "status": "PASS" if quality["total_score"] >= 50 else "WARN"
        }


def run_quality_check_stage(feed_paths=None):
    if feed_paths is None:
        feed_paths = [REPO_ROOT/"api"/"feed.json", REPO_ROOT/"feed.json", REPO_ROOT/"data"/"feed.json"]
    combined = {"stage": "feed_quality", "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {}, "overall_status": "PASS"}
    for path in feed_paths:
        eng = FeedQualityEngine()
        r = eng.run_quality_check(path)
        combined["files"][str(path)] = r
        if r.get("status") == "FAIL":
            combined["overall_status"] = "FAIL"
    rp = REPO_ROOT/"reports"/"feed_quality_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")
    return combined

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_quality_check_stage()
    print(json.dumps(r, indent=2))
