#!/usr/bin/env python3
"""
scripts/timestamp_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Timestamp Integrity Validator
"""
from __future__ import annotations
import json, logging, re
from datetime import datetime, timezone, timedelta
from pathlib import Path

log = logging.getLogger("sentinel.timestamp_validator")
REPO_ROOT = Path(__file__).resolve().parent.parent

class TimestampValidator:
    ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")

    def __init__(self):
        self.now_utc = datetime.now(timezone.utc)
        self.violations = []
        self.fixed = 0
        self.rejected = 0

    def _parse_ts(self, ts_str):
        if not ts_str: return None
        try:
            normalized = str(ts_str).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    def _to_iso(self, dt):
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def validate_timestamp_chain(self, items):
        repaired = []
        for item in items:
            item = dict(item)
            for field in ("published_at", "processed_at", "timestamp", "published"):
                raw = item.get(field)
                if not raw: continue
                dt = self._parse_ts(str(raw))
                if dt is None:
                    self.violations.append({"id": item.get("id","?"), "field": field, "issue": "invalid_iso_format", "original": raw})
                    item[field] = self._to_iso(self.now_utc - timedelta(hours=1))
                    item["_ts_repaired"] = True
                    self.fixed += 1
                elif dt > self.now_utc:
                    clamped = self._to_iso(self.now_utc - timedelta(hours=1))
                    self.violations.append({"id": item.get("id","?"), "field": field, "issue": "future_timestamp", "original": raw, "clamped_to": clamped})
                    item[field] = clamped
                    item["_ts_repaired"] = True
                    self.fixed += 1
                else:
                    item[field] = self._to_iso(dt)
            repaired.append(item)
        return repaired

    def validate_future_dates(self, items):
        return self.validate_timestamp_chain(items)

    def validate_publication_order(self, items):
        fixed_items = []
        for item in items:
            item = dict(item)
            pub_raw = item.get("published_at") or item.get("published")
            proc_raw = item.get("processed_at")
            if pub_raw and proc_raw:
                pub_dt = self._parse_ts(str(pub_raw))
                proc_dt = self._parse_ts(str(proc_raw))
                if pub_dt and proc_dt and proc_dt < pub_dt:
                    corrected = pub_dt + timedelta(minutes=1)
                    self.violations.append({"id": item.get("id","?"), "field": "processed_at", "issue": "processed_before_published", "published_at": str(pub_raw), "processed_at": str(proc_raw), "corrected_to": self._to_iso(corrected)})
                    item["processed_at"] = self._to_iso(corrected)
                    self.fixed += 1
            fixed_items.append(item)
        return fixed_items

    def reject_invalid_records(self, items):
        valid, rejected = [], []
        for item in items:
            pub = item.get("published_at") or item.get("published") or item.get("timestamp")
            if not pub or self._parse_ts(str(pub)) is None:
                self.rejected += 1
                rejected.append({**item, "_reject_reason": "no_valid_published_at"})
            else:
                valid.append(item)
        return valid, rejected

    def run_validation(self, feed_path):
        feed_path = Path(feed_path)
        if not feed_path.exists():
            return {"error": f"File not found: {feed_path}", "status": "FAIL"}
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
        is_dict = isinstance(raw, dict)
        if is_dict:
            items = raw.get("items", raw.get("advisories", raw.get("data", [])))
        else:
            items = raw
        before_count = len(items)
        before_future = sum(1 for i in items for f in ("published_at","processed_at","timestamp","published") if i.get(f) and self._parse_ts(str(i[f])) and self._parse_ts(str(i[f])) > self.now_utc)
        items = self.validate_timestamp_chain(items)
        items = self.validate_publication_order(items)
        valid_items, rejected_items = self.reject_invalid_records(items)
        after_future = sum(1 for i in valid_items for f in ("published_at","processed_at","timestamp","published") if i.get(f) and self._parse_ts(str(i[f])) and self._parse_ts(str(i[f])) > self.now_utc)
        if is_dict:
            for key in ("items","advisories","data"):
                if key in raw:
                    raw[key] = valid_items; break
            else:
                raw["items"] = valid_items
            output = raw
        else:
            output = valid_items
        feed_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"validator": "TimestampValidator", "feed_path": str(feed_path), "run_at": self._to_iso(self.now_utc), "before": {"total_items": before_count, "future_timestamps": before_future}, "after": {"total_items": len(valid_items), "rejected_items": len(rejected_items), "future_timestamps": after_future}, "fixes_applied": self.fixed, "violations": self.violations, "rejected_records": [r.get("id","?") for r in rejected_items], "status": "PASS" if after_future == 0 else "WARN"}


def run_timestamp_validation_stage(feed_paths=None):
    if feed_paths is None:
        feed_paths = [REPO_ROOT/"api"/"feed.json", REPO_ROOT/"feed.json"]
    combined = {"stage": "timestamp_integrity", "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {}, "total_fixes": 0, "total_violations": 0, "overall_status": "PASS"}
    for path in feed_paths:
        v = TimestampValidator()
        r = v.run_validation(path)
        combined["files"][str(path)] = r
        combined["total_fixes"] += r.get("fixes_applied", 0)
        combined["total_violations"] += len(r.get("violations", []))
        if r.get("status") not in ("PASS","WARN"):
            combined["overall_status"] = "FAIL"
    rp = REPO_ROOT/"reports"/"timestamp_integrity_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")
    return combined

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    r = run_timestamp_validation_stage([path] if path else None)
    print(json.dumps(r, indent=2))
