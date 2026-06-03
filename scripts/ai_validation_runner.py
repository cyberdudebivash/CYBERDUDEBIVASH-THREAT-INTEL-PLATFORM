#!/usr/bin/env python3
"""
scripts/ai_validation_runner.py
CYBERDUDEBIVASH(R) SENTINEL APEX — AI Engine Validation Runner
Runs each AI engine against real feed data, verifies non-empty outputs.
"""
from __future__ import annotations
import json, logging, os, sys, importlib.util, traceback
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.ai_validation")
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

def _load_feed(feed_path):
    raw = json.loads(Path(feed_path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        return raw.get("items", raw.get("advisories", raw.get("data", [])))
    return raw if isinstance(raw, list) else []

def _audit_module_for_mocks(source_path):
    """Check Python source for placeholder patterns."""
    issues = []
    try:
        text = Path(source_path).read_text(encoding="utf-8", errors="replace")
        patterns = [
            ("hardcoded_pass", "return []", "returns empty list"),
            ("todo_placeholder", "# TODO", "TODO comment found"),
            ("mock_data", "mock_", "mock_ variable detected"),
            ("raise_notimplemented", "raise NotImplementedError", "NotImplementedError"),
            ("hardcoded_empty_dict", "return {}", "returns empty dict"),
        ]
        for key, pat, desc in patterns:
            if pat in text:
                issues.append({"type": key, "description": desc, "pattern": pat})
    except Exception as e:
        issues.append({"type": "read_error", "description": str(e)})
    return issues

def _try_import_and_run(engine_name, feed_items):
    """Attempt to import engine and call its main prediction/analysis function."""
    engine_path = SCRIPTS_DIR / f"{engine_name}.py"
    result = {"engine": engine_name, "file_exists": engine_path.exists(), "import_ok": False,
              "output_sample": None, "has_real_data": False, "issues": [], "status": "UNKNOWN"}

    if not engine_path.exists():
        result["status"] = "FILE_NOT_FOUND"
        result["issues"].append({"type": "missing_file", "description": f"{engine_name}.py not found"})
        return result

    result["issues"] = _audit_module_for_mocks(engine_path)

    # Try import
    try:
        spec = importlib.util.spec_from_file_location(engine_name, engine_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        result["import_ok"] = True
    except Exception as e:
        result["status"] = "IMPORT_FAIL"
        result["issues"].append({"type": "import_error", "description": str(e)[:200]})
        return result

    # Try to find and call a scoring/prediction function
    called = False
    for fn_name in ("predict", "run", "analyze", "score", "detect", "compute", "run_engine",
                    "run_anomaly_radar", "run_predictions", "explain_confidence"):
        fn = getattr(mod, fn_name, None)
        if callable(fn):
            try:
                out = fn(feed_items[:5]) if fn_name not in ("run","run_engine","run_predictions","run_anomaly_radar") else fn()
                result["output_sample"] = str(out)[:300] if out is not None else None
                result["has_real_data"] = bool(out) and out != [] and out != {}
                called = True
                break
            except Exception as e:
                result["issues"].append({"type": "execution_error", "fn": fn_name, "description": str(e)[:200]})

    if not called:
        # Check if there are class-based engines
        for cls_name in dir(mod):
            cls = getattr(mod, cls_name, None)
            if isinstance(cls, type) and not cls_name.startswith("_"):
                try:
                    obj = cls()
                    for method in ("predict","analyze","score","run","detect"):
                        fn = getattr(obj, method, None)
                        if callable(fn):
                            out = fn(feed_items[:5])
                            result["output_sample"] = str(out)[:300] if out is not None else None
                            result["has_real_data"] = bool(out) and out != [] and out != {}
                            called = True
                            break
                    if called: break
                except Exception as e:
                    result["issues"].append({"type": "class_error", "cls": cls_name, "description": str(e)[:200]})

    result["function_called"] = called
    placeholder_issues = [i for i in result["issues"] if i["type"] in ("hardcoded_pass","hardcoded_empty_dict","raise_notimplemented")]
    if not result["import_ok"]:
        result["status"] = "IMPORT_FAIL"
    elif placeholder_issues:
        result["status"] = "PLACEHOLDER_DETECTED"
    elif result["has_real_data"]:
        result["status"] = "OK"
    else:
        result["status"] = "WARN_NO_OUTPUT"
    return result

def run_ai_validation():
    feed_path = REPO_ROOT / "api" / "feed.json"
    feed_items = _load_feed(feed_path)
    engines_to_audit = [
        "ai_predictions_engine",
        "anomaly_radar_engine",
        "explainable_confidence_engine",
        "ai_explainability_engine",
        "apex_confidence_engine",
    ]
    now = datetime.now(timezone.utc)
    report = {
        "validator": "AIValidationRunner",
        "run_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feed_items_used": len(feed_items),
        "engines": {},
        "summary": {"ok": 0, "warn": 0, "fail": 0, "total": len(engines_to_audit)},
        "overall_status": "PASS"
    }
    for engine in engines_to_audit:
        r = _try_import_and_run(engine, feed_items)
        report["engines"][engine] = r
        if r["status"] == "OK":
            report["summary"]["ok"] += 1
        elif r["status"] in ("IMPORT_FAIL","FILE_NOT_FOUND","PLACEHOLDER_DETECTED"):
            report["summary"]["fail"] += 1
            report["overall_status"] = "WARN"
        else:
            report["summary"]["warn"] += 1
    rp = REPO_ROOT / "reports" / "ai_validation_report.json"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    r = run_ai_validation()
    print(json.dumps({k:v for k,v in r.items() if k!="engines"}, indent=2))
    for eng, data in r["engines"].items():
        print(f"  {eng}: {data['status']} | import_ok={data['import_ok']} | has_real_data={data['has_real_data']}")
