#!/usr/bin/env python3
"""Print guardian report summary — called by autonomous-guardian.yml summary step."""
import json, sys
from pathlib import Path

report_path = Path("data/health/guardian_report.json")
if not report_path.exists():
    print("No guardian report found.")
    sys.exit(0)

r = json.loads(report_path.read_text())
print(f"Status:          {r['overall_status']}")
print(f"Runs scanned:    {r['runs_scanned']}")
print(f"Jobs scanned:    {r['jobs_scanned']}")
print(f"Failures found:  {len(r['failures_detected'])}")
fixes = sum(1 for f in r.get("fixes_applied", []) if f.get("applied"))
print(f"Fixes applied:   {fixes}")
pushed = r.get("push_result") or {}
if pushed:
    print(f"Fix pushed:      {pushed.get('pushed', False)}")
print(f"Duration:        {r['duration_seconds']}s")
if r["failures_detected"]:
    print()
    print("FAILURES DETECTED:")
    for f in r["failures_detected"]:
        wf = f.get("workflow", "?")
        run_no = f.get("run_number", "?")
        print(f"  [{f['severity']}] {f['name']} in {wf} #{run_no}")
else:
    print("No failures — platform healthy.")
