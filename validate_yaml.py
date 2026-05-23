import yaml, sys
from pathlib import Path
wf = Path(".github/workflows/sentinel-blogger.yml")
try:
    yaml.safe_load(wf.read_text(encoding="utf-8"))
    print("YAML VALID — no syntax errors")
    # Verify our stages are present
    content = wf.read_text(encoding="utf-8")
    checks = [
        ("Stage 5.9.1", "Stage 5.9.1 present"),
        ("Stage 5.9.2", "Stage 5.9.2 present"),
        ("Stage 5.9.3", "Stage 5.9.3 present"),
        ("Stage 5.9.4", "Stage 5.9.4 present"),
        ("python3 -c \"", "No inline python3 -c present"),
    ]
    all_ok = True
    for pattern, label in checks:
        if pattern == "python3 -c \"":
            found = pattern in content
            status = "FAIL — still has inline python3 -c" if found else "OK — no inline python3 -c"
            if found:
                all_ok = False
        else:
            found = pattern in content
            status = "OK" if found else "MISSING"
            if not found:
                all_ok = False
        print(f"  [{status}] {label}")
    print(f"\nOverall: {'ALL OK' if all_ok else 'ISSUES FOUND'}")
    sys.exit(0)
except yaml.YAMLError as e:
    print(f"YAML ERROR: {e}")
    sys.exit(1)
