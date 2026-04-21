import pathlib, re

REPO = r"C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
WF = pathlib.Path(REPO) / ".github" / "workflows" / "sentinel-blogger.yml"
BANNED = [b"python3 - << 'PYEOF'",b"python3 - <<'PYEOF'",b"python3 - << PYEOF",
          b"<< PYEOF",b"<< 'PYEOF'",b"<< EOF",b"<< 'EOF'",b"<< ENDJSON",
          b"<< 'ENDJSON'",b"PYEOF",b"ENDJSON"]

content = WF.read_text(encoding="utf-8", errors="replace")
active = [l for l in content.splitlines() if not l.lstrip().startswith("#")]
data = "\n".join(active).encode("utf-8")
found = [p.decode("ascii","replace") for p in BANNED if p in data]
if found:
    print(f"FAIL check_workflow_clean: {found}")
    # Show context
    for pat in found:
        for i,line in enumerate(active):
            if pat in line:
                print(f"  line {i}: {line[:120]}")
else:
    print("PASS check_workflow_clean: no banned patterns")

# check_python_syntax simulation - find any py file with SyntaxWarnings that might be errors on 3.12
import py_compile, os, io, sys, contextlib
SKIP = {".git","__pycache__","node_modules",".venv"}
errors = []
for chk in ["scripts","agent"]:
    chk_dir = pathlib.Path(REPO) / chk
    if not chk_dir.is_dir(): continue
    for dirpath,dirnames,filenames in os.walk(chk_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            if not fn.endswith(".py"): continue
            fp = pathlib.Path(dirpath)/fn
            try:
                py_compile.compile(str(fp), doraise=True)
            except py_compile.PyCompileError as e:
                errors.append(f"{fp.relative_to(REPO)}: {str(e)[:100]}")
if errors:
    print(f"\nFAIL check_python_syntax: {len(errors)} errors:")
    for e in errors[:10]: print(f"  {e}")
else:
    print(f"\nPASS check_python_syntax: all .py files compile clean")
