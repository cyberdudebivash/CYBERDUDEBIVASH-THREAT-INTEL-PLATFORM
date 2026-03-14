#!/usr/bin/env python3
"""
SENTINEL APEX — v43 Genesis Engine v2 Syntax Fix
Fixes unterminated f-string on line 431 of genesis_engine_v2.py

The issue: backslash escapes inside f-string expressions are not 
universally supported across Python versions. Fix extracts the 
expression to a local variable.

Run: python patches/fix_v43_genesis_syntax.py
"""

import os
import sys

TARGET = os.path.join(os.path.dirname(__file__), "..", "agent", "v43_genesis", "genesis_engine_v2.py")

OLD_LINE = '''                "query": f"SecurityAlert | where Description contains '{(cves[0] if cves else title[:20]).replace(\\\"'\\\",\\\"\\\")}' | project TimeGenerated, AlertName, Severity",'''

NEW_LINES = '''                _kql_search = (cves[0] if cves else title[:20]).replace("'", "")
                "query": f"SecurityAlert | where Description contains '{_kql_search}' | project TimeGenerated, AlertName, Severity",'''

def main():
    if not os.path.exists(TARGET):
        print(f"Target file not found: {TARGET}")
        sys.exit(1)

    with open(TARGET, "r") as f:
        content = f.read()

    if OLD_LINE not in content:
        # Try alternate check
        if "_kql_search" in content:
            print("Already patched.")
            sys.exit(0)
        print("Could not find target line — file may have changed.")
        print("Manual fix: line 431 of agent/v43_genesis/genesis_engine_v2.py")
        print("Extract the .replace() call to a local variable before the f-string.")
        sys.exit(1)

    content = content.replace(OLD_LINE, NEW_LINES)

    with open(TARGET, "w") as f:
        f.write(content)

    # Verify
    import py_compile
    try:
        py_compile.compile(TARGET, doraise=True)
        print(f"✅ Fixed: {TARGET}")
    except py_compile.PyCompileError as e:
        print(f"❌ Fix did not resolve: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
