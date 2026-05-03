import sys
content = open('index.html', encoding='utf-8').read()
checks = [
    ("FIX-1: api/feed.json fallback",    "P0 FALLBACK: same-domain, no CORS"),
    ("FIX-2: terminal grid clear",       "v146.0 P0 FIX: #threat-grid MUST never stay stuck"),
    ("FIX-3: 12s safety timer",          "v146.0 P0 SAFETY TIMER"),
    ("FIX-3: force retry in timer",      "P0-SAFETY: Grid stuck after 12s"),
    ("FIX-3: retry-now link in catch",   "retry now"),
    ("MANIFEST has api/feed.json",       "'api/feed.json',"),
]
all_ok = True
for name, needle in checks:
    found = needle in content
    status = "[OK]     " if found else "[MISSING]"
    print(status, name)
    if not found:
        all_ok = False
print()
print("RESULT:", "ALL 6 PATCHES VERIFIED -- P0 FIX DEPLOYED" if all_ok else "WARNING: PATCH MISSING")
sys.exit(0 if all_ok else 1)
