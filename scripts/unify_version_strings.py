#!/usr/bin/env python3
"""
Platform-wide version string unification.
Rewrites every hardcoded legacy version (v134.0 - v134.x, v134.0, v134.0, etc.)
to v134.0.0 / v134.0 / v134. This is the one-time rewrite executed as part of
the v134 hardening release. After it runs, no legacy version string should
remain anywhere in the source tree (excluding CHANGELOG_*.md historical
records and .git internals).

CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import List, Tuple

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_canonical() -> dict:
    return json.loads((REPO_ROOT / 'config' / 'version.json').read_text(encoding='utf-8'))


_CANON = _load_canonical()
NEW_FULL = _CANON['platform_full']          # "SENTINEL APEX v134.0.0"
NEW_SHORT = _CANON.get('platform_label') or 'v134.0'
NEW_NUM = _CANON['platform']                # "134.0.0"
NEW_MAJOR = NEW_NUM.split('.')[0]           # "134"
NEW_GATEWAY = _CANON['api_gateway']         # "SENTINEL-APEX/134.0.0"


# Pattern rewrites — ordered longest-first for safety.
# We deliberately avoid rewriting within CHANGELOG_*.md or patch files so the
# historical record is preserved.
REWRITES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'SENTINEL APEX v1[0-2][0-9]\.[0-9]+\.[0-9]+'), NEW_FULL),
    (re.compile(r'SENTINEL APEX V1[0-2][0-9]\.[0-9]+\.[0-9]+'), NEW_FULL),
    (re.compile(r'SENTINEL APEX v1[3][0-3]\.[0-9]+\.[0-9]+'),   NEW_FULL),
    (re.compile(r'SENTINEL APEX V1[3][0-3]\.[0-9]+\.[0-9]+'),   NEW_FULL),
    (re.compile(r'SENTINEL-APEX/1[0-3][0-9]\.[0-9]+\.[0-9]+'),  NEW_GATEWAY),
    (re.compile(r'NEXUS INTELLIGENCE v[0-9]+\.[0-9]+'),         f'NEXUS INTELLIGENCE {NEW_SHORT}'),
    (re.compile(r'GENESIS v[0-9]+\.[0-9]+'),                    f'GENESIS {NEW_SHORT}'),
    (re.compile(r'BUG HUNTER v[0-9]+\.[0-9]+'),                 f'BUG HUNTER {NEW_SHORT}'),
    (re.compile(r'APEX AI v\d+(\.\d+)?'),                       f'APEX AI v{NEW_MAJOR}'),
    (re.compile(r'TIP \+ SOAR COMMAND CENTER v[0-9]+\.[0-9]+'), f'TIP + SOAR COMMAND CENTER {NEW_SHORT}'),
    (re.compile(r'API ACCESS TIERS\s*[\-—]\s*v[0-9]+\.[0-9]+\.[0-9]+'),
     f'API ACCESS TIERS — {NEW_NUM}'),
    (re.compile(r'v134 CORTEX'),                                 f'v{NEW_MAJOR} CORTEX'),
    (re.compile(r'v134 QUANTUM'),                                f'v{NEW_MAJOR} QUANTUM'),
    (re.compile(r'v134 SOVEREIGN'),                              f'v{NEW_MAJOR} SOVEREIGN'),
    (re.compile(r'v134 GENESIS'),                                f'v{NEW_MAJOR} GENESIS'),
    (re.compile(r'v134 INTEGRITY'),                              f'v{NEW_MAJOR} INTEGRITY'),
    (re.compile(r'v63 TIP\+SOAR'),                              f'v{NEW_MAJOR} TIP+SOAR'),
    (re.compile(r'"GATEWAY_VERSION":\s*"1[0-9]+\.[0-9]+\.[0-9]+"'),
     f'"GATEWAY_VERSION":   "{NEW_NUM}"'),
    (re.compile(r'GATEWAY_VERSION:\s*"1[0-9]+\.[0-9]+\.[0-9]+"'),
     f'GATEWAY_VERSION:   "{NEW_NUM}"'),
    # generic vNNN.N or vNNN.N.N (only rewrite 1xx numbers — preserve
    # vocabulary like v1 / v2 which are API versions, and v15 / v20 which
    # appear in CVSS/schema discussions)
    (re.compile(r'\bv1[0-3][0-9]\.[0-9]+\.[0-9]+\b'),           NEW_SHORT + '.0'),
    (re.compile(r'\bv1[0-3][0-9]\.[0-9]+\b'),                   NEW_SHORT),
    (re.compile(r'\bv81\.7\b'),                                  NEW_SHORT),
    (re.compile(r'\bv63\.0\b'),                                  NEW_SHORT),
    (re.compile(r'\bv47\.0\b'),                                  NEW_SHORT),
    (re.compile(r'\bv43\.0\b'),                                  NEW_SHORT),
    (re.compile(r'\bv42\.0\b'),                                  NEW_SHORT),
    (re.compile(r'\bv41\.0\b'),                                  NEW_SHORT),
    (re.compile(r'\bv40\.0\b'),                                  NEW_SHORT),
    # In-source "vNNN:" annotation comments become "v134:"
    (re.compile(r'\bv1[0-2][0-9]:'),                             f'v{NEW_MAJOR}:'),
    (re.compile(r'\bv13[0-3]:'),                                 f'v{NEW_MAJOR}:'),
    # bare legacy labels in HTML / comments (e.g. 'v134' in isolation)
    (re.compile(r'\bv1[0-2][0-9]\b(?!\d)'),                      f'v{NEW_MAJOR}'),
    (re.compile(r'\bv13[0-3]\b(?!\d)'),                          f'v{NEW_MAJOR}'),
]

TARGET_DIRS = ['scripts', 'core', 'agent', 'workers', 'dashboard',
               'landing', 'api', 'app', 'ai', 'config', '.github',
               'sentinel-apex-api', 'integrations', 'syndicate', 'tools',
               'sdk', 'deploy', 'tests']
TARGET_SUFFIXES = {'.py', '.js', '.ts', '.html', '.json', '.yml', '.yaml',
                   '.toml', '.css', '.tsx', '.jsx'}

# Files we leave alone — they are historical changelogs / patches / legacy snapshots
SKIP_FILE_PATTERNS = [
    re.compile(r'CHANGELOG[_\-]?v\d+'),
    re.compile(r'v\d+_'),   # legacy versioned module folders, leave their README alone
    re.compile(r'\.patch$'),
    re.compile(r'PLATFORM_BASELINE_'),
    re.compile(r'node_modules'),
    re.compile(r'__pycache__'),
    re.compile(r'\.git/'),
    re.compile(r'\.wrangler/'),
]


def skip(path: pathlib.Path) -> bool:
    s = str(path)
    for p in SKIP_FILE_PATTERNS:
        if p.search(s):
            return True
    return False


def rewrite_text(text: str) -> tuple[str, int]:
    n = 0
    for pat, repl in REWRITES:
        text, cnt = pat.subn(repl, text)
        n += cnt
    return text, n


def main() -> int:
    changed = 0
    total_subs = 0
    scanned = 0
    for root_name in TARGET_DIRS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        for f in root.rglob('*'):
            if f.is_dir() or skip(f):
                continue
            if f.suffix not in TARGET_SUFFIXES:
                continue
            scanned += 1
            try:
                text = f.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            new_text, n = rewrite_text(text)
            if n > 0 and new_text != text:
                f.write_text(new_text, encoding='utf-8')
                changed += 1
                total_subs += n
                print(f'  v134: {n:3d} sub(s)  {f.relative_to(REPO_ROOT)}')

    # Also handle top-level version-ish files
    for top in ('index.html', 'README.md', 'CHANGELOG.md', 'VERSION'):
        p = REPO_ROOT / top
        if p.exists() and p.is_file():
            scanned += 1
            try:
                text = p.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            # For CHANGELOG.md we only rewrite the header line, not historical entries
            if top == 'CHANGELOG.md':
                continue
            new_text, n = rewrite_text(text)
            if n > 0 and new_text != text:
                p.write_text(new_text, encoding='utf-8')
                changed += 1
                total_subs += n
                print(f'  v134: {n:3d} sub(s)  {p.name}')

    print(f'\n[unify_version_strings] scanned {scanned} files, '
          f'updated {changed} files, {total_subs} substitutions.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
