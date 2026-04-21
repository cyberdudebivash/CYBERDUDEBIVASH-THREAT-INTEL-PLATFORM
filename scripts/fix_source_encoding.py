#!/usr/bin/env python3
"""
Fix mojibake in platform source files (Python/JS/HTML/YAML).
Run once to repair source code that was previously double-encoded.
Safe to re-run: becomes a no-op after the first successful pass.

CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
from __future__ import annotations

import pathlib
import sys

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Order matters: longer sequences first so that shorter ambiguous matches
# (like the trailing 2-byte pattern for a close-quote) do not eat the
# bytes of a 3-byte em-dash beforehand.
FIXES = [
    ('\u00e2\u20ac\u201c', '\u2014'),    # em dash
    ('\u00e2\u20ac\u201d', '\u2013'),    # en dash
    ('\u00e2\u20ac\u2122', '\u2019'),    # right single quote
    ('\u00e2\u20ac\u00a6', '\u2026'),    # ellipsis
    ('\u00e2\u20ac\u0153', '\u201c'),    # left double quote
    ('\u00e2\u20ac\u02dc', '\u2018'),    # left single quote
    ('\u00e2\u20ac\u009d', '\u201d'),    # right double quote
    ('\u00e2\u201a\u00ac', '\u20ac'),    # euro sign
    ('\u00e2\u201a\u00b9', '\u20b9'),    # rupee sign
    ('\u00e2\u2020\u2019', '\u2192'),    # right arrow
    ('\u00e2\u2020\u2018', '\u2191'),    # up arrow
    ('\u00e2\u2020\u201c', '\u2190'),    # left arrow
    ('\u00e2\u2020\u201d', '\u2193'),    # down arrow
    ('\u00e2\u0153\u201d', '\u2714'),    # heavy check
    ('\u00e2\u0153\u2014', '\u2716'),    # heavy X
    ('\u00e2\u0161\u0094', '\u26a0'),    # warning
    ('\u00e2\u0161\u201d', '\u2694'),    # crossed swords
    ('\u00e2\u00ac\u2021', '\u2b07'),    # downward arrow
    ('\u00e2\u20ac', '\u201d'),           # fallback for close-quote (short match)
    ('\u00c3\u2014', '\u00d7'),          # multiplication sign
    ('\u00c2\u00b7', '\u00b7'),          # middle dot
    ('\u00c2\u00a9', '\u00a9'),          # copyright sign
    ('\u00c2\u00ae', '\u00ae'),          # registered sign
    ('\u00c2\u00a3', '\u00a3'),          # pound sign
    ('\u00c2\u00b0', '\u00b0'),          # degree sign
    ('\u00c2\u00bd', '\u00bd'),          # 1/2
    ('\u00c2\u00b1', '\u00b1'),          # plus-minus
    ('\u00c3\u00a9', '\u00e9'),          # e acute
    ('\u00c3\u00a8', '\u00e8'),          # e grave
    ('\u00c3\u00a0', '\u00e0'),          # a grave
    ('\u00c3\u00a2', '\u00e2'),          # a circumflex
    ('\u00c3\u00ae', '\u00ee'),          # i circumflex
    ('\u00c3\u00b4', '\u00f4'),          # o circumflex
    ('\u00c3\u00bb', '\u00fb'),          # u circumflex
    ('\u00c3\u00a7', '\u00e7'),          # c cedilla
    ('\u00c3\u00bc', '\u00fc'),          # u umlaut
    ('\u00c3\u00b6', '\u00f6'),          # o umlaut
    ('\u00c3\u00a4', '\u00e4'),          # a umlaut
    ('\u00c3\u00ab', '\u00eb'),          # e umlaut
    ('\u00c3\u00af', '\u00ef'),          # i umlaut
    ('\u00c3\u00b1', '\u00f1'),          # n tilde
    # lock emoji: UTF-8 F0 9F 94 92 misread as Latin-1 becomes 4 chars
    ('\u00f0\u0178"\u2019', '\U0001f512'),
    ('\u00f0\u0178"\u2018', '\U0001f513'),
    # box-drawing characters (commonly used as section dividers)
    ('\u00e2\u201d\u20ac', '\u2500'),    # horizontal line
    ('\u00e2\u201d\u201a', '\u2502'),    # vertical line
    ('\u00e2\u201d\u0152', '\u250c'),    # top-left corner
    ('\u00e2\u201d\u0090', '\u2510'),    # top-right corner
    ('\u00e2\u201d\u201d', '\u2514'),    # bottom-left corner
    ('\u00e2\u201d\u02dc', '\u2518'),    # bottom-right corner
    ('\u00e2\u201d\u0153', '\u251c'),    # left T
    ('\u00e2\u201d\u00a4', '\u2524'),    # right T
    ('\u00e2\u201d\u00ac', '\u252c'),    # top T
    ('\u00e2\u201d\u00b4', '\u2534'),    # bottom T
    ('\u00e2\u201d\u00bc', '\u253c'),    # cross
    # block elements
    ('\u00e2\u2013\u2018', '\u2591'),    # light shade
    ('\u00e2\u2013\u2019', '\u2592'),    # medium shade
    ('\u00e2\u2013\u201c', '\u2593'),    # dark shade
    ('\u00e2\u2013\u2012', '\u2588'),    # full block
]

TARGET_DIRS = ['scripts', 'core', 'agent', 'workers', 'dashboard',
               'landing', 'api', 'app', 'ai', 'config']
TARGET_SUFFIXES = {'.py', '.js', '.html', '.json', '.yml', '.yaml', '.md', '.css'}

# Never touch generated output / build dirs
SKIP_PARTS = {'__pycache__', 'node_modules', '.git', 'dist', 'build',
              '.next', 'venv', 'env'}


def fix_file(path: pathlib.Path) -> int:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception as exc:
        print('  SKIP read error: {} -- {}'.format(path, exc))
        return 0
    original = text
    fixes_applied = 0
    for bad, good in FIXES:
        if bad in text:
            new_text = text.replace(bad, good)
            fixes_applied += (len(text) - len(new_text)) // max(
                (len(bad) - len(good)), 1) if len(bad) != len(good) else text.count(bad)
            text = new_text
    if text != original:
        path.write_text(text, encoding='utf-8')
        return 1
    return 0


def should_skip(path: pathlib.Path) -> bool:
    for part in path.parts:
        if part in SKIP_PARTS:
            return True
    return False


def main() -> int:
    repaired = 0
    scanned = 0
    for root_name in TARGET_DIRS:
        root = pathlib.Path(root_name)
        if not root.exists():
            continue
        for f in root.rglob('*'):
            if f.is_dir() or should_skip(f):
                continue
            if f.suffix not in TARGET_SUFFIXES:
                continue
            scanned += 1
            if fix_file(f):
                repaired += 1
                print('  FIXED source: {}'.format(f))

    # Also handle top-level individual files of interest
    for stem in ('VERSION', 'README.md'):
        p = pathlib.Path(stem)
        if p.exists() and p.is_file():
            scanned += 1
            if fix_file(p):
                repaired += 1
                print('  FIXED source: {}'.format(p))

    print(
        '\n[fix_source_encoding] scanned {} files, repaired {}.'.format(
            scanned, repaired))
    return 0


if __name__ == '__main__':
    sys.exit(main())
