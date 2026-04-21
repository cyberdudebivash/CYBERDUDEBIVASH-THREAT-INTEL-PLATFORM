#!/usr/bin/env python3
"""
Fix mojibake in all existing HTML report files.
One-shot remediation pass -- becomes a no-op once all reports are clean.
CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
import pathlib
import sys

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# All replacement values expressed as unicode escapes to avoid encoding
# issues in editors/shells that may not be UTF-8 aware.
FIXES = [
    # Long sequences first (3+ chars) to avoid shorter matches eating them
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
    ('\u00e2\u0161\u0094', '\u26a0'),    # warning triangle
    ('\u00e2\u0161\u201d', '\u2694'),    # crossed swords
    ('\u00e2\u00ac\u2021', '\u2b07'),    # downward arrow
    ('\u00e2\u201d\u20ac', '\u2500'),    # box drawing horizontal
    ('\u00e2\u201d\u201a', '\u2502'),    # box drawing vertical
    ('\u00e2\u201d\u0152', '\u250c'),    # box top-left
    ('\u00e2\u201d\u0090', '\u2510'),    # box top-right
    ('\u00e2\u201d\u201d', '\u2514'),    # box bottom-left
    ('\u00e2\u201d\u02dc', '\u2518'),    # box bottom-right
    ('\u00e2\u201d\u0153', '\u251c'),    # box left T
    ('\u00e2\u201d\u00a4', '\u2524'),    # box right T
    ('\u00e2\u201d\u00ac', '\u252c'),    # box top T
    ('\u00e2\u201d\u00b4', '\u2534'),    # box bottom T
    ('\u00e2\u201d\u00bc', '\u253c'),    # box cross
    ('\u00e2\u2013\u2018', '\u2591'),    # light shade
    ('\u00e2\u2013\u2019', '\u2592'),    # medium shade
    ('\u00e2\u2013\u201c', '\u2593'),    # dark shade
    # emoji mojibake (UTF-8 F0 9F XX XX misread as cp1252 -> 4 chars)
    ('\u00f0\u0178\u201d\u2019', '\U0001f512'),   # 🔒 lock
    ('\u00f0\u0178\u201d\u201c', '\U0001f513'),   # 🔓 unlock
    ('\u00f0\u0178\u201d\u2014', '\U0001f514'),   # 🔔 bell
    ('\u00f0\u0178\u02c6\u201d', '\U0001f508'),   # 🔈 speaker
    ('\u00f0\u0178\u00a7\u00a0', '\U0001f9e0'),   # 🧠 brain
    ('\u00f0\u0178\u201c\u0160', '\U0001f50a'),   # 🔊
    ('\u00f0\u0178\u02dc\u00a8', '\U0001f628'),   # 😨
    ('\u00f0\u0178\u201c\u0160', '\U0001f4ca'),   # 📊 chart
    ('\u00f0\u0178\u2019\u00bb', '\U0001f4bb'),   # 💻 laptop
    ('\u00f0\u0178\u201c\u0160', '\U0001f50d'),   # 🔍 search
    # 2-char sequences
    ('\u00e2\u20ac', '\u201d'),          # fallback close-quote
    ('\u00c3\u2014', '\u00d7'),          # multiplication sign
    ('\u00c2\u00b7', '\u00b7'),          # middle dot
    ('\u00c2\u00a3', '\u00a3'),          # pound sign
    ('\u00c2\u00b0', '\u00b0'),          # degree sign
    ('\u00c2\u00bd', '\u00bd'),          # vulgar fraction 1/2
    ('\u00c2\u00a9', '\u00a9'),          # copyright sign
    ('\u00c2\u00ae', '\u00ae'),          # registered sign
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
]


def fix_file(path):
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        print('  SKIP (read error): {} -- {}'.format(path, e))
        return False
    original = text
    for bad, good in FIXES:
        text = text.replace(bad, good)
    if text != original:
        path.write_text(text, encoding='utf-8')
        return True
    return False


def main():
    roots = [pathlib.Path('reports')]
    # Also check data/ for any cached HTML
    for extra in ['data', 'output', 'dist']:
        p = pathlib.Path(extra)
        if p.exists():
            roots.append(p)

    fixed = 0
    scanned = 0
    for root in roots:
        for f in root.rglob('*.html'):
            scanned += 1
            if fix_file(f):
                fixed += 1
                print('  FIXED: {}'.format(f))

    print('\n[fix_report_encoding] Scanned {} HTML files. Fixed {}.'.format(scanned, fixed))


if __name__ == '__main__':
    main()
