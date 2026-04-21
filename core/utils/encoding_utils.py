#!/usr/bin/env python3
"""
Encoding utility — repairs mojibake and double-encoding artefacts.
Applied at every ingestion boundary of free-text content coming from
external RSS / web feeds before it is written into HTML reports.

CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
from __future__ import annotations

import sys
from typing import Any

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass


# Comprehensive mojibake correction table (ordered: longest sequences first
# so shorter ambiguous patterns don't consume the bytes of a multi-codepoint
# sequence above them). All replacements are expressed as unicode escapes so
# this module is pure-ASCII-safe in any editor/shell that is not UTF-8.
_MOJIBAKE_MAP = [
    # 4-char sequences (emoji: UTF-8 F0 9F XX XX misread as cp1252)
    ('\u00f0\u0178\u201d\u2019', '\U0001f512'),   # 🔒 lock
    ('\u00f0\u0178\u201d\u201c', '\U0001f513'),   # 🔓 unlock
    ('\u00f0\u0178\u201d\u2014', '\U0001f514'),   # 🔔 bell
    ('\u00f0\u0178\u02c6\u201d', '\U0001f508'),   # 🔈
    ('\u00f0\u0178\u00a7\u00a0', '\U0001f9e0'),   # 🧠 brain
    # 3-char sequences (CJK, arrows, symbols — UTF-8 E2 XX XX misread as cp1252)
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
    ('\u00e2\u201d\u20ac', '\u2500'),    # box horizontal
    ('\u00e2\u201d\u201a', '\u2502'),    # box vertical
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
    # 2-char sequences (must come AFTER the 3-char entries above)
    ('\u00e2\u20ac', '\u201d'),          # fallback close-quote
    ('\u00c3\u2014', '\u00d7'),          # multiplication sign
    ('\u00c2\u00b7', '\u00b7'),          # middle dot
    ('\u00c2\u00a9', '\u00a9'),          # copyright
    ('\u00c2\u00ae', '\u00ae'),          # registered
    ('\u00c2\u00a3', '\u00a3'),          # pound
    ('\u00c2\u00b0', '\u00b0'),          # degree
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
]


def fix_mojibake(text: Any) -> Any:
    """Apply the known mojibake correction table.
    Fast, deterministic, preserves all legitimate Unicode.
    Non-strings are returned unchanged.
    """
    if not isinstance(text, str):
        return text
    if not text:
        return text
    for bad, good in _MOJIBAKE_MAP:
        if bad in text:
            text = text.replace(bad, good)
    return text


def fix_encoding(text: Any) -> Any:
    """
    Repair mojibake and double-encoding artefacts produced when UTF-8 bytes
    are misread as Latin-1 / cp1252 and then re-encoded as UTF-8.
    Uses ftfy when installed (best-in-class), falls back to the built-in
    correction table and a conservative round-trip heuristic otherwise.
    """
    if not isinstance(text, str):
        return text
    if not text:
        return text
    # First pass: ftfy if available (handles edge cases the table misses)
    try:
        import ftfy  # type: ignore
        text = ftfy.fix_text(text, normalization='NFC')
    except ImportError:
        # Apply our table-based fix
        text = fix_mojibake(text)
        # Conservative fallback: attempt single-pass round trip
        try:
            candidate = text.encode('latin-1', errors='ignore').decode(
                'utf-8', errors='ignore')
            # Only accept the fix if it didn't dramatically shorten the text
            if candidate and len(candidate) >= len(text) * 0.8 and candidate != text:
                text = candidate
        except (UnicodeDecodeError, UnicodeEncodeError, AttributeError):
            pass
    return text


def sanitize_field(text: Any) -> Any:
    """Full pipeline: mojibake table first, then ftfy normalization.
    Safe default for any free-text field ingested from external sources.
    """
    text = fix_mojibake(text)
    text = fix_encoding(text)
    return text


def sanitize_dict(
    obj: dict,
    fields: tuple = ("title", "description", "summary", "body",
                     "actor_name", "campaign", "source_name"),
) -> dict:
    """Apply sanitize_field to the listed string fields of a dict copy."""
    if not isinstance(obj, dict):
        return obj
    out = dict(obj)
    for k in fields:
        if k in out and isinstance(out[k], str):
            out[k] = sanitize_field(out[k])
    return out


__all__ = [
    "fix_mojibake",
    "fix_encoding",
    "sanitize_field",
    "sanitize_dict",
]
