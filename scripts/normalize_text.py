#!/usr/bin/env python3
"""
scripts/normalize_text.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Universal Text Encoding Sanitizer
=======================================================================
Shared utility imported by all pipeline scripts that produce or consume
text fields (titles, descriptions, summaries, feed.json, manifests).

Usage:
    from scripts.normalize_text import normalize_text, normalize_item, normalize_feed

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# Mojibake replacement table (double-encoded UTF-8 => correct Unicode)
# Each entry: (bad_string, correct_replacement)
# Ordered longest-match first to prevent partial substitution.
# ---------------------------------------------------------------------------
_MOJIBAKE_TABLE: list[tuple[str, str]] = [
    # Double-encoded multibyte sequences (latin-1 re-read as UTF-8)
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u0093", "\u2013"),  # en-dash
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u0094", "\u2014"),  # em-dash
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u0099", "\u2019"),  # right single quote
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u009c", "\u201c"),  # left double quote
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u009d", "\u201d"),  # right double quote
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u00a2", "\u2022"),  # bullet
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u0098", "\u2018"),  # left single quote
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u00a6", "\u2026"),  # ellipsis
    ("\u00c3\u00a2\u00c2\u20ac\u00c2\u008b", ""),         # zero-width space
    # Common single-level mojibake (latin-1 read as UTF-8)
    ("\u00c3\u00a2\u00e2\u20ac\u201c",        "\u2013"),  # en-dash alt
    ("\u00c3\u00a2\u00e2\u20ac\u201d",        "\u2014"),  # em-dash alt
    ("\u00c3\u00a2\u00e2\u20ac\u2122",        "\u2019"),  # right single quote alt
    ("\u00c3\u00a2\u00e2\u20ac\u02dc",        "\u2018"),  # left single quote alt
    ("\u00c3\u00a2\u00e2\u20ac\u0153",        "\u201c"),  # left double quote alt
    ("\u00c3\u00a2\u00e2\u20ac\ufffd",        "\u201d"),  # right double quote alt
    # \u00c3\u00d7 pattern (double-encoded multiplication sign U+00D7)
    ("\u00c3\u00c3\u00d7",                   "\u00d7"),  # \u00c3\u00d7 -> x
    ("A\u00c3\u00a2\u00c2\u0097",            "\u00d7"),  # variant
    # Simple latin-1/cp1252 re-encoded forms
    ("\u00e2\u20ac\u201c",                   "\u2013"),  # en-dash
    ("\u00e2\u20ac\u201d",                   "\u2014"),  # em-dash
    ("\u00e2\u20ac\u2122",                   "\u2019"),  # right single quote
    ("\u00e2\u20ac\u02dc",                   "\u2018"),  # left single quote
    ("\u00e2\u20ac\u0153",                   "\u201c"),  # left double quote
    ("\u00e2\u20ac\ufffd",                   "\u201d"),  # right double quote
    ("\u00e2\u20ac\u00a2",                   "\u2022"),  # bullet
    ("\u00e2\u20ac\u00a6",                   "\u2026"),  # ellipsis
    ("\u00e2\u20ac\u008b",                   ""),         # zero-width space
    # Replacement character
    ("\ufffd",                               ""),
]

# Text-level string patterns that appear in decoded strings
_TEXT_PATTERNS: list[tuple[str, str]] = [
    # ---- Latin-1 / W1252 re-encoded mojibake -> correct Unicode ----
    # Keys are the corrupted string sequences; values are correct codepoints.
    # All non-ASCII chars represented as \uXXXX to prevent encoding bugs.
    ("\u00c3\u2014",     "\u00d7"),   # multiplication sign (common dashboard mojibake)
    ("\u00e2\u20ac\u201d",  "\u2014"),  # em-dash   (W1252: E2 80 94)
    ("\u00e2\u20ac\u201c",  "\u2013"),  # en-dash   (W1252: E2 80 93)
    ("\u00e2\u20ac\u00a6",  "\u2026"),  # ellipsis  (W1252: E2 80 A6)
    ("\u00e2\u20ac\u02dc",  "\u2018"),  # left single quote  (W1252: E2 80 98)
    ("\u00e2\u20ac\u2122",  "\u2019"),  # right single quote (W1252: E2 80 99)
    ("\u00e2\u20ac\u0153",  "\u201c"),  # left double quote  (W1252: E2 80 9C)
    ("\u00e2\u20ac",         "\u201d"),  # right double quote (W1252: E2 80 9D)
    ("\u00e2\u20ac\u00a2",  "\u2022"),  # bullet             (W1252: E2 80 A2)
    ("\u00e2\u2014\u2020",  "\u25c6"),  # diamond bullet
    ("\u00e2\u0161\u00a1",  "\u26a1"),  # lightning bolt
    ("\u00e2\u2014",         "\u25cf"),  # filled circle
    ("\u00e2\u02dc ",        "\u2620"),  # skull and crossbones
    ("\u00e2\u0153\u201d",  "\u2714"),  # heavy check mark   (W1252: E2 9C 94)
    ("\u00e2\u2020'",       "\u2192"),  # right arrow
    ("\u00e2\u2020\u2014",  "\u2197"),  # northeast arrow
    ("\u00e2\u00ac\u00a1",  "\u2b21"),  # hexagon
]

# Control characters to strip (except tab/newline/CR which are valid)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_text(text: Any) -> str:
    """
    Normalize a string value:
    1. Coerce to str
    2. Apply mojibake replacement table (longest match first)
    3. Strip control characters
    4. Return clean Unicode string

    Safe to call on any value type (None -> '').
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text

    # Apply text-level mojibake patterns first (most common)
    for bad, good in _TEXT_PATTERNS:
        if bad in text:
            text = text.replace(bad, good)

    # Apply Unicode-level mojibake table
    for bad, good in _MOJIBAKE_TABLE:
        if bad in text:
            text = text.replace(bad, good)

    # Strip control characters
    text = _CONTROL_RE.sub("", text)

    # Strip replacement character
    text = text.replace("\ufffd", "")

    return text


# ---------------------------------------------------------------------------
# Field lists for item normalization
# ---------------------------------------------------------------------------
_STRING_FIELDS = (
    "title", "description", "summary", "actor_tag", "feed_source",
    "source_url", "report_url", "tlp_label", "severity", "validation_status",
    "campaign_id", "threat_level", "threat_urgency",
)

_NESTED_APEX_FIELDS = ("summary", "threat_level", "campaign_id", "recommendation")


def normalize_item(item: dict) -> dict:
    """
    Normalize all string fields in a threat intel item dict.
    Returns the same dict (mutated in-place for efficiency) with clean text.
    """
    for field in _STRING_FIELDS:
        if field in item and isinstance(item[field], str):
            item[field] = normalize_text(item[field])

    # Nested apex_ai / apex blocks
    for apex_key in ("apex_ai", "apex"):
        apex = item.get(apex_key)
        if isinstance(apex, dict):
            for f in _NESTED_APEX_FIELDS:
                if f in apex and isinstance(apex[f], str):
                    apex[f] = normalize_text(apex[f])
            # Recommendations list
            recs = apex.get("recommendations") or apex.get("remediation_steps")
            if isinstance(recs, list):
                apex[list(apex.keys())[list(apex.values()).index(recs)]] = [
                    normalize_text(r) if isinstance(r, str) else r for r in recs
                ]

    # TTPs
    ttps = item.get("ttps")
    if isinstance(ttps, list):
        item["ttps"] = [
            normalize_text(t) if isinstance(t, str) else t for t in ttps
        ]

    # Threat urgency object
    urgency = item.get("threat_urgency")
    if isinstance(urgency, dict):
        for k in ("message", "cta"):
            if k in urgency and isinstance(urgency[k], str):
                urgency[k] = normalize_text(urgency[k])

    return item


def normalize_feed(items: list[dict]) -> list[dict]:
    """
    Normalize all items in a feed list.
    Returns the same list with all string fields cleaned.
    """
    return [normalize_item(item) for item in items]


def scan_for_mojibake(text: str) -> list[str]:
    """
    Return a list of detected mojibake pattern names found in text.
    Used by CI/validation gates.
    """
    found = []
    for bad, _ in _TEXT_PATTERNS:
        if bad in text:
            found.append(repr(bad))
    # Generic \u00e2-prefix check (catches any unhandled double-encoded sequence)
    if re.search(r"\u00e2[^\s]{1,4}", text):
        found.append("generic-\u00e2-prefix-mojibake")
    return found


def hard_fail_check(text: str, source: str = "unknown") -> None:
    """
    CI hard-fail gate. Call after generating any output.
    Raises SystemExit(1) if mojibake is detected.
    """
    found = scan_for_mojibake(text)
    if found:
        print(f"[ENCODING-FAIL] Mojibake detected in {source}: {found}", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    # Self-test
    tests = [
        ("\u00c3\u2014", "\u00d7"),
        ("\u00e2\u20ac\u201d", "\u2014"),  # em-dash (W1252 full: E2 80 94)
        ("\u00e2\u20ac\u00a6", "\u2026"),
        ("Normal text", "Normal text"),
        ("Risk score: 9.2\u00e2\u20ac\u201dcritical", "Risk score: 9.2\u2014critical"),
    ]
    all_pass = True
    for inp, expected in tests:
        result = normalize_text(inp)
        status = "PASS" if result == expected else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"  [{status}] {repr(inp)} -> {repr(result)} (expected {repr(expected)})")
    print(f"\nSelf-test: {'PASS' if all_pass else 'FAIL'}")
