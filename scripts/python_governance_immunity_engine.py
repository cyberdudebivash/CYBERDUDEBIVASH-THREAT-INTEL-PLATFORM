#!/usr/bin/env python3
"""
Python Governance Immunity Engine (PGIE)
=========================================
SENTINEL APEX - STAGE 0.06b enforcement script.

Forensic-grade Python syntax and encoding guardian.
Detects and reports: syntax errors, BOM, CRLF, smart-quotes,
invisible chars, Unicode corruption, truncation, incomplete
multiline/f-string/docstring blocks.

Exit codes:
  0 - all scripts PASS all checks
  1 - one or more scripts FAIL (hard-fail the pipeline)

Author: CyberDudeBivash governance pipeline
Version: 1.0.0 (SENTINEL APEX v152.0.0)
"""

import ast
import os
import sys
import glob
import re
import tokenize
import io
import traceback

# ── ANSI colours (GitHub Actions supports ANSI via step logs) ─────────────────
RESET  = "\033[0m"
RED    = "\033[1;31m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[1;36m"
WHITE  = "\033[1;37m"
DIM    = "\033[2m"
BOLD   = "\033[1m"

# ── Smart / curly quote codepoints (common corruption artefacts) ──────────────
SMART_QUOTES = {
    "'": "'",  # LEFT SINGLE QUOTATION MARK
    "'": "'",  # RIGHT SINGLE QUOTATION MARK
    """: '"',  # LEFT DOUBLE QUOTATION MARK
    """: '"',  # RIGHT DOUBLE QUOTATION MARK
    "′": "'",  # PRIME
    "″": '"',  # DOUBLE PRIME
    "«": '"',  # LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    "»": '"',  # RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
}

# ── Invisible / zero-width characters ────────────────────────────────────────
INVISIBLE_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2060": "WORD JOINER",
    "\ufeff": "BOM / ZERO WIDTH NO-BREAK SPACE",
    "\u00a0": "NO-BREAK SPACE",
    "\u2028": "LINE SEPARATOR",
    "\u2029": "PARAGRAPH SEPARATOR",
}


def banner(text: str, colour: str = CYAN) -> None:
    width = 72
    print(f"\n{colour}{'═' * width}{RESET}")
    print(f"{colour}{BOLD}  {text}{RESET}")
    print(f"{colour}{'═' * width}{RESET}")


def section(label: str) -> None:
    print(f"\n{DIM}  ── {label} ──{RESET}")


def pass_line(msg: str) -> None:
    print(f"  {GREEN}✔ PASS{RESET}  {msg}")


def warn_line(msg: str) -> None:
    print(f"  {YELLOW}⚠ WARN{RESET}  {msg}")


def fail_line(msg: str) -> None:
    print(f"  {RED}✘ FAIL{RESET}  {msg}")


def snippet(lines: list, error_lineno: int, context: int = 4) -> None:
    """Print a code snippet centred on error_lineno (1-based)."""
    start = max(1, error_lineno - context)
    end   = min(len(lines), error_lineno + context)
    print(f"\n  {DIM}{'─' * 60}{RESET}")
    for i in range(start, end + 1):
        raw = lines[i - 1].rstrip("\n")
        if i == error_lineno:
            print(f"  {RED}{BOLD}→ {i:>4}  │  {raw}{RESET}")
        else:
            print(f"  {DIM}  {i:>4}  │  {raw}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}\n")


def check_syntax(filepath: str, source: str, source_lines: list) -> list:
    """Run py_compile / ast.parse; return list of failure dicts."""
    failures = []
    try:
        ast.parse(source, filename=filepath)
    except SyntaxError as exc:
        lineno = exc.lineno or 0
        failures.append({
            "check": "SYNTAX",
            "filepath": filepath,
            "lineno": lineno,
            "message": str(exc),
            "traceback": traceback.format_exc(),
            "snippet_lines": source_lines,
        })
    return failures


def check_bom(filepath: str, raw_bytes: bytes) -> list:
    failures = []
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        failures.append({
            "check": "BOM",
            "filepath": filepath,
            "lineno": 1,
            "message": "File starts with UTF-8 BOM (\\xEF\\xBB\\xBF) - corrupts module imports and CI tools",
            "traceback": "",
            "snippet_lines": [],
        })
    return failures


def check_crlf(filepath: str, raw_bytes: bytes) -> list:
    failures = []
    crlf_count = raw_bytes.count(b"\r\n")
    if crlf_count > 0:
        failures.append({
            "check": "CRLF",
            "filepath": filepath,
            "lineno": 0,
            "message": f"File contains {crlf_count} CRLF line endings (Windows \\r\\n) - use LF only",
            "traceback": "",
            "snippet_lines": [],
        })
    return failures


def check_encoding(filepath: str, raw_bytes: bytes) -> list:
    failures = []
    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        failures.append({
            "check": "ENCODING",
            "filepath": filepath,
            "lineno": 0,
            "message": f"File is not valid UTF-8: {exc}",
            "traceback": "",
            "snippet_lines": [],
        })
    return failures


def check_smart_quotes(filepath: str, source_lines: list) -> list:
    failures = []
    for lineno, line in enumerate(source_lines, start=1):
        for char, replacement in SMART_QUOTES.items():
            if char in line:
                failures.append({
                    "check": "SMART_QUOTE",
                    "filepath": filepath,
                    "lineno": lineno,
                    "message": f"Smart/curly quote U+{ord(char):04X} ({char!r}) found - replace with {replacement!r}",
                    "traceback": "",
                    "snippet_lines": source_lines,
                })
    return failures


def check_invisible_chars(filepath: str, source_lines: list) -> list:
    failures = []
    for lineno, line in enumerate(source_lines, start=1):
        for char, name in INVISIBLE_CHARS.items():
            if len(char) != 1:  # safety: skip empty/corrupt dict keys
                continue
            if char in line:
                failures.append({
                    "check": "INVISIBLE_CHAR",
                    "filepath": filepath,
                    "lineno": lineno,
                    "message": f"Invisible char U+{ord(char):04X} ({name}) found at line {lineno}",
                    "traceback": "",
                    "snippet_lines": source_lines,
                })
    return failures


def check_truncation(filepath: str, source: str, source_lines: list) -> list:
    """
    Heuristic truncation detection:
    - Last non-empty line is a def/class/decorator with no body
    - Open triple-quote string not closed
    - Open parenthesis / bracket / brace not closed at module level
    """
    failures = []

    # 1. Check for unclosed triple-quoted strings via tokenize
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError as exc:
        msg = str(exc)
        # tokenize raises TokenError for unclosed multi-line strings/brackets
        lineno = exc.args[1][0] if len(exc.args) > 1 else 0
        failures.append({
            "check": "TRUNCATION",
            "filepath": filepath,
            "lineno": lineno,
            "message": f"Tokenization failed - likely truncated/incomplete structure: {msg}",
            "traceback": "",
            "snippet_lines": source_lines,
        })
        return failures

    # 2. Last non-blank line ends with colon → body expected but missing
    non_blank = [l.rstrip() for l in source_lines if l.strip()]
    if non_blank:
        last = non_blank[-1]
        if last.endswith(":") and not last.lstrip().startswith("#"):
            failures.append({
                "check": "TRUNCATION",
                "filepath": filepath,
                "lineno": len(source_lines),
                "message": f"File ends with '{last.strip()}' - expected indented body after colon (truncated?)",
                "traceback": "",
                "snippet_lines": source_lines,
            })

    return failures


def check_incomplete_fstrings(filepath: str, source_lines: list) -> list:
    """Detect lines with an odd number of { or } that are not inside strings."""
    failures = []
    # Simple heuristic: look for f" or f' not closed on same line
    fstr_re = re.compile(r'\bf["\']')
    for lineno, line in enumerate(source_lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Count unmatched braces in apparent f-string contexts
        if fstr_re.search(line):
            opens = line.count("{") - line.count("{{") * 2 // 2 if "{{" in line else line.count("{")
            closes = line.count("}") - line.count("}}") * 2 // 2 if "}}" in line else line.count("}")
            # Rough mismatch that's too large suggests a corrupted f-string
            if abs(opens - closes) > 4:
                failures.append({
                    "check": "FSTRING",
                    "filepath": filepath,
                    "lineno": lineno,
                    "message": f"Possible malformed f-string: unmatched braces ({opens} open, {closes} close)",
                    "traceback": "",
                    "snippet_lines": source_lines,
                })
    return failures


def audit_file(filepath: str) -> dict:
    """Run all governance checks on a single file. Returns audit result dict."""
    result = {
        "filepath": filepath,
        "failures": [],
        "warnings": [],
        "status": "PASS",
    }

    # ── Read raw bytes first ─────────────────────────────────────────────────
    try:
        with open(filepath, "rb") as fh:
            raw_bytes = fh.read()
    except OSError as exc:
        result["failures"].append({
            "check": "READ",
            "filepath": filepath,
            "lineno": 0,
            "message": f"Cannot read file: {exc}",
            "traceback": "",
            "snippet_lines": [],
        })
        result["status"] = "FAIL"
        return result

    # BOM must be checked on raw bytes BEFORE any decode
    result["failures"] += check_bom(filepath, raw_bytes)
    result["failures"] += check_crlf(filepath, raw_bytes)
    result["failures"] += check_encoding(filepath, raw_bytes)

    # If encoding is broken, can't do text-based checks
    if any(f["check"] == "ENCODING" for f in result["failures"]):
        result["status"] = "FAIL"
        return result

    # Strip BOM for text parsing if present
    source_bytes = raw_bytes.lstrip(b"\xef\xbb\xbf")
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        source = source_bytes.decode("latin-1")

    source_lines = source.splitlines(keepends=True)

    # ── Text / structure checks ──────────────────────────────────────────────
    result["failures"] += check_syntax(filepath, source, source_lines)
    result["warnings"] += check_smart_quotes(filepath, source_lines)
    result["warnings"] += check_invisible_chars(filepath, source_lines)
    # Only run truncation / f-string checks if syntax is clean
    if not any(f["check"] == "SYNTAX" for f in result["failures"]):
        result["warnings"] += check_truncation(filepath, source, source_lines)
        # f-string check is informational - downgrade to warning
        result["warnings"] += check_incomplete_fstrings(filepath, source_lines)

    if result["failures"]:
        result["status"] = "FAIL"
    elif result["warnings"]:
        result["status"] = "WARN"

    return result


def print_finding(finding: dict, severity: str) -> None:
    colour = RED if severity == "FAIL" else YELLOW
    lineno_str = f"line {finding['lineno']}" if finding['lineno'] else "file-level"
    print(f"\n  {colour}{BOLD}[{severity}] {finding['check']}{RESET}  "
          f"{WHITE}{finding['filepath']}{RESET}  {DIM}{lineno_str}{RESET}")
    print(f"  {colour}  ↳ {finding['message']}{RESET}")
    if finding.get("traceback"):
        for tb_line in finding["traceback"].strip().splitlines():
            print(f"  {DIM}    {tb_line}{RESET}")
    if finding.get("snippet_lines") and finding.get("lineno", 0) > 0:
        snippet(finding["snippet_lines"], finding["lineno"])


def main() -> int:
    target_pattern = os.environ.get("PGIE_PATTERN", "scripts/*.py")
    files = sorted(glob.glob(target_pattern))

    banner(f"PYTHON GOVERNANCE IMMUNITY ENGINE  -  SENTINEL APEX v152.0.0")
    print(f"  Target pattern : {BOLD}{target_pattern}{RESET}")
    print(f"  Files matched  : {BOLD}{len(files)}{RESET}")

    if not files:
        warn_line(f"No Python files found matching '{target_pattern}'")
        return 0

    total_pass = 0
    total_warn = 0
    total_fail = 0
    all_results = []

    for filepath in files:
        result = audit_file(filepath)
        all_results.append(result)
        if result["status"] == "PASS":
            total_pass += 1
        elif result["status"] == "WARN":
            total_warn += 1
        else:
            total_fail += 1

    # ── Per-file detail report ────────────────────────────────────────────────
    banner("DETAILED FORENSIC REPORT", CYAN)

    for result in all_results:
        fp = result["filepath"]
        status = result["status"]
        colour = GREEN if status == "PASS" else (YELLOW if status == "WARN" else RED)
        print(f"\n  {colour}{BOLD}[{status}]{RESET}  {WHITE}{fp}{RESET}")

        for finding in result["failures"]:
            print_finding(finding, "FAIL")

        for finding in result["warnings"]:
            print_finding(finding, "WARN")

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("GOVERNANCE SUMMARY", CYAN)
    total = len(files)
    print(f"  {GREEN}✔ PASS   {total_pass:>4} / {total}{RESET}")
    print(f"  {YELLOW}⚠ WARN   {total_warn:>4} / {total}{RESET}")
    print(f"  {RED}✘ FAIL   {total_fail:>4} / {total}{RESET}")

    if total_fail > 0:
        banner(f"GOVERNANCE: HARD-FAIL - {total_fail} script(s) corrupted. PIPELINE BLOCKED.", RED)
        print(f"\n  {RED}Fix ALL failures listed above before re-running the pipeline.{RESET}")
        print(f"  {RED}DO NOT: disable syntax guards, bypass regression gates, remove validators, weaken governance.{RESET}\n")
        return 1

    if total_warn > 0:
        banner(f"GOVERNANCE: WARN - {total_warn} script(s) with warnings. Pipeline CONTINUES.", YELLOW)
    else:
        banner("GOVERNANCE: ALL PASS - Pipeline CLEAR.", GREEN)

    return 0


if __name__ == "__main__":
    sys.exit(main())
