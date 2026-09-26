#!/usr/bin/env python3
"""
SENTINEL APEX -- Monetization Gate Mojibake-Detection Regression Tests

Guards against a recurrence of the CI outage that blocked AI publication for
~30 hours across 7 consecutive scheduled runs (generate-and-sync.yml #544
2026-09-02T07:23Z through #550 2026-09-03T13:05Z, fixed in #353 / 9d9a753a1).

WHAT HAPPENED
-------------
scripts/validate_monetization.py's check_no_junk_chars() hand-rolled its own
`junk_patterns` list intended to catch mojibake (encoding corruption). Six of
its eight entries were not corruption signatures at all -- they were the
plain, CORRECT UTF-8 encodings of ordinary punctuation:

    b"\\xe2\\x80\\x94"  is simply U+2014 EM DASH encoded as UTF-8
    b"\\xe2\\x82\\xb9"  is simply U+20B9 RUPEE SIGN
    b"\\xc2\\xa0"       is simply U+00A0 NO-BREAK SPACE
    b"\\xe2\\x80\\x9c/\\x9d/\\x98"  are simply the curly quotes

So any file containing a legitimate em dash failed the gate. PR #316 added em
dashes to upgrade.html's copy on 2026-09-02, and STAGE 5.7 hard-failed on
every run from that moment on. Because the gate runs BEFORE the publication
stages, AI Tracker generation (STAGE 5/6) succeeded every run while its fresh
outputs -- api/ai/tracker.json, health.json, executive-brief.json -- were
never committed or R2-synced. The platform's AI features went stale silently.

sentinel-blogger.yml calls the same script but never tripped it, because its
STAGE 5.7-PRE step (fix_all_html_encoding.py) launders those exact bytes into
HTML entities first. generate-and-sync.yml has no such pre-step, so it met the
underlying defect head-on.

WHY THIS TEST EXISTS
--------------------
#353 corrected the code but added no test. The defect is trivially
re-introducible -- anyone "improving" mojibake detection by appending a
plausible-looking byte string re-creates it, and the failure mode is a silent
30-hour data staleness rather than an obvious break. These tests pin BOTH
directions, because each has its own failure mode:

  * false POSITIVE (the #544-#550 outage): flagging correct UTF-8 punctuation
    blocks publication of healthy content.
  * false NEGATIVE (the tempting over-correction): "fixing" the gate by
    emptying the pattern list would make it pass always and let genuine
    payment-page corruption reach customers.

ADJACENT RISKS FOUND WHILE WRITING THESE TESTS -- REPORTED, NOT CHANGED
-----------------------------------------------------------------------
Both are documented here rather than silently "fixed", because each would
change the behaviour of a customer-facing gate and neither is what #353 fixed:

  1. validate_all_html_encoding() (same module, untouched by #353) keeps its
     own separate two-entry list, one of which is b"\\xc3\\xa2". That is the
     correct UTF-8 encoding of U+00E2 'a-circumflex' -- legitimate in French /
     Portuguese copy ("chateau", "rape") -- so it carries the same
     false-positive shape as the #544-#550 defect. It has not fired because
     that function scans repo-root *.html only, and no root page currently
     contains that character. It is ALSO the shared first two bytes of every
     Latin-1 double-encoded triple, so as a broad heuristic it genuinely does
     catch corruption MOJIBAKE_TRIPLES alone would miss. Narrowing it is a real
     detection-vs-false-positive trade-off, not an obvious win, so it is left
     as-is and flagged here.

  2. Published report HTML under reports/ contains genuine mojibake -- e.g.
     a double-encoded U+2190 back-arrow in the "Back to Platform" link -- via a
     Windows-1252 partial sequence that MOJIBAKE_TRIPLES does not currently
     match. Cosmetic (a broken glyph), not functional, and outside every gate's
     scan scope today. Remediating ~11,000 published files is its own operation.

Run:
    python -m pytest tests/test_monetization_mojibake_detection.py -v
"""

import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fix_all_html_encoding import MOJIBAKE_TRIPLES  # noqa: E402
from homepage_source import read_bytes_for_inspection  # noqa: E402  (index.html + extracted css/js)

MOJIBAKE_PATTERNS = [pattern for pattern, _ in MOJIBAKE_TRIPLES]


def _detects(data: bytes) -> bool:
    """Mirror of check_no_junk_chars()'s decision, over the shared pattern set."""
    return any(p in data for p in MOJIBAKE_PATTERNS)


def _double_encode(text: str) -> bytes:
    """Produce GENUINE mojibake the way it actually happens in production:
    correct UTF-8 bytes misdecoded as Latin-1, then re-encoded as UTF-8."""
    return text.encode("utf-8").decode("latin-1").encode("utf-8")


# Ordinary punctuation that appears in legitimate customer-facing copy and
# must never be mistaken for corruption. The em dash is the exact character
# that caused the #544-#550 outage.
LEGITIMATE_PUNCTUATION = {
    "U+2014 EM DASH": "—",
    "U+2013 EN DASH": "–",
    "U+201C LEFT DOUBLE QUOTE": "“",
    "U+201D RIGHT DOUBLE QUOTE": "”",
    "U+2018 LEFT SINGLE QUOTE": "‘",
    "U+2019 RIGHT SINGLE QUOTE": "’",
    "U+2026 HORIZONTAL ELLIPSIS": "…",
    "U+2022 BULLET": "•",
    "U+20B9 RUPEE SIGN": "₹",
    "U+00A0 NO-BREAK SPACE": " ",
    "U+20AC EURO SIGN": "€",
}


# ---------------------------------------------------------------------------
# Direction 1 -- FALSE POSITIVES (the actual #544-#550 outage)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,char", LEGITIMATE_PUNCTUATION.items(), ids=list(LEGITIMATE_PUNCTUATION))
def test_correctly_encoded_punctuation_is_not_mojibake(name, char):
    """Correct UTF-8 punctuation must never be flagged as corruption."""
    payload = f"<p>SENTINEL APEX {char} enterprise threat intelligence</p>".encode("utf-8")
    assert not _detects(payload), (
        f"{name} is legitimate, correctly-encoded UTF-8 content -- flagging it "
        f"hard-fails the monetization gate on healthy copy and blocks publication. "
        f"This is exactly the defect that broke generate-and-sync.yml #544-#550."
    )


def test_the_exact_byte_sequence_that_broke_runs_544_to_550():
    """Pin the specific regression by its bytes, not just its character."""
    em_dash_utf8 = b"\xe2\x80\x94"
    assert em_dash_utf8 == "—".encode("utf-8"), "sanity: this IS U+2014's correct UTF-8 encoding"
    assert not _detects(em_dash_utf8), (
        "b'\\xe2\\x80\\x94' is the CORRECT UTF-8 encoding of U+2014 EM DASH, not a "
        "mojibake signature. A prior junk_patterns list contained it verbatim, which "
        "hard-failed STAGE 5.7 on every run once PR #316 added em dashes to "
        "upgrade.html -- blocking api/ai/tracker.json publication for ~30 hours."
    )


def test_no_mojibake_pattern_is_a_bare_correct_encoding_of_punctuation():
    """Structural guard: no pattern may equal the plain UTF-8 bytes of a real
    character. Catches a bad entry at the source, whatever list it is added to."""
    for name, char in LEGITIMATE_PUNCTUATION.items():
        correct = char.encode("utf-8")
        assert correct not in MOJIBAKE_PATTERNS, (
            f"{name}'s correct UTF-8 encoding {correct!r} is registered as a mojibake "
            f"pattern. It is legitimate content, not corruption."
        )


def test_real_customer_facing_pages_pass_the_detector():
    """The live payment/monetization pages must be clean under the detector.
    Skips any page not present rather than asserting on repo layout."""
    checked = 0
    for page in ("upgrade.html", "PAYMENT-GATEWAY.html", "pricing.html", "store.html", "index.html"):
        path = REPO_ROOT / page
        if not path.exists():
            continue
        checked += 1
        assert not _detects(path.read_bytes()), (
            f"{page} trips the mojibake detector. Either the page really is corrupted, "
            f"or a false-positive pattern has been reintroduced (see #544-#550)."
        )
    assert checked > 0, "no monetization pages found to check -- test would be vacuous"


# ---------------------------------------------------------------------------
# Direction 2 -- FALSE NEGATIVES (the tempting over-correction)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name,char",
    [(n, c) for n, c in LEGITIMATE_PUNCTUATION.items() if n != "U+00A0 NO-BREAK SPACE"],
    ids=[n for n in LEGITIMATE_PUNCTUATION if n != "U+00A0 NO-BREAK SPACE"],
)
def test_genuine_double_encoded_corruption_is_still_detected(name, char):
    """The gate must keep catching real corruption -- otherwise 'fixing' the
    false positive by emptying the list would ship broken payment pages.

    U+00A0 is excluded: its Latin-1 double-encoding (C2 A0 -> C3 82 C2 A0) is
    not in MOJIBAKE_TRIPLES, which is a deliberate scope choice of that module
    rather than a regression this test should assert on.
    """
    corrupted = _double_encode(char)
    assert _detects(corrupted), (
        f"genuine double-encoded {name} ({corrupted!r}) is NOT detected. The mojibake "
        f"gate has been weakened into a no-op -- real encoding corruption on a payment "
        f"page would now reach customers."
    )


def test_detector_is_not_vacuous():
    """A non-empty pattern set, stated as an assertion: an empty list would make
    every other false-negative test pass trivially."""
    assert len(MOJIBAKE_PATTERNS) >= 8, (
        f"only {len(MOJIBAKE_PATTERNS)} mojibake patterns registered -- the detector "
        f"has been gutted rather than corrected."
    )
    assert all(isinstance(p, bytes) and p for p in MOJIBAKE_PATTERNS)


# ---------------------------------------------------------------------------
# Single source of truth
# ---------------------------------------------------------------------------

def _check_no_junk_chars_source() -> str:
    """Isolate check_no_junk_chars()'s body -- the function this outage was in.

    Deliberately NOT the whole module: validate_all_html_encoding() further down
    keeps its own separate two-entry list, which is a documented adjacent risk
    (see the module docstring note below) but is a different function, a
    different scan scope (repo-root *.html only), and not what #353 fixed.
    Asserting over the whole file would couple this regression test to that
    unrelated code.
    """
    source = (SCRIPTS / "validate_monetization.py").read_text(encoding="utf-8")
    start = source.index("def check_no_junk_chars")
    end = source.index("\ndef ", start + 1)
    return source[start:end]


def test_check_no_junk_chars_reuses_the_shared_pattern_set():
    """check_no_junk_chars() must import MOJIBAKE_TRIPLES, not hand-roll a
    second list. The duplicate list IS the root cause -- two independent
    definitions of 'what mojibake looks like' drifted apart, and the copy in
    validate_monetization.py was the wrong one."""
    module_source = (SCRIPTS / "validate_monetization.py").read_text(encoding="utf-8")
    assert "from fix_all_html_encoding import MOJIBAKE_TRIPLES" in module_source, (
        "validate_monetization.py no longer imports MOJIBAKE_TRIPLES -- a second, "
        "independent mojibake pattern list has been reintroduced. That duplication is "
        "the root cause of the #544-#550 outage."
    )

    fn = _check_no_junk_chars_source()
    assert "MOJIBAKE_TRIPLES" in fn, (
        "check_no_junk_chars() no longer uses the shared MOJIBAKE_TRIPLES set."
    )
    assert "junk_patterns" not in fn, (
        "a local junk_patterns list has returned to check_no_junk_chars(). Mojibake "
        "signatures for this check have exactly one definition: MOJIBAKE_TRIPLES in "
        "fix_all_html_encoding.py."
    )
    # No raw byte literals of their own -- the whole point is that this function
    # owns no pattern data.
    assert 'b"\\x' not in fn and "b'\\x" not in fn, (
        "check_no_junk_chars() has grown its own raw byte patterns again. Every "
        "signature must come from MOJIBAKE_TRIPLES."
    )


def test_monetization_gate_passes_end_to_end():
    """The gate itself must exit 0 on the current tree -- the outage was a
    non-zero exit, so assert the real observable, not just the helper."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_monetization.py")],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, (
        f"validate_monetization.py exited {result.returncode}. STAGE 5.7 blocks all "
        f"downstream publication, so a non-zero exit silently staleness-freezes "
        f"api/ai/tracker.json and the dashboard's AI features.\n"
        f"--- stdout tail ---\n{result.stdout[-2000:]}"
    )
    assert "GATE: PASS" in result.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
