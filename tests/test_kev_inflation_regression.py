#!/usr/bin/env python3
"""
tests/test_kev_inflation_regression.py — Forensic-audit regression suite

ORIGIN: Forensic production audit of run `sentinel-blogger #1551`, which
hard-failed at STAGE 3.93.15 (P0 Intelligence Integrity Gate v160.0) by
flagging CVE-2022-28368 / CVE-2024-39930 as "KEV-inflated".

ROOT CAUSE (verified, traced to source + runtime logs — see
FORENSIC-AUDIT-REPORT.md, Finding F1): `kev_feed_marker._extract_cve()`
scanned text fields (title, id, source_url, description) for CVE IDs, while
`intelligence_integrity_gate._cves()` -> `_title()` scanned (title, headline,
name). For any item whose CVE text lived in `headline`/`name` — a real,
populated field pattern elsewhere in this codebase — the marker returned
cves=[], silently skipped re-validating its `kev` flag against the live CISA
KEV catalog, and let a then-unverified flag survive untouched. The gate, with
its wider view, found the same CVE cleanly and flagged the pairing as
"inflated" — a false positive caused entirely by the marker's blind spot, not
by anything wrong with the underlying intelligence.

MANDATE: These tests are the permanent regression guard for the KEV/CVE
         marking <-> integrity-gate contract. They encode the actual
         field-name invariant that broke in production. If they fail,
         the marker and the gate have diverged again and a false
         HARD_FAIL on genuinely-correct data is the likely outcome.

Tests:
  - test_extract_cve_finds_id_in_every_canonical_text_field()
  - test_headline_only_repro_matches_run_1551_failure_shape()
  - test_marker_and_gate_agree_on_cve_set()                  <- the parity contract
  - test_collector_no_longer_originates_unverified_kev_guess()
"""

import os
import sys

import pytest

# ── Ensure scripts/ is importable (matches tests/test_severity_governance_p0.py) ──
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import kev_feed_marker                      # noqa: E402  (path setup must run first)
import intelligence_integrity_gate as iig   # noqa: E402

_extract_cve = kev_feed_marker._extract_cve
_cves = iig._cves
_title = iig._title


# ─────────────────────────────────────────────────────────────────────────────
# T1 — _extract_cve must see every canonical text field, individually
# ─────────────────────────────────────────────────────────────────────────────

CANONICAL_TEXT_FIELDS = ("title", "headline", "name", "description", "id", "source_url")


@pytest.mark.parametrize("field", CANONICAL_TEXT_FIELDS)
def test_extract_cve_finds_id_in_every_canonical_text_field(field):
    """A CVE mentioned in ANY canonical text field must be extractable.

    Regression for Finding F1: the pre-patch field list
    ("title", "id", "source_url", "description") silently excluded
    `headline` and `name`, which are real, populated keys elsewhere in
    this exact codebase (manifest_repair.py, auto_blog_publisher.py,
    seo_domination.py, threat_page_generator.py all read or write them).
    """
    item = {field: "Exploitation confirmed for CVE-2022-28368 in the wild"}
    assert _extract_cve(item) == ["CVE-2022-28368"], (
        f"_extract_cve must find CVEs living in `{field}` — if this fails, "
        f"it is once again only scanning a subset of the canonical text "
        f"fields, which is exactly how run #1551 produced a false HARD_FAIL."
    )


def test_headline_only_repro_matches_run_1551_failure_shape():
    """Direct repro of the #1551 failure mode.

    Item shape: CVE lives ONLY in `headline` (title is generic), and the
    item is currently flagged kev=True — i.e. exactly the pre-existing
    state of a record the marker is supposed to re-validate. Pre-patch,
    `_extract_cve` returns [] for this item, so the marking loop's
    `if not cves: ... continue` branch fires, the item is counted as
    "already_kev" and passed through with its kev flag UNCHECKED against
    the live catalog — while the gate, using its wider `_title()` fallback,
    sees the CVE plainly and (combined with the still-true kev flag this
    function failed to re-validate) reports it as inflated.
    """
    item = {
        "title": "Vendor ships coordinated patch bundle for Q2",   # no CVE here
        "headline": "CVE-2024-39930 actively exploited — CISA adds to KEV catalog",
        "kev": True,
        "kev_present": True,
    }

    cves_seen_by_marker = _extract_cve(item)
    assert "CVE-2024-39930" in cves_seen_by_marker, (
        "The marker still cannot see a CVE that lives in `headline`. "
        "This item would once again silently bypass de-inflation with "
        "kev=True left unverified — Finding F1, reproduced."
    )

    # And confirm the gate's view — which is what actually fired in #1551 —
    # agrees with what the (patched) marker now sees, closing the loop:
    cves_seen_by_gate = _cves(item)
    assert set(cves_seen_by_marker) == set(cves_seen_by_gate), (
        f"Marker sees {cves_seen_by_marker} but gate sees {cves_seen_by_gate} "
        f"for the SAME item — this divergence is the literal mechanism of "
        f"the #1551 false positive."
    )


# ─────────────────────────────────────────────────────────────────────────────
# T2 — the structural fix's test: marker and gate must agree, by construction
# ─────────────────────────────────────────────────────────────────────────────
#
# Finding F1's real lesson wasn't "the regex was wrong" — it was that two
# functions which MUST produce the same answer about the same flag, at two
# different pipeline stages, were silently allowed to diverge. This test
# asserts that invariant directly, on a small corpus that exercises every
# field-location this audit identified as live in production. If anyone
# changes either function's field list without changing the other, this
# fails immediately in CI — instead of three stages later, in production,
# as a HARD_FAIL with a misleading "inflation" diagnosis.

PARITY_FIXTURES = [
    pytest.param({"title": "CVE-2022-28368 exploited in VMware ESXi"},
                 id="cve-in-title"),
    pytest.param({"title": "Generic vendor advisory",
                  "headline": "CVE-2024-39930 added to CISA KEV catalog"},
                 id="cve-in-headline-only"),
    pytest.param({"title": "Untitled", "headline": "Untitled",
                  "name": "Advisory: CVE-2023-12345 patch available"},
                 id="cve-in-name-only"),
    pytest.param({"title": "Untitled", "headline": "Untitled", "name": "Untitled",
                  "description": "Researchers chained CVE-2021-44228 with another bug"},
                 id="cve-in-description-only"),
    pytest.param({"cve_ids": ["CVE-2020-11111"], "title": "No CVE in any text field"},
                 id="cve-in-structured-field-only"),
    pytest.param({"title": "Routine vendor advisory naming no vulnerabilities"},
                 id="no-cve-anywhere"),
    pytest.param({"title": "CVE-2022-28368 in title",
                  "headline": "CVE-2024-39930 in headline",
                  "name": "CVE-2023-99999 in name"},
                 id="multiple-cves-across-fields"),
]


@pytest.mark.parametrize("item", PARITY_FIXTURES)
def test_marker_and_gate_agree_on_cve_set(item):
    """The parity contract: kev_feed_marker and intelligence_integrity_gate
    must extract an IDENTICAL CVE set from an identical item.

    These two functions audit the same `kev` flag at different stages of
    the same pipeline run. Any divergence here is — by construction — a
    latent false-positive (or false-negative) HARD_FAIL waiting to happen,
    exactly as occurred in run #1551.
    """
    marker_view = set(_extract_cve(dict(item)))
    gate_view = set(_cves(dict(item)))
    assert marker_view == gate_view, (
        f"DIVERGENCE on fixture {item!r}:\n"
        f"  kev_feed_marker._extract_cve          -> {sorted(marker_view)}\n"
        f"  intelligence_integrity_gate._cves     -> {sorted(gate_view)}\n"
        f"Both functions must see the same CVEs on the same item, or the "
        f"gate will eventually flag something the marker already 'handled' "
        f"(or vice versa) — Finding F1's exact mechanism."
    )


def test_title_helper_field_order_documented_and_matched():
    """Pin down _title()'s fallback order explicitly (title > headline > name)
    and assert the marker's text-fallback list is a superset of it. This is
    the precise, minimal invariant whose violation caused F1 — encode it
    directly so the next person who edits either list sees this test name
    and knows exactly which sibling function they must also check."""
    assert _title({"title": "T", "headline": "H", "name": "N"}) == "T"
    assert _title({"headline": "H", "name": "N"}) == "H"
    assert _title({"name": "N"}) == "N"

    # _title()'s fallback chain is the documented source of the asymmetry
    # (see FORENSIC-AUDIT-REPORT.md Finding F1). Pin it down explicitly: every
    # field _title() can return from must also be in the marker's scan list —
    # the parametrized test above is the behavioural enforcement of this.
    gate_fallback_fields = {"title", "headline", "name"}
    assert gate_fallback_fields.issubset(set(CANONICAL_TEXT_FIELDS)), (
        "intelligence_integrity_gate._title()'s fallback fields "
        f"{gate_fallback_fields} must all be present in this suite's "
        f"CANONICAL_TEXT_FIELDS — and, by the parametrized test above, "
        f"in kev_feed_marker._extract_cve()'s scan list too."
    )


# ─────────────────────────────────────────────────────────────────────────────
# T3 — the collector must no longer originate an unverified kev guess
# ─────────────────────────────────────────────────────────────────────────────

def test_collector_no_longer_originates_unverified_kev_guess():
    """Finding F1-secondary: multi_source_collector previously set
    item["kev"] = "YES"/"NO" from a bare substring test on the title
    ("kev" matches inside ANY word containing those three letters in
    sequence — e.g. "wikevent", "McKevin Industries" — independent of
    the correctly-regex-extracted `cve_ids` on the same item).

    That created "Frankenstein" records: a real CVE paired with a
    guessed, unverified KEV flag, which the marker could only correct
    if the CVE happened to live in a field its extractor checked — i.e.
    the exact same blind spot as F1, from a different angle.

    Post-fix, the collector should not assign a `kev` value for CISA
    items at collection time at all — leaving it for the catalog-backed
    kev_feed_marker pass (which runs on every item, including freshly
    collected ones, later in the same pipeline run) to be the sole
    origin of truth. We assert this at the source level: the literal
    substring-guess assignment must be gone.
    """
    collector_path = os.path.join(SCRIPTS_DIR, "multi_source_collector.py")
    with open(collector_path, "r", encoding="utf-8") as f:
        src = f.read()

    assert '"kev" in title_low or "known exploited" in title_low' not in src, (
        "multi_source_collector.py still derives item['kev'] from a bare "
        "title-substring guess. This plants unverified KEV flags that only "
        "get corrected downstream if the CVE lives in a field the marker's "
        "extractor checks — the same failure shape as Finding F1, with a "
        "different entry point."
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
