"""
test_narrative_evidence_grounding.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for PR-E2 (Narrative & Evidence Grounding).

Root causes under test (see PHASE3_NARRATIVE_EVIDENCE_GROUNDING.md for full
live-production evidence):

- scripts/context_aware_narrative_engine.py: the zero-day narrative tier
  unconditionally asserted "active exploitation confirmed" for any item
  whose title/description matched a "zero-day"/"0day" regex, regardless of
  KEV or exploit_maturity evidence. A live public report page
  (reports/2026/08/intel--d7beb221c8a4b865.html, CVE-2026-68820) said
  "active exploitation confirmed" twice while showing KEV STATUS: NOT IN
  KEV, CVSS: N/A, EPSS: N/A two sentences later. Thirteen call sites also
  computed `kev = bool(item.get("kev") or ...)`, which treats the legacy
  string value "NO" as truthy (Python: bool("NO") is True) -- the same
  defect class js/metric-normalize.js's CDB_NORMALIZE.kevState() fixed on
  the frontend in PR-E1.

- scripts/exploit_maturity_enricher.py: exploit_maturity could be assigned
  "FUNCTIONAL" (this module's own docstring: "Public working exploit /
  Metasploit module") purely from EPSS >= 50%, with zero actual exploit-code
  evidence. Live sample: all 10 current FUNCTIONAL items had
  metasploit_available:false, poc_github_count:0.

- scripts/exploit_maturity_enricher.py's _determine_maturity() also ignored
  kev_present/in_kev entirely and read only kev/KEV/cisa_kev without the
  kev_present-takes-precedence rule _kev_confirmed() already established in
  the sibling file -- so {"kev_present": True} (no legacy kev field) fell
  through to UNPROVEN, and {"kev_present": False, "kev": "YES"} (a stale
  legacy field disagreeing with the authoritative boolean) was wrongly
  classified WEAPONIZED. Fixed via the new local _kev_evidence_confirmed(),
  mirroring _kev_confirmed()'s precedence rules.

PR-E2 change-control summary (CYBERDUDEBIVASH SENTINEL APEX Engineering
Constitution, Proof Before Change):

  Objective                 Stop the content pipeline from asserting
                             "active exploitation confirmed" without KEV or
                             evidenced exploit-maturity backing it, and stop
                             exploit_maturity:FUNCTIONAL from being inferred
                             from EPSS alone.
  Affected files             scripts/context_aware_narrative_engine.py,
                             scripts/exploit_maturity_enricher.py,
                             tests/test_narrative_evidence_grounding.py (new)
  Existing engine reused      None re-implemented -- consumes the same
                             kev_present/kev/exploit_maturity fields the
                             pipeline already writes; mirrors (does not
                             import, to avoid a cross-module coupling wider
                             than this fix needs) the KEV-precedence pattern
                             CDB_NORMALIZE.kevState() established on the
                             frontend in PR-E1.
  Evidence modification required  PHASE0_SEMANTIC_INTEGRITY_REPORT.md rows
                             26-28, re-verified this session with exact
                             file:line citations and one live, public,
                             self-contradicting report page (cited above).
  Risk classification         MEDIUM. Backend content-generation pipeline
                             (sentinel-apex.yml), 16 downstream consumers
                             of exploit_maturity verified to only check
                             value membership (no distribution/count
                             assertions broken by values becoming more
                             accurate). No frontend/schema/route/auth
                             changes.
  Regression risk             exploit_maturity FUNCTIONAL/POC counts
                             decrease (only genuinely evidenced items
                             qualify now) -- intended, not a regression.
                             Applies to newly generated content only; does
                             not retroactively rewrite already-published
                             report HTML.
  Rollback plan                Revert this PR's single commit; both files
                             return to their prior state; exploit_maturity
                             remains the same string field/enum, no data
                             migration needed.

Reuse Report: 0 duplicate engines introduced, 0 duplicate routes (none
touched), backward compatibility preserved (exploit_maturity's possible
values are unchanged; only which items qualify became more accurate),
certification chain intact (p33 WORLDWIDE_RELEASE, 0 blockers, re-run after
these changes), regression suite 21/21 PASS
(scripts/regression_tests.py), full existing pytest suite unaffected
(1007/1007 pre-existing passing tests still pass; 19 pre-existing failures
are unrelated environment/dependency gaps in this container).
"""
import pytest

from scripts.context_aware_narrative_engine import (
    _kev_confirmed,
    _narrative_zero_day,
    generate_context_aware_executive_summary,
)
from scripts.exploit_maturity_enricher import _determine_maturity


# ─── _kev_confirmed() ──────────────────────────────────────────────────────

class TestKevConfirmed:
    def test_kev_present_true(self):
        assert _kev_confirmed({"kev_present": True}) is True

    def test_kev_present_false(self):
        assert _kev_confirmed({"kev_present": False}) is False

    def test_legacy_kev_yes_string(self):
        assert _kev_confirmed({"kev": "YES"}) is True

    def test_legacy_kev_no_string_is_not_truthy(self):
        """The exact regression this fix exists for: bool("NO") is True in
        Python, but "NO" must resolve to False, not True."""
        assert _kev_confirmed({"kev": "NO"}) is False

    def test_legacy_kev_false_string(self):
        assert _kev_confirmed({"kev": "FALSE"}) is False

    def test_missing_kev_defaults_false(self):
        assert _kev_confirmed({}) is False

    def test_kev_present_precedence_over_legacy_string(self):
        assert _kev_confirmed({"kev_present": False, "kev": "YES"}) is False
        assert _kev_confirmed({"kev_present": True, "kev": "NO"}) is True

    def test_live_production_regression_case(self):
        """CVE-2026-68820-shaped item: kev_present:null, kev:'NO'."""
        item = {"kev_present": None, "kev": "NO", "cvss_score": None, "epss_score": 0}
        assert _kev_confirmed(item) is False


# ─── Zero-day narrative evidence gating ────────────────────────────────────

class TestZeroDayNarrativeGrounding:
    def test_confirmed_exploitation_language_requires_kev(self):
        item = {
            "title": "Zero-Day Vulnerability in Example Widget",
            "kev_present": True,
            "cvss_score": 9.8,
        }
        html = _narrative_zero_day(item)
        assert "active exploitation confirmed" in html

    def test_confirmed_exploitation_language_requires_functional_maturity(self):
        item = {
            "title": "Zero-Day Vulnerability in Example Widget",
            "kev_present": False,
            "exploit_maturity": "FUNCTIONAL",
            "cvss_score": 9.8,
        }
        html = _narrative_zero_day(item)
        assert "active exploitation confirmed" in html

    def test_no_confirmed_exploitation_claim_without_evidence(self):
        """The exact live-production regression: a title containing
        'zero-day' with no KEV/exploit_maturity evidence must not assert
        confirmed exploitation."""
        item = {
            "title": "ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass",
            "kev_present": False,
            "exploit_maturity": "UNPROVEN",
            "cvss_score": None,
        }
        html = _narrative_zero_day(item)
        assert "active exploitation confirmed" not in html
        assert "has not independently confirmed active exploitation" in html

    def test_no_confirmed_exploitation_claim_with_legacy_kev_no_string(self):
        """kev:'NO' (legacy string) must not be misread as KEV-confirmed."""
        item = {
            "title": "Zero-Day Vulnerability in Example Widget",
            "kev": "NO",
            "exploit_maturity": "POC",
        }
        html = _narrative_zero_day(item)
        assert "active exploitation confirmed" not in html


# ─── Executive summary CLS_ZERO_DAY intro ──────────────────────────────────

class TestExecutiveSummaryZeroDayGrounding:
    # classify_intelligence() only consults _TIER2_CVE_PATTERNS (which is
    # where the zero-day classification lives) when a CVE id is present in
    # the title/description -- so these fixtures must include one, exactly
    # like the real live regression (CVE-2026-50656).
    def test_confirmed_claim_present_with_kev(self):
        item = {
            "title": "CVE-2026-50656: Zero-Day RCE in Example Product",
            "description": "",
            "severity": "CRITICAL",
            "kev_present": True,
        }
        summary = generate_context_aware_executive_summary(item)
        assert "active exploitation confirmed" in summary

    def test_no_confirmed_claim_without_evidence(self):
        item = {
            "title": "CVE-2026-50656: Zero-Day RCE in Example Product",
            "description": "",
            "severity": "HIGH",
            "kev_present": False,
            "exploit_maturity": "UNPROVEN",
        }
        summary = generate_context_aware_executive_summary(item)
        assert "active exploitation confirmed" not in summary
        assert "has not been independently confirmed" in summary


# ─── exploit_maturity: FUNCTIONAL/POC must be evidence-only ────────────────

class TestExploitMaturityEvidenceOnly:
    def test_kev_yields_weaponized(self):
        item = {"kev": "YES", "cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "WEAPONIZED"

    def test_kev_present_true_yields_weaponized_with_no_legacy_field(self):
        """CodeRabbit-flagged regression: a clean kev_present:True with no
        legacy kev/KEV/cisa_kev string field must not fall through to
        UNPROVEN."""
        item = {"kev_present": True, "cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "WEAPONIZED"

    def test_kev_present_false_overrides_disagreeing_legacy_kev_string(self):
        """CodeRabbit-flagged regression: kev_present:False (the
        authoritative boolean) must override a stale/wrong legacy kev:"YES"
        string, not get promoted to WEAPONIZED."""
        item = {"kev_present": False, "kev": "YES", "cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "UNPROVEN"

    def test_metasploit_module_yields_functional(self):
        item = {"cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 0}, {"CVE-2026-1"}) == "FUNCTIONAL"

    def test_github_poc_yields_poc(self):
        item = {"cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 3}, set()) == "POC"

    def test_high_epss_alone_does_not_yield_functional(self):
        """The exact regression: EPSS is a probability signal, not exploit-
        code evidence. A 90% EPSS score with zero real exploit-code evidence
        must not be labeled FUNCTIONAL."""
        item = {"cve_ids": ["CVE-2026-1"], "epss_score": 0.90}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "UNPROVEN"

    def test_moderate_epss_alone_does_not_yield_poc(self):
        item = {"cve_ids": ["CVE-2026-1"], "epss_score": 0.25}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "UNPROVEN"

    def test_no_evidence_at_all_yields_unproven(self):
        item = {"cve_ids": ["CVE-2026-1"]}
        assert _determine_maturity(item, {"poc_count": 0}, set()) == "UNPROVEN"

    def test_kev_takes_precedence_over_other_evidence(self):
        item = {"kev": "YES", "cve_ids": ["CVE-2026-1"], "epss_score": 0.90}
        assert _determine_maturity(item, {"poc_count": 5}, {"CVE-2026-1"}) == "WEAPONIZED"
