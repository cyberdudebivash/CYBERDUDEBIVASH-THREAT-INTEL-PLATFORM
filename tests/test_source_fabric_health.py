"""
tests/test_source_fabric_health.py — CyberDudeBivash SENTINEL APEX
Unit tests for the reason_code/state additions to
scripts/source_fabric_health.py: the additive vocabulary
(LIVE/LIVE_DEGRADED/STALE/FAILING/AUTH_FAILURE/CREDENTIAL_REQUIRED/...)
and per-source reason codes (OK/ZERO_OUTPUT/HTTP_403/NO_RECENT_DATA/...)
that let a WAF block (e.g. CISA's confirmed live 403) surface distinctly
from generic staleness, without changing the existing health_status field
any current consumer (dashboard, P40 certification, handleP40SourceHealth)
already depends on.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import source_fabric_health as sfh  # noqa: E402


class TestConnectorAwareReasonCode:
    """REQUIRES_CREDENTIALS collapses two very different blockers together:
    a wired adapter that genuinely needs only an API key, and a source with
    no adapter at all where a key would change nothing. These cover the
    has_connector parameter that keeps the derived reason_code from
    discarding the connector_ref/integration_mode ground truth."""

    def test_requires_credentials_without_connector_is_not_credential_required(self):
        # The 24-of-25 case: no adapter, so a key alone activates nothing.
        assert sfh._compute_reason_code(
            "REQUIRES_CREDENTIALS", "AWAITING_CREDENTIALS", None, False
        ) == "CONNECTOR_NOT_IMPLEMENTED"

    def test_requires_credentials_with_connector_stays_credential_required(self):
        # The abuse_ch_urlhaus case: wired into the live pipeline, genuinely
        # one API key away from delivering.
        assert sfh._compute_reason_code(
            "REQUIRES_CREDENTIALS", "AWAITING_CREDENTIALS", None, True
        ) == "CREDENTIAL_REQUIRED"

    def test_has_connector_defaults_to_true_for_legacy_callers(self):
        # Backward compatibility: the pre-existing 3-argument call signature
        # must keep its exact previous behaviour.
        assert sfh._compute_reason_code(
            "REQUIRES_CREDENTIALS", "AWAITING_CREDENTIALS", None
        ) == "CREDENTIAL_REQUIRED"

    def test_missing_connector_only_affects_requires_credentials(self):
        # has_connector must not leak into unrelated statuses.
        assert sfh._compute_reason_code(
            "REQUIRES_LICENSE", "AWAITING_LICENSE", None, False
        ) == "LICENSE_REQUIRED"
        assert sfh._compute_reason_code(
            "PLANNED", "NOT_APPLICABLE", None, False
        ) == "NOT_YET_IMPLEMENTED"
        assert sfh._compute_reason_code("ACTIVE", "HEALTHY", None, False) == "OK"

    def test_connector_not_implemented_maps_to_its_own_state(self):
        assert sfh._compute_state(
            "AWAITING_CREDENTIALS", "CONNECTOR_NOT_IMPLEMENTED"
        ) == "CONNECTOR_REQUIRED"

    def test_credential_required_state_unchanged(self):
        assert sfh._compute_state(
            "AWAITING_CREDENTIALS", "CREDENTIAL_REQUIRED"
        ) == "CREDENTIAL_REQUIRED"


class TestComputeReasonCode:
    def test_requires_credentials_status(self):
        assert sfh._compute_reason_code("REQUIRES_CREDENTIALS", "AWAITING_CREDENTIALS", None) == "CREDENTIAL_REQUIRED"

    def test_requires_license_status(self):
        assert sfh._compute_reason_code("REQUIRES_LICENSE", "AWAITING_LICENSE", None) == "LICENSE_REQUIRED"

    def test_disabled_status(self):
        assert sfh._compute_reason_code("DISABLED", "DISABLED", None) == "DISABLED_BY_CONFIG"

    def test_planned_status(self):
        assert sfh._compute_reason_code("PLANNED", "NOT_APPLICABLE", None) == "NOT_YET_IMPLEMENTED"

    def test_implemented_not_running(self):
        assert sfh._compute_reason_code("IMPLEMENTED", "NOT_RUNNING", None) == "NOT_ENABLED"

    def test_active_healthy(self):
        assert sfh._compute_reason_code("ACTIVE", "HEALTHY", None) == "OK"

    def test_active_no_data_without_fs_reason_defaults_zero_output(self):
        assert sfh._compute_reason_code("ACTIVE", "NO_DATA", None) == "ZERO_OUTPUT"

    def test_active_no_data_with_fs_reason_prefers_it(self):
        assert sfh._compute_reason_code("ACTIVE", "NO_DATA", "HTTP_429") == "HTTP_429"

    def test_active_stale_without_fs_reason_defaults_no_recent_data(self):
        assert sfh._compute_reason_code("ACTIVE", "STALE", None) == "NO_RECENT_DATA"

    def test_active_stale_with_ok_fs_reason_still_defaults(self):
        """A feed_state entry that says the LAST fetch was OK but the source
        is STALE (i.e. nothing NEW came through) must not report 'OK' as
        the reason for being stale -- that would be self-contradictory."""
        assert sfh._compute_reason_code("ACTIVE", "STALE", "OK") == "NO_RECENT_DATA"

    def test_active_stale_with_http_403_surfaces_it(self):
        """The exact case this change fixes: CISA advisories RSS blocked
        by Akamai (confirmed live 403), previously indistinguishable from
        any other stale source."""
        assert sfh._compute_reason_code("ACTIVE", "STALE", "HTTP_403") == "HTTP_403"


class TestComputeState:
    def test_healthy_maps_to_live(self):
        assert sfh._compute_state("HEALTHY", "OK") == "LIVE"

    def test_no_data_maps_to_live_degraded(self):
        assert sfh._compute_state("NO_DATA", "ZERO_OUTPUT") == "LIVE_DEGRADED"

    def test_stale_with_no_recent_data_stays_stale(self):
        assert sfh._compute_state("STALE", "NO_RECENT_DATA") == "STALE"

    def test_stale_with_auth_failure_upgrades_to_auth_failure(self):
        assert sfh._compute_state("STALE", "AUTH_FAILURE") == "AUTH_FAILURE"

    def test_stale_with_http_403_upgrades_to_failing(self):
        assert sfh._compute_state("STALE", "HTTP_403") == "FAILING"

    def test_stale_with_network_timeout_upgrades_to_failing(self):
        assert sfh._compute_state("STALE", "NETWORK_TIMEOUT") == "FAILING"

    def test_awaiting_credentials_maps_correctly(self):
        assert sfh._compute_state("AWAITING_CREDENTIALS", "CREDENTIAL_REQUIRED") == "CREDENTIAL_REQUIRED"

    def test_awaiting_license_maps_correctly(self):
        assert sfh._compute_state("AWAITING_LICENSE", "LICENSE_REQUIRED") == "LICENSE_REQUIRED"

    def test_not_running_maps_to_implemented_not_enabled(self):
        assert sfh._compute_state("NOT_RUNNING", "NOT_ENABLED") == "IMPLEMENTED_NOT_ENABLED"

    def test_not_applicable_maps_to_planned(self):
        assert sfh._compute_state("NOT_APPLICABLE", "NOT_YET_IMPLEMENTED") == "PLANNED"

    def test_disabled_maps_to_disabled(self):
        assert sfh._compute_state("DISABLED", "DISABLED_BY_CONFIG") == "DISABLED"

    def test_unknown_health_falls_back_safely(self):
        assert sfh._compute_state("SOME_FUTURE_UNMAPPED_VALUE", "OK") == "UNKNOWN"


class TestFeedStateReasonCodeLookup:
    def test_direct_key_lookup(self):
        feed_state_sources = {"cisa_kev": {"last_reason_code": "OK"}}
        assert sfh._feed_state_reason_code("cisa_kev", feed_state_sources) == "OK"

    def test_missing_key_returns_none(self):
        assert sfh._feed_state_reason_code("nvd_cve", {}) is None

    def test_rss_sentinel_resolves_to_newest_matching_entry(self):
        feed_state_sources = {
            "rss_www_cisa_gov_cybersecurity_advisories_all_xml": {
                "last_seen": "2026-06-18T12:00:00Z",
                "last_reason_code": "HTTP_403",
            },
        }
        assert sfh._feed_state_reason_code("rss:cisa.gov", feed_state_sources) == "HTTP_403"

    def test_rss_sentinel_no_match_returns_none(self):
        feed_state_sources = {"rss_unrelated_feed": {"last_seen": "2026-06-18T12:00:00Z"}}
        assert sfh._feed_state_reason_code("rss:cisa.gov", feed_state_sources) is None


class TestComputeHealthIntegration:
    """End-to-end: compute_health() actually attaches state + reason_code
    to every result entry, without dropping the pre-existing health_status
    field any current API/dashboard consumer depends on."""

    def test_every_result_has_state_and_reason_code_fields(self):
        report = sfh.compute_health()
        assert len(report["sources"]) > 0
        for entry in report["sources"]:
            assert "state" in entry
            assert "reason_code" in entry
            assert "health_status" in entry  # backward compatibility -- unchanged
            assert entry["state"] != ""
            assert entry["reason_code"] != ""
