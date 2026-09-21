"""
tests/test_exposure_intel_enricher.py — CYBERDUDEBIVASH SENTINEL APEX
Unit tests for scripts/exposure_intel_enricher.py, the credential-gated
connector layer for the 15 commercially-usable registry sources.

No network and no credentials are used. The HTTP transport is injected, so
every adapter's request construction (URL, auth header placement, query
encoding) and response parsing is exercised deterministically.

The single most important property under test is the SAFETY CONTRACT: with
no credentials configured the module must be a complete no-op and must never
contact anything. That is its state on merge.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import exposure_intel_enricher as eie  # noqa: E402


def _clear_creds():
    for a in eie.ADAPTERS:
        for name in [a.credential_env] + a.extra_env:
            os.environ.pop(name, None)


def _set(adapter):
    for name in [adapter.credential_env] + adapter.extra_env:
        os.environ[name] = "TEST_KEY_VALUE"


class TestInertWithoutCredentials:
    def test_no_adapter_active_when_no_env_set(self):
        _clear_creds()
        assert eie.active_adapters(eie.CVE_EXPOSURE) == []
        assert eie.active_adapters(eie.INDICATOR_LOOKUP) == []

    def test_enrich_makes_zero_calls_without_credentials(self):
        _clear_creds()
        calls = []

        def spy(url, headers):
            calls.append(url)
            return {"total": 5}

        items = [{"cve_id": "CVE-2026-1111"}]
        tel = eie.enrich_items(items, http=spy)
        assert calls == [], "module must contact nothing without credentials"
        assert tel["calls"] == 0
        assert tel["items_enriched"] == 0
        assert "exposure_intel" not in items[0]

    def test_partial_credentials_keep_adapter_inert(self):
        # Censys needs API ID *and* secret; FOFA needs key *and* email.
        _clear_creds()
        for sid, primary in (("censys", "CENSYS_API_ID"), ("fofa", "FOFA_API_KEY")):
            os.environ[primary] = "only-half"
            a = next(x for x in eie.ADAPTERS if x.source_id == sid)
            assert a.credentials() is None, f"{sid} must stay inert on partial creds"
            os.environ.pop(primary, None)


class TestAdapterRegistry:
    def test_fifteen_commercial_adapters_declared(self):
        assert len(eie.ADAPTERS) == 15

    def test_no_noncommercial_source_is_present(self):
        # These are licensing_class=FREE_NONCOMMERCIAL. Including any of them
        # in a commercially sold product violates their terms and fails
        # p40_production_certification.py G21.
        forbidden = {
            "abuse_ch_urlhaus", "abuse_ch_threatfox", "abuse_ch_malwarebazaar",
            "abuseipdb", "phishtank", "alienvault_otx", "malpedia",
            "ibm_xforce", "urlscan_io", "leakix",
        }
        assert {a.source_id for a in eie.ADAPTERS} & forbidden == set()

    def test_every_adapter_has_a_known_capability(self):
        for a in eie.ADAPTERS:
            assert a.capability in (eie.CVE_EXPOSURE, eie.INDICATOR_LOOKUP)

    def test_adapter_ids_are_unique(self):
        ids = [a.source_id for a in eie.ADAPTERS]
        assert len(ids) == len(set(ids))


class TestRequestConstruction:
    def test_every_adapter_builds_a_request_with_its_credential(self):
        _clear_creds()
        for a in eie.ADAPTERS:
            _set(a)
            creds = a.credentials()
            assert creds is not None
            url, headers = a.build_request("CVE-2026-1234", creds)
            assert url.startswith("https://"), f"{a.source_id} must use https"
            blob = url + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
            # Censys base64-encodes "id:secret" into an HTTP basic auth
            # header, so the credential is present but not literal.
            import base64 as _b64
            encoded = _b64.b64encode(b"TEST_KEY_VALUE").decode().rstrip("=")
            assert ("TEST_KEY_VALUE" in blob) or (encoded[:12] in blob), (
                f"{a.source_id} does not transmit its credential"
            )
            _clear_creds()

    def test_cve_reaches_the_query_for_exposure_adapters(self):
        _clear_creds()
        for a in eie.ADAPTERS:
            if a.capability != eie.CVE_EXPOSURE:
                continue
            _set(a)
            url, _ = a.build_request("CVE-2026-1234", a.credentials())
            # FOFA base64-encodes its query, so the raw id is absent by design.
            if a.source_id != "fofa":
                assert "CVE-2026-1234" in urllib_unquote(url), (
                    f"{a.source_id} must query the CVE"
                )
            _clear_creds()

    def test_secrets_never_appear_in_logged_netloc(self):
        # _http_json logs only the netloc on failure, never the full URL,
        # because several adapters pass the key as a query parameter.
        _clear_creds()
        a = next(x for x in eie.ADAPTERS if x.source_id == "shodan")
        _set(a)
        url, _ = a.build_request("CVE-2026-1234", a.credentials())
        import urllib.parse
        assert "TEST_KEY_VALUE" not in urllib.parse.urlsplit(url).netloc
        _clear_creds()


def urllib_unquote(s):
    import urllib.parse
    return urllib.parse.unquote(s)


class TestResponseParsing:
    def test_each_exposure_adapter_parses_its_documented_shape(self):
        shapes = {
            "shodan":      {"total": 42},
            "censys":      {"result": {"total": 42}},
            "zoomeye":     {"total": 42},
            "fofa":        {"size": 42},
            "binaryedge":  {"total": 42},
            "netlas":      {"count": 42},
            "criminalip":  {"data": {"result_count": 42}},
            "onyphe":      {"total": 42},
        }
        for a in eie.ADAPTERS:
            if a.capability != eie.CVE_EXPOSURE:
                continue
            assert a.extract(shapes[a.source_id]) == 42, a.source_id

    def test_unrecognised_shape_yields_none_not_zero(self):
        # Critical: a parser mismatch must never be published as a real
        # "0 hosts exposed" -- that would be a fabricated intelligence claim.
        for a in eie.ADAPTERS:
            assert a.extract({"unexpected": "shape"}) is None, a.source_id
            assert a.extract([]) is None, a.source_id

    def test_list_payload_counts_length(self):
        assert eie._first_present({"matches": [1, 2, 3]}, [["matches"]]) == 3

    def test_numeric_string_is_coerced(self):
        assert eie._first_present({"total": "7"}, [["total"]]) == 7

    def test_bool_is_not_treated_as_a_count(self):
        assert eie._first_present({"total": True}, [["total"]]) is None

    def test_negative_count_rejected(self):
        assert eie._first_present({"total": -1}, [["total"]]) is None


class TestEnrichment:
    def test_enriches_cve_item_and_records_max(self):
        _clear_creds()
        shodan = next(a for a in eie.ADAPTERS if a.source_id == "shodan")
        netlas = next(a for a in eie.ADAPTERS if a.source_id == "netlas")
        _set(shodan)
        _set(netlas)

        def fake(url, headers):
            return {"total": 100} if "shodan" in url else {"count": 250}

        items = [{"cve_id": "CVE-2026-2222"}]
        tel = eie.enrich_items(items, http=fake)
        assert items[0]["exposure_intel"] == {"shodan": 100, "netlas": 250}
        assert items[0]["exposure_hosts_total"] == 250
        assert items[0]["exposure_sources_count"] == 2
        assert tel["items_enriched"] == 1
        _clear_creds()

    def test_item_without_cve_is_untouched(self):
        _clear_creds()
        _set(next(a for a in eie.ADAPTERS if a.source_id == "shodan"))
        items = [{"title": "generic news item"}]
        eie.enrich_items(items, http=lambda u, h: {"total": 9})
        assert "exposure_intel" not in items[0]
        _clear_creds()

    def test_budget_caps_outbound_calls(self):
        _clear_creds()
        _set(next(a for a in eie.ADAPTERS if a.source_id == "shodan"))
        calls = []
        items = [{"cve_id": f"CVE-2026-{i:04d}"} for i in range(50)]
        eie.enrich_items(items, http=lambda u, h: calls.append(u) or {"total": 1}, budget=5)
        assert len(calls) <= 5, "MAX_LOOKUPS budget must bound API spend"
        _clear_creds()

    def test_transport_failure_is_survived(self):
        _clear_creds()
        _set(next(a for a in eie.ADAPTERS if a.source_id == "shodan"))
        items = [{"cve_id": "CVE-2026-3333"}]
        tel = eie.enrich_items(items, http=lambda u, h: None)
        assert "exposure_intel" not in items[0]
        assert tel["items_enriched"] == 0
        _clear_creds()

    def test_unrecognised_shape_is_counted_in_telemetry(self):
        _clear_creds()
        _set(next(a for a in eie.ADAPTERS if a.source_id == "shodan"))
        items = [{"cve_id": "CVE-2026-4444"}]
        tel = eie.enrich_items(items, http=lambda u, h: {"weird": 1})
        assert tel["unrecognised_shape"].get("shodan") == 1
        assert "exposure_intel" not in items[0]
        _clear_creds()

    def test_indicator_adapters_do_not_run_in_the_cve_pass(self):
        _clear_creds()
        _set(next(a for a in eie.ADAPTERS if a.source_id == "greynoise_community"))
        calls = []
        items = [{"cve_id": "CVE-2026-5555"}]
        tel = eie.enrich_items(items, http=lambda u, h: calls.append(u) or {"total": 1})
        assert calls == [], "INDICATOR_LOOKUP adapters are not CVE-keyed"
        assert tel["indicator_adapters_active"] == ["greynoise_community"]
        _clear_creds()
