#!/usr/bin/env python3
"""
scripts/exposure_intel_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Commercial Source Enrichment Engine v1.0.0
==============================================================================
Credential-gated connector layer for the 15 registry sources that are BOTH
licensing_class=COMMERCIAL_LICENSED AND access_type=FREE_REGISTRATION -- i.e.
the sources this platform may lawfully use in a commercially sold product,
each of which needs only a free API key.

WHY THIS FILE EXISTS
--------------------
data/registry/source_registry.json marked 25 sources REQUIRES_CREDENTIALS
("would work today if a free/paid API key were supplied"). For 24 of them
that was not true: no adapter existed, so a key would have activated nothing
(see source_fabric_health.py:_compute_reason_code). This module is the
missing adapter layer for the 15 of those 25 that are commercially usable.

The remaining 10 REQUIRES_CREDENTIALS sources are licensing_class=
FREE_NONCOMMERCIAL (abuse.ch x3, AbuseIPDB, PhishTank, AlienVault OTX,
Malpedia, IBM X-Force, urlscan.io, LeakIX). They are DELIBERATELY ABSENT
from this file. This platform is sold commercially (Razorpay / Gumroad), and
p40_production_certification.py G21 fails the build if a FREE_NONCOMMERCIAL
source is ever flagged commercially usable. Do not add them here.

WHAT THESE SOURCES ACTUALLY ARE
-------------------------------
None of the 15 is a bulk threat feed. Every one is a LOOKUP API -- you ask it
about an indicator or a CVE and it answers. The registry's own notes say so
("best modeled as ENRICHMENT once activated, not an event stream"). So this
module does NOT add feed items; it deepens the items already there, which is
what the platform's intelligence-depth gap actually needs.

Two capability classes, declared per adapter:

  CVE_EXPOSURE      Answers "how many hosts on the internet are currently
                    exposed to this CVE?" -- a CVE-keyed query. Directly
                    applicable to this feed, which is CVE-dominated, and
                    turns a CVE advisory into exposure intelligence.

  INDICATOR_LOOKUP  Answers questions about an IP / domain / file hash.
                    Implemented and wired, but yields nothing until feed
                    items carry such indicators (IOC coverage was 4.6% when
                    this module was written). They activate on their own as
                    IOC coverage rises -- no code change needed.

SAFETY / COST CONTRACT
----------------------
  * INERT WITHOUT A KEY. An adapter whose env var is unset is skipped with a
    log line and never contacted -- the same contract as
    true_intel_ingestor.py:ingest_urlhaus. With no keys configured this
    entire module is a no-op, which is exactly its state on merge.
  * BUDGETED. MAX_LOOKUPS caps total outbound calls per run, so enabling a
    key can never produce an unbounded API spend or rate-limit ban.
  * Runs in GitHub Actions, not in a Cloudflare Worker, so it consumes no
    Cloudflare request/CPU quota and cannot affect the Cloudflare plan
    budget. It writes only to api/feed.json plus one telemetry file.
  * DEFENSIVE PARSING. Response shapes are read through a list of candidate
    paths and any unrecognised shape yields None (recorded as
    unrecognised_shape telemetry) rather than a crash or a fabricated value.
    No adapter's response shape has been validated against its live API --
    see VERIFIED_SHAPES below.

ENV
  FEED_PATH      -- override feed path (default: api/feed.json)
  MAX_LOOKUPS    -- max outbound calls this run (default: 200)
  DRY_RUN=true   -- compute and log, write nothing
  <PER-ADAPTER>  -- see credential_env on each adapter below
"""
from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EXPOSURE-INTEL] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("EXPOSURE-INTEL")

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO_ROOT / "api" / "feed.json")))
TELEMETRY = REPO_ROOT / "data" / "telemetry" / "exposure_intel_enrichment.json"

MAX_LOOKUPS = int(os.environ.get("MAX_LOOKUPS", "200"))
DRY_RUN = os.environ.get("DRY_RUN", "").lower() == "true"
HTTP_TIMEOUT = 12

# Capability classes -- see module docstring.
CVE_EXPOSURE = "CVE_EXPOSURE"
INDICATOR_LOOKUP = "INDICATOR_LOOKUP"

# No adapter's response shape has been confirmed against its live API from
# this environment (no credentials are held here). The first real run logs
# `unrecognised_shape` for any adapter whose parser does not match, which is
# the signal to correct that adapter's extractor -- it never fabricates a
# value and never blocks the pipeline. Add a source_id here once its shape
# has been confirmed against production.
VERIFIED_SHAPES: set = set()


def _first_present(payload: Any, paths: List[List[str]]) -> Optional[int]:
    """Read the first candidate path that resolves to a non-negative int.

    Each path is a list of keys walked in order. Returns None when no path
    resolves -- callers treat that as "unrecognised shape", never as zero,
    so a parser mismatch can never be published as a real "0 hosts exposed".
    """
    for path in paths:
        cur = payload
        ok = True
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if not ok:
            continue
        if isinstance(cur, bool):
            continue
        if isinstance(cur, int) and cur >= 0:
            return cur
        if isinstance(cur, str) and cur.isdigit():
            return int(cur)
        if isinstance(cur, list):
            return len(cur)
    return None


class Adapter:
    """One commercial source. Declarative: what to call, how to authenticate,
    and how to read a count out of the answer."""

    def __init__(
        self,
        source_id: str,
        capability: str,
        credential_env: str,
        build_request: Callable[[str, Dict[str, str]], Optional[tuple]],
        extract: Callable[[Any], Optional[int]],
        extra_env: Optional[List[str]] = None,
        note: str = "",
    ):
        self.source_id = source_id
        self.capability = capability
        self.credential_env = credential_env
        self.build_request = build_request
        self.extract = extract
        self.extra_env = extra_env or []
        self.note = note

    def credentials(self) -> Optional[Dict[str, str]]:
        """All required env vars, or None if any are missing (=> inert)."""
        creds = {}
        for name in [self.credential_env] + self.extra_env:
            val = os.environ.get(name, "").strip()
            if not val:
                return None
            creds[name] = val
        return creds


# ---------------------------------------------------------------------------
# CVE_EXPOSURE adapters -- "how many hosts are exposed to this CVE"
# ---------------------------------------------------------------------------

def _shodan_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"query": f"vuln:{cve}", "key": c["SHODAN_API_KEY"]})
    return (f"https://api.shodan.io/shodan/host/count?{q}", {})


def _censys_req(cve: str, c: Dict[str, str]):
    token = base64.b64encode(
        f"{c['CENSYS_API_ID']}:{c['CENSYS_API_SECRET']}".encode()
    ).decode()
    q = urllib.parse.urlencode({"q": cve, "per_page": 1})
    return (
        f"https://search.censys.io/api/v2/hosts/search?{q}",
        {"Authorization": f"Basic {token}"},
    )


def _zoomeye_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"query": f'cve:"{cve}"', "page": 1})
    return (f"https://api.zoomeye.org/host/search?{q}", {"API-KEY": c["ZOOMEYE_API_KEY"]})


def _fofa_req(cve: str, c: Dict[str, str]):
    qb64 = base64.b64encode(f'cve="{cve}"'.encode()).decode()
    q = urllib.parse.urlencode(
        {"email": c["FOFA_EMAIL"], "key": c["FOFA_API_KEY"], "qbase64": qb64, "size": 1}
    )
    return (f"https://fofa.info/api/v1/search/all?{q}", {})


def _binaryedge_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"query": cve, "page": 1})
    return (
        f"https://api.binaryedge.io/v2/query/search?{q}",
        {"X-Key": c["BINARYEDGE_API_KEY"]},
    )


def _netlas_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"q": cve})
    return (
        f"https://app.netlas.io/api/responses_count/?{q}",
        {"X-API-Key": c["NETLAS_API_KEY"]},
    )


def _criminalip_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"query": cve, "offset": 0})
    return (
        f"https://api.criminalip.io/v1/banner/search?{q}",
        {"x-api-key": c["CRIMINALIP_API_KEY"]},
    )


def _onyphe_req(cve: str, c: Dict[str, str]):
    q = urllib.parse.urlencode({"q": f"cve:{cve}"})
    return (
        f"https://www.onyphe.io/api/v2/search?{q}",
        {"Authorization": f"apikey {c['ONYPHE_API_KEY']}"},
    )


ADAPTERS: List[Adapter] = [
    Adapter("shodan", CVE_EXPOSURE, "SHODAN_API_KEY", _shodan_req,
            lambda p: _first_present(p, [["total"], ["matches"]]),
            note="host/count is the cheapest Shodan call -- no result bodies."),
    Adapter("censys", CVE_EXPOSURE, "CENSYS_API_ID", _censys_req,
            lambda p: _first_present(p, [["result", "total"], ["result", "hits"]]),
            extra_env=["CENSYS_API_SECRET"],
            note="Censys v2 uses HTTP basic auth: API ID + secret, not one key."),
    Adapter("zoomeye", CVE_EXPOSURE, "ZOOMEYE_API_KEY", _zoomeye_req,
            lambda p: _first_present(p, [["total"], ["matches"]])),
    Adapter("fofa", CVE_EXPOSURE, "FOFA_API_KEY", _fofa_req,
            lambda p: _first_present(p, [["size"], ["results"]]),
            extra_env=["FOFA_EMAIL"],
            note="FOFA authenticates with email + key and base64-encodes the query."),
    Adapter("binaryedge", CVE_EXPOSURE, "BINARYEDGE_API_KEY", _binaryedge_req,
            lambda p: _first_present(p, [["total"], ["events"]])),
    Adapter("netlas", CVE_EXPOSURE, "NETLAS_API_KEY", _netlas_req,
            lambda p: _first_present(p, [["count"], ["total"]])),
    Adapter("criminalip", CVE_EXPOSURE, "CRIMINALIP_API_KEY", _criminalip_req,
            lambda p: _first_present(p, [["data", "result_count"], ["data", "count"]])),
    Adapter("onyphe", CVE_EXPOSURE, "ONYPHE_API_KEY", _onyphe_req,
            lambda p: _first_present(p, [["total"], ["count"], ["results"]])),

    # -----------------------------------------------------------------------
    # INDICATOR_LOOKUP adapters -- keyed on an IP / domain / file hash, not a
    # CVE. Declared and credential-gated now so that activation is purely a
    # matter of supplying the key once feed items carry indicators. They are
    # not invoked by this module's CVE pass; see run() and the module
    # docstring. IOC coverage was 4.6% when this was written.
    # -----------------------------------------------------------------------
    Adapter("greynoise_community", INDICATOR_LOOKUP, "GREYNOISE_API_KEY",
            lambda ind, c: (f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ind)}",
                            {"key": c["GREYNOISE_API_KEY"]}),
            lambda p: _first_present(p, [["classification"]]),
            note="Community tier is lookup-by-IP only."),
    Adapter("virustotal", INDICATOR_LOOKUP, "VIRUSTOTAL_API_KEY",
            lambda ind, c: (f"https://www.virustotal.com/api/v3/search?"
                            f"{urllib.parse.urlencode({'query': ind})}",
                            {"x-apikey": c["VIRUSTOTAL_API_KEY"]}),
            lambda p: _first_present(p, [["data"]]),
            note="Free tier is rate-limited lookup (4/min), not a bulk feed."),
    Adapter("securitytrails", INDICATOR_LOOKUP, "SECURITYTRAILS_API_KEY",
            lambda ind, c: (f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(ind)}",
                            {"APIKEY": c["SECURITYTRAILS_API_KEY"]}),
            lambda p: _first_present(p, [["current_dns", "a", "values"]])),
    Adapter("whoisxmlapi", INDICATOR_LOOKUP, "WHOISXMLAPI_KEY",
            lambda ind, c: (f"https://www.whoisxmlapi.com/whoisserver/WhoisService?"
                            f"{urllib.parse.urlencode({'apiKey': c['WHOISXMLAPI_KEY'], 'domainName': ind, 'outputFormat': 'JSON'})}",
                            {}),
            lambda p: _first_present(p, [["WhoisRecord", "estimatedDomainAge"]])),
    Adapter("dnslytics", INDICATOR_LOOKUP, "DNSLYTICS_API_KEY",
            lambda ind, c: (f"https://api.dnslytics.net/v1/ip2asn/{urllib.parse.quote(ind)}?"
                            f"{urllib.parse.urlencode({'apikey': c['DNSLYTICS_API_KEY']})}",
                            {}),
            lambda p: _first_present(p, [["data", "asn"]])),
    Adapter("anyrun", INDICATOR_LOOKUP, "ANYRUN_API_KEY",
            lambda ind, c: (f"https://api.any.run/v1/analysis?"
                            f"{urllib.parse.urlencode({'search': ind})}",
                            {"Authorization": f"API-Key {c['ANYRUN_API_KEY']}"}),
            lambda p: _first_present(p, [["data", "tasks"]])),
    Adapter("hybrid_analysis", INDICATOR_LOOKUP, "HYBRID_ANALYSIS_API_KEY",
            lambda ind, c: ("https://www.hybrid-analysis.com/api/v2/search/hash",
                            {"api-key": c["HYBRID_ANALYSIS_API_KEY"],
                             "User-Agent": "Falcon Sandbox"}),
            lambda p: _first_present(p, [["count"], ["result"]])),
]


def _http_json(url: str, headers: Dict[str, str]) -> Optional[Any]:
    """GET -> parsed JSON, or None on any transport/parse failure.

    Never raises: an enrichment source being down, rate-limiting us, or
    rejecting our key must degrade this run, not fail the pipeline.
    """
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        log.warning("HTTP %s from %s", e.code, urllib.parse.urlsplit(url).netloc)
    except Exception as e:  # noqa: BLE001 - deliberately total
        log.warning("request failed (%s): %s", urllib.parse.urlsplit(url).netloc, e)
    return None


def _cve_of(item: Dict) -> Optional[str]:
    """Primary CVE id for an item, via the canonical accessor when available."""
    try:
        import sys
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from p38_shared_validators import get_cve_ids  # type: ignore
        ids = get_cve_ids(item)
        return ids[0] if ids else None
    except Exception:
        for key in ("cve_id", "cve_ids", "cves"):
            v = item.get(key)
            if isinstance(v, str) and v.startswith("CVE-"):
                return v
            if isinstance(v, list) and v and isinstance(v[0], str):
                return v[0]
    return None


def active_adapters(capability: str) -> List[Adapter]:
    """Adapters of `capability` whose credentials are fully present."""
    out = []
    for a in ADAPTERS:
        if a.capability != capability:
            continue
        if a.credentials() is None:
            continue
        out.append(a)
    return out


def enrich_items(items: List[Dict], http=_http_json, budget: Optional[int] = None) -> Dict[str, Any]:
    """Attach exposure_intel to CVE-bearing items. Returns telemetry.

    `http` is injectable so the unit tests exercise every adapter's request
    construction and response parsing without network access or credentials.
    """
    budget = MAX_LOOKUPS if budget is None else budget
    adapters = active_adapters(CVE_EXPOSURE)
    telemetry: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "engine_version": "1.0.0",
        "adapters_total": len([a for a in ADAPTERS if a.capability == CVE_EXPOSURE]),
        "adapters_active": [a.source_id for a in adapters],
        "indicator_adapters_active": [a.source_id for a in active_adapters(INDICATOR_LOOKUP)],
        "calls": 0,
        "items_enriched": 0,
        "unrecognised_shape": {},
    }
    if not adapters:
        log.info("no CVE_EXPOSURE adapter has credentials configured -- no-op. "
                 "Set any of: %s",
                 ", ".join(a.credential_env for a in ADAPTERS if a.capability == CVE_EXPOSURE))
        return telemetry

    budget_spent = False
    for item in items:
        if budget_spent:
            break
        cve = _cve_of(item)
        if not cve:
            continue
        per_source: Dict[str, Any] = {}
        for a in adapters:
            if telemetry["calls"] >= budget:
                log.warning("MAX_LOOKUPS budget (%d) reached -- stopping this run; "
                            "remaining items keep their existing values", budget)
                telemetry["budget_exhausted"] = True
                budget_spent = True
                break
            creds = a.credentials()
            if creds is None:
                continue
            built = a.build_request(cve, creds)
            if not built:
                continue
            url, headers = built
            telemetry["calls"] += 1
            payload = http(url, headers)
            if payload is None:
                continue
            count = a.extract(payload)
            if count is None:
                telemetry["unrecognised_shape"][a.source_id] = (
                    telemetry["unrecognised_shape"].get(a.source_id, 0) + 1
                )
                continue
            per_source[a.source_id] = count
        if per_source:
            item["exposure_intel"] = per_source
            item["exposure_hosts_total"] = max(per_source.values())
            item["exposure_sources_count"] = len(per_source)
            item["exposure_queried_at"] = telemetry["generated_at"]
            telemetry["items_enriched"] += 1
    return telemetry


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run() -> int:
    if not FEED_PATH.exists():
        log.warning("feed not found at %s -- nothing to enrich", FEED_PATH)
        return 0

    raw = FEED_PATH.read_bytes().rstrip(b"\x00")
    data = json.loads(raw)
    items = data if isinstance(data, list) else data.get("items", data.get("threats", []))
    log.info("loaded %d feed items from %s", len(items), FEED_PATH)

    configured = [a.source_id for a in ADAPTERS if a.credentials() is not None]
    log.info("%d/%d commercial adapters have credentials: %s",
             len(configured), len(ADAPTERS), ", ".join(configured) or "(none)")

    telemetry = enrich_items(items)
    telemetry["feed_items"] = len(items)
    telemetry["dry_run"] = DRY_RUN

    unrec = telemetry.get("unrecognised_shape") or {}
    if unrec:
        # A shape mismatch is an adapter bug to correct, not a data problem:
        # the value is dropped rather than guessed. See VERIFIED_SHAPES.
        log.warning("unrecognised response shape from: %s -- these adapters "
                    "returned data this parser does not understand; no value "
                    "was recorded for them", ", ".join(sorted(unrec)))

    if DRY_RUN:
        log.info("DRY_RUN -- not writing. telemetry=%s", json.dumps(telemetry))
        return 0

    if telemetry["items_enriched"]:
        _atomic_write(FEED_PATH, data)
        log.info("enriched %d items with exposure intelligence from %d source(s)",
                 telemetry["items_enriched"], len(telemetry["adapters_active"]))
    else:
        log.info("no items enriched -- feed left byte-identical")

    _atomic_write(TELEMETRY, telemetry)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
