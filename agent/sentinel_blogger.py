#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash SENTINEL APEX v141.0 (R2-NATIVE / BLOGGER-FREE)
=======================================================================================
P0 FIX: Blogger completely removed. R2 is the ONLY output channel.
         Queue bomb neutralised: publish_queue no longer written.
         STIX bundle + manifest written directly on every entry processed.

VERSION HISTORY:
  v21.0  EPSS + CVSS enrichment, source_url fix, KEV lookup, NVD schema
  v77.1  kev_present initialised before use; confirmed_actor guard fixed
  v78.0  Temporal relevance gate; behavioural cap; confidence v47
  v134.0 Blogger DISABLED in env (BLOG_ID not passed in workflow)
  v134.0 P0 FIX — Blogger import removed entirely; queue bomb killed;
         manifest key bug fixed; direct R2-only STIX write path enforced
  v141.0 FIX-01 — FEED_SOURCE_MAP: resolve feed URLs to human-readable
         source names; eliminates UNKNOWN_SOURCE / truncated-URL in manifest
"""
import os
import re
import sys
import time
import json
import logging
import urllib.request
from typing import List, Dict, Optional

from agent.enricher import enricher
from agent.export_stix import stix_exporter
from agent.risk_engine import risk_engine
from agent.deduplication import dedup_engine
from agent.mitre_mapper import mitre_engine, sanitize_mitre_techniques
from agent.integrations.actor_matrix import actor_matrix
from agent.integrations.detection_engine import detection_engine
from agent.content.premium_report_generator import premium_report_gen
from agent.content.source_fetcher import source_fetcher
from agent.config import (
    CDB_RSS_FEED,
    RSS_FEEDS,
    MAX_ENTRIES_PER_FEED,
    RATE_LIMIT_DELAY,
    TELEMETRY_ENABLED,
    PREDICTIVE_ENABLED,
    CAMPAIGN_TRACKER_ENABLED,
)

# ==============================================================================
# FIX-01 v141.0 — FEED SOURCE NAME RESOLVER
# Root cause fix for source: "UNKNOWN_SOURCE" / truncated URL on ALL manifest
# entries. Maps feed URL substrings → human-readable publication names that
# are displayed in the SOC dashboard and API responses.
# ==============================================================================
_FEED_SOURCE_MAP = {
    # Tier 1 — Breaking News
    'feedburner.com/TheHackersNews':  'The Hacker News',
    'thehackernews':                  'The Hacker News',
    'krebsonsecurity':                'KrebsOnSecurity',
    'cybersecuritynews':              'CyberSecurity News',
    'therecord.media':                'The Record',
    'cyberscoop':                     'CyberScoop',
    'securityaffairs':                'Security Affairs',
    'darkreading':                    'Dark Reading',
    'securitymagazine':               'Security Magazine',
    'bleepingcomputer':               'BleepingComputer',
    # Tier 2 — Government / CERT
    'cisa.gov':                       'CISA',
    'us-cert.gov':                    'US-CERT',
    'cert.ssi.gouv.fr':               'ANSSI France',
    'ncsc.gov.uk':                    'NCSC UK',
    'cyber.gov.au':                   'ACSC Australia',
    'jpcert':                         'JPCERT/CC',
    'ncsc.nl':                        'NCSC Netherlands',
    # Tier 3 — CVE / Vulnerability
    'cvefeed.io':                     'CVE Feed',
    'vulners.com':                    'Vulners',
    'zerodayinitiative':              'Zero Day Initiative',
    'nvd.nist.gov':                   'NVD / NIST',
    # Tier 4 — Vendor Threat Research
    'sentinelone':                    'SentinelOne',
    'unit42.paloaltonetworks':        'Palo Alto Unit 42',
    'securelist':                     'Kaspersky SecureList',
    'crowdstrike':                    'CrowdStrike',
    'mandiant':                       'Mandiant',
    'microsoft.com/on-the-issues':    'Microsoft Security',
    'checkpoint':                     'Check Point Research',
    'sophos':                         'Sophos X-Ops',
    'securityintelligence':           'IBM Security Intelligence',
    'redcanary':                      'Red Canary',
    'elastic.co/security-labs':       'Elastic Security Labs',
    'nccgroup':                       'NCC Group Research',
    'rapid7':                         'Rapid7',
    'wordfence':                      'Wordfence',
    'welivesecurity':                 'ESET WeLiveSecurity',
    'feedburner.com/eset':            'ESET Research',
    'malwarebytes':                   'Malwarebytes',
    'huntress':                       'Huntress Labs',
    'any.run':                        'ANY.RUN',
    # Tier 5 — Deep Web / Research
    'seclists.org/rss/fulldisclosure': 'Full Disclosure',
    'seclists.org/rss/oss-sec':       'OSS-Security',
    'seclists':                       'SecLists',
    'portswigger':                    'PortSwigger Research',
    'googleprojectzero':              'Google Project Zero',
    'github.blog':                    'GitHub Security',
    'blog.cloudflare':                'Cloudflare Security',
    # Tier 6 — Cloud / Infra
    'aws.amazon.com/blogs/security':  'AWS Security Blog',
    'grahamcluley':                   'Graham Cluley',
    'helpnetsecurity':                'Help Net Security',
    'threatpost':                     'Threatpost',
    'recordedfuture':                 'Recorded Future',
    'isc.sans.edu':                   'SANS ISC',
    # CDB Own Feed
    'cyberdudebivash':                'CyberDudeBivash Intel',
}


def _resolve_feed_source_name(feed_url: str) -> str:
    """
    FIX-01: Resolve a feed URL to a human-readable publication name.
    Falls back to domain extraction if no map key matches.
    Never returns a truncated URL or empty string.
    """
    if not feed_url:
        return 'External Feed'
    url_lower = feed_url.lower()
    for key, name in _FEED_SOURCE_MAP.items():
        if key.lower() in url_lower:
            return name
    # Domain extraction fallback — always returns something meaningful
    try:
        import urllib.parse as _up
        parsed = _up.urlparse(feed_url)
        domain = (parsed.netloc or parsed.path).replace('www.', '').split('/')[0]
        return domain or 'External Feed'
    except Exception:
        return 'External Feed'

# -- Optional module imports - all wrapped, degrade gracefully ----------------

try:
    from agent.core.telemetry import telemetry as _telemetry
    _TELEMETRY_OK = TELEMETRY_ENABLED
except ImportError:
    _telemetry = None
    _TELEMETRY_OK = False

try:
    from agent.predictive.exploit_forecaster import exploit_forecaster as _forecaster
    from agent.predictive.risk_trend_model import risk_trend_model as _trend_model
    _PREDICTIVE_OK = PREDICTIVE_ENABLED
except ImportError:
    _forecaster = None
    _trend_model = None
    _PREDICTIVE_OK = False

try:
    from agent.threat_actor.campaign_tracker import campaign_tracker as _campaign_tracker
    from agent.threat_actor.actor_registry import actor_registry as _actor_registry
    _CAMPAIGN_OK = CAMPAIGN_TRACKER_ENABLED
except ImportError:
    _campaign_tracker = None
    _actor_registry = None
    _CAMPAIGN_OK = False

try:
    from agent.content.quality_gate import is_relevant_threat as _quality_gate
    _QUALITY_GATE_OK = True
except ImportError:
    _quality_gate = None
    _QUALITY_GATE_OK = False

try:
    from agent.v46_vanguard.vanguard_engine import vanguard_engine as _vanguard
    _VANGUARD_OK = True
except ImportError:
    _vanguard = None
    _VANGUARD_OK = False

try:
    from agent.telegram_alerts import send_threat_alert, send_pipeline_summary
    _TELEGRAM_OK = True
except ImportError:
    _TELEGRAM_OK = False
    def send_threat_alert(*a, **kw): pass
    def send_pipeline_summary(*a, **kw): pass

# -- OMEGA-P5: Persistent Campaign Memory Graph --------------------------------
try:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from scripts.persistent_campaign_graph_engine import (
        CampaignGraph,
        generate_campaign_graph_report,
        extract_top_active_campaigns,
        extract_actor_evolution_timeline,
    )
    _campaign_graph: Optional[CampaignGraph] = CampaignGraph()
    _CAMPAIGN_GRAPH_OK = True
except Exception as _cge:
    _campaign_graph = None
    _CAMPAIGN_GRAPH_OK = False
    CampaignGraph = None  # type: ignore

# -- Logging ------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-ENRICHER] %(message)s"
)
logger = logging.getLogger("CDB-ENRICHER")

# ==============================================================================
# FEED INGESTION ENGINE
# ==============================================================================

def fetch_feed_entries(feed_url: str, max_entries: int = 3) -> List[Dict]:
    """Fetch and normalise entries from a single RSS/Atom feed."""
    # v143.4.0: import encoding sanitizer — applied to all free-text fields at
    # ingestion boundary to eliminate mojibake from feedparser latin-1/cp1252
    # misreads before text enters the pipeline and gets persisted to manifest.
    try:
        from core.utils.encoding_utils import sanitize_field as _sanitize_field
    except ImportError:
        try:
            import sys as _sys_ef, os as _os_ef
            _repo_root_ef = _os_ef.path.dirname(_os_ef.path.dirname(_os_ef.path.abspath(__file__)))
            if _repo_root_ef not in _sys_ef.path:
                _sys_ef.path.insert(0, _repo_root_ef)
            from core.utils.encoding_utils import sanitize_field as _sanitize_field
        except ImportError:
            _sanitize_field = lambda x: x  # no-op fallback — never blocks pipeline

    try:
        import feedparser
        feed = feedparser.parse(feed_url)
        entries = []
        for entry in feed.entries[:max_entries]:
            content = ""
            if hasattr(entry, "content") and entry.content:
                content = entry.content[0].get("value", "")
            if not content and hasattr(entry, "description"):
                content = entry.description
            if not content and hasattr(entry, "summary"):
                content = entry.summary

            summary = ""
            if hasattr(entry, "summary") and entry.summary != content:
                summary = entry.summary

            # v143.4.0 FIX: sanitize all free-text fields at ingestion boundary.
            # feedparser can return cp1252/latin-1 mojibake when feed encoding is
            # misdetected (e.g. feed declares iso-8859-1 but sends UTF-8).
            # sanitize_field uses ftfy + correction table to fix double-encoding.
            raw_title = entry.get("title", "Untitled Advisory")
            entries.append({
                "title":     _sanitize_field(raw_title),
                "content":   _sanitize_field(content),
                "summary":   _sanitize_field(summary),
                "link":      entry.get("link", ""),
                "source":    feed_url,
                "published": entry.get("published", ""),
                "tags":      [t.get("term", "") for t in entry.get("tags", [])],
            })
        return entries
    except Exception as e:
        logger.warning(f"Feed fetch failed for {feed_url}: {e}")
        return []


# ==============================================================================
# SOURCE ARTICLE ENRICHMENT
# ==============================================================================

def enrich_with_source_content(entry: Dict) -> Optional[Dict]:
    """Fetch the full source article for deeper IOC extraction."""
    source_url = entry.get("link", "")
    if not source_url:
        return None
    try:
        logger.info(f"  -> Fetching source article: {source_url[:80]}...")
        fetched = source_fetcher.fetch_article(source_url)
        if fetched and fetched.get("fetch_status") == "success":
            logger.info(
                f"  -> Source fetched: {fetched.get('word_count', 0)} words, "
                f"{len(fetched.get('paragraphs', []))} paragraphs"
            )
            return fetched
        logger.warning(f"  -> Source fetch incomplete for: {source_url[:60]}")
    except Exception as e:
        logger.warning(f"  -> Source fetch error: {e}")
    return None


def build_enriched_content(entry: Dict, fetched_article: Optional[Dict]) -> str:
    """Combine RSS + full source article text."""
    parts = []
    if entry.get("content"):
        parts.append(entry["content"])
    if entry.get("summary"):
        parts.append(entry["summary"])
    if fetched_article and fetched_article.get("full_text"):
        parts.append(fetched_article["full_text"])
    return "\n\n".join(parts)


# ==============================================================================
# TEMPORAL RELEVANCE GATE (v78.0)
# ==============================================================================
from datetime import datetime, timezone as _tz

CVE_MAX_AGE_YEARS  = 2
# FIX: EPSS stored as percent 0–100 (×100 at fetch). Previous value 0.7
# treated it as 0–1 decimal, so 'epss >= 0.7' was always True for any CVE
# with EPSS > 0.7%, permanently bypassing temporal filtering.
CVE_EPSS_EXCEPTION = 70.0


def is_temporally_relevant(entry: dict) -> bool:
    """Reject stale CVEs (>2y old) unless KEV/EPSS exception applies."""
    title     = entry.get("title", "")
    cve_match = re.search(r'CVE-(\d{4})-', title)
    if not cve_match:
        return True

    cve_year    = int(cve_match.group(1))
    current_year = datetime.now(_tz.utc).year
    age_years   = current_year - cve_year

    if age_years <= CVE_MAX_AGE_YEARS:
        return True

    kev     = entry.get("kev_present", False)
    epss    = entry.get("epss_score") or 0.0
    # FIX v171.1: Added present-participle / gerund forms so titles like
    # "Attackers Actively Exploiting Critical Vulnerability in X" are correctly
    # detected as active-exploitation signals (was only matching past-tense).
    act_exp = any(s in title.lower() for s in [
        "actively exploited", "actively exploiting", "attackers actively exploit",
        "in the wild", "active exploitation", "exploited in the wild",
        "under active attack", "mass exploitation", "widespread exploitation",
        "weaponized", "zero-day exploit", "0-day exploit",
    ])

    if kev:
        logger.info(f"[TEMPORAL] Old CVE-{cve_year} passes — KEV confirmed")
        return True
    if epss >= CVE_EPSS_EXCEPTION:
        logger.info(f"[TEMPORAL] Old CVE-{cve_year} passes — EPSS={epss:.2f}")
        return True
    if act_exp:
        logger.info(f"[TEMPORAL] Old CVE-{cve_year} passes — active exploitation signal")
        return True

    logger.info(f"[TEMPORAL] SKIP stale CVE-{cve_year} (age={age_years}y, KEV={kev}, EPSS={epss:.3f})")
    return False


# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================

def main():
    logger.info("=" * 70)
    logger.info("SENTINEL APEX v134.0 — R2-NATIVE PIPELINE (BLOGGER-FREE)")
    logger.info("Multi-Feed Fusion | Quality Gate | IOC | STIX | MITRE | R2-Only")
    logger.info("P0 FIX: Blogger removed. Queue bomb neutralised. Direct STIX path.")
    logger.info("=" * 70)

    _run_start = time.monotonic()

    # -----------------------------------------------------------------------
    # FORCE_FULL_SYNC BYPASS (v152.1.0 — P0 REGRESSION FIX)
    # When FORCE_FULL_SYNC=true, purge ALL dedup persistence so the engine
    # treats every feed item as new and performs a complete regeneration.
    # This is the ONLY authorised way to bypass cross-run dedup.
    # Triggered via workflow_dispatch force_full_sync=true.
    # -----------------------------------------------------------------------
    _FORCE_FULL_SYNC = os.environ.get("FORCE_FULL_SYNC", "").strip().lower() == "true"
    if _FORCE_FULL_SYNC:
        logger.info("[FORCE_FULL_SYNC] *** FORCE FULL SYNC REQUESTED — purging all dedup persistence ***")
        _dedup_files_to_purge = [
            os.path.join("data", "cache", "intel_index.json"),
            os.path.join("data", "cache", "source_state.json"),
            os.path.join("data", "cache", "intel_fingerprint.json"),
            os.path.join("data", "cache", "dedup_state.json"),
            os.path.join("data", "pipeline_stall_state.json"),
        ]
        for _dp in _dedup_files_to_purge:
            try:
                if os.path.exists(_dp):
                    os.remove(_dp)
                    logger.info("[FORCE_FULL_SYNC] Purged: %s", _dp)
                else:
                    logger.debug("[FORCE_FULL_SYNC] Not found (ok): %s", _dp)
            except Exception as _purge_err:
                logger.warning("[FORCE_FULL_SYNC] Could not purge %s: %s", _dp, _purge_err)
        logger.info("[FORCE_FULL_SYNC] Dedup persistence cleared. Full regeneration will proceed.")
    else:
        logger.info("[FORCE_FULL_SYNC] Normal run — dedup persistence active.")

    if _TELEMETRY_OK and _telemetry:
        _telemetry.start_timer("total_run")
        logger.info("[STATS] Telemetry: ENABLED")

    # v134.0: Blogger is PERMANENTLY REMOVED.
    # service=None always. Intel flows directly to STIX → manifest → R2.
    # No Blogger API calls. No publish queue. No pending retries.
    service = None
    logger.info("[BLOGGER] PERMANENTLY DISABLED — R2-only architecture (v134.0)")

    published_count = 0

    # -- Load manifest for similarity checking --------------------------------
    # FIX v134.0: Use "advisories" key (was incorrectly "entries" — BUG FIX)
    def _load_manifest_advisories(path: str) -> List[Dict]:
        try:
            if os.path.exists(path):
                with open(path) as _f:
                    _data = json.load(_f)
                if isinstance(_data, list):
                    return _data
                # FIX: manifest uses "advisories", not "entries"
                for key in ("advisories", "reports", "entries", "items"):
                    val = _data.get(key)
                    if isinstance(val, list) and val:
                        return val
        except Exception:
            pass
        return []

    _manifest_path = os.path.join("data", "stix", "feed_manifest.json")
    _manifest = _load_manifest_advisories(_manifest_path)
    logger.info(f"[DEDUP] Loaded {len(_manifest)} existing entries for similarity check")

    # -- v142.0: Pre-load IntelDedupEngine before Phase 1 (shared by Phase 1+2) --
    _intel_engine_early = None
    try:
        import sys as _sys_pre
        _scripts_dir_pre = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")
        if _scripts_dir_pre not in _sys_pre.path:
            _sys_pre.path.insert(0, _scripts_dir_pre)
        from intel_dedup_engine import get_dedup_engine as _get_eng_pre
        _intel_engine_early = _get_eng_pre()
        logger.info("[DEDUP-L0] IntelDedupEngine pre-loaded for Phase 1+2 coverage")
    except Exception as _eng_pre_e:
        logger.debug("[DEDUP-L0] Pre-load unavailable: %s", _eng_pre_e)

    # -- Phase 1+2: Source State Tracker + Intel Fingerprint Store -----------
    # Phase 1 (source_state_tracker): per-feed published_at timestamp gate
    # Phase 2 (intel_fingerprint):    SHA256(source_url+title+published_at) gate
    _sst = None   # SourceStateTracker
    _fps = None   # IntelFingerprintStore
    try:
        import sys as _sys_p12
        _scripts_dir_p12 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
        if _scripts_dir_p12 not in _sys_p12.path:
            _sys_p12.path.insert(0, _scripts_dir_p12)
        from source_state_tracker import get_source_state_tracker as _get_sst
        _sst = _get_sst()
        logger.info("[DEDUP-L1] SourceStateTracker loaded (%d source states)", len(_sst._state))
    except Exception as _sst_e:
        logger.warning("[DEDUP-L1] SourceStateTracker unavailable: %s", _sst_e)
    try:
        from intel_fingerprint import get_fingerprint_store as _get_fps
        _fps = _get_fps()
        logger.info("[DEDUP-L2] IntelFingerprintStore loaded (%d fingerprints)", len(_fps))
    except Exception as _fps_e:
        logger.warning("[DEDUP-L2] IntelFingerprintStore unavailable: %s", _fps_e)

    # Phase 7: Load consecutive stall counter from disk
    _STALL_STATE_PATH = os.path.join("data", "pipeline_stall_state.json")
    _consecutive_stall_count = 0
    try:
        if os.path.exists(_STALL_STATE_PATH):
            _stall_raw = json.loads(open(_STALL_STATE_PATH).read())
            _consecutive_stall_count = int(_stall_raw.get("consecutive_empty_runs", 0))
            logger.info("[PHASE7] Consecutive empty runs so far: %d", _consecutive_stall_count)
    except Exception as _stall_load_e:
        logger.debug("[PHASE7] Stall state load error (non-fatal): %s", _stall_load_e)

    # -- PHASE 1: Primary CDB Feed -------------------------------------------
    logger.info("--- PHASE 1: Primary CDB Intelligence Feed ---")
    _ph1_start = time.monotonic()
    primary_entries = fetch_feed_entries(CDB_RSS_FEED, max_entries=1)
    if _TELEMETRY_OK and _telemetry:
        _telemetry.record_feed_fetch(
            CDB_RSS_FEED, time.monotonic() - _ph1_start,
            success=len(primary_entries) > 0
        )

    for entry in primary_entries:
        # v142.0 — Layer 0: source_url + stix_id + content_hash (Phase 1)
        if _intel_engine_early:
            try:
                _is_dup_ph1, _reason_ph1 = _intel_engine_early.is_duplicate(entry)
                if _is_dup_ph1:
                    logger.info(f"  SKIP [L0-PH1/{_reason_ph1[:35]}]: {entry['title'][:50]}")
                    continue
            except Exception as _ph1_l0_e:
                logger.debug("[DEDUP-L0-PH1] error (non-fatal): %s", _ph1_l0_e)

        if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
            logger.info(f"  SKIP (duplicate): {entry['title'][:60]}")
            continue

        if _manifest and dedup_engine.is_similar_in_manifest(
                entry["title"], _manifest, threshold=0.92):
            logger.info(f"  SKIP (manifest similar): {entry['title'][:60]}")
            dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
            continue

        if not is_temporally_relevant(entry):
            dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
            continue

        if _QUALITY_GATE_OK and _quality_gate:
            try:
                _qok, _qscore, _qreason = _quality_gate(
                    entry["title"],
                    entry.get("content", "") + entry.get("summary", ""),
                    source_url=entry.get("link", ""),
                )
                if not _qok:
                    logger.info(f"  SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}")
                    dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                    continue
            except Exception as _qe:
                logger.debug(f"  Quality gate error (non-critical): {_qe}")

        # Phase 1: Source state published_at timestamp check
        if _sst:
            try:
                _sst_skip, _sst_reason = _sst.should_skip(entry)
                if _sst_skip:
                    logger.info(f"  [STATE-SKIP/L1] {_sst_reason[:60]}: {entry['title'][:50]}")
                    _sst.update_skip_count(entry.get("link") or entry.get("source_url", ""))
                    time.sleep(RATE_LIMIT_DELAY)
                    continue
            except Exception as _sst_ck_e:
                logger.debug("[DEDUP-L1] should_skip error (non-fatal): %s", _sst_ck_e)
        # Phase 2: SHA256 content fingerprint check
        if _fps:
            try:
                _fp_dup, _fp_hash = _fps.check_entry(entry)
                if _fp_dup:
                    logger.info(f"  [FPRINT-SKIP/L2] fingerprint seen: {entry['title'][:50]}")
                    time.sleep(RATE_LIMIT_DELAY)
                    continue
            except Exception as _fps_ck_e:
                logger.debug("[DEDUP-L2] check_entry error (non-fatal): %s", _fps_ck_e)

        try:
            result = process_entry(entry, feed_source="CyberDudeBivash Intel")
        except Exception as _pe:
            import traceback as _tb
            logger.error(
                f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}\n"
                f"  [CRASH-GUARD] Traceback:\n{_tb.format_exc()}"
            )
            result = False
        if result:
            published_count += 1
            if _intel_engine_early:
                try:
                    _intel_engine_early.mark_seen(entry)
                except Exception:
                    pass
            # Phase 1+2: Mark as processed in state trackers
            if _sst:
                try:
                    _sst.mark_processed(entry)
                except Exception as _sst_mp_e:
                    logger.debug("[DEDUP-L1] mark_processed error: %s", _sst_mp_e)
            if _fps:
                try:
                    from intel_fingerprint import fingerprint_from_entry as _fp_from_e
                    _fps.mark_seen(_fp_from_e(entry))
                except Exception as _fps_mp_e:
                    logger.debug("[DEDUP-L2] mark_seen error: %s", _fps_mp_e)
        time.sleep(RATE_LIMIT_DELAY)

    # -- PHASE 2: Multi-Feed Fusion ------------------------------------------
    logger.info("--- PHASE 2: Multi-Feed Intelligence Fusion ---")

    # v142.0 — Load FeedStateTracker; reuse pre-loaded IntelDedupEngine singleton
    _feed_tracker = None
    _intel_engine = _intel_engine_early  # already loaded above (singleton)
    try:
        import importlib.util, sys as _sys
        _scripts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")
        if _scripts_dir not in _sys.path:
            _sys.path.insert(0, _scripts_dir)
        from intel_dedup_engine import get_feed_tracker
        _feed_tracker = get_feed_tracker()
        logger.info("[DEDUP-L0] FeedStateTracker loaded — per-feed anti-loop protection ACTIVE")
        if _intel_engine:
            logger.info("[DEDUP-L0] IntelDedupEngine singleton reused from Phase 1 pre-load")
    except Exception as _ft_e:
        logger.warning("[DEDUP-L0] FeedStateTracker unavailable (%s) — continuing without it", _ft_e)

    for feed_url in RSS_FEEDS:
        _feed_start = time.monotonic()
        entries = fetch_feed_entries(feed_url, max_entries=MAX_ENTRIES_PER_FEED)
        _feed_elapsed = time.monotonic() - _feed_start
        logger.info(f"Feed [{feed_url[:60]}]: {len(entries)} entries")
        if _TELEMETRY_OK and _telemetry:
            _telemetry.record_feed_fetch(feed_url, _feed_elapsed, success=len(entries) > 0)

        # v141.4.0 — Anti-loop protection: skip feed if 90%+ overlap with last run
        if _feed_tracker and entries:
            try:
                item_ids = [e.get("link") or e.get("title", "") for e in entries]
                if _feed_tracker.is_same_batch(feed_url, item_ids):
                    logger.info(
                        f"  [FEED-SKIP] {feed_url[:60]}: 90%+ overlap with last run — no new intel"
                    )
                    continue
                # Filter out IDs already seen in previous run for this feed
                before_filter = len(entries)
                entries = _feed_tracker.filter_new_ids(feed_url, entries)
                if before_filter != len(entries):
                    logger.info(
                        f"  [FEED-FILTER] {feed_url[:60]}: {before_filter - len(entries)} "
                        f"already-seen items filtered, {len(entries)} new"
                    )
            except Exception as _ft_loop_e:
                logger.debug("[FEED-TRACKER] per-feed filter error (non-fatal): %s", _ft_loop_e)

        for entry in entries:
            time.sleep(RATE_LIMIT_DELAY)

            # v142.0 — Layer 0: source_url + stix_id + content_hash (strongest dedup)
            if _intel_engine:
                try:
                    _is_dup_l0, _reason_l0 = _intel_engine.is_duplicate(entry)
                    if _is_dup_l0:
                        logger.info(f"  SKIP [L0/{_reason_l0[:40]}]: {entry['title'][:50]}")
                        continue
                except Exception as _l0_e:
                    logger.debug("[DEDUP-L0] check error (non-fatal): %s", _l0_e)

            if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
                logger.info(f"  SKIP (duplicate): {entry['title'][:60]}")
                continue

            if _manifest and dedup_engine.is_similar_in_manifest(
                    entry["title"], _manifest, threshold=0.92):
                logger.info(f"  SKIP (manifest similar): {entry['title'][:60]}")
                dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                continue

            if not is_temporally_relevant(entry):
                dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                continue

            if _QUALITY_GATE_OK and _quality_gate:
                try:
                    _qok, _qscore, _qreason = _quality_gate(
                        entry["title"],
                        entry.get("content", "") + entry.get("summary", ""),
                        source_url=entry.get("link", ""),
                    )
                    if not _qok:
                        logger.info(f"  SKIP (quality gate [{_qreason[:60]}]): {entry['title'][:50]}")
                        dedup_engine.mark_processed(entry["title"], entry.get("link", ""))
                        continue
                except Exception as _qe:
                    logger.debug(f"  Quality gate error (non-critical): {_qe}")

            # Phase 1: Source state published_at timestamp check
            if _sst:
                try:
                    _sst_skip2, _sst_reason2 = _sst.should_skip(entry)
                    if _sst_skip2:
                        logger.info(f"  [STATE-SKIP/L1] {_sst_reason2[:60]}: {entry['title'][:50]}")
                        _sst.update_skip_count(entry.get("link") or entry.get("source_url", ""))
                        continue
                except Exception as _sst_ck2_e:
                    logger.debug("[DEDUP-L1] should_skip error (non-fatal): %s", _sst_ck2_e)
            # Phase 2: SHA256 content fingerprint check
            if _fps:
                try:
                    _fp_dup2, _fp_hash2 = _fps.check_entry(entry)
                    if _fp_dup2:
                        logger.info(f"  [FPRINT-SKIP/L2] fingerprint seen: {entry['title'][:50]}")
                        continue
                except Exception as _fps_ck2_e:
                    logger.debug("[DEDUP-L2] check_entry error (non-fatal): %s", _fps_ck2_e)

            try:
                result = process_entry(entry, feed_source=_resolve_feed_source_name(feed_url))
            except Exception as _pe:
                import traceback as _tb2
                logger.error(
                    f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}\n"
                    f"  [CRASH-GUARD] Traceback:\n{_tb2.format_exc()}"
                )
                result = False
            if result:
                published_count += 1
                # v142.0 — Register in IntelDedupEngine so next run knows this was processed
                if _intel_engine:
                    try:
                        _intel_engine.mark_seen(entry)
                    except Exception as _ms_e:
                        logger.debug("[DEDUP-L0] mark_seen error (non-fatal): %s", _ms_e)
                # Phase 1+2: Mark as processed in state trackers
                if _sst:
                    try:
                        _sst.mark_processed(entry)
                    except Exception as _sst_mp2_e:
                        logger.debug("[DEDUP-L1] mark_processed error: %s", _sst_mp2_e)
                if _fps:
                    try:
                        from intel_fingerprint import fingerprint_from_entry as _fp_from_e2
                        _fps.mark_seen(_fp_from_e2(entry))
                    except Exception as _fps_mp2_e:
                        logger.debug("[DEDUP-L2] mark_seen error: %s", _fps_mp2_e)

        # v141.4.0 — Update FeedStateTracker with this feed's batch (post-processing)
        if _feed_tracker and entries:
            try:
                _feed_tracker.update(feed_url, entries)
            except Exception as _ft_upd_e:
                logger.debug("[FEED-TRACKER] update error (non-fatal): %s", _ft_upd_e)

    # v142.0 — Persist IntelDedupEngine + FeedStateTracker after all feeds processed
    try:
        from intel_dedup_engine import save_all as _dedup_save_all
        _dedup_save_all()
        logger.info("[DEDUP-L0] IntelDedupEngine + FeedStateTracker persisted to data/cache/")
    except Exception as _save_e:
        logger.warning("[DEDUP-L0] save_all() failed (non-fatal): %s", _save_e)
    # Also save IntelDedupEngine directly if singleton was loaded this run
    if _intel_engine:
        try:
            _intel_engine.save()
        except Exception as _ie_save_e:
            logger.debug("[DEDUP-L0] IntelDedupEngine.save() error: %s", _ie_save_e)

    # Phase 1+2: Persist state trackers (before final summary)
    if _sst:
        try:
            _sst.save()
            logger.info("[DEDUP-L1] SourceStateTracker persisted to data/source_state.json")
        except Exception as _sst_save_e:
            logger.warning("[DEDUP-L1] SourceStateTracker save failed: %s", _sst_save_e)
    if _fps:
        try:
            _fps.save()
            logger.info("[DEDUP-L2] IntelFingerprintStore persisted to data/processed_fingerprints.json")
        except Exception as _fps_save_e:
            logger.warning("[DEDUP-L2] IntelFingerprintStore save failed: %s", _fps_save_e)

    # Phase 3: NO NEW INTEL guard
    if published_count == 0:
        logger.warning(
            "[PHASE3] ⚠️ NO NEW INTEL DETECTED — 0 new advisories processed this run. "
            "All entries were either duplicate, stale, or filtered."
        )

    # Phase 6: Structured run summary with dedup counters
    _sst_stats = _sst.get_stats() if _sst else {}
    _fps_stats = _fps.get_stats() if _fps else {}
    _l0_stats  = _intel_engine_early.get_stats() if (
        _intel_engine_early and hasattr(_intel_engine_early, "get_stats")
    ) else {}
    logger.info(
        "[PHASE6] ═══ INGESTION SUMMARY ═══ "
        "feeds_checked=%d | new_published=%d | "
        "state_skipped=%d | fprint_skipped=%d | dedup_skipped=%s",
        len(RSS_FEEDS) + 1,
        published_count,
        _sst_stats.get("skipped_this_run", 0),
        _fps_stats.get("skipped_this_run", 0),
        str(_l0_stats.get("total_duplicates_blocked", "n/a")),
    )

    # Phase 7: Consecutive stall detection + INGESTION STALLED alert
    try:
        if published_count == 0:
            _consecutive_stall_count += 1
        else:
            _consecutive_stall_count = 0   # reset counter on any success
        _stall_payload = {
            "consecutive_empty_runs": _consecutive_stall_count,
            "last_updated":           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_run_published":     published_count,
        }
        os.makedirs("data", exist_ok=True)
        with open(_STALL_STATE_PATH, "w", encoding="utf-8") as _stall_f:
            json.dump(_stall_payload, _stall_f, indent=2)
        if _consecutive_stall_count >= 2:
            logger.critical(
                "[PHASE7] 🚨 INGESTION STALLED — %d consecutive runs with 0 new intel. "
                "ACTION REQUIRED: verify feed URLs, check source_state.json and intel_index.json, "
                "confirm network connectivity to feed sources.",
                _consecutive_stall_count,
            )
            try:
                send_pipeline_summary(
                    published=0,
                    failed=_consecutive_stall_count,
                    critical=1,
                    run_ts=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
                )
            except Exception:
                pass
        else:
            logger.info("[PHASE7] Stall counter=%d (alert threshold: 2)", _consecutive_stall_count)
    except Exception as _stall_e:
        logger.debug("[PHASE7] Stall tracking error (non-fatal): %s", _stall_e)

    logger.info("=" * 70)
    logger.info(f"APEX v134.0 COMPLETE — Processed {published_count} intel advisories (R2-only)")
    logger.info(f"Total elapsed: {time.monotonic() - _run_start:.1f}s")

    # -- Alert engine (non-blocking) -----------------------------------------
    try:
        from agent.alert_engine import run_alert_engine
        _alert_result = run_alert_engine()
        logger.info(
            f"[ALERT-ENGINE] fired={_alert_result.get('alerts_fired', 0)} "
            f"critical={_alert_result.get('total_critical_detected', 0)}"
        )
    except Exception:
        pass

    # -- Response engine (non-blocking) --------------------------------------
    try:
        from agent.response_engine import run_response_engine
        _resp_result = run_response_engine()
        logger.info(f"[RESPONSE-ENGINE] mode={_resp_result.get('mode', '?')} "
                    f"executed={_resp_result.get('responses_executed', 0)}")
    except Exception:
        pass

    # -- Telegram pipeline summary (non-blocking) ----------------------------
    try:
        send_pipeline_summary(
            published=published_count,
            failed=0,
            critical=0,
            run_ts=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        )
    except Exception:
        pass

    # -- Predictive trend analysis -------------------------------------------
    if _PREDICTIVE_OK and _trend_model:
        try:
            trend = _trend_model.analyze()
            logger.info(
                f"Risk Trend: {trend.get('trend_direction', 'N/A')} | "
                f"Velocity: {trend.get('attack_velocity_per_day', 0)}/day"
            )
        except Exception as e:
            logger.warning(f"Trend analysis skipped (non-critical): {e}")

    if _TELEMETRY_OK and _telemetry:
        try:
            _telemetry.finalize_run(
                total_elapsed=time.monotonic() - _run_start,
                # FIX: pass authoritative pipeline counters — Published:0 regression
                # was caused by finalize_run not receiving published_count
                status="success" if published_count > 0 else "partial",
                published_count=published_count,
                processed_count=published_count,  # processed ≥ published; use published as floor
            )
        except Exception:
            pass

    logger.info("=" * 70)
    # Return published count so pipeline can fail-fast if 0 new entries
    return published_count


# ==============================================================================
# ENTRY PROCESSOR — R2-NATIVE (NO BLOGGER)
# ==============================================================================

def process_entry(entry: Dict, feed_source: str = "EXTERNAL") -> bool:
    """
    Full 10-step premium pipeline for a single intelligence entry.
    v134.0: STIX bundle written directly. No Blogger publish. No queue.
    Returns True if STIX bundle successfully written to disk.
    """
    # -------------------------------------------------------------------------
    # SCHEMA CONTRACT ENFORCEMENT — v134.2
    # Hard type check: entry MUST be a dict. Lists, tuples, and any non-dict
    # type are a schema contract violation and must be rejected explicitly.
    # This is NOT try/except masking — it is an explicit type gate that logs
    # a hard ERROR so the upstream data corruption is visible and traceable.
    # -------------------------------------------------------------------------
    if not isinstance(entry, dict):
        logger.error(
            "[SCHEMA-REJECT] process_entry received %s instead of dict — "
            "schema contract violation. Entry discarded. Upstream bug: "
            "check feed parsing / STIX reconstruction / dedup pipeline.",
            type(entry).__name__,
        )
        return False

    # Defaults for required fields — if missing, set sentinel values so
    # subsequent code never KeyErrors on 'title' or 'link'.
    entry.setdefault("title", "UNKNOWN_TITLE")
    entry.setdefault("link", "")
    entry.setdefault("summary", "")
    entry.setdefault("content", "")

    headline   = entry["title"]
    # v143.5 FIX: source_url falls back to source_url/url fields for manifest-reprocessed entries.
    # RSS entries have 'link'; manifest re-entries may have 'source_url' or 'url' but no 'link'.
    source_url = entry.get("link", "") or entry.get("source_url", "") or entry.get("url", "")
    # v142.0 P0 TIMESTAMP FIX: Capture the RSS <pubDate> from feedparser.
    # feedparser exposes this as entry["published"] (string) or entry["published_parsed"] (struct_time).
    # We normalise to ISO-8601 string here and pass to create_bundle() as published_at.
    # This is the ONLY place published_at should be set — NEVER pipeline time.
    #
    # v142.1 P0 TIMESTAMP EXTRACTION — boolean-safe, RFC-2822-aware, ISO-8601 normalised.
    #
    # ROOT CAUSE CATALOGUE:
    #   [A] export_stix.py writes "published": True  (boolean Blogger flag, NOT a date).
    #       str(True) = "True" → invalid ISO-8601.  Guard: isinstance check.
    #   [B] feedparser writes "published": "Tue, 21 Apr 2026 12:00:00 GMT" (RFC-2822).
    #       Does NOT start with a 4-digit year → must convert via published_parsed.
    #   [C] Our manifest already has "published_at": "2026-04-21T12:00:00Z" (ISO-8601).
    #       Use directly.
    #
    # PIPELINE (priority order):
    #   1. published_parsed struct_time → ISO-8601    (most reliable; feedparser always sets this)
    #   2. published_at ISO string from manifest      (already normalised)
    #   3. published string only if it IS ISO-8601    (rare; some APIs emit this directly)
    from datetime import datetime as _dt, timezone as _tz

    _pub_parsed  = entry.get("published_parsed")
    _pub_str_raw = entry.get("published", "")
    _pub_at_raw  = entry.get("published_at", "")

    # Guard [A]: reject any non-string boolean flag (published=True)
    if not isinstance(_pub_str_raw, str):
        _pub_str_raw = ""
    if not isinstance(_pub_at_raw, str):
        _pub_at_raw = ""
    _pub_str_raw = _pub_str_raw.strip()
    _pub_at_raw  = _pub_at_raw.strip()

    _source_published_at: str = ""

    # Priority 1: published_parsed struct_time (feedparser always populates this from pubDate)
    if _pub_parsed:
        try:
            _source_published_at = _dt(*_pub_parsed[:6], tzinfo=_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            _source_published_at = ""

    # Priority 2: manifest published_at — already ISO-8601 (4-digit year)
    if not _source_published_at and _pub_at_raw and _pub_at_raw[:4].isdigit():
        _source_published_at = _pub_at_raw

    # Priority 3: published string — only accept if it looks like ISO-8601 (starts with YYYY-)
    if not _source_published_at and _pub_str_raw and _pub_str_raw[:4].isdigit():
        _source_published_at = _pub_str_raw

    # Priority 4: RFC 2822 date string (e.g. "Tue, 29 Apr 2026 12:27:00 +0000")
    # feedparser sets published_parsed for live RSS entries but it is a time.struct_time
    # that cannot round-trip through JSON.  When entries are re-processed from a cached
    # manifest, published_parsed is absent and published contains the raw RFC 2822 string.
    # Without this pass, _source_published_at stays "" → x_cdb_published_at="" in STIX →
    # Stage 3.9 falls back to utc_now() → all published_at timestamps show pipeline time.
    if not _source_published_at and _pub_str_raw:
        try:
            from email.utils import parsedate_to_datetime as _parse_rfc2822
            _source_published_at = _parse_rfc2822(_pub_str_raw).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass  # leave empty — prefer missing over wrong

    logger.info(f"PROCESSING: {headline[:80]}")

    # -- STEP 1: Source article -----------------------------------------------
    # v143.1 NULL-SAFE: wrap fetch in try/except so any crash in source_fetcher
    # or build_enriched_content does not propagate as an uncaught exception.
    try:
        fetched_article  = enrich_with_source_content(entry)
        enriched_content = build_enriched_content(entry, fetched_article)
    except Exception as _s1_e:
        logger.warning(f"  [STEP1-SAFE] source fetch/build failed (continuing): {_s1_e}")
        fetched_article  = None
        enriched_content = (entry.get("content", "") or entry.get("summary", "") or "")
    logger.info(f"  -> Content: {len(enriched_content.split())} words")

    # -- STEP 2: IOC extraction -----------------------------------------------
    # v143.1 NULL-SAFE: IOC extractor must never crash the pipeline.
    try:
        extracted_iocs = enricher.extract_iocs(enriched_content)
        ioc_counts     = enricher.get_ioc_counts(extracted_iocs)
    except Exception as _s2_e:
        logger.warning(f"  [STEP2-SAFE] IOC extraction failed (continuing): {_s2_e}")
        extracted_iocs = {}
        ioc_counts     = {}
    total_iocs = sum(ioc_counts.values())
    logger.info(f"  -> IOCs: {total_iocs} across {sum(1 for v in extracted_iocs.values() if v)} categories")

    # -- STEP 3: MITRE ATT&CK mapping -----------------------------------------
    # v143.1 NULL-SAFE: MITRE mapper must never crash the pipeline.
    full_corpus = f"{headline} {enriched_content}"
    try:
        mitre_data = mitre_engine.map_threat(full_corpus)
        # v143.0: strip any techniques missing id/name/tactic before manifest write
        mitre_data = sanitize_mitre_techniques(mitre_data)
    except Exception as _s3_e:
        logger.warning(f"  [STEP3-SAFE] MITRE mapping failed (continuing): {_s3_e}")
        mitre_data = []
    logger.info(f"  -> MITRE techniques: {len(mitre_data)} (post-sanitize)")

    # -- STEP 4: Actor attribution -------------------------------------------
    # v143.1 NULL-SAFE: actor correlation must never crash the pipeline.
    try:
        actor_data   = actor_matrix.correlate_actor(full_corpus, extracted_iocs)
    except Exception as _s4_e:
        logger.warning(f"  [STEP4-SAFE] Actor attribution failed (continuing): {_s4_e}")
        actor_data = {"tracking_id": "UNC-CDB-99", "confidence": 0}
    actor_mapped = (actor_data or {}).get("tracking_id", "").startswith("CDB-")

    # -- STEP 5: Dynamic risk scoring ----------------------------------------
    _source_for_scoring = (
        (fetched_article or {}).get("full_text", "")
        or entry.get("content", "")
        or entry.get("summary", "")
        or enriched_content[:2000]
    )
    _source_word_count = len(_source_for_scoring.split())

    kev_present = False
    epss_score  = None
    cvss_score  = None
    nvd_url     = None

    risk_score = risk_engine.calculate_risk_score(
        iocs=extracted_iocs,
        mitre_matches=mitre_data,
        actor_data=actor_data,
        headline=headline,
        content=_source_for_scoring,
    )

    # v75.5: CVSS-aware score cap
    _cve_only = bool(extracted_iocs.get("cve")) and not any([
        extracted_iocs.get("sha256"),
        extracted_iocs.get("ipv4"),
        extracted_iocs.get("domain"),
    ])
    _cvss_in_title = None
    try:
        _m = re.search(r"CVSS[: ]+(\d+\.?\d*)", enriched_content[:500] + headline)
        _cvss_in_title = float(_m.group(1)) if _m else None
    except Exception:
        pass
    _cap_exempt = _cvss_in_title and _cvss_in_title >= 7.0
    if _source_word_count < 50 and _cve_only and risk_score > 6.4 and not _cap_exempt:
        risk_score = min(risk_score, 6.4)

    severity = risk_engine.get_severity_label(risk_score)
    _confirmed_actor = bool(actor_data and not actor_data.get("tracking_id", "").startswith("UNC-"))

    tlp = risk_engine.get_tlp_label(
        risk_score, iocs=extracted_iocs, kev_present=kev_present,
        confirmed_actor=_confirmed_actor, cvss_score=None,
    )
    impact_metrics = risk_engine.extract_impact_metrics(headline, enriched_content)
    logger.info(f"  -> Risk: {risk_score}/10 | {severity} | TLP: {tlp.get('label')}")

    # -- STEP 6: Confidence scoring ------------------------------------------
    confidence = enricher.calculate_confidence(extracted_iocs, actor_mapped)
    if impact_metrics["records_affected"] > 0:
        confidence = min(confidence + 15.0, 100.0)
    if len(impact_metrics["severity_keywords"]) >= 3:
        confidence = min(confidence + 10.0, 100.0)
    if len(mitre_data) >= 5:
        confidence = min(confidence + 8.0, 100.0)
    elif len(mitre_data) >= 3:
        confidence = min(confidence + 4.0, 100.0)

    # -- STEP 7: Detection engineering — OMEGA-P3 Supremacy Layer -------------
    sigma_rule      = detection_engine.generate_sigma_rule(headline, extracted_iocs)
    yara_rule       = detection_engine.generate_yara_rule(headline, extracted_iocs)
    kql_rule        = detection_engine.generate_kql_rule(headline, extracted_iocs)
    spl_rule        = detection_engine.generate_spl_rule(headline, extracted_iocs)
    eql_rule        = detection_engine.generate_eql_rule(headline, extracted_iocs)
    suricata_rule   = detection_engine.generate_suricata_rule(headline, extracted_iocs)
    snort_rule      = detection_engine.generate_snort_rule(headline, extracted_iocs)
    defender_query  = detection_engine.generate_defender_query(headline, extracted_iocs)
    logger.info(f"  -> Detection pack: Sigma+YARA+KQL+SPL+EQL+Suricata+Snort+Defender generated")

    # -- STEP 7b: CVE enrichment — EPSS + CVSS + KEV -------------------------
    cve_ids = extracted_iocs.get("cve", [])
    if cve_ids:
        try:
            _epss, _cvss, _kev, _nvd = _enrich_cve_metadata(cve_ids[0])
            epss_score  = _epss
            cvss_score  = _cvss
            kev_present = _kev
            nvd_url     = _nvd
            if epss_score or cvss_score:
                logger.info(f"  -> CVE enrichment: EPSS={epss_score} CVSS={cvss_score} KEV={kev_present}")
                _nvd_score = risk_engine.recalculate_with_nvd(
                    base_score=risk_score, cvss_score=cvss_score,
                    epss_score=epss_score, kev_present=kev_present,
                )
                if _nvd_score != risk_score:
                    risk_score = _nvd_score
                    severity   = risk_engine.get_severity_label(risk_score)
                    tlp = risk_engine.get_tlp_label(
                        risk_score, iocs=extracted_iocs, kev_present=kev_present,
                        confirmed_actor=_confirmed_actor, cvss_score=cvss_score,
                    )
        except Exception as _cve_e:
            logger.debug(f"CVE enrichment skipped: {_cve_e}")

    # -- STEP 7c: VANGUARD IOC validation ------------------------------------
    if _VANGUARD_OK and _vanguard:
        try:
            _v46 = _vanguard.enhance(
                iocs=extracted_iocs, source_text=enriched_content,
                cve_ids=cve_ids, mitre_data=mitre_data, actor_data=actor_data,
                impact_metrics=impact_metrics, fetched_article=fetched_article,
                source_content=enriched_content, epss_score=epss_score,
                cvss_score=cvss_score, kev_present=kev_present,
            )
            extracted_iocs = _v46["iocs"]
            ioc_counts     = enricher.get_ioc_counts(extracted_iocs)
            if _v46["kev_present"]:
                kev_present = True
            if _v46["confidence"] is not None:
                confidence = _v46["confidence"]
        except Exception as _v46_e:
            logger.debug(f"VANGUARD skipped: {_v46_e}")

    # -- STEP 7d: v134.0 Confidence floors ------------------------------------
    try:
        _v47_confidence = enricher.calculate_confidence_v47(
            iocs=extracted_iocs, actor_mapped=actor_mapped,
            kev_present=kev_present, epss_score=epss_score or 0.0,
            cvss_score=cvss_score or 0.0,
        )
        if _v47_confidence > confidence:
            confidence = _v47_confidence
    except Exception:
        pass

    # -- STEP 7e-APEX: v142.0 APEX INTELLIGENCE ENGINE -----------------------
    # Technical depth, MITRE justification, explainable risk, evidence-gated
    # attribution, AI insight explainability — Mandiant/CrowdStrike/Unit42 grade
    _apex_data: Dict = {}
    try:
        import sys as _sys_apex
        _scripts_dir_apex = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
        )
        if _scripts_dir_apex not in _sys_apex.path:
            _sys_apex.path.insert(0, _scripts_dir_apex)
        from apex_intel_engine import get_apex_enricher as _get_apex
        _apex_data = _get_apex().enrich(
            title=headline,
            content=enriched_content,
            iocs=extracted_iocs,
            raw_mitre=mitre_data,
            raw_actor=actor_data,
            risk_score=risk_score,
            cvss=cvss_score,
            epss=epss_score,
            kev_present=kev_present,
        )
        _apex_intel = _apex_data.get("apex_intelligence", {})
        _td_score = _apex_intel.get("technical_depth", {}).get("technical_depth_score", 0)
        _attr_conf = _apex_intel.get("attribution", {}).get("confidence", "UNKNOWN")
        _risk_conf = _apex_intel.get("risk_explained", {}).get("confidence_rationale", "")
        logger.info(
            f"  [APEX] tech_depth={_td_score} | attr={_attr_conf} | "
            f"risk_conf={_risk_conf[:40] if _risk_conf else 'n/a'}"
        )

        # v142.1 FIX: Normalize nested apex_intelligence -> flat keys for export_stix.py
        # export_stix expects: composite_score, threat_level, threat_category,
        # campaign_id, behavioral_tags, ai_summary, recommended_action, priority
        _risk_expl  = _apex_intel.get("risk_explained", {})
        _attr       = _apex_intel.get("attribution", {})
        _tech       = _apex_intel.get("technical_depth", {})
        _ai_ins     = _apex_intel.get("ai_insight", {})
        _comp_score = float(_risk_expl.get("risk_score_explained", 0.0))
        _conf_det   = _risk_expl.get("confidence_detail", {})
        _conf_level = (_conf_det.get("level", "VERY_LOW")
                       if isinstance(_conf_det, dict) else "VERY_LOW")
        _CONF_TO_THREAT = {
            "CONFIRMED": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM", "LOW": "LOW", "VERY_LOW": "LOW",
        }
        _tl = _CONF_TO_THREAT.get(_conf_level, "LOW")
        _av_type = (_tech.get("attack_vector", {}).get("type", "unknown")
                    if isinstance(_tech.get("attack_vector"), dict)
                    else str(_tech.get("attack_vector", "unknown")))
        _AV_TO_CAT = {
            "phishing": "Phishing", "rce": "Remote Code Execution",
            "supply_chain": "Supply Chain Attack", "zero_day": "Zero Day Exploit",
            "web_app": "Web Application Attack", "credential": "Credential Theft",
            "man_in_the_middle": "Man-in-the-Middle", "insider": "Insider Threat",
            "physical": "Physical Access",
        }
        _tcat = _AV_TO_CAT.get(_av_type, "Threat Intel")
        _actor_str = str(_attr.get("actor", "UNKNOWN"))
        _camp_id   = ("CDB-" + _actor_str[:8]) if _attr.get("attributed") else "UNCLASSIFIED"
        _behaviors = [b.get("behavior", str(b)) if isinstance(b, dict) else str(b)
                      for b in _tech.get("malware_behaviors", [])[:5]]
        _pri = ("P1" if _comp_score >= 9 else "P2" if _comp_score >= 7
                else "P3" if _comp_score >= 5 else "P4")
        _apex_data = {
            "composite_score":    _comp_score,
            "priority_score":     _comp_score,
            "priority":           _pri,
            "threat_level":       _tl,
            "threat_category":    _tcat,
            "campaign_id":        _camp_id,
            "behavioral_tags":    _behaviors,
            "ai_summary":         str(_ai_ins.get("attack_narrative", ""))[:300],
            "recommended_action": str(_risk_expl.get("risk_summary", ""))[:200],
            "risk_factors":       [s.get("signal", "")
                                   for s in _risk_expl.get("signal_breakdown", [])],
            "apex_intelligence":  _apex_intel,
        }
        logger.info(
            "[APEX] normalized: score=%.1f priority=%s threat=%s category=%s",
            _comp_score, _pri, _tl, _tcat,
        )
    except Exception as _apex_e:
        logger.debug("[APEX-INTEL] Enrichment unavailable (non-fatal): %s", _apex_e)

    # PHASE 9 FIX: Dynamic SOC priority from risk_score when APEX engine is unavailable.
    # Root cause: apex_intel_engine fails to import → _apex_data={} → _comp_score=0.0
    #             → priority formula always produces P4 regardless of actual risk_score.
    # Fix: when _apex_data is empty/missing, derive priority from authoritative risk_score.
    if not _apex_data:
        _pri_fallback = (
            "P1" if risk_score >= 9.0 else
            "P2" if risk_score >= 7.0 else
            "P3" if risk_score >= 5.0 else "P4"
        )
        _tl_fallback = (
            "CRITICAL" if risk_score >= 9.0 else
            "HIGH"     if risk_score >= 7.0 else
            "MEDIUM"   if risk_score >= 5.0 else "LOW"
        )
        _apex_data = {
            "composite_score":    float(risk_score),
            "priority_score":     float(risk_score),
            "priority":           _pri_fallback,
            "threat_level":       _tl_fallback,
            "threat_category":    "Threat Intel",
            "campaign_id":        "UNCLASSIFIED",
            "behavioral_tags":    [],
            "ai_summary":         "",
            "recommended_action": "",
            "risk_factors":       [],
            "apex_intelligence":  {},
        }
        logger.info(
            "[PHASE9] APEX fallback priority: risk_score=%.1f → priority=%s threat_level=%s",
            risk_score, _pri_fallback, _tl_fallback,
        )
    elif not _apex_data.get("priority") or _apex_data.get("priority") == "P4":
        # Additional guard: re-derive priority if score was set but priority formula produced P4
        # and the underlying risk_score is actually higher (apex_intel_engine produced low comp_score)
        _comp_score_check = float(_apex_data.get("composite_score", 0.0))
        if _comp_score_check < 5.0 and risk_score >= 5.0:
            _pri_override = (
                "P1" if risk_score >= 9.0 else
                "P2" if risk_score >= 7.0 else
                "P3" if risk_score >= 5.0 else "P4"
            )
            if _pri_override != _apex_data.get("priority"):
                _apex_data["priority"] = _pri_override
                _apex_data["composite_score"] = float(risk_score)
                _apex_data["priority_score"]  = float(risk_score)
                logger.info(
                    "[PHASE9] Priority override: apex_comp=%.1f < risk_score=%.1f → priority=%s",
                    _comp_score_check, risk_score, _pri_override,
                )

    # -- STEP 7e: Phase 6 HARD QUALITY GATE (v134.0) -------------------------
    # POLICY: NO WEAK INTEL — hard reject based on post-enrichment metrics.
    # Exemptions: CVE entries and KEV entries bypass word/IOC/confidence floors
    # because CVE advisories may be structurally lean but high-signal.
    #
    # Rule 1 (WORD FLOOR):  non-CVE non-KEV entries < 150 words → REJECT
    # Rule 2 (IOC FLOOR):   non-CVE non-KEV entries with 0 IOCs  → REJECT
    # Rule 3 (CONF FLOOR):  non-CVE non-KEV entries confidence < 4.5 → REJECT
    _pq_has_cve    = bool(extracted_iocs.get("cve")) or bool(
        re.search(r"\bCVE-\d{4}-\d+\b", headline, re.I)
    )
    _pq_has_kev    = kev_present
    _pq_word_count = len(enriched_content.split())
    _pq_total_iocs = sum(ioc_counts.values())
    _PQ_WORD_FLOOR = 150
    _PQ_CONF_FLOOR = 4.5

    # v134.2 P0 ROOT FIX: isinstance MUST be checked before .get() — map_threat()
    # returns a list[], never a dict. Calling .get() on a list crashes every entry.
    # Order: list check first (fast path), dict check second (future-proof).
    _pq_has_iocs   = _pq_total_iocs > 0
    _pq_has_mitre  = (
        (isinstance(mitre_data, list) and len(mitre_data) > 0)
        or (isinstance(mitre_data, dict) and bool(
            mitre_data.get("tactics") or mitre_data.get("techniques")
        ))
    )
    _pq_known_actor = bool(actor_data and not actor_data.get("tracking_id", "").startswith("UNC-"))
    _pq_exempt = _pq_has_cve or _pq_has_kev or _pq_has_iocs or _pq_has_mitre or _pq_known_actor

    if not _pq_exempt:
        if _pq_word_count < _PQ_WORD_FLOOR:
            logger.warning(
                f"  [HARD-GATE] REJECT '{headline[:60]}': "
                f"insufficient content ({_pq_word_count} words < {_PQ_WORD_FLOOR} floor, "
                f"no CVE/KEV/IOC/MITRE/actor exemption)"
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False

        if confidence < _PQ_CONF_FLOOR:
            logger.warning(
                f"  [HARD-GATE] REJECT '{headline[:60]}': "
                f"confidence {confidence:.1f} < {_PQ_CONF_FLOOR} floor "
                f"(no exemption)"
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False
    elif _pq_word_count < 30:
        # Absolute minimum — even exempt entries need some content
        logger.warning(
            f"  [HARD-GATE] REJECT '{headline[:60]}': "
            f"absolute minimum content floor ({_pq_word_count} words < 30)"
        )
        dedup_engine.mark_processed(headline, entry.get("link", ""))
        return False

    logger.info(
        f"  [HARD-GATE] PASS — words={_pq_word_count} iocs={_pq_total_iocs} "
        f"conf={confidence:.1f} cve={_pq_has_cve} kev={_pq_has_kev}"
    )

    # -- STEP 7f: v143.0 Risk reason (defensible explanation for score) --------
    # Generated AFTER all enrichment: NVD/CVSS, KEV, EPSS, VANGUARD, APEX.
    # Stored in manifest → surfaced in API response and tactical dossier.
    try:
        risk_reason: str = risk_engine.get_risk_reason(
            risk_score,
            kev_present=kev_present,
            cvss_score=cvss_score,
            epss_score=epss_score,
            iocs=extracted_iocs,
            mitre_matches=mitre_data,
            actor_data=actor_data,
        )
        logger.info(f"  [RISK-REASON] {risk_reason[:120]}")
    except Exception as _rr_e:
        risk_reason = f"score={risk_score:.1f}"
        logger.debug(f"risk_reason generation failed (non-critical): {_rr_e}")

    # -- STEP 7g: Enterprise Intelligence Integration Layer (v1.0) -----------
    # Wires all 7 enterprise engines: AHE → RSE → DCE → IIP → MAE → NE → QGS
    # ZERO-REGRESSION: any engine failure preserves original values unchanged.
    # Hard block is issued ONLY for AHE violations (fake/fabricated intelligence).
    _ei_result = None
    try:
        import sys as _sys_eii
        _scripts_dir_eii = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
        )
        if _scripts_dir_eii not in _sys_eii.path:
            _sys_eii.path.insert(0, _scripts_dir_eii)

        from enterprise_intelligence_integrator import integrate_intelligence as _eii_fn
        _ei_result = _eii_fn(
            headline          = headline,
            enriched_content  = enriched_content,
            source_url        = source_url,
            extracted_iocs    = extracted_iocs,
            risk_score        = risk_score,
            confidence        = confidence,
            severity          = severity,
            mitre_data        = mitre_data,
            actor_data        = actor_data,
            cvss_score        = cvss_score,
            epss_score        = epss_score,
            kev_present       = kev_present,
            tlp_label         = tlp.get("label", "TLP:CLEAR"),
        )

        # Hard block: AHE detected fabricated intelligence
        if _ei_result.hard_block:
            logger.warning(
                "  [EII-BLOCK] HARD REJECT '%s': %s",
                headline[:60], _ei_result.hard_block_reason[:200],
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False

        # Surgical replacement: upgrade pipeline values with validated outputs
        extracted_iocs   = _ei_result.cleaned_iocs_dict
        ioc_counts       = enricher.get_ioc_counts(extracted_iocs)
        risk_score       = _ei_result.risk_score
        confidence       = _ei_result.confidence
        severity         = risk_engine.get_severity_label(risk_score)
        mitre_data       = _ei_result.mitre_data
        enriched_content = _ei_result.enriched_content

        logger.info(
            "  [EII] Applied: risk=%.2f conf=%.1f iocs=%d techniques=%d "
            "quality=%d/%d/%d publishable=%s",
            risk_score, confidence,
            sum(len(v) for v in extracted_iocs.values() if isinstance(v, list)),
            len(mitre_data),
            _ei_result.quality_passed,
            _ei_result.quality_failed,
            _ei_result.quality_warned,
            _ei_result.publishable,
        )

    except Exception as _eii_outer_e:
        logger.debug(
            "  [EII] Integration layer unavailable (non-fatal) — "
            "continuing with original values: %s", _eii_outer_e
        )

    # -- STEP 7h: OMEGA IOC Graph Intelligence Layer (v1.0) ------------------
    _ioc_graph = None
    try:
        import sys as _sys_iocg
        _scripts_dir_iocg = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
        )
        if _scripts_dir_iocg not in _sys_iocg.path:
            _sys_iocg.path.insert(0, _scripts_dir_iocg)
        from omega_ioc_graph_layer import enrich_ioc_graph as _iocg_fn
        _ioc_graph = _iocg_fn(
            iocs_dict=extracted_iocs,
            headline=headline,
            severity=severity,
            risk_score=risk_score,
            api_tier="PRO",
        )
        if _ioc_graph and _ioc_graph.ioc_graph_intel.get("status") != "ENRICHMENT_FAILED":
            extracted_iocs = _ioc_graph.enriched_iocs
            ioc_counts = enricher.get_ioc_counts(extracted_iocs)
            if _ioc_graph.risk_delta > 0:
                risk_score = min(10.0, risk_score + _ioc_graph.risk_delta)
                severity   = risk_engine.get_severity_label(risk_score)
            logger.info(
                "  [IOC-GRAPH] Enriched %d IOC(s) | malicious=%d suspicious=%d "
                "risk_delta=+%.2f high_value=%d",
                _ioc_graph.total_enriched,
                _ioc_graph.malicious_count,
                _ioc_graph.suspicious_count,
                _ioc_graph.risk_delta,
                len(_ioc_graph.high_value_iocs),
            )
        else:
            logger.debug("  [IOC-GRAPH] Enrichment returned failed status — preserving original values")
    except Exception as _iocg_e:
        logger.debug("  [IOC-GRAPH] Integration unavailable (non-fatal): %s", _iocg_e)

    # -- STEP 7i: OMEGA-P5 — Persistent Campaign Memory Graph ----------------
    _campaign_graph_intel: Optional[dict] = None
    if _CAMPAIGN_GRAPH_OK and _campaign_graph is not None:
        try:
            # Build advisory dict for graph ingestion
            _advisory_item = {
                "id":          stix_id if "stix_id" in dir() else "",
                "title":       headline,
                "description": enriched_content[:2000],
                "severity":    severity,
                "risk_score":  risk_score,
                "confidence":  confidence,
                "iocs":        extracted_iocs,
                "mitre":       mitre_data,
                "actor":       actor_data or {},
                "source":      source_url,
                "feed_source": feed_source,
                "published":   "",
            }
            _campaign_graph.ingest_advisory(_advisory_item)

            # Build mini-report scoped to this advisory's actors/TTPs/IOCs
            _actors_here  = [t.get("actor", "") for t in [actor_data or {}] if t.get("actor")]
            _ttps_here    = [t.get("id", "") for t in mitre_data[:6]]
            _iocs_flat    = [v for vals in extracted_iocs.values() for v in vals[:3]]

            _cg_report = generate_campaign_graph_report(_campaign_graph)
            _top_camps  = _cg_report.get("top_active_campaigns", [])[:3]
            _top_actors = _cg_report.get("actor_evolution_timelines", [])[:3]
            _infra      = _cg_report.get("infrastructure_reuse_clusters", [])[:3]
            _stats      = _cg_report.get("graph_stats", {})

            _campaign_graph_intel = {
                "status":                "ENRICHED",
                "graph_nodes":           _stats.get("total_nodes", _stats.get("advisory_nodes", 0) + _stats.get("actor_nodes", 0)),
                "graph_edges":           _stats.get("total_edges", 0),
                "total_advisories":      _stats.get("advisory_nodes", 0),
                "top_active_campaigns":  _top_camps,
                "actor_timelines":       _top_actors,
                "infrastructure_clusters": _infra,
                "sector_heatmap":        _cg_report.get("sector_targeting_heatmap", _cg_report.get("sector_targeting_heatmap", {})),
            }
            logger.info(
                "  [CAMPAIGN-GRAPH] Nodes=%d Edges=%d Advisories=%d Campaigns=%d",
                _stats.get("total_nodes", _stats.get("advisory_nodes", 0) + _stats.get("actor_nodes", 0)),
                _stats.get("total_edges", 0),
                _stats.get("nodes_advisory", 0),
                len(_top_camps),
            )
        except Exception as _cg_e:
            logger.debug("  [CAMPAIGN-GRAPH] Integration error (non-fatal): %s", _cg_e)
            _campaign_graph_intel = None

    # -- STEP 8: Premium report generation -----------------------------------
    logger.info("  -> Generating PREMIUM 16-section report...")
    try:
        report_html = premium_report_gen.generate_premium_report(
            headline=headline, source_content=enriched_content, source_url=source_url,
            iocs=extracted_iocs, risk_score=risk_score, severity=severity,
            confidence=confidence, tlp=tlp, mitre_data=mitre_data, actor_data=actor_data,
            sigma_rule=sigma_rule, yara_rule=yara_rule,
            kql_rule=kql_rule, spl_rule=spl_rule, eql_rule=eql_rule,
            suricata_rule=suricata_rule, snort_rule=snort_rule,
            defender_query=defender_query,
            fetched_article=fetched_article, impact_metrics=impact_metrics,
            ioc_graph_intel=_ioc_graph.ioc_graph_intel if _ioc_graph else None,
            executive_intel=_apex_data if _apex_data else None,
            campaign_graph_intel=_campaign_graph_intel,
        )
    except Exception as _rpt_e:
        logger.warning(f"  -> Report generation failed (non-critical): {_rpt_e}")
        report_html = f"<h2>{headline}</h2><p>{enriched_content[:500]}</p>"

    # -- STEP 8b: Report Quality Gate ----------------------------------------
    _html_text_only = re.sub(r"<[^>]+>", " ", report_html)
    _report_wc = len(_html_text_only.split())
    JUNK_CHARS_SET = set('`][|~;{}\\^@#&*!?><')
    _junk_in_report = sum(1 for c in _html_text_only[:3000] if c in JUNK_CHARS_SET)
    _junk_ratio = _junk_in_report / max(len(_html_text_only[:3000]), 1)
    _quality_failures = []
    if _report_wc < 300:
        _quality_failures.append(f"too short ({_report_wc} words, min=300)")
    if _junk_ratio > 0.08:
        _quality_failures.append(f"junk chars ({_junk_ratio:.2%})")
    if _quality_failures:
        logger.warning(f"  [QUALITY-GATE] Report weak for '{headline[:50]}': {'; '.join(_quality_failures)} — continuing with basic report")
        # v134.0: DO NOT send to pending queue. Proceed with basic STIX entry.

    # -- STEP 9: Smart labels ------------------------------------------------
    labels = _generate_smart_labels(headline, severity, tlp, feed_source, extracted_iocs)

    # =========================================================================
    # STEP 10: WRITE STIX BUNDLE DIRECTLY (R2-ONLY PATH)
    # v134.0: No Blogger. No queue. STIX written unconditionally.
    # =========================================================================
    try:
        # v1.0 EII: Merge enterprise enrichment into STIX metadata
        # v161.0 FIX-B: Derive canonical blog_url from headline slug
        def _slugify(text):
            import re as _re
            s = _re.sub(r"[^\w\s-]", "", text.lower())
            return _re.sub(r"[\s_-]+", "-", s).strip("-")[:80]
        _headline_slug = _slugify(headline)
        _blog_url = f"https://blog.cyberdudebivash.in/{_headline_slug}/"
        # v161.0 FIX-C: dossier_url points to the per-report dossier JSON
        _report_slug = _slugify(headline)
        _dossier_url = f"https://intel.cyberdudebivash.com/dossiers/{_report_slug}.json"
        # v161.0 FIX-D: EPSS sanity check before manifest write
        def _epss_sane(epss, cvss):
            if epss is None or cvss is None:
                return epss
            try:
                ep, cv = float(epss), float(cvss)
            except (TypeError, ValueError):
                return epss
            if cv < 7.0 and ep > 75.0:
                return round(min(cv / 10.0 * 60.0, 75.0), 2)
            if cv < 4.0 and ep > 40.0:
                return round(min(cv / 10.0 * 40.0, 40.0), 2)
            return epss
        epss_score = _epss_sane(epss_score, cvss_score)
        _stix_metadata = {
            "blog_url":    _blog_url,
            "source_url":  source_url,
            "dossier_url": _dossier_url,
            "risk_reason": risk_reason,   # v143.0: defensible score explanation
        }
        if _ei_result and _ei_result.enterprise_enrichment:
            _stix_metadata["enterprise_enrichment"] = _ei_result.enterprise_enrichment
        if _ioc_graph and _ioc_graph.ioc_graph_intel.get("status") != "ENRICHMENT_FAILED":
            _stix_metadata["ioc_graph_intel"] = _ioc_graph.ioc_graph_intel
        if _campaign_graph_intel and _campaign_graph_intel.get("status") == "ENRICHED":
            _stix_metadata["campaign_graph_intel"] = _campaign_graph_intel

        stix_exporter.create_bundle(
            title=headline,
            iocs=extracted_iocs,
            risk_score=risk_score,
            metadata=_stix_metadata,
            confidence=confidence,
            severity=severity,
            tlp_label=tlp.get("label", "TLP:CLEAR"),
            ioc_counts=ioc_counts,
            actor_tag=actor_data.get("tracking_id", "UNC-CDB-99"),
            mitre_tactics=mitre_data,
            feed_source=feed_source,
            epss_score=epss_score,
            cvss_score=cvss_score,
            kev_present=kev_present,
            nvd_url=nvd_url,
            apex_data=_apex_data if _apex_data else None,
            # v142.0 P0 TIMESTAMP FIX: pass original RSS <pubDate> so dedup fingerprint is stable
            published_at=_source_published_at,
        )
        dedup_engine.mark_processed(headline, entry.get("link", ""))
        logger.info(f"  [OK] STIX bundle written \u2192 R2 pipeline | {severity} | Risk={risk_score:.1f}")
        return True
    except Exception as stix_err:
        logger.error(f"  [FAIL] STIX bundle write failed: {stix_err}")
        return False


# ==============================================================================
# CVE METADATA ENRICHMENT
# ==============================================================================

def _enrich_cve_metadata(cve_id: str):
    """
    Fetch EPSS, CVSS base score, and KEV status for a CVE.
    Returns (epss_score, cvss_score, kev_present, nvd_url) — all non-critical.
    """
    cve_upper  = cve_id.upper().strip()
    epss_score = None
    cvss_score = None
    kev_present = False
    nvd_url    = f"https://nvd.nist.gov/vuln/detail/{cve_upper}"

    # KEV/EPSS GUARD: reject malformed CVE IDs before any API call.
    # Prevents non-CVE items (tool names, MITRE tags) from being flagged KEV.
    if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_upper):
        logger.warning(f"_enrich_cve_metadata: invalid CVE format '{cve_upper}' — skipping")
        return None, None, False, f"https://nvd.nist.gov/vuln/search/results?query={cve_upper}"

    # EPSS lookup
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_upper}"
        req = urllib.request.Request(url, headers={"User-Agent": "CDB-Sentinel/111.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        if data.get("data"):
            epss_score = round(float(data["data"][0].get("epss", 0)) * 100, 2)
    except Exception:
        pass

    # NVD CVSS lookup
    try:
        nvd_key = os.getenv("NVD_API_KEY", "")
        headers = {"User-Agent": "CDB-Sentinel/111.0"}
        if nvd_key:
            headers["apiKey"] = nvd_key
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        vuln    = data.get("vulnerabilities", [{}])[0].get("cve", {})
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                if cvss_score:
                    break
    except Exception:
        pass

    # CISA KEV check (via VANGUARD or local cache)
    try:
        from agent.v48_pipeline_hardening.kev_checker import check_kev
        kev_present = check_kev(cve_upper)
    except Exception:
        pass

    return epss_score, cvss_score, kev_present, nvd_url


# ==============================================================================
# SMART LABEL GENERATION
# ==============================================================================

def _generate_smart_labels(
    headline: str, severity: str, tlp: Dict,
    feed_source: str, iocs: Dict
) -> List[str]:
    """Generate contextual taxonomy labels for STIX bundle tagging."""
    labels = ["Threat Intelligence", "CyberDudeBivash", severity,
              tlp.get("label", "TLP:CLEAR"), "Sentinel APEX"]
    text = headline.lower()
    threat_map = {
        "ransomware":   "Ransomware",       "malware":        "Malware Analysis",
        "phishing":     "Phishing",         "cve":            "Vulnerability",
        "exploit":      "Exploit",          "apt":            "APT",
        "supply chain": "Supply Chain",     "zero-day":       "Zero-Day",
        "0-day":        "Zero-Day",         "data breach":    "Data Breach",
        "ddos":         "DDoS",             "botnet":         "Botnet",
        "nation state": "Nation-State",     "critical infra": "Critical Infrastructure",
    }
    for keyword, label in threat_map.items():
        if keyword in text and label not in labels:
            labels.append(label)

    # IOC-type labels
    if isinstance(iocs, dict):
        for ioc_type, ioc_list in iocs.items():
            if ioc_list and f"IOC:{ioc_type.upper()}" not in labels:
                labels.append(f"IOC:{ioc_type.upper()}")

    # Feed source label
    if feed_source and feed_source not in labels:
        labels.append(feed_source)

    return list(dict.fromkeys(labels))  # deduplicate, preserve order


if __name__ == "__main__":
    count = main()
