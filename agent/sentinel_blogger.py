#!/usr/bin/env python3
"""
sentinel_blogger.py — CyberDudeBivash SENTINEL APEX v134.0 (R2-NATIVE / BLOGGER-FREE)
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
from agent.mitre_mapper import mitre_engine
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

            entries.append({
                "title":     entry.get("title", "Untitled Advisory"),
                "content":   content,
                "summary":   summary,
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
CVE_EPSS_EXCEPTION = 0.7


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
    act_exp = any(s in title.lower() for s in ["actively exploited", "in the wild"])

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
        if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
            logger.info(f"  SKIP (duplicate): {entry['title'][:60]}")
            continue

        if _manifest and dedup_engine.is_similar_in_manifest(
                entry["title"], _manifest, threshold=0.80):
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

        try:
            result = process_entry(entry, feed_source="CDB-NEWS")
        except Exception as _pe:
            logger.error(f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}")
            result = False
        if result:
            published_count += 1
        time.sleep(RATE_LIMIT_DELAY)

    # -- PHASE 2: Multi-Feed Fusion ------------------------------------------
    logger.info("--- PHASE 2: Multi-Feed Intelligence Fusion ---")

    for feed_url in RSS_FEEDS:
        _feed_start = time.monotonic()
        entries = fetch_feed_entries(feed_url, max_entries=MAX_ENTRIES_PER_FEED)
        _feed_elapsed = time.monotonic() - _feed_start
        logger.info(f"Feed [{feed_url[:60]}]: {len(entries)} entries")
        if _TELEMETRY_OK and _telemetry:
            _telemetry.record_feed_fetch(feed_url, _feed_elapsed, success=len(entries) > 0)

        for entry in entries:
            time.sleep(RATE_LIMIT_DELAY)

            if dedup_engine.is_duplicate(entry["title"], entry.get("link", "")):
                logger.info(f"  SKIP (duplicate): {entry['title'][:60]}")
                continue

            if _manifest and dedup_engine.is_similar_in_manifest(
                    entry["title"], _manifest, threshold=0.80):
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

            try:
                result = process_entry(entry, feed_source=feed_url[:30])
            except Exception as _pe:
                logger.error(f"  [CRASH-GUARD] process_entry failed for '{entry['title'][:60]}': {_pe}")
                result = False
            if result:
                published_count += 1

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
                status="success" if published_count >= 0 else "partial",
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
    headline   = entry["title"]
    source_url = entry.get("link", "")

    logger.info(f"PROCESSING: {headline[:80]}")

    # -- STEP 1: Source article -----------------------------------------------
    fetched_article  = enrich_with_source_content(entry)
    enriched_content = build_enriched_content(entry, fetched_article)
    logger.info(f"  -> Content: {len(enriched_content.split())} words")

    # -- STEP 2: IOC extraction -----------------------------------------------
    extracted_iocs = enricher.extract_iocs(enriched_content)
    ioc_counts     = enricher.get_ioc_counts(extracted_iocs)
    total_iocs     = sum(ioc_counts.values())
    logger.info(f"  -> IOCs: {total_iocs} across {sum(1 for v in extracted_iocs.values() if v)} categories")

    # -- STEP 3: MITRE ATT&CK mapping -----------------------------------------
    full_corpus = f"{headline} {enriched_content}"
    mitre_data  = mitre_engine.map_threat(full_corpus)
    logger.info(f"  -> MITRE techniques: {len(mitre_data)}")

    # -- STEP 4: Actor attribution -------------------------------------------
    actor_data  = actor_matrix.correlate_actor(full_corpus, extracted_iocs)
    actor_mapped = actor_data.get("tracking_id", "").startswith("CDB-")

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

    # -- STEP 7: Detection engineering ----------------------------------------
    sigma_rule = detection_engine.generate_sigma_rule(headline, extracted_iocs)
    yara_rule  = detection_engine.generate_yara_rule(headline, extracted_iocs)

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

    if not (_pq_has_cve or _pq_has_kev):
        if _pq_word_count < _PQ_WORD_FLOOR:
            logger.warning(
                f"  [HARD-GATE] REJECT '{headline[:60]}': "
                f"insufficient content ({_pq_word_count} words < {_PQ_WORD_FLOOR} floor, "
                f"no CVE/KEV exemption)"
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False

        if _pq_total_iocs == 0:
            logger.warning(
                f"  [HARD-GATE] REJECT '{headline[:60]}': "
                f"zero IOCs extracted (no CVE/KEV exemption)"
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False

        if confidence < _PQ_CONF_FLOOR:
            logger.warning(
                f"  [HARD-GATE] REJECT '{headline[:60]}': "
                f"confidence {confidence:.1f} < {_PQ_CONF_FLOOR} floor "
                f"(no CVE/KEV exemption)"
            )
            dedup_engine.mark_processed(headline, entry.get("link", ""))
            return False

    logger.info(
        f"  [HARD-GATE] PASS — words={_pq_word_count} iocs={_pq_total_iocs} "
        f"conf={confidence:.1f} cve={_pq_has_cve} kev={_pq_has_kev}"
    )

    # -- STEP 8: Premium report generation -----------------------------------
    logger.info("  -> Generating PREMIUM 16-section report...")
    try:
        report_html = premium_report_gen.generate_premium_report(
            headline=headline, source_content=enriched_content, source_url=source_url,
            iocs=extracted_iocs, risk_score=risk_score, severity=severity,
            confidence=confidence, tlp=tlp, mitre_data=mitre_data, actor_data=actor_data,
            sigma_rule=sigma_rule, yara_rule=yara_rule,
            fetched_article=fetched_article, impact_metrics=impact_metrics,
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
        stix_exporter.create_bundle(
            title=headline,
            iocs=extracted_iocs,
            risk_score=risk_score,
            metadata={"blog_url": "", "source_url": source_url},
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
        )
        dedup_engine.mark_processed(headline, entry.get("link", ""))
        logger.info(f"  [OK] STIX bundle written → R2 pipeline | {severity} | Risk={risk_score:.1f}")
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
        "ransomware":    "Ransomware",      "malware":       "Malware Analysis",
        "phishing":      "Phishing",        "cve":           "CVE Advisory",
        "vulnerability": "Vulnerability",   "breach":        "Data Breach",
        "zero-day":      "Zero-Day",        "exploit":       "Exploit Analysis",
        "apt":           "APT",             "supply chain":  "Supply Chain",
        "backdoor":      "Backdoor",        "trojan":        "Trojan",
        "botnet":        "Botnet",          "windows":       "Windows Security",
        "microsoft":     "Microsoft",       "linux":         "Linux Security",
    }
    for keyword, label in threat_map.items():
        if keyword in text:
            labels.append(label)
    if iocs.get("cve"):
        labels.append("CVE Analysis")
    if iocs.get("sha256") or iocs.get("md5"):
        labels.append("IOC Report")
    return list(dict.fromkeys(labels))[:10]


if __name__ == "__main__":
    count = main()
    # Exit 0 always — pipeline continues even if 0 new entries (dedup is valid)
    sys.exit(0)
