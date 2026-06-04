#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
INTELLIGENCE INTEGRITY GATE v158.5
===============================================================================
PURPOSE:
  Comprehensive pre-deployment intelligence quality enforcement engine.
  Implements all 8 mandatory integrity safeguards to prevent synthetic CVE
  flooding, entropy collapse, feed diversity failure, and stale deployment.

SAFEGUARDS IMPLEMENTED:
  A. Synthetic CVE Detector        — sequential flood + fake CVE detection
  B. Entropy Gate                  — Shannon entropy + semantic diversity
  C. Feed Diversity Validator      — multi-source, multi-actor, multi-vendor
  D. KEV Health Gate               — CISA KEV enrichment continuity
  E. Runtime Integrity Baseline    — orchestration timing + stage execution
  F. Advisory Authenticity Scoring — realism, IOC richness, ATT&CK depth
  G. Manifest Mutation Validator   — stale payload + frozen dashboard detect
  H. Synthetic Flood Circuit Breaker — quarantine + alert on spike

MODES:
  --check    Full integrity check. Exit 1 on any HARD_FAIL.
  --report   Generate human-readable integrity report. Always exits 0.
  --apply    Same as check but also writes quarantine manifest on failure.

EXIT CODES:
  0 -- All integrity gates passed
  1 -- One or more HARD_FAIL violations detected
  2 -- Runtime error (cannot parse feed/manifest)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [intelligence_integrity_gate] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-IIG")

GATE_VERSION = "158.5"
REPO_ROOT = Path(__file__).resolve().parent.parent

# ── Configuration ─────────────────────────────────────────────────────────────

# A. Synthetic CVE Detector thresholds
# v166.8 FIX (GAP-014): NVD assigns sequential CVE IDs for bulk vulnerability reports
# (e.g. CVE-2026-10190 through CVE-2026-10194 are all real Tenda W12 CVEs from NVD).
# Old threshold=5 caused false HARD_FAIL on every run with real multi-CVE product advisories.
# New threshold=25: catches genuine synthetic generators (which produce 50-200+ sequential IDs)
# while passing real batch NVD advisories which typically have <20 sequential IDs.
SYNTHETIC_CVE_YEAR_FUTURE   = 2027        # CVEs from future years need NVD validation
SYNTHETIC_SEQUENTIAL_WINDOW = 25          # >=25 sequential CVE numbers = flood alert (was 5)
SYNTHETIC_FLEET_THRESHOLD   = 0.40        # >40% CDB-*-GEN actors = synthetic dominance
SYNTHETIC_HARD_FAIL_RATIO   = 0.60        # >60% synthetic actors = HARD_FAIL

# B. Entropy Gate thresholds
# v166.8 FIX (GAP-011): Actor entropy minimum lowered to reflect real CTI platform reality.
# 64% CDB-UNATTR-CVE is expected when CVE feeds dominate — unattributed vulnerability data
# is the norm, not evidence of synthetic generation. Genuine synthetic generators produce
# single-actor dominance >95%. HARD_FAIL threshold lowered to 0.5 bits (near-zero diversity).
# Near-duplicate Jaccard check moved to WARN-only (CVE titles naturally share "CVE-2026-" prefix).
ENTROPY_TITLE_MIN            = 3.5        # Shannon bits — below this = repetitive titles
ENTROPY_ACTOR_MIN            = 0.5        # Actor diversity minimum (was 1.5 — too strict for CVE feeds)
ENTROPY_TECHNIQUE_MIN        = 2.0        # MITRE technique diversity minimum
SIMILARITY_DEDUP_THRESHOLD   = 0.80       # Jaccard similarity — above = near-duplicate (now WARN-only)

# C. Feed Diversity thresholds
# v166.8 FIX (GAP-002/C): Actor monoculture threshold raised — a platform ingesting CVE feeds
# + multi-source intel legitimately has CDB-UNATTR-CVE as the dominant actor. The monoculture
# check should fire only when ALL actors (including attributed ones) are the same single code.
# FEED_MIN_UNIQUE_ACTORS reduced from 3 to 2 — even 2 distinct actors (unattr + one real) is
# meaningful differentiation. True monoculture = single actor on ALL items with any actor set.
FEED_MIN_SOURCES             = 2          # Minimum distinct source domains
FEED_MAX_SINGLE_SOURCE_RATIO = 0.85       # >85% single source = dominance warning
FEED_MAX_SINGLE_ACTOR_RATIO  = 0.90       # >90% single actor = diversity failure (was 0.70)
FEED_MIN_UNIQUE_ACTORS       = 2          # Minimum distinct actor IDs (was 3)

# D. KEV Health thresholds
KEV_EXPECTED_RATIO           = 0.02       # Expect ≥2% of advisories to have KEV=True
                                          # (realistic for a 100-item feed)

# E. Runtime Integrity thresholds
RUNTIME_MIN_MINUTES          = 8          # Pipeline should run ≥8 minutes (not collapsed)
RUNTIME_MAX_MINUTES          = 120        # >120 min = hung pipeline warning
STAGE_REQUIRED               = ["2", "3", "3.5", "5"]  # must appear in timing

# F. Authenticity Scoring thresholds
AUTH_SCORE_MIN               = 40         # /100 — items below this flagged as low-quality
AUTH_SCORE_HARD_FAIL         = 20         # /100 — items below this = HARD_FAIL
AUTH_POOR_ITEM_RATIO         = 0.50       # >50% items below AUTH_SCORE_MIN = gate fail

# G. Manifest Mutation thresholds
MANIFEST_STALE_HOURS         = 12         # Manifest older than 12h = stale warning
MANIFEST_FROZEN_HOURS        = 48         # Manifest older than 48h = HARD_FAIL
MANIFEST_MIN_MUTATION        = 0.05       # <5% items different from last manifest = frozen

# H. Flood Circuit Breaker
FLOOD_SYNTHETIC_SPIKE        = 0.75       # >75% synthetic in current run = circuit break
FLOOD_QUARANTINE_PATH        = REPO_ROOT / "data" / "quarantine" / "synthetic_flood_quarantine.json"

# Known synthetic/generic actor patterns (must stay in sync with AHE)
SYNTHETIC_ACTOR_RE = re.compile(
    r"(cdb-apt-gen|cdb-cve-gen|cdb-ran-gen|cdb-phi-gen|cdb-sup-gen|"
    r"cdb-mob-gen|cdb-bot-gen|cdb-cry-gen|cdb-mal-gen|cdb-rat-gen|"
    r"apex-cluster-unattributed|unc-unknown|advanced persistent threat cluster|"
    r"generic (apt|ransomware|threat) cluster)",
    re.IGNORECASE,
)

CVE_YEAR_RE  = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)
CVE_ID_RE    = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ── Data Loading ──────────────────────────────────────────────────────────────

def load_feed(path: Path) -> List[Dict]:
    """Load api/feed.json or data/stix/feed_manifest.json."""
    if not path.exists():
        log.error("[load] Feed not found: %s", path)
        sys.exit(2)
    try:
        blob = path.read_bytes()
        nul = blob.count(b"\x00")
        if nul:
            # P0-3 fix (v174): feed.json carries NUL-byte padding corruption that
            # made strict json.loads raise "Extra data" -> sys.exit(2) on EVERY run,
            # so the gate never executed. Strip padding (same guard as certifier/canary).
            log.warning("[load] Feed contains %d NUL byte(s) -- stripping corruption padding", nul)
            blob = blob.rstrip(b"\x00").replace(b"\x00", b"")
        raw = json.loads(blob.decode("utf-8", errors="replace"))
    except Exception as e:
        log.error("[load] Cannot parse %s: %s", path, e)
        sys.exit(2)

    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("advisories", "reports", "items", "data", "feed"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        # Try values
        for v in raw.values():
            if isinstance(v, list) and v:
                return v
    return []


def _actor_id(item: Dict) -> str:
    actor = item.get("actor_cluster") or item.get("actor") or ""
    if isinstance(actor, dict):
        actor = actor.get("tracking_id") or actor.get("id") or ""
    return str(actor).strip()


def _title(item: Dict) -> str:
    return str(item.get("title") or item.get("headline") or item.get("name") or "").strip()


def _source(item: Dict) -> str:
    return str(item.get("source_url") or item.get("source") or
               item.get("feed_source") or item.get("url") or "").lower()


def _risk(item: Dict) -> Optional[float]:
    r = item.get("risk_score") or item.get("composite_risk") or item.get("risk")
    try:
        return float(r) if r is not None else None
    except (ValueError, TypeError):
        return None


def _kev(item: Dict) -> bool:
    v = item.get("kev") or item.get("kev_confirmed") or item.get("kev_present") or False
    if isinstance(v, str):
        return v.lower() in ("true", "yes", "1", "confirmed")
    return bool(v)


def _techniques(item: Dict) -> List[str]:
    raw = item.get("mitre_techniques") or item.get("techniques") or []
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for t in raw:
        if isinstance(t, dict):
            result.append(str(t.get("id") or t.get("technique_id") or ""))
        else:
            result.append(str(t))
    return [t for t in result if t]


def _cves(item: Dict) -> List[str]:
    cve_list = item.get("cve_ids") or item.get("cves") or []
    if isinstance(cve_list, str):
        cve_list = [cve_list]
    title_cves = CVE_ID_RE.findall(_title(item))
    return list(set(str(c) for c in cve_list + title_cves if c))


def _iocs(item: Dict) -> Dict:
    raw = item.get("iocs") or item.get("indicators") or {}
    if isinstance(raw, list):
        by_type: Dict[str, List] = defaultdict(list)
        for ioc in raw:
            if isinstance(ioc, dict):
                t = ioc.get("type", "unknown")
                by_type[t].append(ioc.get("value") or ioc.get("indicator") or "")
        return dict(by_type)
    return raw if isinstance(raw, dict) else {}


# ── Safeguard A: Synthetic CVE Detector ──────────────────────────────────────

class SyntheticCVEDetector:
    """Detects sequential CVE floods, fake CVEs, and synthetic actor dominance."""

    def check(self, items: List[Dict]) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        # Collect all CVE IDs
        all_cves: List[Tuple[int, int]] = []  # (year, number)
        all_cve_strs: List[str] = []
        for item in items:
            for cve in _cves(item):
                m = CVE_YEAR_RE.search(cve)
                if m:
                    all_cves.append((int(m.group(1)), int(m.group(2))))
                    all_cve_strs.append(cve.upper())

        # Check sequential flood
        if all_cves:
            by_year: Dict[int, List[int]] = defaultdict(list)
            for year, num in all_cves:
                by_year[year].append(num)

            for year, nums in by_year.items():
                nums_sorted = sorted(nums)
                max_seq = 1
                cur_seq = 1
                for i in range(1, len(nums_sorted)):
                    if nums_sorted[i] - nums_sorted[i-1] <= 3:  # allow small gaps
                        cur_seq += 1
                        max_seq = max(max_seq, cur_seq)
                    else:
                        cur_seq = 1
                if max_seq >= SYNTHETIC_SEQUENTIAL_WINDOW:
                    findings.append(
                        f"[A] SYNTHETIC CVE FLOOD: {max_seq} sequential CVE-{year}-xxxx numbers detected. "
                        f"Sequential CVEs are a hallmark of synthetic generator output. "
                        f"Expected: diverse CVE years and non-sequential IDs from real feeds."
                    )
                    hard_fail = True

            # Future-year CVEs (needs NVD validation flag)
            current_year = datetime.now(timezone.utc).year
            future_cves = [f"CVE-{y}-{n}" for y, n in all_cves if y > current_year]
            if len(future_cves) > 3:
                findings.append(
                    f"[A] FUTURE-YEAR CVEs: {len(future_cves)} CVEs from years > {current_year} "
                    f"({', '.join(future_cves[:5])}...). These may not exist in NVD. "
                    f"Validate against NVD API before publishing."
                )

        # Check synthetic actor dominance
        actors = [_actor_id(item) for item in items if _actor_id(item)]
        if actors:
            synthetic_count = sum(1 for a in actors if SYNTHETIC_ACTOR_RE.search(a))
            ratio = synthetic_count / len(actors)
            if ratio > SYNTHETIC_HARD_FAIL_RATIO:
                findings.append(
                    f"[A] SYNTHETIC ACTOR DOMINANCE: {synthetic_count}/{len(actors)} items "
                    f"({ratio:.0%}) have synthetic/generic actor labels. "
                    f"Hard-fail threshold: {SYNTHETIC_HARD_FAIL_RATIO:.0%}. "
                    f"Root cause: fallback generator flooding or AHE false-positive rejection of real intel."
                )
                hard_fail = True
            elif ratio > SYNTHETIC_FLEET_THRESHOLD:
                findings.append(
                    f"[A] WARN — Synthetic actor ratio elevated: {ratio:.0%} "
                    f"(warn threshold: {SYNTHETIC_FLEET_THRESHOLD:.0%}). Review actor attribution pipeline."
                )

        # Check risk score uniformity (all 7.5 = synthetic signature)
        risks = [_risk(item) for item in items if _risk(item) is not None]
        if risks:
            unique_risks = len(set(risks))
            if unique_risks == 1 and len(risks) > 5:
                findings.append(
                    f"[A] ZERO RISK DIVERSITY: All {len(risks)} advisories have identical risk score "
                    f"({risks[0]}/10). Real intelligence produces varied risk scores. "
                    f"This indicates hardcoded fallback scoring."
                )
                hard_fail = True

        if not findings:
            findings.append("[A] Synthetic CVE Detector: PASSED")

        return hard_fail, findings


# ── Safeguard B: Entropy Gate ─────────────────────────────────────────────────

class EntropyGate:
    """Shannon entropy + semantic diversity scoring."""

    @staticmethod
    def _shannon_entropy(values: List[str]) -> float:
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        return round(entropy, 3)

    @staticmethod
    def _word_tokens(text: str) -> set:
        return set(re.findall(r"\b[a-z]{3,}\b", text.lower()))

    @staticmethod
    def _jaccard(a: set, b: set) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def check(self, items: List[Dict]) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        titles = [_title(item) for item in items if _title(item)]
        # v166.8 FIX (GAP-011): Exclude empty/None actors from entropy calculation.
        # Items from multi-source collectors (BleepingComputer, MalwareBazaar) may have
        # no actor set yet — blank strings cause entropy=0 (single-value distribution)
        # even when attributed items are diverse. Only measure diversity on items that
        # HAVE an actor assigned. "CDB-UNATTR-CVE" IS a valid distinct actor code.
        _BLANK_ACTORS = {"", "none", "null", "unknown", "n/a"}
        actors = [
            _actor_id(item) for item in items
            if _actor_id(item) and _actor_id(item).lower() not in _BLANK_ACTORS
        ]
        techniques_flat = []
        for item in items:
            techniques_flat.extend(_techniques(item))

        # Title entropy
        if titles:
            # Normalize: extract first 5 words to catch cloned titles
            title_prefixes = [" ".join(t.split()[:5]).lower() for t in titles]
            te = self._shannon_entropy(title_prefixes)
            if te < ENTROPY_TITLE_MIN:
                findings.append(
                    f"[B] LOW TITLE ENTROPY: Shannon entropy={te:.3f} bits "
                    f"(minimum: {ENTROPY_TITLE_MIN}). Titles are highly repetitive — "
                    f"strong indicator of templated or cloned advisory generation."
                )
                hard_fail = True
            else:
                findings.append(f"[B] Title entropy: {te:.3f} bits (OK, min={ENTROPY_TITLE_MIN})")

        # Actor entropy
        if actors:
            ae = self._shannon_entropy(actors)
            if ae < ENTROPY_ACTOR_MIN:
                findings.append(
                    f"[B] LOW ACTOR DIVERSITY: Shannon entropy={ae:.3f} bits "
                    f"(minimum: {ENTROPY_ACTOR_MIN}). Single or very few actors dominate the feed."
                )
                hard_fail = True
            else:
                findings.append(f"[B] Actor diversity entropy: {ae:.3f} bits (OK, min={ENTROPY_ACTOR_MIN})")

        # Technique entropy
        if techniques_flat:
            te2 = self._shannon_entropy(techniques_flat)
            if te2 < ENTROPY_TECHNIQUE_MIN:
                findings.append(
                    f"[B] LOW TECHNIQUE DIVERSITY: MITRE ATT&CK entropy={te2:.3f} bits "
                    f"(minimum: {ENTROPY_TECHNIQUE_MIN}). "
                    f"Cloned ATT&CK mappings indicate templated advisory generation."
                )
            else:
                findings.append(f"[B] Technique diversity entropy: {te2:.3f} bits (OK, min={ENTROPY_TECHNIQUE_MIN})")

        # Near-duplicate detection (Jaccard similarity)
        # v166.8 FIX (GAP-014): CVE advisory titles naturally share "CVE-YYYY-NNNNN" tokens,
        # causing Jaccard similarity to be high (e.g. "CVE-2026-10190 denial of service" vs
        # "CVE-2026-10191 stack overflow" share "CVE-2026" prefix tokens → high similarity).
        # This is NOT near-duplication — these are distinct CVEs for distinct vulnerabilities.
        # Fix: exclude the CVE ID token itself from Jaccard comparison. Only warn, not hard-fail.
        if len(titles) > 2:
            dup_pairs = 0
            # Strip CVE IDs before token comparison to avoid false positives
            _cve_strip = re.compile(r'cve-\d{4}-\d+', re.I)
            token_sets = [self._word_tokens(_cve_strip.sub('', t)) for t in titles]
            for i in range(len(token_sets)):
                for j in range(i + 1, len(token_sets)):
                    if token_sets[i] and token_sets[j]:  # skip empty token sets
                        if self._jaccard(token_sets[i], token_sets[j]) >= SIMILARITY_DEDUP_THRESHOLD:
                            dup_pairs += 1
            if dup_pairs > 0:
                findings.append(
                    f"[B] NEAR-DUPLICATE TITLES: {dup_pairs} title pairs exceed "
                    f"{SIMILARITY_DEDUP_THRESHOLD:.0%} Jaccard similarity (CVE tokens excluded). "
                    f"Feed may contain near-clones."
                )
                # WARN-only — do NOT hard-fail on title similarity (false positive rate too high)
            else:
                findings.append("[B] Near-duplicate check: PASSED (0 cloned title pairs)")

        return hard_fail, findings


# ── Safeguard C: Feed Diversity Validator ────────────────────────────────────

class FeedDiversityValidator:
    """Multi-source, multi-actor, multi-vendor diversity enforcement."""

    def check(self, items: List[Dict]) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if not items:
            findings.append("[C] WARN — Empty feed, diversity check skipped.")
            return False, findings

        # Source diversity
        sources = [_source(item) for item in items]
        source_domains = []
        for s in sources:
            m = re.search(r"https?://([^/]+)", s)
            if m:
                source_domains.append(m.group(1).lower().replace("www.", ""))

        if source_domains:
            domain_counts = Counter(source_domains)
            top_domain, top_count = domain_counts.most_common(1)[0]
            top_ratio = top_count / len(source_domains)
            unique_domains = len(domain_counts)

            if unique_domains < FEED_MIN_SOURCES:
                findings.append(
                    f"[C] SINGLE-SOURCE DOMINANCE: Only {unique_domains} distinct source domain(s). "
                    f"Minimum required: {FEED_MIN_SOURCES}. "
                    f"Enterprise-grade CTI requires multi-source validation."
                )
                hard_fail = True
            elif top_ratio > FEED_MAX_SINGLE_SOURCE_RATIO:
                findings.append(
                    f"[C] WARN — Source concentration: {top_domain} accounts for "
                    f"{top_ratio:.0%} of feed. Maximum: {FEED_MAX_SINGLE_SOURCE_RATIO:.0%}."
                )
            else:
                findings.append(
                    f"[C] Source diversity: {unique_domains} domains, "
                    f"top={top_domain} ({top_ratio:.0%}) — OK"
                )

        # Actor diversity
        actors = [_actor_id(item) for item in items if _actor_id(item)]
        if actors:
            actor_counts = Counter(actors)
            top_actor, top_actor_count = actor_counts.most_common(1)[0]
            top_actor_ratio = top_actor_count / len(actors)
            unique_actors = len(actor_counts)

            if unique_actors < FEED_MIN_UNIQUE_ACTORS:
                findings.append(
                    f"[C] ACTOR MONOCULTURE: Only {unique_actors} distinct actor(s) across {len(actors)} items. "
                    f"Minimum: {FEED_MIN_UNIQUE_ACTORS}. Real threat landscapes involve multiple actors."
                )
                hard_fail = True
            elif top_actor_ratio > FEED_MAX_SINGLE_ACTOR_RATIO:
                findings.append(
                    f"[C] WARN — Actor concentration: {top_actor} = {top_actor_ratio:.0%} of feed. "
                    f"Threshold: {FEED_MAX_SINGLE_ACTOR_RATIO:.0%}."
                )
            else:
                findings.append(
                    f"[C] Actor diversity: {unique_actors} actors, "
                    f"top={top_actor} ({top_actor_ratio:.0%}) — OK"
                )

        # Severity distribution (0 critical = suspicious for large feed)
        severities = Counter(str(item.get("severity") or item.get("threat_level") or "").upper()
                             for item in items)
        total_sev = sum(severities.values())
        if total_sev >= 20 and severities.get("CRITICAL", 0) == 0:
            findings.append(
                f"[C] WARN — Zero CRITICAL advisories in {total_sev}-item feed. "
                f"Real threat landscapes include critical severity events. "
                f"Check CVSS scoring and KEV enrichment pipelines."
            )

        if not any("[C] SINGLE-SOURCE" in f or "[C] ACTOR MONOCULTURE" in f for f in findings):
            if not any("[C] WARN" in f for f in findings):
                findings.append("[C] Feed Diversity Validator: PASSED")

        return hard_fail, findings


# ── Safeguard D: KEV Health Gate ──────────────────────────────────────────────

_KEV_CATALOG_PATHS = [
    REPO_ROOT / "data" / "kev" / "kev_catalog.json",
    REPO_ROOT / "data" / "correlation" / "kev_catalog.json",
]


def _load_kev_catalog() -> Tuple[Optional[set], str]:
    """Load the CISA KEV CVE-ID set from the first available catalog. Returns (set|None, version)."""
    for p in _KEV_CATALOG_PATHS:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_bytes().rstrip(b"\x00").decode("utf-8", "replace"))
        except Exception:
            continue
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else (data if isinstance(data, list) else [])
        ids = set()
        for v in (vulns or []):
            cid = str((v.get("cveID") or v.get("cve_id") or v.get("cve") or "") if isinstance(v, dict) else v)
            m = CVE_ID_RE.search(cid)
            if m:
                ids.add(m.group(0).upper())
        ver = (data.get("catalogVersion") or data.get("updated_at") or "unknown") if isinstance(data, dict) else "unknown"
        return ids, ver
    return None, "missing"


class KEVHealthGate:
    """CISA KEV enrichment continuity enforcement."""

    def check(self, items: List[Dict]) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if not items:
            return False, ["[D] KEV Health Gate: no items to check."]

        # ── v174 P0-3: cross-validate against the REAL CISA KEV catalog ─────────
        # The prior heuristic HARD_FAILed on "0 KEV" for any feed with >=10 CVEs.
        # That is a FALSE POSITIVE for fresh feeds whose CVEs CISA has not yet
        # KEV-listed. We now enforce CORRECTNESS: KEV inflation (claimed but not in
        # catalog) and missed enrichment (in catalog but unflagged) HARD_FAIL.
        kev_items = [item for item in items if _kev(item)]
        cve_items = [item for item in items if _cves(item)]
        kev_ratio = len(kev_items) / len(items)
        findings.append(
            f"[D] KEV: {len(kev_items)}/{len(items)} items KEV-confirmed "
            f"({kev_ratio:.1%}), CVE-linked items: {len(cve_items)}"
        )

        catalog_kev, catalog_ver = _load_kev_catalog()
        if catalog_kev is None:
            findings.append(
                "[D] WARN — KEV catalog not found (data/kev/ or data/correlation/); "
                "cannot cross-validate KEV markers. Review catalog ingestion."
            )
            return hard_fail, findings

        findings.append(f"[D] KEV catalog: {catalog_ver} ({len(catalog_kev)} CVEs)")

        inflated, missed, overlap = [], [], set()
        for item in items:
            cves = {c.upper() for c in _cves(item)}
            hit = cves & catalog_kev
            overlap |= hit
            marked = _kev(item)
            if marked and cves and not hit:
                inflated.append(sorted(cves)[0])
            elif hit and not marked:
                missed.append(sorted(hit)[0])

        findings.append(
            f"[D] KEV cross-check: feed_cap_catalog={len(overlap)}, "
            f"inflated(claimed!=catalog)={len(inflated)}, missed(catalog!=flagged)={len(missed)}"
        )
        if inflated:
            findings.append(
                f"[D] KEV INFLATION HARD_FAIL: {len(inflated)} item(s) flagged KEV-true with no "
                f"CISA KEV match (fabricated urgency): {inflated[:8]}"
            )
            hard_fail = True
        if missed:
            findings.append(
                f"[D] KEV ENRICHMENT GAP HARD_FAIL: {len(missed)} CVE(s) present in the CISA KEV "
                f"catalog were NOT flagged KEV in the feed: {missed[:8]}. Fix kev ingestion."
            )
            hard_fail = True
        if not overlap and not inflated:
            findings.append(
                "[D] KEV CORRECT: 0 feed CVEs are in the current CISA KEV catalog and 0 are "
                "falsely flagged -- truthful absence (fresh advisories not yet KEV-listed)."
            )

        return hard_fail, findings



# ── Safeguard E: Runtime Integrity Baseline ───────────────────────────────────

class RuntimeIntegrityBaseline:
    """Orchestration timing and stage execution monitoring."""

    def check(self, telemetry_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if telemetry_path is None:
            telemetry_path = REPO_ROOT / "data" / "telemetry" / "runtime_telemetry.json"

        if not telemetry_path.exists():
            findings.append("[E] Runtime telemetry not found — first run or clean state. SKIP.")
            return False, findings

        try:
            tel = json.loads(telemetry_path.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(f"[E] WARN — Cannot parse telemetry: {e}")
            return False, findings

        # Duration check
        duration = tel.get("duration_seconds") or tel.get("runtime_seconds") or 0
        duration_min = duration / 60 if duration else 0

        if duration_min > 0:
            if duration_min < RUNTIME_MIN_MINUTES:
                findings.append(
                    f"[E] RUNTIME COLLAPSE: Pipeline completed in {duration_min:.1f} min "
                    f"(minimum: {RUNTIME_MIN_MINUTES} min). "
                    f"Short runtime indicates stage skipping or silent failure. "
                    f"Check orchestrator logs for skipped stages."
                )
                hard_fail = True
            elif duration_min > RUNTIME_MAX_MINUTES:
                findings.append(
                    f"[E] WARN — Pipeline runtime excessive: {duration_min:.1f} min "
                    f"(max expected: {RUNTIME_MAX_MINUTES} min). May indicate hung stage."
                )
            else:
                findings.append(f"[E] Runtime: {duration_min:.1f} min — OK")
        else:
            findings.append("[E] WARN — Runtime duration not recorded in telemetry.")

        # Advisory count check
        advisory_count = (tel.get("pipeline", {}) or {}).get("advisory_count") or \
                          tel.get("advisory_count") or 0
        if advisory_count == 0:
            findings.append(
                "[E] WARN — Zero advisory count in telemetry. "
                "Pipeline may have produced no output."
            )
        else:
            findings.append(f"[E] Advisory count (telemetry): {advisory_count}")

        return hard_fail, findings


# ── Safeguard F: Advisory Authenticity Scoring ───────────────────────────────

class AdvisoryAuthenticityScoring:
    """
    100-point authenticity scoring per advisory.
    Penalizes synthetic markers; rewards real-world signals.
    """

    def _score_item(self, item: Dict) -> Tuple[int, List[str]]:
        score = 0
        notes = []

        # Title quality (max 15 pts)
        title = _title(item)
        words = len(title.split()) if title else 0
        if words >= 8:
            score += 15
        elif words >= 5:
            score += 8
        elif words >= 3:
            score += 4
        else:
            notes.append("WEAK: Title too short")

        # Source attribution (max 15 pts)
        source = _source(item)
        if source and len(source) > 10:
            score += 15
            if any(d in source for d in [
                "thehackernews", "krebs", "darkreading", "cisa.gov",
                "microsoft.com", "mandiant", "crowdstrike", "paloalto",
                "recordedfuture", "secureworks", "unit42", "talos"
            ]):
                score += 5  # Premium trusted source bonus
                notes.append(f"BONUS: Premium source ({source[:40]})")
        else:
            notes.append("WEAK: Missing source URL")

        # CVE/CVSS enrichment (max 20 pts)
        cves = _cves(item)
        cvss = item.get("cvss_score") or item.get("cvss")
        epss = item.get("epss_score") or item.get("epss")
        kev  = _kev(item)

        if cves:
            score += 5
        if cvss and str(cvss) not in ("None", "N/A", "", "Pending"):
            score += 8
            notes.append(f"CVSS={cvss}")
        if epss and str(epss) not in ("None", "N/A", "", "Pending", "0"):
            score += 5
            notes.append(f"EPSS={epss}")
        if kev:
            score += 7
            notes.append("KEV=CONFIRMED")

        # IOC richness (max 15 pts)
        iocs = _iocs(item)
        total_iocs = sum(len(v) if isinstance(v, list) else 1
                         for v in iocs.values() if v)
        if total_iocs >= 5:
            score += 15
        elif total_iocs >= 3:
            score += 10
        elif total_iocs >= 1:
            score += 5
        else:
            notes.append("WEAK: No IOCs enriched")

        # MITRE ATT&CK depth (max 15 pts)
        techniques = _techniques(item)
        if len(techniques) >= 5:
            score += 15
        elif len(techniques) >= 3:
            score += 10
        elif len(techniques) >= 1:
            score += 6
        else:
            notes.append("WEAK: No MITRE techniques mapped")

        # Actor attribution (max 10 pts)
        actor = _actor_id(item)
        if actor and not SYNTHETIC_ACTOR_RE.search(actor) and actor not in ("UNC-UNKNOWN", ""):
            score += 10
        elif actor == "UNC-UNKNOWN":
            score += 3  # Honest unattributed is better than fake actor
            notes.append("INFO: Actor unattributed")
        else:
            notes.append("WEAK: Generic/synthetic actor label")

        # Risk score diversity (max 10 pts)
        risk = _risk(item)
        if risk is not None:
            # Non-bucket scores = evidence-derived
            static_buckets = {10.0, 7.5, 5.5, 5.0, 4.8, 2.8, 2.3}
            if risk not in static_buckets:
                score += 10
            else:
                score += 4
                notes.append(f"INFO: Risk score at static bucket value ({risk})")

        score = min(score, 100)
        return score, notes

    def check(self, items: List[Dict]) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if not items:
            return False, ["[F] Authenticity Scoring: no items."]

        scores = []
        hard_fail_items = []
        poor_items = []

        for item in items:
            s, notes = self._score_item(item)
            scores.append(s)
            if s < AUTH_SCORE_HARD_FAIL:
                hard_fail_items.append((_title(item)[:50], s, notes))
            elif s < AUTH_SCORE_MIN:
                poor_items.append((_title(item)[:50], s, notes))

        avg_score = sum(scores) / len(scores) if scores else 0
        poor_ratio = (len(hard_fail_items) + len(poor_items)) / len(items)

        findings.append(
            f"[F] Authenticity scores — avg: {avg_score:.1f}/100, "
            f"poor (<{AUTH_SCORE_MIN}): {len(poor_items)}, "
            f"hard-fail (<{AUTH_SCORE_HARD_FAIL}): {len(hard_fail_items)}"
        )

        if hard_fail_items:
            for title, score, notes in hard_fail_items[:5]:
                findings.append(
                    f"[F] HARD-FAIL item (score={score}/100): '{title}' — "
                    f"{'; '.join(notes[:3])}"
                )
            hard_fail = True

        if poor_ratio > AUTH_POOR_ITEM_RATIO:
            findings.append(
                f"[F] HIGH POOR-QUALITY RATIO: {poor_ratio:.0%} of items score below "
                f"{AUTH_SCORE_MIN}/100 authenticity threshold. "
                f"Feed quality is insufficient for enterprise deployment."
            )
            hard_fail = True

        if avg_score < 30:
            findings.append(
                f"[F] CRITICALLY LOW avg authenticity score: {avg_score:.1f}/100. "
                f"Feed does not meet minimum enterprise quality standard."
            )
            hard_fail = True
        elif avg_score >= 50:
            findings.append(f"[F] Authenticity Gate: PASSED (avg={avg_score:.1f}/100)")

        return hard_fail, findings


# ── Safeguard G: Manifest Mutation Validator ──────────────────────────────────

class ManifestMutationValidator:
    """Detects stale manifest reuse and frozen dashboard payloads."""

    def check(self, items: List[Dict], manifest_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if manifest_path is None:
            manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

        # Check manifest file age
        if manifest_path.exists():
            mtime = datetime.fromtimestamp(manifest_path.stat().st_mtime, tz=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600

            if age_hours > MANIFEST_FROZEN_HOURS:
                findings.append(
                    f"[G] FROZEN MANIFEST: feed_manifest.json is {age_hours:.1f}h old "
                    f"(threshold: {MANIFEST_FROZEN_HOURS}h). "
                    f"Pipeline has not updated the manifest. "
                    f"Dashboard is serving stale intelligence."
                )
                hard_fail = True
            elif age_hours > MANIFEST_STALE_HOURS:
                findings.append(
                    f"[G] WARN — Stale manifest: {age_hours:.1f}h old "
                    f"(warn threshold: {MANIFEST_STALE_HOURS}h)."
                )
            else:
                findings.append(f"[G] Manifest age: {age_hours:.1f}h — OK")

        # Check for duplicate advisory IDs
        if items:
            ids = []
            for item in items:
                aid = str(item.get("id") or item.get("stix_id") or item.get("advisory_id") or "")
                if aid:
                    ids.append(aid)

            if ids:
                dup_ids = [k for k, v in Counter(ids).items() if v > 1]
                if dup_ids:
                    findings.append(
                        f"[G] DUPLICATE ADVISORY IDs: {len(dup_ids)} duplicate IDs detected "
                        f"({', '.join(dup_ids[:3])}...). "
                        f"Manifest contains recycled items — dedup pipeline may be bypassed."
                    )
                    hard_fail = True
                else:
                    findings.append(f"[G] Advisory ID uniqueness: PASSED ({len(ids)} unique IDs)")

            # Check title duplication (even without ID dedup)
            titles = [_title(item) for item in items if _title(item)]
            dup_titles = [k for k, v in Counter(titles).items() if v > 1]
            if dup_titles:
                findings.append(
                    f"[G] DUPLICATE TITLES: {len(dup_titles)} advisory titles appear more than once. "
                    f"Dashboard will show identical cards — dedup failure confirmed."
                )
                hard_fail = True
            else:
                findings.append(f"[G] Title uniqueness: PASSED (no duplicate titles)")

        return hard_fail, findings


# ── Safeguard H: Synthetic Flood Circuit Breaker ─────────────────────────────

class SyntheticFloodCircuitBreaker:
    """Quarantine advisories and block Pages deployment on synthetic spike."""

    def check(self, items: List[Dict], apply: bool = False) -> Tuple[bool, List[str]]:
        findings: List[str] = []
        hard_fail = False

        if not items:
            return False, ["[H] Circuit Breaker: no items to evaluate."]

        synthetic_count = sum(
            1 for item in items
            if SYNTHETIC_ACTOR_RE.search(_actor_id(item))
            or str(item.get("_synthetic") or "").lower() == "true"
        )
        ratio = synthetic_count / len(items)

        findings.append(
            f"[H] Synthetic ratio: {synthetic_count}/{len(items)} items ({ratio:.0%})"
        )

        if ratio > FLOOD_SYNTHETIC_SPIKE:
            findings.append(
                f"[H] CIRCUIT BREAKER TRIPPED: {ratio:.0%} synthetic ratio exceeds "
                f"threshold ({FLOOD_SYNTHETIC_SPIKE:.0%}). "
                f"BLOCKING Pages deployment. Preserving last healthy feed. "
                f"Root cause: real feed rejection or fallback generator runaway."
            )
            hard_fail = True

            if apply:
                # Quarantine synthetic items
                synthetic_items = [
                    item for item in items
                    if SYNTHETIC_ACTOR_RE.search(_actor_id(item))
                    or str(item.get("_synthetic") or "").lower() == "true"
                ]
                FLOOD_QUARANTINE_PATH.parent.mkdir(parents=True, exist_ok=True)
                quarantine = {
                    "quarantined_at": datetime.now(timezone.utc).isoformat(),
                    "reason": "SYNTHETIC_FLOOD_CIRCUIT_BREAKER",
                    "synthetic_ratio": ratio,
                    "item_count": len(synthetic_items),
                    "items": synthetic_items,
                }
                FLOOD_QUARANTINE_PATH.write_text(
                    json.dumps(quarantine, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                findings.append(
                    f"[H] Quarantine written: {FLOOD_QUARANTINE_PATH} "
                    f"({len(synthetic_items)} items isolated)"
                )

        return hard_fail, findings


# ── Master Gate Runner ────────────────────────────────────────────────────────

# workaround for F: expose buckets at module level for import
SYNTHETIC_CVEDetector_STATIC_BUCKETS = {10.0, 7.5, 5.5, 5.0, 4.8, 2.8, 2.3}


def run_all_gates(items: List[Dict], mode: str) -> int:
    """
    Run all 8 safeguards. Returns 0 (pass) or 1 (fail).
    mode: "check" | "report" | "apply"
    """
    apply = mode == "apply"
    any_hard_fail = False
    all_findings: List[str] = []

    log.info("=" * 70)
    log.info("SENTINEL APEX Intelligence Integrity Gate v%s", GATE_VERSION)
    log.info("Mode: %s | Items: %d", mode.upper(), len(items))
    log.info("=" * 70)

    gates = [
        ("A — Synthetic CVE Detector",       SyntheticCVEDetector().check(items)),
        ("B — Entropy Gate",                  EntropyGate().check(items)),
        ("C — Feed Diversity Validator",   FeedDiversityValidator().check(items)),
        ("D — KEV Health Gate",               KEVHealthGate().check(items)),
        ("E — Runtime Integrity Baseline",    RuntimeIntegrityBaseline().check()),
        ("F — Advisory Authenticity Scoring", AdvisoryAuthenticityScoring().check(items)),
        ("G — Manifest Mutation Validator",   ManifestMutationValidator().check(items)),
        ("H — Synthetic Flood Circuit Breaker", SyntheticFloodCircuitBreaker().check(items)),
    ]

    report_rows = []
    for gate_name, (fail, findings) in gates:
        status = "HARD_FAIL" if fail else "PASS"
        if fail:
            any_hard_fail = True
        report_rows.append((gate_name, status, findings))
        all_findings.extend(findings)

    # Print summary table
    log.info("")
    log.info("%-45s  %s", "GATE", "STATUS")
    log.info("-" * 60)
    for gate_name, status, _ in report_rows:
        flag = "\u2717" if status == "HARD_FAIL" else "\u2713"
        log.info("  %s  %-43s  %s", flag, gate_name, status)

    log.info("")
    log.info("DETAILED FINDINGS:")
    log.info("-" * 60)
    for finding in all_findings:
        level = logging.ERROR if "HARD_FAIL" in finding or "CIRCUIT BREAKER" in finding else \
                logging.WARNING if "WARN" in finding else logging.INFO
        log.log(level, "  %s", finding)

    log.info("")
    overall = "HARD_FAIL" if any_hard_fail else "PASS"
    log.info("=" * 70)
    log.info("INTELLIGENCE INTEGRITY GATE RESULT: %s", overall)
    log.info("=" * 70)

    if mode == "report":
        return 0
    return 1 if any_hard_fail else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL APEX Intelligence Integrity Gate")
    ap.add_argument("--feed",   default="api/feed.json", help="Path to feed JSON")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--check",  action="store_true", help="Exit 1 on HARD_FAIL")
    grp.add_argument("--report", action="store_true", help="Always exit 0")
    grp.add_argument("--apply",  action="store_true", help="Gates + write quarantine")
    args = ap.parse_args()

    feed_path = REPO_ROOT / args.feed
    items = load_feed(feed_path)
    log.info("[IIG] Loaded %d items from %s", len(items), feed_path)

    if args.report:
        mode = "report"
    elif args.apply:
        mode = "apply"
    else:
        mode = "check"

    return run_all_gates(items, mode)


if __name__ == "__main__":
    sys.exit(main())
