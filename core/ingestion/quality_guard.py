"""
CYBERDUDEBIVASH® SENTINEL APEX – Intelligence Quality Guard v1.0
================================================================
Production-grade quality gate for the CTI ingestion pipeline.

Systems implemented:
  1. Content Quality Gate    – min 300-word threshold, low-signal rejection
  2. Source Trust Scoring    – domain reputation weighting table + multiplier
  3. Exploit Maturity Engine – PoC / weaponized / active / theoretical
  4. Confidence Score Boost  – IOC density + source weight + exploit state
  5. Asset Targeting Extractor – sector/asset extraction from content

Integration:
  from core.ingestion.quality_guard import QualityGuard
  guard = QualityGuard()
  result = guard.evaluate(raw_item)
  if result.accepted:
      enriched_item = result.item  # has confidence_score, exploit_maturity, source_trust

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-QUALITY-GUARD")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MIN_WORD_COUNT        = 300    # Hard floor – items below this are rejected
MIN_TITLE_CHARS       = 15     # Title too short = noise
MIN_IOC_DENSITY_BONUS = 3      # â‰¥3 IOCs → confidence boost applied
MAX_CONFIDENCE        = 100
BASE_CONFIDENCE       = 50

# Exploit maturity levels – ordered by severity
MATURITY_ACTIVE      = "active"
MATURITY_WEAPONIZED  = "weaponized"
MATURITY_POC         = "poc"
MATURITY_THEORETICAL = "theoretical"

# ─────────────────────────────────────────────────────────────────────────────
# SOURCE TRUST REGISTRY
# Domain-level reputation weights (0.0 — 1.0)
# 1.0 = authoritative primary source (CISA, NVD, vendor advisories)
# 0.8 = tier-1 threat intelligence feeds
# 0.6 = credible secondary sources (news, research blogs)
# 0.4 = low-signal / aggregator sources
# ─────────────────────────────────────────────────────────────────────────────
SOURCE_TRUST_TABLE: Dict[str, float] = {
    # Government / authoritative
    "cisa.gov":                   1.0,
    "nvd.nist.gov":               1.0,
    "cert.org":                   1.0,
    "us-cert.cisa.gov":           1.0,
    "ncsc.gov.uk":                1.0,
    "bsi.bund.de":                1.0,
    "cyber.gov.au":               1.0,
    "cccs.ca":                    1.0,

    # Vendor security advisories
    "microsoft.com":              0.95,
    "security.microsoft.com":     0.95,
    "msrc.microsoft.com":         0.95,
    "support.apple.com":          0.95,
    "security.googleblog.com":    0.95,
    "googleprojectzero.blogspot": 0.95,
    "blog.google":                0.90,
    "cisco.com":                  0.90,
    "redhat.com":                 0.90,
    "ubuntu.com":                 0.88,
    "oracle.com":                 0.88,
    "sap.com":                    0.88,
    "fortinet.com":               0.90,
    "paloaltonetworks.com":       0.90,
    "crowdstrike.com":            0.90,
    "mandiant.com":               0.92,
    "unit42.paloaltonetworks.com":0.92,
    "securelist.com":             0.90,     # Kaspersky research
    "talosintelligence.com":      0.92,     # Cisco Talos

    # Tier-1 CTI feeds
    "threatpost.com":             0.80,
    "bleepingcomputer.com":       0.78,
    "krebsonsecurity.com":        0.85,
    "darkreading.com":            0.75,
    "securityweek.com":           0.75,
    "theregister.com":            0.72,
    "arstechnica.com":            0.72,
    "wired.com":                  0.70,
    "thehackernews.com":          0.72,
    "cyberscoop.com":             0.78,
    "recordedfuture.com":         0.90,
    "vxunderground.org":          0.80,
    "abuse.ch":                   0.88,
    "otx.alienvault.com":         0.82,
    "feodotracker.abuse.ch":      0.88,
    "urlhaus.abuse.ch":           0.85,
    "virustotal.com":             0.80,
    "mitre.org":                  0.95,
    "attack.mitre.org":           0.95,
    "cve.mitre.org":              1.0,
    "exploit-db.com":             0.80,

    # Research / academic
    "arxiv.org":                  0.70,
    "ieeexplore.ieee.org":        0.72,
    "usenix.org":                 0.75,
    "blackhat.com":               0.80,
    "defcon.org":                 0.78,

    # Low trust – aggregators / content farms
    "feedburner.com":             0.40,
    "feedspot.com":               0.40,
    "alltop.com":                 0.35,
}

# Keyword signals for source trust inference when domain not in table
HIGH_TRUST_SIGNALS    = ["cisa", "nvd", "nist", "cert", "msrc", "advisory", "bulletin"]
MEDIUM_TRUST_SIGNALS  = ["security", "threat", "intel", "research", "vulnerability"]
LOW_TRUST_SIGNALS     = ["blog", "news", "daily", "weekly", "roundup", "digest"]


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT MATURITY SIGNAL PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
_ACTIVE_SIGNALS: List[str] = [
    "actively exploit", "in the wild", "zero-day", "0-day", "0day",
    "ransomware", "ransomware group", "nation.state", "nation state",
    "apt", "advanced persistent", "supply chain attack", "cisa kev",
    "known exploited", "mass exploitation", "widespread exploitation",
    "botnet", "wiper", "destructive",
]
_WEAPONIZED_SIGNALS: List[str] = [
    "weaponized", "exploit kit", "crimeware", "metasploit module",
    "cobalt strike", "c2 framework", "malware family", "backdoor",
    "trojan", "remote access trojan", "rat", "loader", "dropper",
    "post-exploitation", "lateral movement",
]
_POC_SIGNALS: List[str] = [
    "proof.of.concept", "poc", "exploit code", "working exploit",
    "technical analysis", "reverse engineer", "decompil", "patch diff",
    "vulnerability research", "cve-", "rce", "sqli", "ssrf", "lfi", "rfi",
    "privilege escalation", "auth bypass", "memory corruption",
]

# ─────────────────────────────────────────────────────────────────────────────
# SECTOR / ASSET TARGETING PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
SECTOR_PATTERNS: Dict[str, List[str]] = {
    "financial":       ["bank", "fintech", "payment", "swift", "atm", "financial", "brokerage", "crypto exchange"],
    "healthcare":      ["hospital", "healthcare", "medical", "ehr", "patient", "pharma", "biotech"],
    "government":      ["government", "federal", "ministry", "military", "defense", "nato", "pentagon"],
    "energy":          ["energy", "oil", "gas", "power grid", "ics", "scada", "pipeline", "nuclear"],
    "technology":      ["software", "saas", "cloud", "it infrastructure", "csp", "managed service", "msp"],
    "retail":          ["retail", "e-commerce", "pos system", "point of sale", "supply chain"],
    "education":       ["university", "school", "education", "academic", "research institution"],
    "telecommunications": ["telecom", "isp", "mobile network", "5g", "carrier"],
    "critical_infrastructure": ["critical infrastructure", "water treatment", "transportation", "airports"],
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QualityResult:
    accepted:         bool
    item:             Dict[str, Any]
    reject_reason:    Optional[str] = None
    word_count:       int           = 0
    source_trust:     float         = 0.5
    exploit_maturity: str           = MATURITY_THEORETICAL
    confidence_score: int           = BASE_CONFIDENCE
    sectors_targeted: List[str]     = field(default_factory=list)
    quality_flags:    List[str]     = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# QUALITY GUARD ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class QualityGuard:
    """
    Single-pass quality evaluator for raw CTI items.
    Call evaluate(item) → QualityResult.
    Thread-safe (stateless evaluation).
    """

    def __init__(
        self,
        min_words: int = MIN_WORD_COUNT,
        min_confidence: int = 40,        # v134: raised floor from 20 to 40
        enforce_min_words: bool = True,
        enforce_ioc_gate: bool = True,
        ioc_gate_downgrade: bool = False, # v134: BLOCK (not downgrade) zero-IOC HIGH/CRITICAL
        enforce_mitre_gate: bool = True,  # v134: require >= 2 MITRE techniques
        enforce_dedup: bool = True,       # v134: hash-based fingerprint dedup
        min_mitre_techniques: int = 2,    # v134: minimum MITRE ATT&CK techniques
    ):
        self.min_words              = min_words
        self.min_confidence         = min_confidence
        self.enforce_min_words      = enforce_min_words
        self.enforce_ioc_gate       = enforce_ioc_gate
        self.ioc_gate_downgrade     = ioc_gate_downgrade
        # v134 additions
        self.enforce_mitre_gate     = enforce_mitre_gate
        self.enforce_dedup          = enforce_dedup
        self.min_mitre_techniques   = min_mitre_techniques
        # Dedup registry: content fingerprint -> first seen title
        self._seen_fingerprints: dict = {}
        self._seen_titles: dict = {}

    # ── v134: Dedup fingerprinting ─────────────────────────────────────────────
    @staticmethod
    def _fingerprint(item: Dict[str, Any]) -> str:
        """SHA-256 fingerprint of (title+cve+actor) normalized to lowercase."""
        import hashlib
        title  = (item.get("title") or "").lower().strip()
        cve    = (item.get("cve") or item.get("cve_id") or "")
        actor  = (item.get("actor_tag") or item.get("threat_actor") or "")
        key    = f"{title}|{cve}|{actor}"
        return hashlib.sha256(key.encode()).hexdigest()

    @staticmethod
    def _title_similarity(a: str, b: str) -> float:
        """Jaccard similarity of word sets (0.0—1.0). Fast, no deps."""
        wa = set(a.lower().split())
        wb = set(b.lower().split())
        if not wa or not wb:
            return 0.0
        return len(wa & wb) / len(wa | wb)

    # ── Low-value title patterns (v134) ───────────────────────────────────────
    _LOW_VALUE_PATTERNS = [
        r"^(test|demo|sample|placeholder|lorem|ipsum)",
        r"^\[?\s*(untitled|no title|n/a|none)\s*\]?$",
        r"^cdb-\w{3}-\d+ campaign$",  # generic synthetic campaign names
    ]

    # ─── Public API ─────────────────────────────────────────────────────────

    def evaluate(self, item: Dict[str, Any]) -> QualityResult:
        """
        Evaluate a raw CTI item for quality and enrich it.
        Returns QualityResult – check .accepted before using .item.
        """
        flags: List[str] = []

        # ── 1. Extract text content ──────────────────────────────────────────
        text  = self._full_text(item)
        words = _word_count(text)

        # ── 2. Content quality gate ──────────────────────────────────────────
        title = (item.get("title") or "").strip()
        if len(title) < MIN_TITLE_CHARS:
            return QualityResult(
                accepted=False, item=item,
                reject_reason=f"title_too_short:{len(title)}_chars",
                word_count=words,
            )

        if self.enforce_min_words and words < self.min_words:
            return QualityResult(
                accepted=False, item=item,
                reject_reason=f"below_word_threshold:{words}/{self.min_words}",
                word_count=words,
            )

        # ── 3. Source trust score ────────────────────────────────────────────
        source_url   = item.get("source_url") or item.get("url") or item.get("feed_source") or ""
        source_trust = self._score_source(source_url)
        flags.append(f"source_trust:{source_trust:.2f}")

        # ── 4. Exploit maturity classification ──────────────────────────────
        maturity = self._classify_exploit_maturity(text, item)
        flags.append(f"exploit_maturity:{maturity}")

        # ── 5. IOC density calculation ───────────────────────────────────────
        iocs       = item.get("iocs") or []
        # Support both list format and dict-of-arrays format
        if isinstance(iocs, dict):
            ioc_count = sum(
                len(v) if isinstance(v, list) else (1 if v else 0)
                for v in iocs.values()
                if not isinstance(v, bool)
            )
        elif isinstance(iocs, list):
            ioc_count = len(iocs)
        else:
            ioc_count = 0
        # Also check ioc_count field if already computed by IOC engine
        pre_computed = item.get("ioc_count")
        if isinstance(pre_computed, int) and pre_computed > ioc_count:
            ioc_count = pre_computed
        flags.append(f"ioc_count:{ioc_count}")

        # ── 5b. MANDATORY IOC—SEVERITY GATE (v134.0) ────────────────────────
        # Rule: NO advisory with severity â‰¥ HIGH may be published with 0 IOCs.
        # Action A (default): downgrade severity to MEDIUM
        # Action B (strict):  block publication entirely
        severity_raw = (item.get("severity") or item.get("risk_level") or "").upper()
        HIGH_SEV_LEVELS = {"HIGH", "CRITICAL", "CRITICAL-RISK", "HIGH-RISK"}
        if self.enforce_ioc_gate and severity_raw in HIGH_SEV_LEVELS and ioc_count == 0:
            if self.ioc_gate_downgrade:
                # Downgrade: preserve advisory but reduce severity
                logger.warning(
                    "[IOC-GATE] DOWNGRADE severity=%s → MEDIUM for '%s' (0 IOCs)",
                    severity_raw, title[:80]
                )
                flags.append(f"ioc_gate:downgraded_from_{severity_raw}")
                # Will mutate enriched dict below – store original for audit
                item = dict(item)
                item["original_severity"] = severity_raw
                item["severity"]          = "MEDIUM"
                item["ioc_gate_triggered"] = True
                severity_raw = "MEDIUM"
            else:
                # Block: reject publication
                logger.error(
                    "[IOC-GATE] BLOCKED severity=%s advisory '%s' – 0 IOCs violates quality gate",
                    severity_raw, title[:80]
                )
                return QualityResult(
                    accepted=False, item=item,
                    reject_reason=f"ioc_gate:blocked_{severity_raw}_0_iocs",
                    word_count=words,
                    source_trust=source_trust,
                    exploit_maturity=maturity,
                )

        # ── 5c. v134: Low-value title pattern rejection ──────────────────────
        import re as _re
        for pat in self._LOW_VALUE_PATTERNS:
            if _re.search(pat, title, _re.IGNORECASE):
                logger.warning("[QUALITY-GUARD] LOW-VALUE title rejected: '%s'", title[:80])
                return QualityResult(
                    accepted=False, item=item,
                    reject_reason=f"low_value_title_pattern:{title[:40]}",
                    word_count=words,
                )

        # ── 5d. v134: MITRE ATT&CK technique gate ────────────────────────────
        if self.enforce_mitre_gate:
            mitre = (
                item.get("mitre_techniques") or
                item.get("ttps") or
                item.get("mitre_tactics") or []
            )
            mitre_count = len(mitre) if isinstance(mitre, list) else 0
            flags.append(f"mitre_count:{mitre_count}")
            if mitre_count < self.min_mitre_techniques:
                severity_chk = (item.get("severity") or "").upper()
                # Enforce strictly for HIGH/CRITICAL; warn for MEDIUM/LOW
                if severity_chk in {"HIGH", "CRITICAL"}:
                    logger.warning(
                        "[QUALITY-GUARD] MITRE gate: %d techniques < %d required for %s '%s'",
                        mitre_count, self.min_mitre_techniques, severity_chk, title[:60],
                    )
                    flags.append(f"mitre_gate:insufficient_{mitre_count}")
                    # Mark item rather than block (IOC enforcer handles fallback generation)
                    item = dict(item)
                    item["mitre_gate_warning"] = True
                    item["mitre_count"] = mitre_count

        # ── 5e. v134: Duplicate fingerprint detection ─────────────────────────
        if self.enforce_dedup:
            fp = self._fingerprint(item)
            if fp in self._seen_fingerprints:
                logger.info(
                    "[QUALITY-GUARD] DUPLICATE fingerprint rejected: '%s' (same as '%s')",
                    title[:60], self._seen_fingerprints[fp][:40],
                )
                return QualityResult(
                    accepted=False, item=item,
                    reject_reason=f"duplicate_fingerprint:{fp[:12]}",
                    word_count=words,
                )
            # Check title similarity against all seen titles (Jaccard >= 0.85 = near-duplicate)
            for seen_title, seen_fp in self._seen_titles.items():
                sim = self._title_similarity(title, seen_title)
                if sim >= 0.85:
                    logger.info(
                        "[QUALITY-GUARD] NEAR-DUPLICATE title (sim=%.2f) rejected: '%s'",
                        sim, title[:60],
                    )
                    return QualityResult(
                        accepted=False, item=item,
                        reject_reason=f"near_duplicate_title:sim={sim:.2f}",
                        word_count=words,
                    )
            self._seen_fingerprints[fp]    = title
            self._seen_titles[title]        = fp
            flags.append("dedup:unique")

        # ── 6. Composite confidence score ────────────────────────────────────
        confidence = self._compute_confidence(
            item, words, source_trust, maturity, ioc_count
        )
        flags.append(f"confidence:{confidence}")

        # ── 7. Asset/sector targeting extraction ─────────────────────────────
        sectors = self._extract_sectors(text)
        if sectors:
            flags.append(f"sectors:{','.join(sectors)}")

        # ── 8. Reject low-confidence items ───────────────────────────────────
        if confidence < self.min_confidence:
            return QualityResult(
                accepted=False, item=item,
                reject_reason=f"confidence_below_floor:{confidence}/{self.min_confidence}",
                word_count=words,
                source_trust=source_trust,
                exploit_maturity=maturity,
                confidence_score=confidence,
            )

        # ── 9. Enrich item in-place ──────────────────────────────────────────
        enriched = dict(item)
        enriched["confidence_score"]   = confidence
        enriched["exploit_maturity"]   = maturity
        enriched["source_trust"]       = round(source_trust, 3)
        enriched["sectors_targeted"]   = sectors
        enriched["word_count"]         = words
        enriched["quality_flags"]      = flags

        logger.debug("[QUALITY-GUARD] ACCEPTED word_count=%d confidence=%d maturity=%s trust=%.2f title=%s",
                     words, confidence, maturity, source_trust, title[:60])

        return QualityResult(
            accepted=True,
            item=enriched,
            word_count=words,
            source_trust=source_trust,
            exploit_maturity=maturity,
            confidence_score=confidence,
            sectors_targeted=sectors,
            quality_flags=flags,
        )

    def filter_batch(self, items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        """
        Evaluate a batch of items. Returns (accepted_items, rejected_count).
        Accepted items are enriched in-place.
        """
        accepted  = []
        rejected  = 0
        for item in items:
            result = self.evaluate(item)
            if result.accepted:
                accepted.append(result.item)
            else:
                rejected += 1
                logger.debug("[QUALITY-GUARD] REJECTED %s – %s",
                             (item.get("title") or "")[:60], result.reject_reason)
        logger.info("[QUALITY-GUARD] Batch: %d accepted, %d rejected (%.0f%% pass rate)",
                    len(accepted), rejected,
                    100 * len(accepted) / max(1, len(items)))
        return accepted, rejected

    # ─── Private helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _full_text(item: Dict[str, Any]) -> str:
        """Concatenate all textual fields for analysis."""
        parts = [
            item.get("title") or "",
            item.get("description") or "",
            item.get("summary") or "",
            item.get("content") or "",
            item.get("body") or "",
        ]
        return " ".join(p for p in parts if p).lower()

    @staticmethod
    def _score_source(source_url: str) -> float:
        """
        Return trust score [0.0—1.0] for a source URL.
        Checks exact domain table, then substring heuristics.
        """
        if not source_url:
            return 0.5   # unknown – neutral

        url_lower = source_url.lower()

        # Exact domain match
        for domain, score in SOURCE_TRUST_TABLE.items():
            if domain in url_lower:
                return score

        # Heuristic fallback
        for kw in HIGH_TRUST_SIGNALS:
            if kw in url_lower:
                return 0.75
        for kw in MEDIUM_TRUST_SIGNALS:
            if kw in url_lower:
                return 0.60
        for kw in LOW_TRUST_SIGNALS:
            if kw in url_lower:
                return 0.45

        return 0.55   # unknown domain – slightly below neutral

    @staticmethod
    def _classify_exploit_maturity(text: str, item: Dict[str, Any]) -> str:
        """
        Classify exploit maturity from content signals.
        Returns one of: active / weaponized / poc / theoretical
        """
        # Explicit field takes priority
        existing = (item.get("exploit_maturity") or "").lower()
        if existing in (MATURITY_ACTIVE, MATURITY_WEAPONIZED, MATURITY_POC, MATURITY_THEORETICAL):
            return existing

        # KEV = active by definition
        if item.get("kev_present") is True:
            return MATURITY_ACTIVE

        # Signal scan (ordered by severity – highest wins)
        for sig in _ACTIVE_SIGNALS:
            if sig in text:
                return MATURITY_ACTIVE
        for sig in _WEAPONIZED_SIGNALS:
            if sig in text:
                return MATURITY_WEAPONIZED
        for sig in _POC_SIGNALS:
            if sig in text:
                return MATURITY_POC

        return MATURITY_THEORETICAL

    @staticmethod
    def _compute_confidence(
        item: Dict[str, Any],
        word_count: int,
        source_trust: float,
        maturity: str,
        ioc_count: int,
    ) -> int:
        """
        Composite confidence score [0—100].

        Base: 50
        + Source trust multiplier (×0.25 of base max)
        + Content richness (word count tier)
        + IOC density bonus
        + Exploit maturity bonus
        + KEV bonus
        + CVSS/EPSS signals
        """
        score = BASE_CONFIDENCE

        # Source trust contribution: 0—20 points
        score += int((source_trust - 0.5) * 40)   # 0.5 → 0pts, 1.0 → +20pts, 0.0 → -20pts

        # Content richness: 0—10 points
        if word_count >= 1000:
            score += 10
        elif word_count >= 600:
            score += 7
        elif word_count >= 300:
            score += 4

        # IOC density bonus: 0—8 points
        if ioc_count >= 10:
            score += 8
        elif ioc_count >= MIN_IOC_DENSITY_BONUS:
            score += 4
        elif ioc_count >= 1:
            score += 2

        # Exploit maturity bonus
        maturity_bonus = {
            MATURITY_ACTIVE:      15,
            MATURITY_WEAPONIZED:  10,
            MATURITY_POC:          5,
            MATURITY_THEORETICAL:  0,
        }
        score += maturity_bonus.get(maturity, 0)

        # KEV: authoritative exploitation signal
        if item.get("kev_present") is True:
            score += 10

        # CVSS signal: high score = higher confidence
        cvss = item.get("cvss_score") or 0
        if isinstance(cvss, (int, float)):
            if cvss >= 9.0:
                score += 8
            elif cvss >= 7.0:
                score += 4

        # EPSS signal: high exploitation probability
        epss = item.get("epss_score") or 0
        if isinstance(epss, (int, float)):
            if epss >= 0.8:
                score += 6
            elif epss >= 0.5:
                score += 3

        # TTPs enrichment bonus
        ttps = item.get("ttps") or []
        if isinstance(ttps, list) and len(ttps) >= 3:
            score += 4

        return max(0, min(MAX_CONFIDENCE, score))

    @staticmethod
    def _extract_sectors(text: str) -> List[str]:
        """Extract sector/asset targeting from content text."""
        found = []
        for sector, keywords in SECTOR_PATTERNS.items():
            if any(kw in text for kw in keywords):
                found.append(sector)
        return found


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _word_count(text: str) -> int:
    """Fast word count via whitespace split."""
    return len(text.split()) if text else 0


def score_source_trust(source_url: str) -> float:
    """Module-level helper – score a source URL without instantiating QualityGuard."""
    return QualityGuard._score_source(source_url)


def classify_exploit_maturity(text: str, item: Optional[Dict[str, Any]] = None) -> str:
    """Module-level helper – classify exploit maturity from text."""
    return QualityGuard._classify_exploit_maturity(text, item or {})


# ─────────────────────────────────────────────────────────────────────────────
# CLI DIAGNOSTIC
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("reports", data.get("advisories", [data]))
    else:
        # Self-test with synthetic items
        items = [
            {
                "title": "CISA KEV: CVE-2024-12345 Actively Exploited in Ransomware Campaigns",
                "description": "A critical remote code execution vulnerability in Apache Log4j is being actively exploited "
                               "by ransomware groups to gain initial access to enterprise networks. The exploit chain "
                               "involves JNDI injection leading to arbitrary code execution. Threat actors including "
                               "LockBit 3.0 and BlackBasta have been observed leveraging this vulnerability in campaigns "
                               "targeting financial services and healthcare sectors. CISA has added this to the KEV catalog "
                               "and mandated patching by all federal agencies. " * 10,
                "cve_id":        "CVE-2024-12345",
                "kev_present":   True,
                "cvss_score":    9.8,
                "epss_score":    0.95,
                "iocs":          [{"type": "domain", "value": "evil.com"}, {"type": "ipv4", "value": "1.2.3.4"},
                                  {"type": "sha256", "value": "abc123"}] * 4,
                "ttps":          [{"technique_id": "T1190"}, {"technique_id": "T1059"}, {"technique_id": "T1486"}],
                "source_url":    "https://cisa.gov/advisory/2024-12345",
            },
            {
                "title": "Short",
                "description": "Too brief.",
                "source_url":    "https://example.com",
            },
        ]

    guard  = QualityGuard()
    passed, failed = guard.filter_batch(items)
    print(json.dumps({
        "total":    len(items),
        "accepted": len(passed),
        "rejected": failed,
        "results": [
            {"title": i.get("title","")[:80], "confidence": i.get("confidence_score"),
             "maturity": i.get("exploit_maturity"), "trust": i.get("source_trust"),
             "sectors": i.get("sectors_targeted")}
            for i in passed
        ],
    }, indent=2, default=str))

