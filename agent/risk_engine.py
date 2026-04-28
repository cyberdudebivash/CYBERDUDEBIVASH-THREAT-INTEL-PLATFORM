#!/usr/bin/env python3
"""
risk_engine.py - CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
UPGRADED: Content-Aware Dynamic Risk Scoring + KEV weighting + EPSS tiers
+ Supply chain detection + PoC/active exploitation signals + CVE count scoring.

v22.0 ADDITIONS (fully non-breaking - calculate_risk_score() signature unchanged):
  - KEV presence now directly boosts base risk score (+2.5)
  - EPSS tiered weighting (very-high / high / medium) instead of binary threshold
  - Supply chain attack detection with dedicated signal weight
  - PoC public availability detection
  - Active in-the-wild exploitation detection
  - Nation-state involvement detection
  - Multi-CVE count boosting
  - Critical infrastructure targeting detection
  - All new signals use RISK_WEIGHTS from config for easy tuning

v17.0 ADDITIONS (preserved):
  - predictive_risk_delta, exploit_velocity, intel_confidence_score,
    threat_momentum_score via compute_extended_metrics()

All existing calculate_risk_score() output fields are UNCHANGED.
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

from agent.config import RISK_WEIGHTS, TLP_MATRIX, SUPPLY_CHAIN_SIGNALS

logger = logging.getLogger("CDB-RISK-ENGINE")


class RiskScoringEngine:
    """
    Content-aware dynamic risk scoring with impact intelligence.
    """

    # -- Threat severity keywords with weights --
    SEVERITY_SIGNALS = {
        # Critical severity (weight 3.0+)
        "zero-day": 3.5, "zero day": 3.5, "0-day": 3.5, "0day": 3.5,
        "actively exploited": 3.0, "in the wild": 2.5,
        "critical vulnerability": 3.0, "remote code execution": 3.0,
        "rce": 2.5, "pre-auth": 2.5,
        "nation-state": 2.5, "state-sponsored": 2.5,
        "ransomware attack": 2.5, "supply chain attack": 2.5,
        "supply chain compromise": 2.5,
        # High severity (weight 1.5-2.5)
        "data breach": 2.0, "records exposed": 2.0, "records leaked": 2.0,
        "customer records": 1.8, "customer data": 1.8,
        "personal data": 1.8, "pii exposed": 2.0,
        "ransomware": 2.0, "malware campaign": 1.8,
        "backdoor": 1.8, "rootkit": 2.0,
        "privilege escalation": 1.5, "authentication bypass": 2.0,
        "credential theft": 1.8, "credential stuffing": 1.5,
        "credential harvest": 1.8, "harvested credentials": 1.8,
        "session token": 1.8, "token theft": 1.8,
        "data exfiltration": 2.0, "data stolen": 2.0,
        "hackers leak": 2.0, "hackers claim": 1.5,
        "critical infrastructure": 2.0,
        "financial fraud": 1.8, "banking trojan": 1.8,
        "espionage": 2.0, "cyber espionage": 2.0,
        # Browser / Extension attacks (NEW)
        "malicious extension": 2.0, "fake extension": 2.0,
        "browser extension": 1.5, "chrome extension": 1.5,
        "malicious browser": 1.8, "fake browser": 1.8,
        "malicious plugin": 1.8, "fake plugin": 1.8,
        "webstore": 1.2, "web store": 1.2,
        "browser hijack": 2.0, "session hijack": 1.8,
        "oauth token": 1.5, "cookie theft": 1.8,
        "users duped": 1.8, "users tricked": 1.8,
        "users compromised": 1.8, "users affected": 1.5,
        "users impacted": 1.5, "users targeted": 1.5,
        "impersonat": 1.5,
        # Identity / MFA / Account Compromise (NEW for 0ktapus-style campaigns)
        "mfa bypass": 2.2, "mfa fatigue": 2.0, "mfa interception": 2.2,
        "multi-factor authentication": 1.8, "mfa codes": 1.8,
        "sim swap": 2.0, "sim swapping": 2.0,
        "account takeover": 2.0, "identity theft": 2.0,
        "identity credential": 1.8, "okta": 1.5,
        "credential phishing": 1.8, "spear phishing": 1.5,
        "smishing": 1.5, "sms phishing": 1.5,
        "authentication page": 1.5, "spoofed": 1.5, "mimicked": 1.5,
        "organizations being compromised": 2.0, "accounts compromised": 2.0,
        # Medium severity (weight 0.8-1.5)
        "vulnerability": 1.0, "exploit": 1.2,
        "phishing campaign": 1.2, "phishing attack": 1.2,
        "phishing": 1.0,
        "social engineering": 1.0, "clickfix": 1.2,
        "malware": 1.2, "trojan": 1.2, "stealer": 1.2,
        "botnet": 1.2, "infostealer": 1.2,
        "security flaw": 1.0, "security bug": 1.0,
        "patch": 0.8, "update": 0.5, "security update": 0.8,
        "denial of service": 1.0, "ddos": 1.0,
        "unauthorized access": 1.5,
        "leaked": 1.5, "exposed": 1.5,
        "compromised": 1.5, "breached": 1.5,
        "duped": 1.5, "tricked": 1.5,
        "fake ai": 1.5, "malicious ai": 1.5,
    }

    # -- Impact magnitude patterns --
    # KEY FIXES in v12.1:
    # - \+? after K/M to handle "260K+" shorthand
    # - (?:\w+\s+){0,3} to handle multi-word gaps like "Chrome Users"
    # - More action verbs: installed, duped, tricked, targeted, infected, hit
    # - Patterns that work WITHOUT requiring action verb after entity
    ENTITY_WORDS = r'(?:records|users|customers|accounts|people|individuals|patients|loanees|members|victims|devices|systems|endpoints)'
    IMPACT_PATTERNS = [
        # -- K/M SHORTHAND (260K+, 2.5M, 600K) --
        # Handles: "260K+ Chrome Users", "2.5M records exposed", "600K customer records"
        (r'(\d+(?:\.\d+)?)[Kk]\+?\s+(?:\w+\s+){0,3}' + ENTITY_WORDS, "records", 1_000),
        (r'(\d+(?:\.\d+)?)[Mm]\+?\s+(?:\w+\s+){0,3}' + ENTITY_WORDS, "records", 1_000_000),

        # -- MILLIONS: "2.5 million loanees", "over 1.2 million patient records" --
        (r'(?:over\s+)?(\d+(?:\.\d+)?)\s*(?:million)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1_000_000),
        (r'(\d+(?:\.\d+)?)\s*(?:million)\s+(?:affected|impacted|exposed|breached|compromised)',
         "affected", 1_000_000),

        # -- THOUSANDS: "50 thousand users" --
        (r'(?:over\s+)?(\d+(?:\.\d+)?)\s*(?:thousand)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1_000),

        # -- DIRECT NUMBERS: "260,000 Chrome users", "600000 customer records" --
        # Up to 3 words between number and entity
        (r'(?:over\s+|more\s+than\s+)?(\d[\d,]+)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1),

        # -- VERB-FIRST: "affected 500,000 users", "exposed 2.5M records" --
        (r'(?:exposed|leaked|breached|stolen|compromised|affected|impacted|infected|hit|targeted|duped|tricked)\s+(?:\w+\s+){0,2}(\d[\d,]+)\s+(?:\w+\s+){0,2}' + ENTITY_WORDS,
         "records", 1),

        # -- DOLLAR AMOUNTS --
        (r'\$\s*(\d+(?:\.\d+)?)\s*(?:million|M|billion|B)', "financial", 1_000_000),
        (r'(\d+(?:\.\d+)?)\s*(?:million|M)\s*(?:dollars|\$|USD)', "financial", 1_000_000),
    ]

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def extract_impact_metrics(self, headline: str, content: str) -> Dict:
        """
        Extract quantified impact metrics from text.
        Returns: {records_affected, financial_impact, severity_keywords, impact_score}
        """
        text = f"{headline} {content}"
        metrics = {
            "records_affected": 0,
            "financial_impact": 0,
            "severity_keywords": [],
            "impact_score": 0.0,
            "affected_entities": [],
        }

        # Extract record/user counts
        for pattern, metric_type, multiplier in self.IMPACT_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                try:
                    num = float(match.replace(',', ''))
                    value = num * multiplier
                    if metric_type == "records":
                        metrics["records_affected"] = max(metrics["records_affected"], int(value))
                    elif metric_type == "financial":
                        metrics["financial_impact"] = max(metrics["financial_impact"], value)
                except (ValueError, TypeError):
                    continue

        # Extract severity keywords found
        text_lower = text.lower()
        for keyword, weight in self.SEVERITY_SIGNALS.items():
            if keyword in text_lower:
                metrics["severity_keywords"].append((keyword, weight))

        # Calculate impact score from metrics
        impact = 0.0

        # Record count impact
        if metrics["records_affected"] >= 10_000_000:
            impact += 4.0
        elif metrics["records_affected"] >= 1_000_000:
            impact += 3.0
        elif metrics["records_affected"] >= 100_000:
            impact += 2.5
        elif metrics["records_affected"] >= 10_000:
            impact += 1.5
        elif metrics["records_affected"] >= 1_000:
            impact += 1.0

        # Keyword severity impact (take top 3 weights)
        if metrics["severity_keywords"]:
            sorted_kw = sorted(metrics["severity_keywords"], key=lambda x: x[1], reverse=True)
            top_weights = [w for _, w in sorted_kw[:3]]
            impact += sum(top_weights) / len(top_weights)  # Average of top 3

        # Financial impact
        if metrics["financial_impact"] >= 100_000_000:
            impact += 2.0
        elif metrics["financial_impact"] >= 1_000_000:
            impact += 1.0

        metrics["impact_score"] = round(min(impact, 6.0), 1)  # Cap content boost at 6.0

        return metrics

    def calculate_risk_score(
        self,
        iocs: Dict[str, List[str]],
        mitre_matches: Optional[List[Dict]] = None,
        actor_data: Optional[Dict] = None,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        headline: str = "",
        content: str = "",
        kev_present: bool = False,
    ) -> float:
        """
        Calculate dynamic risk score (0.0 - 10.0).
        v22.0: NOW INCLUDES KEV, supply chain, EPSS tiers, PoC, active exploitation.
        Signature extended with optional kev_present (default False = backward compatible).
        """
        # v23.0: base_score reduced 2.0->1.0
        # This prevents articles with zero real threat signals from scoring 4+ from base alone
        score = 1.0
        text_lower = f"{headline} {content}".lower()

        # -- IOC Diversity Scoring (preserved) --
        ioc_categories_found = sum(1 for v in iocs.values() if v)
        score += ioc_categories_found * self.weights.get("base_ioc_count", 0.5)

        if iocs.get('sha256') or iocs.get('sha1') or iocs.get('md5'):
            score += self.weights.get("has_sha256", 1.5)
        if iocs.get('ipv4'):
            score += self.weights.get("has_ipv4", 1.0)
        if iocs.get('domain'):
            score += self.weights.get("has_domain", 0.8)
        if iocs.get('url'):
            score += self.weights.get("has_url", 0.7)
        if iocs.get('email'):
            score += self.weights.get("has_email", 0.5)
        if iocs.get('registry'):
            score += self.weights.get("has_registry", 1.2)
        if iocs.get('artifacts'):
            score += self.weights.get("has_artifacts", 1.0)

        # -- MITRE ATT&CK Scoring (preserved) --
        if mitre_matches:
            score += len(mitre_matches) * self.weights.get("mitre_technique_count", 0.3)

        # -- Actor Attribution Scoring (preserved) --
        if actor_data:
            tracking_id = actor_data.get('tracking_id', '')
            if tracking_id and not tracking_id.startswith('UNC-'):
                score += self.weights.get("actor_mapped", 1.0)
            else:
                score += 0.3

        # -- CVSS Scoring (preserved) --
        if cvss_score and cvss_score >= 9.0:
            score += self.weights.get("cvss_above_9", 2.0)
        elif cvss_score and cvss_score >= 7.0:
            score += 1.0

        # -- v22.0: EPSS Tiered Scoring (replaces binary threshold) --
        # v46.0 FIX: Removed dead branches (0.90/0.50 were unreachable after 0.10)
        if epss_score is not None:
            if epss_score >= 0.70:
                score += self.weights.get("epss_tier_very_high", 1.8)
                logger.debug(f"EPSS very-high tier: +{self.weights.get('epss_tier_very_high', 1.8)}")
            elif epss_score >= 0.40:
                score += self.weights.get("epss_tier_high", 1.2)
            elif epss_score >= 0.10:
                score += self.weights.get("epss_tier_medium", 0.6)
            elif epss_score >= 0.01:
                score += 0.2  # Low but nonzero EPSS

        # -- v22.0: KEV Presence (CRITICAL signal - confirmed exploited) --
        if kev_present:
            kev_boost = self.weights.get("kev_present", 2.5)
            score += kev_boost
            logger.info(f"? KEV CONFIRMED: +{kev_boost} risk boost applied")

        # -- v22.0: Active Exploitation Signal --
        # NOTE: active_exploitation is a GROUND-TRUTH signal — NOT subject to behavioral cap.
        active_exploit_terms = [
            "actively exploited", "in the wild", "active exploitation",
            "exploited in the wild", "under active attack", "being exploited"
        ]
        if any(t in text_lower for t in active_exploit_terms):
            boost = self.weights.get("active_exploitation", 2.5)
            score += boost
            logger.info(f"[!] Active exploitation detected: +{boost}")

        # -- v23.0: Behavioral Signals (with stacking cap) ──────────────────
        # Supply chain, PoC, and nation-state are CONTEXTUAL signals.
        # They add to score but are collectively CAPPED to prevent inflation
        # to 10/10 from signal stacking alone (without ground-truth evidence).
        _behavioral_cap = self.weights.get("behavioral_signal_cap", 3.5)
        _behavioral_total = 0.0

        # -- v22.0: Supply Chain Attack Detection --
        supply_chain_hit = any(sig in text_lower for sig in SUPPLY_CHAIN_SIGNALS)
        if supply_chain_hit:
            boost = self.weights.get("supply_chain_signal", 1.5)
            _behavioral_total += boost
            logger.info(f"? Supply chain signal detected: +{boost}")

        # -- v22.0: Public PoC Availability --
        poc_terms = [
            "proof of concept", "poc available", "poc released",
            "exploit released", "exploit code available", "weaponized",
            "metasploit module", "exploit published"
        ]
        if any(t in text_lower for t in poc_terms):
            boost = self.weights.get("poc_public", 1.2)
            _behavioral_total += boost
            logger.info(f"? Public PoC detected: +{boost}")

        # -- v22.0: Nation-State Actor Involvement --
        nation_state_terms = [
            # v75.3: removed bare "apt" (fires on laptop/captain/adapt)
            "nation-state", "state-sponsored", "lazarus group",
            "cozy bear", "fancy bear", "volt typhoon", "salt typhoon",
            "sandworm", "hafnium", "charming kitten", "apt28", "apt29",
            "apt34", "apt41", "apt38", "nasir security", "teampcp",
            "state-nexus actor", "state-sponsored actor", "pro-iranian threat",
        ]
        import re as _re_ns
        _apt_number = bool(_re_ns.search(r'\\bapt\\s*\\d+', text_lower))
        if _apt_number or any(t in text_lower for t in nation_state_terms):
            boost = self.weights.get("nation_state", 1.5)
            _behavioral_total += boost
            logger.info(f"? Nation-state signal detected: +{boost}")

        # Apply behavioral signals with cap enforcement
        capped_behavioral = min(_behavioral_total, _behavioral_cap)
        if capped_behavioral < _behavioral_total:
            logger.info(f"[v23.0] Behavioral signal cap applied: {_behavioral_total:.1f} -> {capped_behavioral:.1f}")
        score += capped_behavioral

        # -- v22.0: Critical Infrastructure Targeting --
        critical_infra_terms = [
            # v75.3: removed bare "bank" (fires on "banking app", "bank account")
            "critical infrastructure", "power grid", "water treatment plant",
            "hospital network", "healthcare system", "financial institution",
            "government network", "military network", "nuclear facility",
            "ics attack", "scada attack", "operational technology breach",
            "industrial control system", "energy grid attack", "utility attack",
        ]
        if any(t in text_lower for t in critical_infra_terms):
            boost = self.weights.get("critical_infra", 1.5)
            score += boost
            logger.info(f"? Critical infrastructure target detected: +{boost}")

        # -- v22.0: Multi-CVE Boosting --
        cve_ids = iocs.get('cve', [])
        if len(cve_ids) > 1:
            extra_cves = len(cve_ids) - 1
            cve_boost = min(extra_cves * self.weights.get("cve_count_multi", 0.4), 1.6)
            score += cve_boost
            if cve_boost > 0:
                logger.debug(f"Multi-CVE boost ({len(cve_ids)} CVEs): +{cve_boost}")

        # -- Content-Aware Intelligence Analysis (v23.0 FIXED) --
        # v23.0 FIX: Cap content boost when no real IOCs present.
        # Without this cap, articles with zero IOCs (Google announcements, news roundups)
        # could reach 8-10 score purely from keyword matching in the article text.
        if headline or content:
            impact = self.extract_impact_metrics(headline, content)
            content_boost = impact["impact_score"]
            if content_boost > 0:
                # Cap content boost based on IOC presence to prevent keyword inflation
                real_ioc_count = sum(1 for k in ['sha256','md5','sha1','ipv4','domain','cve']
                                     if iocs.get(k))
                if real_ioc_count == 0:
                    content_boost = min(content_boost, 1.5)  # Hard cap: no IOCs = max +1.5
                elif real_ioc_count == 1:
                    content_boost = min(content_boost, 3.0)  # One IOC type = max +3.0
                score += content_boost
                logger.info(f"Content intelligence boost: +{content_boost} "
                           f"(records: {impact['records_affected']:,}, "
                           f"keywords: {len(impact['severity_keywords'])}, "
                           f"ioc_types: {real_ioc_count})")

        # -- Cap at maximum --
        max_score = self.weights.get("max_score", 10.0)
        final_score = min(round(score, 1), max_score)


        # ── v143.0: NO-EVIDENCE CAP ───────────────────────────────────────────
        # A score ≥ 8 (HIGH/CRITICAL) asserts confirmed severe threat.
        # Without at least one piece of EXTERNAL evidence we cannot defensibly
        # make that claim. Prevents pure keyword-stacking articles (Wordfence
        # roundups, advisory summaries) from scoring 10/10 when there is no
        # CVSS, no EPSS signal, no KEV, no hash, and no IP.
        #
        # Evidence qualifiers (ANY ONE satisfies the gate):
        #   - KEV confirmed (CISA known exploited)
        #   - CVSS >= 4.0 (NVD-sourced severity)
        #   - EPSS >= 0.05 (5%+ exploitation probability in 30 days)
        #   - File hash IOC (sha256 / sha1 / md5)
        #   - IPv4 IOC (confirmed C2/attacker network observable)
        _has_real_evidence = (
            kev_present
            or (cvss_score is not None and float(cvss_score) >= 4.0)
            or (epss_score is not None and float(epss_score) >= 0.05)
            or bool(iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"))
            or bool(iocs.get("ipv4"))
        )
        _NO_EVIDENCE_CEIL = 5.5
        if not _has_real_evidence and final_score > _NO_EVIDENCE_CEIL:
            logger.info(
                "[v143.0] No-evidence cap: %.1f → %.1f "
                "(kev=%s cvss=%s epss=%s hashes=%s ips=%s)",
                final_score, _NO_EVIDENCE_CEIL,
                kev_present, cvss_score, epss_score,
                bool(iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5")),
                bool(iocs.get("ipv4")),
            )
            final_score = _NO_EVIDENCE_CEIL
        logger.info(
            f"Dynamic Risk Score v23.0: {final_score}/10 "
            f"(IOC cats: {ioc_categories_found}, "
            f"MITRE: {len(mitre_matches or [])}, "
            f"KEV: {kev_present}, "
            f"Actor: {bool(actor_data)}, "
            f"SupplyChain: {supply_chain_hit})"
        )

        return final_score

    def get_severity_label(self, risk_score: float) -> str:
        if risk_score >= 8.5:
            return "CRITICAL"
        elif risk_score >= 6.5:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        return "INFO"

    def get_risk_reason(
        self,
        risk_score: float,
        *,
        kev_present: bool = False,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        iocs: Optional[Dict] = None,
        mitre_matches: Optional[List] = None,
        actor_data: Optional[Dict] = None,
    ) -> str:
        """
        v143.0: Generate a human-readable, SOC-defensible explanation for the
        risk score. Surfaces the primary evidence signals that drove the score.
        Returns a concise string for the `risk_reason` manifest field.
        """
        iocs = iocs or {}
        parts: list = []

        if kev_present:
            parts.append("KEV confirmed (CISA active exploitation)")

        if cvss_score is not None:
            label = ("CRITICAL" if cvss_score >= 9.0 else
                     "HIGH"     if cvss_score >= 7.0 else
                     "MEDIUM"   if cvss_score >= 4.0 else "LOW")
            parts.append(f"CVSS {cvss_score:.1f} ({label})")

        if epss_score is not None:
            if epss_score >= 0.70:
                parts.append(f"EPSS {epss_score:.2f} (very high exploitation probability)")
            elif epss_score >= 0.40:
                parts.append(f"EPSS {epss_score:.2f} (high exploitation probability)")
            elif epss_score >= 0.05:
                parts.append(f"EPSS {epss_score:.2f} (moderate exploitation probability)")

        _hashes = (list(iocs.get("sha256", [])) + list(iocs.get("sha1", [])) + list(iocs.get("md5", [])))
        if _hashes:
            parts.append(f"{len(_hashes)} file hash IOC(s)")
        if iocs.get("ipv4"):
            parts.append(f"{len(iocs['ipv4'])} IPv4 IOC(s)")
        if iocs.get("domain"):
            parts.append(f"{len(iocs['domain'])} domain IOC(s)")
        if iocs.get("url"):
            parts.append(f"{len(iocs['url'])} malicious URL(s)")

        if mitre_matches:
            parts.append(f"{len(mitre_matches)} MITRE technique(s) mapped")

        if actor_data:
            tid = actor_data.get("tracking_id", "")
            actor = actor_data.get("actor", actor_data.get("name", ""))
            if tid and not tid.startswith("UNC-") and actor:
                parts.append(f"confirmed actor: {actor}")

        _has_evidence = (
            kev_present
            or (cvss_score is not None and float(cvss_score) >= 4.0)
            or (epss_score is not None and float(epss_score) >= 0.05)
            or bool(iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"))
            or bool(iocs.get("ipv4"))
        )
        if not _has_evidence:
            parts.append("no external evidence (CVSS/EPSS/KEV/hash/IP absent); score capped at 5.5")

        if not parts:
            parts.append(f"keyword/behavioral signals only; score={risk_score}")

        return "; ".join(parts)

    def get_tlp_label(self, risk_score: float,
                      iocs: Dict = None, kev_present: bool = False,
                      confirmed_actor: bool = False,
                      cvss_score: float = None) -> Dict[str, str]:
        """
        v76.2 CORRECTED: Evidence-based TLP with CVSS as primary qualifier.

        TLP:RED   -> (KEV confirmed) OR (CVSS >= 9.0) OR (score >= 9 AND real IOCs AND confirmed actor)
        TLP:AMBER -> score >= 7.0 AND (real IOCs OR CVEs OR CVSS >= 7.0 OR KEV)
        TLP:GREEN -> score >= 4.0
        TLP:CLEAR -> anything else

        v23.0 introduced evidence gating to prevent keyword-inflated TLP:RED.
        v76.2 fixes the over-correction: CVSS >= 9.0 is definitive evidence of
        a critical vulnerability - it does NOT require KEV confirmation.
        A Canon CVSS 9.8 RCE is TLP:RED regardless of KEV catalog status.
        Non-CVE articles still require KEV or confirmed actor+IOC for RED.
        """
        iocs = iocs or {}
        has_real_iocs = any([
            iocs.get('sha256'), iocs.get('md5'), iocs.get('sha1'),
            iocs.get('ipv4'), iocs.get('domain'), iocs.get('cve'),
        ])
        has_cvss_critical = cvss_score is not None and float(cvss_score) >= 9.0
        has_cvss_high     = cvss_score is not None and float(cvss_score) >= 7.0

        # -- TLP:RED --------------------------------------------------
        if risk_score >= 9.0:
            if kev_present:
                # KEV = confirmed active exploitation -> always RED
                return {"label": "TLP:RED", "color": "#ff3e3e"}
            if has_cvss_critical:
                # CVSS >= 9.0 is definitive severity evidence -> RED
                return {"label": "TLP:RED", "color": "#ff3e3e"}
            if has_real_iocs and confirmed_actor:
                # Named actor + confirmed IOCs -> RED
                return {"label": "TLP:RED", "color": "#ff3e3e"}
            # High score but no CVE/KEV/actor evidence -> AMBER
            # (prevents non-CVE editorial articles scoring 10/10 from getting RED)
            return {"label": "TLP:AMBER", "color": "#ff9f43"}

        # -- TLP:AMBER -------------------------------------------------
        if risk_score >= 7.0:
            if kev_present or has_real_iocs or has_cvss_high:
                return {"label": "TLP:AMBER", "color": "#ff9f43"}
            return {"label": "TLP:GREEN", "color": "#00e5c3"}

        # -- TLP:GREEN -------------------------------------------------
        if risk_score >= 4.0:
            return {"label": "TLP:GREEN", "color": "#00e5c3"}

        return {"label": "TLP:CLEAR", "color": "#94a3b8"}


    def recalculate_with_nvd(
        self,
        base_score: float,
        cvss_score: float = None,
        epss_score: float = None,
        kev_present: bool = False,
    ) -> float:
        """
        v75.5: Recalculate risk score AFTER NVD data is fetched.
        Call this AFTER _enrich_cve_metadata() to apply real CVSS/EPSS to score.

        This fixes the pipeline ordering bug:
          Step 5: calculate_risk_score() -> base_score (no CVSS yet)
          Step 7b: _enrich_cve_metadata() -> CVSS, EPSS, KEV fetched
          <- INSERT: recalculate_with_nvd() -> final_score with CVSS applied

        Rules:
          - CVSS 9.0-10.0 -> minimum score 8.5 (CRITICAL floor)
          - CVSS 7.0-8.9  -> minimum score 6.5 (HIGH floor)
          - CVSS 4.0-6.9  -> minimum score 4.0 (MEDIUM floor)
          - EPSS > 0.70   -> +2.0 boost (very high exploitation probability)
          - EPSS > 0.40   -> +1.5 boost
          - EPSS > 0.10   -> +0.8 boost
          - KEV confirmed -> +2.5 boost (confirmed exploited in wild)
          - Never LOWER a score below base_score
        """
        score = base_score

        # CVSS floor enforcement - never score below CVSS-derived minimum
        if cvss_score is not None:
            if cvss_score >= 9.0:
                score = max(score, 8.5)   # CRITICAL floor
                score += self.weights.get('cvss_above_9', 2.0)
            elif cvss_score >= 7.0:
                score = max(score, 6.5)   # HIGH floor
                score += 1.0
            elif cvss_score >= 4.0:
                score = max(score, 4.0)   # MEDIUM floor
                score += 0.5

        # EPSS tiered boost
        if epss_score is not None:
            if epss_score >= 0.70:
                score += self.weights.get('epss_tier_very_high', 1.8)
            elif epss_score >= 0.40:
                score += self.weights.get('epss_tier_high', 1.2)
            elif epss_score >= 0.10:
                score += self.weights.get('epss_tier_medium', 0.6)

        # KEV confirmed exploited
        if kev_present:
            score += self.weights.get('kev_present', 2.5)
            logger.info(f"KEV CONFIRMED: +{self.weights.get('kev_present', 2.5)} NVD boost")

        final = min(round(score, 1), self.weights.get('max_score', 10.0))
        if final != base_score:
            logger.info(f"NVD recalculation: {base_score:.1f} -> {final:.1f} "
                        f"(CVSS={cvss_score}, EPSS={epss_score}, KEV={kev_present})")
        return final

    # ==============================================================
    # v17.0 EXTENDED METRICS - SUPPLEMENTARY INTELLIGENCE FIELDS
    # All methods below are ADDITIVE. They do not modify any
    # existing method output. Call compute_extended_metrics() after
    # calculate_risk_score() to get additional intelligence signals.
    # ==============================================================

    def compute_extended_metrics(
        self,
        risk_score: float,
        headline: str = "",
        content: str = "",
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        kev_present: bool = False,
        source_count: int = 1,
        iocs: Optional[Dict] = None,
        mitre_matches: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Compute supplementary intelligence metrics for a threat item.
        Returns a dict of new fields - NEVER modifies base risk_score.

        New fields:
          - predictive_risk_delta: estimated risk change signal (-3.0 to +3.0)
          - exploit_velocity: exploit momentum signal (0.0-10.0)
          - intel_confidence_score: multi-source confidence (0.0-100.0)
          - threat_momentum_score: Sentinel Momentum Index(TM) (0.0-10.0)
        """
        predictive_delta = self._compute_predictive_risk_delta(
            headline, content, cvss_score, epss_score, kev_present
        )
        exploit_velocity = self._compute_exploit_velocity(headline, content, cvss_score)
        intel_confidence = self._compute_intel_confidence(
            source_count, iocs or {}, mitre_matches or [], risk_score
        )
        momentum = self._compute_threat_momentum(exploit_velocity, predictive_delta)

        extended = {
            "predictive_risk_delta": round(predictive_delta, 2),
            "exploit_velocity": round(exploit_velocity, 2),
            "intel_confidence_score": round(intel_confidence, 1),
            "threat_momentum_score": round(momentum, 2),
            "threat_momentum_label": self._momentum_label(momentum),
        }

        logger.info(
            f"? Extended Metrics | "
            f"? Risk: {extended['predictive_risk_delta']:+.2f} | "
            f"Velocity: {extended['exploit_velocity']}/10 | "
            f"Confidence: {extended['intel_confidence_score']}% | "
            f"Momentum: {extended['threat_momentum_score']}/10 ({extended['threat_momentum_label']})"
        )

        return extended

    def _compute_predictive_risk_delta(
        self,
        headline: str,
        content: str,
        cvss_score: Optional[float],
        epss_score: Optional[float],
        kev_present: bool,
    ) -> float:
        """
        Estimate how risk is likely to change over the next 14 days.
        Positive delta = risk likely increasing. Negative = stabilizing.
        Range: -3.0 to +3.0
        """
        delta = 0.0
        text = f"{headline} {content}".lower()

        # Positive signals (risk escalating)
        if kev_present:
            delta += 1.5
        if epss_score and epss_score >= 0.9:
            delta += 1.0
        elif epss_score and epss_score >= 0.5:
            delta += 0.5
        if any(t in text for t in ["zero-day", "0-day", "actively exploited", "in the wild"]):
            delta += 1.0
        if any(t in text for t in ["ransomware", "nation-state", "supply chain attack"]):
            delta += 0.8
        if cvss_score and cvss_score >= 9.0:
            delta += 0.5

        # Negative signals (risk stabilizing)
        if any(t in text for t in ["patched", "fixed", "mitigated", "remediated", "update available"]):
            delta -= 1.0
        if any(t in text for t in ["no active exploitation", "not exploited", "theoretical"]):
            delta -= 0.8

        return max(-3.0, min(3.0, delta))

    def _compute_exploit_velocity(
        self,
        headline: str,
        content: str,
        cvss_score: Optional[float],
    ) -> float:
        """
        Compute exploit momentum: how quickly this threat is accelerating.
        Based on urgency signals + CVSS + content keywords.
        Range: 0.0 - 10.0
        """
        text = f"{headline} {content}".lower()
        velocity = 2.0  # Baseline

        # High velocity signals
        if "actively exploited" in text or "in the wild" in text:
            velocity += 3.0
        if "zero-day" in text or "0-day" in text:
            velocity += 2.5
        if "ransomware" in text:
            velocity += 2.0
        if "nation-state" in text or "state-sponsored" in text:
            velocity += 1.5
        if "poc available" in text or "proof of concept" in text:
            velocity += 1.5
        if "critical" in text:
            velocity += 1.0
        if cvss_score and cvss_score >= 9.0:
            velocity += 1.5
        elif cvss_score and cvss_score >= 7.0:
            velocity += 0.8

        # Velocity dampeners
        if "low severity" in text or "informational" in text:
            velocity -= 1.5
        if "patched" in text or "fixed" in text:
            velocity -= 1.0

        return max(0.0, min(10.0, velocity))

    def _compute_intel_confidence(
        self,
        source_count: int,
        iocs: Dict,
        mitre_matches: List[Dict],
        risk_score: float,
    ) -> float:
        """
        Weighted multi-source confidence score (0.0 - 100.0).
        Based on: source diversity, IOC richness, MITRE coverage, risk signal strength.
        """
        confidence = 20.0  # Base

        # Source diversity contribution (up to 25 pts)
        confidence += min(source_count * 5.0, 25.0)

        # IOC richness contribution (up to 30 pts)
        ioc_types_found = sum(1 for v in iocs.values() if v)
        confidence += min(ioc_types_found * 5.0, 30.0)

        # MITRE coverage contribution (up to 20 pts)
        confidence += min(len(mitre_matches) * 3.0, 20.0)

        # Risk score strength (up to 5 pts bonus for high-confidence threats)
        if risk_score >= 8.0:
            confidence += 5.0
        elif risk_score >= 6.0:
            confidence += 3.0

        return min(confidence, 100.0)

    def _compute_threat_momentum(
        self, exploit_velocity: float, predictive_delta: float
    ) -> float:
        """
        Sentinel Momentum Index(TM) (SMI) - composite threat acceleration score.
        Formula: SMI = (exploit_velocity x 0.6) + (predictive_delta_normalized x 0.4)
        Range: 0.0 - 10.0
        """
        # Normalize predictive_delta from [-3, 3] to [0, 10]
        delta_normalized = ((predictive_delta + 3.0) / 6.0) * 10.0
        momentum = (exploit_velocity * 0.6) + (delta_normalized * 0.4)
        return max(0.0, min(10.0, momentum))

    def _momentum_label(self, momentum: float) -> str:
        if momentum >= 8.0:
            return "SURGE"
        elif momentum >= 6.0:
            return "ACCELERATING"
        elif momentum >= 4.0:
            return "ACTIVE"
        elif momentum >= 2.0:
            return "STABLE"
        return "LOW"


risk_engine = RiskScoringEngine()
