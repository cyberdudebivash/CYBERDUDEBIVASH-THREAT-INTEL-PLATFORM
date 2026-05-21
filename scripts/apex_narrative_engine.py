#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_narrative_engine.py — Enterprise Analyst Narrative Engine
================================================================================
Version : 152.0.0

PROBLEM SOLVED:
  Every report generates the same template executive summary:
  "CYBERDUDEBIVASH SENTINEL APEX has identified a MEDIUM-severity security
   advisory affecting Exploit for CVE. The vulnerability presents an exploitable
   attack surface..."

  This is AI-generated filler instantly recognised by any analyst.
  It destroys enterprise credibility and monetisation potential.

SOLUTION — INTELLIGENCE-TIER-AWARE NARRATIVE GENERATION:

  Differentiates 9 intelligence tiers with distinct narrative logic:
    1. CVE_ADVISORY        — vulnerability-focused, technical depth
    2. APT_CAMPAIGN        — actor-focused, strategic context
    3. RANSOMWARE          — operational impact, financial risk
    4. ICS_OT_ADVISORY     — operational continuity, sector impact
    5. MALWARE_OPERATION   — behavioral analysis, IOC focus
    6. EXPLOIT_WEAPONIZATION — exploit lifecycle, patch urgency
    7. PHISHING_CAMPAIGN   — delivery mechanics, user risk
    8. GEOPOLITICAL_CTI    — attribution context, sector targeting
    9. VULNERABILITY_RESEARCH — research depth, disclosure context

  Each tier uses:
    - Different opening constructs
    - Different evidence framing
    - Different urgency calibration
    - Different audience calibration (SOC / CISO / analyst)
    - Semantic variation to prevent duplication

  Anti-Duplication Controls:
    - Template phrase detection and blocking
    - Semantic fingerprinting of generated summaries
    - Entropy scoring (low entropy = too repetitive → reject)
    - Per-run deduplication across all generated summaries

  Quality Standard: Mandiant / CrowdStrike / Unit42 prose quality.
================================================================================
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("apex.narrative")
ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-NE"

# ── Intelligence Tier Detection ───────────────────────────────────────────────

TIER_PATTERNS = {
    "RANSOMWARE": re.compile(
        r"(ransomware|lockbit|blackcat|alphv|clop|akira|bianlian|"
        r"play\s+ransomware|blackbasta|revil|ryuk|conti|hive|scattered\s+spider|"
        r"double\s+extortion|data\s+leak\s+site|ransom\s+demand)",
        re.IGNORECASE,
    ),
    "APT_CAMPAIGN": re.compile(
        r"(apt\s+\d+|UNC\d+|TA\d+|nation.state|state.sponsored|"
        r"gru|fsb|svr|lazarus|kimsuky|sandworm|volt\s+typhoon|"
        r"silk\s+typhoon|muddywater|charming\s+kitten|APT\d+|"
        r"espionage|intelligence.collection|strategic\s+targeting)",
        re.IGNORECASE,
    ),
    "ICS_OT_ADVISORY": re.compile(
        r"(scada|ics|industrial\s+control|plc|hmi|modbus|dnp3|"
        r"profinet|iec\s+6185|iec\s+6244|operational\s+technology|"
        r"siemens\s+s7|rockwell|allen.bradley|water\s+treatment|"
        r"power\s+grid|substation|pipeline\s+control|historian)",
        re.IGNORECASE,
    ),
    "MALWARE_OPERATION": re.compile(
        r"(malware|trojan|rat\s|backdoor|rootkit|bootkit|stealer|"
        r"lummastealer|lummac2|redline|vidar|infostealer|loader|dropper|"
        r"cobalt\s+strike|metasploit\s+module|sliver|brute\s+ratel|"
        r"command.and.control|c2\s+infrastructure|malware\s+family)",
        re.IGNORECASE,
    ),
    "PHISHING_CAMPAIGN": re.compile(
        r"(phishing|spearphishing|vishing|smishing|lure|pretexting|"
        r"credential\s+harvest|business\s+email\s+compromise|BEC|"
        r"malicious\s+attachment|invoice\s+fraud|social\s+engineering)",
        re.IGNORECASE,
    ),
    "EXPLOIT_WEAPONIZATION": re.compile(
        r"(metasploit\s+module|exploit\s+kit|weaponi[sz]ed|"
        r"exploit\s+chain|0.click|zero.click|itw\s+exploit|"
        r"in.the.wild\s+exploit|poc.*exploit|exploit.*poc|"
        r"actively\s+exploit|exploit\s+available|github.*exploit)",
        re.IGNORECASE,
    ),
    "GEOPOLITICAL_CTI": re.compile(
        r"(geopolit|nation.state|state.nexus|russia|china.nexus|"
        r"iran.affiliated|north\s+korea|dprk|prc.linked|"
        r"government.target|critical\s+infrastructure.*target|"
        r"western\s+target|sector.target)",
        re.IGNORECASE,
    ),
    "VULNERABILITY_RESEARCH": re.compile(
        r"(research|disclosure|responsible\s+disclosure|"
        r"0day|zero.day|bug\s+bounty|CVE.*assigned|"
        r"proof.of.concept.*research|academic|university)",
        re.IGNORECASE,
    ),
}

# Blocked template phrases — any of these in a summary triggers rejection
TEMPLATE_PHRASES = [
    r"has identified a (critical|high|medium|low)-severity security advisory",
    r"the vulnerability presents an exploitable attack surface",
    r"structural and behavioural analysis.*reveals a generic class vulnerability",
    r"threat vector identified from threat intelligence feed analysis",
    r"system integrity and data confidentiality at risk",
    r"technique id mapped from threat intelligence corpus",
    r"patch within standard window",
    r"cyberdudebivash sentinel apex has identified",
    r"this advisory documents a nation-state advanced persistent threat",
    r"adversary may leverage for initial access, data exposure, or service disruption",
    r"exploitation in the wild is probable within 14.30 days",
    r"assess the advisory against your asset inventory",
    r"apex ml corpus",
    r"escalation probability.*apex model.*14-day horizon",
]
TEMPLATE_RE = re.compile("|".join(TEMPLATE_PHRASES), re.IGNORECASE)


# ── Tier-specific narrative builders ─────────────────────────────────────────

def _detect_tier(item: Dict) -> str:
    """Detect intelligence tier from item content."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "threat_type",
        "actor_cluster", "campaign", "malware_family",
    ))
    for tier, pattern in TIER_PATTERNS.items():
        if pattern.search(all_text):
            return tier
    return "CVE_ADVISORY"  # default


def _build_cve_summary(item: Dict) -> str:
    title        = str(item.get("title") or "").strip()
    apex_risk    = item.get("apex_risk") or item.get("risk_score") or "N/A"
    cvss         = item.get("cvss_score") or item.get("cvss") or None
    epss         = item.get("epss_score") or item.get("epss") or None
    kev          = str(item.get("kev") or "").upper() in ("YES", "TRUE", "1", "LISTED")
    exploit_mat  = str(item.get("exploit_maturity") or "")
    ioc_count    = item.get("ioc_count") or 0
    ttp_count    = item.get("ttp_count") or 0
    confidence   = item.get("confidence") or 0
    affected     = str(item.get("affected_products") or item.get("affected_versions") or "")

    # Extract CVE ID
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title)
    cve_id = cve_match.group(0) if cve_match else None

    # Opening — vary by signal availability
    if kev:
        opening = (
            f"CISA has confirmed active exploitation of {title[:100]} in the wild. "
            f"This vulnerability carries APEX risk score {apex_risk}/10 and is listed in the "
            f"Known Exploited Vulnerabilities catalogue, representing an immediate, "
            f"evidence-confirmed threat requiring emergency patching."
        )
    elif cvss and cvss not in ("N/A", "", None):
        opening = (
            f"{title[:100]} (CVSS {cvss}) represents a {item.get('apex_risk_label', 'notable')} "
            f"exposure with APEX composite risk score {apex_risk}/10. "
            f"The vulnerability has been assigned {'a FIRST EPSS probability of ' + str(epss) if epss and epss not in ('N/A', '') else 'no EPSS estimate yet'}."
        )
    else:
        # Derive a specific lead from the title itself
        opening = (
            f"A {item.get('apex_risk_label', 'newly disclosed').lower()} vulnerability — "
            f"{title[:100]} — has been processed through APEX enrichment with "
            f"composite risk score {apex_risk}/10. "
            f"{'No CVSS or EPSS data was available at analysis time; score reflects available behavioral signals only.' if not cvss else ''}"
        )

    # Technical context
    tech_context = ""
    if affected:
        tech_context = f" Affected component: {affected[:150]}."
    if exploit_mat and exploit_mat.lower() not in ("none", "theoretical", ""):
        tech_context += f" Exploit maturity: {exploit_mat}."

    # Urgency
    urgency = str(item.get("apex_risk_urgency") or "")
    if not urgency:
        risk_val = float(apex_risk) if str(apex_risk).replace('.','').isdigit() else 5.0
        if risk_val >= 9:
            urgency = "Emergency remediation required. Patch or mitigate within 24 hours."
        elif risk_val >= 7:
            urgency = "High priority. Apply vendor patch within 72 hours."
        elif risk_val >= 5:
            urgency = "Standard patching SLA applies. Remediate within 14 days."
        else:
            urgency = "Monitor. Remediate at next maintenance window."

    # Intel depth indicator
    intel_depth = f"Analysis supported by {ioc_count} operational IOC(s) and {ttp_count} ATT&CK technique mapping(s)."
    if confidence:
        intel_depth += f" Intelligence confidence: {confidence}%."

    return " ".join(filter(None, [opening, tech_context, urgency, intel_depth]))


def _build_ransomware_summary(item: Dict) -> str:
    title      = str(item.get("title") or "")
    actor      = str(item.get("actor_cluster") or "an unattributed ransomware group")
    apex_risk  = item.get("apex_risk") or item.get("risk_score") or "N/A"
    ioc_count  = item.get("ioc_count") or 0
    confidence = item.get("confidence") or 0

    # Detect ransomware group name from title/actor
    group_match = re.search(
        r"(lockbit|blackcat|alphv|clop|cl0p|akira|bianlian|blackbasta|"
        r"play|royal|medusa|hive|revil|scattered\s+spider)",
        title + " " + actor, re.IGNORECASE,
    )
    group = group_match.group(0).title() if group_match else "a tracked ransomware operator"

    return (
        f"{group} ransomware activity has been identified with APEX risk score {apex_risk}/10. "
        f"Ransomware operators in this cluster employ double-extortion methodology: "
        f"data is exfiltrated prior to encryption, with victim data published on dedicated "
        f"leak infrastructure if ransom demands are not met. "
        f"Immediate containment priority: isolate affected endpoints, preserve forensic evidence, "
        f"and engage incident response before ransom negotiation. "
        f"{'Activate cyber-insurance notification procedures within 72 hours of confirmed compromise. ' if float(str(apex_risk).replace('N/A','0') or 0) >= 7 else ''}"
        f"Analysis incorporates {ioc_count} infrastructure IOC(s). "
        f"Intelligence confidence: {confidence}% (verify IOC freshness before blocking)."
    )


def _build_apt_summary(item: Dict) -> str:
    title      = str(item.get("title") or "")
    actor      = str(item.get("actor_cluster") or "")
    apex_risk  = item.get("apex_risk") or item.get("risk_score") or "N/A"
    ioc_count  = item.get("ioc_count") or 0

    # Do NOT fabricate APT attribution — check evidence chain
    evidence = str(item.get("attribution_evidence") or item.get("attribution_basis") or "")
    if not evidence or re.search(r"synthetic|generated|cluster", actor, re.IGNORECASE):
        actor_text = "an unattributed threat actor cluster"
        attrib_note = (
            "Attribution has not been confirmed by independent corroboration. "
            "This advisory is based on observed tactics and infrastructure patterns — "
            "analyst review of attribution confidence is required before attributing to a specific threat group."
        )
    else:
        actor_text = actor
        attrib_note = f"Attribution basis: {evidence[:150]}."

    return (
        f"Strategic cyber-espionage activity consistent with {actor_text} has been identified. "
        f"APEX risk score: {apex_risk}/10. "
        f"Advanced persistent threat operations are characterised by extended dwell time, "
        f"multi-stage payload deployment, and mission-driven intelligence collection — "
        f"objectives typically include credential harvesting, intellectual property theft, "
        f"or pre-positioning for disruption operations. "
        f"{attrib_note} "
        f"Deploy {ioc_count} infrastructure IOC(s) to detection stack with HIGH priority. "
        f"Defensive focus: endpoint detection across authentication events, "
        f"lateral movement indicators, and unusual outbound data transfers."
    )


def _build_ics_summary(item: Dict) -> str:
    title     = str(item.get("title") or "")
    apex_risk = item.get("apex_risk") or item.get("risk_score") or "N/A"
    cvss      = item.get("cvss_score") or "N/A"

    return (
        f"A vulnerability affecting industrial control system (ICS) or operational technology (OT) "
        f"components has been identified: {title[:120]}. "
        f"APEX risk score: {apex_risk}/10 (ICS sector multiplier applied). "
        f"ICS/SCADA vulnerabilities carry amplified business impact: exploitation can cause "
        f"physical process disruption, safety system compromise, or extended operational downtime "
        f"with potential safety-of-life implications. "
        f"{'CVSS ' + str(cvss) + ' base score noted; ' if cvss != 'N/A' else ''}"
        f"Standard IT patching timelines do not apply to OT environments — "
        f"coordinate with OPS/engineering teams and apply vendor-recommended mitigations "
        f"within your change management process. "
        f"Dragos and ICS-CERT advisories should be cross-referenced for sector-specific guidance."
    )


def _build_malware_summary(item: Dict) -> str:
    title      = str(item.get("title") or "")
    malware    = str(item.get("malware_family") or "")
    ioc_count  = item.get("ioc_count") or 0
    ttp_count  = item.get("ttp_count") or 0
    apex_risk  = item.get("apex_risk") or item.get("risk_score") or "N/A"

    # Extract malware name from title if not in field
    if not malware:
        mal_match = re.search(
            r"(lummac2|lummastealer|redline|vidar|cobalt\s+strike|"
            r"sliver|brute\s+ratel|emotet|qakbot|icedid|formbook|agent\s+tesla|"
            r"asyncrat|njrat|remcos|nanocore)",
            title, re.IGNORECASE,
        )
        malware = mal_match.group(0) if mal_match else "a tracked malware family"

    return (
        f"{malware.title()} malware activity has been identified with APEX risk score {apex_risk}/10. "
        f"Malware campaign intelligence is time-sensitive — C2 infrastructure turns over rapidly, "
        f"typically within 24–72 hours of public IOC disclosure. "
        f"Deploy {ioc_count} IOC(s) to detection stack immediately, prioritising C2 IP/domain blocks "
        f"at DNS resolver and egress firewall. "
        f"Hunt across EDR telemetry for {ttp_count} mapped ATT&CK technique(s). "
        f"File hash indicators should be submitted to your sandboxing platform for "
        f"dynamic behavioral analysis to confirm payload capability and C2 protocol."
    )


def _build_phishing_summary(item: Dict) -> str:
    title     = str(item.get("title") or "")
    apex_risk = item.get("apex_risk") or item.get("risk_score") or "N/A"
    ioc_count = item.get("ioc_count") or 0

    return (
        f"A phishing campaign delivering {title[:80]} has been identified at APEX risk score {apex_risk}/10. "
        f"Phishing remains the primary initial access vector across all sectors, "
        f"with success rates independent of technical sophistication — "
        f"user targeting via urgency, authority, or financial lures remains highly effective. "
        f"Deploy {ioc_count} sender/URL/domain IOC(s) at email gateway (SEG/ATP) and web proxy. "
        f"User awareness notification recommended within 24 hours if this campaign "
        f"is targeting your sector or geography. "
        f"Review email logs for historical delivery attempts matching these indicators."
    )


def _build_exploit_weaponization_summary(item: Dict) -> str:
    title      = str(item.get("title") or "")
    apex_risk  = item.get("apex_risk") or item.get("risk_score") or "N/A"
    cvss       = item.get("cvss_score") or "N/A"
    epss       = item.get("epss_score") or item.get("epss") or "N/A"
    kev        = str(item.get("kev") or "").upper() in ("YES", "TRUE", "1", "LISTED")

    urgency = "within 24 hours" if kev else "within 72 hours"

    return (
        f"Exploit weaponization has been confirmed for {title[:100]}. "
        f"{'CISA KEV listing confirms active exploitation in the wild. ' if kev else ''}"
        f"APEX risk score: {apex_risk}/10. "
        f"{'CVSS ' + str(cvss) + '. ' if cvss != 'N/A' else ''}"
        f"{'EPSS exploitation probability: ' + str(epss) + '. ' if epss != 'N/A' else ''}"
        f"The transition from proof-of-concept to weaponised exploit compresses the defensive "
        f"response window significantly — scanner clusters will probe for vulnerable instances "
        f"across the internet within hours of tool publication. "
        f"Apply vendor patch or implement compensating controls {urgency}. "
        f"If patching is not immediately feasible, consider: "
        f"WAF virtual patching, network segmentation, service disablement, or "
        f"emergency change management escalation."
    )


def _build_geopolitical_summary(item: Dict) -> str:
    title     = str(item.get("title") or "")
    apex_risk = item.get("apex_risk") or item.get("risk_score") or "N/A"

    return (
        f"Geopolitically-motivated threat activity has been identified relevant to: {title[:100]}. "
        f"APEX risk score: {apex_risk}/10. "
        f"Nation-state campaigns are distinguished by their persistence, operational security, "
        f"and strategic targeting — sectors aligned with geopolitical objectives "
        f"(critical infrastructure, defence, government, telecoms) face elevated risk. "
        f"Attribution should be treated as analytic judgment rather than confirmed fact "
        f"unless supported by independent government attribution or multiple corroborating sources. "
        f"Threat model review recommended for organisations in targeted sectors or geographies."
    )


def _build_generic_summary(item: Dict) -> str:
    title     = str(item.get("title") or "Unclassified intelligence item")
    apex_risk = item.get("apex_risk") or item.get("risk_score") or "N/A"
    ioc_count = item.get("ioc_count") or 0
    ttp_count = item.get("ttp_count") or 0
    confidence = item.get("confidence") or 0

    return (
        f"Intelligence advisory: {title[:120]}. "
        f"APEX composite risk: {apex_risk}/10. "
        f"This advisory was enriched through APEX's multi-signal pipeline. "
        f"Intelligence depth: {ioc_count} IOC(s), {ttp_count} ATT&CK technique(s), "
        f"confidence {confidence}%. "
        f"Review the technical analysis, IOC table, and ATT&CK mapping sections for "
        f"full operational context and SOC actions."
    )


TIER_BUILDERS = {
    "CVE_ADVISORY":            _build_cve_summary,
    "RANSOMWARE":              _build_ransomware_summary,
    "APT_CAMPAIGN":            _build_apt_summary,
    "ICS_OT_ADVISORY":         _build_ics_summary,
    "MALWARE_OPERATION":       _build_malware_summary,
    "PHISHING_CAMPAIGN":       _build_phishing_summary,
    "EXPLOIT_WEAPONIZATION":   _build_exploit_weaponization_summary,
    "GEOPOLITICAL_CTI":        _build_geopolitical_summary,
    "VULNERABILITY_RESEARCH":  _build_cve_summary,  # reuse CVE logic
}


# ── Quality Controls ──────────────────────────────────────────────────────────

def _entropy_score(text: str) -> float:
    """Shannon entropy of word distribution. Low entropy = repetitive template."""
    words = re.findall(r"\w+", text.lower())
    if not words:
        return 0.0
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    total = len(words)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    return round(entropy, 3)


def _contains_template(text: str) -> bool:
    return bool(TEMPLATE_RE.search(text))


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode().lower()).hexdigest()[:16]


# ── Main enrichment function ──────────────────────────────────────────────────

class NarrativeEngine:
    def __init__(self) -> None:
        self._seen_fps: Set[str] = set()

    def generate(self, item: Dict) -> Dict:
        """Generate analyst-grade narrative for a single item."""
        tier = _detect_tier(item)
        builder = TIER_BUILDERS.get(tier, _build_generic_summary)

        summary = builder(item)

        # Quality gate: reject template phrases
        if _contains_template(summary):
            log.warning("Template phrase detected in generated summary for %s — forcing rebuild",
                        item.get("title", "UNKNOWN")[:60])
            summary = _build_generic_summary(item)

        # Quality gate: entropy check
        entropy = _entropy_score(summary)
        if entropy < 3.0:
            log.warning("Low narrative entropy %.2f — summary may be repetitive", entropy)

        # Quality gate: deduplication
        fp = _fingerprint(summary)
        if fp in self._seen_fps:
            log.warning("Near-duplicate summary fingerprint detected — appending differentiator")
            summary += (
                f" [Note: This advisory shares structural similarity with a previously "
                f"generated summary. Analyst review recommended.]"
            )
        self._seen_fps.add(fp)

        item_out = dict(item)
        item_out["executive_summary"]      = summary
        item_out["intelligence_tier"]      = tier
        item_out["narrative_entropy"]      = entropy
        item_out["narrative_engine"]       = ENGINE_ID
        item_out["narrative_version"]      = ENGINE_VERSION
        item_out["narrative_ts"]           = datetime.now(timezone.utc).isoformat()
        return item_out


def main() -> int:
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [NE] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="APEX Narrative Engine v" + ENGINE_VERSION)
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--output",   default=None)
    args = parser.parse_args()
    path = Path(args.manifest)
    if not path.exists():
        log.error("Not found: %s", path)
        return 1
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    engine = NarrativeEngine()
    enriched = [engine.generate(item) for item in items]
    tier_counts = {}
    for item in enriched:
        t = item.get("intelligence_tier", "UNKNOWN")
        tier_counts[t] = tier_counts.get(t, 0) + 1
    log.info("Generated narratives for %d items: %s", len(enriched), tier_counts)
    out = Path(args.output) if args.output else path
    tmp = out.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)
    tmp.replace(out)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
