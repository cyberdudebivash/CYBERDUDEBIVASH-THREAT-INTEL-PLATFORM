"""
context_aware_narrative_engine.py — CYBERDUDEBIVASH Threat Intelligence Platform
Phase: Enterprise Operational Trust — P0 Intelligence Rendering Engine

Eliminates ALL generic template language from tactical dossiers.
Produces threat-type-adaptive, operationally specific intelligence narratives
for every advisory class the platform ingests.

Intelligence classes handled:
  THREAT_ACTOR_REPORT   — APT/threat actor investigation (Check Point, Mandiant, etc.)
  RANSOMWARE            — Ransomware operations, RaaS campaigns, extortion events
  APT_ESPIONAGE         — Nation-state espionage, strategic intelligence collection
  ICS_OT                — Industrial control systems, OT, SCADA, critical infrastructure
  CLOUD_SAAS            — Cloud/SaaS attacks, tenant exposure, identity compromise
  SUPPLY_CHAIN          — Software supply chain, dependency injection, build compromise
  PHISHING_CAMPAIGN     — Phishing operations, BEC, credential harvesting campaigns
  MALWARE_FAMILY        — Malware analysis, family profiling, campaign attribution
  ZERO_DAY              — Zero-day vulnerability with active exploitation
  CVE_RCE               — Remote code execution vulnerability
  CVE_AUTH_BYPASS       — Authentication bypass vulnerability
  CVE_SQLI              — SQL injection vulnerability
  CVE_XSS               — Cross-site scripting vulnerability
  CVE_PRIVESC           — Privilege escalation vulnerability
  CVE_SSRF              — SSRF vulnerability
  CVE_DOS               — Denial of service vulnerability
  CVE_INFODISC          — Information disclosure vulnerability
  CVE_MEMORY            — Memory corruption vulnerability
  CVE_GENERIC           — Generic CVE (no specific vuln class match)
  THREAT_INTEL          — General threat intelligence (fallback with no CVE)

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
"""

from __future__ import annotations

import html as _html_mod
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("context_aware_narrative")

_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Intelligence Class Constants
# ---------------------------------------------------------------------------
CLS_THREAT_ACTOR   = "THREAT_ACTOR_REPORT"
CLS_RANSOMWARE     = "RANSOMWARE"
CLS_APT_ESPIONAGE  = "APT_ESPIONAGE"
CLS_ICS_OT         = "ICS_OT"
CLS_CLOUD_SAAS     = "CLOUD_SAAS"
CLS_SUPPLY_CHAIN   = "SUPPLY_CHAIN"
CLS_PHISHING       = "PHISHING_CAMPAIGN"
CLS_MALWARE        = "MALWARE_FAMILY"
CLS_ZERO_DAY       = "ZERO_DAY"
CLS_CVE_RCE        = "CVE_RCE"
CLS_CVE_AUTH       = "CVE_AUTH_BYPASS"
CLS_CVE_SQLI       = "CVE_SQLI"
CLS_CVE_XSS        = "CVE_XSS"
CLS_CVE_PRIVESC    = "CVE_PRIVESC"
CLS_CVE_SSRF       = "CVE_SSRF"
CLS_CVE_DOS        = "CVE_DOS"
CLS_CVE_INFODISC   = "CVE_INFODISC"
CLS_CVE_MEMORY     = "CVE_MEMORY"
CLS_CVE_DESER      = "CVE_DESERIALIZATION"
CLS_CVE_GENERIC    = "CVE_GENERIC"
CLS_THREAT_INTEL   = "THREAT_INTEL"

# ---------------------------------------------------------------------------
# Threat-Type Signals: Ordered by priority (first match wins at tier)
# ---------------------------------------------------------------------------

# Tier 1: Non-CVE intelligence classes (checked before CVE patterns)
_TIER1_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # ICS/OT — check first, very specific vocabulary
    (re.compile(
        r'\bSCADA\b|\bICS\b|\bOT\b|\bPLC\b|\bDCS\b|\bHMI\b|\bModbus\b|\bDNP3\b'
        r'|\bPROFINET\b|\bEtherNet/IP\b|\bindustrial.control|\boperational.technolog'
        r'|\bpower.grid|\belectric.grid|\bwater.treatment|\bnatural.gas|\bpipeline'
        r'|\bCritical Infrastructure|\bmanufacturing.floor|\bsubstation|\bPLC.exploit',
        re.I), CLS_ICS_OT),

    # Supply Chain
    (re.compile(
        r'\bsupply.chain|\bdependency.inject|\bbuild.system|\bpackage.manager'
        r'|\bopen.source.poison|\bpypi|\bnpm.malicious|\btyposquat|\bSolarWinds'
        r'|\bCI/CD.comprom|\bbuild.pipeline|\bartifact.inject|\bcode.signing'
        r'|\brepository.inject',
        re.I), CLS_SUPPLY_CHAIN),

    # Threat Actor Investigation (research publications, not CVEs)
    (re.compile(
        r'\bthreat.actor|\bAPT-?\d+|\bthreat.group|\bhacker.group|\bcyber.gang'
        r'|\bcriminal.gang|\boperati(?:on|onal).(?:COBALT|GHOST|THUNDER|IRON'
        r'|SHADOW|DARK|BLACK|WHITE|BLUE|RED|VOLT|SALT|FANCY|COZY|SANDWORM'
        r'|LAZARUS|KIMSUKY|TURLA|CARBANAK|LAPSUS|SCATTERED|SCATTERED.SPIDER'
        r'|SILENT|DEEP.PANDA|STONE.PANDA|COMMENT.CREW|OCEAN.LOTUS|EQUATION'
        r'|LONGHORN|DRAGONFLY|MACHETE|MUDDY|SIDEWINDER|ELEPHANT|BITTER)'
        r'|\bGentlemen\b|\bGang\b.*\bmalware|\bGroup\b.*\bcampaign'
        r'|\bthreat.cluster|\bintrusion.set|\bcampaign.analysis|\bactor.analysis'
        r'|\binvestigation.report|\bthreat.report|\bmalware.analysis.report'
        r'|\bresearch.report|\bcyber.espionage.campaign|\battribution.report',
        re.I), CLS_THREAT_ACTOR),

    # APT Espionage
    (re.compile(
        r'\bAPT\b|\badvanced.persistent|\bnation.state|\bstate.sponsor'
        r'|\bespionage|\bcyber.spy|\bintelligence.collection|\bdata.theft.campaign'
        r'|\bgeopolitical|\bgovernment.target|\bdefence.contrac|\bmilitary.intel'
        r'|\bdiplom.*target|\bforeign.intel|\bsigint|\bcyber.warfare',
        re.I), CLS_APT_ESPIONAGE),

    # Cloud/SaaS
    (re.compile(
        r'\bcloud.tenant|\bAzure\b|\bAWS\b|\bGCP\b|\bSaaS\b|\bM365\b'
        r'|\bMicrosoft.365|\bGoogle.Workspace|\bOkta\b|\bIAM.comprom'
        r'|\bcloud.account|\bservice.account.abuse|\bfederated.identity'
        r'|\bOAuth.exploit|\bSAML.bypass|\bcloud.misconfig|\bmulti-tenant'
        r'|\bcloud.storage.expo|\bBlob.exposure|\bS3.exposure|\btenancy.escape',
        re.I), CLS_CLOUD_SAAS),

    # Ransomware
    (re.compile(
        r'\brandsom|\bRaaS\b|\braas\b|\bransomware.as.a|\bencrypt.files'
        r'|\bcrypt.locker|\bdouble.extort|\btriple.extort|\bdata.leak.site'
        r'|\bvictim.publish|\bblacksuit\b|\blockbit\b|\bblackcat\b|\balphv\b'
        r'|\bconti\b|\bclop\b|\bhive\b|\bplay.ransomware|\baka.i\b'
        r'|\bmedibank|\bchange.healthcare|\bnoberus|\bransomhub',
        re.I), CLS_RANSOMWARE),

    # Phishing Campaign
    (re.compile(
        r'\bphishing.campaign|\bspear.phish|\bbusiness.email.comprom|\bBEC\b'
        r'|\bcredential.harvest|\bsmishing|\bvishing|\bwhaling\b'
        r'|\bmass.phish|\bphishing.kit|\blanding.page|\btrojanized.link'
        r'|\bphishing.lure|\bauthentication.harvest',
        re.I), CLS_PHISHING),

    # Malware Family Analysis
    (re.compile(
        r'\bmalware.famil|\btrojan\b.*\banalysis|\bRAT\b.*\banalysis|\bbackdoor.analys'
        r'|\bloader\b.*\bmalware|\bimplant\b.*\banalysis|\bbotnet\b.*\banalysis'
        r'|\bC2.infrastructure|\bcommand.and.control|\bmalware.campaign'
        r'|\bpayload.analysis|\bstager\b|\bdroper\b|\bdownloader\b.*\bmalware'
        r'|\bcobalt.strike|\bbrute.ratel|\bSliver\b|\bmetasploit.abuse',
        re.I), CLS_MALWARE),
]

# Tier 2: CVE-specific patterns (only applied if CVE present in title/desc)
_TIER2_CVE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\bzero.day\b|\b0day\b|\bunpatched\b.*\bexploit|\bun.patch.*exploit', re.I),
     CLS_ZERO_DAY),
    (re.compile(r'\bremote.code.exec|\bRCE\b|\barbitrary.code|\bcode.execution', re.I),
     CLS_CVE_RCE),
    (re.compile(r'\bsql.inject|\bSQLi\b', re.I),
     CLS_CVE_SQLI),
    (re.compile(r'\bcross.site.script|\bXSS\b|\bscript.inject', re.I),
     CLS_CVE_XSS),
    (re.compile(r'\bSSRF\b|\bserver.side.request.forgery', re.I),
     CLS_CVE_SSRF),
    (re.compile(r'\bauth.bypass|\bauthentication.bypass|\bunauthenticated.access|\bauth.flaw', re.I),
     CLS_CVE_AUTH),
    (re.compile(r'\bprivilege.escal|\bprivilege.elev|\bprivilege.abuse|\bLPE\b', re.I),
     CLS_CVE_PRIVESC),
    (re.compile(r'\bdenial.of.service|\bDoS\b|\bDDoS\b|\bservice.disrupt|\bcrash', re.I),
     CLS_CVE_DOS),
    (re.compile(r'\binformation.disclos|\bdata.expo|\bsensitive.data.leak|\bconfig.expo', re.I),
     CLS_CVE_INFODISC),
    (re.compile(r'\bmemory.corrupt|\bbuffer.over|\bheap.over|\bstack.over|\buse.after.free|\bUAF\b|\btype.confus', re.I),
     CLS_CVE_MEMORY),
    (re.compile(r'\bdeserial|\bpickle.inject|\bobject.inject', re.I),
     CLS_CVE_DESER),
]

# Known threat actor research sources (high confidence THREAT_ACTOR classification)
_RESEARCH_SOURCES = frozenset({
    "research.checkpoint.com", "blog.checkpoint.com",
    "blog.malwarebytes.com", "malwarebytes.com",
    "securelist.com", "kaspersky.com",
    "unit42.paloaltonetworks.com", "paloaltonetworks.com",
    "talosintelligence.com", "blog.talosintelligence.com",
    "mandiant.com", "fireeye.com",
    "crowdstrike.com", "adversary.crowdstrike.com",
    "sentinelone.com", "labs.sentinelone.com",
    "huntress.com", "labs.huntress.com",
    "elastic.co", "www.elastic.co",
    "recordedfuture.com", "go.recordedfuture.com",
    "blog.google", "gti.google",
    "msrc.microsoft.com", "microsoft.com/en-us/security",
    "symantec.com", "broadcom.com",
    "rapid7.com", "vulncheck.com",
    "vx-underground.org",
})

def _is_research_source(source_url: str) -> bool:
    """Check if source URL is from a known threat research publication."""
    if not source_url:
        return False
    url_lower = source_url.lower()
    for domain in _RESEARCH_SOURCES:
        if domain in url_lower:
            return True
    return False

def _has_cve(title: str, desc: str) -> Optional[str]:
    """Extract first CVE ID from title or description. Returns None if absent."""
    m = re.search(r'CVE-\d{4}-\d+', title + " " + desc, re.I)
    return m.group(0).upper() if m else None

def classify_intelligence(item: Dict[str, Any]) -> str:
    """
    Multi-signal intelligence class classifier.

    Evaluates: title, description, threat_type, actor, source_url, feed_source,
    tags, ttps, iocs in decreasing priority order.

    Returns one of the CLS_* constants.
    """
    title      = str(item.get("title") or "")
    desc       = str(item.get("description") or item.get("summary") or "")
    threat_type = str(item.get("threat_type") or "").lower()
    actor      = str(item.get("actor_tag") or item.get("actor_cluster") or item.get("primary_actor") or "")
    source_url = str(item.get("source_url") or "")
    feed       = str(item.get("feed_source") or "")
    tags       = [str(t).lower() for t in (item.get("tags") or [])]
    corpus     = f"{title} {desc}"

    cve_id = _has_cve(title, desc)

    # Signal 1: Explicit threat_type from feed
    if "ransomware" in threat_type:
        return CLS_RANSOMWARE
    if "apt" in threat_type or "espionage" in threat_type:
        return CLS_APT_ESPIONAGE
    if "ics" in threat_type or "ot " in threat_type or "scada" in threat_type:
        return CLS_ICS_OT
    if "supply chain" in threat_type:
        return CLS_SUPPLY_CHAIN
    if "phishing" in threat_type or "bec" in threat_type:
        return CLS_PHISHING
    if "malware" in threat_type and not cve_id:
        return CLS_MALWARE
    if "cloud" in threat_type or "saas" in threat_type:
        return CLS_CLOUD_SAAS

    # Signal 2: Research source URL + no dominant CVE → threat actor investigation
    if _is_research_source(source_url) and not cve_id:
        return CLS_THREAT_ACTOR

    # Signal 3: Known actor cluster present → APT or threat actor report
    if actor and actor not in ("UNATTRIBUTED", "CDB-CVE-GEN", "", "Unknown"):
        # Has named actor but no CVE → likely threat actor campaign
        if not cve_id:
            return CLS_THREAT_ACTOR
        # Has named actor AND CVE → likely APT exploitation of vulnerability
        if any(a in actor.upper() for a in ("APT", "LAZARUS", "VOLT", "SALT", "FANCY", "COZY", "SANDWORM", "TURLA")):
            return CLS_APT_ESPIONAGE

    # Signal 4: Tier 1 content pattern matching
    for pattern, cls in _TIER1_PATTERNS:
        if pattern.search(corpus):
            return cls

    # Signal 5: CVE-based classification (only if CVE present)
    if cve_id:
        for pattern, cls in _TIER2_CVE_PATTERNS:
            if pattern.search(corpus):
                return cls
        # CVE present but no specific class matched
        return CLS_CVE_GENERIC

    # Signal 6: Tag-based
    tag_str = " ".join(tags)
    if "ransomware" in tag_str:
        return CLS_RANSOMWARE
    if "apt" in tag_str:
        return CLS_APT_ESPIONAGE
    if "phishing" in tag_str:
        return CLS_PHISHING

    # Signal 7: Threat type field "Threat Intel" with research source
    if _is_research_source(source_url):
        return CLS_THREAT_ACTOR

    # Default for non-CVE threat intel
    return CLS_THREAT_INTEL


# ---------------------------------------------------------------------------
# Narrative Templates per Intelligence Class
# ---------------------------------------------------------------------------

def _h(s: Any) -> str:
    """HTML-escape a value safely."""
    return _html_mod.escape(str(s) if s is not None else "")


def _extract_product_from_title(title: str) -> str:
    """Extract product name from CVE advisory title."""
    # Remove CVE ID prefix
    clean = re.sub(r'^CVE-\d{4}-\d+\s*[-–—:]\s*', '', title).strip()
    # Truncate to reasonable length
    if len(clean) > 80:
        clean = clean[:77] + "..."
    return clean or title[:60]


def _get_actor_display(item: Dict[str, Any]) -> str:
    """Get best available actor display name."""
    return (
        item.get("_actor_display") or
        item.get("actor_cluster") or
        item.get("actor_tag") or
        item.get("primary_actor") or
        "untracked threat cluster"
    )


def _get_sector_context(item: Dict[str, Any]) -> str:
    """Build sector targeting context string."""
    sectors = item.get("sectors") or item.get("targeted_sectors") or []
    if isinstance(sectors, list) and sectors:
        sector_list = [str(s) for s in sectors[:4]]
        return f"Targeted sectors include {', '.join(sector_list)}."
    # Default from threat type
    tt = str(item.get("threat_type") or "").lower()
    if "healthcare" in tt:
        return "Healthcare sector at elevated risk due to operational criticality and high data sensitivity."
    if "finance" in tt or "financial" in tt:
        return "Financial services sector at elevated risk due to monetary targeting and regulatory exposure."
    if "government" in tt or "critical" in tt:
        return "Government and critical infrastructure sectors are primary targeting focus."
    return "All sectors with internet-exposed assets are in scope; prioritise by operational criticality."


def _get_kev_context(kev: bool) -> str:
    """Build KEV-aware urgency context."""
    if kev:
        return (
            "<strong class='apex-kev'>⚠ CISA KEV CONFIRMED:</strong> "
            "Active exploitation observed in the wild. CISA Binding Operational Directive 22-01 "
            "mandates remediation for US federal agencies within the specified timeline. "
            "All organisations should treat this as an emergency — evidence of exploitation "
            "precedes your organisation's awareness. Assume some assets may already be compromised."
        )
    return (
        "No confirmed active exploitation in CISA KEV at time of analysis. "
        "Monitor CISA KEV updates; EPSS and CVSS signals should drive patch prioritisation "
        "in the interim."
    )


def _get_cvss_context(cvss: Any) -> str:
    """Build CVSS severity context."""
    if cvss is None:
        return ""
    try:
        v = float(cvss)
        if v >= 9.0:
            return f" CVSS {v:.1f} (CRITICAL) — exploitation probability extremely high within 7 days of disclosure."
        if v >= 7.0:
            return f" CVSS {v:.1f} (HIGH) — weaponised exploit likely available or imminent."
        if v >= 4.0:
            return f" CVSS {v:.1f} (MEDIUM) — patch within standard maintenance window; assess exposure first."
        return f" CVSS {v:.1f} (LOW) — low severity; include in next scheduled patching cycle."
    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# Intelligence Class Narrative Generators
# ---------------------------------------------------------------------------

def _narrative_threat_actor(item: Dict[str, Any]) -> str:
    """Threat actor investigation/campaign report narrative."""
    title      = str(item.get("title") or "")
    desc       = str(item.get("description") or "")
    actor      = _get_actor_display(item)
    feed       = str(item.get("feed_source") or "threat intelligence feed")
    ttps       = item.get("ttps") or []
    iocs       = item.get("iocs") or []
    ioc_count  = len(iocs)
    kev        = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    epss       = item.get("epss_score")
    sectors    = _get_sector_context(item)
    sev        = str(item.get("severity") or "HIGH").upper()

    # Extract CVEs mentioned in desc/title
    cve_refs = re.findall(r'CVE-\d{4}-\d+', f"{title} {desc}", re.I)
    cve_str  = ""
    if cve_refs:
        unique_cves = list(dict.fromkeys(c.upper() for c in cve_refs[:4]))
        cve_str = f" The adversary has been observed exploiting: <strong>{', '.join(unique_cves)}</strong>."

    # TTP phase summary
    tactic_phases: List[str] = []
    for t in ttps[:6]:
        tac = ""
        if isinstance(t, dict):
            tac = str(t.get("tactic") or "")
        elif isinstance(t, str) and len(t) <= 10:
            # It's a technique ID — map to tactic
            from agent.apex_intelligence_upgrade import resolve_technique as _rt
            try:
                tac = _rt(t).get("tactic", "")
            except Exception:
                pass
        if tac and tac not in tactic_phases:
            tactic_phases.append(tac)

    phase_str = ""
    if tactic_phases:
        phase_str = (
            f" The attack chain spans <strong>{len(tactic_phases)}</strong> tactical phases: "
            f"{', '.join(tactic_phases)}."
        )

    # Exploitation urgency
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    epss_str = ""
    if epss is not None:
        try:
            e = float(epss)
            if e >= 50:
                epss_str = f" EPSS exploitation probability: <strong>{e:.1f}%</strong> (30-day) — active exploitation expected or ongoing."
            elif e >= 10:
                epss_str = f" EPSS exploitation probability: <strong>{e:.1f}%</strong> — elevated exploitation risk."
        except (ValueError, TypeError):
            pass

    _adversary_profile_type = "nation-state affiliated" if any(k in str(item.get("actor_cluster", "")).upper() for k in ["APT", "VOLT", "SALT", "FANCY", "COZY", "SANDWORM"]) else "threat cluster under active tracking"
    _operational_objective = "Financial gain via ransomware/extortion" if "ransom" in title.lower() else "Intelligence collection, credential theft, and persistent access"

    return (
        f"<div class='apex-narrative'>"
        f"<p><strong>{_h(feed)}</strong> has published threat actor intelligence "
        f"documenting the activities of <strong>{_h(actor)}</strong>. "
        f"This is an adversary campaign report — not a standard CVE advisory. "
        f"The intelligence documents observed attack operations, tooling, and infrastructure "
        f"deployed by this threat cluster in live intrusion campaigns.{cve_str}{epss_str}</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Intelligence Type</span>"
        f"<span class='apex-value'>Threat Actor Campaign Report — adversary-centric intelligence</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Adversary Profile</span>"
        f"<span class='apex-value'>{_h(actor)} &mdash; {_adversary_profile_type}</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Operational Objective</span>"
        f"<span class='apex-value'>{_operational_objective}</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>Correlate all {ioc_count} IOCs against SIEM/EDR; hunt for TTP signatures; review identity telemetry for lateral movement</span></div>"
        f"</div>"
        f"<p>{_h(sectors)}{phase_str} "
        f"Defenders should treat this as operational campaign intelligence — correlate the IOC table "
        f"against 30-day SIEM retention, DNS query logs, EDR process telemetry, and authentication events. "
        f"The {ioc_count} indicator{'s' if ioc_count != 1 else ''} provided represent confirmed adversary "
        f"infrastructure observed during active campaign operations.</p>"
        f"</div>"
    )


def _narrative_ransomware(item: Dict[str, Any]) -> str:
    """Ransomware operation narrative — operational disruption focus."""
    title     = str(item.get("title") or "")
    actor     = _get_actor_display(item)
    iocs      = item.get("iocs") or []
    ioc_count = len(iocs)
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    sectors   = _get_sector_context(item)
    ttps      = item.get("ttps") or []
    sev       = str(item.get("severity") or "HIGH").upper()

    # Extract family name from title
    family_match = re.search(
        r'\b(LockBit|BlackCat|AlphV|Conti|Clop|Hive|RansomHub|BlackSuit|Play|Akira|'
        r'Cuba|Vice|Royal|Medusa|Phobos|Dharma|Ryuk|REvil|DarkSide|ALPHV|NobeRus)\b',
        title, re.I
    )
    family = family_match.group(1) if family_match else "ransomware operator"

    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    lateral_ttps = [t for t in ttps if isinstance(t, str) and t in
                    ("T1021", "T1021.001", "T1021.002", "T1021.004",
                     "T1078", "T1110", "T1550", "T1076")]
    exfil_ttps   = [t for t in ttps if isinstance(t, str) and t.startswith(("T1020", "T1041", "T1048", "T1567"))]

    double_extort = (
        "Double-extortion confirmed — data theft precedes encryption. "
        "Assume sensitive data has been staged for leak-site publication. "
        "Engage legal and PR crisis management before any public disclosure."
        if exfil_ttps or "exfil" in str(item.get("description","")).lower()
        else
        "Monitor for dual-extortion indicators — data staging activity often precedes encryption deployment."
    )

    lateral_movement_text = (
        "RDP, SMB lateral movement, and WMIC observed - segment network immediately on first IOC match"
        if lateral_ttps else
        "Domain credential reuse for lateral movement - audit privileged account activity across all hosts"
    )

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a <strong>{_h(family)}</strong> ransomware operation attributed to "
        f"<strong>{_h(actor)}</strong>. "
        f"The operational pattern follows a multi-stage intrusion chain: initial access via phishing or "
        f"credential abuse, followed by lateral movement across the domain environment, data staging for "
        f"exfiltration, shadow copy deletion, and finally mass encryption of file shares and backup systems.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Operational Disruption Risk</span>"
        f"<span class='apex-value'>Complete operational shutdown if encryption reaches domain controllers and file servers — average recovery time 15–21 days without clean backups</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Business Interruption</span>"
        f"<span class='apex-value'>Manufacturing, logistics, healthcare, and financial services face SLA breach within hours of detonation — validate backup isolation immediately</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Lateral Movement Vector</span>"
        f"<span class='apex-value'>{lateral_movement_text}</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>Validate offline backup integrity NOW; enforce network segmentation; deploy EDR anti-ransomware behavioural policy; hunt all {ioc_count} IOCs</span></div>"
        f"</div>"
        f"<p>{double_extort}</p>"
        f"<p>{_h(sectors)} "
        f"Immediate actions: (1) Validate backup isolation and recovery capability, (2) Block all {ioc_count} IOCs at "
        f"firewall, DNS RPZ, and EDR immediately, (3) Audit RDP exposure and privileged account usage, "
        f"(4) Enable enhanced alerting for shadow copy deletion and mass file rename operations.</p>"
        f"</div>"
    )


def _narrative_apt_espionage(item: Dict[str, Any]) -> str:
    """APT/espionage narrative — strategic persistence and targeting focus."""
    title      = str(item.get("title") or "")
    actor      = _get_actor_display(item)
    ioc_count  = len(item.get("iocs") or [])
    kev        = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    sectors    = _get_sector_context(item)
    ttps       = item.get("ttps") or []
    cvss       = item.get("cvss_score")

    # Determine geopolitical nexus from actor name
    nexus = ""
    actor_up = actor.upper()
    if any(k in actor_up for k in ("VOLT", "SALT", "FANCY PANDA", "DEEP PANDA", "APT41", "APT10", "APT40", "COMMENT CREW")):
        nexus = "China-attributed"
    elif any(k in actor_up for k in ("FANCY BEAR", "COZY BEAR", "SANDWORM", "APT28", "APT29", "TURLA", "BERSERK BEAR")):
        nexus = "Russia-attributed"
    elif any(k in actor_up for k in ("LAZARUS", "KIMSUKY", "ANDARIEL", "APT38", "BLUENOROFF")):
        nexus = "DPRK-attributed"
    elif any(k in actor_up for k in ("APT33", "APT34", "APT35", "MUDDY", "CHARMING KITTEN", "OILRIG")):
        nexus = "Iran-attributed"

    nexus_str = f" This cluster is <strong>{_h(nexus)}</strong>." if nexus else ""

    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""
    cvss_str  = _get_cvss_context(cvss)

    persistence_ttps = [t for t in (ttps if (ttps and isinstance(ttps[0], str)) else [])
                        if t in ("T1053", "T1053.005", "T1547", "T1543", "T1098", "T1078")]
    persist_str = (
        f" Persistence mechanisms identified: scheduled tasks, registry run keys, and valid account "
        f"abuse — dwell time may already extend weeks before initial detection."
        if persistence_ttps
        else
        f" APT operators prioritise long-term persistent access over immediate impact — "
        f"assume dwell time of 30–180 days if IOCs match your environment."
    )

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a nation-state Advanced Persistent Threat (APT) operation "
        f"attributed to threat cluster <strong>{_h(actor)}</strong>.{nexus_str} "
        f"APT operations are characterised by long-term persistent access, stealthy exfiltration, "
        f"and mission-driven intelligence collection — not immediate destructive impact.{cvss_str}</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Strategic Objective</span>"
        f"<span class='apex-value'>Long-term intelligence collection, credential harvesting, and pre-positioning — not immediate disruption</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Campaign Persistence</span>"
        f"<span class='apex-value'>Adversary establishes multiple redundant persistence mechanisms — single IOC block insufficient for eviction</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Exfiltration Pattern</span>"
        f"<span class='apex-value'>Slow, low-volume data exfiltration via encrypted C2 to avoid anomaly detection — review DLP and proxy logs</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Detection Challenge</span>"
        f"<span class='apex-value'>APT actors use legitimate tools (LOLBins, legitimate cloud services) to blend with normal traffic — behavioural analytics required</span></div>"
        f"</div>"
        f"<p>{persist_str} "
        f"{_h(sectors)} "
        f"{ioc_count} IOCs documented — hunt across all telemetry sources including cloud access logs, "
        f"email security gateways, and VPN authentication events. "
        f"Complete eviction requires a coordinated incident response — single IOC blocking "
        f"will not remove an established APT from your environment.</p>"
        f"</div>"
    )


def _narrative_ics_ot(item: Dict[str, Any]) -> str:
    """ICS/OT narrative — operational continuity and industrial impact focus."""
    actor     = _get_actor_display(item)
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss      = item.get("cvss_score")
    cvss_str  = _get_cvss_context(cvss)

    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a threat to <strong>Industrial Control Systems (ICS), Operational "
        f"Technology (OT), or SCADA infrastructure</strong>.{cvss_str} "
        f"ICS/OT threats represent a fundamentally different risk profile from enterprise IT — "
        f"exploitation does not just compromise data; it can cause physical process disruption, "
        f"equipment damage, safety system failure, and regulatory shutdown.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Operational Continuity Risk</span>"
        f"<span class='apex-value'>Process disruption, equipment damage, or safety system failure — not just data loss. Production downtime cost: $500K–$2M+/hour in critical sectors</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>IT/OT Convergence Vector</span>"
        f"<span class='apex-value'>Attackers pivot from IT network to OT via shared authentication, engineering workstations, or historian servers — air-gap integrity must be validated</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Patch Complexity</span>"
        f"<span class='apex-value'>OT patching requires vendor coordination, maintenance windows, and safety validation — traditional patch-immediately guidance does NOT apply; plan compensating controls</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Regulatory Exposure</span>"
        f"<span class='apex-value'>NERC CIP (energy), IEC 62443, and sector-specific OT security frameworks mandate incident reporting — engage compliance team immediately</span></div>"
        f"</div>"
        f"<p>Immediate compensating controls: (1) Validate IT/OT network segmentation integrity, "
        f"(2) Audit engineering workstation access and remote maintenance connections, "
        f"(3) Block all {ioc_count} IOCs at IT/OT boundary firewalls, "
        f"(4) Engage OT security vendor and CISA ICS-CERT before applying any patches. "
        f"Physical safety systems must be tested after any remediation activity.</p>"
        f"</div>"
    )


def _narrative_cloud_saas(item: Dict[str, Any]) -> str:
    """Cloud/SaaS narrative — tenant exposure and identity compromise focus."""
    actor     = _get_actor_display(item)
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss      = item.get("cvss_score")
    desc      = str(item.get("description") or "")
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    # Detect specific cloud platform from description
    platform = "cloud service"
    for p in ["Azure", "AWS", "GCP", "M365", "Microsoft 365", "Google Workspace", "Okta", "Entra ID"]:
        if p.lower() in desc.lower():
            platform = p
            break

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a <strong>{_h(platform)}</strong> security exposure "
        f"affecting cloud tenant environments. Cloud/SaaS attacks bypass traditional perimeter "
        f"defences — the attack surface is your identity layer, not your firewall.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Tenant Exposure Risk</span>"
        f"<span class='apex-value'>Multi-tenant platform compromise may expose all customer tenants — assess shared responsibility model and tenant isolation guarantees</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Identity Compromise Vector</span>"
        f"<span class='apex-value'>OAuth token theft, SAML bypass, or federated identity abuse — review conditional access policies and anomalous sign-in alerts immediately</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Cloud-Specific Risk</span>"
        f"<span class='apex-value'>Cloud misconfigurations (storage exposure, overprivileged service accounts, public API endpoints) amplify blast radius — audit cloud posture now</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Detection Priority</span>"
        f"<span class='apex-value'>Review cloud audit logs (CloudTrail/Entra Sign-In Logs), token issuance events, and anomalous API calls for the past 90 days</span></div>"
        f"</div>"
        f"<p>Immediate actions: (1) Audit all service accounts and OAuth application permissions, "
        f"(2) Review Conditional Access policies and MFA enforcement gaps, "
        f"(3) Search {ioc_count} IOCs across cloud access logs (90-day lookback minimum), "
        f"(4) Validate that tenant isolation controls are functioning as designed. "
        f"Revoke all session tokens for affected accounts — not just passwords.</p>"
        f"</div>"
    )


def _narrative_supply_chain(item: Dict[str, Any]) -> str:
    """Supply chain compromise narrative."""
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a <strong>software supply chain compromise</strong>. "
        f"Supply chain attacks are uniquely dangerous because trusted update mechanisms, "
        f"package repositories, or build systems become the delivery vector — bypassing "
        f"standard perimeter and endpoint defences entirely.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Blast Radius</span>"
        f"<span class='apex-value'>Potentially all organisations using the affected package, library, or software build — scope audit across entire software dependency tree required</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Exploitation Vector</span>"
        f"<span class='apex-value'>Malicious code injected via trusted update channel — traditional signature-based detection will not flag as malicious</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Detection Challenge</span>"
        f"<span class='apex-value'>Malicious code is signed with legitimate vendor/developer certificates — behavioural analytics and SBOM validation required</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Remediation Complexity</span>"
        f"<span class='apex-value'>All systems that installed the affected package/version may be compromised — full dependency audit required before declaring clean</span></div>"
        f"</div>"
        f"<p>Immediate actions: (1) Audit software inventory for affected packages and versions via SBOM, "
        f"(2) Hunt {ioc_count} IOCs across build systems, CI/CD pipelines, and deployment targets, "
        f"(3) Validate code signing certificate integrity and update pipeline authentication, "
        f"(4) Treat any system running affected versions as potentially compromised until proven otherwise.</p>"
        f"</div>"
    )


def _narrative_phishing(item: Dict[str, Any]) -> str:
    """Phishing campaign narrative — credential harvesting and BEC focus."""
    actor     = _get_actor_display(item)
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    sectors   = _get_sector_context(item)
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents an active <strong>phishing and credential harvesting campaign</strong> "
        f"attributed to <strong>{_h(actor)}</strong>. "
        f"Phishing campaigns represent the leading initial access vector in enterprise breaches — "
        f"a single successful credential compromise can be the entry point for ransomware, "
        f"BEC fraud, or APT establishment.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Attack Objective</span>"
        f"<span class='apex-value'>Credential harvesting for initial access resale, ransomware staging, BEC wire fraud, or espionage persistence</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Delivery Vector</span>"
        f"<span class='apex-value'>Spearphishing email with malicious link or attachment; QR code phishing and multi-factor authentication bypass kits observed in active campaigns</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>BEC Risk</span>"
        f"<span class='apex-value'>Business Email Compromise via harvested executive credentials — average BEC loss: $125K per incident; immediate financial exposure if wire transfer approval accounts targeted</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Detection Priority</span>"
        f"<span class='apex-value'>Review email security gateway for campaign indicators; hunt {ioc_count} IOCs across email logs, proxy, and DNS; audit recent privileged logins</span></div>"
        f"</div>"
        f"<p>{_h(sectors)} "
        f"Deploy all {ioc_count} IOCs to email security gateway, DNS RPZ, and proxy blocklists immediately. "
        f"Activate end-user phishing awareness alert and validate MFA enforcement for all privileged accounts. "
        f"Review O365/Google Workspace mail flow rules for any adversary-planted forwarding rules.</p>"
        f"</div>"
    )


def _narrative_malware(item: Dict[str, Any]) -> str:
    """Malware family analysis narrative."""
    title     = str(item.get("title") or "")
    actor     = _get_actor_display(item)
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    # Detect malware type from title
    malware_type = "Remote Access Trojan (RAT)"
    for m_type in [
        ("infostealer", "Infostealer"), ("stealer", "Credential Stealer"),
        ("loader", "Malware Loader"), ("dropper", "Malware Dropper"),
        ("backdoor", "Backdoor Implant"), ("botnet", "Botnet"),
        ("wiper", "Destructive Wiper"), ("rootkit", "Rootkit"),
        ("keylogger", "Keylogger"), ("spyware", "Spyware"),
    ]:
        if m_type[0] in title.lower():
            malware_type = m_type[1]
            break

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a <strong>{_h(malware_type)}</strong> — "
        f"malware deployed by <strong>{_h(actor)}</strong> in active intrusion operations. "
        f"Malware family intelligence enables proactive detection before your environment "
        f"is directly targeted — deploy the detection pack now as a defensive pre-position.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Malware Capability</span>"
        f"<span class='apex-value'>{_h(malware_type)} — persistent implant with command-and-control capability, capable of data exfiltration, lateral movement facilitation, and secondary payload delivery</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>C2 Infrastructure</span>"
        f"<span class='apex-value'>Block all {ioc_count} network IOCs at perimeter firewall and DNS RPZ — C2 communication is the adversary's kill switch; severing it disrupts the entire operation</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Host Forensic Priority</span>"
        f"<span class='apex-value'>Deploy YARA signatures to memory scanner and file system; review process creation events for malware loader signatures; check scheduled tasks and registry run keys</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Threat Intelligence Value</span>"
        f"<span class='apex-value'>Shared IOC infrastructure with previously documented campaigns — correlate against historical incidents and threat intel platform for attribution continuity</span></div>"
        f"</div>"
        f"<p>Deploy all {ioc_count} IOCs to EDR, AV, firewall, and DNS RPZ immediately. "
        f"Run memory scan with provided YARA signatures against all endpoints — "
        f"particularly internet-facing servers and privileged workstations. "
        f"If malware is detected, isolate immediately and engage incident response — "
        f"malware presence indicates active adversary control of affected hosts.</p>"
        f"</div>"
    )


def _narrative_zero_day(item: Dict[str, Any]) -> str:
    """Zero-day narrative — emergency response framing."""
    title   = str(item.get("title") or "")
    product = _extract_product_from_title(title)
    ioc_count = len(item.get("iocs") or [])
    cvss    = item.get("cvss_score")
    kev     = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss_str = _get_cvss_context(cvss)
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else (
        "<div class='callout critical'>"
        "<strong>⚠ ZERO-DAY — NO VENDOR PATCH AVAILABLE:</strong> "
        "Standard patch-based remediation is not yet possible. "
        "Compensating controls and exposure reduction are the immediate priority. "
        "Monitor vendor advisory channels for emergency patch release."
        "</div>"
    )

    return (
        f"<div class='apex-narrative'>"
        f"<p>This advisory documents a <strong>zero-day vulnerability</strong> in "
        f"<strong>{_h(product)}</strong> with active exploitation confirmed before "
        f"a vendor patch is available.{cvss_str} "
        f"Zero-day exploitation windows are measured in hours — adversaries with "
        f"prior knowledge of the vulnerability have already begun targeting exposed systems.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Exposure Reduction Priority</span>"
        f"<span class='apex-value'>Disable, isolate, or restrict access to affected system immediately — operational risk of connectivity outweighs service disruption in zero-day scenarios</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Compensating Controls</span>"
        f"<span class='apex-value'>WAF virtual patching, network segmentation, authentication requirement enforcement, and enhanced monitoring on affected systems pending vendor patch</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Vendor Engagement</span>"
        f"<span class='apex-value'>Monitor vendor security advisory channel for emergency patch — activate your vendor escalation contact and subscribe to emergency notification list</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Threat Hunting Priority</span>"
        f"<span class='apex-value'>Hunt {ioc_count} IOCs across all telemetry for evidence of pre-patch exploitation — assume adversary access until forensics confirm clean state</span></div>"
        f"</div>"
        f"<p>This is a time-critical emergency response scenario. "
        f"If you cannot immediately patch, you must reduce exposure by other means: "
        f"network restriction, authentication hardening, or temporary service suspension "
        f"depending on operational risk tolerance and asset criticality.</p>"
        f"</div>"
    )


def _narrative_cve_rce(item: Dict[str, Any]) -> str:
    """RCE CVE narrative."""
    title     = str(item.get("title") or "")
    product   = _extract_product_from_title(title)
    ioc_count = len(item.get("iocs") or [])
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss      = item.get("cvss_score")
    cvss_str  = _get_cvss_context(cvss)
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    return (
        f"<div class='apex-narrative'>"
        f"<p>A <strong>Remote Code Execution (RCE)</strong> vulnerability has been identified in "
        f"<strong>{_h(product)}</strong>.{cvss_str} "
        f"RCE vulnerabilities represent the highest-value initial access vector — "
        f"adversaries will attempt lateral movement, credential harvesting, and "
        f"ransomware staging within 4–6 hours of a working exploit becoming available.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Attack Vector</span>"
        f"<span class='apex-value'>Network-accessible code path exploitable without authentication — internet-exposed instances are immediately in scope</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Impact Classification</span>"
        f"<span class='apex-value'>Full system compromise — adversary achieves arbitrary code execution with application-level or system-level privileges</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Lateral Movement Risk</span>"
        f"<span class='apex-value'>Post-RCE lateral movement typically begins within minutes — credential dumping and domain reconnaissance commence immediately after foothold establishment</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>Emergency patching; network segmentation of affected systems; EDR alerting for anomalous child process spawning from web server processes; hunt {ioc_count} IOCs</span></div>"
        f"</div>"
        f"<p>Defenders should correlate the IOC table against 30-day SIEM retention, proxy logs, "
        f"and EDR process telemetry. Specifically hunt for: web shell deployment, anomalous "
        f"child process spawning from the affected service, and outbound connections to "
        f"new external destinations from the vulnerable host class.</p>"
        f"</div>"
    )


def _narrative_cve_auth_bypass(item: Dict[str, Any]) -> str:
    """Auth bypass CVE narrative."""
    title    = str(item.get("title") or "")
    product  = _extract_product_from_title(title)
    ioc_count = len(item.get("iocs") or [])
    kev      = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss     = item.get("cvss_score")
    cvss_str = _get_cvss_context(cvss)
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    return (
        f"<div class='apex-narrative'>"
        f"<p>An <strong>Authentication Bypass</strong> vulnerability in "
        f"<strong>{_h(product)}</strong> allows unauthenticated access to "
        f"protected resources or administrative functionality.{cvss_str} "
        f"Authentication bypass to administrative functions should be treated as "
        f"severity CRITICAL regardless of the assigned CVSS score — "
        f"it grants immediate full application control.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Access Gained</span>"
        f"<span class='apex-value'>Unauthenticated access to privileged functionality — adversary can read sensitive data, modify configurations, or pivot to deeper system access</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Exploitation Simplicity</span>"
        f"<span class='apex-value'>Authentication bypasses typically require no sophisticated tooling — script-kiddie exploitation is expected within 24 hours of PoC publication</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Identity Impact</span>"
        f"<span class='apex-value'>Admin-level bypass enables credential reset, backdoor account creation, and authentication infrastructure manipulation — review all admin account activity</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>Emergency patch or disable affected authentication endpoint; audit admin account creation since last patch; hunt {ioc_count} IOCs across auth logs</span></div>"
        f"</div>"
        f"<p>Immediate actions: (1) Apply vendor patch or disable the authentication endpoint, "
        f"(2) Audit all privileged account creation and configuration changes in the past 30 days, "
        f"(3) Hunt for anomalous unauthenticated access in application and web server logs, "
        f"(4) Validate that session invalidation is complete after patching.</p>"
        f"</div>"
    )


def _narrative_cve_generic(item: Dict[str, Any]) -> str:
    """Generic CVE narrative — used only when no specific class matches."""
    title    = str(item.get("title") or "")
    product  = _extract_product_from_title(title)
    ioc_count = len(item.get("iocs") or [])
    kev      = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    cvss     = item.get("cvss_score")
    epss     = item.get("epss_score")
    sev      = str(item.get("severity") or "MEDIUM").upper()
    cvss_str = _get_cvss_context(cvss)
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    sev_context = {
        "CRITICAL": "requires emergency response within 4 hours — immediate patching or exposure reduction mandatory",
        "HIGH":     "requires action within 72 hours — prioritise patching above standard maintenance cycle",
        "MEDIUM":   "warrants prioritised assessment; patch within standard maintenance window",
        "LOW":      "schedule for next maintenance cycle; assess compensating controls if patching is delayed",
    }.get(sev, "requires risk assessment and prioritised remediation")

    epss_str = ""
    if epss is not None:
        try:
            e = float(epss)
            if e >= 50:
                epss_str = f" EPSS exploitation probability <strong>{e:.1f}%</strong> (30-day) confirms active or imminent exploitation — treat as HIGH urgency regardless of CVSS."
            elif e >= 10:
                epss_str = f" EPSS exploitation probability <strong>{e:.1f}%</strong> (30-day) — elevated exploitation risk warrants accelerated patching."
        except (ValueError, TypeError):
            pass

    _cve_impact_text = "System integrity and data confidentiality at risk - exploitation may enable code execution, data access, or service disruption" if sev in ("CRITICAL", "HIGH") else "Limited impact scope - assess compensating controls before emergency patching"
    _cve_defender_priority = "Hunt " + str(ioc_count) + " IOCs across SIEM/EDR; apply patch immediately; validate no pre-patch exploitation occurred" if ioc_count > 0 else "Apply vendor patch; validate patching completeness across all affected asset classes"

    return (
        f"<div class='apex-narrative'>"
        f"<p>A <strong>{_h(sev)}</strong>-severity vulnerability has been identified affecting "
        f"<strong>{_h(product)}</strong>.{cvss_str}{epss_str} "
        f"This advisory {sev_context}.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Attack Surface</span>"
        f"<span class='apex-value'>All systems running the affected software version — assess your asset inventory against affected versions listed in the vendor advisory</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Impact Classification</span>"
        f"<span class='apex-value'>{_cve_impact_text}</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Patch Availability</span>"
        f"<span class='apex-value'>Refer to vendor advisory for patch availability — apply vendor-recommended workaround immediately if patch is not yet available</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>{_cve_defender_priority}</span></div>"
        f"</div>"
        f"<p>Defenders should correlate the IOC table (Section 7) against 30-day SIEM retention, "
        f"proxy logs, EDR process telemetry, and authentication events. "
        f"Assess the advisory against your asset inventory and identify all affected versions "
        f"before applying the vendor-provided patch.</p>"
        f"</div>"
    )


def _narrative_threat_intel(item: Dict[str, Any]) -> str:
    """General threat intelligence narrative — non-CVE, non-specific-class."""
    title     = str(item.get("title") or "")
    actor     = _get_actor_display(item)
    ioc_count = len(item.get("iocs") or [])
    feed      = str(item.get("feed_source") or "threat intelligence source")
    kev       = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    sectors   = _get_sector_context(item)
    sev       = str(item.get("severity") or "MEDIUM").upper()
    kev_block = f"<div class='callout critical'>{_get_kev_context(kev)}</div>" if kev else ""

    _actor_attribution_status = "actively tracked threat cluster with operational history" if actor not in ("UNATTRIBUTED", "CDB-CVE-GEN", "Unknown", "untracked threat cluster") else "attribution pending - monitor APEX actor tracking for updates"

    return (
        f"<div class='apex-narrative'>"
        f"<p><strong>{_h(feed)}</strong> has published threat intelligence: "
        f"<em>&ldquo;{_h(title)}&rdquo;</em>. "
        f"APEX has classified this as <strong>{sev}</strong>-severity operational intelligence "
        f"documenting adversary activity, tooling, or techniques relevant to your defensive posture.</p>"
        f"{kev_block}"
        f"<div class='apex-intel-grid'>"
        f"<div class='apex-intel-item'><span class='apex-label'>Intelligence Type</span>"
        f"<span class='apex-value'>Operational threat intelligence — adversary activity, campaign indicators, or technique documentation from a trusted threat research source</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Actor Attribution</span>"
        f"<span class='apex-value'>{_h(actor)} &mdash; {_actor_attribution_status}</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Defender Priority</span>"
        f"<span class='apex-value'>Deploy all {ioc_count} IOCs to detection layers; correlate against 30-day SIEM history; review TTP coverage gaps using ATT&CK section</span></div>"
        f"<div class='apex-intel-item'><span class='apex-label'>Operational Relevance</span>"
        f"<span class='apex-value'>{_h(sectors)}</span></div>"
        f"</div>"
        f"<p>Deploy all {ioc_count} IOCs to SIEM, EDR, DNS RPZ, and perimeter firewall. "
        f"Correlate against 30-day SIEM retention for pre-existing compromise indicators. "
        f"Review the ATT&CK mapping (Section 6) to identify detection coverage gaps "
        f"for the documented technique set.</p>"
        f"</div>"
    )


# ---------------------------------------------------------------------------
# Dispatcher — Maps intelligence class to narrative generator
# ---------------------------------------------------------------------------

_NARRATIVE_DISPATCH = {
    CLS_THREAT_ACTOR:  _narrative_threat_actor,
    CLS_RANSOMWARE:    _narrative_ransomware,
    CLS_APT_ESPIONAGE: _narrative_apt_espionage,
    CLS_ICS_OT:        _narrative_ics_ot,
    CLS_CLOUD_SAAS:    _narrative_cloud_saas,
    CLS_SUPPLY_CHAIN:  _narrative_supply_chain,
    CLS_PHISHING:      _narrative_phishing,
    CLS_MALWARE:       _narrative_malware,
    CLS_ZERO_DAY:      _narrative_zero_day,
    CLS_CVE_RCE:       _narrative_cve_rce,
    CLS_CVE_AUTH:      _narrative_cve_auth_bypass,
    CLS_CVE_SQLI:      _narrative_cve_generic,   # uses generic with specific intro
    CLS_CVE_XSS:       _narrative_cve_generic,
    CLS_CVE_PRIVESC:   _narrative_cve_generic,
    CLS_CVE_SSRF:      _narrative_cve_generic,
    CLS_CVE_DOS:       _narrative_cve_generic,
    CLS_CVE_INFODISC:  _narrative_cve_generic,
    CLS_CVE_MEMORY:    _narrative_cve_generic,
    CLS_CVE_DESER:     _narrative_cve_rce,       # deserialization → RCE path
    CLS_CVE_GENERIC:   _narrative_cve_generic,
    CLS_THREAT_INTEL:  _narrative_threat_intel,
}


def generate_context_aware_technical_narrative(item: Dict[str, Any]) -> str:
    """
    PRIMARY ENTRY POINT.

    Classifies the advisory and dispatches to the appropriate
    threat-type-specific narrative generator.

    Never raises — returns safe HTML fallback on any error.
    """
    try:
        intel_class = classify_intelligence(item)
        # Inject class into item for downstream use
        item["_intel_class"] = intel_class

        generator = _NARRATIVE_DISPATCH.get(intel_class, _narrative_threat_intel)
        result = generator(item)

        log.debug(
            "Context-aware narrative: class=%s, id=%s",
            intel_class, str(item.get("id", "?"))[:16]
        )
        return result

    except Exception as exc:
        log.error("generate_context_aware_technical_narrative failed: %s", exc)
        # Safe fallback — better than crashing
        title = _h(str(item.get("title") or "Unknown Advisory"))
        return (
            f"<div class='apex-narrative'>"
            f"<p>Technical analysis for <strong>{title}</strong>. "
            f"Refer to the vendor advisory, MITRE ATT&CK mapping, and IOC table for "
            f"full operational details. Deploy all available IOCs to detection layers immediately.</p>"
            f"</div>"
        )


def generate_context_aware_executive_summary(item: Dict[str, Any]) -> str:
    """
    Context-aware executive summary — replaces generic 'APEX has detected a severity advisory' boilerplate.
    Adapts to intelligence class for business-relevant executive framing.

    Never raises.
    """
    try:
        title    = str(item.get("title") or "Unknown Advisory")
        intel_class = item.get("_intel_class") or classify_intelligence(item)
        sev      = str(item.get("severity") or "HIGH").upper()
        kev      = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
        cvss     = item.get("cvss_score")
        epss     = item.get("epss_score")
        risk     = float(item.get("risk_score") or 0)
        ioc_count = len(item.get("iocs") or [])
        ttps     = item.get("ttps") or []
        feed     = str(item.get("feed_source") or "threat intelligence feed")
        actor    = _get_actor_display(item)

        # CVE reference
        desc = str(item.get("description") or "")
        cve_refs = re.findall(r'CVE-\d{4}-\d+', f"{title} {desc}", re.I)
        cve_str = (
            f" Vulnerability identifier: <strong>{', '.join(cve_refs[:3])}</strong>."
            if cve_refs else ""
        )

        # EPSS framing
        epss_str = ""
        if epss is not None:
            try:
                e = float(epss)
                if e >= 90:
                    epss_str = (
                        f" EPSS exploitation probability: <strong>{e:.1f}%</strong> — "
                        "active exploitation is near-certain or already underway."
                    )
                elif e >= 50:
                    epss_str = (
                        f" EPSS exploitation probability: <strong>{e:.1f}%</strong> — "
                        "exploitation is highly probable within 30 days."
                    )
                elif e >= 10:
                    epss_str = f" EPSS: <strong>{e:.1f}%</strong> exploitation probability."
            except (ValueError, TypeError):
                pass

        # CVSS framing
        cvss_str = ""
        if cvss is not None:
            try:
                cvss_str = f" CVSS: <strong>{float(cvss):.1f}</strong>."
            except (ValueError, TypeError):
                pass

        # KEV warning block
        kev_block = ""
        if kev:
            kev_block = (
                "<div class='callout critical'>"
                "<strong>WARNING — CISA KEV CONFIRMED:</strong> "
                "This vulnerability has been added to the CISA Known Exploited Vulnerabilities (KEV) "
                "catalogue, confirming active exploitation in the wild. "
                "CISA Binding Operational Directive 22-01 requires US federal agencies to remediate "
                "within mandated timelines. All organisations should treat this as an emergency. "
                "Evidence of exploitation precedes your organisation's awareness — "
                "assume some assets may already be compromised. "
                "Execute immediate triage against your asset inventory."
                "</div>"
            )

        # Class-specific executive framing
        exec_intros = {
            CLS_THREAT_ACTOR: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified and analysed a <strong>{sev}</strong>-severity "
                f"threat actor report published by <strong>{_h(feed)}</strong>. "
                f"This intelligence documents adversary operations by <strong>{_h(actor)}</strong> "
                f"— providing direct actionable indicators and detection opportunities for defensive operations.{cve_str}"
            ),
            CLS_RANSOMWARE: (
                f"CYBERDUDEBIVASH SENTINEL APEX has detected a <strong>{sev}</strong>-severity "
                f"<strong>ransomware campaign</strong> with potential for complete operational disruption. "
                f"The threat actor <strong>{_h(actor)}</strong> is conducting active extortion operations — "
                f"immediate defensive action is required to prevent business-impacting encryption.{cve_str}"
            ),
            CLS_APT_ESPIONAGE: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified a <strong>{sev}</strong>-severity "
                f"<strong>nation-state cyber espionage operation</strong> attributed to "
                f"<strong>{_h(actor)}</strong>. "
                f"This advisory documents strategic intelligence collection activity — "
                f"the adversary prioritises persistent access and long-term exfiltration "
                f"over immediate disruptive impact.{cve_str}"
            ),
            CLS_ICS_OT: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified a <strong>{sev}</strong>-severity "
                f"threat to <strong>Industrial Control Systems and Operational Technology</strong>. "
                f"This advisory requires immediate engagement from both IT security and OT/plant operations teams — "
                f"the risk profile extends beyond data confidentiality to operational continuity and physical safety.{cve_str}"
            ),
            CLS_CLOUD_SAAS: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified a <strong>{sev}</strong>-severity "
                f"<strong>cloud and SaaS platform exposure</strong>. "
                f"The attack surface is your identity and access management layer — "
                f"traditional perimeter defences do not apply. "
                f"Immediate identity telemetry review and tenant audit are required.{cve_str}"
            ),
            CLS_ZERO_DAY: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified a <strong>{sev}</strong>-severity "
                f"<strong>zero-day vulnerability</strong> with active exploitation confirmed "
                f"before a vendor patch is available.{cve_str} "
                f"The exploitation window is open now — immediate exposure reduction is the only available defence."
            ),
            CLS_CVE_RCE: (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified a <strong>{sev}</strong>-severity "
                f"<strong>Remote Code Execution vulnerability</strong>.{cve_str} "
                f"RCE vulnerabilities are the primary gateway to ransomware deployment and "
                f"domain-wide compromise — adversaries prioritise these for weaponisation."
            ),
        }

        intro = exec_intros.get(
            intel_class,
            (
                f"CYBERDUDEBIVASH SENTINEL APEX has identified and validated a "
                f"<strong>{sev}</strong>-severity security advisory: "
                f"<em>&ldquo;{_h(title)}&rdquo;</em>. "
                f"Intelligence was sourced from <strong>{_h(feed)}</strong> and enriched "
                f"across CVE, EPSS, CISA KEV, MITRE ATT&CK, and threat-actor tracking pipelines.{cve_str}"
            )
        )

        action = (
            "Assess the advisory against your asset inventory, identify affected versions, "
            "and apply the vendor-provided patch within your risk-tiered patching SLA. "
            f"Deploy the APEX detection pack (Sigma, YARA, KQL) to identify exploitation "
            "attempts against your environment during the remediation window."
        ) if intel_class in (CLS_CVE_RCE, CLS_CVE_AUTH, CLS_CVE_SQLI, CLS_CVE_XSS,
                              CLS_CVE_PRIVESC, CLS_CVE_SSRF, CLS_CVE_DOS,
                              CLS_CVE_INFODISC, CLS_CVE_MEMORY, CLS_CVE_GENERIC) else (
            f"Deploy all {ioc_count} IOCs to your detection stack immediately. "
            f"Hunt across SIEM, EDR, DNS, and proxy logs using the provided detection pack. "
            "Assess this intelligence against your current threat model and risk register."
        )

        _esm_risk_label = "RISK/10" if risk else "SEVERITY"
        _esm_cvss_val = "Pending" if not cvss else str(cvss)
        _esm_epss_val = "N/A" if not epss else str(epss) + "%"
        _esm_kev_status = "KEV CONFIRMED" if kev else "NOT IN KEV"

        return (
            f"<div class='exec-summary-grid'>"
            f"<div class='esm-stat'><div class='esm-val'>{_h(str(risk or sev))}</div>"
            f"<div class='esm-label'>{_esm_risk_label}</div></div>"
            f"<div class='esm-stat'><div class='esm-val'>{_esm_cvss_val}</div>"
            f"<div class='esm-label'>CVSS</div></div>"
            f"<div class='esm-stat'><div class='esm-val'>{_esm_epss_val}</div>"
            f"<div class='esm-label'>EPSS 30d</div></div>"
            f"<div class='esm-stat'><div class='esm-val'>{_esm_kev_status}</div>"
            f"<div class='esm-label'>KEV STATUS</div></div>"
            f"<div class='esm-stat'><div class='esm-val'>{len(ttps)} TTPs / {ioc_count} IOCs</div>"
            f"<div class='esm-label'>INTEL DEPTH</div></div>"
            f"</div>"
            f"<p>{intro}</p>"
            f"{kev_block}"
            f"<p>{action}</p>"
        )

    except Exception as exc:
        log.error("generate_context_aware_executive_summary failed: %s", exc)
        title = _h(str(item.get("title") or "Unknown Advisory"))
        sev   = _h(str(item.get("severity") or "UNKNOWN").upper())
        return f"<p>SENTINEL APEX has identified a <strong>{sev}</strong>-severity advisory: <em>{title}</em>. Deploy all IOCs and apply vendor remediation guidance.</p>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "classify_intelligence",
    "generate_context_aware_technical_narrative",
    "generate_context_aware_executive_summary",
    # Class constants
    "CLS_THREAT_ACTOR", "CLS_RANSOMWARE", "CLS_APT_ESPIONAGE",
    "CLS_ICS_OT", "CLS_CLOUD_SAAS", "CLS_SUPPLY_CHAIN",
    "CLS_PHISHING", "CLS_MALWARE", "CLS_ZERO_DAY",
    "CLS_CVE_RCE", "CLS_CVE_AUTH", "CLS_CVE_SQLI",
    "CLS_CVE_XSS", "CLS_CVE_PRIVESC", "CLS_CVE_SSRF",
    "CLS_CVE_DOS", "CLS_CVE_INFODISC", "CLS_CVE_MEMORY",
    "CLS_CVE_DESER", "CLS_CVE_GENERIC", "CLS_THREAT_INTEL",
]
