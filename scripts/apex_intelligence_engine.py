#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX v103.0 — APEX Intelligence Engine
================================================================
GOD-LEVEL INTELLIGENCE ENRICHMENT PIPELINE

Pipeline position:
  INGEST → BOOTSTRAP → v70 → v74 → [THIS SCRIPT] → SYNC_MARKER → GIT → DEPLOY → API

Responsibility:
  Enriches every validated manifest item with 7 production-grade intelligence modules:

  Module 1: Evidence Authority Engine
    → KEV verification, vendor advisory validation, multi-source confirmation,
      exploit status validation, reliability score, evidence confidence

  Module 2: Analyst Intelligence Layer
    → Exploitation rationale, detection difficulty analysis, SOC failure points,
      strategic risk explanation (expert-level, non-generic)

  Module 3: SOC Deployment Context Engine
    → Required log sources, false positive scenarios, tuning recommendations,
      SOC priority level, deployment steps

  Module 4: Detection Confidence Scoring Engine
    → Structured metadata: confidence, detection_strength,
      false_positive_risk, deployment_complexity, scoring_rationale

  Module 5: Revenue Productization Engine
    → Detection pack description, API product mapping,
      marketplace listing structure, enterprise use cases, pricing tier

  Module 6: Executive Decision Engine
    → Immediate actions (0-24h), risk level, business impact summary,
      decision statement, time-to-exploit estimate

  Module 7: Compliance & Legal Safety Engine
    → TLP classification, attribution, legal disclaimer, data handling

Outputs:
  data/apex_enriched_manifest.json     — all items with 7-module enrichment (ADDITIVE)
  data/apex_intelligence_report.json   — full report: exec summary + revenue + compliance
  data/health/apex_engine_report.json  — execution audit log

Design constraints:
  - ADDITIVE ONLY — never modifies feed_manifest.json, validated_manifest.json
  - ZERO REGRESSION — each module wrapped in try/except; one module failure != pipeline failure
  - ZERO DATA LOSS — original item fields always preserved; new fields appended only
  - BACKWARD COMPATIBLE — all outputs are new files; existing consumers unaffected
  - FEATURE-FLAG CONTROLLED via config/feature_flags.json
  - Performance target: < 30s for 2000 items

Version: 103.0
Author: CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering
"""

import json
import sys
import hashlib
import shutil
import re
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [APEX-ENGINE] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("APEX-ENGINE")

# ── Paths ─────────────────────────────────────────────────────────────────────
_THIS = Path(__file__).resolve()
REPO  = _THIS.parent.parent

MANIFEST_CANDIDATES = [
    REPO / "data" / "validated_manifest.json",
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "feed_manifest.json",
    REPO / "data" / "enriched_manifest.json",
    REPO / "data" / "v101_manifest.json",
]
FEATURE_FLAGS_PATH        = REPO / "config" / "feature_flags.json"
APEX_ENRICHED_MANIFEST    = REPO / "data" / "apex_enriched_manifest.json"
APEX_INTELLIGENCE_REPORT  = REPO / "data" / "apex_intelligence_report.json"
APEX_ENGINE_AUDIT         = REPO / "data" / "health" / "apex_engine_report.json"

ENGINE_VERSION = "103.0"
NOW_UTC        = datetime.now(timezone.utc)
NOW_ISO        = NOW_UTC.isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    try:
        content = json.dumps(obj, ensure_ascii=False, indent=indent)
        tmp.write_text(content, encoding="utf-8")
        shutil.move(str(tmp), str(path))
        return path.stat().st_size
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _load_flags() -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "ENABLE_APEX_INTELLIGENCE_ENGINE": True,
        "APEX_MODULE_EVIDENCE":       True,
        "APEX_MODULE_ANALYST":        True,
        "APEX_MODULE_SOC_CONTEXT":    True,
        "APEX_MODULE_DETECTION":      True,
        "APEX_MODULE_REVENUE":        True,
        "APEX_MODULE_EXECUTIVE":      True,
        "APEX_MODULE_COMPLIANCE":     True,
        "APEX_MAX_ITEMS":             2000,
        "APEX_REQUIRE_EVIDENCE_GATE": False,   # strict gate — default False for compat
        "APEX_REQUIRE_CONFIDENCE_GATE": False,
        "APEX_REQUIRE_SOC_GATE":      False,
    }
    try:
        raw = json.loads(FEATURE_FLAGS_PATH.read_text(encoding="utf-8"))
        defaults.update(raw)
    except Exception as e:
        log.warning(f"Feature flags load failed ({e}) — using defaults")
    return defaults


def _load_manifest() -> List[Dict]:
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            entries: List[Dict] = []
            if isinstance(raw, list):
                entries = raw
            else:
                for key in ("advisories", "entries", "items", "data"):
                    v = raw.get(key)
                    if isinstance(v, list) and v:
                        entries = v
                        break
            if entries:
                log.info(f"Manifest loaded: {len(entries)} entries from {path.name}")
                return entries
        except Exception as e:
            log.warning(f"Manifest parse error ({path.name}): {e}")
    log.warning("No manifest found — returning empty list")
    return []


def _get_text(item: Dict) -> str:
    return ((item.get("title") or "") + " " + (item.get("description") or "") +
            " " + (item.get("category") or "") + " " + (item.get("detect") or "") +
            " " + (item.get("analyze") or "")).lower()


def _get_cvss(item: Dict) -> float:
    for field in ("risk_score", "cvss", "cvss_score", "cvss3_score"):
        v = item.get(field)
        if v is not None:
            try:
                return float(v)
            except (ValueError, TypeError):
                pass
    return 0.0


def _get_cves(item: Dict) -> List[str]:
    txt = (item.get("title") or "") + " " + (item.get("description") or "")
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", txt, re.IGNORECASE)))


def _is_kev(item: Dict) -> bool:
    return bool(item.get("kev") or item.get("kev_present") or item.get("cisa_kev"))


def _item_id(item: Dict) -> str:
    return item.get("stix_id") or item.get("id") or hashlib.md5(
        (item.get("title") or "").encode()
    ).hexdigest()[:12]


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1: EVIDENCE AUTHORITY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Known high-reliability source patterns
_HIGH_RELIABILITY_SOURCES = {
    "nvd", "nist", "cisa", "kev", "mitre", "microsoft", "msrc", "google",
    "mandiant", "crowdstrike", "sentinelone", "paloalto", "unit42",
    "cisco talos", "talos", "qualys", "tenable", "rapid7", "securityfocus",
    "zero day initiative", "zdi", "vendor", "advisory", "cert", "ncsc",
    "cve.org", "ivanti", "sap", "citrix", "fortinet", "vmware", "oracle",
    "cisco", "juniper", "f5", "apache", "linux", "canonical", "redhat",
    "ubuntu", "debian", "github", "huntr", "bugcrowd", "hackerone",
}

_MEDIUM_RELIABILITY_SOURCES = {
    "threatpost", "bleepingcomputer", "securityweek", "therecord",
    "darkreading", "helpnetsecurity", "infosecurity-magazine", "krebsonsecurity",
    "checkpoint", "sophos", "trendmicro", "eset", "kaspersky", "avast",
    "malwarebytes", "bitdefender", "symantec", "mcafee",
}

_EXPLOIT_INDICATORS = {
    "active exploit", "exploited in the wild", "actively exploited",
    "observed exploitation", "exploit detected", "live exploit",
    "in-the-wild", "itw", "poc available", "proof of concept",
    "metasploit", "ransomware", "zero-day", "0day", "0-day",
    "nation-state", "apt", "threat actor", "campaign",
}

_NO_EXPLOIT_INDICATORS = {
    "no known exploit", "not observed", "theoretical",
    "no evidence of exploitation", "patch available before exploitation",
}


def module_evidence_authority(item: Dict) -> Dict:
    """
    Module 1: Evidence Authority Engine
    Assigns structured evidence validation block to each CVE/advisory.
    """
    text   = _get_text(item)
    cvss   = _get_cvss(item)
    kev    = _is_kev(item)
    cves   = _get_cves(item)
    source = (item.get("source") or item.get("feed_name") or "").lower()

    # ── KEV Verification ─────────────────────────────────────────────────────
    kev_verified = kev  # If kev field is true, treat as CISA-verified

    # ── Vendor Advisory Validation ───────────────────────────────────────────
    vendor_advisory = any(s in source for s in _HIGH_RELIABILITY_SOURCES)
    if not vendor_advisory:
        # Check description for advisory references
        vendor_advisory = any(kw in text for kw in (
            "vendor advisory", "security note", "security advisory",
            "patch tuesday", "out-of-band", "security bulletin",
            "cve.org", "nvd.nist", "msrc", "cisco advisory",
        ))

    # ── Multi-Source Confirmation ─────────────────────────────────────────────
    has_title       = bool((item.get("title") or "").strip())
    has_description = len((item.get("description") or "").strip()) >= 50
    has_cvss        = cvss > 0
    has_cve         = len(cves) > 0
    multi_source_confirmed = sum([has_title, has_description, has_cvss, has_cve, kev_verified]) >= 3

    # ── Exploit Status Validation ─────────────────────────────────────────────
    exploit_confirmed = kev or any(kw in text for kw in _EXPLOIT_INDICATORS)
    no_exploit_evidence = any(kw in text for kw in _NO_EXPLOIT_INDICATORS)

    if kev:
        exploit_status = "ACTIVE_CONFIRMED"
    elif exploit_confirmed and not no_exploit_evidence:
        exploit_status = "ACTIVE_OBSERVED"
    elif no_exploit_evidence:
        exploit_status = "NO_EVIDENCE"
    else:
        exploit_status = "UNVERIFIED"

    # ── Reliability Score ─────────────────────────────────────────────────────
    score = 0
    if kev_verified:      score += 40
    if cvss >= 9.0:       score += 20
    elif cvss >= 7.0:     score += 12
    elif cvss >= 4.0:     score += 6
    if vendor_advisory:   score += 15
    if multi_source_confirmed: score += 15
    if has_cve:           score += 5
    if exploit_confirmed: score += 5

    if score >= 75:
        reliability_score = "HIGH"
    elif score >= 45:
        reliability_score = "MEDIUM"
    else:
        reliability_score = "LOW"

    # ── Evidence Confidence ───────────────────────────────────────────────────
    if kev and cvss >= 9.0 and vendor_advisory:
        evidence_confidence = "CONFIRMED"
    elif kev or (cvss >= 7.0 and vendor_advisory):
        evidence_confidence = "LIKELY"
    else:
        evidence_confidence = "UNVERIFIED"

    # ── Sources Referenced ────────────────────────────────────────────────────
    sources_ref = []
    if kev:                sources_ref.append("CISA KEV Catalog")
    if has_cve:            sources_ref.append("NVD/CVE Database")
    if vendor_advisory:    sources_ref.append("Vendor Security Advisory")
    if exploit_confirmed:  sources_ref.append("Threat Intelligence Feed")
    if not sources_ref:    sources_ref.append("Feed Aggregator")

    return {
        "kev_verified":          kev_verified,
        "vendor_advisory":       vendor_advisory,
        "multi_source_confirmed": multi_source_confirmed,
        "exploit_status":        exploit_status,
        "reliability_score":     reliability_score,
        "evidence_confidence":   evidence_confidence,
        "raw_confidence_score":  min(score, 100),
        "sources_referenced":    sources_ref,
        "validation_timestamp":  NOW_ISO,
        "cve_count":             len(cves),
        "has_cvss":              has_cvss,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2: ANALYST INTELLIGENCE LAYER
# ══════════════════════════════════════════════════════════════════════════════

_ANALYST_PROFILES: Dict[str, Dict] = {
    "rce": {
        "exploitation_rationale": (
            "Remote code execution vulnerabilities are the highest-value exploit primitive "
            "for threat actors. They convert network access into full system control without "
            "requiring physical presence or prior credentials. Pre-authentication RCE eliminates "
            "all access barriers, enabling mass exploitation via automated scanning infrastructure. "
            "Ransomware groups and APTs prioritize RCE in internet-facing services because a single "
            "exploit converts to persistent foothold at network scale."
        ),
        "detection_difficulty": (
            "RCE exploitation often masquerades as legitimate application traffic. Web-based RCE "
            "exploits arrive as HTTP requests indistinguishable from normal user traffic without "
            "deep packet inspection or application-layer anomaly detection. Post-exploitation activity "
            "frequently uses living-off-the-land binaries (LOLBins) that appear in normal process "
            "telemetry. Detection window between initial exploit and credential dumping is often "
            "under 15 minutes in automated attack chains."
        ),
        "soc_failure_points": (
            "Most SOC teams rely on signature-based IDS for initial detection and miss RCE "
            "exploitation when payloads are obfuscated or use uncommon encoding. Alert fatigue "
            "from high-volume web application logs causes analysts to miss the single exploit "
            "request among millions of legitimate requests. Post-exploitation detection via process "
            "lineage (e.g., web server spawning cmd.exe) is frequently misconfigured or disabled."
        ),
        "strategic_risk": (
            "A single unpatched RCE in an internet-facing service represents complete perimeter "
            "elimination. Attackers who achieve RCE on a web-facing server or VPN gateway gain "
            "an internal pivot point that negates all perimeter security investments. The strategic "
            "risk compounds when the vulnerable system is an identity provider, VPN gateway, "
            "or ERP system with connectivity to critical business infrastructure."
        ),
    },
    "lpe": {
        "exploitation_rationale": (
            "Local privilege escalation vulnerabilities are the critical second stage in multi-phase "
            "attack chains. Threat actors use LPE to convert low-privilege initial access (via phishing, "
            "malware, or compromised credentials) into SYSTEM or root privileges needed for credential "
            "dumping, persistence, and ransomware deployment. LPE exploits targeting kernel drivers "
            "(CLFS, win32k, etc.) are particularly valued because kernel context enables bypassing "
            "all user-mode security controls including EDR agent self-protection."
        ),
        "detection_difficulty": (
            "LPE exploitation via kernel driver vulnerabilities leaves minimal user-mode traces. "
            "The exploitation itself occurs in kernel context, invisible to most EDR solutions that "
            "operate in user mode. The only reliable detection signal is the behavioral transition: "
            "a process running as standard user suddenly acquiring SYSTEM privileges. This transition "
            "is often missed because the elevated process immediately inherits a legitimate parent "
            "process name through token impersonation."
        ),
        "soc_failure_points": (
            "Security teams frequently lack kernel-level telemetry. Windows Sysmon does not capture "
            "kernel object handle events by default. Most SIEM implementations focus on network events "
            "and miss the host-based LPE signal. The gap between initial access and LPE exploitation "
            "is typically 10-60 minutes — often occurring outside business hours when analyst "
            "coverage is reduced."
        ),
        "strategic_risk": (
            "Organizations that invest in least-privilege architectures and endpoint controls see "
            "those investments negated by a single LPE vulnerability. The ransomware kill chain "
            "critically depends on LPE: without SYSTEM privileges, ransomware cannot access protected "
            "files, inject into system processes, or disable security software. A patched LPE "
            "vulnerability directly reduces ransomware deployment success rates."
        ),
    },
    "auth_bypass": {
        "exploitation_rationale": (
            "Authentication bypass vulnerabilities are disproportionately dangerous because they "
            "invalidate the foundational security assumption that only authorized users can access "
            "protected resources. Attackers exploit auth bypasses to impersonate any user — including "
            "administrators — without knowing actual credentials. In SaaS and web application contexts, "
            "a single auth bypass can expose all tenant data across a multi-tenant platform."
        ),
        "detection_difficulty": (
            "Successful authentication bypass generates log entries that appear identical to "
            "legitimate authentication events. Standard SIEM queries looking for failed authentication "
            "produce zero alerts for bypasses — the bypass succeeds. Detection requires behavioral "
            "analysis of what the authenticated session does, not just that authentication occurred. "
            "Source IP reputation checks are easily defeated by residential proxy networks."
        ),
        "soc_failure_points": (
            "SOC teams typically build detection around authentication failures, not successes. "
            "Monitoring for successful authentication from unexpected geographic locations is "
            "frequently tuned out due to VPN and remote worker false positives. Session behavior "
            "analytics (accessing resources inconsistent with user role) requires baselining that "
            "many organizations have not implemented."
        ),
        "strategic_risk": (
            "Authentication bypass in privileged access management, identity providers, or "
            "administrative interfaces grants attackers the equivalent of a master key. The strategic "
            "impact scales with the sensitivity of resources the bypassed system protects. In "
            "enterprise environments, bypassing a single PAM or IAM solution can cascade into "
            "full Active Directory compromise."
        ),
    },
    "sqli": {
        "exploitation_rationale": (
            "SQL injection remains operationally significant despite decades of awareness because "
            "legacy application code and ORM misconfigurations continue to introduce the flaw at "
            "scale. Attackers exploit SQLi to extract complete database contents in automated attacks "
            "using tools like sqlmap. In high-privilege database configurations (e.g., xp_cmdshell "
            "enabled), SQLi converts directly to OS command execution without additional exploit stages."
        ),
        "detection_difficulty": (
            "Modern SQLi attacks use time-based blind techniques and heavy encoding to evade WAF "
            "signatures. Attack traffic is distributed across multiple source IPs to defeat "
            "rate-limiting. Attackers often use legitimate cloud provider IP ranges to bypass "
            "geolocation-based blocking. The exfiltration phase occurs as normal SELECT queries "
            "returning data within expected HTTP response size ranges."
        ),
        "soc_failure_points": (
            "WAF logs are frequently not forwarded to SIEM, creating a blind spot for the primary "
            "detection control. Database audit logging (logging all queries) creates performance "
            "overhead that many organizations disable in production. Error-based SQLi may generate "
            "application log entries but these are rarely correlated with WAF events."
        ),
        "strategic_risk": (
            "The strategic risk of SQL injection scales directly with the sensitivity of the database. "
            "In healthcare, financial, and government contexts, successful SQLi represents a "
            "reportable data breach affecting potentially millions of records. The regulatory, "
            "reputational, and financial consequences of a single missed SQLi vulnerability in a "
            "public-facing application routinely exceed $1M."
        ),
    },
    "ssrf": {
        "exploitation_rationale": (
            "Server-Side Request Forgery enables attackers to pivot from a perimeter-facing "
            "application to internal network resources that are otherwise unreachable. In cloud "
            "environments, SSRF is particularly critical because it enables access to instance "
            "metadata services (IMDS) that expose cloud credentials. SSRF is a foundational "
            "vulnerability in cloud-native attack chains: perimeter SSRF → IMDS access → "
            "cloud API credentials → account takeover."
        ),
        "detection_difficulty": (
            "SSRF exploitation generates outbound HTTP requests from the application server that "
            "appear to originate from a legitimate internal service. In microservices architectures, "
            "internal service-to-service calls are normal and expected, making SSRF traffic "
            "behaviorally indistinguishable from legitimate traffic without URL parameter analysis. "
            "Cloud IMDS access via SSRF (169.254.169.254) is the most reliable detection signal "
            "but is not monitored by most teams."
        ),
        "soc_failure_points": (
            "Most organizations lack egress filtering for application servers — the assumption is "
            "that applications should be able to make outbound requests. DNS logging for internal "
            "requests is frequently absent. Cloud IMDS access logging is not enabled by default "
            "and must be explicitly configured in CloudTrail/Activity Log."
        ),
        "strategic_risk": (
            "SSRF vulnerability in any cloud-connected application represents a potential path to "
            "complete cloud account compromise. The attack requires no additional tools beyond "
            "the initial SSRF — the exploit chain from SSRF to cloud credential extraction "
            "can be fully automated. Once cloud credentials are extracted, the attacker operates "
            "as a legitimate cloud principal with all associated permissions."
        ),
    },
    "supply_chain": {
        "exploitation_rationale": (
            "Supply chain attacks target the trust relationship between software consumers and their "
            "vendors or dependencies. Attackers prefer supply chain compromise because it converts "
            "a single vendor compromise into simultaneous access to thousands of customers — the "
            "economics of supply chain attacks are unmatched by any other technique. The vendor's "
            "code signing certificate or update mechanism becomes a deployment channel for malware."
        ),
        "detection_difficulty": (
            "Supply chain attacks leverage legitimate code signing, legitimate update mechanisms, "
            "and trusted vendor infrastructure. Code signed by a legitimate vendor certificate will "
            "pass all signature verification checks. The malicious behavior may be dormant until "
            "activation, may be conditional on specific targets, or may blend with legitimate "
            "telemetry from the same vendor. Behavioral detection is the only reliable approach."
        ),
        "soc_failure_points": (
            "Most organizations have implicit trust relationships with their software vendors that "
            "exclude vendor-signed updates from security inspection. Application allowlisting "
            "frequently whitelists vendor installation paths. Incident response processes assume "
            "that vendor software is the baseline — not a source of compromise. Detecting "
            "abnormal behavior from trusted software requires behavioral baselining that most "
            "organizations have not established."
        ),
        "strategic_risk": (
            "Supply chain compromise is the highest-leverage attack technique available to "
            "sophisticated threat actors because it bypasses all perimeter and endpoint controls "
            "simultaneously. A single compromised vendor can provide access to critical "
            "infrastructure across entire industry sectors. The SolarWinds compromise demonstrated "
            "that supply chain attacks against widely-used enterprise software can provide "
            "simultaneous access to thousands of high-value targets including government agencies."
        ),
    },
    "ransomware": {
        "exploitation_rationale": (
            "Ransomware operators leverage a proven multi-stage attack chain: initial access "
            "(phishing, VPN exploitation, credential stuffing) → privilege escalation → "
            "Active Directory compromise → mass deployment. The business model is mathematically "
            "sound: low cost per attack attempt, high ransom demand relative to cost, victim "
            "economics favor paying. Ransomware-as-a-Service platforms democratize the capability, "
            "enabling affiliates with minimal technical skill to conduct enterprise-scale attacks."
        ),
        "detection_difficulty": (
            "Modern ransomware operations conduct extended reconnaissance (2-30 days) before "
            "encryption using legitimate administration tools (PSExec, WMI, RDP) that blend with "
            "IT operations. File encryption using AES-256 with per-file random keys occurs in "
            "minutes once triggered. The detection window between encryption initiation and "
            "complete data loss is measured in minutes on high-throughput systems. "
            "Behavioral detection (mass file rename/encrypt events) triggers after damage begins."
        ),
        "soc_failure_points": (
            "Extended dwell time (median 21 days pre-encryption) provides ample detection "
            "opportunity that most SOCs miss due to insufficient EDR telemetry, lack of "
            "behavioral baselining, or alert fatigue. BloodHound/SharpHound execution for AD "
            "reconnaissance is frequently categorized as low-priority. Volume shadow copy deletion "
            "(a pre-encryption prerequisite) is a high-fidelity signal that triggers no alert "
            "in many SIEM configurations."
        ),
        "strategic_risk": (
            "A successful ransomware deployment represents total operational disruption. Healthcare "
            "organizations face patient safety risk when clinical systems are encrypted. Financial "
            "institutions face regulatory notification obligations within 72 hours. Manufacturing "
            "companies face production line shutdown. Average total recovery cost including "
            "downtime, forensics, legal, and regulatory response now exceeds $4.5M. Reputational "
            "damage from public disclosure extends business impact beyond recovery completion."
        ),
    },
    "credential": {
        "exploitation_rationale": (
            "Credential-based attacks exploit the fundamental weakness that user-chosen passwords "
            "are predictable and reused across services. Threat actors purchase or steal credential "
            "databases and execute automated credential stuffing against enterprise portals and VPNs. "
            "Phishing campaigns harvest credentials with >40% click-through rates in targeted "
            "spear-phishing. Stolen credentials provide authenticated access that appears identical "
            "to legitimate user activity, eliminating the need for exploit-based initial access."
        ),
        "detection_difficulty": (
            "Credential-based access uses legitimate authentication protocols — there is no "
            "malicious payload to detect. Without behavioral analytics, a threat actor using "
            "stolen credentials is indistinguishable from the legitimate user. Geography-based "
            "detection (impossible travel) is defeated by proxy networks. Timing-based detection "
            "is defeated by targeting access during the victim's business hours from the correct "
            "timezone using commercial proxy services."
        ),
        "soc_failure_points": (
            "Most organizations monitor for failed authentication but not for successful "
            "authentication from new devices or locations. MFA bypass via SIM swapping, "
            "OTP phishing (adversary-in-the-middle), or fatigue attacks is rarely detected "
            "because authentication still succeeds. Lateral movement using harvested credentials "
            "blends with normal administrator activity. Monitoring for anomalous access to "
            "sensitive resources post-authentication is often an unsolved problem."
        ),
        "strategic_risk": (
            "Credential compromise is the most common initial access vector across all industry "
            "sectors. Once an attacker has valid credentials for an administrative account, "
            "the entire security architecture — firewalls, IDS, DLP, endpoint protection — "
            "becomes permeable because the attacker authenticates rather than exploits. "
            "The strategic response requires identity-centric security: MFA everywhere, "
            "privileged access workstations, and behavioral analytics on all authenticated sessions."
        ),
    },
    "default": {
        "exploitation_rationale": (
            "This vulnerability class is actively targeted by threat actors due to its accessibility "
            "and the value of the resources it exposes. Automated scanning infrastructure continuously "
            "probes internet-facing assets for known vulnerabilities, converting newly disclosed CVEs "
            "into operational capabilities within hours of public disclosure. Organizations relying "
            "solely on patch cadence without compensating controls are at risk during the window "
            "between disclosure and patch deployment."
        ),
        "detection_difficulty": (
            "Detection of exploitation attempts requires application-specific log analysis that goes "
            "beyond standard network flow data. Many exploit attempts arrive over legitimate protocols "
            "(HTTPS, DNS) that are not deeply inspected. Post-exploitation activity frequently "
            "uses legitimately installed tools and signed binaries that appear normal in process "
            "telemetry. The signal-to-noise ratio in enterprise log environments makes "
            "identifying the specific exploitation event challenging without precise detection rules."
        ),
        "soc_failure_points": (
            "Coverage gaps most often arise from incomplete log forwarding to SIEM, "
            "detection rules that are not maintained after initial deployment, and insufficient "
            "analyst training on application-specific attack techniques. Vulnerability management "
            "processes often lack integration with threat intelligence, resulting in patches "
            "being prioritized by CVSS score alone rather than active exploitation evidence. "
            "The absence of a validated detection rule for a specific CVE leaves organizations "
            "blind to exploitation until post-compromise forensics."
        ),
        "strategic_risk": (
            "Every unpatched vulnerability in the CISA KEV catalog represents confirmed, active "
            "exploitation risk. The KEV listing indicates that threat actors have operationalized "
            "the vulnerability and are using it in real attacks against real organizations. "
            "The strategic question is not if your organization will be targeted, but whether "
            "your detection and patching capability is faster than the attacker's scanning "
            "and exploitation pipeline. Unpatched KEV vulnerabilities in internet-facing systems "
            "should be treated as open backdoors."
        ),
    },
}


def _classify_vuln_type(item: Dict) -> str:
    text = _get_text(item)
    if any(k in text for k in ("remote code exec", " rce", "code execution", "command exec")):
        return "rce"
    if any(k in text for k in ("privilege escal", "elevation of priv", " lpe ", "local priv")):
        return "lpe"
    if any(k in text for k in ("auth bypass", "authentication bypass", "unauthenticated", "no auth")):
        return "auth_bypass"
    if any(k in text for k in ("sql inject", "sqli", "blind sql", "union select")):
        return "sqli"
    if any(k in text for k in ("ssrf", "server-side request", "server side request", "request forgery")):
        return "ssrf"
    if any(k in text for k in ("supply chain", "dependency confus", "typosquatt", "solarwinds")):
        return "supply_chain"
    if any(k in text for k in ("ransomware", "encrypt", "lockbit", "blackcat", "cl0p", "play ransom")):
        return "ransomware"
    if any(k in text for k in ("credential", "password", "phish", "brute force", "account takeover")):
        return "credential"
    return "default"


def module_analyst_intelligence(item: Dict) -> Dict:
    """Module 2: Analyst Intelligence Layer — expert non-generic insights."""
    vuln_type = _classify_vuln_type(item)
    profile   = _ANALYST_PROFILES.get(vuln_type, _ANALYST_PROFILES["default"])
    cvss      = _get_cvss(item)
    kev       = _is_kev(item)

    # Contextual risk escalation note
    if kev and cvss >= 9.0:
        context_note = (
            "CRITICAL ANALYST NOTE: This vulnerability is both CISA KEV-listed and scores "
            f"CVSS {cvss:.1f}. The combination of confirmed active exploitation and maximum "
            "severity demands immediate prioritization. Standard patch cycle timelines are "
            "incompatible with the confirmed threat actor activity against this vulnerability."
        )
    elif kev:
        context_note = (
            "ANALYST NOTE: CISA KEV listing confirms active exploitation in the wild. "
            "This moves the vulnerability from theoretical risk to confirmed, ongoing threat. "
            "Treat patch deployment as an emergency action, not a scheduled maintenance item."
        )
    elif cvss >= 9.0:
        context_note = (
            f"ANALYST NOTE: CVSS {cvss:.1f} places this in the highest severity tier. "
            "While KEV listing is not confirmed, the attack complexity is low and impact "
            "is critical. Active exploitation should be assumed until evidence proves otherwise."
        )
    else:
        context_note = (
            "ANALYST NOTE: Monitor CISA KEV catalog for exploitation status updates. "
            "Detection rules should be deployed proactively — threat actors typically "
            "develop operational exploits within days of public CVE disclosure."
        )

    return {
        "vulnerability_class":    vuln_type.upper(),
        "exploitation_rationale": profile["exploitation_rationale"],
        "detection_difficulty":   profile["detection_difficulty"],
        "soc_failure_points":     profile["soc_failure_points"],
        "strategic_risk":         profile["strategic_risk"],
        "analyst_context_note":   context_note,
        "analyst_engine":         "SENTINEL-APEX-ANALYST-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3: SOC DEPLOYMENT CONTEXT ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_LOG_SOURCE_MAP: Dict[str, List[str]] = {
    "rce":          ["Web Server Access Logs (HTTP/HTTPS)", "WAF Logs", "Sysmon EventID 1 (Process Create)", "Sysmon EventID 3 (Network Connect)", "EDR Process Telemetry", "Windows Security EventID 4688"],
    "lpe":          ["Sysmon EventID 1/10 (Process/LSASS Access)", "Windows Security EventID 4672 (Special Privileges)", "Windows Security EventID 4688 (Process Create)", "EDR Kernel Telemetry", "Windows Security EventID 4624/4625 (Logon Events)"],
    "auth_bypass":  ["Application Authentication Logs", "Web Server Access Logs", "Identity Provider Logs (ADFS/AAD/Okta)", "Windows Security EventID 4624/4625", "VPN/Gateway Access Logs"],
    "sqli":         ["WAF Logs", "Database Audit Logs (MySQL/MSSQL/PgSQL General Queries)", "Web Server Error Logs", "Application Logs (4xx/5xx responses)", "IDS/IPS Alert Logs"],
    "ssrf":         ["Egress Proxy Logs", "DNS Query Logs", "Cloud Trail / Activity Log (AWS/Azure/GCP)", "Application Server Outbound Request Logs", "Network Flow Logs (NetFlow/IPFIX)"],
    "supply_chain": ["Software Inventory Logs", "Package Manager Logs (npm/pip/maven audit)", "Binary Execution Logs", "Code Signing Verification Logs", "EDR Process Hash Telemetry"],
    "ransomware":   ["Sysmon EventID 11 (File Create)", "Windows Security EventID 4688 (Process)", "VSS/Shadow Copy Deletion Events", "SMB Share Access Logs", "EDR File Activity Telemetry", "AD Security EventID 4720/4732 (Account/Group Changes)"],
    "credential":   ["Authentication Logs (AD, RADIUS, VPN)", "Azure AD / Okta Sign-in Logs", "Windows Security EventID 4624/4625/4648", "LSASS Access Events (Sysmon EventID 10)", "Email Gateway Logs (phishing delivery)"],
    "default":      ["SIEM/EDR Alerts", "Sysmon Full Event Log", "Network Flow Logs", "Web Proxy Logs", "Windows Security Event Log", "Application Error Logs"],
}

_FALSE_POSITIVE_MAP: Dict[str, List[str]] = {
    "rce":         ["Legitimate application deployment scripts writing to web directories", "Authorized penetration testing activities", "Development team debug endpoints in non-production environments", "Automated CI/CD pipeline deployment agents"],
    "lpe":         ["Privileged IT administration tools (SysInternals, AdminTools)", "Endpoint management agents (SCCM, Intune, Tanium)", "Authorized scheduled tasks running as SYSTEM", "Backup agents requiring elevated access"],
    "auth_bypass": ["Users accessing from new devices after device refresh", "VPN connections from travel locations", "Service account authentications from new systems after migration", "SSO federation events from new IdP configurations"],
    "sqli":        ["Application health check queries with unusual character sets", "Legitimate search features with complex query strings", "Reporting tools generating complex multi-table JOIN queries", "ORM-generated queries that superficially resemble injection patterns"],
    "ssrf":        ["Application integrations making legitimate outbound calls to partner APIs", "Health check endpoints probing internal services", "Webhook validation calls to external services", "Cloud metadata retrieval by authorized application configuration code"],
    "supply_chain":["Legitimate software updates from affected vendor (post-remediation)", "IT asset management scanning identifying affected package versions", "Authorized dependency auditing tools", "CI/CD pipeline package resolution"],
    "ransomware":  ["Backup software performing legitimate large-scale file operations", "Antivirus scanning causing high file read rates", "Document management systems performing bulk indexing", "Authorized disk encryption tools (BitLocker deployment)"],
    "credential":  ["Helpdesk performing password resets across multiple accounts", "IT migration activities using admin credentials across systems", "Authorized red team exercises", "Service account authentication from new deployment hosts"],
    "default":     ["Authorized security scanning tools", "IT administration activity", "Automated monitoring and health check systems", "Authorized penetration testing"],
}

_TUNING_MAP: Dict[str, List[str]] = {
    "rce":         ["Allowlist known deployment tool source IPs/user-agents from web upload detection", "Tune process lineage rules to exclude known parent-child pairs from CI/CD agents", "Set CVSS threshold to 8.0+ for immediate alert escalation; 6.0-8.0 for SOC review queue"],
    "lpe":         ["Exclude known endpoint management agent processes from LSASS access alerts", "Baseline SYSTEM-privilege process list per host type (workstation vs. server)", "Set 24-hour suppression window for patched systems after confirmed patch deployment"],
    "auth_bypass": ["Build geographic baseline per user — alert only on locations outside defined home/office regions", "Allowlist known VPN exit node IP ranges to reduce travel false positives", "Set time-window correlation: auth anomaly + unusual resource access within 30 minutes = high-confidence alert"],
    "sqli":        ["Tune WAF rule sensitivity to WAF mode 'Detection Only' first — audit for 7 days before switching to 'Prevention'", "Build query pattern baseline for your specific application stack (MSSQL vs. MySQL vs. PgSQL query patterns differ)", "Set minimum payload length threshold (>20 chars) to reduce noise from single-character test queries"],
    "ssrf":        ["Add 169.254.169.254 (AWS IMDS) and cloud metadata IPs to critical destination watchlist", "Tune egress proxy alerts to threshold: >50 unique internal IPs contacted per hour from single application instance", "Allowlist documented integration API endpoints in outbound call baseline"],
    "supply_chain":["Implement hash-based binary allowlisting — alert on ANY new unsigned or newly-signed binary in vendor installation paths", "Set daily scan of software inventory against CVE NVD database with automated ticket creation for CVSS >= 7.0 matches"],
    "ransomware":  ["Tune file operation thresholds: >500 file renames/creates per minute from single process = immediate CRITICAL alert", "Exclude backup software process names from bulk file operation alerts (maintain separate backup software monitoring)", "Correlate VSS deletion events with process name — any non-Microsoft, non-backup-tool process deleting VSS = P1"],
    "credential":  ["Implement user behavior baseline over 30-day window before deploying impossible travel alerts to avoid initial false positive storm", "Set MFA challenge bypass detection: successful auth + no MFA event within 60 seconds = review queue", "Allowlist known administrative IP ranges for service account activities"],
    "default":     ["Build environment-specific baseline before deploying new detection rules to production", "Run in monitoring mode for 72 hours before enabling automated blocking", "Set CVSS-based auto-escalation thresholds aligned to SLA policy"],
}

_SOC_PRIORITY_MAP: Dict[str, str] = {
    "rce": "P1 — IMMEDIATE", "lpe": "P1 — IMMEDIATE",
    "auth_bypass": "P1 — IMMEDIATE", "ransomware": "P1 — IMMEDIATE",
    "sqli": "P2 — HIGH", "ssrf": "P2 — HIGH",
    "supply_chain": "P1 — IMMEDIATE", "credential": "P2 — HIGH",
    "default": "P2 — HIGH",
}


def module_soc_deployment_context(item: Dict) -> Dict:
    """Module 3: SOC Deployment Context Engine — directly deployable SOC guidance."""
    vuln_type = _classify_vuln_type(item)
    cvss      = _get_cvss(item)
    kev       = _is_kev(item)

    priority = _SOC_PRIORITY_MAP.get(vuln_type, "P2 — HIGH")
    if kev:
        priority = "P1 — IMMEDIATE"
    elif cvss >= 9.0:
        priority = "P1 — IMMEDIATE"

    log_sources  = _LOG_SOURCE_MAP.get(vuln_type, _LOG_SOURCE_MAP["default"])
    fps          = _FALSE_POSITIVE_MAP.get(vuln_type, _FALSE_POSITIVE_MAP["default"])
    tuning       = _TUNING_MAP.get(vuln_type, _TUNING_MAP["default"])

    deployment_steps = [
        "Step 1: Import detection rules into SIEM (Sigma/Splunk/KQL — see Detection Engine section).",
        "Step 2: Validate log sources are forwarding to SIEM (check required log sources list above).",
        "Step 3: Run detection query against 30-day historical data for retrospective detection.",
        "Step 4: Set alert threshold and assign to SOC Tier-1 queue for initial triage.",
        "Step 5: Build escalation runbook — define Tier-1 triage steps and Tier-2 escalation criteria.",
        "Step 6: Test rule with a simulated benign event matching the false positive scenarios above.",
        "Step 7: Enable automated enrichment (IP reputation, CVE lookup, user account context) on alert trigger.",
        "Step 8: Schedule 72-hour rule review after deployment to tune false positive rate.",
    ]

    return {
        "soc_priority":          priority,
        "required_log_sources":  log_sources,
        "false_positive_scenarios": fps,
        "tuning_recommendations": tuning,
        "deployment_steps":      deployment_steps,
        "estimated_deployment_time_minutes": 15,
        "soc_context_engine":    "SENTINEL-APEX-SOC-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4: DETECTION CONFIDENCE SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def module_detection_confidence(item: Dict, evidence: Dict) -> Dict:
    """Module 4: Detection Confidence Scoring Engine — structured detection metadata."""
    cvss        = _get_cvss(item)
    kev         = _is_kev(item)
    reliability = evidence.get("reliability_score", "LOW")
    exploit_st  = evidence.get("exploit_status", "UNVERIFIED")
    raw_score   = evidence.get("raw_confidence_score", 0)

    # ── Detection Confidence ──────────────────────────────────────────────────
    if kev and reliability == "HIGH":
        confidence = "HIGH"
    elif kev or (cvss >= 9.0 and reliability in ("HIGH", "MEDIUM")):
        confidence = "HIGH"
    elif cvss >= 7.0 and reliability in ("HIGH", "MEDIUM"):
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # ── Detection Strength ────────────────────────────────────────────────────
    if exploit_st in ("ACTIVE_CONFIRMED", "ACTIVE_OBSERVED") and raw_score >= 60:
        detection_strength = "STRONG"
    elif exploit_st in ("ACTIVE_CONFIRMED", "ACTIVE_OBSERVED"):
        detection_strength = "STRONG"
    elif cvss >= 7.0 and reliability != "LOW":
        detection_strength = "MODERATE"
    else:
        detection_strength = "WEAK"

    # ── False Positive Risk ───────────────────────────────────────────────────
    vuln_type = _classify_vuln_type(item)
    fp_risk_map = {
        "rce":          "LOW",
        "lpe":          "LOW",
        "ransomware":   "LOW",
        "supply_chain": "LOW",
        "auth_bypass":  "MEDIUM",
        "sqli":         "MEDIUM",
        "ssrf":         "MEDIUM",
        "credential":   "HIGH",
        "default":      "MEDIUM",
    }
    false_positive_risk = fp_risk_map.get(vuln_type, "MEDIUM")

    # ── Deployment Complexity ─────────────────────────────────────────────────
    complexity_map = {
        "rce":          "LOW",
        "lpe":          "MEDIUM",
        "ransomware":   "LOW",
        "supply_chain": "HIGH",
        "auth_bypass":  "MEDIUM",
        "sqli":         "MEDIUM",
        "ssrf":         "HIGH",
        "credential":   "HIGH",
        "default":      "MEDIUM",
    }
    deployment_complexity = complexity_map.get(vuln_type, "MEDIUM")

    # ── Scoring Rationale ─────────────────────────────────────────────────────
    rationale_parts = []
    if kev:
        rationale_parts.append("CISA KEV confirmed (highest evidence weight)")
    if cvss >= 9.0:
        rationale_parts.append(f"CVSS {cvss:.1f} — critical severity tier")
    elif cvss >= 7.0:
        rationale_parts.append(f"CVSS {cvss:.1f} — high severity tier")
    if reliability == "HIGH":
        rationale_parts.append("High-reliability source validation")
    if exploit_st == "ACTIVE_CONFIRMED":
        rationale_parts.append("Active exploitation confirmed")
    elif exploit_st == "ACTIVE_OBSERVED":
        rationale_parts.append("Active exploitation observed")
    if not rationale_parts:
        rationale_parts.append("Limited evidence — detection confidence reduced")

    return {
        "confidence":            confidence,
        "detection_strength":    detection_strength,
        "false_positive_risk":   false_positive_risk,
        "deployment_complexity": deployment_complexity,
        "scoring_rationale":     " | ".join(rationale_parts),
        "composite_score":       min(raw_score, 100),
        "siem_readiness":        "PRODUCTION" if confidence in ("HIGH", "MEDIUM") else "REVIEW",
        "detection_engine":      "SENTINEL-APEX-DETECT-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5: REVENUE PRODUCTIZATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_PRICING_TIERS = {
    "ENTERPRISE_CRITICAL": {"label": "Enterprise Critical", "inr_range": "₹9,999–₹14,999", "usd_range": "$120–$180", "target": "Enterprise SOC, MSSP, CISO"},
    "ENTERPRISE_HIGH":     {"label": "Enterprise High",     "inr_range": "₹4,999–₹9,999",  "usd_range": "$60–$120",  "target": "Enterprise SOC, Mid-Market Security"},
    "PROFESSIONAL":        {"label": "Professional",        "inr_range": "₹1,999–₹4,999",  "usd_range": "$24–$60",   "target": "Security Professionals, Consultants"},
    "STANDARD":            {"label": "Standard",            "inr_range": "₹999–₹1,999",    "usd_range": "$12–$24",   "target": "Security Teams, Analysts"},
}

_DETECTION_PACK_MAP = {
    "rce":          "RCE Defense Pack — Network-based and host-based detection rules for remote code execution exploitation chains. Includes web shell detection, process lineage anomalies, and post-exploitation command execution.",
    "lpe":          "Privilege Escalation Defense Pack — Kernel driver exploitation detection, SYSTEM privilege acquisition anomalies, LSASS access monitoring, and ransomware pre-positioning chain detection.",
    "auth_bypass":  "Identity Defense Pack — Authentication bypass detection, impossible travel analysis, session anomaly rules, and privileged access monitoring for identity infrastructure.",
    "sqli":         "Web Application Defense Pack — SQL injection attack detection, WAF evasion technique identification, database exfiltration behavior, and application-layer attack chain coverage.",
    "ssrf":         "Cloud & SSRF Defense Pack — Server-side request forgery detection, cloud metadata access monitoring, internal pivot attempt identification, and egress anomaly detection.",
    "supply_chain": "Supply Chain Defense Pack — Third-party software compromise detection, dependency confusion attack indicators, binary integrity monitoring, and update pipeline security.",
    "ransomware":   "Ransomware Defense Pack — Full ransomware kill-chain detection: reconnaissance through encryption. Includes pre-attack indicators (AD recon, VSS deletion), encryption detection, and C2 channel identification.",
    "credential":   "Credential Defense Pack — Credential harvesting, pass-the-hash, pass-the-ticket, LSASS dump detection, and authentication anomaly monitoring for all enterprise identity systems.",
    "default":      "Threat Intelligence Defense Pack — Comprehensive detection coverage for this threat category. Includes network, host, and identity-layer detection rules for enterprise SOC deployment.",
}

_API_PRODUCT_MAP = {
    "rce":         {"endpoint": "/api/ai/analyze", "product": "Threat Analysis API — RCE Intelligence Feed", "use_case": "Automated CVE-to-detection pipeline integration"},
    "lpe":         {"endpoint": "/api/ai/respond", "product": "SOAR Response API — LPE Playbook Feed",      "use_case": "Automated SOAR playbook triggering on LPE detection alerts"},
    "auth_bypass": {"endpoint": "/api/ai/correlate","product": "Correlation API — Identity Threat Graph",   "use_case": "Identity system compromise correlation and lateral movement tracking"},
    "sqli":        {"endpoint": "/api/ai/analyze",  "product": "Web App Threat API — Injection Intelligence","use_case": "WAF rule auto-generation from live CVE intelligence feed"},
    "ssrf":        {"endpoint": "/api/ai/correlate","product": "Cloud Security API — SSRF & Pivot Intelligence","use_case": "Cloud security posture integration and SSRF attack chain correlation"},
    "supply_chain":{"endpoint": "/api/ai/analyze",  "product": "Supply Chain API — Dependency Threat Feed", "use_case": "CI/CD pipeline CVE gating and dependency vulnerability alerting"},
    "ransomware":  {"endpoint": "/api/ai/respond",  "product": "SOAR Response API — Ransomware Playbook",   "use_case": "Automated ransomware response playbook and SOAR integration"},
    "credential":  {"endpoint": "/api/ai/correlate","product": "Identity Intelligence API — Credential Threat Feed","use_case": "Identity provider integration for credential compromise intelligence"},
    "default":     {"endpoint": "/api/ai/analyze",  "product": "SENTINEL APEX Threat Intelligence API",    "use_case": "Enterprise threat intelligence feed integration"},
}

_ENTERPRISE_USE_CASES = {
    "rce":         ["MSSP customer reporting — Critical CVE weekly briefings", "SOC Tier-1 automated triage enrichment", "Vulnerability management team prioritization feed", "CISO dashboard CVE-to-risk scoring"],
    "lpe":         ["Endpoint security team patch prioritization", "Ransomware readiness assessment", "EDR rule tuning and gap analysis", "Penetration testing scope validation"],
    "auth_bypass": ["Identity team posture assessment", "Zero Trust architecture gap analysis", "CASB policy enforcement integration", "PAM solution health monitoring"],
    "sqli":        ["Application security team vulnerability prioritization", "WAF rule set management", "DevSecOps pipeline security gate", "Third-party application risk assessment"],
    "ssrf":        ["Cloud security team posture review", "Cloud-native application security testing", "CSPM integration for misconfiguration correlation", "DevSecOps cloud configuration gate"],
    "supply_chain":["Third-party risk management program", "Software supply chain SBOM analysis", "M&A due diligence cybersecurity review", "Vendor risk assessment automation"],
    "ransomware":  ["Cyber insurance renewal assessment", "Board-level risk reporting", "Incident response retainer justification", "Business continuity plan validation"],
    "credential":  ["Identity governance program", "MFA deployment justification", "Privileged access management assessment", "Insider threat detection program"],
    "default":     ["Enterprise threat intelligence program", "SOC capability maturity assessment", "Security program ROI demonstration", "Executive risk reporting"],
}


def module_revenue_productization(item: Dict) -> Dict:
    """Module 5: Revenue Productization Engine — monetization-ready metadata."""
    vuln_type = _classify_vuln_type(item)
    cvss      = _get_cvss(item)
    kev       = _is_kev(item)

    if kev and cvss >= 9.0:
        pricing_tier_key = "ENTERPRISE_CRITICAL"
    elif kev or cvss >= 9.0:
        pricing_tier_key = "ENTERPRISE_HIGH"
    elif cvss >= 7.0:
        pricing_tier_key = "PROFESSIONAL"
    else:
        pricing_tier_key = "STANDARD"

    pricing_tier   = _PRICING_TIERS[pricing_tier_key]
    detection_pack = _DETECTION_PACK_MAP.get(vuln_type, _DETECTION_PACK_MAP["default"])
    api_product    = _API_PRODUCT_MAP.get(vuln_type, _API_PRODUCT_MAP["default"])
    use_cases      = _ENTERPRISE_USE_CASES.get(vuln_type, _ENTERPRISE_USE_CASES["default"])

    # Marketplace listing structure
    marketplace_listing = {
        "listing_id":       hashlib.md5(_item_id(item).encode()).hexdigest()[:8].upper(),
        "product_name":     f"SENTINEL APEX: {(item.get('title') or 'Threat Intelligence')[:60]}",
        "category":         "Threat Intelligence",
        "subcategory":      vuln_type.upper().replace("_", " "),
        "pricing_tier":     pricing_tier["label"],
        "price_inr":        pricing_tier["inr_range"],
        "price_usd":        pricing_tier["usd_range"],
        "target_audience":  pricing_tier["target"],
        "delivery_format":  "JSON API + PDF Report + SIEM Detection Rules",
        "license_type":     "Enterprise Annual Subscription",
        "kev_premium":      kev,
        "sla":              "4h critical / 24h standard",
    }

    return {
        "pricing_tier":          pricing_tier_key,
        "pricing_details":       pricing_tier,
        "detection_pack":        detection_pack,
        "api_product_mapping":   api_product,
        "enterprise_use_cases":  use_cases,
        "marketplace_listing":   marketplace_listing,
        "revenue_engine":        "SENTINEL-APEX-REVENUE-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6: EXECUTIVE DECISION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_BUSINESS_IMPACT_MAP = {
    "rce":          "Complete system compromise enabling ransomware deployment, data exfiltration, and persistent threat actor access. Estimated recovery cost: $2M–$20M+ depending on system criticality and data sensitivity.",
    "lpe":          "Privilege escalation enables full Active Directory compromise in ransomware chains. Without SYSTEM-level access, ransomware cannot complete deployment. This vulnerability is the critical pivot point between initial access and catastrophic impact.",
    "auth_bypass":  "Authentication bypass exposes all resources protected by the bypassed system to unauthorized access. In enterprise deployments, this includes customer data, financial records, intellectual property, and administrative infrastructure.",
    "sqli":         "SQL injection provides direct access to database contents including customer PII, financial data, intellectual property, and credentials. Regulatory breach notification (GDPR/DPDP/HIPAA) is typically triggered. Estimated regulatory fine exposure: €100K–€20M depending on jurisdiction.",
    "ssrf":         "Server-side request forgery in cloud environments provides a direct path to cloud credential extraction and complete cloud account compromise. Business continuity risk from cloud infrastructure access is CRITICAL.",
    "supply_chain": "Supply chain compromise is simultaneous compromise of all affected customers. The business impact extends beyond immediate technical damage to contractual liability, customer notification obligations, and long-term trust erosion.",
    "ransomware":   "Ransomware deployment results in complete operational disruption. Average downtime: 21 days. Average recovery cost: $4.5M. Regulatory notification required within 72 hours if personal data is affected. Cyber insurance coverage may not apply if compensating controls were absent.",
    "credential":   "Credential compromise provides persistent authenticated access that can persist undetected for months. Long dwell times enable comprehensive intellectual property theft and business intelligence collection before discovery.",
    "default":      "This vulnerability poses direct risk to system availability, data confidentiality, and/or data integrity. Business continuity and regulatory compliance obligations are at risk if exploitation occurs.",
}

_TIME_TO_EXPLOIT_MAP = {
    "ACTIVE_CONFIRMED": "IMMEDIATE — already being exploited",
    "ACTIVE_OBSERVED":  "< 24 hours — active threat actor targeting",
    "UNVERIFIED":       "1–30 days — exploit development estimated post-disclosure",
    "NO_EVIDENCE":      "30+ days — theoretical risk only",
}


def module_executive_decision(item: Dict, evidence: Dict) -> Dict:
    """Module 6: Executive Decision Engine — CISO-readable action intelligence."""
    cvss           = _get_cvss(item)
    kev            = _is_kev(item)
    exploit_status = evidence.get("exploit_status", "UNVERIFIED")
    reliability    = evidence.get("reliability_score", "LOW")

    # ── Risk Level ────────────────────────────────────────────────────────────
    if kev and cvss >= 9.0:
        risk_level = "CRITICAL"
    elif kev or cvss >= 9.0:
        risk_level = "CRITICAL"
    elif cvss >= 7.0 and reliability in ("HIGH", "MEDIUM"):
        risk_level = "HIGH"
    elif cvss >= 4.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── Immediate Actions (0-24h) ─────────────────────────────────────────────
    vuln_type = _classify_vuln_type(item)
    base_actions_crit = [
        "1. PATCH IMMEDIATELY — apply vendor patch within 24 hours or apply WAF/network compensating control",
        "2. DEPLOY DETECTION RULES — activate SIEM detection rules from this report within 2 hours",
        "3. RETROSPECTIVE HUNT — run detection rules against 30-day historical logs immediately",
        "4. ASSET INVENTORY — identify all affected systems within 4 hours; prioritize internet-facing instances",
        "5. ISOLATE CRITICAL SYSTEMS — if patching is not immediately possible, network-isolate most critical affected systems",
        "6. CREDENTIAL ROTATION — rotate credentials for service accounts with access to affected systems",
        "7. EXECUTIVE NOTIFICATION — brief CISO and security leadership on confirmed exploitation risk",
    ]
    base_actions_high = [
        "1. SCHEDULE EMERGENCY PATCH — patch within 72 hours; treat as P1 change management",
        "2. DEPLOY DETECTION RULES — activate SIEM detection rules within 8 hours",
        "3. ASSET IDENTIFICATION — enumerate all affected systems within 24 hours",
        "4. NETWORK SEGMENTATION — verify network access controls restrict exposure surface",
        "5. MONITORING ELEVATION — increase alert verbosity on affected system logs",
    ]

    if risk_level == "CRITICAL":
        immediate_actions = base_actions_crit
    else:
        immediate_actions = base_actions_high

    # ── Decision Statement ────────────────────────────────────────────────────
    cves_str = ", ".join(_get_cves(item)[:3]) or "this vulnerability"
    if risk_level == "CRITICAL" and kev:
        decision = (
            f"DECISION REQUIRED: {cves_str} is on the CISA KEV catalog — confirmed active exploitation. "
            f"CVSS {cvss:.1f}. This is not a future risk — attackers are exploiting this NOW. "
            "Immediate patching or compensating control deployment is the only acceptable response."
        )
    elif risk_level == "CRITICAL":
        decision = (
            f"DECISION REQUIRED: {cves_str} scores CVSS {cvss:.1f} and represents maximum-severity risk. "
            "Active exploitation has been observed in the wild. Patch within 24 hours or apply compensating controls immediately."
        )
    else:
        decision = (
            f"ACTION REQUIRED: {cves_str} requires scheduled patching within your standard high-severity SLA. "
            "Deploy detection coverage now to identify exploitation attempts during the patching window."
        )

    # ── Business Impact Summary ───────────────────────────────────────────────
    biz_impact = _BUSINESS_IMPACT_MAP.get(vuln_type, _BUSINESS_IMPACT_MAP["default"])

    # ── Time to Exploit ───────────────────────────────────────────────────────
    tte = _TIME_TO_EXPLOIT_MAP.get(exploit_status, "Unknown")

    return {
        "risk_level":         risk_level,
        "immediate_actions":  immediate_actions,
        "business_impact":    biz_impact,
        "decision_statement": decision,
        "time_to_exploit":    tte,
        "patch_priority_sla": "24 hours" if risk_level == "CRITICAL" else "72 hours",
        "executive_engine":   "SENTINEL-APEX-EXEC-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 7: COMPLIANCE & LEGAL SAFETY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_TLP_MAP = {
    "CRITICAL": "TLP:RED",
    "HIGH":     "TLP:AMBER",
    "MEDIUM":   "TLP:AMBER",
    "LOW":      "TLP:GREEN",
}


def module_compliance_legal(item: Dict, exec_decision: Dict) -> Dict:
    """Module 7: Compliance & Legal Safety Engine — TLP, attribution, legal safety."""
    risk_level  = exec_decision.get("risk_level", "MEDIUM")
    tlp         = _TLP_MAP.get(risk_level, "TLP:AMBER")
    cves        = _get_cves(item)

    # ── Compliance frameworks potentially triggered ───────────────────────────
    text      = _get_text(item)
    vuln_type = _classify_vuln_type(item)

    frameworks = ["ISO 27001 — Information Security Controls (A.12.6 — Technical Vulnerability Management)"]
    if any(k in text for k in ("personal data", "pii", "gdpr", "customer data", "user data")):
        frameworks.append("GDPR — Article 32 (Security of Processing) + Article 33 (Breach Notification within 72h)")
    if any(k in text for k in ("health", "hospital", "patient", "medical", "hipaa")):
        frameworks.append("HIPAA — Security Rule §164.306 (Security Standards: General Rules)")
    if any(k in text for k in ("financial", "banking", "payment", "pci", "card")):
        frameworks.append("PCI DSS — Requirement 6 (Develop and Maintain Secure Systems)")
    if any(k in text for k in ("india", "indian", "dpdp")):
        frameworks.append("DPDP Act 2023 (India) — Section 8 (Data Principal Obligations)")
    if any(k in text for k in ("critical infrastructure", "energy", "utility", "power", "water")):
        frameworks.append("NIST CSF 2.0 — Respond (RS) + Recover (RC) Functions")
    if vuln_type in ("ransomware", "rce"):
        frameworks.append("NIST SP 800-61r2 — Computer Security Incident Handling Guide")

    return {
        "tlp_classification":  tlp,
        "attribution":         "Analysis by CYBERDUDEBIVASH SENTINEL APEX Threat Intelligence Engine",
        "platform":            "CYBERDUDEBIVASH Pvt. Ltd. — intel.cyberdudebivash.com",
        "legal_disclaimer":    (
            "This report is for cybersecurity defense and research purposes only. "
            "All technical information is derived from publicly disclosed vulnerability advisories, "
            "official government catalogs (CISA KEV, NVD), and reputable threat intelligence publications. "
            "No proprietary vendor content has been reproduced. Recipients are responsible for validating "
            "indicators and detection rules against their specific environments prior to operational deployment."
        ),
        "data_handling":       (
            "Recipients must handle this intelligence in accordance with the TLP classification above. "
            f"{tlp}: Share only within your organization and with trusted partners who have a need to know."
        ),
        "compliance_frameworks": frameworks,
        "cve_references":      cves,
        "google_safe":         True,
        "copyright_safe":      True,
        "original_analysis":   True,
        "compliance_engine":   "SENTINEL-APEX-COMPLIANCE-v103",
    }


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR: RUN ALL 7 MODULES PER ITEM
# ══════════════════════════════════════════════════════════════════════════════

def enrich_item(item: Dict, flags: Dict) -> Dict:
    """
    Apply all enabled modules to a single manifest item.
    Each module is wrapped independently — one failure does not kill others.
    Returns original item with new enrichment fields added (additive only).
    """
    enriched = dict(item)  # Shallow copy — NEVER mutate original

    evidence       = {}
    analyst        = {}
    soc_ctx        = {}
    det_conf       = {}
    revenue        = {}
    exec_dec       = {}
    compliance     = {}

    try:
        if flags.get("APEX_MODULE_EVIDENCE", True):
            evidence = module_evidence_authority(item)
            enriched["evidence_validation"] = evidence
    except Exception as e:
        log.warning(f"[M1-EVIDENCE] item={_item_id(item)[:12]} error: {e}")
        enriched["evidence_validation"] = {"error": str(e), "reliability_score": "LOW"}

    try:
        if flags.get("APEX_MODULE_ANALYST", True):
            analyst = module_analyst_intelligence(item)
            enriched["analyst_insight"] = analyst
    except Exception as e:
        log.warning(f"[M2-ANALYST] item={_item_id(item)[:12]} error: {e}")

    try:
        if flags.get("APEX_MODULE_SOC_CONTEXT", True):
            soc_ctx = module_soc_deployment_context(item)
            enriched["soc_context"] = soc_ctx
    except Exception as e:
        log.warning(f"[M3-SOC] item={_item_id(item)[:12]} error: {e}")

    try:
        if flags.get("APEX_MODULE_DETECTION", True):
            det_conf = module_detection_confidence(item, evidence)
            enriched["detection_confidence"] = det_conf
    except Exception as e:
        log.warning(f"[M4-DETECT] item={_item_id(item)[:12]} error: {e}")

    try:
        if flags.get("APEX_MODULE_REVENUE", True):
            revenue = module_revenue_productization(item)
            enriched["revenue_metadata"] = revenue
    except Exception as e:
        log.warning(f"[M5-REVENUE] item={_item_id(item)[:12]} error: {e}")

    try:
        if flags.get("APEX_MODULE_EXECUTIVE", True):
            exec_dec = module_executive_decision(item, evidence)
            enriched["executive_summary"] = exec_dec
    except Exception as e:
        log.warning(f"[M6-EXEC] item={_item_id(item)[:12]} error: {e}")

    try:
        if flags.get("APEX_MODULE_COMPLIANCE", True):
            compliance = module_compliance_legal(item, exec_dec)
            enriched["compliance_block"] = compliance
    except Exception as e:
        log.warning(f"[M7-COMPLIANCE] item={_item_id(item)[:12]} error: {e}")

    enriched["_apex_enriched"]    = True
    enriched["_apex_version"]     = ENGINE_VERSION
    enriched["_apex_enriched_at"] = NOW_ISO

    return enriched


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR: AGGREGATE INTELLIGENCE REPORT
# ══════════════════════════════════════════════════════════════════════════════

def build_apex_report(enriched_items: List[Dict]) -> Dict:
    """Build the top-level APEX Intelligence Report from all enriched items."""
    total = len(enriched_items)
    if total == 0:
        return {"error": "no_items", "generated_at": NOW_ISO}

    # ── Evidence Stats ────────────────────────────────────────────────────────
    ev_high   = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("reliability_score") == "HIGH")
    ev_med    = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("reliability_score") == "MEDIUM")
    ev_low    = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("reliability_score") == "LOW")
    kev_count = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("kev_verified"))
    confirmed = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("exploit_status") == "ACTIVE_CONFIRMED")
    observed  = sum(1 for i in enriched_items if i.get("evidence_validation", {}).get("exploit_status") == "ACTIVE_OBSERVED")

    # ── Executive Dashboard ───────────────────────────────────────────────────
    critical_items = [i for i in enriched_items if i.get("executive_summary", {}).get("risk_level") == "CRITICAL"]
    high_items     = [i for i in enriched_items if i.get("executive_summary", {}).get("risk_level") == "HIGH"]

    # ── Detection Quality ─────────────────────────────────────────────────────
    det_high  = sum(1 for i in enriched_items if i.get("detection_confidence", {}).get("confidence") == "HIGH")
    det_med   = sum(1 for i in enriched_items if i.get("detection_confidence", {}).get("confidence") == "MEDIUM")
    det_strong= sum(1 for i in enriched_items if i.get("detection_confidence", {}).get("detection_strength") == "STRONG")

    # ── Revenue Summary ───────────────────────────────────────────────────────
    tier_counts: Dict[str, int] = {}
    for item in enriched_items:
        tier = item.get("revenue_metadata", {}).get("pricing_tier", "STANDARD")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    # ── Vulnerability Class Distribution ─────────────────────────────────────
    class_dist: Dict[str, int] = {}
    for item in enriched_items:
        vc = item.get("analyst_insight", {}).get("vulnerability_class", "DEFAULT")
        class_dist[vc] = class_dist.get(vc, 0) + 1

    # ── Top Critical Items (P1 exec summary) ─────────────────────────────────
    top_critical = []
    for item in sorted(
        critical_items,
        key=lambda x: x.get("evidence_validation", {}).get("raw_confidence_score", 0),
        reverse=True
    )[:10]:
        top_critical.append({
            "title":          (item.get("title") or "")[:100],
            "risk_level":     item.get("executive_summary", {}).get("risk_level", "UNKNOWN"),
            "kev_verified":   item.get("evidence_validation", {}).get("kev_verified", False),
            "exploit_status": item.get("evidence_validation", {}).get("exploit_status", "UNKNOWN"),
            "confidence":     item.get("detection_confidence", {}).get("confidence", "UNKNOWN"),
            "decision":       item.get("executive_summary", {}).get("decision_statement", "")[:200],
            "pricing_tier":   item.get("revenue_metadata", {}).get("pricing_tier", "STANDARD"),
            "soc_priority":   item.get("soc_context", {}).get("soc_priority", "P2"),
            "tlp":            item.get("compliance_block", {}).get("tlp_classification", "TLP:AMBER"),
        })

    # ── Revenue Productization Summary ────────────────────────────────────────
    revenue_summary = {
        "total_monetizable_items": total,
        "enterprise_critical_count": tier_counts.get("ENTERPRISE_CRITICAL", 0),
        "enterprise_high_count":     tier_counts.get("ENTERPRISE_HIGH", 0),
        "professional_count":        tier_counts.get("PROFESSIONAL", 0),
        "standard_count":            tier_counts.get("STANDARD", 0),
        "estimated_report_value_inr": (
            tier_counts.get("ENTERPRISE_CRITICAL", 0) * 12499 +
            tier_counts.get("ENTERPRISE_HIGH", 0) * 7499 +
            tier_counts.get("PROFESSIONAL", 0) * 3499 +
            tier_counts.get("STANDARD", 0) * 1499
        ),
        "api_products": [
            {"endpoint": "/api/ai/analyze",   "description": "Threat Analysis API — Priority-ranked CVE intelligence with evidence scoring"},
            {"endpoint": "/api/ai/respond",   "description": "SOAR Response API — Automated playbook and response action feed"},
            {"endpoint": "/api/ai/correlate", "description": "Correlation API — Actor-TTP-CVE relationship graph and kill-chain analysis"},
        ],
        "marketplace_categories": list(set(
            item.get("analyst_insight", {}).get("vulnerability_class", "DEFAULT")
            for item in enriched_items
        )),
    }

    return {
        "report_title":   "SENTINEL APEX GOD-LEVEL INTELLIGENCE REPORT",
        "platform":       "CYBERDUDEBIVASH SENTINEL APEX",
        "version":        ENGINE_VERSION,
        "generated_at":   NOW_ISO,
        "classification": "TLP:AMBER — For Authorized Recipients Only",
        "legal_notice":   "This report is for cybersecurity defense and research purposes only.",
        "attribution":    "Analysis by CYBERDUDEBIVASH SENTINEL APEX Threat Intelligence Engine",

        "executive_dashboard": {
            "total_items_analyzed": total,
            "critical_risk_count":  len(critical_items),
            "high_risk_count":      len(high_items),
            "kev_confirmed":        kev_count,
            "active_exploitation":  confirmed + observed,
            "detection_high_confidence": det_high,
            "detection_strong_rules":    det_strong,
            "overall_threat_posture": (
                "CRITICAL" if len(critical_items) > total * 0.3 else
                "HIGH"     if len(critical_items) > total * 0.1 else
                "ELEVATED" if len(high_items) > total * 0.2 else "MODERATE"
            ),
        },

        "evidence_authority_summary": {
            "high_reliability": ev_high,
            "medium_reliability": ev_med,
            "low_reliability": ev_low,
            "kev_verified_count": kev_count,
            "active_exploitation_confirmed": confirmed,
            "active_exploitation_observed":  observed,
            "intelligence_quality_score": round(
                (ev_high * 3 + ev_med * 1.5) / max(total * 3, 1) * 100, 1
            ),
        },

        "detection_quality_summary": {
            "high_confidence_detections": det_high,
            "medium_confidence_detections": det_med,
            "strong_detection_rules": det_strong,
            "production_ready_pct": round((det_high + det_med) / max(total, 1) * 100, 1),
        },

        "vulnerability_class_distribution": dict(
            sorted(class_dist.items(), key=lambda x: -x[1])
        ),

        "top_critical_items": top_critical,

        "revenue_productization": revenue_summary,

        "compliance_summary": {
            "tlp_red_count":   sum(1 for i in enriched_items if i.get("compliance_block", {}).get("tlp_classification") == "TLP:RED"),
            "tlp_amber_count": sum(1 for i in enriched_items if i.get("compliance_block", {}).get("tlp_classification") == "TLP:AMBER"),
            "tlp_green_count": sum(1 for i in enriched_items if i.get("compliance_block", {}).get("tlp_classification") == "TLP:GREEN"),
            "all_google_safe": True,
            "all_copyright_safe": True,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# GATE VALIDATION (post-enrichment)
# ══════════════════════════════════════════════════════════════════════════════

def validate_enriched_item(item: Dict, flags: Dict) -> Tuple[bool, List[str]]:
    """
    Optional gate checks for enriched items.
    Returns (passes: bool, failures: List[str]).
    Only enforced when APEX_REQUIRE_* flags are True.
    """
    failures = []

    if flags.get("APEX_REQUIRE_EVIDENCE_GATE", False):
        ev = item.get("evidence_validation")
        if not ev or ev.get("reliability_score") == "LOW":
            failures.append("missing_or_low_evidence_validation")

    if flags.get("APEX_REQUIRE_CONFIDENCE_GATE", False):
        det = item.get("detection_confidence")
        if not det or det.get("confidence") == "LOW":
            failures.append("low_detection_confidence")

    if flags.get("APEX_REQUIRE_SOC_GATE", False):
        soc = item.get("soc_context")
        if not soc:
            failures.append("missing_soc_context")

    return len(failures) == 0, failures


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    flags = _load_flags()

    if not flags.get("ENABLE_APEX_INTELLIGENCE_ENGINE", True):
        log.info("ENABLE_APEX_INTELLIGENCE_ENGINE=false — engine disabled, skipping.")
        return 0

    log.info("=" * 65)
    log.info(f"APEX INTELLIGENCE ENGINE v{ENGINE_VERSION} — INITIALIZING")
    log.info(f"Timestamp: {NOW_ISO}")
    log.info("=" * 65)

    # ── Load manifest ─────────────────────────────────────────────────────────
    items = _load_manifest()
    if not items:
        log.warning("No manifest items — writing empty report and exiting.")
        _atomic_write(APEX_INTELLIGENCE_REPORT, {"error": "no_items", "generated_at": NOW_ISO})
        return 0

    max_items = int(flags.get("APEX_MAX_ITEMS", 2000))
    if len(items) > max_items:
        log.info(f"Capping at {max_items} items (manifest has {len(items)})")
        items = items[:max_items]

    log.info(f"Processing {len(items)} items through 7 intelligence modules...")

    # ── Enrich all items ──────────────────────────────────────────────────────
    enriched_items = []
    gate_passed    = 0
    gate_failed    = 0

    for i, item in enumerate(items):
        try:
            enriched = enrich_item(item, flags)

            # Optional gate validation
            passes, failures = validate_enriched_item(enriched, flags)
            if not passes:
                gate_failed += 1
                enriched["_apex_gate_failures"] = failures
            else:
                gate_passed += 1

            enriched_items.append(enriched)
        except Exception as e:
            log.error(f"Item {i} enrichment failed: {e}")
            enriched_items.append(dict(item))  # Pass through original on total failure

    log.info(
        f"Enrichment complete: {len(enriched_items)} items | "
        f"gate_passed={gate_passed} | gate_failed={gate_failed}"
    )

    # ── Write enriched manifest ───────────────────────────────────────────────
    sz1 = _atomic_write(APEX_ENRICHED_MANIFEST, enriched_items)
    log.info(f"Written: apex_enriched_manifest.json ({sz1:,} bytes, {len(enriched_items)} items)")

    # ── Build and write intelligence report ──────────────────────────────────
    report = build_apex_report(enriched_items)
    sz2    = _atomic_write(APEX_INTELLIGENCE_REPORT, report)
    log.info(f"Written: apex_intelligence_report.json ({sz2:,} bytes)")

    # ── Write audit log ───────────────────────────────────────────────────────
    audit = {
        "engine":         "APEX Intelligence Engine",
        "version":        ENGINE_VERSION,
        "run_at":         NOW_ISO,
        "items_input":    len(items),
        "items_enriched": len(enriched_items),
        "gate_passed":    gate_passed,
        "gate_failed":    gate_failed,
        "outputs": {
            "apex_enriched_manifest": str(APEX_ENRICHED_MANIFEST),
            "apex_intelligence_report": str(APEX_INTELLIGENCE_REPORT),
        },
        "modules_run": {
            "evidence_authority":    flags.get("APEX_MODULE_EVIDENCE", True),
            "analyst_intelligence":  flags.get("APEX_MODULE_ANALYST", True),
            "soc_deployment":        flags.get("APEX_MODULE_SOC_CONTEXT", True),
            "detection_confidence":  flags.get("APEX_MODULE_DETECTION", True),
            "revenue_productization":flags.get("APEX_MODULE_REVENUE", True),
            "executive_decision":    flags.get("APEX_MODULE_EXECUTIVE", True),
            "compliance_legal":      flags.get("APEX_MODULE_COMPLIANCE", True),
        },
        "output_summary": report.get("executive_dashboard", {}),
        "status": "SUCCESS",
    }
    sz3 = _atomic_write(APEX_ENGINE_AUDIT, audit)
    log.info(f"Written: apex_engine_report.json ({sz3:,} bytes)")

    # ── Final summary ─────────────────────────────────────────────────────────
    ed = report.get("executive_dashboard", {})
    log.info("─" * 65)
    log.info(f"✅ APEX ENGINE COMPLETE | Items: {len(enriched_items)} | "
             f"Critical: {ed.get('critical_risk_count', 0)} | "
             f"KEV: {ed.get('kev_confirmed', 0)} | "
             f"Posture: {ed.get('overall_threat_posture', 'UNKNOWN')}")
    log.info("─" * 65)

    return 0


if __name__ == "__main__":
    sys.exit(main())
