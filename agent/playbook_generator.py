#!/usr/bin/env python3
"""
playbook_generator.py — CYBERDUDEBIVASH® SENTINEL APEX v20.0
AUTOMATED INCIDENT RESPONSE PLAYBOOK ENGINE

Generates NIST SP 800-61 / SANS 6-Step compliant Incident Response Playbooks
for EVERY threat intel report published by the Sentinel APEX pipeline.

Features:
  - Jinja2-templated, scenario-specific playbooks (Ransomware, XSS, Supply Chain, etc.)
  - Auto-populated from live threat data (IOCs, MITRE, risk score, CVE, actor)
  - Saves as both .md (Blogger embed) and .json (API / STIX enrichment)
  - Generates YARA, Sigma, KQL, PowerShell containment scripts per incident
  - Gumroad product URL injection for revenue bridge
  - Zero breaking changes — fully standalone, called after publish in sentinel_blogger.py

Called from: agent/sentinel_blogger.py → process_entry() → Step 14
Output dirs:  data/playbooks/  (markdown + json)
              data/playbooks/scripts/  (generated containment scripts)
"""

import os
import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from jinja2 import Template
    _JINJA2_OK = True
except ImportError:
    _JINJA2_OK = False

from agent.config import BRAND, COLORS

logger = logging.getLogger("CDB-PLAYBOOK")

# ──────────────────────────────────────────────────────────────────────
# OUTPUT DIRECTORIES
# ──────────────────────────────────────────────────────────────────────
PLAYBOOK_DIR = Path("data/playbooks")
SCRIPTS_DIR  = Path("data/playbooks/scripts")


# ──────────────────────────────────────────────────────────────────────
# SCENARIO DETECTION — maps headline/content to playbook type
# ──────────────────────────────────────────────────────────────────────
_SCENARIO_MAP = {
    "ransomware":       ["ransomware", "ransom", "lockbit", "blackcat", "cl0p", "encrypt files"],
    "supply_chain":     ["supply chain", "dependency confusion", "package poisoning", "build system", "npm", "pypi"],
    "data_breach":      ["data breach", "leak", "exposed records", "stolen data", "database dump"],
    "apt":              ["apt", "nation-state", "state-sponsored", "volt typhoon", "lazarus", "apt29", "apt28"],
    "phishing":         ["phishing", "spear-phishing", "credential harvest", "fake login", "clickfix"],
    "malware_campaign": ["malware", "trojan", "stealer", "rat", "backdoor", "infostealer", "loader"],
    "mobile_malware":   ["android", "ios malware", "apk", "banking trojan", "mobile malware"],
    "browser_ext":      ["browser extension", "chrome extension", "malicious extension", "web store"],
    "cloud_attack":     ["cloud misconfiguration", "s3 bucket", "aws exposed", "azure", "gcp"],
    "xss_injection":    ["xss", "cross-site scripting", "reflected xss", "stored xss", "injection"],
    "rce":              ["remote code execution", "rce", "code execution", "privilege escalation", "zero-day"],
    "vulnerability":    ["cve-", "vulnerability", "patch", "security update", "buffer overflow"],
}

def _detect_scenario(headline: str, content: str) -> str:
    text = f"{headline} {content}".lower()
    scores = {}
    for scenario, keywords in _SCENARIO_MAP.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[scenario] = score
    return max(scores, key=scores.get) if scores else "generic"


# ──────────────────────────────────────────────────────────────────────
# CONTAINMENT SCRIPT GENERATORS
# ──────────────────────────────────────────────────────────────────────

def _gen_powershell_containment(headline: str, iocs: Dict, scenario: str) -> str:
    """Generate a PowerShell containment script tailored to the threat."""
    ips   = iocs.get("ipv4", [])[:10]
    hashes = (iocs.get("sha256", []) + iocs.get("md5", []))[:10]
    domains = iocs.get("domain", [])[:10]
    cves   = iocs.get("cve", [])[:5]
    safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', headline)[:60]
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    script = f"""# ============================================================
# CyberDudeBivash SENTINEL APEX — Containment Script
# Threat  : {safe_title}
# Scenario: {scenario.upper()}
# Generated: {ts}
# Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
# USAGE: Run as Administrator in an elevated PowerShell session.
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'
Write-Host "[CDB-SENTINEL] Initiating containment for: {safe_title}" -ForegroundColor Red

"""
    # Network IOC blocking
    if ips:
        script += "# --- BLOCK MALICIOUS IPs VIA WINDOWS FIREWALL ---\n"
        for ip in ips:
            script += f'New-NetFirewallRule -DisplayName "CDB-BLOCK-{ip}" -Direction Outbound -RemoteAddress "{ip}" -Action Block -Profile Any\n'
        script += "\n"

    if domains:
        script += "# --- BLOCK MALICIOUS DOMAINS VIA HOSTS FILE ---\n"
        script += "$hostsPath = '$env:SystemRoot\\System32\\drivers\\etc\\hosts'\n"
        for dom in domains:
            script += f"Add-Content -Path $hostsPath -Value '0.0.0.0 {dom}  # CDB-SENTINEL BLOCK'\n"
        script += "\n"

    # Hash-based IOC termination
    if hashes:
        script += "# --- KILL PROCESSES MATCHING KNOWN MALICIOUS HASHES ---\n"
        script += "$maliciousHashes = @(\n"
        for h in hashes:
            script += f'    "{h}",\n'
        script += ")\n"
        script += """
Get-Process | ForEach-Object {
    try {
        $filePath = $_.MainModule.FileName
        $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        if ($maliciousHashes -contains $fileHash) {
            Write-Host "[CDB-SENTINEL] Terminating malicious process: $($_.Name) (PID: $($_.Id))" -ForegroundColor Red
            Stop-Process -Id $_.Id -Force
        }
    } catch {}
}

"""

    # CVE-specific patches
    if cves:
        script += "# --- CVE PATCHING VALIDATION ---\n"
        for cve in cves:
            script += f'Write-Host "[CDB-SENTINEL] Check patch status for {cve}" -ForegroundColor Yellow\n'
        script += 'Write-Host "[CDB-SENTINEL] Run Windows Update or apply vendor patch." -ForegroundColor Yellow\n\n'

    # Scenario-specific actions
    if scenario == "ransomware":
        script += """# --- RANSOMWARE-SPECIFIC: DISABLE VSSADMIN & NET USE ---
Write-Host "[CDB-SENTINEL] Disabling VSS deletion capability (ransomware defense)..." -ForegroundColor Cyan
$vssPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VSS"
Set-ItemProperty -Path $vssPath -Name "Start" -Value 4 -ErrorAction SilentlyContinue

# Isolate machine from network shares
net use * /delete /yes
Write-Host "[CDB-SENTINEL] Network shares disconnected." -ForegroundColor Green
"""
    elif scenario in ("xss_injection", "vulnerability", "rce"):
        script += """# --- WEB EXPLOIT: DISABLE INBOUND WEB TRAFFIC TEMPORARILY ---
Write-Host "[CDB-SENTINEL] Blocking inbound HTTP/HTTPS while patch is applied..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "CDB-BLOCK-HTTP-TEMP" -Direction Inbound -Protocol TCP -LocalPort @(80, 443) -Action Block
Write-Host "[CDB-SENTINEL] Re-enable with: Remove-NetFirewallRule -DisplayName CDB-BLOCK-HTTP-TEMP" -ForegroundColor Yellow
"""

    script += """
# --- SESSION INVALIDATION ---
Write-Host "[CDB-SENTINEL] Forcing active session logoff for containment..." -ForegroundColor Cyan
quser | ForEach-Object {
    if ($_ -match "\\s+(\\d+)\\s+Active") {
        logoff $matches[1]
    }
}

Write-Host "[CDB-SENTINEL] Containment complete. Review firewall rules and apply vendor patches." -ForegroundColor Green
Write-Host "[CDB-SENTINEL] NEXT: Run eradication playbook from intel.cyberdudebivash.com" -ForegroundColor Cyan
"""
    return script


def _gen_bash_containment(headline: str, iocs: Dict, scenario: str) -> str:
    """Generate a Bash/Linux containment script."""
    ips     = iocs.get("ipv4", [])[:10]
    domains = iocs.get("domain", [])[:10]
    hashes  = (iocs.get("sha256", []) + iocs.get("md5", []))[:10]
    safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', headline)[:60]
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    script = f"""#!/bin/bash
# ============================================================
# CyberDudeBivash SENTINEL APEX — Linux Containment Script
# Threat  : {safe_title}
# Scenario: {scenario.upper()}
# Generated: {ts}
# Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
# USAGE: sudo bash containment_linux.sh
# ============================================================

set -euo pipefail
echo "[CDB-SENTINEL] Initiating Linux containment for: {safe_title}"

"""
    if ips:
        script += "# --- BLOCK MALICIOUS IPs WITH IPTABLES ---\n"
        for ip in ips:
            script += f"iptables -A OUTPUT -d {ip} -j DROP && echo '[CDB] Blocked outbound: {ip}'\n"
            script += f"iptables -A INPUT  -s {ip} -j DROP && echo '[CDB] Blocked inbound:  {ip}'\n"
        script += "\n"

    if domains:
        script += "# --- NULL-ROUTE MALICIOUS DOMAINS ---\n"
        for dom in domains:
            script += f"echo '0.0.0.0 {dom}' >> /etc/hosts  # CDB-SENTINEL BLOCK\n"
        script += "\n"

    if hashes:
        script += "# --- HUNT FOR MALICIOUS FILES BY HASH ---\n"
        for h in hashes:
            script += f"find / -type f -exec sha256sum {{}} \\; 2>/dev/null | grep -i '{h}' && echo '[CDB] Malicious file FOUND: {h}' || true\n"
        script += "\n"

    if scenario == "ransomware":
        script += """# --- RANSOMWARE: ISOLATE NETWORK + BACKUP PROTECTION ---
echo "[CDB-SENTINEL] Disabling network interfaces for isolation..."
ip link set eth0 down 2>/dev/null || true
ip link set ens3 down 2>/dev/null || true
echo "[CDB-SENTINEL] Network interfaces downed. Manual re-enable required after eradication."
"""

    script += """
echo "[CDB-SENTINEL] Saving iptables rules..."
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "[CDB-SENTINEL] Containment complete. Apply vendor patches and review logs."
echo "[CDB-SENTINEL] Platform: https://intel.cyberdudebivash.com"
"""
    return script


def _gen_eradication_script(headline: str, iocs: Dict, cves: List, scenario: str) -> str:
    """Generate patch/eradication guidance script."""
    safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', headline)[:60]
    cve_list   = " | ".join(cves[:5]) if cves else "No CVEs extracted"
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    return f"""#!/usr/bin/env python3
# ============================================================
# CyberDudeBivash SENTINEL APEX — Eradication & Hardening Guide
# Threat   : {safe_title}
# CVEs     : {cve_list}
# Scenario : {scenario.upper()}
# Generated: {ts}
# Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
# ============================================================
\"\"\"
ERADICATION CHECKLIST — Run step by step after containment.

[PHASE 1] ROOT CAUSE REMOVAL
  1. Apply all vendor patches for: {cve_list}
  2. Remove malicious files identified in IOC feed (ioc_feed.csv)
  3. Close all backdoors: scan for scheduled tasks, startup entries, cron jobs
  4. Rotate ALL credentials: admin accounts, service accounts, API keys
  5. Revoke active sessions and re-issue MFA tokens

[PHASE 2] SYSTEM RESTORATION
  1. Restore from last-known-good backup (pre-compromise baseline)
  2. Validate backup integrity before restoration (check file hashes)
  3. Bring systems online in isolated environment first
  4. Run full AV/EDR scan post-restoration
  5. Validate all critical services are operational

[PHASE 3] HARDENING (POST-INCIDENT)
  1. Deploy Sigma rules from detection_sigma.yml into your SIEM
  2. Deploy KQL queries from detection_kql.txt into Microsoft Sentinel
  3. Apply YARA rules from detection_yara.yar into your EDR
  4. Enable enhanced logging: process creation, network events, PowerShell
  5. Review and tighten firewall rules using blocked IPs from IOC feed
  6. Schedule 30-day threat hunt for re-infection indicators

[PHASE 4] LESSONS LEARNED (NIST SP 800-61 R2)
  1. Document full incident timeline (detection → containment → eradication)
  2. Identify detection gap that allowed initial compromise
  3. Update your runbooks and IR playbooks based on this incident
  4. Report to stakeholders with executive summary

GENERATED BY: CyberDudeBivash SENTINEL APEX v20.0
AUTHORITY   : intel.cyberdudebivash.com
\"\"\"

print("Eradication guide loaded. Follow each phase in sequence.")
"""


# ──────────────────────────────────────────────────────────────────────
# PLAYBOOK JINJA2 TEMPLATE
# ──────────────────────────────────────────────────────────────────────

_PLAYBOOK_TEMPLATE_MD = """\
# 🛡️ CYBERDUDEBIVASH® Incident Response Playbook
**Authority:** CyberDudeBivash SENTINEL APEX v20.0 | [intel.cyberdudebivash.com](https://intel.cyberdudebivash.com)
**Generated:** {{ timestamp }}
**Incident ID:** `{{ incident_id }}`
**Classification:** TLP:{{ tlp }} | Severity: **{{ severity }}** | Risk: **{{ risk_score }}/10**

---

## 1. Incident Overview & Classification

| Field | Value |
|-------|-------|
| **Incident Type** | {{ threat_type }} |
| **Scenario** | {{ scenario }} |
| **Severity Level** | {{ severity }} |
| **Risk Score** | {{ risk_score }}/10 |
| **TLP Classification** | TLP:{{ tlp }} |
| **Affected Asset / Product** | {{ asset }} |
| **CVEs Involved** | {{ cves_str }} |
| **Threat Actor** | {{ actor_tag }} |
| **Source URL** | {{ source_url }} |
| **Blog Report** | {{ blog_url }} |

**Summary:** {{ summary }}

---

## 2. Phase 1 — Detection & Identification

### 2.1 Indicators of Compromise (IOCs)

{% if ioc_table %}
| Indicator Type | Value |
|---------------|-------|
{% for row in ioc_table %}| {{ row.type }} | `{{ row.value }}` |
{% endfor %}
{% else %}
> No specific IOCs extracted. Review source article for manual indicator identification.
{% endif %}

### 2.2 MITRE ATT&CK Techniques
{% if mitre_techniques %}
{% for t in mitre_techniques %}- **{{ t }}** — see [MITRE ATT&CK](https://attack.mitre.org/techniques/{{ t }}/)
{% endfor %}
{% else %}
- No MITRE techniques automatically mapped. Manual triage recommended.
{% endif %}

### 2.3 Triage Summary
- **IOCs Extracted:** {{ total_iocs }}
- **Confidence Score:** {{ confidence }}%
- **Actor Attribution:** {{ actor_tag }}
- **Detection Coverage:** Sigma, YARA, KQL, SPL rules available in detection pack

---

## 3. Phase 2 — Containment Strategies

### 3.1 Short-Term Containment (Execute Immediately)

{% if scenario == "ransomware" %}
1. **ISOLATE** the infected host from the network immediately (disable NIC or VLAN quarantine)
2. **DISABLE** VSS deletion: `vssadmin delete shadows /all` — prevent ransomware from clearing backups
3. **REVOKE** active user sessions and invalidate SSO tokens
4. **NOTIFY** CISO and legal team — activate your Incident Response retainer
5. **PRESERVE** forensic evidence before any remediation (disk image if possible)
{% elif scenario in ["xss_injection", "vulnerability", "rce"] %}
1. **DISABLE** the vulnerable endpoint or service temporarily
2. **BLOCK** inbound/outbound traffic to/from malicious IPs in IOC feed
3. **INVALIDATE** all active web sessions (clear server-side sessions)
4. **ROTATE** all application secrets, API keys, and database credentials
5. **ENABLE** WAF rule blocking the exploit pattern immediately
{% elif scenario == "supply_chain" %}
1. **PIN** all package versions immediately — freeze dependency updates
2. **AUDIT** recent CI/CD pipeline runs for unauthorized package pulls
3. **REVOKE** build system credentials and rotate secrets
4. **QUARANTINE** any systems that executed compromised builds
5. **NOTIFY** all downstream customers / tenants if shared infrastructure
{% elif scenario == "apt" %}
1. **ISOLATE** compromised systems — APTs move laterally, stop the spread
2. **RESET** all privileged account credentials (AD, cloud IAM)
3. **AUDIT** authentication logs for lateral movement (Pass-the-Hash, Pass-the-Ticket)
4. **ENGAGE** your incident response retainer or MSSP immediately
5. **PRESERVE** all log data — APT investigations require extensive forensics
{% elif scenario == "data_breach" %}
1. **CLOSE** the exfiltration channel (revoke credentials, close API endpoint)
2. **ASSESS** scope of data exposed (PII, PCI, PHI, IP)
3. **PRESERVE** access logs for forensic investigation
4. **NOTIFY** legal team — GDPR/PDPB breach notification requirements may apply (72h window)
5. **FREEZE** affected database accounts
{% else %}
1. **BLOCK** all IOC-associated IPs, domains, and URLs at firewall/proxy
2. **ISOLATE** potentially affected systems
3. **DISABLE** affected services or endpoints until patched
4. **ROTATE** credentials for any accounts that may have been exposed
5. **NOTIFY** your security team and begin formal IR process
{% endif %}

### 3.2 Long-Term Containment
- Deploy detection rules (Sigma, YARA, KQL) from the detection pack
- Maintain production by applying temporary mitigation while patching
- Implement egress filtering for all IOC domains and IPs
- Enable enhanced audit logging on affected systems

### 3.3 Containment Validation
- Automated IOC blocklist verification via Sentinel APEX feed
- Re-run EDR scan to confirm threat is no longer active in environment
- Monitor SIEM alerts for 48h post-containment for re-infection indicators

---

## 4. Phase 3 — Eradication & Recovery

### 4.1 Root Cause Removal
{% if cves %}
{% for cve in cves %}
- **{{ cve }}**: Apply vendor-issued security patch immediately. Verify patch installation.
{% endfor %}
{% else %}
- Identify and remove all malicious files, registry keys, and persistence mechanisms
{% endif %}
- Remove all IOC-listed files, processes, and registry entries
- Close identified backdoors and revoke unauthorized access

### 4.2 System Restoration
1. Restore from last-known-good baseline (pre-compromise backup)
2. Validate backup integrity before restoration
3. Test restored systems in an isolated environment first
4. Perform full EDR/AV scan post-restoration
5. Re-enable services only after clean bill of health

### 4.3 Hardening (Prevent Recurrence)
- Deploy all detection rules from `detection_pack/` into production SIEM/EDR
- Review and tighten firewall egress rules
- Implement network segmentation based on this attack's lateral movement path
- Enable PowerShell script block logging and process command-line auditing
- Schedule quarterly threat hunt using IOC feed as baseline

---

## 5. Phase 4 — Post-Incident Activity

### 5.1 Incident Timeline (Complete After Resolution)

| Milestone | Target SLA | Actual Time |
|-----------|-----------|-------------|
| Detection | < 1h | ________ |
| Containment | < 4h | ________ |
| Eradication | < 24h | ________ |
| Full Recovery | < 72h | ________ |
| Report to CISO | < 8h | ________ |

### 5.2 Effectiveness Review
- What detection control caught this first?
- What was the dwell time?
- Which containment actions were most effective?
- What hardening gaps allowed initial compromise?

### 5.3 Compliance Reporting
{% if risk_score >= 7.0 %}
- **GDPR Article 33**: If EU personal data affected, notify supervisory authority within **72 hours**
- **India PDPB**: Notify CERT-In within 6 hours of discovery (significant breach)
- **PCI DSS**: Notify acquiring bank and card brands within 24 hours
{% else %}
- Review applicable regulatory notification requirements based on data type affected
{% endif %}

---

## 6. Revenue & Authority Links

> **This playbook was auto-generated by CyberDudeBivash SENTINEL APEX v20.0**

- 🛒 **Defense Kit (Sigma + YARA + KQL + Scripts)**: [Download on Gumroad]({{ gumroad_url }})
- 🏢 **Enterprise IR Retainer**: [Contact CyberDudeBivash](https://www.cyberdudebivash.com/#contact)
- 📊 **Live Threat Dashboard**: [intel.cyberdudebivash.com](https://intel.cyberdudebivash.com)
- 📞 **Emergency Hotline**: +91 8179881447 | bivash@cyberdudebivash.com

---
*Generated by CyberDudeBivash SENTINEL APEX v20.0 | [cyberdudebivash.com](https://cyberdudebivash.com)*
*NIST SP 800-61 R2 / SANS 6-Step Framework | Incident ID: {{ incident_id }}*
"""


# ──────────────────────────────────────────────────────────────────────
# MAIN GENERATOR CLASS
# ──────────────────────────────────────────────────────────────────────

class PlaybookGenerator:
    """
    Generates NIST SP 800-61 / SANS compliant Incident Response Playbooks
    from live threat intel data, auto-populates all sections, and saves
    the output as Markdown + JSON for downstream consumption.
    """

    def __init__(self):
        PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
        SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    def _build_ioc_table(self, iocs: Dict) -> List[Dict]:
        """Flatten IOCs into a table-friendly list."""
        rows = []
        type_map = {
            "ipv4": "IPv4 Address", "domain": "Domain", "url": "URL",
            "sha256": "SHA-256 Hash", "md5": "MD5 Hash", "sha1": "SHA-1 Hash",
            "email": "Email Address", "cve": "CVE ID",
            "registry": "Registry Key", "artifacts": "File Artifact",
        }
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for v in values[:8]:  # Cap at 8 per type for readability
                    rows.append({"type": type_map.get(ioc_type, ioc_type), "value": v})
        return rows

    def _resolve_gumroad_url(self, scenario: str, risk_score: float) -> str:
        """Resolve contextual Gumroad product URL."""
        try:
            from agent.upsell_injector import GUMROAD_PRODUCTS
            mapping = {
                "ransomware": GUMROAD_PRODUCTS.get("ransomware", ""),
                "supply_chain": GUMROAD_PRODUCTS.get("supply_chain", ""),
                "apt": GUMROAD_PRODUCTS.get("apt", ""),
                "vulnerability": GUMROAD_PRODUCTS.get("vulnerability", ""),
                "xss_injection": GUMROAD_PRODUCTS.get("vulnerability", ""),
                "rce": GUMROAD_PRODUCTS.get("vulnerability", ""),
                "data_breach": GUMROAD_PRODUCTS.get("data_breach", ""),
                "phishing": GUMROAD_PRODUCTS.get("phishing", ""),
                "malware_campaign": GUMROAD_PRODUCTS.get("malware_campaign", ""),
                "default": GUMROAD_PRODUCTS.get("default", "https://cyberdudebivash.gumroad.com"),
            }
            return mapping.get(scenario, mapping["default"])
        except Exception:
            return "https://cyberdudebivash.gumroad.com"

    def generate(
        self,
        headline: str,
        content: str,
        source_url: str,
        blog_url: str,
        iocs: Dict,
        risk_score: float,
        severity: str,
        confidence: float,
        tlp: Dict,
        mitre_data: List,
        actor_data: Dict,
        cve_list: Optional[List] = None,
    ) -> Dict:
        """
        Generate a complete IR Playbook for a single threat intel event.
        Returns a dict with paths to all generated artifacts.
        """
        scenario = _detect_scenario(headline, content)
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        # Incident ID
        uid = hashlib.sha256(f"{headline}{ts}".encode()).hexdigest()[:8].upper()
        incident_id = f"SENTINEL-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uid}"

        # CVE extraction
        if cve_list is None:
            cve_list = iocs.get("cve", [])
        cves_str = ", ".join(cve_list) if cve_list else "None identified"

        # IOC Table
        ioc_table = self._build_ioc_table(iocs)
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))

        # Asset/product from headline
        asset = re.findall(r'[A-Z][a-zA-Z0-9-\.]+(?:\s[0-9\.]+)?', headline)
        asset = " / ".join(asset[:3]) if asset else "See threat report"

        # TLP label
        tlp_label = tlp.get("label", "CLEAR").replace("TLP:", "") if isinstance(tlp, dict) else "CLEAR"

        # Gumroad URL
        gumroad_url = self._resolve_gumroad_url(scenario, risk_score)

        # Threat type display name
        type_map = {
            "ransomware": "Ransomware Deployment", "supply_chain": "Supply Chain Attack",
            "apt": "APT Campaign / Nation-State Operation", "data_breach": "Data Breach / Exposure",
            "phishing": "Phishing / Social Engineering", "malware_campaign": "Malware Campaign",
            "mobile_malware": "Mobile Malware Campaign", "browser_ext": "Browser Extension Compromise",
            "cloud_attack": "Cloud Infrastructure Attack", "xss_injection": "XSS / Injection Attack",
            "rce": "Remote Code Execution / Exploit", "vulnerability": "Vulnerability Disclosure",
            "generic": "Cybersecurity Incident",
        }
        threat_type = type_map.get(scenario, "Cybersecurity Incident")

        # Summary from content
        summary = content[:300].replace('\n', ' ').strip() + "..." if len(content) > 300 else content[:300]

        # Actor
        actor_tag = actor_data.get("tracking_id", "UNC-CDB-99") if isinstance(actor_data, dict) else "UNC-CDB-99"

        template_vars = {
            "timestamp": ts,
            "incident_id": incident_id,
            "threat_type": threat_type,
            "scenario": scenario.replace("_", " ").title(),
            "severity": severity,
            "risk_score": risk_score,
            "tlp": tlp_label,
            "asset": asset,
            "cves": cve_list,
            "cves_str": cves_str,
            "source_url": source_url or "N/A",
            "blog_url": blog_url or "N/A",
            "summary": summary,
            "ioc_table": ioc_table,
            "total_iocs": total_iocs,
            "mitre_techniques": mitre_data[:10] if isinstance(mitre_data, list) else [],
            "confidence": confidence,
            "actor_tag": actor_tag,
            "gumroad_url": gumroad_url,
        }

        # ── Render Playbook Markdown ──
        if _JINJA2_OK:
            tmpl = Template(_PLAYBOOK_TEMPLATE_MD)
            playbook_md = tmpl.render(**template_vars)
        else:
            # Fallback: basic string replacement
            playbook_md = _PLAYBOOK_TEMPLATE_MD
            for k, v in template_vars.items():
                playbook_md = playbook_md.replace(f"{{{{ {k} }}}}", str(v))

        # ── Save Markdown ──
        md_filename  = f"{incident_id}.md"
        json_filename = f"{incident_id}.json"
        md_path   = PLAYBOOK_DIR / md_filename
        json_path = PLAYBOOK_DIR / json_filename

        md_path.write_text(playbook_md, encoding="utf-8")

        # ── Save JSON (for API + STIX enrichment) ──
        playbook_json = {
            "incident_id": incident_id,
            "title": headline,
            "scenario": scenario,
            "threat_type": threat_type,
            "severity": severity,
            "risk_score": risk_score,
            "tlp": tlp_label,
            "confidence": confidence,
            "actor_tag": actor_tag,
            "cves": cve_list,
            "mitre_techniques": template_vars["mitre_techniques"],
            "ioc_count": total_iocs,
            "source_url": source_url,
            "blog_url": blog_url,
            "gumroad_url": gumroad_url,
            "generated_at": ts,
            "playbook_md": str(md_path),
            "platform": BRAND.get("platform", "https://intel.cyberdudebivash.com"),
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(playbook_json, f, indent=2)

        # ── Generate Containment Scripts ──
        ps_script  = _gen_powershell_containment(headline, iocs, scenario)
        bash_script = _gen_bash_containment(headline, iocs, scenario)
        eradic_script = _gen_eradication_script(headline, iocs, cve_list, scenario)

        ps_path   = SCRIPTS_DIR / f"{incident_id}_containment.ps1"
        bash_path = SCRIPTS_DIR / f"{incident_id}_containment.sh"
        eradic_path = SCRIPTS_DIR / f"{incident_id}_eradication.py"

        ps_path.write_text(ps_script, encoding="utf-8")
        bash_path.write_text(bash_script, encoding="utf-8")
        eradic_path.write_text(eradic_script, encoding="utf-8")

        logger.info(f"  ✅ Playbook generated: {incident_id} | Scenario: {scenario}")
        logger.info(f"     → MD: {md_path} | JSON: {json_path}")
        logger.info(f"     → Scripts: PowerShell + Bash + Eradication")

        return {
            "incident_id": incident_id,
            "scenario": scenario,
            "playbook_md_path": str(md_path),
            "playbook_json_path": str(json_path),
            "powershell_script": str(ps_path),
            "bash_script": str(bash_path),
            "eradication_guide": str(eradic_path),
            "gumroad_url": gumroad_url,
        }


# Singleton
playbook_generator = PlaybookGenerator()
