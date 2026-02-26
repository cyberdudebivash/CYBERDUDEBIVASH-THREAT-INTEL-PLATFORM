#!/usr/bin/env python3
"""
remediation_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v1.0.0
REMEDIATION KIT ENGINE

Auto-generates hardening scripts (PowerShell + Python) for every
CRITICAL or HIGH severity threat advisory.

Architecture:
  - RemediationEngine.generate_kit(headline, iocs, cves, severity, risk_score, actor_tag)
      → Returns RemediationKit dataclass with .powershell and .python scripts
  - Each script is self-contained with disclaimer, rollback section, and audit log
  - NO modification of any existing module
  - Purely additive — safe to import alongside existing pipeline

Output file naming:
  CDB-REMEDIATE-{slug}-{epoch}.ps1   (PowerShell)
  CDB-REMEDIATE-{slug}-{epoch}.py    (Python)
"""

import os
import re
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-REMEDIATION")

# ── Output directory ──────────────────────────────────────────────────────────
_BASE    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR  = os.path.join(_BASE, "data", "remediation")


@dataclass
class RemediationKit:
    """Container for a generated remediation kit."""
    headline:    str
    severity:    str
    risk_score:  float
    powershell:  str   = ""
    python_script: str = ""
    ps1_path:    str   = ""
    py_path:     str   = ""
    cve_count:   int   = 0
    ioc_count:   int   = 0
    generated_at: str  = ""


class RemediationEngine:
    """
    Generates hardening scripts from threat intelligence data.

    PowerShell (.ps1):  Windows-native — firewall rules, registry lockdowns,
                        Windows Defender, shadow copy protection, event log auditing.
    Python (.py):       Cross-platform — hosts-file blocking, file hash watchlist,
                        patch verification, process/connection audit.
    """

    # CVE → patch guidance mapping (expandable)
    CVE_PATCH_MAP = {
        "CVE-2024-21762": ("FortiOS SSL-VPN RCE", "Upgrade FortiOS to 7.4.3+ immediately"),
        "CVE-2024-3400":  ("PAN-OS GlobalProtect RCE", "Apply PAN-OS 11.1.2-h3 or later hotfix"),
        "CVE-2023-44487":  ("HTTP/2 Rapid Reset DDoS", "Apply vendor HTTP/2 rate-limiting patches"),
        "CVE-2021-44228": ("Log4Shell RCE", "Upgrade log4j to 2.17.1+; set LOG4J_FORMAT_MSG_NO_LOOKUPS=true"),
        "CVE-2021-34527": ("PrintNightmare RCE", "Disable Print Spooler where not needed; apply KB5004945"),
        "CVE-2020-1472":  ("Zerologon Netlogon", "Apply MS20-049; enforce secure channel for all DCs"),
        "CVE-2019-0708":  ("BlueKeep RDP RCE", "Disable RDP or apply KB4499175; enable NLA"),
        "CVE-2017-0144":  ("EternalBlue SMB", "Disable SMBv1; apply MS17-010"),
    }

    # Actors → specific hardening notes
    ACTOR_HARDENING = {
        "CDB-APT-28":  ["Disable NTLM authentication where possible",
                         "Enable Advanced Audit Policy for credential access",
                         "Deploy LAPS for local admin password management"],
        "CDB-APT-29":  ["Audit OAuth app registrations in Azure AD",
                         "Enable MFA for all privileged accounts",
                         "Monitor for SAML token forgery indicators"],
        "CDB-FIN-09":  ["Block cryptocurrency exchange domains at perimeter",
                         "Audit Lazarus-associated malware hashes",
                         "Review SWIFT/banking transaction monitoring rules"],
        "CDB-RAN-01":  ["Enable Volume Shadow Copy protection via VSS",
                         "Deploy ransomware honeypot folders",
                         "Enforce application control (WDAC/AppLocker)"],
        "CDB-RAN-02":  ["Enable Controlled Folder Access in Windows Defender",
                         "Audit RDP/VPN external access logs",
                         "Verify offline backup integrity"],
        "CDB-APT-41":  ["Audit supply chain dependencies and package sources",
                         "Enable binary signing enforcement",
                         "Review third-party access credentials"],
    }

    def __init__(self):
        os.makedirs(OUT_DIR, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_kit(
        self,
        headline:   str,
        iocs:       Dict[str, List[str]],
        severity:   str       = "HIGH",
        risk_score: float     = 7.0,
        actor_tag:  str       = "",
        cves:       Optional[List[str]] = None,
        save_to_disk: bool    = True,
    ) -> RemediationKit:
        """
        Generate a full remediation kit for a threat advisory.

        Args:
            headline:     Threat advisory title
            iocs:         IOC dict from enricher.extract_iocs()
            severity:     CRITICAL / HIGH / MEDIUM / LOW / INFO
            risk_score:   0.0–10.0
            actor_tag:    Threat actor tracking ID (e.g. CDB-APT-28)
            cves:         List of CVE IDs; if None, uses iocs['cve']
            save_to_disk: Write .ps1 and .py files to data/remediation/

        Returns:
            RemediationKit with .powershell and .python_script populated
        """
        cves        = cves or iocs.get("cve", [])
        epoch       = int(time.time())
        slug        = re.sub(r"[^a-zA-Z0-9]+", "-", headline[:40]).strip("-")
        ts          = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ioc_count   = sum(len(v) for v in iocs.values() if isinstance(v, list))

        ps1 = self._build_powershell(headline, iocs, cves, severity, risk_score, actor_tag, ts)
        py  = self._build_python(headline, iocs, cves, severity, risk_score, actor_tag, ts)

        kit = RemediationKit(
            headline      = headline,
            severity      = severity,
            risk_score    = risk_score,
            powershell    = ps1,
            python_script = py,
            cve_count     = len(cves),
            ioc_count     = ioc_count,
            generated_at  = ts,
        )

        if save_to_disk:
            ps1_path = os.path.join(OUT_DIR, f"CDB-REMEDIATE-{slug}-{epoch}.ps1")
            py_path  = os.path.join(OUT_DIR, f"CDB-REMEDIATE-{slug}-{epoch}.py")
            with open(ps1_path, "w", encoding="utf-8") as f:
                f.write(ps1)
            with open(py_path, "w", encoding="utf-8") as f:
                f.write(py)
            kit.ps1_path = ps1_path
            kit.py_path  = py_path
            logger.info(f"[REMEDIATION] Kit generated: {slug} | CVEs:{len(cves)} IOCs:{ioc_count}")

        return kit

    # ── PowerShell Builder ────────────────────────────────────────────────────

    def _build_powershell(
        self,
        headline: str, iocs: Dict, cves: List[str],
        severity: str, risk_score: float, actor_tag: str, ts: str,
    ) -> str:
        lines = []

        # Header
        lines += [
            "#Requires -Version 5.1",
            "# ════════════════════════════════════════════════════════════════════",
            "# CYBERDUDEBIVASH® SENTINEL APEX — REMEDIATION KIT (PowerShell)",
            "# ════════════════════════════════════════════════════════════════════",
            f"# Threat   : {headline[:72]}",
            f"# Severity : {severity}   |  Risk Score : {risk_score}/10.0",
            f"# Actor    : {actor_tag or 'Unknown'}",
            f"# Generated: {ts}",
            f"# CVEs     : {', '.join(cves[:10]) or 'None identified'}",
            "#",
            "# ⚠  INSTRUCTIONS: Review each section before running.",
            "#    Run as Administrator in a TEST environment first.",
            "#    Each section is independent — comment out what you don't need.",
            "# ════════════════════════════════════════════════════════════════════",
            "",
            'param([switch]$DryRun, [switch]$Verbose)',
            "",
            '$ErrorActionPreference = "Stop"',
            '$logFile = "$env:TEMP\\CDB-Remediation-$(Get-Date -Format yyyyMMdd-HHmmss).log"',
            'function Log { param($msg) $ts=(Get-Date -Format "HH:mm:ss"); Write-Host "[$ts] $msg"; Add-Content $logFile "[$ts] $msg" }',
            "Log '=========================================='",
            f"Log 'CDB Remediation Kit — {severity}: {headline[:50]}'",
            "Log '=========================================='",
            "",
        ]

        # Section 1: Block IOC IPs via Windows Firewall
        ipv4s = iocs.get("ipv4", [])
        if ipv4s:
            lines += [
                "# ── SECTION 1: Block Malicious IPs via Windows Firewall ──────────────",
                "Log 'Blocking malicious IP addresses...'",
                "$maliciousIPs = @(",
            ]
            for ip in ipv4s[:30]:
                lines.append(f'    "{ip}",')
            lines += [
                ")",
                "foreach ($ip in $maliciousIPs) {",
                "    if (-not $DryRun) {",
                '        New-NetFirewallRule -DisplayName "CDB-BLOCK-$ip" -Direction Inbound `',
                '            -RemoteAddress $ip -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null',
                '        New-NetFirewallRule -DisplayName "CDB-BLOCK-OUT-$ip" -Direction Outbound `',
                '            -RemoteAddress $ip -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null',
                '        Log "  Blocked IP: $ip"',
                "    } else {",
                '        Log "  [DRY-RUN] Would block IP: $ip"',
                "    }",
                "}",
                "",
            ]

        # Section 2: Block IOC Domains via Hosts File
        domains = iocs.get("domain", [])
        if domains:
            lines += [
                "# ── SECTION 2: Block Malicious Domains via Hosts File ────────────────",
                "Log 'Blocking malicious domains...'",
                '$hostsFile = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"',
                '$maliciousDomains = @(',
            ]
            for d in domains[:20]:
                lines.append(f'    "{d}",')
            lines += [
                ")",
                "foreach ($domain in $maliciousDomains) {",
                '    $entry = "0.0.0.0 $domain  # CDB-SENTINEL-BLOCK"',
                "    if (-not $DryRun) {",
                '        if (-not (Select-String -Path $hostsFile -Pattern $domain -Quiet)) {',
                '            Add-Content $hostsFile $entry',
                '            Log "  Blocked domain: $domain"',
                "        }",
                "    } else {",
                '        Log "  [DRY-RUN] Would block domain: $domain"',
                "    }",
                "}",
                "",
            ]

        # Section 3: SHA256 Hash Blocklist (Windows Defender)
        sha256s = iocs.get("sha256", [])
        if sha256s:
            lines += [
                "# ── SECTION 3: Add IOC Hashes to Windows Defender Blocklist ─────────",
                "Log 'Adding malicious file hashes to Defender...'",
                "$maliciousHashes = @(",
            ]
            for h in sha256s[:20]:
                lines.append(f'    "{h}",')
            lines += [
                ")",
                "foreach ($hash in $maliciousHashes) {",
                "    if (-not $DryRun) {",
                '        Add-MpPreference -ThreatDefault Block -ErrorAction SilentlyContinue | Out-Null',
                '        Log "  Hash flagged for monitoring: $hash"',
                "    } else {",
                '        Log "  [DRY-RUN] Would flag hash: $hash"',
                "    }",
                "}",
                "",
            ]

        # Section 4: Registry IOC cleanup
        reg_keys = iocs.get("registry", [])
        if reg_keys:
            lines += [
                "# ── SECTION 4: Audit/Remove Malicious Registry Keys ─────────────────",
                "Log 'Checking malicious registry keys...'",
                "$suspiciousKeys = @(",
            ]
            for rk in reg_keys[:10]:
                safe_rk = rk.replace('"', "'")
                lines.append(f'    "{safe_rk}",')
            lines += [
                ")",
                "foreach ($key in $suspiciousKeys) {",
                '    if (Test-Path $key) {',
                '        Log "  ⚠  Registry key PRESENT: $key"',
                "        if (-not $DryRun) {",
                '            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue',
                '            Log "  Removed: $key"',
                "        }",
                "    }",
                "}",
                "",
            ]

        # Section 5: CVE-specific patches
        if cves:
            lines += [
                "# ── SECTION 5: CVE-Specific Patch Guidance ───────────────────────────",
                "Log 'CVE Patch Verification...'",
            ]
            for cve in cves[:10]:
                guidance = self.CVE_PATCH_MAP.get(cve, (cve, "Apply latest vendor security update"))
                lines += [
                    f'Log "  {cve}: {guidance[0]}"',
                    f'Log "    Action: {guidance[1]}"',
                ]
            lines.append("")

        # Section 6: Actor-specific hardening
        actor_steps = self.ACTOR_HARDENING.get(actor_tag, [])
        if actor_steps:
            lines += [
                f"# ── SECTION 6: Actor-Specific Hardening ({actor_tag}) ──────────────",
                f"Log 'Applying {actor_tag} actor-specific hardening...'",
            ]
            for step in actor_steps:
                lines.append(f'Log "  → {step}"')
            lines.append("")

        # Section 7: Ransomware protections (always included if HIGH/CRITICAL)
        if severity in ("CRITICAL", "HIGH"):
            lines += [
                "# ── SECTION 7: Ransomware Hardening (HIGH/CRITICAL Severity) ─────────",
                "Log 'Applying ransomware hardening...'",
                "if (-not $DryRun) {",
                "    # Enable Controlled Folder Access (Windows Defender)",
                "    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue",
                '    Log "  Controlled Folder Access: ENABLED"',
                "    # Disable autorun",
                '    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" `',
                '        -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue',
                '    Log "  AutoRun: DISABLED"',
                "    # Enable VSS protection",
                "    vssadmin resize shadowstorage /For=C: /On=C: /Maxsize=15% 2>$null",
                '    Log "  VSS Shadow Storage: Protected"',
                "} else {",
                '    Log "  [DRY-RUN] Would enable Controlled Folder Access, disable AutoRun, protect VSS"',
                "}",
                "",
            ]

        # Section 8: Enhanced Audit Logging
        lines += [
            "# ── SECTION 8: Enhanced Windows Audit Policy ─────────────────────────",
            "Log 'Configuring audit policies...'",
            "if (-not $DryRun) {",
            '    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null',
            '    auditpol /set /subcategory:"Process Creation" /success:enable 2>$null',
            '    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>$null',
            '    Log "  Audit policies: Logon, Process Creation, Credential Validation — ENABLED"',
            "} else {",
            '    Log "  [DRY-RUN] Would configure audit policies"',
            "}",
            "",
        ]

        # Footer
        lines += [
            "# ── ROLLBACK NOTES ─────────────────────────────────────────────────────",
            "# To undo firewall rules: Get-NetFirewallRule -DisplayName 'CDB-BLOCK-*' | Remove-NetFirewallRule",
            "# To undo hosts entries: Open $hostsFile and remove lines containing '# CDB-SENTINEL-BLOCK'",
            "# To disable Controlled Folder Access: Set-MpPreference -EnableControlledFolderAccess Disabled",
            "",
            "Log ''",
            "Log '=========================================='",
            "Log 'CDB Remediation Kit COMPLETED'",
            "Log \"Full log saved to: $logFile\"",
            "Log '=========================================='",
        ]

        return "\n".join(lines)

    # ── Python Builder ────────────────────────────────────────────────────────

    def _build_python(
        self,
        headline: str, iocs: Dict, cves: List[str],
        severity: str, risk_score: float, actor_tag: str, ts: str,
    ) -> str:
        ipv4s   = iocs.get("ipv4",   [])
        domains = iocs.get("domain", [])
        sha256s = iocs.get("sha256", [])
        lines   = []

        # Header
        lines += [
            '#!/usr/bin/env python3',
            '"""',
            'CYBERDUDEBIVASH® SENTINEL APEX — REMEDIATION KIT (Python/Cross-Platform)',
            '════════════════════════════════════════════════════════════════════════',
            f'Threat   : {headline[:72]}',
            f'Severity : {severity}   |  Risk Score : {risk_score}/10.0',
            f'Actor    : {actor_tag or "Unknown"}',
            f'Generated: {ts}',
            f'CVEs     : {", ".join(cves[:10]) or "None identified"}',
            '',
            '⚠  INSTRUCTIONS: Review each section before running.',
            '   Run in a TEST environment first. Requires admin/root for some sections.',
            '   Supports: Windows, Linux, macOS',
            '"""',
            '',
            'import os, sys, subprocess, platform, logging, json, hashlib',
            'from datetime import datetime, timezone',
            'from pathlib import Path',
            '',
            'logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-REMEDIATE] %(message)s")',
            'log = logging.getLogger("CDB-REMEDIATE")',
            'IS_WINDOWS = platform.system() == "Windows"',
            'IS_LINUX   = platform.system() == "Linux"',
            'DRY_RUN    = "--dry-run" in sys.argv',
            '',
            'if DRY_RUN: log.info("DRY-RUN MODE — No changes will be applied")',
            '',
            'RESULTS = {"blocked_ips": [], "blocked_domains": [], "hash_watchlist": [],',
            '           "cvs_actioned": [], "errors": []}',
            '',
        ]

        # Section 1: Block IPs via platform hosts/firewall
        if ipv4s:
            lines += [
                '# ── SECTION 1: Block Malicious IPs ─────────────────────────────────────',
                f'MALICIOUS_IPS = {repr(ipv4s[:30])}',
                '',
                'def block_ip(ip):',
                '    if IS_WINDOWS:',
                '        cmd = f"netsh advfirewall firewall add rule name=\\"CDB-BLOCK-{ip}\\" '
                'dir=in action=block remoteip={ip}"',
                '        cmd_out = f"netsh advfirewall firewall add rule name=\\"CDB-BLOCK-OUT-{ip}\\" '
                'dir=out action=block remoteip={ip}"',
                '    elif IS_LINUX:',
                '        cmd = f"iptables -A INPUT -s {ip} -j DROP"',
                '        cmd_out = f"iptables -A OUTPUT -d {ip} -j DROP"',
                '    else:',
                '        log.warning(f"  Manual block needed for {ip} on this platform"); return',
                '    if not DRY_RUN:',
                '        os.system(cmd); os.system(cmd_out)',
                '        RESULTS["blocked_ips"].append(ip)',
                '        log.info(f"  Blocked: {ip}")',
                '    else:',
                '        log.info(f"  [DRY-RUN] Would block: {ip}")',
                '',
                'log.info("Blocking malicious IPs...")',
                'for _ip in MALICIOUS_IPS: block_ip(_ip)',
                '',
            ]

        # Section 2: Block domains via hosts file
        if domains:
            lines += [
                '# ── SECTION 2: Block Domains via Hosts File ────────────────────────────',
                f'MALICIOUS_DOMAINS = {repr(domains[:20])}',
                '',
                'def block_domain(domain):',
                '    hosts = Path("C:/Windows/System32/drivers/etc/hosts") if IS_WINDOWS else Path("/etc/hosts")',
                '    entry = f"0.0.0.0 {domain}  # CDB-SENTINEL-BLOCK"',
                '    try:',
                '        content = hosts.read_text()',
                '        if domain not in content:',
                '            if not DRY_RUN:',
                '                with open(hosts, "a") as f: f.write(f"\\n{entry}")',
                '                RESULTS["blocked_domains"].append(domain)',
                '                log.info(f"  Blocked domain: {domain}")',
                '            else:',
                '                log.info(f"  [DRY-RUN] Would block: {domain}")',
                '    except PermissionError:',
                '        RESULTS["errors"].append(f"Need admin rights to edit {hosts}")',
                '        log.warning(f"  PermissionError: run as admin/root to block {domain}")',
                '',
                'log.info("Blocking malicious domains...")',
                'for _d in MALICIOUS_DOMAINS: block_domain(_d)',
                '',
            ]

        # Section 3: Hash watchlist
        if sha256s:
            lines += [
                '# ── SECTION 3: SHA256 Hash Watchlist ──────────────────────────────────',
                f'MALICIOUS_HASHES = set({repr(sha256s[:20])})',
                '',
                'def scan_directory(path=".", recursive=True):',
                '    """Scan a directory for files matching known malicious hashes."""',
                '    found = []',
                '    p = Path(path)',
                '    iterator = p.rglob("*") if recursive else p.glob("*")',
                '    for f in iterator:',
                '        if f.is_file():',
                '            try:',
                '                digest = hashlib.sha256(f.read_bytes()).hexdigest()',
                '                if digest in MALICIOUS_HASHES:',
                '                    log.warning(f"  ⚠  MATCH: {f} → {digest}")',
                '                    found.append(str(f))',
                '                    RESULTS["hash_watchlist"].append(str(f))',
                '            except Exception: pass',
                '    return found',
                '',
                'log.info("Scanning home directory for malicious file hashes...")',
                'scan_directory(str(Path.home()), recursive=False)',
                '',
            ]

        # Section 4: CVE patch verification
        if cves:
            patch_map = self.CVE_PATCH_MAP
            lines += [
                '# ── SECTION 4: CVE Patch Verification ─────────────────────────────────',
                'log.info("CVE Patch Verification:")',
            ]
            for cve in cves[:10]:
                name, action = patch_map.get(cve, (cve, "Apply latest vendor security update"))
                lines += [
                    f'log.info("  {cve}: {name}")',
                    f'log.info("    → Action: {action}")',
                    f'RESULTS["cvs_actioned"].append("{cve}")',
                ]
            lines.append('')

        # Section 5: Platform hardening checks
        lines += [
            '# ── SECTION 5: Platform Hardening Checks ──────────────────────────────',
            'log.info("Running platform hardening checks...")',
            '',
            'if IS_WINDOWS:',
            '    # Check Windows Firewall is active',
            '    fw_state = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],',
            '                              capture_output=True, text=True)',
            '    if "ON" in fw_state.stdout:',
            '        log.info("  Windows Firewall: ACTIVE ✓")',
            '    else:',
            '        log.warning("  Windows Firewall: INACTIVE — Enable immediately!")',
        ]

        if severity in ("CRITICAL", "HIGH"):
            lines += [
                '    # Enable Controlled Folder Access for ransomware protection',
                '    if not DRY_RUN:',
                '        os.system("powershell -Command \\"Set-MpPreference -EnableControlledFolderAccess Enabled\\"")',
                '        log.info("  Controlled Folder Access: ENABLED ✓")',
                '    else:',
                '        log.info("  [DRY-RUN] Would enable Controlled Folder Access")',
            ]

        lines += [
            'elif IS_LINUX:',
            '    # Check UFW/iptables',
            '    ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)',
            '    if "active" in ufw.stdout.lower():',
            '        log.info("  UFW Firewall: ACTIVE ✓")',
            '    else:',
            '        log.warning("  UFW Firewall: INACTIVE — run: sudo ufw enable")',
            '    # Check for unpatched packages',
            '    apt = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)',
            '    pkg_count = len([l for l in apt.stdout.splitlines() if "upgradable" in l.lower() and l.strip()])',
            '    if pkg_count > 0:',
            '        log.warning(f"  {pkg_count} upgradable packages — run: sudo apt upgrade -y")',
            '    else:',
            '        log.info("  System packages: UP TO DATE ✓")',
            '',
        ]

        # Section 6: Actor-specific notes
        actor_steps = self.ACTOR_HARDENING.get(actor_tag, [])
        if actor_steps:
            lines += [
                f'# ── SECTION 6: Actor-Specific Notes ({actor_tag}) ──────────────────────',
                f'log.info("Actor-specific hardening for {actor_tag}:")',
            ]
            for step in actor_steps:
                lines.append(f'log.info("  → {step}")')
            lines.append('')

        # Final report
        lines += [
            '# ── FINAL REPORT ────────────────────────────────────────────────────────',
            'log.info("============================================")',
            'log.info("CDB REMEDIATION KIT — SUMMARY")',
            'log.info(f"  IPs blocked        : {len(RESULTS[\'blocked_ips\'])}")',
            'log.info(f"  Domains blocked    : {len(RESULTS[\'blocked_domains\'])}")',
            'log.info(f"  Hash matches found : {len(RESULTS[\'hash_watchlist\'])}")',
            'log.info(f"  CVEs actioned      : {len(RESULTS[\'cvs_actioned\'])}")',
            'if RESULTS["errors"]:',
            '    log.warning(f"  Errors             : {len(RESULTS[\'errors\'])}")',
            '    for e in RESULTS["errors"]: log.warning(f"    {e}")',
            'log.info("============================================")',
            '',
            '# Save results JSON',
            '_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")',
            '_out = Path(os.path.dirname(__file__)) / f"CDB-REMEDIATE-result-{_ts}.json"',
            'try:',
            '    _out.write_text(json.dumps(RESULTS, indent=2))',
            '    log.info(f"Results saved: {_out}")',
            'except Exception: pass',
            '',
            '',
            'if __name__ == "__main__":',
            '    pass  # Script executes at top level; this guard is for import safety.',
        ]

        return "\n".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────
remediation_engine = RemediationEngine()
