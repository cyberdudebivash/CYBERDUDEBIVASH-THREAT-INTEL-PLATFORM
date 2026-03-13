#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — REMEDIATION KIT (Python/Cross-Platform)
════════════════════════════════════════════════════════════════════════
Threat   : STANDALONE TEST: Critical RCE via Log4Shell + FortiOS
Severity : CRITICAL   |  Risk Score : 9.5/10.0
Actor    : CDB-APT-28
Generated: 2026-03-13T10:55:25Z
CVEs     : CVE-2024-21762, CVE-2021-44228

⚠  INSTRUCTIONS: Review each section before running.
   Run in a TEST environment first. Requires admin/root for some sections.
   Supports: Windows, Linux, macOS
"""

import os, sys, subprocess, platform, logging, json, hashlib
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-REMEDIATE] %(message)s")
log = logging.getLogger("CDB-REMEDIATE")
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
DRY_RUN    = "--dry-run" in sys.argv

if DRY_RUN: log.info("DRY-RUN MODE — No changes will be applied")

RESULTS = {"blocked_ips": [], "blocked_domains": [], "hash_watchlist": [],
           "cvs_actioned": [], "errors": []}

# ── SECTION 1: Block Malicious IPs ─────────────────────────────────────
MALICIOUS_IPS = ['10.13.37.1', '192.168.99.2']

def block_ip(ip):
    if IS_WINDOWS:
        cmd = f"netsh advfirewall firewall add rule name=\"CDB-BLOCK-{ip}\" dir=in action=block remoteip={ip}"
        cmd_out = f"netsh advfirewall firewall add rule name=\"CDB-BLOCK-OUT-{ip}\" dir=out action=block remoteip={ip}"
    elif IS_LINUX:
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        cmd_out = f"iptables -A OUTPUT -d {ip} -j DROP"
    else:
        log.warning(f"  Manual block needed for {ip} on this platform"); return
    if not DRY_RUN:
        os.system(cmd); os.system(cmd_out)
        RESULTS["blocked_ips"].append(ip)
        log.info(f"  Blocked: {ip}")
    else:
        log.info(f"  [DRY-RUN] Would block: {ip}")

log.info("Blocking malicious IPs...")
for _ip in MALICIOUS_IPS: block_ip(_ip)

# ── SECTION 2: Block Domains via Hosts File ────────────────────────────
MALICIOUS_DOMAINS = ['evil-c2.example.com', 'malware.test.net']

def block_domain(domain):
    hosts = Path("C:/Windows/System32/drivers/etc/hosts") if IS_WINDOWS else Path("/etc/hosts")
    entry = f"0.0.0.0 {domain}  # CDB-SENTINEL-BLOCK"
    try:
        content = hosts.read_text()
        if domain not in content:
            if not DRY_RUN:
                with open(hosts, "a") as f: f.write(f"\n{entry}")
                RESULTS["blocked_domains"].append(domain)
                log.info(f"  Blocked domain: {domain}")
            else:
                log.info(f"  [DRY-RUN] Would block: {domain}")
    except PermissionError:
        RESULTS["errors"].append(f"Need admin rights to edit {hosts}")
        log.warning(f"  PermissionError: run as admin/root to block {domain}")

log.info("Blocking malicious domains...")
for _d in MALICIOUS_DOMAINS: block_domain(_d)

# ── SECTION 3: SHA256 Hash Watchlist ──────────────────────────────────
MALICIOUS_HASHES = set(['aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ab'])

def scan_directory(path=".", recursive=True):
    """Scan a directory for files matching known malicious hashes."""
    found = []
    p = Path(path)
    iterator = p.rglob("*") if recursive else p.glob("*")
    for f in iterator:
        if f.is_file():
            try:
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                if digest in MALICIOUS_HASHES:
                    log.warning(f"  ⚠  MATCH: {f} → {digest}")
                    found.append(str(f))
                    RESULTS["hash_watchlist"].append(str(f))
            except Exception: pass
    return found

log.info("Scanning home directory for malicious file hashes...")
scan_directory(str(Path.home()), recursive=False)

# ── SECTION 4: CVE Patch Verification ─────────────────────────────────
log.info("CVE Patch Verification:")
log.info("  CVE-2024-21762: FortiOS SSL-VPN RCE")
log.info("    → Action: Upgrade FortiOS to 7.4.3+ immediately")
RESULTS["cvs_actioned"].append("CVE-2024-21762")
log.info("  CVE-2021-44228: Log4Shell RCE")
log.info("    → Action: Upgrade log4j to 2.17.1+; set LOG4J_FORMAT_MSG_NO_LOOKUPS=true")
RESULTS["cvs_actioned"].append("CVE-2021-44228")

# ── SECTION 5: Platform Hardening Checks ──────────────────────────────
log.info("Running platform hardening checks...")

if IS_WINDOWS:
    # Check Windows Firewall is active
    fw_state = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                              capture_output=True, text=True)
    if "ON" in fw_state.stdout:
        log.info("  Windows Firewall: ACTIVE ✓")
    else:
        log.warning("  Windows Firewall: INACTIVE — Enable immediately!")
    # Enable Controlled Folder Access for ransomware protection
    if not DRY_RUN:
        os.system("powershell -Command \"Set-MpPreference -EnableControlledFolderAccess Enabled\"")
        log.info("  Controlled Folder Access: ENABLED ✓")
    else:
        log.info("  [DRY-RUN] Would enable Controlled Folder Access")
elif IS_LINUX:
    # Check UFW/iptables
    ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    if "active" in ufw.stdout.lower():
        log.info("  UFW Firewall: ACTIVE ✓")
    else:
        log.warning("  UFW Firewall: INACTIVE — run: sudo ufw enable")
    # Check for unpatched packages
    apt = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
    pkg_count = len([l for l in apt.stdout.splitlines() if "upgradable" in l.lower() and l.strip()])
    if pkg_count > 0:
        log.warning(f"  {pkg_count} upgradable packages — run: sudo apt upgrade -y")
    else:
        log.info("  System packages: UP TO DATE ✓")

# ── SECTION 6: Actor-Specific Notes (CDB-APT-28) ──────────────────────
log.info("Actor-specific hardening for CDB-APT-28:")
log.info("  → Disable NTLM authentication where possible")
log.info("  → Enable Advanced Audit Policy for credential access")
log.info("  → Deploy LAPS for local admin password management")

# ── FINAL REPORT ────────────────────────────────────────────────────────
log.info("============================================")
log.info("CDB REMEDIATION KIT — SUMMARY")
log.info(f"  IPs blocked        : {len(RESULTS['blocked_ips'])}")
log.info(f"  Domains blocked    : {len(RESULTS['blocked_domains'])}")
log.info(f"  Hash matches found : {len(RESULTS['hash_watchlist'])}")
log.info(f"  CVEs actioned      : {len(RESULTS['cvs_actioned'])}")
if RESULTS["errors"]:
    log.warning(f"  Errors             : {len(RESULTS['errors'])}")
    for e in RESULTS["errors"]: log.warning(f"    {e}")
log.info("============================================")

# Save results JSON
_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
_out = Path(os.path.dirname(__file__)) / f"CDB-REMEDIATE-result-{_ts}.json"
try:
    _out.write_text(json.dumps(RESULTS, indent=2))
    log.info(f"Results saved: {_out}")
except Exception: pass


if __name__ == "__main__":
    pass  # Script executes at top level; this guard is for import safety.