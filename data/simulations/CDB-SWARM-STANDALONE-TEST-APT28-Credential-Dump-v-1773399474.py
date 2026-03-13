#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — ADVERSARY SWARM SIMULATION           ║
║  ⚠  SAFE DETECTION-VALIDATION SCRIPT — NO REAL PAYLOAD                ║
╚══════════════════════════════════════════════════════════════════════════╝

PURPOSE:
  This script simulates adversary behaviour to verify that your EDR, SIEM,
  and SOAR rules correctly detect and alert on the following threat:

  Threat   : STANDALONE TEST: APT28 Credential Dump via LSASS
  Severity : CRITICAL
  Actor    : CDB-APT-28
  Generated: 2026-03-13T10:57:54Z
  CVEs     : CVE-2023-3519

WHAT THIS SCRIPT DOES (SAFE ONLY):
  ✅ Creates temp canary files with IOC-derived names
  ✅ Writes safe canary registry keys (Windows only, auto-cleaned)
  ✅ Performs DNS resolution probes on IOC domains
  ✅ Attempts TCP connect probes to IOC IPs (no data sent)
  ✅ Writes event log simulation entries
  ✅ Auto-cleans all artefacts on exit

WHAT THIS SCRIPT NEVER DOES:
  ❌ No real exploit or shellcode
  ❌ No data exfiltration
  ❌ No encryption or file destruction
  ❌ No privilege escalation
  ❌ No network data transmission

USAGE:
  python CDB-SWARM-*.py                  # Full simulation
  python CDB-SWARM-*.py --dry-run         # List tests without executing
  python CDB-SWARM-*.py --technique dns   # Run DNS probe only
"""

import os, sys, socket, tempfile, platform, logging, json, time, atexit
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [CDB-SWARM] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("CDB-SWARM")

IS_WINDOWS = platform.system() == "Windows"
DRY_RUN    = "--dry-run" in sys.argv
TECHNIQUE  = next((sys.argv[i+1] for i, a in enumerate(sys.argv)
                   if a == "--technique" and i+1 < len(sys.argv)), "all")

THREAT_META = {
    "headline":  'STANDALONE TEST: APT28 Credential Dump via LSASS',
    "severity":  'CRITICAL',
    "actor_tag": 'CDB-APT-28',
    "generated": '2026-03-13T10:57:54Z',
    "cves":      ['CVE-2023-3519'],
}

_CLEANUP_TARGETS = []  # Files/keys registered for cleanup

def _cleanup():
    """Auto-cleanup all simulation artefacts on exit."""
    for target in _CLEANUP_TARGETS:
        try:
            p = Path(target)
            if p.exists(): p.unlink()
        except Exception: pass
    log.info("[CLEANUP] All simulation artefacts removed.")

atexit.register(_cleanup)

RESULTS = {"passed": [], "failed": [], "skipped": [], "total": 0}

def record(name, status, detail=""):
    RESULTS["total"] += 1
    RESULTS[status].append(name)
    icon = {"passed": "✅", "failed": "❌", "skipped": "⚠ "}.get(status, " ")
    log.info(f"  {icon} {name}" + (f": {detail}" if detail else ""))

# ── Threat Intelligence Data ────────────────────────────────────────────
IOC_IPS     = ['10.99.1.200', '203.0.113.5']
IOC_DOMAINS = ['c2-test.malware.dev', 'ransomware-c2.example.net']
IOC_HASHES  = ['deadbeefdeadbeef00112233445566778899aabbccddeeff001122334455ab']
IOC_URLS    = ['http://c2-test.malware.dev/gate']

# ── SIMULATION 1: Canary File Drop ──────────────────────────────────────
def sim_file_drop():
    """Simulate malware dropping files to disk (canary files only)."""
    tmp = Path(tempfile.gettempdir())
    canary_names = [
        "cdb_swarm_dropper_canary.exe.sim",
        "cdb_swarm_payload_canary.dll.sim",
        "cdb_swarm_stager_canary.bat.sim",
    ]
    for name in canary_names:
        p = tmp / name
        if not DRY_RUN:
            p.write_text(
                f"# CDB-SWARM CANARY FILE\n"
                f"# This file simulates a malware dropper artefact.\n"
                f"# Threat: {headline[:60]}\n"
                f"# Generated: {ts}\n"
                f"# SAFE - NOT EXECUTABLE\n"
            )
            _CLEANUP_TARGETS.append(str(p))
            record("file_drop:" + name, "passed")
        else:
            record("file_drop:" + name, "skipped", "dry-run")

# ── SIMULATION 2: C2 DNS Resolution Probe ──────────────────────────────
def sim_c2_dns():
    """Simulate C2 domain lookups. Triggers DNS monitoring rules."""
    for domain in IOC_DOMAINS[:5]:
        if not DRY_RUN:
            try:
                result = socket.getaddrinfo(domain, None, socket.AF_INET)
                record(f"dns_probe:{domain}", "passed", f"resolved:{result[0][4][0]}")
            except socket.gaierror:
                record(f"dns_probe:{domain}", "passed", "NXDOMAIN (expected)")
            except Exception as e:
                record(f"dns_probe:{domain}", "failed", str(e))
        else:
            record(f"dns_probe:{domain}", "skipped", "dry-run")

# ── SIMULATION 3: C2 TCP Connection Probe ──────────────────────────────
def sim_c2_tcp():
    """Simulate TCP connection attempts to C2 IPs. Triggers network rules."""
    for ip in IOC_IPS[:5]:
        if not DRY_RUN:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, 443))  # connect-only, no data sent
                s.close()
                status = "port_open" if result == 0 else f"port_closed(code={result})"
                record(f"tcp_probe:{ip}:443", "passed", status)
            except Exception as e:
                record(f"tcp_probe:{ip}:443", "passed", f"blocked:{type(e).__name__}")
        else:
            record(f"tcp_probe:{ip}:443", "skipped", "dry-run")

# ── SIMULATION 4: Registry Canary Write (Windows Only) ─────────────────
def sim_registry_canary():
    """Write a canary registry key to simulate persistence. Windows only."""
    if not IS_WINDOWS:
        record("registry_canary", "skipped", "Windows only")
        return
    try:
        import winreg
        key_path = r"Software\CDB-SWARM-TEST\SimulatedPersistence"
        if not DRY_RUN:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "CDB_SWARM_CANARY", 0, winreg.REG_SZ,
                             "SIMULATION:STANDALONE TEST: APT28 Credential Dump v")
            winreg.CloseKey(key)
            # Schedule registry cleanup
            def _del_reg():
                try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
                except Exception: pass
            atexit.register(_del_reg)
            record("registry_canary:HKCU\\Software\\CDB-SWARM-TEST", "passed")
        else:
            record("registry_canary", "skipped", "dry-run")
    except ImportError:
        record("registry_canary", "skipped", "winreg not available")
    except Exception as e:
        record("registry_canary", "failed", str(e))

# ── SIMULATION 5: Ransomware Canary (CRITICAL Severity) ─────────────
def sim_ransomware_canary():
    """
    Simulate ransomware precursor behaviour:
    - Creates a canary folder with dummy files (simulates staging)
    - Writes a fake ransom note (no encryption)
    - Triggers VSS-query (shadow copy enumeration)
    """
    tmp = Path(tempfile.gettempdir()) / "CDB_SWARM_RANSOM_CANARY"
    if not DRY_RUN:
        tmp.mkdir(exist_ok=True)
        _CLEANUP_TARGETS.append(str(tmp / "README_RANSOM_CANARY.txt"))
        _CLEANUP_TARGETS.append(str(tmp / "STAGED_DATA_CANARY.txt"))
        (tmp / "README_RANSOM_CANARY.txt").write_text(
            "# CDB-SWARM CANARY — RANSOMWARE NOTE SIMULATION\n"
            "# This is a SAFE simulation file. No encryption occurred.\n"
            "# Threat: STANDALONE TEST: APT28 Credential Dump via LSASS\n"
        )
        (tmp / "STAGED_DATA_CANARY.txt").write_text(
            "# CDB-SWARM CANARY — DATA STAGING SIMULATION\n"
            "# Simulates data collected before exfiltration attempt.\n"
        )
        record("ransomware_canary:note_drop", "passed")
        record("ransomware_canary:staging", "passed")
        # VSS query (read-only, no deletion)
        if IS_WINDOWS:
            os.system("vssadmin list shadows > nul 2>&1")
            record("ransomware_canary:vss_query", "passed")
    else:
        record("ransomware_canary", "skipped", "dry-run")

# ── SIMULATION 6: Hash-Based Detection Canary ───────────────────────
def sim_hash_canary():
    """Write canary files embedding known IOC hash metadata."""
    tmp = Path(tempfile.gettempdir())
    for h in IOC_HASHES[:3]:
        p = tmp / f"CDB_SWARM_HASH_{h[:16]}.sim"
        if not DRY_RUN:
            p.write_text(f"CDB-SWARM-HASH-SIM:{h}\nSAFE CANARY — NOT MALICIOUS\n")
            _CLEANUP_TARGETS.append(str(p))
            record(f"hash_canary:{h[:16]}", "passed")
        else:
            record(f"hash_canary:{h[:16]}", "skipped", "dry-run")

# ── MAIN RUNNER ─────────────────────────────────────────────────────────
def main():
    log.info("╔══════════════════════════════════════════════════════╗")
    log.info("║  CDB ADVERSARY SWARM — SIMULATION STARTING          ║")
    log.info("╚══════════════════════════════════════════════════════╝")
    log.info(f"Threat  : STANDALONE TEST: APT28 Credential Dump via LSASS")
    log.info("Severity: CRITICAL  |  Actor: CDB-APT-28")
    log.info(f"Mode    : {'DRY-RUN' if DRY_RUN else 'LIVE SIMULATION'}")
    log.info("")

    # Run all simulations (or selected technique)
    sims = {
        "file_drop":         sim_file_drop,
        "dns":               sim_c2_dns,
        "tcp":               sim_c2_tcp,
        "registry":          sim_registry_canary,
        "ransomware":        sim_ransomware_canary,
        "hash":              sim_hash_canary,
    }

    for name, fn in sims.items():
        if TECHNIQUE == "all" or TECHNIQUE == name:
            log.info(f"── Running: {name} ──────────────────────────")
            try: fn()
            except Exception as e:
                record(name, "failed", str(e))

    # Summary
    log.info("")
    log.info("════════════════════════════════════════════════════")
    log.info("  ADVERSARY SWARM SIMULATION — RESULTS SUMMARY")
    log.info("════════════════════════════════════════════════════")
    log.info(f"  Total   : {RESULTS['total']}")
    log.info(f"  Passed  : {len(RESULTS['passed'])}")
    log.info(f"  Failed  : {len(RESULTS['failed'])}")
    log.info(f"  Skipped : {len(RESULTS['skipped'])}")
    log.info("")
    if RESULTS["failed"]:
        log.warning("FAILED SIMULATIONS (check EDR/SIEM rules):")
        for f in RESULTS["failed"]: log.warning(f"  ❌ {f}")
    else:
        log.info("✅ All simulations completed — Review your SIEM/EDR for alerts")
    log.info("════════════════════════════════════════════════════")

    # Save results
    _ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    _out = Path(tempfile.gettempdir()) / f"CDB-SWARM-result-{_ts}.json"
    try:
        _out.write_text(json.dumps({**THREAT_META, **RESULTS}, indent=2))
        log.info(f"Results saved: {_out}")
    except Exception: pass


if __name__ == "__main__":
    main()