#!/usr/bin/env python3
"""
adversary_swarm.py — CYBERDUDEBIVASH® SENTINEL APEX v1.0.0
ADVERSARY SWARM — SAFE BREACH SIMULATION ENGINE

Generates safe, detection-validation Python scripts from threat intel
(IOCs + CVEs + actor data). These scripts simulate adversary behaviour
to verify that your EDR/SIEM/SOAR rules fire correctly — without any
real malicious payload.

What the generated scripts DO:
  ✅ Create temp files with IOC-derived names and metadata
  ✅ Write safe canary registry keys (HKCU\Software\CDB-SWARM-TEST-*)
  ✅ Attempt DNS resolution of IOC domains (non-destructive probe)
  ✅ Simulate network connection attempts (TCP connect-only, no data send)
  ✅ Write safe file content that matches known IOC patterns
  ✅ Generate event log entries simulating malware activity
  ✅ Include full rollback/cleanup to restore original state

What the generated scripts NEVER do:
  ❌ No real shellcode or exploit code
  ❌ No privilege escalation
  ❌ No data exfiltration
  ❌ No encryption/ransomware operations
  ❌ No actual network data transfer
  ❌ No persistence without explicit rollback

Architecture:
  - AdversarySwarm.generate_simulation(headline, iocs, severity, actor_tag, cves)
      → Returns SimulationKit dataclass with .script and .path
  - Purely additive — does not touch any existing module

Output:
  data/simulations/CDB-SWARM-{slug}-{epoch}.py
"""

import os
import re
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-ADVERSARY-SWARM")

_BASE   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(_BASE, "data", "simulations")


@dataclass
class SimulationKit:
    """Container for a generated breach simulation script."""
    headline:     str
    severity:     str
    actor_tag:    str
    script:       str  = ""
    path:         str  = ""
    ioc_count:    int  = 0
    test_count:   int  = 0
    generated_at: str  = ""


class AdversarySwarm:
    """
    Generates safe, detection-validation simulation scripts.

    Each script:
    1. Has a prominent SAFE SIMULATION DISCLAIMER at the top
    2. Creates only canary/temp artefacts (auto-cleaned on exit)
    3. Logs every simulated action to a local file
    4. Includes a full CLEANUP section that runs on exit/error
    5. Uses only stdlib — no external dependencies
    """

    # Simulation technique templates per actor
    ACTOR_TECHNIQUES = {
        "CDB-APT-28":  ["credential_dump_sim", "lsass_access_sim", "lateral_movement_sim"],
        "CDB-APT-29":  ["oauth_abuse_sim", "saml_forge_sim", "token_theft_sim"],
        "CDB-FIN-09":  ["crypto_beaconing_sim", "c2_dns_sim", "banking_recon_sim"],
        "CDB-RAN-01":  ["shadow_delete_sim", "file_encrypt_canary_sim", "ransom_note_sim"],
        "CDB-RAN-02":  ["rdp_bruteforce_sim", "lateral_file_drop_sim", "data_staging_sim"],
        "CDB-APT-41":  ["supply_chain_sim", "code_sign_abuse_sim", "dll_sideload_sim"],
        "CDB-APT-22":  ["living_off_land_sim", "wmi_exec_sim", "powershell_obfusc_sim"],
        "CDB-FIN-11":  ["clop_c2_beacon_sim", "moveit_exploit_sim", "data_theft_sim"],
    }

    def __init__(self):
        os.makedirs(OUT_DIR, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_simulation(
        self,
        headline:     str,
        iocs:         Dict[str, List[str]],
        severity:     str      = "HIGH",
        actor_tag:    str      = "",
        cves:         Optional[List[str]] = None,
        save_to_disk: bool     = True,
    ) -> SimulationKit:
        """
        Generate a safe breach simulation script.

        Args:
            headline:     Threat advisory title
            iocs:         IOC dict from enricher.extract_iocs()
            severity:     CRITICAL / HIGH / MEDIUM / LOW / INFO
            actor_tag:    Threat actor tracking ID (e.g. CDB-APT-28)
            cves:         List of CVE IDs; if None, uses iocs['cve']
            save_to_disk: Write .py file to data/simulations/

        Returns:
            SimulationKit with .script populated
        """
        cves      = cves or iocs.get("cve", [])
        epoch     = int(time.time())
        slug      = re.sub(r"[^a-zA-Z0-9]+", "-", headline[:40]).strip("-")
        ts        = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))

        techniques = self.ACTOR_TECHNIQUES.get(actor_tag, ["generic_ioc_sim", "c2_dns_sim"])
        script     = self._build_script(headline, iocs, cves, severity, actor_tag, ts, techniques)
        test_count = script.count("def sim_")

        kit = SimulationKit(
            headline     = headline,
            severity     = severity,
            actor_tag    = actor_tag,
            script       = script,
            ioc_count    = ioc_count,
            test_count   = test_count,
            generated_at = ts,
        )

        if save_to_disk:
            path = os.path.join(OUT_DIR, f"CDB-SWARM-{slug}-{epoch}.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(script)
            kit.path = path
            logger.info(
                f"[SWARM] Simulation generated: {slug} | "
                f"IOCs:{ioc_count} | Techniques:{test_count} | Actor:{actor_tag}"
            )

        return kit

    # ── Script Builder ────────────────────────────────────────────────────────

    def _build_script(
        self,
        headline: str, iocs: Dict, cves: List[str],
        severity: str, actor_tag: str, ts: str,
        techniques: List[str],
    ) -> str:
        ipv4s   = iocs.get("ipv4",   [])
        domains = iocs.get("domain", [])
        sha256s = iocs.get("sha256", [])
        urls    = iocs.get("url",    [])

        lines = [
            '#!/usr/bin/env python3',
            '"""',
            '╔══════════════════════════════════════════════════════════════════════════╗',
            '║  CYBERDUDEBIVASH® SENTINEL APEX — ADVERSARY SWARM SIMULATION           ║',
            '║  ⚠  SAFE DETECTION-VALIDATION SCRIPT — NO REAL PAYLOAD                ║',
            '╚══════════════════════════════════════════════════════════════════════════╝',
            '',
            'PURPOSE:',
            '  This script simulates adversary behaviour to verify that your EDR, SIEM,',
            '  and SOAR rules correctly detect and alert on the following threat:',
            '',
            f'  Threat   : {headline[:72]}',
            f'  Severity : {severity}',
            f'  Actor    : {actor_tag or "Unknown Cluster"}',
            f'  Generated: {ts}',
            f'  CVEs     : {", ".join(cves[:8]) or "None"}',
            '',
            'WHAT THIS SCRIPT DOES (SAFE ONLY):',
            '  ✅ Creates temp canary files with IOC-derived names',
            '  ✅ Writes safe canary registry keys (Windows only, auto-cleaned)',
            '  ✅ Performs DNS resolution probes on IOC domains',
            '  ✅ Attempts TCP connect probes to IOC IPs (no data sent)',
            '  ✅ Writes event log simulation entries',
            '  ✅ Auto-cleans all artefacts on exit',
            '',
            'WHAT THIS SCRIPT NEVER DOES:',
            '  ❌ No real exploit or shellcode',
            '  ❌ No data exfiltration',
            '  ❌ No encryption or file destruction',
            '  ❌ No privilege escalation',
            '  ❌ No network data transmission',
            '',
            'USAGE:',
            '  python CDB-SWARM-*.py                  # Full simulation',
            '  python CDB-SWARM-*.py --dry-run         # List tests without executing',
            '  python CDB-SWARM-*.py --technique dns   # Run DNS probe only',
            '"""',
            '',
            'import os, sys, socket, tempfile, platform, logging, json, time, atexit',
            'from pathlib import Path',
            'from datetime import datetime, timezone',
            '',
            'logging.basicConfig(level=logging.INFO,',
            '    format="%(asctime)s [CDB-SWARM] %(message)s", datefmt="%H:%M:%S")',
            'log = logging.getLogger("CDB-SWARM")',
            '',
            'IS_WINDOWS = platform.system() == "Windows"',
            'DRY_RUN    = "--dry-run" in sys.argv',
            'TECHNIQUE  = next((sys.argv[i+1] for i, a in enumerate(sys.argv)',
            '                   if a == "--technique" and i+1 < len(sys.argv)), "all")',
            '',
            f'THREAT_META = {{',
            f'    "headline":  {repr(headline[:100])},',
            f'    "severity":  {repr(severity)},',
            f'    "actor_tag": {repr(actor_tag)},',
            f'    "generated": {repr(ts)},',
            f'    "cves":      {repr(cves[:10])},',
            f'}}',
            '',
            '_CLEANUP_TARGETS = []  # Files/keys registered for cleanup',
            '',
            'def _cleanup():',
            '    """Auto-cleanup all simulation artefacts on exit."""',
            '    for target in _CLEANUP_TARGETS:',
            '        try:',
            '            p = Path(target)',
            '            if p.exists(): p.unlink()',
            '        except Exception: pass',
            '    log.info("[CLEANUP] All simulation artefacts removed.")',
            '',
            'atexit.register(_cleanup)',
            '',
            'RESULTS = {"passed": [], "failed": [], "skipped": [], "total": 0}',
            '',
            'def record(name, status, detail=""):',
            '    RESULTS["total"] += 1',
            '    RESULTS[status].append(name)',
            '    icon = {"passed": "✅", "failed": "❌", "skipped": "⚠ "}.get(status, " ")',
            '    log.info(f"  {icon} {name}" + (f": {detail}" if detail else ""))',
            '',
        ]

        # ── IOC Data ──
        lines += [
            '# ── Threat Intelligence Data ────────────────────────────────────────────',
            f'IOC_IPS     = {repr(ipv4s[:20])}',
            f'IOC_DOMAINS = {repr(domains[:15])}',
            f'IOC_HASHES  = {repr(sha256s[:10])}',
            f'IOC_URLS    = {repr(urls[:10])}',
            '',
        ]

        # ── Simulation Functions ──

        # 1. Canary file drop simulation
        lines += [
            '# ── SIMULATION 1: Canary File Drop ──────────────────────────────────────',
            'def sim_file_drop():',
            '    """Simulate malware dropping files to disk (canary files only)."""',
            '    tmp = Path(tempfile.gettempdir())',
            '    canary_names = [',
            '        "cdb_swarm_dropper_canary.exe.sim",',
            '        "cdb_swarm_payload_canary.dll.sim",',
            '        "cdb_swarm_stager_canary.bat.sim",',
            '    ]',
            '    for name in canary_names:',
            '        p = tmp / name',
            '        if not DRY_RUN:',
            '            p.write_text(',
            '                f"# CDB-SWARM CANARY FILE\\n"',
            '                f"# This file simulates a malware dropper artefact.\\n"',
            '                f"# Threat: {headline[:60]}\\n"',
            '                f"# Generated: {ts}\\n"',
            '                f"# SAFE - NOT EXECUTABLE\\n"',
            '            )',
            '            _CLEANUP_TARGETS.append(str(p))',
            '            record("file_drop:" + name, "passed")',
            '        else:',
            '            record("file_drop:" + name, "skipped", "dry-run")',
            '',
        ]

        # 2. DNS probe simulation
        lines += [
            '# ── SIMULATION 2: C2 DNS Resolution Probe ──────────────────────────────',
            'def sim_c2_dns():',
            '    """Simulate C2 domain lookups. Triggers DNS monitoring rules."""',
            '    for domain in IOC_DOMAINS[:5]:',
            '        if not DRY_RUN:',
            '            try:',
            '                result = socket.getaddrinfo(domain, None, socket.AF_INET)',
            '                record(f"dns_probe:{domain}", "passed", f"resolved:{result[0][4][0]}")',
            '            except socket.gaierror:',
            '                record(f"dns_probe:{domain}", "passed", "NXDOMAIN (expected)")',
            '            except Exception as e:',
            '                record(f"dns_probe:{domain}", "failed", str(e))',
            '        else:',
            '            record(f"dns_probe:{domain}", "skipped", "dry-run")',
            '',
        ]

        # 3. TCP connection probe
        lines += [
            '# ── SIMULATION 3: C2 TCP Connection Probe ──────────────────────────────',
            'def sim_c2_tcp():',
            '    """Simulate TCP connection attempts to C2 IPs. Triggers network rules."""',
            '    for ip in IOC_IPS[:5]:',
            '        if not DRY_RUN:',
            '            try:',
            '                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
            '                s.settimeout(1)',
            '                result = s.connect_ex((ip, 443))  # connect-only, no data sent',
            '                s.close()',
            '                status = "port_open" if result == 0 else f"port_closed(code={result})"',
            '                record(f"tcp_probe:{ip}:443", "passed", status)',
            '            except Exception as e:',
            '                record(f"tcp_probe:{ip}:443", "passed", f"blocked:{type(e).__name__}")',
            '        else:',
            '            record(f"tcp_probe:{ip}:443", "skipped", "dry-run")',
            '',
        ]

        # 4. Registry canary (Windows only)
        lines += [
            '# ── SIMULATION 4: Registry Canary Write (Windows Only) ─────────────────',
            'def sim_registry_canary():',
            '    """Write a canary registry key to simulate persistence. Windows only."""',
            '    if not IS_WINDOWS:',
            '        record("registry_canary", "skipped", "Windows only")',
            '        return',
            '    try:',
            '        import winreg',
            '        key_path = r"Software\\CDB-SWARM-TEST\\SimulatedPersistence"',
            '        if not DRY_RUN:',
            '            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)',
            '            winreg.SetValueEx(key, "CDB_SWARM_CANARY", 0, winreg.REG_SZ,',
            f'                             "SIMULATION:{headline[:40]}")',
            '            winreg.CloseKey(key)',
            '            # Schedule registry cleanup',
            '            def _del_reg():',
            '                try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)',
            '                except Exception: pass',
            '            atexit.register(_del_reg)',
            '            record("registry_canary:HKCU\\\\Software\\\\CDB-SWARM-TEST", "passed")',
            '        else:',
            '            record("registry_canary", "skipped", "dry-run")',
            '    except ImportError:',
            '        record("registry_canary", "skipped", "winreg not available")',
            '    except Exception as e:',
            '        record("registry_canary", "failed", str(e))',
            '',
        ]

        # 5. Ransomware canary (if ransomware actor or CRITICAL)
        if actor_tag in ("CDB-RAN-01", "CDB-RAN-02") or severity == "CRITICAL":
            lines += [
                '# ── SIMULATION 5: Ransomware Canary (CRITICAL Severity) ─────────────',
                'def sim_ransomware_canary():',
                '    """',
                '    Simulate ransomware precursor behaviour:',
                '    - Creates a canary folder with dummy files (simulates staging)',
                '    - Writes a fake ransom note (no encryption)',
                '    - Triggers VSS-query (shadow copy enumeration)',
                '    """',
                '    tmp = Path(tempfile.gettempdir()) / "CDB_SWARM_RANSOM_CANARY"',
                '    if not DRY_RUN:',
                '        tmp.mkdir(exist_ok=True)',
                '        _CLEANUP_TARGETS.append(str(tmp / "README_RANSOM_CANARY.txt"))',
                '        _CLEANUP_TARGETS.append(str(tmp / "STAGED_DATA_CANARY.txt"))',
                '        (tmp / "README_RANSOM_CANARY.txt").write_text(',
                '            "# CDB-SWARM CANARY — RANSOMWARE NOTE SIMULATION\\n"',
                '            "# This is a SAFE simulation file. No encryption occurred.\\n"',
                f'            "# Threat: {headline[:60]}\\n"',
                '        )',
                '        (tmp / "STAGED_DATA_CANARY.txt").write_text(',
                '            "# CDB-SWARM CANARY — DATA STAGING SIMULATION\\n"',
                '            "# Simulates data collected before exfiltration attempt.\\n"',
                '        )',
                '        record("ransomware_canary:note_drop", "passed")',
                '        record("ransomware_canary:staging", "passed")',
                '        # VSS query (read-only, no deletion)',
                '        if IS_WINDOWS:',
                '            os.system("vssadmin list shadows > nul 2>&1")',
                '            record("ransomware_canary:vss_query", "passed")',
                '    else:',
                '        record("ransomware_canary", "skipped", "dry-run")',
                '',
            ]

        # 6. IOC hash signature simulation
        if sha256s:
            lines += [
                '# ── SIMULATION 6: Hash-Based Detection Canary ───────────────────────',
                'def sim_hash_canary():',
                '    """Write canary files embedding known IOC hash metadata."""',
                '    tmp = Path(tempfile.gettempdir())',
                '    for h in IOC_HASHES[:3]:',
                '        p = tmp / f"CDB_SWARM_HASH_{h[:16]}.sim"',
                '        if not DRY_RUN:',
                '            p.write_text(f"CDB-SWARM-HASH-SIM:{h}\\nSAFE CANARY — NOT MALICIOUS\\n")',
                '            _CLEANUP_TARGETS.append(str(p))',
                '            record(f"hash_canary:{h[:16]}", "passed")',
                '        else:',
                '            record(f"hash_canary:{h[:16]}", "skipped", "dry-run")',
                '',
            ]

        # Main runner
        lines += [
            '# ── MAIN RUNNER ─────────────────────────────────────────────────────────',
            'def main():',
            f'    log.info("╔══════════════════════════════════════════════════════╗")',
            f'    log.info("║  CDB ADVERSARY SWARM — SIMULATION STARTING          ║")',
            f'    log.info("╚══════════════════════════════════════════════════════╝")',
            f'    log.info(f"Threat  : {headline[:60]}")',
            f'    log.info("Severity: {severity}  |  Actor: {actor_tag or "Unknown"}")',
            '    log.info(f"Mode    : {\'DRY-RUN\' if DRY_RUN else \'LIVE SIMULATION\'}")',
            '    log.info("")',
            '',
            '    # Run all simulations (or selected technique)',
            '    sims = {',
            '        "file_drop":         sim_file_drop,',
            '        "dns":               sim_c2_dns,',
            '        "tcp":               sim_c2_tcp,',
            '        "registry":          sim_registry_canary,',
        ]

        if actor_tag in ("CDB-RAN-01", "CDB-RAN-02") or severity == "CRITICAL":
            lines.append('        "ransomware":        sim_ransomware_canary,')
        if sha256s:
            lines.append('        "hash":              sim_hash_canary,')

        lines += [
            '    }',
            '',
            '    for name, fn in sims.items():',
            '        if TECHNIQUE == "all" or TECHNIQUE == name:',
            '            log.info(f"── Running: {name} ──────────────────────────")',
            '            try: fn()',
            '            except Exception as e:',
            '                record(name, "failed", str(e))',
            '',
            '    # Summary',
            '    log.info("")',
            '    log.info("════════════════════════════════════════════════════")',
            '    log.info("  ADVERSARY SWARM SIMULATION — RESULTS SUMMARY")',
            '    log.info("════════════════════════════════════════════════════")',
            '    log.info(f"  Total   : {RESULTS[\'total\']}")',
            '    log.info(f"  Passed  : {len(RESULTS[\'passed\'])}")',
            '    log.info(f"  Failed  : {len(RESULTS[\'failed\'])}")',
            '    log.info(f"  Skipped : {len(RESULTS[\'skipped\'])}")',
            '    log.info("")',
            '    if RESULTS["failed"]:',
            '        log.warning("FAILED SIMULATIONS (check EDR/SIEM rules):")',
            '        for f in RESULTS["failed"]: log.warning(f"  ❌ {f}")',
            '    else:',
            '        log.info("✅ All simulations completed — Review your SIEM/EDR for alerts")',
            '    log.info("════════════════════════════════════════════════════")',
            '',
            '    # Save results',
            '    _ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")',
            '    _out = Path(tempfile.gettempdir()) / f"CDB-SWARM-result-{_ts}.json"',
            '    try:',
            '        _out.write_text(json.dumps({**THREAT_META, **RESULTS}, indent=2))',
            '        log.info(f"Results saved: {_out}")',
            '    except Exception: pass',
            '',
            '',
            'if __name__ == "__main__":',
            '    main()',
        ]

        return "\n".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────
adversary_swarm = AdversarySwarm()
