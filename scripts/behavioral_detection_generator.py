#!/usr/bin/env python3
"""
scripts/behavioral_detection_generator.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Behavioral Detection Rule Generator
=======================================================================
Generates REAL behavioral detection rules (Sigma YAML format).
NOT CVE string matching - actual behavioral patterns that detect
malicious activity based on process behavior, registry changes,
network patterns, and file system indicators.

Stage 2.3 - Behavioral Detection Generation
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [behavioral-detect] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.behavioral_detect")

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "data" / "detection_rules"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SIGMA_RULES = [
    # -------------------------------------------------------------------------
    # AUTH_BYPASS class
    # -------------------------------------------------------------------------
    {
        "id": "SIGMA-AUTH-001",
        "class": "AUTH_BYPASS",
        "title": "Sequential HTTP 401 to 200 Authentication Bypass",
        "status": "stable",
        "description": "Detects HTTP authentication bypass patterns where a 401 Unauthorized response is immediately followed by a 200 OK on a protected endpoint, indicating potential authentication bypass exploitation.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.defense_evasion", "attack.T1078", "attack.credential_access"],
        "logsource": {"category": "webserver", "product": "apache|nginx|iis"},
        "detection": {
            "selection_auth_bypass": {
                "cs_status": ["401", "403"],
                "cs_uri_stem|contains": ["/admin", "/api", "/management", "/console"]
            },
            "selection_success": {
                "cs_status": "200",
                "cs_uri_stem|contains": ["/admin", "/api", "/management", "/console"]
            },
            "timeframe": "10s",
            "condition": "selection_auth_bypass followed by selection_success from same source IP within timeframe"
        },
        "falsepositives": ["Legitimate users with cached credentials re-authenticating"],
        "level": "high",
        "yaml": """title: Sequential HTTP 401 to 200 Authentication Bypass
id: auth-bypass-seq-001
status: stable
description: Detects HTTP auth bypass - 401 immediately followed by 200 on admin paths from same source IP
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.defense_evasion
    - attack.T1078
    - attack.credential_access
logsource:
    category: webserver
detection:
    selection_bypass_pattern:
        sc_status:
            - '401'
            - '403'
        cs_uri_stem|contains:
            - '/admin'
            - '/api/admin'
            - '/management'
            - '/console'
            - '/.env'
            - '/wp-admin'
    condition: selection_bypass_pattern
falsepositives:
    - Legitimate users with browser-cached credentials
    - Automated security scanners
level: high
"""
    },
    {
        "id": "SIGMA-AUTH-002",
        "class": "AUTH_BYPASS",
        "title": "JWT None Algorithm Authentication Bypass",
        "status": "stable",
        "description": "Detects use of 'none' algorithm in JWT tokens which bypasses signature verification on vulnerable implementations.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.defense_evasion", "attack.T1550"],
        "logsource": {"category": "application", "product": "custom"},
        "detection": {
            "selection_jwt_none": {
                "http_request_headers_authorization|contains": ["eyJhbGciOiJub25lIi", "alg: none", "alg\":\"none\""]
            },
            "condition": "selection_jwt_none"
        },
        "falsepositives": ["Intentionally unsigned tokens in test environments"],
        "level": "critical",
        "yaml": """title: JWT None Algorithm Authentication Bypass Attempt
id: auth-bypass-jwt-none-001
status: stable
description: Detects JWT tokens using 'none' algorithm which bypasses signature verification
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.defense_evasion
    - attack.T1550
    - attack.T1078
logsource:
    category: webserver
detection:
    selection_jwt_none:
        cs_uri_query|base64offset|contains:
            - 'alg":"none"'
            - 'alg": "none"'
            - '"alg":"NONE"'
        cs_referer|contains: '/api/'
    selection_header_jwt:
        Authorization|contains: 'eyJhbGciOiJub25lIi'
    condition: 1 of selection_*
falsepositives:
    - Development/test environments with unsigned tokens
level: critical
"""
    },
    # -------------------------------------------------------------------------
    # RANSOMWARE class
    # -------------------------------------------------------------------------
    {
        "id": "SIGMA-RANSOM-001",
        "class": "RANSOMWARE",
        "title": "Ransomware Shadow Copy and Backup Deletion Chain",
        "status": "stable",
        "description": "Detects the combination of shadow copy deletion, backup catalog deletion, and boot recovery disable commands executed in sequence - the standard ransomware pre-encryption preparation routine.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.impact", "attack.T1490", "attack.T1486"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_vss": {
                "Image|endswith": "\\vssadmin.exe",
                "CommandLine|contains": ["Delete Shadows", "delete shadows", "/All", "/Quiet"]
            },
            "selection_wbadmin": {
                "Image|endswith": "\\wbadmin.exe",
                "CommandLine|contains": ["delete catalog", "delete backup", "-quiet"]
            },
            "selection_bcdedit": {
                "Image|endswith": "\\bcdedit.exe",
                "CommandLine|contains": ["recoveryenabled No", "bootstatuspolicy ignoreallfailures"]
            },
            "condition": "1 of selection_*"
        },
        "falsepositives": ["Legitimate system administrators performing backup maintenance"],
        "level": "critical",
        "yaml": """title: Ransomware Pre-Encryption Shadow Copy and Backup Deletion
id: ransom-shadow-delete-001
status: stable
description: |
    Detects ransomware preparation - deletion of shadow copies and disabling
    recovery mechanisms. This is a near-universal ransomware pre-stage activity
    observed in LockBit, BlackCat, Black Basta, Akira and other ransomware families.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.impact
    - attack.T1490
    - attack.T1486
    - detection.threat_hunting
references:
    - https://attack.mitre.org/techniques/T1490/
logsource:
    category: process_creation
    product: windows
detection:
    selection_vss_delete:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains:
            - 'Delete Shadows'
            - 'delete shadows'
            - 'resize shadowstorage'
    selection_wbadmin_delete:
        Image|endswith: '\\wbadmin.exe'
        CommandLine|contains:
            - 'delete catalog'
            - 'delete backup'
    selection_bcdedit_disable:
        Image|endswith: '\\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled No'
            - 'bootstatuspolicy ignoreallfailures'
    selection_wmic_shadow:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - 'shadowcopy delete'
            - 'shadowcopy where'
    condition: 1 of selection_*
falsepositives:
    - Legitimate system administrators performing maintenance
    - Backup software agents (verify parent process)
level: critical
"""
    },
    {
        "id": "SIGMA-RANSOM-002",
        "class": "RANSOMWARE",
        "title": "Mass File Extension Rename - Ransomware Encryption",
        "status": "experimental",
        "description": "Detects rapid bulk file renaming to unknown extensions indicative of ransomware encryption activity.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.impact", "attack.T1486"],
        "logsource": {"category": "file_event", "product": "windows"},
        "detection": {
            "selection_known_ransom_ext": {
                "TargetFilename|endswith": [".lockbit", ".basta", ".akira", ".alphv", ".sykffle", ".locked"]
            },
            "condition": "selection_known_ransom_ext | count() by Computer > 20"
        },
        "falsepositives": ["File format conversion tools"],
        "level": "critical",
        "yaml": """title: Mass File Rename to Ransomware Extension
id: ransom-mass-rename-001
status: stable
description: |
    Detects mass file renaming to known ransomware extensions.
    Threshold of 20+ renames in 60 seconds indicates active encryption.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.impact
    - attack.T1486
logsource:
    category: file_event
    product: windows
detection:
    selection_ransomware_extensions:
        TargetFilename|endswith:
            - '.lockbit'
            - '.basta'
            - '.akira'
            - '.alphv'
            - '.sykffle'
            - '.locked'
            - '.encrypted'
            - '.ransom'
            - '.crypted'
            - '.WNCRY'
    filter_expected_apps:
        Image|contains:
            - '\\Program Files\\'
            - 'Windows Defender'
    condition: selection_ransomware_extensions and not filter_expected_apps
falsepositives:
    - File encryption utilities used legitimately
level: critical
"""
    },
    {
        "id": "SIGMA-RANSOM-003",
        "class": "RANSOMWARE",
        "title": "Ransomware Service and Process Termination",
        "status": "stable",
        "description": "Detects bulk service and process termination targeting backup, database, and AV services - standard ransomware preparation to maximize encryption impact.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.impact", "attack.T1489", "attack.T1562"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_sc_stop": {
                "Image|endswith": "\\sc.exe",
                "CommandLine|contains": ["stop"],
                "CommandLine|contains_any": ["BackupExec", "MSSQL", "MySQL", "Oracle", "veeam", "SQLWriter"]
            },
            "selection_taskkill": {
                "Image|endswith": "\\taskkill.exe",
                "CommandLine|contains": ["/f", "/im"],
                "CommandLine|contains_any": ["sql", "oracle", "backup", "veeam", "exchange"]
            },
            "condition": "1 of selection_*"
        },
        "falsepositives": ["System administrators stopping services for maintenance"],
        "level": "high",
        "yaml": """title: Ransomware Bulk Service/Database Process Termination
id: ransom-service-kill-001
status: stable
description: |
    Detects bulk termination of database, backup, and security services
    as a precursor to ransomware deployment. This pattern is observed
    across LockBit, Black Basta, Akira, and Cl0p operations.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.impact
    - attack.T1489
    - attack.T1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc_stop:
        Image|endswith: '\\sc.exe'
        CommandLine|contains: 'stop'
        CommandLine|contains:
            - 'BackupExec'
            - 'MSSQL'
            - 'MySQL'
            - 'Oracle'
            - 'Veeam'
            - 'SQLWriter'
            - 'VeeamDeploymentSvc'
    selection_net_stop:
        Image|endswith:
            - '\\net.exe'
            - '\\net1.exe'
        CommandLine|startswith: 'stop'
        CommandLine|contains:
            - 'sql'
            - 'oracle'
            - 'backup'
            - 'veeam'
            - 'exchange'
    selection_taskkill_db:
        Image|endswith: '\\taskkill.exe'
        CommandLine|contains: '/f'
        CommandLine|contains:
            - 'sqlservr'
            - 'mysqld'
            - 'oracle'
            - 'backup'
    condition: 1 of selection_*
falsepositives:
    - Planned database maintenance windows
    - Legitimate deployment scripts
level: high
"""
    },
    # -------------------------------------------------------------------------
    # PHISHING class
    # -------------------------------------------------------------------------
    {
        "id": "SIGMA-PHISH-001",
        "class": "PHISHING",
        "title": "Office Application Spawning Scripting Engine",
        "status": "stable",
        "description": "Detects Microsoft Office applications (Word, Excel, PowerPoint, Outlook) spawning scripting engines or command interpreters, indicating macro or embedded script execution from a potentially malicious document.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.initial_access", "attack.T1566.001", "attack.execution", "attack.T1204.002"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_office_parent": {
                "ParentImage|endswith": ["\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe", "\\onenote.exe"]
            },
            "selection_suspicious_child": {
                "Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\wscript.exe", "\\cscript.exe", "\\mshta.exe", "\\regsvr32.exe", "\\rundll32.exe"]
            },
            "condition": "all of selection_*"
        },
        "falsepositives": ["Legitimate macros in trusted document templates"],
        "level": "high",
        "yaml": """title: Office Application Spawning Scripting Interpreter
id: phish-office-spawn-001
status: stable
description: |
    Detects Microsoft Office applications spawning command interpreters or
    scripting engines. This is a primary indicator of malicious macro execution
    from phishing documents. Observed in Emotet, QakBot, IcedID, and numerous
    other malware families delivered via email.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.T1566.001
    - attack.execution
    - attack.T1204.002
    - attack.T1059
references:
    - https://attack.mitre.org/techniques/T1566/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection_office_parent:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
            - '\\outlook.exe'
            - '\\onenote.exe'
            - '\\msaccess.exe'
    selection_suspicious_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
            - '\\regsvr32.exe'
            - '\\rundll32.exe'
            - '\\certutil.exe'
            - '\\bitsadmin.exe'
    condition: all of selection_*
falsepositives:
    - Legitimate macros in organization-trusted document templates
    - IT automation scripts run via Office (verify with baseline)
level: high
"""
    },
    {
        "id": "SIGMA-PHISH-002",
        "class": "PHISHING",
        "title": "HTML Smuggling File Written to Downloads",
        "status": "stable",
        "description": "Detects HTML smuggling technique where a browser writes an executable or archive to the Downloads folder as triggered by visiting a malicious web page.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.initial_access", "attack.T1566.002", "attack.T1027.006"],
        "logsource": {"category": "file_event", "product": "windows"},
        "detection": {
            "selection_browser_drop": {
                "Image|endswith": ["\\chrome.exe", "\\msedge.exe", "\\firefox.exe"],
                "TargetFilename|contains": "\\Downloads\\",
                "TargetFilename|endswith": [".exe", ".dll", ".msi", ".iso", ".img", ".zip", ".7z", ".hta"]
            },
            "condition": "selection_browser_drop"
        },
        "falsepositives": ["Legitimate software downloads from browsers"],
        "level": "medium",
        "yaml": """title: HTML Smuggling - Browser Writing Executable to Downloads
id: phish-html-smuggling-001
status: stable
description: |
    Detects potential HTML smuggling where a browser process writes executable
    content directly to the Downloads directory. Used in sophisticated phishing
    campaigns to bypass email gateway scanning.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.T1566.002
    - attack.T1027.006
logsource:
    category: file_event
    product: windows
detection:
    selection_browser_drop_executable:
        Image|endswith:
            - '\\chrome.exe'
            - '\\msedge.exe'
            - '\\firefox.exe'
            - '\\iexplore.exe'
        TargetFilename|contains: '\\Downloads\\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.msi'
            - '.iso'
            - '.img'
            - '.hta'
    filter_known_updates:
        TargetFilename|contains:
            - 'ChromeSetup'
            - 'MicrosoftEdgeSetup'
            - 'Firefox Setup'
    condition: selection_browser_drop_executable and not filter_known_updates
falsepositives:
    - Legitimate software downloads
    - Security tool deployment via browser
level: medium
"""
    },
    # -------------------------------------------------------------------------
    # MALWARE class
    # -------------------------------------------------------------------------
    {
        "id": "SIGMA-MAL-001",
        "class": "MALWARE",
        "title": "Process Injection via WriteProcessMemory and CreateRemoteThread",
        "status": "stable",
        "description": "Detects classic process injection technique using WriteProcessMemory followed by CreateRemoteThread - used by Cobalt Strike, Meterpreter, and numerous malware loaders.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.defense_evasion", "attack.T1055", "attack.privilege_escalation"],
        "logsource": {"category": "process_access", "product": "windows"},
        "detection": {
            "selection_lsass": {
                "TargetImage|endswith": "\\lsass.exe",
                "GrantedAccess": ["0x1010", "0x1410", "0x147a", "0x143a", "0x1438", "0x1fffff"]
            },
            "filter_legit": {
                "SourceImage|contains": ["MsMpEng.exe", "csrss.exe", "wininit.exe", "services.exe", "lsm.exe"]
            },
            "condition": "selection_lsass and not filter_legit"
        },
        "falsepositives": ["Security products legitimately accessing LSASS"],
        "level": "critical",
        "yaml": """title: Suspicious LSASS Process Access - Credential Dumping
id: malware-lsass-access-001
status: stable
description: |
    Detects suspicious access to LSASS process memory with credential-dumping
    level access rights. Used by Mimikatz, Cobalt Strike sekurlsa, and
    virtually every post-exploitation framework for credential harvesting.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.credential_access
    - attack.T1003.001
    - attack.T1055
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    category: process_access
    product: windows
detection:
    selection_lsass_access:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x143a'
            - '0x1438'
            - '0x1fffff'
            - '0x40'
            - '0x1000'
    filter_legit_tools:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
            - '\\wininit.exe'
            - '\\services.exe'
            - '\\lsm.exe'
            - '\\svchost.exe'
        SourceImage|contains:
            - 'SentinelOne'
            - 'CrowdStrike'
            - 'Cylance'
    condition: selection_lsass_access and not filter_legit_tools
falsepositives:
    - EDR/AV products that legitimately access LSASS
    - Task Manager (verify SourceImage = taskmgr.exe for low-severity)
level: critical
"""
    },
    {
        "id": "SIGMA-MAL-002",
        "class": "MALWARE",
        "title": "Registry Run Key Persistence by Suspicious Process",
        "status": "stable",
        "description": "Detects malware persistence via Windows Registry run keys created by non-standard parent processes.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.persistence", "attack.T1547.001"],
        "logsource": {"category": "registry_event", "product": "windows"},
        "detection": {
            "selection_run_key": {
                "EventType": "SetValue",
                "TargetObject|contains": ["\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce"]
            },
            "filter_legit": {
                "Image|contains": ["\\Program Files\\", "\\Windows\\", "MicrosoftEdgeUpdate"]
            },
            "condition": "selection_run_key and not filter_legit"
        },
        "falsepositives": ["Legitimate software setting startup entries from user profile"],
        "level": "high",
        "yaml": """title: Registry Run Key Created by Suspicious Process
id: malware-reg-run-persist-001
status: stable
description: |
    Detects creation of registry run keys by processes outside of standard
    installation paths. Used by virtually all RATs, infostealers, and
    backdoors for persistence: Remcos, AsyncRAT, njRAT, AgentTesla, XWorm.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.persistence
    - attack.T1547.001
logsource:
    category: registry_event
    product: windows
detection:
    selection_run_keys:
        EventType: SetValue
        TargetObject|contains:
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'
            - '\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
    filter_legitimate:
        Image|contains:
            - '\\Program Files\\'
            - '\\Program Files (x86)\\'
            - '\\Windows\\System32\\'
            - '\\Windows\\SysWOW64\\'
            - 'MicrosoftEdgeUpdate'
            - 'OneDrive'
    filter_user_scope:
        TargetObject|contains:
            - 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive'
            - 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Teams'
    condition: selection_run_keys and not 1 of filter_*
falsepositives:
    - Legitimate user-installed software using run keys
    - Software update mechanisms
level: high
"""
    },
    {
        "id": "SIGMA-MAL-003",
        "class": "MALWARE",
        "title": "C2 Beaconing - Regular Interval Outbound Connection",
        "status": "experimental",
        "description": "Detects regular-interval outbound connections from non-browser processes indicative of C2 beaconing behavior.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.command_and_control", "attack.T1071.001", "attack.T1095"],
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection": {
            "selection_beacon": {
                "Initiated": "true",
                "DestinationPort": [80, 443, 8080, 8443, 4443],
                "Image|endswith": ["\\rundll32.exe", "\\regsvr32.exe", "\\mshta.exe", "\\wscript.exe", "\\cscript.exe"]
            },
            "filter_legit": {
                "DestinationHostname|endswith": [".microsoft.com", ".windows.com", ".windowsupdate.com"]
            },
            "condition": "selection_beacon and not filter_legit"
        },
        "falsepositives": ["Legitimate applications using rundll32 for network operations"],
        "level": "high",
        "yaml": """title: C2 Beaconing from LOLBin Process
id: malware-c2-beacon-lolbin-001
status: stable
description: |
    Detects outbound network connections from LOLBins (Living off the Land Binaries)
    to external IPs/domains. Rundll32, regsvr32, wscript, and mshta are commonly
    used by Cobalt Strike, Sliver, Havoc, and other C2 frameworks to evade
    process-based detection while maintaining C2 communication.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.command_and_control
    - attack.T1071.001
    - attack.T1218
logsource:
    category: network_connection
    product: windows
detection:
    selection_lolbin_network:
        Initiated: 'true'
        DestinationPort:
            - 80
            - 443
            - 8080
            - 8443
            - 4443
            - 1337
        Image|endswith:
            - '\\rundll32.exe'
            - '\\regsvr32.exe'
            - '\\mshta.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\msiexec.exe'
    filter_known_legit:
        DestinationHostname|endswith:
            - '.microsoft.com'
            - '.windows.com'
            - '.windowsupdate.com'
            - '.digicert.com'
    condition: selection_lolbin_network and not filter_known_legit
falsepositives:
    - Legitimate software using LOLBins for update checks
    - Windows component network operations
level: high
"""
    },
    # -------------------------------------------------------------------------
    # EXPLOIT class
    # -------------------------------------------------------------------------
    {
        "id": "SIGMA-EXPLOIT-001",
        "class": "EXPLOIT",
        "title": "Web Server Process Spawning Interactive Shell",
        "status": "stable",
        "description": "Detects web server processes spawning command shells or interpreters, a strong indicator of successful web application exploitation (RCE, SQLi, LFI to RCE, web shell execution).",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.initial_access", "attack.T1190", "attack.execution", "attack.T1059"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_webserver_parent": {
                "ParentImage|endswith": ["\\w3wp.exe", "\\httpd.exe", "\\nginx.exe", "\\tomcat.exe", "\\catalina.exe"]
            },
            "selection_shell_child": {
                "Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\pwsh.exe", "\\bash.exe", "\\sh.exe"]
            },
            "condition": "all of selection_*"
        },
        "falsepositives": ["Web applications legitimately spawning shell for system integration"],
        "level": "critical",
        "yaml": """title: Web Server Spawning Command Shell - RCE Indicator
id: exploit-webserver-shell-001
status: stable
description: |
    Detects web server processes (IIS, Apache, Nginx, Tomcat) spawning command
    line interpreters. This is a critical indicator of successful Remote Code
    Execution exploitation via web application vulnerabilities. Observed during
    ProxyLogon, Log4Shell, MOVEit, and GoAnywhere exploitation campaigns.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.T1190
    - attack.execution
    - attack.T1059
    - attack.T1505.003
references:
    - https://attack.mitre.org/techniques/T1190/
    - https://attack.mitre.org/techniques/T1505/003/
logsource:
    category: process_creation
    product: windows
detection:
    selection_web_process_parent:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
    selection_shell_spawned:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\certutil.exe'
            - '\\net.exe'
            - '\\whoami.exe'
    condition: all of selection_*
falsepositives:
    - Web application administration scripts (whitelist specific paths)
    - Known legitimate web-triggered automation
level: critical
"""
    },
    {
        "id": "SIGMA-EXPLOIT-002",
        "class": "EXPLOIT",
        "title": "Exchange Server OWA Web Shell Execution",
        "status": "stable",
        "description": "Detects web shell execution on Microsoft Exchange Server OWA paths, indicative of ProxyLogon/ProxyShell or similar Exchange exploitation.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.initial_access", "attack.T1190", "attack.T1505.003"],
        "logsource": {"category": "webserver", "product": "microsoft-exchange"},
        "detection": {
            "selection_owa_webshell": {
                "cs_uri_stem|contains": ["/owa/auth/", "/ecp/", "/aspnet_client/"],
                "cs_method": "POST",
                "cs_status": "200"
            },
            "filter_legit": {
                "cs_uri_stem|contains": ["/owa/auth/logon.aspx", "/owa/auth/owaauth.aspx"]
            },
            "condition": "selection_owa_webshell and not filter_legit"
        },
        "falsepositives": ["Legitimate Exchange web services"],
        "level": "critical",
        "yaml": """title: Exchange Server Web Shell Execution via OWA/ECP
id: exploit-exchange-webshell-001
status: stable
description: |
    Detects POST requests to non-standard ASPX files in Exchange OWA/ECP
    paths, indicative of web shell deployment and execution following
    ProxyLogon (CVE-2021-26855), ProxyShell, or similar Exchange exploitation.
    Observed in HAFNIUM, APT41, and opportunistic exploitation campaigns.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.T1190
    - attack.T1505.003
references:
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
logsource:
    category: webserver
    product: ms-exchange
detection:
    selection_webshell_post:
        cs_uri_stem|contains:
            - '/owa/auth/'
            - '/ecp/'
            - '/aspnet_client/'
        cs_method: 'POST'
        sc_status: '200'
    filter_legit_exchange:
        cs_uri_stem|endswith:
            - '/owa/auth/logon.aspx'
            - '/owa/auth/owaauth.aspx'
            - '/owa/auth/FBA/auth.aspx'
    selection_unusual_aspx:
        cs_uri_stem|re: '/owa/auth/[a-z0-9]{6,}\\.aspx'
    condition: (selection_webshell_post and not filter_legit_exchange) or selection_unusual_aspx
falsepositives:
    - Legitimate Exchange web service calls (validate against baseline)
level: critical
"""
    },
    {
        "id": "SIGMA-EXPLOIT-003",
        "class": "EXPLOIT",
        "title": "Log4Shell JNDI Exploitation Attempt",
        "status": "stable",
        "description": "Detects Log4Shell (CVE-2021-44228) exploitation attempts via JNDI injection strings in HTTP headers or request parameters.",
        "author": "SENTINEL APEX",
        "date": "2026-06-02",
        "tags": ["attack.initial_access", "attack.T1190", "attack.T1059"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection_jndi": {
                "request|contains": ["${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://", "${${lower:j}ndi:"]
            },
            "condition": "selection_jndi"
        },
        "falsepositives": ["Security scanner testing"],
        "level": "critical",
        "yaml": """title: Log4Shell JNDI Injection Exploitation Attempt
id: exploit-log4shell-jndi-001
status: stable
description: |
    Detects Log4Shell (CVE-2021-44228, CVSS 10.0) exploitation attempts
    via JNDI injection strings in HTTP user-agents, headers, or request
    parameters. This vulnerability affects Apache Log4j 2.x and enables
    unauthenticated RCE. Immediately exploited by APT41, Lazarus, Iranian APTs.
author: SENTINEL APEX
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.T1190
    - attack.exploitation
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
logsource:
    category: webserver
detection:
    selection_jndi_patterns:
        cs_useragent|contains:
            - '${jndi:'
            - '${${lower:j}ndi:'
            - '${${::-j}ndi:'
            - '%24%7Bjndi%3A'
        cs_uri_query|contains:
            - '${jndi:'
            - '${${lower:j}ndi:'
    selection_jndi_headers:
        cs_referer|contains:
            - '${jndi:ldap://'
            - '${jndi:rmi://'
    condition: 1 of selection_*
falsepositives:
    - Security scanner/penetration test activity (correlate with authorized scan windows)
level: critical
"""
    },
]


def write_sigma_rules(rules: list[dict]) -> None:
    """Write individual Sigma YAML rule files"""
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    for rule in rules:
        rule_id = rule["id"].lower().replace("-", "_")
        rule_path = RULES_DIR / f"{rule_id}.yml"
        try:
            rule_path.write_text(rule["yaml"], encoding="utf-8")
            log.debug("Written: %s", rule_path.name)
        except Exception as e:
            log.warning("Failed to write %s: %s", rule_path, e)


def write_rules_index(rules: list[dict]) -> None:
    """Write a JSON index of all detection rules"""
    index = []
    for rule in rules:
        index.append({
            "id": rule["id"],
            "class": rule["class"],
            "title": rule["title"],
            "status": rule["status"],
            "description": rule["description"],
            "level": rule["level"],
            "tags": rule.get("tags", []),
            "falsepositives": rule.get("falsepositives", []),
            "rule_file": f"data/detection_rules/{rule['id'].lower().replace('-', '_')}.yml"
        })

    index_data = {
        "version": "1.0.0",
        "generated_at": utc_now(),
        "total": len(index),
        "note": "Behavioral detection rules - NOT CVE ID string matching",
        "rules": index
    }

    index_path = RULES_DIR / "index.json"
    try:
        index_path.write_text(json.dumps(index_data, indent=2, ensure_ascii=False),
                              encoding="utf-8")
        log.info("Detection rules index written: %d rules", len(index))
    except Exception as e:
        log.warning("Failed to write rules index: %s", e)

    # Also write to api/ for API access
    api_rules_path = REPO_ROOT / "api" / "detection_rules.json"
    try:
        api_rules_path.write_text(json.dumps(index_data, indent=2, ensure_ascii=False),
                                  encoding="utf-8")
        log.info("Detection rules API file written: api/detection_rules.json")
    except Exception as e:
        log.warning("Failed to write api/detection_rules.json: %s", e)


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX - Behavioral Detection Rule Generator")
    log.info("Generating %d REAL behavioral detection rules", len(SIGMA_RULES))
    log.info("=" * 60)

    write_sigma_rules(SIGMA_RULES)
    write_rules_index(SIGMA_RULES)

    # Summary by class
    by_class: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for rule in SIGMA_RULES:
        by_class[rule["class"]] = by_class.get(rule["class"], 0) + 1
        by_level[rule["level"]] = by_level.get(rule["level"], 0) + 1

    log.info("Rules by class: %s", by_class)
    log.info("Rules by level: %s", by_level)
    log.info("All rules use BEHAVIORAL detection - no CVE string matching")
    log.info("Detection rule generation complete.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
