#!/usr/bin/env python3
"""
mitre_mapper.py — CyberDudeBivash v12.0 (SENTINEL APEX ULTRA)
REWRITE: Expanded from 8 keywords to 50+ high-fidelity triggers
covering all 14 MITRE ATT&CK tactics. Includes technique names
and descriptions for report enrichment.
"""


class MITREMapper:
    def __init__(self):
        # Comprehensive keyword → technique mapping
        self.mapping_db = {
            # ── RECONNAISSANCE ──
            "scanning": {"id": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning"},
            "osint": {"id": "T1593", "tactic": "Reconnaissance", "name": "Search Open Websites/Domains"},
            "reconnaissance": {"id": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning"},

            # ── RESOURCE DEVELOPMENT ──
            "typosquatting": {"id": "T1583.001", "tactic": "Resource Development", "name": "Acquire Infrastructure: Domains"},
            "fake website": {"id": "T1583.001", "tactic": "Resource Development", "name": "Acquire Infrastructure: Domains"},

            # ── INITIAL ACCESS ──
            "phishing": {"id": "T1566", "tactic": "Initial Access", "name": "Phishing"},
            "spearphishing": {"id": "T1566.001", "tactic": "Initial Access", "name": "Spearphishing Attachment"},
            "phishing link": {"id": "T1566.002", "tactic": "Initial Access", "name": "Spearphishing Link"},
            "exploit public": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
            "vulnerable api": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
            "api endpoint": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
            "drive-by": {"id": "T1189", "tactic": "Initial Access", "name": "Drive-by Compromise"},
            "supply chain": {"id": "T1195", "tactic": "Initial Access", "name": "Supply Chain Compromise"},
            "valid accounts": {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},
            "stolen credentials": {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},
            "default password": {"id": "T1078.001", "tactic": "Initial Access", "name": "Default Accounts"},
            "trusted relationship": {"id": "T1199", "tactic": "Initial Access", "name": "Trusted Relationship"},
            "third-party": {"id": "T1199", "tactic": "Initial Access", "name": "Trusted Relationship"},

            # ── EXECUTION ──
            "exploit": {"id": "T1203", "tactic": "Execution", "name": "Exploitation for Client Execution"},
            "powershell": {"id": "T1059.001", "tactic": "Execution", "name": "PowerShell"},
            "script": {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
            "command line": {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
            "macro": {"id": "T1204.002", "tactic": "Execution", "name": "Malicious File"},
            "malicious file": {"id": "T1204.002", "tactic": "Execution", "name": "Malicious File"},
            "malicious link": {"id": "T1204.001", "tactic": "Execution", "name": "Malicious Link"},
            "clickfix": {"id": "T1204.001", "tactic": "Execution", "name": "Malicious Link"},
            "nslookup": {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
            # User execution / social engineering (NEW)
            "duped": {"id": "T1204", "tactic": "Execution", "name": "User Execution"},
            "tricked": {"id": "T1204", "tactic": "Execution", "name": "User Execution"},
            "lured": {"id": "T1204", "tactic": "Execution", "name": "User Execution"},
            "users installed": {"id": "T1204", "tactic": "Execution", "name": "User Execution"},
            "fake ai": {"id": "T1204.001", "tactic": "Execution", "name": "Malicious Link"},
            "fake app": {"id": "T1204", "tactic": "Execution", "name": "User Execution"},

            # ── PERSISTENCE ──
            "persistence": {"id": "T1547", "tactic": "Persistence", "name": "Boot or Logon Autostart Execution"},
            "registry": {"id": "T1547.001", "tactic": "Persistence", "name": "Registry Run Keys"},
            "scheduled task": {"id": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task"},
            "web shell": {"id": "T1505.003", "tactic": "Persistence", "name": "Web Shell"},
            "backdoor": {"id": "T1547", "tactic": "Persistence", "name": "Boot or Logon Autostart Execution"},
            "implant": {"id": "T1547", "tactic": "Persistence", "name": "Boot or Logon Autostart Execution"},
            "boot": {"id": "T1542", "tactic": "Persistence", "name": "Pre-OS Boot"},
            # Browser Extension persistence (NEW - critical for extension attacks)
            "browser extension": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "chrome extension": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "fake extension": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "malicious extension": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "browser plugin": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "addon": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},
            "add-on": {"id": "T1176", "tactic": "Persistence", "name": "Browser Extensions"},

            # ── PRIVILEGE ESCALATION ──
            "privilege escalation": {"id": "T1068", "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation"},
            "elevation": {"id": "T1068", "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation"},
            "admin access": {"id": "T1078.003", "tactic": "Privilege Escalation", "name": "Local Accounts"},

            # ── DEFENSE EVASION ──
            "obfuscation": {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"},
            "evasion": {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"},
            "dll sideloading": {"id": "T1574.002", "tactic": "Defense Evasion", "name": "DLL Side-Loading"},
            "dll hijack": {"id": "T1574.001", "tactic": "Defense Evasion", "name": "DLL Search Order Hijacking"},
            "process injection": {"id": "T1055", "tactic": "Defense Evasion", "name": "Process Injection"},
            "fileless": {"id": "T1620", "tactic": "Defense Evasion", "name": "Reflective Code Loading"},
            "living off the land": {"id": "T1218", "tactic": "Defense Evasion", "name": "System Binary Proxy Execution"},
            "disable security": {"id": "T1562", "tactic": "Defense Evasion", "name": "Impair Defenses"},
            # Masquerading / Impersonation (NEW - for fake extension attacks)
            "impersonat": {"id": "T1036", "tactic": "Defense Evasion", "name": "Masquerading"},
            "masquerad": {"id": "T1036", "tactic": "Defense Evasion", "name": "Masquerading"},
            "deceptive": {"id": "T1036", "tactic": "Defense Evasion", "name": "Masquerading"},
            "fake brand": {"id": "T1036.005", "tactic": "Defense Evasion", "name": "Match Legitimate Name or Location"},

            # ── CREDENTIAL ACCESS ──
            "credential": {"id": "T1555", "tactic": "Credential Access", "name": "Credentials from Password Stores"},
            "brute force": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
            "password spray": {"id": "T1110.003", "tactic": "Credential Access", "name": "Password Spraying"},
            "keylogger": {"id": "T1056.001", "tactic": "Credential Access", "name": "Keylogging"},
            "credential dump": {"id": "T1003", "tactic": "Credential Access", "name": "OS Credential Dumping"},
            "mimikatz": {"id": "T1003.001", "tactic": "Credential Access", "name": "LSASS Memory"},
            "cookie theft": {"id": "T1539", "tactic": "Credential Access", "name": "Steal Web Session Cookie"},
            "session hijack": {"id": "T1539", "tactic": "Credential Access", "name": "Steal Web Session Cookie"},
            "session token": {"id": "T1539", "tactic": "Credential Access", "name": "Steal Web Session Cookie"},
            "infostealer": {"id": "T1555", "tactic": "Credential Access", "name": "Credentials from Password Stores"},
            "stealer": {"id": "T1555", "tactic": "Credential Access", "name": "Credentials from Password Stores"},
            "harvested credentials": {"id": "T1555.003", "tactic": "Credential Access", "name": "Credentials from Web Browsers"},
            "browser data": {"id": "T1555.003", "tactic": "Credential Access", "name": "Credentials from Web Browsers"},
            "oauth token": {"id": "T1528", "tactic": "Credential Access", "name": "Steal Application Access Token"},
            "token theft": {"id": "T1528", "tactic": "Credential Access", "name": "Steal Application Access Token"},
            "access token": {"id": "T1528", "tactic": "Credential Access", "name": "Steal Application Access Token"},

            # ── DISCOVERY ──
            "reconnaissance internal": {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery"},
            "network scanning": {"id": "T1046", "tactic": "Discovery", "name": "Network Service Discovery"},
            "enumerat": {"id": "T1087", "tactic": "Discovery", "name": "Account Discovery"},

            # ── LATERAL MOVEMENT ──
            "lateral movement": {"id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services"},
            "remote desktop": {"id": "T1021.001", "tactic": "Lateral Movement", "name": "Remote Desktop Protocol"},
            "internal spread": {"id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services"},
            "pass the hash": {"id": "T1550.002", "tactic": "Lateral Movement", "name": "Pass the Hash"},

            # ── COLLECTION ──
            "data collection": {"id": "T1005", "tactic": "Collection", "name": "Data from Local System"},
            "database": {"id": "T1213", "tactic": "Collection", "name": "Data from Information Repositories"},
            "screen capture": {"id": "T1113", "tactic": "Collection", "name": "Screen Capture"},
            "email collection": {"id": "T1114", "tactic": "Collection", "name": "Email Collection"},
            "records exposed": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage"},
            "data breach": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage"},
            "personal data": {"id": "T1005", "tactic": "Collection", "name": "Data from Local System"},
            "customer records": {"id": "T1213", "tactic": "Collection", "name": "Data from Information Repositories"},
            "exposed": {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service"},
            "unauthorized access": {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},

            # ── COMMAND AND CONTROL ──
            "c2": {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"},
            "beacon": {"id": "T1071.004", "tactic": "Command and Control", "name": "DNS"},
            "dns tunneling": {"id": "T1071.004", "tactic": "Command and Control", "name": "DNS"},
            "dns-based": {"id": "T1071.004", "tactic": "Command and Control", "name": "DNS"},
            "cobalt strike": {"id": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols"},
            "reverse shell": {"id": "T1572", "tactic": "Command and Control", "name": "Protocol Tunneling"},

            # ── EXFILTRATION ──
            "exfiltration": {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel"},
            "data leak": {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service"},
            "leaked": {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service"},
            "data stolen": {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel"},
            "data dump": {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service"},
            "breach": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
            "compromised": {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},

            # ── IMPACT ──
            "ransomware": {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
            "encrypt": {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
            "wiper": {"id": "T1485", "tactic": "Impact", "name": "Data Destruction"},
            "denial of service": {"id": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service"},
            "ddos": {"id": "T1498", "tactic": "Impact", "name": "Network Denial of Service"},
            "defacement": {"id": "T1491", "tactic": "Impact", "name": "Defacement"},
        }

    def map_threat(self, corpus: str) -> list:
        """Scans the threat corpus and returns matched MITRE techniques."""
        matches = []
        seen_ids = set()
        corpus_lower = corpus.lower()

        for keyword, meta in self.mapping_db.items():
            if keyword in corpus_lower and meta["id"] not in seen_ids:
                matches.append(meta)
                seen_ids.add(meta["id"])

        # Sort by tactic kill-chain order
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]
        matches.sort(key=lambda x: tactic_order.index(x["tactic"])
                     if x["tactic"] in tactic_order else 99)

        return matches


mitre_engine = MITREMapper()
