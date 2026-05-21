#!/usr/bin/env python3
"""
detection_engine.py - CyberDudeBivash v11.5 (SENTINEL APEX ULTRA)
UPGRADED: Production-ready Sigma and YARA rule generation with real IOC data.
Generates meaningful detection rules even when IOC data is limited.
"""
import re
import yaml
from datetime import datetime, timezone
from typing import Dict, List


class DetectionEngine:
    """Enterprise-grade automated detection rule synthesis."""

    def _detect_threat_platform(self, title: str, iocs: Dict) -> str:
        """v23.0: Detect the platform this threat targets - windows/android/linux/web/network"""
        text = title.lower()
        cves = iocs.get('cve', [])
        # Mobile/Android
        mobile_signals = ['android', 'apk', 'mobile malware', 'zygote', 'triada',
                         'badbox', 'vo1d', 'keenadu', 'sideload', 'bootloader',
                         'google play', 'play store malware', 'flubot', 'cerberus']
        if any(s in text for s in mobile_signals):
            return 'android'
        # Linux
        linux_signals = ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'kernel exploit',
                        'bash', 'ssh exploit', 'rootkit linux']
        if any(s in text for s in linux_signals):
            return 'linux'
        # Web/Network
        web_signals = ['web shell', 'sql injection', 'xss', 'csrf', 'ssrf',
                      'phishing', 'credential harvest', 'c2', 'botnet']
        if any(s in text for s in web_signals) and not any(w in text for w in ['windows', 'endpoint']):
            return 'web'
        # Default: Windows (most enterprise threats)
        return 'windows'

    def generate_sigma_rule(self, title: str, iocs: Dict) -> str:
        """
        v23.0: Platform-aware Sigma rule generation.
        Android threats -> Android/mobile detection, NOT Windows powershell rules.
        Generates meaningful detection rules matched to the actual threat platform.
        """
        platform = self._detect_threat_platform(title, iocs)
        if platform == 'android':
            return self._generate_android_sigma_rule(title, iocs)
        return self._generate_windows_sigma_rule(title, iocs)

    def _generate_android_sigma_rule(self, title: str, iocs: Dict) -> str:
        """Generate Android/mobile-specific Sigma detection rule."""
        import yaml
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]
        date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')
        apks = iocs.get('artifacts', [])
        hashes = iocs.get('sha256', []) + iocs.get('md5', [])

        rules = []
        # Android MDM/SIEM detection
        rule = {
            'title': f'CDB-Sentinel: {safe_title} - Android Threat Detection',
            'id': f'cdb-android-{abs(hash(title)) % 999999:06d}',
            'status': 'experimental',
            'description': f'Detects Android-platform threat activity associated with: {safe_title}.',
            'author': 'CyberDudeBivash GOC (Automated)',
            'date': date_str,
            'tags': ['attack.t1476', 'attack.t1475', 'attack.mobile'],
            'logsource': {'product': 'android', 'category': 'application'},
            'detection': {
                'selection_install': {
                    'event_type': ['PACKAGE_INSTALL', 'PACKAGE_ADDED'],
                    'source|contains': ['sideload', 'unknown_source', 'adb'],
                },
                'condition': 'selection_install',
            },
            'falsepositives': ['Legitimate enterprise app deployment via MDM', 'Developer devices'],
            'level': 'medium',
        }
        if hashes:
            rule['detection']['selection_hash'] = {'file_hash|contains': hashes[:5]}
            rule['detection']['condition'] = 'selection_install or selection_hash'
        rules.append(yaml.dump(rule, default_flow_style=False, sort_keys=False))

        # Network rule if domains/IPs present
        domains = iocs.get('domain', [])
        ips = iocs.get('ipv4', [])
        if domains or ips:
            net_rule = {
                'title': f'CDB-Sentinel: {safe_title} - C2 Network Indicators',
                'id': f'cdb-android-net-{abs(hash(title+"net")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects C2 communication from Android threat: {safe_title}.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.command_and_control'],
                'logsource': {'category': 'dns', 'product': 'any'},
                'detection': {
                    'selection': {'query|contains': (domains + ips)[:8]},
                    'condition': 'selection',
                },
                'falsepositives': ['Legitimate app CDN domains'],
                'level': 'high',
            }
            rules.append(yaml.dump(net_rule, default_flow_style=False, sort_keys=False))

        return '\n---\n'.join(rules) if rules else self._generate_no_ioc_android_sigma(title, date_str)

    def _generate_no_ioc_android_sigma(self, title: str, date_str: str) -> str:
        """Behavioral Android detection when no IOCs available."""
        import yaml
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]
        rule = {
            'title': f'CDB-Sentinel: {safe_title} - Behavioral Android Detection',
            'id': f'cdb-android-beh-{abs(hash(title+"beh")) % 999999:06d}',
            'status': 'experimental',
            'description': f'Behavioral detection for Android threat: {safe_title}.',
            'author': 'CyberDudeBivash GOC (Automated)',
            'date': date_str,
            'tags': ['attack.t1476', 'attack.persistence'],
            'logsource': {'product': 'android', 'category': 'application'},
            'detection': {
                'selection_suspicious': {
                    'event_type': 'PACKAGE_INSTALL',
                    'install_source': 'sideload',
                    'permissions|contains': ['READ_SMS', 'RECEIVE_SMS', 'READ_CONTACTS',
                                             'PROCESS_OUTGOING_CALLS', 'ACCESS_FINE_LOCATION'],
                },
                'condition': 'selection_suspicious',
            },
            'falsepositives': ['Legitimate apps with SMS access (banking, 2FA apps)'],
            'level': 'medium',
        }
        return yaml.dump(rule, default_flow_style=False, sort_keys=False)

    def _generate_windows_sigma_rule(self, title: str, iocs: Dict) -> str:
        """Original Windows sigma rule logic (formerly generate_sigma_rule)."""
        domains = iocs.get('domain', [])
        ips = iocs.get('ipv4', [])
        urls = iocs.get('url', [])
        hashes = iocs.get('sha256', []) + iocs.get('md5', [])
        artifacts = iocs.get('artifacts', [])
        cves = iocs.get('cve', [])

        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]
        date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')

        rules = []

        # Rule 1: Network IOCs (domains + IPs)
        if domains or ips:
            net_indicators = (domains[:10] + ips[:10])
            rule = {
                'title': f'CDB-Sentinel: {safe_title} - Network IOCs',
                'id': f'cdb-{abs(hash(title)) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects network connections to infrastructure associated with: {safe_title}. Auto-generated by CyberDudeBivash Sentinel APEX.',
                'references': ['https://cyberdudebivash.com', 'https://cyberbivash.blogspot.com'],
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.command_and_control', 'attack.exfiltration'],
                'logsource': {'category': 'dns', 'product': 'any'},
                'detection': {
                    'selection_dns': {'query|contains': net_indicators[:8]},
                    'condition': 'selection_dns',
                },
                'falsepositives': ['Legitimate traffic to similarly named domains', 'Internal DNS resolution'],
                'level': 'high',
            }
            rules.append(yaml.dump(rule, default_flow_style=False, sort_keys=False))

        # Rule 2: File-based IOCs (hashes + artifacts)
        if hashes or artifacts:
            rule = {
                'title': f'CDB-Sentinel: {safe_title} - File Indicators',
                'id': f'cdb-{abs(hash(title + "file")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects malicious file indicators associated with: {safe_title}.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.execution', 'attack.defense_evasion'],
                'logsource': {'category': 'file_event', 'product': 'windows'},
                'detection': {},
                'falsepositives': ['Legitimate software with matching names'],
                'level': 'high',
            }
            if hashes:
                rule['detection']['selection_hash'] = {'Hashes|contains': hashes[:5]}
            if artifacts:
                rule['detection']['selection_file'] = {'TargetFilename|endswith': artifacts[:5]}
            conditions = [k for k in rule['detection'].keys()]
            rule['detection']['condition'] = ' or '.join(conditions)
            rules.append(yaml.dump(rule, default_flow_style=False, sort_keys=False))

        # Rule 3: Behavioral detection (always generated as fallback)
        title_lower = title.lower()

        # Detect threat type for contextual rule generation
        is_browser_attack = any(w in title_lower for w in ['extension', 'browser', 'chrome', 'addon', 'plugin', 'webstore'])
        is_script_attack = any(w in title_lower for w in ['powershell', 'script', 'clickfix', 'nslookup'])
        is_malware = any(w in title_lower for w in ['malware', 'trojan', 'backdoor', 'stealer', 'rat'])
        is_exploit = any(w in title_lower for w in ['exploit', 'cve', 'vulnerability', 'rce', 'zero-day'])
        is_ransomware = any(w in title_lower for w in ['ransomware', 'ransom', 'encrypt', 'lockbit', 'blackcat'])
        is_phishing_identity = any(w in title_lower for w in ['phishing', 'credential', 'mfa', 'okta', 'identity',
                                                                'authentication', 'oauth', 'sim swap', 'smishing',
                                                                'victimize', '0ktapus', 'oktapus', 'spoofed'])

        if is_browser_attack:
            # BROWSER EXTENSION-SPECIFIC Sigma rule
            behavioral_rule = {
                'title': f'CDB-Sentinel: {safe_title} - Browser Extension Abuse Detection',
                'id': f'cdb-{abs(hash(title + "behav")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects suspicious browser extension activity associated with: {safe_title}. Monitors for unauthorized extension installation, excessive permissions, and credential exfiltration.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.persistence.t1176', 'attack.credential_access.t1555.003'],
                'logsource': {'category': 'process_creation', 'product': 'windows'},
                'detection': {
                    'selection_install': {
                        'Image|endswith': ['chrome.exe', 'msedge.exe', 'brave.exe'],
                        'CommandLine|contains': ['--load-extension', '--install-extension',
                                                  '--disable-extensions-except', 'extension_id'],
                    },
                    'selection_suspicious': {
                        'Image|endswith': ['chrome.exe', 'msedge.exe'],
                        'CommandLine|contains': ['--no-sandbox', '--disable-web-security',
                                                  '--allow-running-insecure-content'],
                    },
                    'condition': 'selection_install or selection_suspicious',
                },
                'falsepositives': ['Enterprise browser extension deployment via GPO',
                                   'Developer testing with extension flags'],
                'level': 'high',
            }
        elif is_ransomware:
            behavioral_rule = {
                'title': f'CDB-Sentinel: {safe_title} - Ransomware Behavioral Detection',
                'id': f'cdb-{abs(hash(title + "behav")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects ransomware TTPs associated with: {safe_title}.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.impact.t1486', 'attack.defense_evasion'],
                'logsource': {'category': 'process_creation', 'product': 'windows'},
                'detection': {
                    'selection': {
                        'Image|endswith': ['vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe',
                                            'wmic.exe', 'cmd.exe'],
                        'CommandLine|contains': ['delete shadows', 'delete catalog',
                                                  'recoveryenabled no', 'shadowcopy delete'],
                    },
                    'condition': 'selection',
                },
                'falsepositives': ['Legitimate backup management'],
                'level': 'critical',
            }
        elif is_phishing_identity:
            # PHISHING / IDENTITY / MFA COMPROMISE detection (NEW for 0ktapus-style)
            behavioral_rule = {
                'title': f'CDB-Sentinel: {safe_title} - Credential Phishing & MFA Bypass Detection',
                'id': f'cdb-{abs(hash(title + "behav")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Detects credential phishing and MFA interception patterns associated with: {safe_title}. Monitors for suspicious OAuth token activity, anomalous authentication flows, and credential harvesting infrastructure.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.initial_access.t1566', 'attack.credential_access.t1111',
                         'attack.credential_access.t1539'],
                'logsource': {'category': 'authentication', 'product': 'azure_ad'},
                'detection': {
                    'selection_mfa_anomaly': {
                        'EventType': ['MfaRequestFailed', 'MfaRequestDenied',
                                      'InteractiveMfaRequest'],
                        'Status|contains': ['Failed', 'Denied', 'Timeout'],
                    },
                    'selection_token_theft': {
                        'EventType': ['TokenIssuance', 'RefreshTokenGranted'],
                        'UserAgent|contains': ['python-requests', 'curl', 'wget',
                                                'AitM', 'Evilginx'],
                    },
                    'selection_suspicious_login': {
                        'EventType': 'SignInActivity',
                        'RiskLevel|contains': ['high', 'atRisk'],
                    },
                    'condition': 'selection_mfa_anomaly or selection_token_theft or selection_suspicious_login',
                },
                'falsepositives': ['Users with genuine MFA issues',
                                   'Automated security testing tools',
                                   'Legacy applications with unusual user agents'],
                'level': 'high',
            }
        else:
            process_patterns = []
            if is_script_attack:
                process_patterns = ['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe']
            elif is_malware:
                process_patterns = ['cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe']
            elif is_exploit:
                process_patterns = ['cmd.exe', 'powershell.exe', 'certutil.exe', 'bitsadmin.exe']
            else:
                process_patterns = ['powershell.exe', 'cmd.exe', 'mshta.exe', 'wmic.exe']

            behavioral_rule = {
                'title': f'CDB-Sentinel: {safe_title} - Behavioral Detection',
                'id': f'cdb-{abs(hash(title + "behav")) % 999999:06d}',
                'status': 'experimental',
                'description': f'Behavioral detection for TTPs associated with: {safe_title}. Detects suspicious process execution patterns.',
                'author': 'CyberDudeBivash GOC (Automated)',
                'date': date_str,
                'tags': ['attack.execution', 'attack.persistence'],
                'logsource': {'category': 'process_creation', 'product': 'windows'},
                'detection': {
                    'selection': {
                        'Image|endswith': process_patterns,
                        'CommandLine|contains': ['-enc', '-nop', '-w hidden', 'bypass',
                                                 'downloadstring', 'invoke-', 'iex('],
                    },
                    'condition': 'selection',
                },
                'falsepositives': ['Legitimate administrative scripts', 'Software deployment tools'],
                'level': 'medium',
            }
        rules.append(yaml.dump(behavioral_rule, default_flow_style=False, sort_keys=False))

        return '\n---\n'.join(rules)

    def generate_yara_rule(self, title: str, iocs: Dict) -> str:
        """
        Generates a production-ready YARA rule for memory and disk forensics.
        Enhanced: Includes actual IOC strings and behavioral patterns.
        """
        ips = iocs.get('ipv4', [])
        domains = iocs.get('domain', [])
        hashes = iocs.get('sha256', []) + iocs.get('md5', [])
        artifacts = iocs.get('artifacts', [])
        urls = iocs.get('url', [])

        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', title)[:40]
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        strings_section = []
        string_idx = 0

        # Add IP indicators
        for ip in ips[:5]:
            strings_section.append(f'        $ip{string_idx} = "{ip}" ascii wide')
            string_idx += 1

        # Add domain indicators
        for d in domains[:5]:
            strings_section.append(f'        $dom{string_idx} = "{d}" ascii wide nocase')
            string_idx += 1

        # Add artifact filenames
        for a in artifacts[:3]:
            strings_section.append(f'        $file{string_idx} = "{a}" ascii wide nocase')
            string_idx += 1

        # Add URL indicators
        for u in urls[:3]:
            # Truncate long URLs
            u_short = u[:100]
            strings_section.append(f'        $url{string_idx} = "{u_short}" ascii wide')
            string_idx += 1

        # Always add behavioral strings based on threat type
        title_lower = title.lower()
        is_browser_attack = any(w in title_lower for w in ['extension', 'browser', 'chrome', 'addon', 'plugin', 'webstore'])
        is_script_attack = any(w in title_lower for w in ['powershell', 'script', 'clickfix'])

        if is_browser_attack:
            strings_section.extend([
                f'        $beh{string_idx} = "chrome-extension://" ascii wide nocase',
                f'        $beh{string_idx+1} = "chrome.runtime.sendMessage" ascii wide',
                f'        $beh{string_idx+2} = "document.cookie" ascii wide',
                f'        $beh{string_idx+3} = "XMLHttpRequest" ascii wide',
                f'        $beh{string_idx+4} = "permissions" ascii wide',
            ])
            string_idx += 5
        elif is_script_attack:
            strings_section.extend([
                f'        $beh{string_idx} = "powershell" ascii wide nocase',
                f'        $beh{string_idx+1} = "-EncodedCommand" ascii wide nocase',
                f'        $beh{string_idx+2} = "Invoke-Expression" ascii wide nocase',
                f'        $beh{string_idx+3} = "nslookup" ascii wide nocase',
            ])
            string_idx += 4
        elif any(w in title_lower for w in ['malware', 'trojan', 'stealer', 'rat']):
            strings_section.extend([
                f'        $beh{string_idx} = "CreateRemoteThread" ascii wide',
                f'        $beh{string_idx+1} = "VirtualAllocEx" ascii wide',
                f'        $beh{string_idx+2} = "WriteProcessMemory" ascii wide',
                f'        $beh{string_idx+3} = "NtUnmapViewOfSection" ascii wide',
            ])
            string_idx += 4
        elif any(w in title_lower for w in ['ransomware', 'ransom', 'encrypt']):
            strings_section.extend([
                f'        $beh{string_idx} = "vssadmin delete shadows" ascii wide nocase',
                f'        $beh{string_idx+1} = "bcdedit /set" ascii wide nocase',
                f'        $beh{string_idx+2} = ".onion" ascii wide',
                f'        $beh{string_idx+3} = "YOUR FILES HAVE BEEN" ascii wide nocase',
            ])
            string_idx += 4
        elif any(w in title_lower for w in ['phishing', 'credential', 'mfa', 'okta', 'identity',
                                             'authentication', 'oauth', 'victimize', '0ktapus']):
            strings_section.extend([
                f'        $beh{string_idx} = "password" ascii wide nocase',
                f'        $beh{string_idx+1} = "document.forms" ascii wide',
                f'        $beh{string_idx+2} = "XMLHttpRequest" ascii wide',
                f'        $beh{string_idx+3} = "login" ascii wide nocase',
                f'        $beh{string_idx+4} = "oauth" ascii wide nocase',
                f'        $beh{string_idx+5} = "token" ascii wide nocase',
            ])
            string_idx += 6
        else:
            strings_section.extend([
                f'        $beh{string_idx} = "cmd.exe /c" ascii wide nocase',
                f'        $beh{string_idx+1} = "whoami" ascii wide',
                f'        $beh{string_idx+2} = "net user" ascii wide nocase',
            ])
            string_idx += 3

        if not strings_section:
            strings_section = [
                '        $gen0 = "cmd.exe" ascii wide',
                '        $gen1 = "powershell" ascii wide nocase',
            ]

        strings_block = '\n'.join(strings_section)

        # Determine condition based on what we have
        if string_idx > 6:
            condition = "3 of them"
        elif string_idx > 3:
            condition = "2 of them"
        else:
            condition = "any of them"

        yara = f"""rule CDB_{rule_name} {{
    meta:
        author = "CyberDudeBivash GOC"
        description = "Detects indicators associated with: {title[:60]}"
        date = "{date_str}"
        reference = "https://cyberbivash.blogspot.com"
        severity = "high"
        tlp = "TLP:CLEAR"

    strings:
{strings_block}

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and {condition}
}}"""

        return yara

    # ──────────────────────────────────────────────────────────────────────────
    # OMEGA-P3: Detection Supremacy Layer — KQL, SPL, EQL, Suricata, Snort
    # ──────────────────────────────────────────────────────────────────────────

    def generate_kql_rule(self, title: str, iocs: Dict) -> str:
        """Microsoft Sentinel / Defender XDR — KQL hunting query."""
        date_str  = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
        ips       = iocs.get('ipv4', [])[:8]
        domains   = iocs.get('domain', [])[:8]
        hashes    = (iocs.get('sha256', []) + iocs.get('md5', []))[:6]
        cves      = iocs.get('cve', [])[:4]
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]

        ioc_list  = ips + domains + hashes
        ioc_dyn   = ('dynamic(["' + '","'.join(ioc_list) + '"])') if ioc_list else 'dynamic([])'
        cve_dyn   = ('dynamic(["' + '","'.join(cves) + '"])') if cves else 'dynamic([])'

        return (
            f"// CyberDudeBivash SENTINEL APEX — KQL Detection Pack\n"
            f"// Advisory : {safe_title}\n"
            f"// Generated: {date_str}\n"
            f"// Platform : Microsoft Sentinel / Defender XDR (30d retro-hunt)\n\n"
            f"let lookback  = 30d;\n"
            f"let apex_iocs = {ioc_dyn};\n"
            f"let apex_cves = {cve_dyn};\n\n"
            f"// 1. Network IOC hits\n"
            f"DeviceNetworkEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where RemoteUrl has_any (apex_iocs) or RemoteIP has_any (apex_iocs)\n"
            f"| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName\n"
            f"| order by Timestamp desc;\n\n"
            f"// 2. Suspicious process execution\n"
            f"DeviceProcessEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where ProcessCommandLine has_any (\"invoke-expression\",\"downloadstring\","
            f"\"bypass\",\"encodedcommand\",\"bitsadmin\",\"certutil -decode\")\n"
            f"| summarize count() by DeviceName, FileName, ProcessCommandLine, bin(Timestamp,1h)\n"
            f"| where count_ > 2 | order by count_ desc;\n\n"
            f"// 3. Hash correlation\n"
            f"DeviceFileEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where SHA256 has_any (apex_iocs) or MD5 has_any (apex_iocs)\n"
            f"| project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5;\n\n"
            f"// 4. Authentication anomaly\n"
            f"SigninLogs\n"
            f"| where TimeGenerated > ago(lookback)\n"
            f"| where ResultType != 0 and IPAddress has_any (apex_iocs)\n"
            f"| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultDescription;\n\n"
            f"// 5. CVE exposure in TVM\n"
            f"DeviceTvmSoftwareVulnerabilities\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where CveId has_any (apex_cves)\n"
            f"| summarize Devices=dcount(DeviceId) by CveId, SoftwareName, VulnerabilitySeverityLevel;\n"
        )

    def generate_spl_rule(self, title: str, iocs: Dict) -> str:
        """Splunk Enterprise Security — SPL correlation search."""
        date_str   = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
        ips        = iocs.get('ipv4', [])[:8]
        domains    = iocs.get('domain', [])[:8]
        hashes     = (iocs.get('sha256', []) + iocs.get('md5', []))[:6]
        cves       = iocs.get('cve', [])[:4]
        all_iocs   = ips + domains + hashes + cves
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]

        ioc_search  = " OR ".join('"' + v + '"' for v in all_iocs) if all_iocs else '"APEX_NO_IOC"'
        hash_search = " OR ".join('"' + h + '"' for h in hashes) if hashes else '"NO_HASH"'
        # Pre-escape regex pattern outside f-string (no backslash in f-expr)
        ioc_re = ("|".join(v.replace(".", "\\.") for v in all_iocs))[:200] if all_iocs else "APEX"

        lines = [
            f'| comment "CyberDudeBivash SENTINEL APEX SPL Pack — {safe_title}"',
            f'| comment "Generated: {date_str}"',
            "",
            f"index=* (sourcetype=zeek* OR sourcetype=suricata* OR sourcetype=proxy*)",
            f"    ({ioc_search})",
            f'| eval ioc_hit=if(match(_raw,"{ioc_re}"),"IOC_HIT","NONE")',
            f"| stats count by src_ip, dest_ip, dest_port, ioc_hit, sourcetype, _time",
            f'| where ioc_hit="IOC_HIT"',
            f'| eval risk_score=case(sourcetype="suricata",95,sourcetype="zeek",85,1==1,70)',
            f"| sort - risk_score, _time",
            "",
            f"index=* sourcetype=wineventlog (EventCode=4688 OR EventCode=4624 OR EventCode=4720)",
            f'    (CommandLine="*invoke-expression*" OR CommandLine="*downloadstring*"',
            f'     OR CommandLine="*bypass*" OR CommandLine="*certutil*-decode*")',
            f"| stats count by host, user, CommandLine, EventCode, bin(_time,1h)",
            f"| where count > 2",
            "",
            f"index=* (sourcetype=crowdstrike* OR sourcetype=carbonblack* OR sourcetype=defender*)",
            f"    ({hash_search})",
            f"| stats count by host, filename, file_hash, _time | sort - _time",
        ]
        return "\n".join(lines)

    def generate_eql_rule(self, title: str, iocs: Dict) -> str:
        """Elastic EQL — Event Query Language sequences."""
        date_str   = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
        ips        = iocs.get('ipv4', [])[:6]
        domains    = iocs.get('domain', [])[:6]
        hashes     = (iocs.get('sha256', []) + iocs.get('md5', []))[:4]
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]

        dest_filter = ('destination.ip : ("' + '","'.join(ips) + '")') if ips else 'destination.ip : *'
        dom_filter  = ('dns.question.name : ("' + '","'.join(domains) + '")') if domains else 'dns.question.name : *'
        hash_filter = ('process.hash.sha256 : ("' + '","'.join(hashes) + '")') if hashes else None

        lines = [
            f"// CyberDudeBivash SENTINEL APEX — EQL Detection Pack",
            f"// Advisory : {safe_title}",
            f"// Generated: {date_str}",
            f"// Platform : Elastic Security / Kibana SIEM",
            "",
            "// 1. Suspicious LOTL process → network sequence",
            "sequence by host.name with maxspan=5m",
            "  [process where event.type == \"start\"",
            "   and process.name : (\"powershell.exe\",\"cmd.exe\",\"wscript.exe\",\"mshta.exe\",\"certutil.exe\")",
            "   and process.command_line : (\"*invoke-expression*\",\"*downloadstring*\",\"*bypass*\",\"*bitsadmin*\")]",
            f"  [network where event.type == \"connection\" and {dest_filter}]",
            "",
            "// 2. Network IOC hit",
            f"network where event.type in (\"connection\",\"dns\") and ({dest_filter} or {dom_filter})",
            "",
            "// 3. Credential dumping sequence",
            "sequence by host.name with maxspan=2m",
            "  [process where event.type == \"start\"",
            "   and process.name : (\"lsass.exe\",\"procdump.exe\",\"mimikatz*\",\"wce.exe\")]",
            "  [file where event.type == \"creation\" and file.extension : (\"dmp\",\"dump\",\"bin\")]",
            "",
            "// 4. Persistence — Registry run key modification",
            "registry where event.type in (\"creation\",\"change\")",
            "and registry.path : (\"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*\",",
            "                    \"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*\")",
            "and not process.name : (\"msiexec.exe\",\"setup.exe\",\"installer.exe\")",
        ]
        if hash_filter:
            lines += [
                "",
                "// 5. Known malware hash execution",
                f"process where event.type == \"start\" and ({hash_filter})",
            ]
        return "\n".join(lines)

    def generate_suricata_rule(self, title: str, iocs: Dict) -> str:
        """Suricata IDS/IPS — production NSM rules."""
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]
        date_str   = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        ips        = iocs.get('ipv4', [])[:5]
        domains    = iocs.get('domain', [])[:5]
        cves       = iocs.get('cve', [])[:2]
        sid_base   = abs(hash(title)) % 8000000 + 1000000

        rules = []
        for i, ip in enumerate(ips):
            rules.append(
                f'alert tcp $HOME_NET any -> {ip} any '
                f'(msg:"CDB-APEX C2 Beacon — {safe_title}"; '
                f'flow:established,to_server; '
                f'threshold:type both,track by_src,count 3,seconds 120; '
                f'classtype:trojan-activity; '
                f'reference:url,intel.cyberdudebivash.com; '
                f'sid:{sid_base + i}; rev:1;)'
            )
        for i, dom in enumerate(domains):
            rules.append(
                f'alert dns $HOME_NET any -> any 53 '
                f'(msg:"CDB-APEX DNS — {safe_title} [{dom}]"; '
                f'dns.query; content:"{dom}"; nocase; '
                f'classtype:trojan-activity; '
                f'reference:url,intel.cyberdudebivash.com; '
                f'sid:{sid_base + 100 + i}; rev:1;)'
            )
        rules.append(
            f'alert http $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"CDB-APEX HTTP Suspicious — {safe_title}"; '
            f'flow:established,to_server; http.method; content:"POST"; '
            f'http.uri; pcre:"/(\\.php|\\.aspx|gate\\.php|panel\\.php)/i"; '
            f'threshold:type both,track by_src,count 5,seconds 300; '
            f'classtype:trojan-activity; '
            f'sid:{sid_base + 200}; rev:1;)'
        )
        for i, cve in enumerate(cves):
            rules.append(
                f'alert http any any -> $HTTP_SERVERS any '
                f'(msg:"CDB-APEX Exploit — {cve} — {safe_title}"; '
                f'flow:established,to_server; '
                f'http.uri; pcre:"/(%27|UNION|SELECT|exec\\(|eval\\()/i"; '
                f'classtype:web-application-attack; '
                f'reference:cve,{cve.replace("CVE-","")}; '
                f'sid:{sid_base + 300 + i}; rev:1;)'
            )
        if not rules:
            rules.append(
                f'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"CDB-APEX Behavioral — {safe_title}"; '
                f'flow:established,to_server; '
                f'threshold:type threshold,track by_src,count 20,seconds 60; '
                f'classtype:policy-violation; sid:{sid_base + 999}; rev:1;)'
            )
        header = (
            f"# CyberDudeBivash SENTINEL APEX — Suricata Rule Pack\n"
            f"# Advisory : {safe_title}\n"
            f"# Generated: {date_str}\n"
            f"# Deploy   : /etc/suricata/rules/cdb-apex.rules\n\n"
        )
        return header + "\n".join(rules)

    def generate_snort_rule(self, title: str, iocs: Dict) -> str:
        """Snort 3 — IDS/IPS rules."""
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]
        date_str   = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        ips        = iocs.get('ipv4', [])[:4]
        domains    = iocs.get('domain', [])[:4]
        sid_base   = abs(hash(title + "snort")) % 7000000 + 2000000

        rules = []
        for i, ip in enumerate(ips):
            rules.append(
                f'alert tcp $HOME_NET any -> {ip} any '
                f'(msg:"CDB-APEX C2 [{safe_title}]"; '
                f'flow:established,to_server; classtype:trojan-activity; '
                f'priority:1; sid:{sid_base + i}; rev:1;)'
            )
        for i, dom in enumerate(domains):
            rules.append(
                f'alert udp $HOME_NET any -> any 53 '
                f'(msg:"CDB-APEX DNS [{dom}]"; '
                f'content:"{dom}"; nocase; classtype:trojan-activity; '
                f'priority:2; sid:{sid_base + 50 + i}; rev:1;)'
            )
        if not rules:
            rules.append(
                f'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
                f'(msg:"CDB-APEX Behavioral [{safe_title}]"; '
                f'flow:established,to_server; classtype:policy-violation; '
                f'priority:3; sid:{sid_base + 999}; rev:1;)'
            )
        return (
            f"# CyberDudeBivash SENTINEL APEX — Snort 3 Rules\n"
            f"# Advisory: {safe_title}  |  Generated: {date_str}\n\n"
            + "\n".join(rules)
        )

    def generate_defender_query(self, title: str, iocs: Dict) -> str:
        """Microsoft Defender XDR — Advanced Hunting KQL."""
        date_str  = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
        ips       = iocs.get('ipv4', [])[:6]
        domains   = iocs.get('domain', [])[:6]
        hashes    = (iocs.get('sha256', []) + iocs.get('md5', []))[:4]
        cves      = iocs.get('cve', [])[:4]
        safe_title = re.sub(r'[^a-zA-Z0-9 _-]', '', title)[:80]

        ioc_list  = ips + domains + hashes
        ioc_dyn   = ('dynamic(["' + '","'.join(ioc_list) + '"])') if ioc_list else 'dynamic([])'
        cve_dyn   = ('dynamic(["' + '","'.join(cves) + '"])') if cves else 'dynamic([])'

        return (
            f"// CyberDudeBivash SENTINEL APEX — Defender XDR Advanced Hunting\n"
            f"// Advisory : {safe_title}\n"
            f"// Generated: {date_str}\n\n"
            f"let lookback  = 30d;\n"
            f"let apex_iocs = {ioc_dyn};\n"
            f"let apex_cves = {cve_dyn};\n\n"
            f"// TVM CVE Exposure\n"
            f"DeviceTvmSoftwareVulnerabilities\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where CveId has_any (apex_cves)\n"
            f"| summarize Devices=dcount(DeviceId), DeviceList=make_set(DeviceName,20)\n"
            f"    by CveId, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel\n"
            f"| order by VulnerabilitySeverityLevel asc;\n\n"
            f"// Email IOC hits\n"
            f"EmailEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where SenderIPv4 has_any (apex_iocs) or SenderFromDomain has_any (apex_iocs)\n"
            f"| project Timestamp, SenderIPv4, SenderFromDomain, RecipientEmailAddress,\n"
            f"          Subject, DeliveryAction, ThreatTypes;\n\n"
            f"// Cloud app anomaly\n"
            f"CloudAppEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where IPAddress has_any (apex_iocs)\n"
            f"| project Timestamp, AccountDisplayName, IPAddress, ActionType, Application;\n\n"
            f"// Risky identity sign-ins\n"
            f"IdentityLogonEvents\n"
            f"| where Timestamp > ago(lookback)\n"
            f"| where IPAddress has_any (apex_iocs)\n"
            f"| project Timestamp, AccountName, IPAddress, Location, Protocol, FailureReason;\n"
        )


detection_engine = DetectionEngine()