"""
CYBERDUDEBIVASH SENTINEL APEX
Production-Grade Sigma Rule Generation Engine v2.0
====================================================
Fixes the broken template that was producing:
  1. Syntax error: `condition: unexpected_outboundor ioc_network_indicators` (missing space)
  2. IOC-based detection using news URLs and blog post links
  3. YARA rules matching own infrastructure domains
  4. Generic rules with no tuning guidance

This module generates per-vulnerability-class Sigma rules that are:
  - Syntactically valid YAML
  - Logically correct (real threat patterns, not source URLs)
  - Tuned per vulnerability class (SQLi, RCE, Supply Chain, etc.)
  - False-positive annotated
  - MITRE ATT&CK tagged
"""

import uuid
import re
from datetime import date
from typing import Optional
from dataclasses import dataclass, field
import yaml


# ---------------------------------------------------------------------------
# Vulnerability class definitions — drives which detection logic to use
# ---------------------------------------------------------------------------

VULN_CLASS_MAP = {
    "sqli":         "SQL Injection",
    "rce":          "Remote Code Execution",
    "supply_chain": "Supply Chain Compromise",
    "xss":          "Cross-Site Scripting",
    "ssrf":         "Server-Side Request Forgery",
    "xxe":          "XML External Entity Injection",
    "lfi":          "Local File Inclusion",
    "rfi":          "Remote File Inclusion",
    "deserial":     "Insecure Deserialization",
    "privesc":      "Privilege Escalation",
    "auth_bypass":  "Authentication Bypass",
    "csrf":         "Cross-Site Request Forgery",
    "path_trav":    "Path Traversal",
    "dos":          "Denial of Service",
    "overflow":     "Buffer/Stack Overflow",
    "cmd_inject":   "OS Command Injection",
    "generic":      "Generic Vulnerability",
}


@dataclass
class SigmaRule:
    title: str
    rule_id: str
    status: str
    description: str
    references: list[str]
    author: str
    date_str: str
    tags: list[str]
    logsource: dict
    detection: dict
    falsepositives: list[str]
    level: str
    fields: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Render to valid Sigma YAML."""
        rule_dict = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": self.references,
            "author": self.author,
            "date": self.date_str,
            "tags": self.tags,
            "logsource": self.logsource,
            "detection": self.detection,
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        if self.fields:
            rule_dict["fields"] = self.fields
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Per-class detection logic
# ---------------------------------------------------------------------------

def _sqli_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """SQL injection detection: web log patterns, NOT source URLs."""
    detection = {
        "sqli_union_based": {
            "cs-uri-query|contains": [
                "UNION SELECT", "UNION+SELECT", "UNION%20SELECT",
                "UNION/**/SELECT",
            ]
        },
        "sqli_boolean_blind": {
            "cs-uri-query|contains": [
                "' OR '1'='1", "' OR 1=1--", "1' AND 1=1--",
                "admin'--", "; SELECT 1--",
            ]
        },
        "sqli_time_based": {
            "cs-uri-query|contains": [
                "SLEEP(", "WAITFOR DELAY", "BENCHMARK(",
                "pg_sleep(", "; SELECT SLEEP",
            ]
        },
        "sqli_stacked": {
            "cs-uri-query|contains": [
                "; DROP TABLE", "; INSERT INTO", "; UPDATE ",
                "xp_cmdshell", "EXEC(CHAR",
            ]
        },
        "condition": "sqli_union_based or sqli_boolean_blind or sqli_time_based or sqli_stacked"
    }
    # Add real IOCs if provided (hashes, IPs — not URLs)
    real_ioc_values = [i for i in iocs if _is_real_ioc(i)]
    if real_ioc_values:
        detection["ioc_network"] = {"dst_ip|cidr": real_ioc_values}
        detection["condition"] = "ioc_network or sqli_union_based or sqli_boolean_blind or sqli_time_based or sqli_stacked"

    fps = [
        "URL-encoded legitimate content containing SQL-like keywords",
        "Security scanner automated SQL injection testing in dev/staging",
        "UNION appearing in legitimate application query strings",
    ]
    return detection, fps


def _cmd_inject_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """OS command injection: process creation and web log patterns."""
    detection = {
        "web_cmd_inject": {
            "cs-uri-query|contains": [
                "; cat /etc/passwd", "; id;", "| whoami", "`id`",
                "$(id)", "&& id &&", "; curl ", "; wget ",
            ]
        },
        "process_cmd_spawn": {
            "EventID": [4688],
            "CommandLine|contains": [
                "cmd.exe /c", "sh -c", "bash -c",
                "/bin/sh -c", "powershell -enc",
            ],
            "ParentImage|endswith": [
                "\\apache2.exe", "\\nginx.exe", "\\httpd.exe",
                "\\php-cgi.exe", "\\tomcat.exe",
            ]
        },
        "condition": "web_cmd_inject or process_cmd_spawn"
    }
    fps = [
        "Legitimate CGI scripts that spawn shell processes",
        "Scheduled maintenance scripts running via web application",
    ]
    return detection, fps


def _supply_chain_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """Supply chain: package manager lifecycle hooks spawning shells."""
    detection = {
        "npm_malicious_lifecycle": {
            "Image|endswith": ["\\node.exe", "\\npm.cmd"],
            "CommandLine|contains": ["preinstall", "postinstall", "install"],
            "CommandLine|contains_all": ["curl ", "wget ", "powershell"],
        },
        "pip_dependency_confusion": {
            "Image|endswith": ["\\pip.exe", "\\pip3.exe"],
            "CommandLine|contains": [
                "--extra-index-url", "--index-url http://",
                "--trusted-host",
            ]
        },
        "pkg_manager_spawns_shell": {
            "ParentImage|endswith": [
                "\\node.exe", "\\python.exe", "\\pip.exe",
                "\\npm.cmd", "\\gem",
            ],
            "Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\bash.exe"],
            "CommandLine|contains": ["-enc", "IEX", "Invoke-Expression", "DownloadString"]
        },
        "ci_pipeline_tampering": {
            "EventID": [4663],
            "ObjectName|contains": [".github/workflows/", "Jenkinsfile", ".gitlab-ci.yml"],
            "AccessMask": ["0x2", "0x6"],
        },
        "condition": (
            "npm_malicious_lifecycle or pip_dependency_confusion "
            "or pkg_manager_spawns_shell or ci_pipeline_tampering"
        )
    }
    fps = [
        "Legitimate build tools that spawn shell processes during dependency installation",
        "Development environments with postinstall hooks",
        "CI/CD pipelines running legitimate pipeline updates",
    ]
    return detection, fps


def _rce_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """Generic RCE: process spawned from web service, reverse shell patterns."""
    detection = {
        "web_service_shell_spawn": {
            "ParentImage|endswith": [
                "\\httpd.exe", "\\apache2", "\\nginx", "\\IIS",
                "\\w3wp.exe", "\\tomcat", "\\jetty",
            ],
            "Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\bash", "\\sh"]
        },
        "reverse_shell_tcp": {
            "CommandLine|contains": [
                "bash -i >& /dev/tcp/",
                "nc -e /bin/bash",
                "nc -e /bin/sh",
                "/dev/tcp/",
                "python -c 'import socket",
                "python3 -c 'import socket",
            ]
        },
        "unusual_c2_ports": {
            "Initiated": "true",
            "DestinationPort": [4444, 1337, 31337, 8888, 9001, 9999, 6666]
        },
        "condition": (
            "(web_service_shell_spawn or reverse_shell_tcp) "
            "or unusual_c2_ports"
        )
    }
    fps = [
        "Legitimate applications using non-standard ports for business logic",
        "Development and testing environments",
        "Penetration testing infrastructure (should be excluded by host scope)",
    ]
    return detection, fps


def _overflow_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """Buffer/Stack overflow: process crash patterns and exploit delivery."""
    detection = {
        "app_crash_exploit": {
            "EventID": [1000, 1001],
            "Application|contains": ["EXCEPTION_STACK_OVERFLOW", "EXCEPTION_ACCESS_VIOLATION"]
        },
        "shellcode_process": {
            "CommandLine|re": r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}"
        },
        "condition": "app_crash_exploit or shellcode_process"
    }
    fps = [
        "Legitimate application crashes during normal operation",
        "Memory analysis tools generating shellcode-like strings",
    ]
    return detection, fps


def _generic_detection(cve_id: str, iocs: list[str]) -> tuple[dict, list[str]]:
    """
    Generic fallback — used when vulnerability class is unknown.
    Contains only real threat patterns, no noise.
    """
    detection = {
        "suspicious_outbound_ports": {
            "Initiated": "true",
            "DestinationPort": [4444, 1337, 31337, 8888, 9001, 9999]
        },
        "condition": "suspicious_outbound_ports"
    }
    # NOTE: Previously, blog post source URLs and JavaScript properties like
    # 'attack.execution' were being added here as IOCs. This was WRONG.
    # Only add real network IOCs (IPs, validated domains) to detection.
    real_iocs = [i for i in iocs if _is_real_ioc(i)]
    if real_iocs:
        detection["confirmed_ioc_network"] = {"DestinationIp": real_iocs}
        detection["condition"] = "confirmed_ioc_network or suspicious_outbound_ports"

    fps = [
        "Legitimate applications using non-standard ports",
        "Development and testing environments",
        "VPN or tunneling software using unusual port ranges",
    ]
    return detection, fps


DETECTION_FUNCTIONS = {
    "sqli":         _sqli_detection,
    "cmd_inject":   _cmd_inject_detection,
    "supply_chain": _supply_chain_detection,
    "rce":          _rce_detection,
    "overflow":     _overflow_detection,
    "generic":      _generic_detection,
}


def _is_real_ioc(value: str) -> bool:
    """
    Return True only if value is a real network indicator (IP, validated domain, hash).
    Rejects: source URLs, blog URLs, JavaScript properties, software filenames.
    """
    JUNK_PATTERNS = [
        r"^attack\.",      # attack.execution, attack.discovery etc.
        r"^document\.",    # document.cookie etc.
        r"^tools\.",       # tools.installer etc.
        r"\.exe$",         # Software binaries
        r"^https?://",     # URLs in IOC list — use url type instead
        r"cyberdudebivash",
        r"cybersecuritynews",
        r"thehackernews",
        r"bleepingcomputer",
        r"nvd\.nist",
        r"cisa\.gov",
    ]
    for pattern in JUNK_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return False

    # Must look like an IP or domain or hash
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    hash_pattern = r'^[0-9a-f]{32,128}$'
    domain_pattern = r'^[a-z0-9\-]+(\.[a-z0-9\-]+)+\.[a-z]{2,}$'

    return bool(
        re.match(ip_pattern, value)
        or re.match(hash_pattern, value, re.IGNORECASE)
        or re.match(domain_pattern, value, re.IGNORECASE)
    )


# ---------------------------------------------------------------------------
# Rule generator
# ---------------------------------------------------------------------------

class APEXSigmaGenerator:
    """
    Generates production-grade Sigma rules for SENTINEL APEX advisories.

    Usage:
        gen = APEXSigmaGenerator()
        rule = gen.generate(
            advisory_title="CISA Warns of Drupal Core SQL Injection",
            cve_id="CVE-2026-9082",
            vuln_class="sqli",
            mitre_techniques=["T1190", "T1059"],
            real_iocs=["45.153.204.118", "a3f5d0c9e8b726..."],
            severity="high",
        )
        print(rule.to_yaml())
    """

    AUTHOR = "CYBERDUDEBIVASH SENTINEL APEX"
    BASE_REFERENCE = "https://intel.cyberdudebivash.com"

    def generate(
        self,
        advisory_title: str,
        cve_id: Optional[str],
        vuln_class: str,
        mitre_techniques: list[str],
        real_iocs: Optional[list[str]] = None,
        severity: str = "medium",
        source_url: Optional[str] = None,
        logsource_override: Optional[dict] = None,
    ) -> SigmaRule:
        real_iocs = real_iocs or []
        vuln_class = vuln_class.lower().replace(" ", "_").replace("-", "_")
        if vuln_class not in DETECTION_FUNCTIONS:
            vuln_class = "generic"

        detection_fn = DETECTION_FUNCTIONS[vuln_class]
        detection, fps = detection_fn(cve_id or "", real_iocs)

        # Build MITRE ATT&CK tags
        tags = ["attack.initial_access"]
        for tech in mitre_techniques:
            tech_lower = tech.lower().replace(".", "").replace("T", "t")
            tags.append(f"attack.{tech_lower}")

        # Select logsource based on vuln class
        if logsource_override:
            logsource = logsource_override
        elif vuln_class in ("sqli", "xss", "ssrf", "lfi", "rfi", "path_trav"):
            logsource = {"category": "webserver"}
        elif vuln_class in ("supply_chain",):
            logsource = {"category": "process_creation", "product": "windows"}
        elif vuln_class in ("rce", "cmd_inject", "privesc"):
            logsource = {"category": "process_creation", "product": "windows"}
        elif vuln_class in ("overflow",):
            logsource = {"category": "application", "product": "windows"}
        else:
            logsource = {"category": "network_connection", "product": "windows"}

        references = [self.BASE_REFERENCE]
        if source_url:
            references.append(source_url)
        if cve_id:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

        # Sanitise title for rule name
        safe_title = re.sub(r'[^a-zA-Z0-9 ]', '', advisory_title)[:80].strip()
        rule_title = f"APEX - {safe_title} [{VULN_CLASS_MAP.get(vuln_class, 'Generic')}]"

        return SigmaRule(
            title=rule_title,
            rule_id=str(uuid.uuid4()),
            status="experimental",
            description=(
                f"Detects {VULN_CLASS_MAP.get(vuln_class, 'exploitation')} activity "
                f"related to: {advisory_title[:100]}. "
                f"Generated by CYBERDUDEBIVASH SENTINEL APEX. "
                f"Review and tune for your environment before production deployment."
            ),
            references=references,
            author=self.AUTHOR,
            date_str=date.today().isoformat().replace("-", "/"),
            tags=tags,
            logsource=logsource,
            detection=detection,
            falsepositives=fps,
            level=severity,
        )


# ---------------------------------------------------------------------------
# YARA rule generator — fixed to not include own infrastructure
# ---------------------------------------------------------------------------

YARA_TEMPLATE = '''rule APEX_{safe_name}_{vuln_class_upper} {{
    meta:
        description   = "APEX detection: {description}"
        cve           = "{cve_id}"
        vuln_class    = "{vuln_class_upper}"
        author        = "CYBERDUDEBIVASH SENTINEL APEX v2.0"
        date          = "{date}"
        reference     = "https://intel.cyberdudebivash.com"
        severity      = "{severity}"
        mitre_attack  = "{mitre_str}"

    strings:
{strings_block}
    condition:
        {condition}
}}
'''


def generate_yara(
    advisory_title: str,
    cve_id: Optional[str],
    vuln_class: str,
    mitre_techniques: list[str],
    real_iocs: Optional[list[str]] = None,
    file_hashes: Optional[list[str]] = None,
    malicious_strings: Optional[list[str]] = None,
) -> str:
    """
    Generate a YARA rule for the given advisory.
    Only includes actual threat strings/hashes — NOT blog URLs, NOT own domains.
    """
    real_iocs = [i for i in (real_iocs or []) if _is_real_ioc(i)]
    file_hashes = file_hashes or []
    malicious_strings = malicious_strings or []

    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', advisory_title[:30]).strip('_')
    vuln_upper = vuln_class.upper().replace(" ", "_")
    cve_display = cve_id or "N/A"
    mitre_str = ", ".join(mitre_techniques)
    today = date.today().isoformat()

    strings_lines = []
    condition_parts = []

    # Add hash-based detection (highest fidelity)
    for i, h in enumerate(file_hashes[:10]):
        length = len(h)
        hash_type = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(length, "HASH")
        strings_lines.append(
            f'        $hash_{i} = "{h}" ascii wide nocase  // {hash_type} file hash'
        )
    if file_hashes:
        condition_parts.append("any of ($hash_*)")

    # Add malicious string patterns (tool-specific, not generic URLs)
    class_strings = {
        "sqli": [
            ('$sqli_union', '"UNION SELECT"', "SQLi UNION-based"),
            ('$sqli_sleep', '"SLEEP("', "SQLi time-based"),
            ('$sqli_xp',    '"xp_cmdshell"', "SQLi MSSQL stacked"),
            ('$sqli_blind', '"1=1--"', "SQLi boolean blind"),
        ],
        "supply_chain": [
            ('$sc_postinstall', '"postinstall"', "NPM lifecycle hook"),
            ('$sc_pip_extra',   '"--extra-index-url"', "Pip dependency confusion"),
            ('$sc_github_act',  '".github/workflows"', "GitHub Actions tampering"),
        ],
        "rce": [
            ('$rce_shell',   '"/bin/bash -i"', "Reverse shell"),
            ('$rce_nc',      '"nc -e /bin"', "Netcat reverse shell"),
            ('$rce_python',  '"import socket,subprocess"', "Python reverse shell"),
        ],
        "cmd_inject": [
            ('$ci_cat',  '"cat /etc/passwd"', "Unix credential theft"),
            ('$ci_wget', '"wget http"', "Payload download via wget"),
            ('$ci_curl', '"curl http"', "Payload download via curl"),
        ],
    }

    vuln_lower = vuln_class.lower().replace(" ", "_")
    if vuln_lower in class_strings:
        for var, string_val, comment in class_strings[vuln_lower]:
            strings_lines.append(
                f'        {var} = {string_val} ascii wide nocase  // {comment}'
            )
        condition_parts.append(f"any of (${ {k[0] for k, _, _ in class_strings[vuln_lower]}.pop()}*)")
        # Simpler: use prefix
        prefix_char = class_strings[vuln_lower][0][0][1]  # e.g. '$sqli_union' -> 's'
        first_var_prefix = class_strings[vuln_lower][0][0][:5]  # '$sqli' or '$sc_p' etc
        condition_parts = [f"any of ($hash_*)"] if file_hashes else []
        # rebuild
        prefixes = set()
        for var, _, _ in class_strings.get(vuln_lower, []):
            prefixes.add(var.split('_')[0] + '_' + var.split('_')[1])
        for prefix in prefixes:
            condition_parts.append(f"any of ({prefix}*)")

    # Add real network IOC strings
    for i, ioc in enumerate(real_iocs[:5]):
        strings_lines.append(
            f'        $ioc_{i} = "{ioc}" ascii wide nocase  // Network IOC: {ioc[:40]}'
        )
    if real_iocs:
        condition_parts.append("any of ($ioc_*)")

    # Add user-provided malicious strings
    for i, s in enumerate(malicious_strings[:5]):
        strings_lines.append(
            f'        $mal_{i} = "{s}" ascii wide nocase  // Malicious string'
        )
    if malicious_strings:
        condition_parts.append("any of ($mal_*)")

    # If no strings at all, add a placeholder comment
    if not strings_lines:
        strings_lines = [
            "        // No confirmed IOC strings available for this advisory.",
            "        // Add file hashes, C2 IPs, or malicious strings when available.",
            "        $placeholder = \"APEX-PLACEHOLDER\" ascii  // Remove before deployment",
        ]
        condition_parts = ["$placeholder"]

    strings_block = "\n".join(strings_lines)
    condition = " or ".join(condition_parts) if condition_parts else "false"

    desc = f"{advisory_title[:80].replace(chr(34), chr(39))}"

    return YARA_TEMPLATE.format(
        safe_name=safe_name,
        vuln_class_upper=vuln_upper,
        description=desc,
        cve_id=cve_display,
        date=today,
        severity="high",
        mitre_str=mitre_str,
        strings_block=strings_block,
        condition=condition,
    )


# ---------------------------------------------------------------------------
# Demo / test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    gen = APEXSigmaGenerator()

    # Test 1: SQLi advisory (Drupal)
    print("=" * 60)
    print("TEST 1: SQL Injection Rule (Drupal)")
    print("=" * 60)
    rule = gen.generate(
        advisory_title="CISA Warns of Drupal Core SQL Injection Vulnerability Exploited in Attacks",
        cve_id="CVE-2026-9082",
        vuln_class="sqli",
        mitre_techniques=["T1190", "T1059", "T1190.001"],
        real_iocs=["45.153.204.118"],
        severity="high",
        source_url="https://cybersecuritynews.com/drupal-core-sql-injection-vulnerability-exploited/",
    )
    print(rule.to_yaml())

    # Test 2: Supply chain (npm/GitHub)
    print("=" * 60)
    print("TEST 2: Supply Chain Rule (npm)")
    print("=" * 60)
    rule2 = gen.generate(
        advisory_title="Hackers Compromised 34 Packages in npm PyPI and Crates in New Supply Chain Attack",
        cve_id=None,
        vuln_class="supply_chain",
        mitre_techniques=["T1195.002", "T1554"],
        real_iocs=[],
        severity="high",
    )
    print(rule2.to_yaml())

    # Test 3: YARA with real hashes
    print("=" * 60)
    print("TEST 3: YARA Rule (SQLi with hash)")
    print("=" * 60)
    yara = generate_yara(
        advisory_title="CISA Drupal Core SQL Injection",
        cve_id="CVE-2026-9082",
        vuln_class="sqli",
        mitre_techniques=["T1190"],
        file_hashes=["a3f5d0c9e8b7261453f0a8e56d2c14f0a9b3e7c215d84f60b9c7d3a2e1f8054b"],
        real_iocs=["45.153.204.118"],
    )
    print(yara)

    print("All Sigma conditions use proper spacing — no more 'orKeyword' bugs!")
