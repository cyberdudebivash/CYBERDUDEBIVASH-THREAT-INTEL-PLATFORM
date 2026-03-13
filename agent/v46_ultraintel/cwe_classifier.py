#!/usr/bin/env python3
"""
cwe_classifier.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
CWE (Common Weakness Enumeration) classification from CVE title patterns.
Maps 50+ vulnerability type patterns to CWE IDs, names, and categories.
Used for threat modal display and dashboard enrichment.

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-CWE-CLASSIFIER-V46")

# ── CWE DATABASE (50+ mappings) ──────────────────────────────────────────────
# Format: (pattern_list, CWE_ID, CWE_Name, Category, Severity_Hint)
CWE_PATTERN_DB: List[Tuple[List[str], str, str, str, str]] = [
    # Injection Attacks
    (["sql injection", "sqli", "sql inj", "unsanitized.*sql", "rlike clause"],
     "CWE-89", "SQL Injection", "Injection", "HIGH"),
    (["command injection", "os command injection", "command execution"],
     "CWE-78", "OS Command Injection", "Injection", "CRITICAL"),
    (["xpath injection"],
     "CWE-643", "XPath Injection", "Injection", "HIGH"),
    (["ldap injection"],
     "CWE-90", "LDAP Injection", "Injection", "HIGH"),
    (["template injection", "ssti"],
     "CWE-1336", "Improper Neutralization in Template Engine", "Injection", "CRITICAL"),
    (["code injection"],
     "CWE-94", "Code Injection", "Injection", "CRITICAL"),

    # XSS
    (["cross.site scripting", "xss", "script injection", "stored xss",
      "reflected xss", "unauthenticated.*xss", "dom.based xss"],
     "CWE-79", "Cross-site Scripting (XSS)", "Injection", "MEDIUM"),

    # CSRF
    (["cross.site request forgery", "csrf"],
     "CWE-352", "Cross-Site Request Forgery", "Behavioral", "MEDIUM"),

    # Path/Directory Traversal
    (["path traversal", "directory traversal", "local file inclusion",
      "relative path", "extractzip path"],
     "CWE-22", "Path Traversal", "File Handling", "HIGH"),

    # Authentication & Authorization
    (["authentication bypass", "missing authentication", "unauthenticated",
      "improper authentication"],
     "CWE-306", "Missing Authentication for Critical Function", "Auth", "CRITICAL"),
    (["improper access control", "broken access control", "unauthorized access"],
     "CWE-284", "Improper Access Control", "Auth", "HIGH"),
    (["privilege escalation", "privilege escalat"],
     "CWE-269", "Improper Privilege Management", "Auth", "HIGH"),
    (["insecure direct object", "idor", "indirect object reference",
      "broken object level"],
     "CWE-639", "Authorization Bypass Through User-Controlled Key", "Auth", "HIGH"),
    (["session.*fixation", "session token exposure", "session.*url"],
     "CWE-384", "Session Fixation", "Auth", "MEDIUM"),
    (["weak password", "default password", "plaintext credential",
      "plaintext.*password", "credential.*exposure"],
     "CWE-259", "Use of Hard-coded Password", "Auth", "HIGH"),

    # Memory Safety
    (["buffer overflow", "stack overflow", "heap overflow", "heap buffer overflow",
      "buffer overrun"],
     "CWE-120", "Buffer Copy without Checking Size of Input", "Memory", "CRITICAL"),
    (["heap buffer.*overflow", "heap.*over-read"],
     "CWE-122", "Heap-based Buffer Overflow", "Memory", "CRITICAL"),
    (["use after free", "use-after-free", "uaf"],
     "CWE-416", "Use After Free", "Memory", "CRITICAL"),
    (["null pointer", "null dereference"],
     "CWE-476", "NULL Pointer Dereference", "Memory", "MEDIUM"),
    (["integer overflow", "integer underflow"],
     "CWE-190", "Integer Overflow", "Memory", "HIGH"),
    (["out of bounds", "out-of-bounds"],
     "CWE-125", "Out-of-bounds Read", "Memory", "HIGH"),
    (["memory corruption", "memory safety"],
     "CWE-119", "Improper Restriction of Operations within Bounds of Memory Buffer", "Memory", "HIGH"),
    (["memory allocation.*excessive", "excessive.*allocation"],
     "CWE-770", "Allocation of Resources Without Limits", "Resource", "MEDIUM"),

    # Remote Code Execution
    (["remote code execution", "rce", "arbitrary code execution",
      "unauthenticated.*rce", "pre-auth.*rce"],
     "CWE-502", "Deserialization of Untrusted Data", "RCE", "CRITICAL"),

    # Denial of Service
    (["denial of service", "dos attack", "resource exhaustion",
      "memory exhaustion", "cpu exhaustion"],
     "CWE-400", "Uncontrolled Resource Consumption", "DoS", "MEDIUM"),

    # SSRF
    (["server.side request forgery", "ssrf"],
     "CWE-918", "Server-Side Request Forgery", "Web", "HIGH"),

    # Information Disclosure
    (["information disclosure", "information leak", "data exposure",
      "sensitive data.*exposure", "memory leak"],
     "CWE-200", "Exposure of Sensitive Information", "Disclosure", "MEDIUM"),

    # File Upload
    (["unrestricted file upload", "file upload", "arbitrary file upload"],
     "CWE-434", "Unrestricted Upload of File with Dangerous Type", "File Handling", "HIGH"),

    # Race Condition
    (["race condition", "toctou", "time of check"],
     "CWE-362", "Race Condition", "Concurrency", "MEDIUM"),

    # Cryptographic Issues
    (["weak crypto", "weak encryption", "insecure random", "weak hash"],
     "CWE-327", "Use of Broken or Risky Cryptographic Algorithm", "Crypto", "MEDIUM"),
    (["missing.*nosniff", "x-content-type", "clickjacking", "missing.*header",
      "x-frame-options"],
     "CWE-693", "Protection Mechanism Failure", "Config", "LOW"),

    # Deserialization
    (["insecure deserialization", "deserialization", "object deserialization"],
     "CWE-502", "Deserialization of Untrusted Data", "RCE", "CRITICAL"),

    # IDOR / Object Reference
    (["broken object", "insecure direct", "idor"],
     "CWE-639", "Authorization Bypass Through User-Controlled Key", "Auth", "HIGH"),

    # Bootkit / Firmware
    (["firmware", "secure boot bypass", "bootkit", "bootloader"],
     "CWE-494", "Download of Code Without Integrity Check", "Firmware", "CRITICAL"),

    # Uncontrolled Search Path
    (["uncontrolled search path", "dll hijacking", "dll injection",
      "search path element"],
     "CWE-427", "Uncontrolled Search Path Element", "File Handling", "HIGH"),

    # Open Redirect
    (["open redirect", "url redirection"],
     "CWE-601", "URL Redirection to Untrusted Site", "Web", "MEDIUM"),

    # XML/XXE
    (["xxe", "xml external entity", "xml injection"],
     "CWE-611", "Improper Restriction of XML External Entity Reference", "Web", "HIGH"),

    # Supply Chain
    (["supply chain", "backdoor.*package", "malicious.*package"],
     "CWE-494", "Download of Code Without Integrity Check", "Supply Chain", "CRITICAL"),
]

# Fallback: no match
_DEFAULT_CWE = {
    "cwe_id": "CWE-1",
    "cwe_name": "Location",
    "cwe_category": "General",
    "severity_hint": "MEDIUM",
    "matched_pattern": "default",
}


class CWEClassifierV46:
    """
    Pattern-based CWE classifier from CVE title strings.
    Matches title against 50+ regex patterns to assign CWE classification.
    """

    def classify_title(self, title: str) -> Optional[Dict]:
        """
        Classify a CVE title to a CWE.
        Returns dict with cwe_id, cwe_name, cwe_category, severity_hint.
        """
        if not title:
            return None
        title_lower = title.lower()

        for patterns, cwe_id, cwe_name, category, sev in CWE_PATTERN_DB:
            for pattern in patterns:
                try:
                    if re.search(pattern, title_lower):
                        return {
                            "cwe_id": cwe_id,
                            "cwe_name": cwe_name,
                            "cwe_category": category,
                            "severity_hint": sev,
                            "matched_pattern": pattern,
                            "mitre_cwe_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
                        }
                except re.error:
                    continue

        return None

    def enrich_item(self, item: Dict) -> Dict:
        """Enrich item with cwe_classification field."""
        cwe = self.classify_title(item.get("title", ""))
        if cwe:
            item["cwe_classification"] = cwe
        else:
            item["cwe_classification"] = None
        return item

    def batch_enrich(self, items):
        enriched = []
        for item in items:
            try:
                enriched.append(self.enrich_item(item))
            except Exception as e:
                logger.warning(f"CWE classification failed: {e}")
                item.setdefault("cwe_classification", None)
                enriched.append(item)
        return enriched


cwe_classifier_v46 = CWEClassifierV46()
