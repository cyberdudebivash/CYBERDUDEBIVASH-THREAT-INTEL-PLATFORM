"""
SENTINEL APEX v27.0 — YARA Rule Generator
===========================================
Generates YARA rules for malware detection.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .generator import (
    BaseRuleGenerator,
    GeneratedRule,
    RuleType,
    RuleConfidence,
)


class YaraRuleGenerator(BaseRuleGenerator):
    """
    Generates YARA rules from threat intelligence.
    
    YARA rules are used for malware identification and classification.
    """
    
    RULE_TYPE = RuleType.YARA
    
    def generate(
        self,
        threat_data: Dict[str, Any],
        iocs: Optional[List[Dict]] = None,
    ) -> Optional[GeneratedRule]:
        """Generate YARA rule from threat data"""
        
        title = threat_data.get("title", "Unknown_Threat")
        description = threat_data.get("description", "")
        severity = threat_data.get("severity", "medium")
        mitre_techniques = threat_data.get("mitre_techniques", [])
        
        # Extract IOCs
        extracted_iocs = self._extract_iocs_from_text(description)
        
        # Need at least some IOCs for YARA
        if not any(extracted_iocs.values()):
            return None
        
        # Generate rule name
        rule_name = self._sanitize_rule_name(title)
        rule_id = self._generate_rule_id(rule_name)
        
        # Build strings section
        strings_section = self._build_strings(extracted_iocs, description)
        
        if not strings_section:
            return None
        
        # Build condition
        condition = self._build_condition(len(strings_section))
        
        # Build rule content
        content = self._format_rule(
            rule_name=rule_name,
            rule_id=rule_id,
            description=description[:200],
            author="CyberDudeBivash SENTINEL APEX",
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            severity=severity,
            mitre=mitre_techniques[:3],
            strings=strings_section,
            condition=condition,
        )
        
        # Determine confidence
        ioc_count = sum(len(v) for v in extracted_iocs.values())
        confidence = self._determine_confidence(
            ioc_count,
            len(mitre_techniques) > 0,
            bool(extracted_iocs.get("md5") or extracted_iocs.get("sha256"))
        )
        
        return GeneratedRule(
            rule_id=rule_id,
            rule_type=RuleType.YARA,
            name=rule_name,
            description=description[:200],
            content=content,
            confidence=confidence,
            severity=severity,
            mitre_techniques=mitre_techniques,
            iocs_used=[k for k, v in extracted_iocs.items() if v],
            source_threat=threat_data.get("id"),
        )
    
    def validate(self, rule: GeneratedRule) -> bool:
        """Validate YARA rule syntax"""
        content = rule.content
        
        # Basic structure checks
        if "rule " not in content:
            return False
        if "strings:" not in content:
            return False
        if "condition:" not in content:
            return False
        
        # Check for balanced braces
        if content.count("{") != content.count("}"):
            return False
        
        return True
    
    def _build_strings(
        self,
        iocs: Dict[str, List[str]],
        description: str
    ) -> List[Dict[str, str]]:
        """Build YARA strings section"""
        strings = []
        idx = 0
        
        # Add hash strings
        for hash_type in ["md5", "sha256"]:
            for hash_val in iocs.get(hash_type, [])[:3]:
                strings.append({
                    "name": f"$hash{idx}",
                    "type": "text",
                    "value": hash_val.lower(),
                })
                idx += 1
        
        # Add domain strings
        for domain in iocs.get("domain", [])[:5]:
            if len(domain) > 5:  # Skip very short domains
                strings.append({
                    "name": f"$domain{idx}",
                    "type": "text",
                    "value": domain,
                })
                idx += 1
        
        # Add IP strings
        for ip in iocs.get("ip", [])[:5]:
            strings.append({
                "name": f"$ip{idx}",
                "type": "text",
                "value": ip,
            })
            idx += 1
        
        # Add URL strings
        for url in iocs.get("url", [])[:3]:
            # Extract meaningful part of URL
            url_part = url.replace("http://", "").replace("https://", "")[:50]
            strings.append({
                "name": f"$url{idx}",
                "type": "text",
                "value": url_part,
            })
            idx += 1
        
        # Extract suspicious strings from description
        suspicious = self._extract_suspicious_strings(description)
        for s in suspicious[:5]:
            strings.append({
                "name": f"$suspicious{idx}",
                "type": "text",
                "value": s,
            })
            idx += 1
        
        return strings
    
    def _extract_suspicious_strings(self, description: str) -> List[str]:
        """Extract potentially suspicious strings from description"""
        patterns = [
            r'\b(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)\b',
            r'\b(mimikatz|cobalt\s*strike|metasploit)\b',
            r'\b(reverse\s*shell|backdoor|trojan|ransomware)\b',
            r'\b(/c\s+|/k\s+|-enc\s+|-exec\s+)\b',
        ]
        
        found = []
        for pattern in patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            found.extend(matches)
        
        return list(set(found))[:5]
    
    def _build_condition(self, string_count: int) -> str:
        """Build YARA condition"""
        if string_count <= 2:
            return "any of them"
        elif string_count <= 5:
            return "2 of them"
        else:
            threshold = max(2, string_count // 3)
            return f"{threshold} of them"
    
    def _format_rule(
        self,
        rule_name: str,
        rule_id: str,
        description: str,
        author: str,
        date: str,
        severity: str,
        mitre: List[str],
        strings: List[Dict],
        condition: str,
    ) -> str:
        """Format complete YARA rule"""
        
        # Meta section
        meta_lines = [
            f'        description = "{self._escape_string(description)}"',
            f'        author = "{author}"',
            f'        date = "{date}"',
            f'        reference = "CyberDudeBivash SENTINEL APEX"',
            f'        rule_id = "{rule_id}"',
            f'        severity = "{severity}"',
        ]
        
        for i, technique in enumerate(mitre):
            meta_lines.append(f'        mitre_{i} = "{technique}"')
        
        # Strings section
        string_lines = []
        for s in strings:
            if s["type"] == "text":
                string_lines.append(f'        {s["name"]} = "{self._escape_string(s["value"])}" nocase')
            elif s["type"] == "hex":
                string_lines.append(f'        {s["name"]} = {{ {s["value"]} }}')
        
        # Build rule
        rule = f"""rule {rule_name}
{{
    meta:
{chr(10).join(meta_lines)}
    
    strings:
{chr(10).join(string_lines)}
    
    condition:
        {condition}
}}"""
        
        return rule
    
    def _sanitize_rule_name(self, title: str) -> str:
        """Create valid YARA rule name"""
        # Replace spaces and special chars with underscore
        name = re.sub(r'[^\w]', '_', title)
        # Remove consecutive underscores
        name = re.sub(r'_+', '_', name)
        # Remove leading/trailing underscores
        name = name.strip('_')
        # Ensure starts with letter
        if name and not name[0].isalpha():
            name = 'rule_' + name
        # Limit length
        return name[:60] or "unknown_threat"
    
    def _escape_string(self, s: str) -> str:
        """Escape special characters for YARA strings"""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')


__all__ = ["YaraRuleGenerator"]
