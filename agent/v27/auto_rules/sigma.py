"""
SENTINEL APEX v27.0 — Sigma Rule Generator
============================================
Generates SIEM-agnostic Sigma detection rules.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .generator import (
    BaseRuleGenerator,
    GeneratedRule,
    RuleType,
    RuleConfidence,
)


class SigmaRuleGenerator(BaseRuleGenerator):
    """
    Generates Sigma rules from threat intelligence.
    
    Sigma is a generic signature format for SIEM systems.
    Rules can be converted to Splunk, Elastic, QRadar, etc.
    """
    
    RULE_TYPE = RuleType.SIGMA
    
    # Log source mappings
    LOG_SOURCES = {
        "process": {"category": "process_creation", "product": "windows"},
        "network": {"category": "network_connection", "product": "windows"},
        "dns": {"category": "dns_query", "product": "windows"},
        "file": {"category": "file_event", "product": "windows"},
        "registry": {"category": "registry_event", "product": "windows"},
        "firewall": {"category": "firewall", "product": "any"},
        "web": {"category": "webserver", "product": "any"},
    }
    
    def generate(
        self,
        threat_data: Dict[str, Any],
        iocs: Optional[List[Dict]] = None,
    ) -> Optional[GeneratedRule]:
        """Generate Sigma rule from threat data"""
        
        title = threat_data.get("title", "Unknown Threat")
        description = threat_data.get("description", "")
        severity = threat_data.get("severity", "medium")
        mitre_techniques = threat_data.get("mitre_techniques", [])
        cve_id = threat_data.get("cve_id")
        
        # Extract IOCs
        extracted_iocs = self._extract_iocs_from_text(description)
        
        # Determine what kind of detection this should be
        detection_type = self._determine_detection_type(extracted_iocs, description)
        
        if not detection_type:
            return None
        
        # Build detection logic
        detection = self._build_detection(detection_type, extracted_iocs, description)
        
        if not detection:
            return None
        
        # Determine log source
        logsource = self.LOG_SOURCES.get(detection_type, {"category": "any"})
        
        # Build Sigma rule
        sigma_rule = {
            "title": self._sanitize_title(title),
            "id": "",  # Will be filled with rule_id
            "status": "experimental",
            "description": self._truncate_description(description),
            "author": "CyberDudeBivash SENTINEL APEX",
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "references": [],
            "tags": [],
            "logsource": logsource,
            "detection": detection,
            "falsepositives": ["Unknown"],
            "level": severity,
        }
        
        # Add references
        if cve_id:
            sigma_rule["references"].append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        
        # Add MITRE tags
        for technique in mitre_techniques[:5]:
            sigma_rule["tags"].append(f"attack.{technique.lower().replace(' ', '_')}")
        
        # Generate rule content
        rule_id = self._generate_rule_id(str(sigma_rule))
        sigma_rule["id"] = rule_id
        
        # Determine confidence
        ioc_count = sum(len(v) for v in extracted_iocs.values())
        confidence = self._determine_confidence(
            ioc_count,
            len(mitre_techniques) > 0,
            detection_type in ["process", "registry"]
        )
        
        # Convert to YAML
        content = yaml.dump(sigma_rule, default_flow_style=False, sort_keys=False)
        
        return GeneratedRule(
            rule_id=rule_id,
            rule_type=RuleType.SIGMA,
            name=sigma_rule["title"],
            description=sigma_rule["description"],
            content=content,
            confidence=confidence,
            severity=severity,
            mitre_techniques=mitre_techniques,
            iocs_used=list(extracted_iocs.keys()),
            source_threat=threat_data.get("id"),
            metadata={"detection_type": detection_type},
        )
    
    def validate(self, rule: GeneratedRule) -> bool:
        """Validate Sigma rule syntax"""
        try:
            parsed = yaml.safe_load(rule.content)
            
            # Check required fields
            required = ["title", "logsource", "detection"]
            for field in required:
                if field not in parsed:
                    return False
            
            # Check detection has condition
            if "condition" not in parsed.get("detection", {}):
                return False
            
            return True
        except yaml.YAMLError:
            return False
    
    def _determine_detection_type(
        self,
        iocs: Dict[str, List[str]],
        description: str
    ) -> Optional[str]:
        """Determine the type of detection based on IOCs and description"""
        desc_lower = description.lower()
        
        if iocs.get("ip") or iocs.get("domain"):
            if any(kw in desc_lower for kw in ["dns", "resolve", "lookup"]):
                return "dns"
            return "network"
        
        if iocs.get("md5") or iocs.get("sha256"):
            return "process"
        
        if any(kw in desc_lower for kw in ["registry", "regkey", "hkey"]):
            return "registry"
        
        if any(kw in desc_lower for kw in ["file", "drop", "create", "write"]):
            return "file"
        
        if any(kw in desc_lower for kw in ["powershell", "cmd", "execute", "spawn"]):
            return "process"
        
        if iocs:
            return "network"  # Default fallback
        
        return None
    
    def _build_detection(
        self,
        detection_type: str,
        iocs: Dict[str, List[str]],
        description: str
    ) -> Optional[Dict[str, Any]]:
        """Build Sigma detection logic"""
        
        if detection_type == "network":
            return self._build_network_detection(iocs)
        elif detection_type == "dns":
            return self._build_dns_detection(iocs)
        elif detection_type == "process":
            return self._build_process_detection(iocs, description)
        elif detection_type == "file":
            return self._build_file_detection(iocs)
        elif detection_type == "registry":
            return self._build_registry_detection(description)
        
        return None
    
    def _build_network_detection(self, iocs: Dict) -> Dict:
        """Build network connection detection"""
        selection = {}
        
        if iocs.get("ip"):
            selection["DestinationIp"] = iocs["ip"][:10]
        
        if iocs.get("domain"):
            selection["DestinationHostname|contains"] = iocs["domain"][:10]
        
        if not selection:
            return None
        
        return {
            "selection": selection,
            "condition": "selection"
        }
    
    def _build_dns_detection(self, iocs: Dict) -> Dict:
        """Build DNS query detection"""
        domains = iocs.get("domain", [])[:10]
        
        if not domains:
            return None
        
        return {
            "selection": {
                "QueryName|contains": domains
            },
            "condition": "selection"
        }
    
    def _build_process_detection(self, iocs: Dict, description: str) -> Dict:
        """Build process creation detection"""
        selection = {}
        
        # Add hash-based detection
        if iocs.get("md5"):
            selection["Hashes|contains"] = iocs["md5"][:5]
        if iocs.get("sha256"):
            selection["Hashes|contains"] = iocs["sha256"][:5]
        
        # Extract process names from description
        process_patterns = re.findall(
            r'\b(\w+\.exe)\b', 
            description, 
            re.IGNORECASE
        )
        if process_patterns:
            selection["Image|endswith"] = list(set(process_patterns))[:5]
        
        if not selection:
            return None
        
        return {
            "selection": selection,
            "condition": "selection"
        }
    
    def _build_file_detection(self, iocs: Dict) -> Dict:
        """Build file event detection"""
        selection = {}
        
        if iocs.get("md5"):
            selection["Hashes|contains"] = iocs["md5"][:5]
        if iocs.get("sha256"):
            selection["Hashes|contains"] = iocs["sha256"][:5]
        
        if not selection:
            return None
        
        return {
            "selection": selection,
            "condition": "selection"
        }
    
    def _build_registry_detection(self, description: str) -> Dict:
        """Build registry event detection"""
        # Extract registry paths from description
        reg_patterns = re.findall(
            r'(HKLM\\[^\s,]+|HKCU\\[^\s,]+|HKEY_[^\s,]+)',
            description,
            re.IGNORECASE
        )
        
        if not reg_patterns:
            return None
        
        return {
            "selection": {
                "TargetObject|contains": list(set(reg_patterns))[:5]
            },
            "condition": "selection"
        }
    
    def _sanitize_title(self, title: str) -> str:
        """Sanitize rule title"""
        # Remove special characters
        sanitized = re.sub(r'[^\w\s\-]', '', title)
        # Limit length
        return sanitized[:100]
    
    def _truncate_description(self, description: str) -> str:
        """Truncate description for rule"""
        if len(description) > 500:
            return description[:497] + "..."
        return description


__all__ = ["SigmaRuleGenerator"]
