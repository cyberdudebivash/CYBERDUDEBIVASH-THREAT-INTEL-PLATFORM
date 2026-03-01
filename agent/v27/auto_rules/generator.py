"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — Auto Rule Generator
============================================================
AI-powered detection rule synthesis from threat intelligence.

Generates:
- Sigma rules (SIEM-agnostic)
- YARA rules (file/memory scanning)
- KQL queries (Microsoft Sentinel)
- SPL queries (Splunk)
- EQL queries (Elastic)

Features:
- IOC-based rule generation
- Behavior-based rule synthesis
- MITRE ATT&CK technique mapping
- Confidence scoring
- Automatic testing/validation

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
import json
import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from enum import Enum

logger = logging.getLogger("CDB-RuleGen")


class RuleType(Enum):
    """Supported rule types"""
    SIGMA = "sigma"
    YARA = "yara"
    KQL = "kql"
    SPL = "spl"
    EQL = "eql"


class RuleConfidence(Enum):
    """Rule confidence levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    EXPERIMENTAL = "experimental"


@dataclass
class GeneratedRule:
    """Container for a generated detection rule"""
    rule_id: str
    rule_type: RuleType
    name: str
    description: str
    content: str
    confidence: RuleConfidence
    severity: str
    mitre_techniques: List[str]
    iocs_used: List[str]
    source_threat: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type.value,
            "name": self.name,
            "description": self.description,
            "content": self.content,
            "confidence": self.confidence.value,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "iocs_used": self.iocs_used,
            "source_threat": self.source_threat,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }
    
    def to_file_content(self) -> str:
        """Get content ready for file export"""
        return self.content


class BaseRuleGenerator(ABC):
    """Base class for rule generators"""
    
    RULE_TYPE: RuleType = None
    
    @abstractmethod
    def generate(
        self,
        threat_data: Dict[str, Any],
        iocs: Optional[List[Dict]] = None,
    ) -> Optional[GeneratedRule]:
        """Generate a detection rule from threat data"""
        pass
    
    @abstractmethod
    def validate(self, rule: GeneratedRule) -> bool:
        """Validate generated rule syntax"""
        pass
    
    def _generate_rule_id(self, content: str) -> str:
        """Generate unique rule ID"""
        hash_input = f"{self.RULE_TYPE.value}:{content}:{datetime.now(timezone.utc).isoformat()}"
        return f"CDB-{self.RULE_TYPE.value.upper()}-{hashlib.sha256(hash_input.encode()).hexdigest()[:12]}"
    
    def _extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text"""
        patterns = {
            "ip": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        }
        
        results = {}
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results[ioc_type] = list(set(matches))
        
        return results
    
    def _map_severity(self, cvss_score: Optional[float]) -> str:
        """Map CVSS score to severity string"""
        if cvss_score is None:
            return "medium"
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        return "low"
    
    def _determine_confidence(
        self,
        ioc_count: int,
        has_mitre: bool,
        has_behavior: bool
    ) -> RuleConfidence:
        """Determine rule confidence based on inputs"""
        score = 0
        
        if ioc_count >= 5:
            score += 3
        elif ioc_count >= 2:
            score += 2
        elif ioc_count >= 1:
            score += 1
        
        if has_mitre:
            score += 2
        
        if has_behavior:
            score += 2
        
        if score >= 6:
            return RuleConfidence.HIGH
        elif score >= 4:
            return RuleConfidence.MEDIUM
        elif score >= 2:
            return RuleConfidence.LOW
        return RuleConfidence.EXPERIMENTAL


class RuleGenerator:
    """
    Main rule generator orchestrator.
    
    Coordinates multiple rule type generators and provides
    unified interface for rule generation.
    """
    
    def __init__(self):
        self._generators: Dict[RuleType, BaseRuleGenerator] = {}
        self._generated_count = 0
    
    def register(self, generator: BaseRuleGenerator):
        """Register a rule generator"""
        self._generators[generator.RULE_TYPE] = generator
        logger.info(f"Registered generator: {generator.RULE_TYPE.value}")
    
    def generate(
        self,
        threat_data: Dict[str, Any],
        rule_types: Optional[List[RuleType]] = None,
        iocs: Optional[List[Dict]] = None,
    ) -> List[GeneratedRule]:
        """
        Generate detection rules from threat data.
        
        Args:
            threat_data: Threat intelligence data
            rule_types: Types of rules to generate (default: all registered)
            iocs: Optional list of IOCs
            
        Returns:
            List of generated rules
        """
        if rule_types is None:
            rule_types = list(self._generators.keys())
        
        rules = []
        
        for rule_type in rule_types:
            generator = self._generators.get(rule_type)
            if not generator:
                logger.warning(f"No generator for rule type: {rule_type}")
                continue
            
            try:
                rule = generator.generate(threat_data, iocs)
                if rule:
                    if generator.validate(rule):
                        rules.append(rule)
                        self._generated_count += 1
                        logger.info(f"Generated {rule_type.value} rule: {rule.rule_id}")
                    else:
                        logger.warning(f"Rule validation failed: {rule.rule_id}")
            except Exception as e:
                logger.error(f"Rule generation error for {rule_type}: {e}")
        
        return rules
    
    def generate_from_manifest_entry(
        self,
        entry: Dict[str, Any],
        rule_types: Optional[List[RuleType]] = None,
    ) -> List[GeneratedRule]:
        """
        Generate rules from a feed manifest entry.
        
        Extracts relevant data from manifest format.
        """
        threat_data = {
            "id": entry.get("id", ""),
            "title": entry.get("title", ""),
            "description": entry.get("content", "") or entry.get("description", ""),
            "severity": entry.get("severity", "medium"),
            "cvss_score": entry.get("cvss_score"),
            "cve_id": entry.get("cve_id"),
            "mitre_techniques": entry.get("mitre_techniques", []),
            "iocs": entry.get("iocs", []),
            "threat_actors": entry.get("threat_actors", []),
            "timestamp": entry.get("timestamp"),
        }
        
        return self.generate(threat_data, rule_types, entry.get("iocs"))
    
    def bulk_generate(
        self,
        manifest_entries: List[Dict],
        rule_types: Optional[List[RuleType]] = None,
        min_severity: str = "medium"
    ) -> Dict[str, List[GeneratedRule]]:
        """
        Generate rules from multiple manifest entries.
        
        Returns rules grouped by type.
        """
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_level = severity_order.get(min_severity, 2)
        
        results: Dict[str, List[GeneratedRule]] = {t.value: [] for t in RuleType}
        
        for entry in manifest_entries:
            entry_severity = entry.get("severity", "medium").lower()
            if severity_order.get(entry_severity, 0) < min_level:
                continue
            
            rules = self.generate_from_manifest_entry(entry, rule_types)
            for rule in rules:
                results[rule.rule_type.value].append(rule)
        
        return results
    
    def export_rules(
        self,
        rules: List[GeneratedRule],
        output_dir: str = "data/rules"
    ) -> Dict[str, str]:
        """
        Export rules to files.
        
        Returns mapping of rule_id to file path.
        """
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        
        file_extensions = {
            RuleType.SIGMA: ".yml",
            RuleType.YARA: ".yar",
            RuleType.KQL: ".kql",
            RuleType.SPL: ".spl",
            RuleType.EQL: ".eql",
        }
        
        exported = {}
        
        for rule in rules:
            ext = file_extensions.get(rule.rule_type, ".txt")
            filename = f"{rule.rule_id}{ext}"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, "w") as f:
                f.write(rule.to_file_content())
            
            exported[rule.rule_id] = filepath
            logger.info(f"Exported rule: {filepath}")
        
        return exported
    
    def get_stats(self) -> Dict[str, Any]:
        """Get generator statistics"""
        return {
            "registered_generators": [t.value for t in self._generators.keys()],
            "total_generated": self._generated_count,
        }


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_generator: Optional[RuleGenerator] = None


def get_rule_generator() -> RuleGenerator:
    """Get or create the global rule generator"""
    global _generator
    if _generator is None:
        _generator = RuleGenerator()
        
        # Register default generators
        from .sigma import SigmaRuleGenerator
        from .yara import YaraRuleGenerator
        from .siem_queries import KQLGenerator, SPLGenerator
        
        _generator.register(SigmaRuleGenerator())
        _generator.register(YaraRuleGenerator())
        _generator.register(KQLGenerator())
        _generator.register(SPLGenerator())
    
    return _generator


__all__ = [
    "RuleGenerator",
    "BaseRuleGenerator",
    "GeneratedRule",
    "RuleType",
    "RuleConfidence",
    "get_rule_generator",
]
