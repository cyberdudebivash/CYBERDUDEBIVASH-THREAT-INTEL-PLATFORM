"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — NLP Threat Summarizer
==============================================================
AI-powered threat intelligence summarization.

Features:
- Executive summary generation
- Key findings extraction
- Threat actor profiling
- Technical impact analysis
- Multi-language support

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter

logger = logging.getLogger("CDB-NLP")


@dataclass
class ThreatSummary:
    """Structured threat summary"""
    executive_summary: str
    key_findings: List[str]
    technical_impact: str
    threat_actors: List[str]
    affected_systems: List[str]
    recommended_actions: List[str]
    confidence: float
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "technical_impact": self.technical_impact,
            "threat_actors": self.threat_actors,
            "affected_systems": self.affected_systems,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "generated_at": self.generated_at.isoformat(),
        }


class ThreatSummarizer:
    """
    NLP-based threat intelligence summarizer.
    
    Uses pattern matching and heuristics for offline operation,
    with optional AI backend integration.
    """
    
    # Threat actor patterns
    ACTOR_PATTERNS = [
        r'\b(APT\d+|APT-\d+|APT \d+)\b',
        r'\b(Lazarus|Cozy Bear|Fancy Bear|Equation Group|Sandworm)\b',
        r'\b(Volt Typhoon|Salt Typhoon|Charcoal Typhoon)\b',
        r'\b(TA\d+|UNC\d+|DEV-\d+)\b',
        r'\b(FIN\d+|Evil Corp|REvil|LockBit|BlackCat)\b',
    ]
    
    # System/technology patterns
    SYSTEM_PATTERNS = [
        r'\b(Windows|Linux|macOS|iOS|Android)\b',
        r'\b(Exchange|SharePoint|Active Directory|Azure AD)\b',
        r'\b(VMware|Citrix|Ivanti|Fortinet|Palo Alto)\b',
        r'\b(Apache|Nginx|IIS|Tomcat)\b',
        r'\b(Docker|Kubernetes|AWS|Azure|GCP)\b',
    ]
    
    # Impact keywords by category
    IMPACT_KEYWORDS = {
        "critical": [
            "remote code execution", "rce", "zero-day", "0-day",
            "unauthenticated", "pre-auth", "wormable", "critical vulnerability"
        ],
        "high": [
            "privilege escalation", "data exfiltration", "ransomware",
            "authentication bypass", "command injection", "sql injection"
        ],
        "medium": [
            "information disclosure", "denial of service", "xss",
            "csrf", "path traversal", "memory corruption"
        ],
    }
    
    # Action patterns
    ACTION_KEYWORDS = {
        "patch": ["patch", "update", "upgrade", "fix available"],
        "mitigate": ["workaround", "mitigation", "disable", "restrict access"],
        "monitor": ["monitor", "detect", "investigate", "hunt"],
        "block": ["block", "firewall", "ioc", "indicator"],
    }
    
    def __init__(self, max_summary_length: int = 500):
        self.max_summary_length = max_summary_length
    
    def summarize(
        self,
        title: str,
        content: str,
        severity: str = "medium",
        cvss_score: Optional[float] = None,
    ) -> ThreatSummary:
        """
        Generate comprehensive threat summary.
        
        Args:
            title: Threat title/headline
            content: Full threat content/description
            severity: Severity level
            cvss_score: CVSS score if available
            
        Returns:
            ThreatSummary with all analysis components
        """
        # Clean content
        clean_content = self._clean_text(content)
        
        # Extract components
        threat_actors = self._extract_threat_actors(clean_content)
        affected_systems = self._extract_systems(clean_content)
        impact_analysis = self._analyze_impact(clean_content, severity, cvss_score)
        key_findings = self._extract_key_findings(clean_content, title)
        recommended_actions = self._generate_recommendations(
            clean_content, severity, impact_analysis
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            threat_actors=threat_actors,
            affected_systems=affected_systems,
            impact=impact_analysis,
        )
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            len(key_findings),
            len(threat_actors),
            len(affected_systems),
            bool(cvss_score),
        )
        
        return ThreatSummary(
            executive_summary=executive_summary,
            key_findings=key_findings,
            technical_impact=impact_analysis,
            threat_actors=threat_actors,
            affected_systems=affected_systems,
            recommended_actions=recommended_actions,
            confidence=confidence,
        )
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # Remove URLs
        text = re.sub(r'https?://\S+', ' ', text)
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def _extract_threat_actors(self, content: str) -> List[str]:
        """Extract threat actor names"""
        actors = set()
        
        for pattern in self.ACTOR_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            actors.update(m if isinstance(m, str) else m[0] for m in matches)
        
        return list(actors)[:5]
    
    def _extract_systems(self, content: str) -> List[str]:
        """Extract affected systems/technologies"""
        systems = set()
        
        for pattern in self.SYSTEM_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            systems.update(matches)
        
        return list(systems)[:10]
    
    def _analyze_impact(
        self,
        content: str,
        severity: str,
        cvss_score: Optional[float]
    ) -> str:
        """Analyze and describe technical impact"""
        content_lower = content.lower()
        
        impacts = []
        
        # Check for impact keywords
        for level, keywords in self.IMPACT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in content_lower:
                    impacts.append((level, keyword))
        
        if not impacts:
            return f"{severity.capitalize()} severity threat requiring attention."
        
        # Group by level
        critical = [i[1] for i in impacts if i[0] == "critical"]
        high = [i[1] for i in impacts if i[0] == "high"]
        
        parts = []
        
        if critical:
            parts.append(f"Critical impact: {', '.join(critical[:3])}")
        if high:
            parts.append(f"High risk of: {', '.join(high[:3])}")
        
        if cvss_score and cvss_score >= 9.0:
            parts.append(f"CVSS {cvss_score} indicates critical severity")
        
        return ". ".join(parts) if parts else f"{severity.capitalize()} severity threat."
    
    def _extract_key_findings(self, content: str, title: str) -> List[str]:
        """Extract key findings from content"""
        findings = []
        
        # Split into sentences
        sentences = re.split(r'[.!?]+', content)
        
        # Score sentences by relevance
        scored = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 20 or len(sentence) > 200:
                continue
            
            score = 0
            sentence_lower = sentence.lower()
            
            # Boost for key terms
            if any(term in sentence_lower for term in ["vulnerability", "exploit", "attack"]):
                score += 2
            if any(term in sentence_lower for term in ["allows", "enables", "could"]):
                score += 1
            if any(term in sentence_lower for term in ["remote", "unauthenticated"]):
                score += 2
            if re.search(r'CVE-\d{4}-\d+', sentence):
                score += 3
            
            if score > 0:
                scored.append((score, sentence))
        
        # Sort by score and take top findings
        scored.sort(key=lambda x: x[0], reverse=True)
        
        for _, sentence in scored[:5]:
            # Clean up sentence
            finding = sentence.strip()
            if not finding.endswith('.'):
                finding += '.'
            findings.append(finding)
        
        return findings
    
    def _generate_recommendations(
        self,
        content: str,
        severity: str,
        impact: str
    ) -> List[str]:
        """Generate recommended actions"""
        recommendations = []
        content_lower = content.lower()
        
        # Check for action keywords
        for action_type, keywords in self.ACTION_KEYWORDS.items():
            for keyword in keywords:
                if keyword in content_lower:
                    if action_type == "patch":
                        recommendations.append("Apply vendor patches immediately")
                    elif action_type == "mitigate":
                        recommendations.append("Implement available mitigations")
                    elif action_type == "monitor":
                        recommendations.append("Enable enhanced monitoring")
                    elif action_type == "block":
                        recommendations.append("Block known IOCs at perimeter")
                    break
        
        # Add severity-based recommendations
        if severity.lower() in ["critical", "high"]:
            if "Apply vendor patches" not in str(recommendations):
                recommendations.append("Prioritize patching affected systems")
            recommendations.append("Review systems for indicators of compromise")
        
        # Default recommendations
        if not recommendations:
            recommendations = [
                "Review vendor advisories for updates",
                "Monitor for suspicious activity",
                "Update threat detection rules",
            ]
        
        return list(set(recommendations))[:5]
    
    def _generate_executive_summary(
        self,
        title: str,
        severity: str,
        cvss_score: Optional[float],
        threat_actors: List[str],
        affected_systems: List[str],
        impact: str,
    ) -> str:
        """Generate executive summary paragraph"""
        
        parts = []
        
        # Opening
        parts.append(f"This {severity.lower()} severity threat")
        
        # CVSS if available
        if cvss_score:
            parts.append(f"(CVSS {cvss_score})")
        
        # Affected systems
        if affected_systems:
            systems_str = ", ".join(affected_systems[:3])
            parts.append(f"affects {systems_str} systems")
        
        # Threat actors
        if threat_actors:
            actors_str = ", ".join(threat_actors[:2])
            parts.append(f"and has been linked to {actors_str}")
        
        # Impact
        parts.append(f". {impact}")
        
        summary = " ".join(parts)
        
        # Truncate if needed
        if len(summary) > self.max_summary_length:
            summary = summary[:self.max_summary_length-3] + "..."
        
        return summary
    
    def _calculate_confidence(
        self,
        findings_count: int,
        actors_count: int,
        systems_count: int,
        has_cvss: bool,
    ) -> float:
        """Calculate summary confidence score"""
        score = 0.5  # Base confidence
        
        if findings_count >= 3:
            score += 0.15
        elif findings_count >= 1:
            score += 0.08
        
        if actors_count > 0:
            score += 0.1
        
        if systems_count > 0:
            score += 0.1
        
        if has_cvss:
            score += 0.15
        
        return min(1.0, round(score, 2))


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_summarizer: Optional[ThreatSummarizer] = None


def get_summarizer() -> ThreatSummarizer:
    """Get or create the global summarizer"""
    global _summarizer
    if _summarizer is None:
        _summarizer = ThreatSummarizer()
    return _summarizer


__all__ = ["ThreatSummarizer", "ThreatSummary", "get_summarizer"]
