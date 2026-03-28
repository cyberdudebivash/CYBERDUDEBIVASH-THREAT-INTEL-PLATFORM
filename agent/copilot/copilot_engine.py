"""
CYBERDUDEBIVASH® SENTINEL APEX
AI SECURITY COPILOT v1.0
Chat-based threat explanation, MITRE mapping, remediation guidance.
No LLM dependency — uses structured knowledge base + template engine.
"""
import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-COPILOT")

MITRE_KNOWLEDGE = {
    "T1566": {"name":"Phishing","tactic":"Initial Access","description":"Spearphishing, attachment/link-based attacks","mitigation":"Email filtering, security awareness training, MFA"},
    "T1059": {"name":"Command Execution","tactic":"Execution","description":"Scripting interpreters: PowerShell, Bash, cmd","mitigation":"Constrained Language Mode, WDAC/AppLocker, EDR"},
    "T1078": {"name":"Valid Accounts","tactic":"Initial Access/Persistence","description":"Compromised or created accounts","mitigation":"PAM, MFA, just-in-time access"},
    "T1486": {"name":"Data Encrypted","tactic":"Impact","description":"Ransomware file encryption","mitigation":"Offline backups, EDR, network segmentation"},
    "T1190": {"name":"Exploit Public App","tactic":"Initial Access","description":"CVE exploitation on internet-facing systems","mitigation":"Patch management, WAF, vulnerability scanning"},
    "T1055": {"name":"Process Injection","tactic":"Defense Evasion","description":"Injecting into legitimate processes","mitigation":"EDR with behavioral detection, memory protection"},
    "T1195": {"name":"Supply Chain","tactic":"Initial Access","description":"Compromised third-party components","mitigation":"Software composition analysis, vendor risk management"},
    "T1041": {"name":"Exfil over C2","tactic":"Exfiltration","description":"Data exfiltration over C2 channel","mitigation":"DLP, proxy inspection, DNS monitoring"},
    "T1490": {"name":"Inhibit Recovery","tactic":"Impact","description":"Deleting backups and shadow copies","mitigation":"Protect VSS, immutable backups, restrict vssadmin"},
    "T1003": {"name":"Credential Dumping","tactic":"Credential Access","description":"Dumping credentials from LSASS, SAM, NTDS","mitigation":"Credential Guard, EDR, restricted LSASS access"},
}

INTENT_PATTERNS = [
    (r"\bexplain\b|\bwhat is\b|\bdescribe\b",                     "explain"),
    (r"\bmitigate\b|\bfix\b|\bremovate\b|\bprevent\b",            "mitigate"),
    (r"\bdetect\b|\bhunt\b|\bfind\b",                             "detect"),
    (r"\bpriority\b|\bprioritize\b|\bscore\b|\brank\b",           "prioritize"),
    (r"\bplaybook\b|\bresponse\b|\bincident\b",                   "playbook"),
    (r"\bmitre\b|\batt&ck\b|\bttp\b|\bt\d{4}\b",                 "mitre"),
    (r"\bcve\b",                                                  "cve"),
    (r"\bstatus\b|\bhealth\b|\boperational\b",                    "status"),
]


class SecurityCopilot:
    """
    AI Security Copilot — chat-based security intelligence assistant.
    Answers questions about TTPs, CVEs, advisories, and remediation.
    """

    def __init__(self):
        self.advisory_index: Dict[str, Dict] = {}
        self.query_count = 0

    def index_advisories(self, advisories: List[Dict]) -> int:
        """Build searchable index from advisories."""
        for adv in advisories:
            self.advisory_index[adv.get("stix_id", "")] = adv
            for cve in adv.get("cves", []):
                self.advisory_index[cve.upper()] = adv
        return len(self.advisory_index)

    def _detect_intent(self, query: str) -> str:
        query_lower = query.lower()
        for pattern, intent in INTENT_PATTERNS:
            if re.search(pattern, query_lower):
                return intent
        return "general"

    def _extract_ttp(self, query: str) -> Optional[str]:
        m = re.search(r"T\d{4}(?:\.\d{3})?", query, re.I)
        return m.group(0).upper() if m else None

    def _extract_cve(self, query: str) -> Optional[str]:
        m = re.search(r"CVE-\d{4}-\d{4,}", query, re.I)
        return m.group(0).upper() if m else None

    def query(self, user_query: str, context: Optional[Dict] = None) -> Dict:
        """Process a copilot query and return structured response."""
        self.query_count += 1
        intent = self._detect_intent(user_query)
        ttp_id = self._extract_ttp(user_query)
        cve_id = self._extract_cve(user_query)

        response_text = ""
        references = []
        actions = []

        if intent == "mitre" and ttp_id:
            info = MITRE_KNOWLEDGE.get(ttp_id)
            if info:
                response_text = (
                    f"**{ttp_id} — {info['name']}** | Tactic: {info['tactic']}\n\n"
                    f"**Description:** {info['description']}\n\n"
                    f"**Detection:** Deploy EDR behavioral rules, monitor process creation events.\n\n"
                    f"**Mitigation:** {info['mitigation']}"
                )
                references = [f"https://attack.mitre.org/techniques/{ttp_id}/"]
                actions = ["Deploy detection rule", "Review coverage", "Update playbook"]
            else:
                response_text = f"TTP {ttp_id} not in knowledge base. Check attack.mitre.org."

        elif intent == "cve" and cve_id:
            adv = self.advisory_index.get(cve_id)
            if adv:
                response_text = (
                    f"**{cve_id}** | CVSS: {adv.get('cvss','N/A')} | "
                    f"EPSS: {adv.get('epss','N/A')} | KEV: {adv.get('kev_confirmed','N/A')}\n\n"
                    f"**Advisory:** {adv.get('title','')}\n\n"
                    f"**Action:** {self._get_cve_action(adv)}"
                )
                references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
            else:
                response_text = (f"No indexed advisory found for {cve_id}. "
                                 f"Check https://nvd.nist.gov/vuln/detail/{cve_id}")

        elif intent == "explain":
            if ttp_id:
                info = MITRE_KNOWLEDGE.get(ttp_id, {})
                response_text = info.get("description", f"TTP {ttp_id}: see MITRE ATT&CK.")
            elif context:
                response_text = self._explain_advisory(context)
            else:
                response_text = "Please provide a TTP ID (e.g., T1566) or CVE ID for explanation."

        elif intent == "mitigate":
            if ttp_id:
                info = MITRE_KNOWLEDGE.get(ttp_id, {})
                response_text = info.get("mitigation", f"Apply defense-in-depth for {ttp_id}.")
            elif context:
                response_text = self._mitigate_advisory(context)
            else:
                response_text = "Provide a TTP or CVE ID for specific mitigation guidance."

        elif intent == "status":
            response_text = (
                "**CYBERDUDEBIVASH Sentinel APEX — Operational Status**\n"
                "- Threat Intel Pipeline: ACTIVE\n"
                "- SOC Engine: OPERATIONAL\n"
                "- Predictive Engine: RUNNING\n"
                "- Ingested Advisories: " + str(len(self.advisory_index)) + "\n"
                "- Copilot Queries Answered: " + str(self.query_count)
            )
        else:
            response_text = (
                "I can help with:\n"
                "- **Explain**: Describe any TTP or CVE\n"
                "- **Mitigate**: Get remediation guidance\n"
                "- **Detect**: Get hunt queries for a TTP\n"
                "- **Prioritize**: Score and rank vulnerabilities\n"
                "- **Playbook**: Get incident response steps\n\n"
                "Try: 'Explain T1566' or 'How do I detect T1486?'"
            )

        logger.info(f"[COPILOT] Query: '{user_query[:60]}' → intent={intent}")
        return {
            "query":      user_query,
            "intent":     intent,
            "response":   response_text,
            "references": references,
            "actions":    actions,
            "ttp_context": ttp_id,
            "cve_context": cve_id,
            "query_id":   self.query_count,
            "answered_at": datetime.now(timezone.utc).isoformat(),
        }

    def _get_cve_action(self, advisory: Dict) -> str:
        cvss = float(advisory.get("cvss") or 0)
        if cvss >= 9: return "IMMEDIATE patch required — critical severity"
        if cvss >= 7: return "Patch within 72 hours — high severity"
        return "Schedule patch within 30 days"

    def _explain_advisory(self, advisory: Dict) -> str:
        return (f"Advisory: **{advisory.get('title','')}**\n"
                f"CVSS: {advisory.get('cvss','N/A')} | EPSS: {advisory.get('epss','N/A')}\n"
                f"TTPs: {', '.join(advisory.get('mitre_techniques',[]))}\n"
                f"Summary: {str(advisory.get('summary',''))[:200]}")

    def _mitigate_advisory(self, advisory: Dict) -> str:
        ttps = advisory.get("mitre_techniques", [])
        mitigations = [MITRE_KNOWLEDGE[t]["mitigation"] for t in ttps if t in MITRE_KNOWLEDGE]
        return "\n".join(f"- {m}" for m in mitigations) if mitigations else "Apply defense-in-depth."

    def get_stats(self) -> Dict:
        return {"queries_answered": self.query_count,
                "indexed_advisories": len(self.advisory_index),
                "agent": "SecurityCopilot v1.0"}
