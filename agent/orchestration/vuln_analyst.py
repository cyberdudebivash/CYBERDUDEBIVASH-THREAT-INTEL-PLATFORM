"""
CYBERDUDEBIVASH® SENTINEL APEX
VULNERABILITY ANALYST AGENT — CVE prioritization and patch intelligence
Produces: exploitability assessment, patch priority, affected product mapping.
"""
import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-VULN-ANALYST")

PATCH_PRIORITY = {
    "P1_IMMEDIATE":     {"min_score": 9.0, "label": "Patch within 24h",  "sla": "24 hours"},
    "P2_URGENT":        {"min_score": 7.0, "label": "Patch within 72h",  "sla": "72 hours"},
    "P3_HIGH":          {"min_score": 5.0, "label": "Patch within 7d",   "sla": "7 days"},
    "P4_MEDIUM":        {"min_score": 3.0, "label": "Patch within 30d",  "sla": "30 days"},
    "P5_LOW":           {"min_score": 0.0, "label": "Patch next cycle",  "sla": "90 days"},
}

VENDOR_PATCH_URLS = {
    "microsoft": "https://msrc.microsoft.com/update-guide",
    "cisco":     "https://tools.cisco.com/security/center/publicationListing.x",
    "apache":    "https://httpd.apache.org/security/vulnerabilities_24.html",
    "linux":     "https://www.kernel.org/category/releases.html",
    "vmware":    "https://www.vmware.com/security/advisories.html",
    "fortinet":  "https://www.fortiguard.com/psirt",
    "palo alto": "https://security.paloaltonetworks.com/",
    "juniper":   "https://kb.juniper.net/InfoCenter/index?page=answerlist&channel=TAC",
    "default":   "https://nvd.nist.gov/vuln/search",
}


class VulnerabilityAnalystAgent:
    """
    Autonomous vulnerability analyst.
    Prioritizes CVEs, maps affected products, generates patch guidance.
    """

    def __init__(self):
        self.analyses_done = 0

    def compute_exploitability_score(self, advisory: Dict) -> Dict:
        """Compute composite exploitability score."""
        cvss = float(advisory.get("cvss") or 0)
        epss = float(advisory.get("epss") or 0)
        kev = advisory.get("kev_confirmed", False)
        text = f"{advisory.get('title','')} {advisory.get('summary','')}".lower()

        # Base from CVSS
        score = cvss * 0.4

        # EPSS contribution (0-1 → scaled)
        score += epss * 10 * 0.35

        # KEV bonus
        if kev:
            score += 2.0

        # Context signals
        if "actively exploit" in text or "exploit in the wild" in text:
            score += 1.5
        if "public exploit" in text or "poc" in text or "proof of concept" in text:
            score += 1.0
        if "worm" in text or "self-propagat" in text:
            score += 1.5
        if "no patch" in text or "zero-day" in text or "0-day" in text:
            score += 2.0
        if "authentication bypass" in text or "unauthenticated" in text:
            score += 0.8
        if "remote code execution" in text or "rce" in text:
            score += 1.2

        final = round(min(10.0, score), 2)
        return {
            "exploitability_score": final,
            "exploitability_level": "CRITICAL" if final >= 9 else "HIGH" if final >= 7
                                    else "MEDIUM" if final >= 4 else "LOW",
            "kev_confirmed": kev,
            "factors": {
                "cvss_contribution":    round(cvss * 0.4, 2),
                "epss_contribution":    round(epss * 10 * 0.35, 2),
                "kev_bonus":            2.0 if kev else 0,
                "context_signals_used": True,
            },
        }

    def determine_patch_priority(self, exploitability_score: float) -> Dict:
        for priority_key, config in PATCH_PRIORITY.items():
            if exploitability_score >= config["min_score"]:
                return {
                    "priority": priority_key,
                    "label": config["label"],
                    "sla": config["sla"],
                    "urgency": "CRITICAL" if priority_key == "P1_IMMEDIATE" else
                               "HIGH" if priority_key in ("P2_URGENT", "P3_HIGH") else "MEDIUM",
                }
        return {"priority": "P5_LOW", "label": "Patch next cycle", "sla": "90 days", "urgency": "LOW"}

    def map_affected_products(self, advisory: Dict) -> List[Dict]:
        """Extract and map affected products from advisory."""
        text = f"{advisory.get('title','')} {advisory.get('summary','')}"
        products = []

        vendor_keywords = {
            "Microsoft": ["windows", "office", "azure", "exchange", "iis", "sharepoint"],
            "Cisco":     ["cisco", "ios xe", "asa", "firepower", "webex"],
            "Apache":    ["apache", "tomcat", "log4j", "struts", "httpd"],
            "Linux":     ["linux kernel", "ubuntu", "debian", "red hat", "centos"],
            "VMware":    ["vmware", "vsphere", "vcenter", "esxi", "workspace one"],
            "Fortinet":  ["fortinet", "fortigate", "fortios", "forticlient"],
            "Palo Alto": ["palo alto", "pan-os", "globalprotect", "cortex"],
        }

        text_lower = text.lower()
        for vendor, keywords in vendor_keywords.items():
            if any(kw in text_lower for kw in keywords):
                patch_url = VENDOR_PATCH_URLS.get(vendor.lower().split()[0],
                                                    VENDOR_PATCH_URLS["default"])
                products.append({
                    "vendor": vendor,
                    "matched_keywords": [kw for kw in keywords if kw in text_lower],
                    "patch_advisory_url": patch_url,
                })

        # Extract CVEs mentioned
        cves = list(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)))
        return products if products else [{"vendor": "Unknown", "cves": cves,
                                           "patch_advisory_url": VENDOR_PATCH_URLS["default"]}]

    def generate_patch_guidance(self, advisory: Dict) -> Dict:
        """Generate actionable patch guidance."""
        exploitability = self.compute_exploitability_score(advisory)
        priority = self.determine_patch_priority(exploitability["exploitability_score"])
        products = self.map_affected_products(advisory)
        cves = advisory.get("cves", [])

        guidance = {
            "advisory_id":      advisory.get("stix_id", ""),
            "title":            advisory.get("title", "")[:80],
            "cves":             cves,
            "exploitability":   exploitability,
            "patch_priority":   priority,
            "affected_products": products,
            "patch_steps": [
                f"1. Identify all systems running affected {p['vendor']} software"
                for p in products[:3]
            ] + [
                "2. Apply vendor security patches from advisory URLs",
                "3. Verify patch application via version check",
                "4. Restart affected services if required",
                "5. Update vulnerability scan signatures",
                "6. Document patching in change management system",
            ],
            "compensating_controls": self._get_compensating_controls(advisory),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self.analyses_done += 1
        logger.info(f"[VULN-ANALYST] {advisory.get('title','')[:50]} → "
                    f"Priority={priority['priority']} | Score={exploitability['exploitability_score']}")
        return guidance

    def _get_compensating_controls(self, advisory: Dict) -> List[str]:
        text = f"{advisory.get('title','')} {advisory.get('summary','')}".lower()
        controls = ["Enable enhanced logging and monitoring for affected systems"]
        if "rce" in text or "remote code execution" in text:
            controls.append("Restrict inbound network access to affected services")
            controls.append("Enable application-layer firewall WAF rules")
        if "credential" in text or "authentication" in text:
            controls.append("Enforce MFA on affected systems immediately")
        if "web" in text or "http" in text:
            controls.append("Deploy IPS signatures for known exploit patterns")
        return controls

    def get_stats(self) -> Dict:
        return {"analyses_done": self.analyses_done, "agent": "VulnerabilityAnalystAgent v1.0"}
