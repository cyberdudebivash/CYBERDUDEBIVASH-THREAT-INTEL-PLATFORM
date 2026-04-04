#!/usr/bin/env python3
"""
threat_correlator.py — CYBERDUDEBIVASH® SENTINEL APEX v82.0
════════════════════════════════════════════════════════════════════════════════
THREAT CORRELATION ENGINE
Full chain: CVE → EPSS Score → KEV Status → Exploit Intel → Malware Family
            → Threat Actor → IOC Cluster → Detection Rule → Risk Score

Architecture:
  - CVEEnricher:        NVD API + EPSS scoring + KEV catalog mapping
  - ExploitCorrelator:  Links CVEs to known exploit kits/PoC status
  - MalwareCorrelator:  Maps exploits to malware families via shared IOCs
  - ActorCorrelator:    Links malware to known threat actors (MITRE groups)
  - CorrelationGraph:   In-memory graph linking all entity types
  - RiskScoringEngine:  Multi-factor 0-100 scoring with decay functions
  - ContextEnricher:    Geo/ASN/tag enrichment for IOCs
  - STIXBundleBuilder:  Outputs STIX-2.1 compatible enriched intelligence

Zero external dependencies for core logic (requests is optional).
Graceful degradation: works without network, enriches from cache.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
import threading
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-CORRELATOR")

# ── Optional network imports ──────────────────────────────────────────────────
try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _requests = None  # type: ignore
    _REQUESTS_AVAILABLE = False

# ── Constants ────────────────────────────────────────────────────────────────
BASE_DIR         = Path(__file__).resolve().parent.parent.parent
DATA_DIR         = BASE_DIR / "data" / "correlation"
CACHE_FILE       = DATA_DIR / "correlation_cache.json"
KEV_CACHE_FILE   = DATA_DIR / "kev_catalog.json"
EPSS_CACHE_FILE  = DATA_DIR / "epss_cache.json"
GRAPH_FILE       = DATA_DIR / "threat_graph.json"

# NIST NVD API (no key required for low-volume usage)
NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE    = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# MITRE ATT&CK threat actor to technique mapping (static, curated)
ACTOR_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "APT28":   ["T1566", "T1059", "T1027", "T1190", "T1078"],
    "APT29":   ["T1566", "T1195", "T1071", "T1027", "T1550"],
    "APT41":   ["T1566", "T1059", "T1190", "T1486", "T1133"],
    "Lazarus": ["T1566", "T1059", "T1486", "T1190", "T1027"],
    "FIN7":    ["T1566", "T1059", "T1055", "T1486", "T1078"],
    "Conti":   ["T1486", "T1490", "T1059", "T1027", "T1566"],
    "LockBit": ["T1486", "T1490", "T1059", "T1562", "T1070"],
    "Cl0p":    ["T1566", "T1059", "T1486", "T1537", "T1190"],
    "REvil":   ["T1486", "T1059", "T1027", "T1566", "T1190"],
    "BlackCat":["T1486", "T1490", "T1059", "T1562", "T1190"],
}

# Malware family to threat actor associations (curated Intel)
MALWARE_ACTOR_MAP: Dict[str, str] = {
    "emotet": "TA542", "trickbot": "Wizard Spider", "ryuk": "Wizard Spider",
    "lockbit": "LockBit", "revil": "REvil", "conti": "Conti",
    "cobaltstrike": "Multiple", "mimikatz": "Multiple",
    "wannacry": "Lazarus", "notpetya": "Sandworm",
    "solarwinds": "APT29", "sunburst": "APT29",
    "blackcat": "BlackCat", "alphv": "BlackCat",
    "cl0p": "Cl0p", "clop": "Cl0p",
    "fin7": "FIN7", "carbanak": "FIN7",
    "hafnium": "HAFNIUM", "exchange": "HAFNIUM",
    "bluekeep": "Multiple", "eternalblue": "NSA/Shadow Brokers",
    "log4shell": "Multiple", "log4j": "Multiple",
    "spring4shell": "Multiple",
}

# CVE severity to CVSS approximate mapping (for fallback scoring)
SEVERITY_CVSS: Dict[str, float] = {
    "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5, "NONE": 1.0
}


# ════════════════════════════════════════════════════════════════════════════════
# CVE ENRICHER — NVD + EPSS + KEV
# ════════════════════════════════════════════════════════════════════════════════

class CVEEnricher:
    """
    Fetches CVE metadata from NVD, EPSS probability scores, and KEV catalog.
    Implements aggressive caching with TTL to minimize external API calls.
    """

    CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    CACHE_TTL_HOURS = 24
    REQUEST_TIMEOUT = 10

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._nvd_cache: Dict[str, Dict] = self._load_cache(CACHE_FILE)
        self._epss_cache: Dict[str, float] = self._load_cache(EPSS_CACHE_FILE)
        self._kev_set: Set[str] = self._load_kev_set()
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────

    def extract_cves(self, text: str) -> List[str]:
        """Extract unique CVE IDs from text, normalized to uppercase."""
        found = self.CVE_PATTERN.findall(text)
        return list({cve.upper() for cve in found})

    def enrich_cve(self, cve_id: str) -> Dict:
        """
        Return full enrichment for a CVE:
          - CVSS base score + vector
          - EPSS probability (exploitation likelihood)
          - KEV status (is it actively exploited?)
          - Affected products (CPE)
          - Published / modified dates
          - CWE weakness type
        """
        cve_id = cve_id.upper()
        cached = self._get_cached(cve_id)
        if cached:
            return cached

        enrichment = self._build_base_enrichment(cve_id)

        if _REQUESTS_AVAILABLE:
            enrichment.update(self._fetch_nvd(cve_id))
            enrichment["epss_score"] = self._fetch_epss(cve_id)

        enrichment["kev_status"] = cve_id in self._kev_set
        enrichment["risk_multiplier"] = self._compute_risk_multiplier(enrichment)

        self._cache_result(cve_id, enrichment)
        return enrichment

    def enrich_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Enrich multiple CVEs efficiently."""
        return {cve_id: self.enrich_cve(cve_id) for cve_id in set(cve_ids)}

    def is_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._kev_set

    def get_epss(self, cve_id: str) -> float:
        return self._epss_cache.get(cve_id.upper(), 0.0)

    # ── NVD Fetch ───────────────────────────────────────────────────────────

    def _fetch_nvd(self, cve_id: str) -> Dict:
        """Fetch CVE data from NVD API v2.0."""
        try:
            resp = _requests.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                timeout=self.REQUEST_TIMEOUT,
                headers={"User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX/82.0"}
            )
            if resp.status_code != 200:
                return {}

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {}

            cve_data = vulns[0].get("cve", {})
            return self._parse_nvd_cve(cve_data)

        except Exception as e:
            logger.debug(f"NVD fetch failed for {cve_id}: {e}")
            return {}

    def _parse_nvd_cve(self, cve_data: Dict) -> Dict:
        """Parse NVD CVE response into enrichment dict."""
        result = {}

        # Description
        descs = cve_data.get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                result["description"] = d.get("value", "")
                break

        # CVSS v3.1 metrics
        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        if cvss_v31:
            cvss = cvss_v31[0].get("cvssData", {})
            result["cvss_score"] = cvss.get("baseScore", 0.0)
            result["cvss_severity"] = cvss.get("baseSeverity", "UNKNOWN")
            result["cvss_vector"] = cvss.get("vectorString", "")
            result["cvss_version"] = "3.1"
        else:
            cvss_v30 = metrics.get("cvssMetricV30", [{}])
            if cvss_v30:
                cvss = cvss_v30[0].get("cvssData", {})
                result["cvss_score"] = cvss.get("baseScore", 0.0)
                result["cvss_severity"] = cvss.get("baseSeverity", "UNKNOWN")
                result["cvss_vector"] = cvss.get("vectorString", "")
                result["cvss_version"] = "3.0"

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwes.append(d.get("value", ""))
        result["cwe_ids"] = cwes[:5]

        # CPE / Affected products
        configs = cve_data.get("configurations", [])
        products = set()
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product_name = parts[4]
                        if vendor not in ("*", "-") and product_name not in ("*", "-"):
                            products.add(f"{vendor}:{product_name}")
        result["affected_products"] = list(products)[:20]

        # Dates
        result["published_date"] = cve_data.get("published", "")
        result["modified_date"] = cve_data.get("lastModified", "")

        # References
        refs = cve_data.get("references", [])
        result["references"] = [r.get("url", "") for r in refs[:5]]

        return result

    def _fetch_epss(self, cve_id: str) -> float:
        """Fetch EPSS exploitation probability score from FIRST.org."""
        cached = self._epss_cache.get(cve_id)
        if cached is not None:
            return cached

        try:
            resp = _requests.get(
                EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=self.REQUEST_TIMEOUT,
                headers={"User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX/82.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                epss_list = data.get("data", [])
                if epss_list:
                    score = float(epss_list[0].get("epss", 0.0))
                    with self._lock:
                        self._epss_cache[cve_id] = score
                    return score
        except Exception as e:
            logger.debug(f"EPSS fetch failed for {cve_id}: {e}")

        return 0.0

    def _load_kev_set(self) -> Set[str]:
        """Load CISA KEV catalog from cache or fetch fresh."""
        if KEV_CACHE_FILE.exists():
            age_hours = (time.time() - KEV_CACHE_FILE.stat().st_mtime) / 3600
            if age_hours < 24:
                try:
                    data = json.loads(KEV_CACHE_FILE.read_text())
                    vulns = data.get("vulnerabilities", [])
                    return {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
                except Exception:
                    pass

        # Try fetching fresh KEV catalog
        if _REQUESTS_AVAILABLE:
            try:
                resp = _requests.get(KEV_CATALOG_URL, timeout=15,
                                     headers={"User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX/82.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    KEV_CACHE_FILE.write_text(json.dumps(data))
                    vulns = data.get("vulnerabilities", [])
                    return {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
            except Exception as e:
                logger.debug(f"KEV fetch failed: {e}")

        return set()

    def _build_base_enrichment(self, cve_id: str) -> Dict:
        """Build base enrichment structure."""
        return {
            "cve_id": cve_id,
            "cvss_score": 0.0,
            "cvss_severity": "UNKNOWN",
            "cvss_vector": "",
            "cvss_version": "",
            "epss_score": 0.0,
            "kev_status": False,
            "description": "",
            "affected_products": [],
            "cwe_ids": [],
            "references": [],
            "published_date": "",
            "modified_date": "",
            "risk_multiplier": 1.0,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

    def _compute_risk_multiplier(self, enrichment: Dict) -> float:
        """
        Compute composite risk multiplier:
          KEV status:       +3.0x (actively exploited = critical)
          EPSS > 0.7:       +2.0x
          EPSS 0.3-0.7:     +1.5x
          CVSS >= 9.0:      +1.5x
          CVSS 7.0-8.9:     +1.2x
        Max multiplier: 4.0 (capped to prevent runaway scores)
        """
        mult = 1.0
        if enrichment.get("kev_status"):
            mult += 3.0
        epss = enrichment.get("epss_score", 0.0)
        if epss >= 0.7:
            mult += 2.0
        elif epss >= 0.3:
            mult += 1.5
        cvss = enrichment.get("cvss_score", 0.0)
        if cvss >= 9.0:
            mult += 1.5
        elif cvss >= 7.0:
            mult += 1.2
        return min(4.0, round(mult, 2))

    # ── Cache helpers ────────────────────────────────────────────────────────

    def _get_cached(self, cve_id: str) -> Optional[Dict]:
        entry = self._nvd_cache.get(cve_id)
        if not entry:
            return None
        enriched_at = entry.get("enriched_at", "")
        if enriched_at:
            try:
                ts = datetime.fromisoformat(enriched_at.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
                if age < self.CACHE_TTL_HOURS:
                    return entry
            except Exception:
                pass
        return None

    def _cache_result(self, cve_id: str, data: Dict):
        with self._lock:
            self._nvd_cache[cve_id] = data
            try:
                CACHE_FILE.write_text(json.dumps(self._nvd_cache, default=str, indent=2))
            except Exception:
                pass

    @staticmethod
    def _load_cache(path: Path) -> Dict:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return {}


# ════════════════════════════════════════════════════════════════════════════════
# EXPLOIT CORRELATOR
# ════════════════════════════════════════════════════════════════════════════════

class ExploitCorrelator:
    """
    Correlates CVEs with exploit availability signals.
    Sources: NVD references, keyword matching in intel content,
    known exploit-kit CVE associations.
    """

    # CVEs with known exploit kits / ransomware usage (curated set)
    KNOWN_EXPLOITED_CVES: Dict[str, Dict] = {
        "CVE-2021-44228": {"name": "Log4Shell", "kit": "Multiple", "malware": ["LockBit", "Khonsari"]},
        "CVE-2021-34527": {"name": "PrintNightmare", "kit": "Multiple", "malware": ["Magniber"]},
        "CVE-2021-26855": {"name": "ProxyLogon", "kit": "HAFNIUM", "malware": ["China Chopper", "DLTMiner"]},
        "CVE-2021-26084": {"name": "Confluence RCE", "kit": "Multiple", "malware": ["z0Miner", "LemonDuck"]},
        "CVE-2021-21985": {"name": "VMware vCenter RCE", "kit": "Multiple", "malware": ["DarkSide"]},
        "CVE-2022-30190": {"name": "Follina/MSDT", "kit": "APT28", "malware": ["QakBot"]},
        "CVE-2022-26134": {"name": "Atlassian Confluence RCE", "kit": "Multiple", "malware": ["Cerber"]},
        "CVE-2023-23397": {"name": "Outlook NTLM Leak", "kit": "APT28", "malware": []},
        "CVE-2023-34048": {"name": "VMware vCenter DCERPC", "kit": "Multiple", "malware": []},
        "CVE-2023-22515": {"name": "Confluence Priv Esc", "kit": "Multiple", "malware": []},
        "CVE-2024-3400": {"name": "PAN-OS Command Injection", "kit": "UTA0218", "malware": ["UPSTYLE"]},
        "CVE-2024-21762": {"name": "FortiOS SSL VPN RCE", "kit": "Multiple", "malware": []},
        "CVE-2024-27198": {"name": "TeamCity Auth Bypass", "kit": "Multiple", "malware": []},
        "CVE-2023-20198": {"name": "Cisco IOS XE Priv Esc", "kit": "Multiple", "malware": ["Implant"]},
        "CVE-2024-1709":  {"name": "ConnectWise ScreenConnect", "kit": "Multiple", "malware": ["LockBit", "BlackCat"]},
        "CVE-2024-6387":  {"name": "OpenSSH regreSSHion", "kit": "Multiple", "malware": []},
    }

    EXPLOIT_KEYWORDS = [
        "exploit", "poc", "proof of concept", "0day", "zero-day", "metasploit",
        "cobalt strike", "nuclei template", "weaponized", "in the wild",
        "active exploitation", "actively exploited", "exploit kit",
        "shellcode", "remote code execution", "rce", "arbitrary code",
        "exploit available", "exploit published",
    ]

    def correlate_cve_exploits(self, cve_id: str, intel_text: str = "") -> Dict:
        """
        Return exploit correlation for a CVE:
          - exploit_available: bool
          - exploit_maturity: none/poc/weaponized/in_wild
          - associated_malware: list of malware families
          - associated_actors: list of threat actors
          - exploit_refs: reference URLs
        """
        cve_upper = cve_id.upper()

        # Check curated known-exploited list
        if cve_upper in self.KNOWN_EXPLOITED_CVES:
            entry = self.KNOWN_EXPLOITED_CVES[cve_upper]
            return {
                "exploit_available": True,
                "exploit_maturity": "in_wild",
                "exploit_name": entry.get("name", ""),
                "associated_malware": entry.get("malware", []),
                "associated_actors": [entry.get("kit", "")] if entry.get("kit") else [],
                "exploit_source": "curated_intel",
            }

        # Signal detection from text content
        text_lower = intel_text.lower()
        exploit_signals = sum(1 for kw in self.EXPLOIT_KEYWORDS if kw in text_lower)

        if exploit_signals >= 3:
            maturity = "in_wild"
        elif exploit_signals >= 2:
            maturity = "weaponized"
        elif exploit_signals >= 1:
            maturity = "poc"
        else:
            maturity = "none"

        return {
            "exploit_available": exploit_signals > 0,
            "exploit_maturity": maturity,
            "exploit_name": "",
            "associated_malware": self._extract_malware_from_text(text_lower),
            "associated_actors": self._extract_actors_from_text(text_lower),
            "exploit_source": "signal_analysis",
            "exploit_signal_strength": exploit_signals,
        }

    def _extract_malware_from_text(self, text: str) -> List[str]:
        families = []
        for family in MALWARE_ACTOR_MAP.keys():
            if family in text:
                families.append(family.title())
        return list(set(families))[:10]

    def _extract_actors_from_text(self, text: str) -> List[str]:
        actors = []
        for actor in ACTOR_TECHNIQUE_MAP.keys():
            if actor.lower() in text:
                actors.append(actor)
        return list(set(actors))[:5]


# ════════════════════════════════════════════════════════════════════════════════
# MALWARE CORRELATOR
# ════════════════════════════════════════════════════════════════════════════════

class MalwareCorrelator:
    """
    Maps malware families to TTPs, actors, and shared IOC signatures.
    """

    MALWARE_TTP_MAP: Dict[str, List[str]] = {
        "emotet":        ["T1566.001", "T1059.003", "T1027", "T1071.001"],
        "trickbot":      ["T1566.001", "T1059.001", "T1082", "T1016", "T1486"],
        "ryuk":          ["T1486", "T1490", "T1059.001", "T1570"],
        "lockbit":       ["T1486", "T1490", "T1059.003", "T1562.001", "T1070.004"],
        "conti":         ["T1566.001", "T1059.003", "T1486", "T1490", "T1027"],
        "cobalt strike": ["T1055", "T1071.001", "T1059.001", "T1021.002", "T1078"],
        "mimikatz":      ["T1003.001", "T1003.002", "T1558.003"],
        "log4j":         ["T1190", "T1059", "T1105"],
        "blackcat":      ["T1486", "T1490", "T1059", "T1562", "T1190"],
        "cl0p":          ["T1566", "T1059", "T1486", "T1537", "T1190"],
        "revil":         ["T1486", "T1059.001", "T1027", "T1566.001", "T1190"],
    }

    MALWARE_INDICATORS: Dict[str, Dict] = {
        "cobalt strike": {
            "network_patterns": ["beacon", "c2", "malleable profile"],
            "process_patterns": ["rundll32", "wscript", "cmstp"],
            "file_patterns": [".cobaltstrike.beacon", "artifact.exe"],
        },
        "emotet": {
            "network_patterns": ["epoch4", "epoch5"],
            "process_patterns": ["regsvr32", "wscript"],
            "file_patterns": ["emotet_*.dll"],
        },
    }

    FAMILY_PATTERN = re.compile(
        r'\b(emotet|trickbot|ryuk|lockbit|conti|cobalt\s?strike|mimikatz|'
        r'log4j|blackcat|alphv|cl0p|clop|revil|sodinokibi|qakbot|dridex|'
        r'formbook|remcos|njrat|asyncrat|raccoon|vidar|redline|'
        r'wannacry|notpetya|petya|maze|ragnar|darkside)\b',
        re.IGNORECASE
    )

    def extract_malware_families(self, text: str) -> List[str]:
        found = self.FAMILY_PATTERN.findall(text)
        normalized = []
        for f in found:
            f_norm = f.lower().replace(" ", "")
            if f_norm in ("alphv",):
                f_norm = "blackcat"
            elif f_norm in ("sodinokibi",):
                f_norm = "revil"
            elif f_norm in ("cobaltstrike",):
                f_norm = "cobalt strike"
            normalized.append(f_norm)
        return list(set(normalized))

    def get_malware_ttps(self, family: str) -> List[str]:
        return self.MALWARE_TTP_MAP.get(family.lower(), [])

    def get_malware_actor(self, family: str) -> Optional[str]:
        return MALWARE_ACTOR_MAP.get(family.lower())

    def correlate_malware(self, families: List[str], iocs: Dict) -> Dict:
        """Return full malware correlation for a set of detected families."""
        if not families:
            return {"families": [], "ttps": [], "actors": [], "ioc_signatures": []}

        all_ttps = []
        all_actors = []
        for fam in families:
            all_ttps.extend(self.get_malware_ttps(fam))
            actor = self.get_malware_actor(fam)
            if actor:
                all_actors.append(actor)

        return {
            "families": families,
            "family_count": len(families),
            "ttps": list(set(all_ttps))[:20],
            "actors": list(set(all_actors))[:10],
            "ioc_signature_count": sum(len(v) for v in iocs.values() if isinstance(v, list)),
        }


# ════════════════════════════════════════════════════════════════════════════════
# ACTOR CORRELATOR
# ════════════════════════════════════════════════════════════════════════════════

class ActorCorrelator:
    """
    Links threat actors to campaigns, TTPs, target sectors, and IOC patterns.
    """

    ACTOR_PROFILE: Dict[str, Dict] = {
        "APT28": {
            "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Strontium"],
            "nation": "Russia", "motivation": "espionage",
            "targets": ["government", "defense", "aerospace", "energy"],
            "primary_ttps": ["T1566", "T1059", "T1027", "T1190", "T1078"],
        },
        "APT29": {
            "aliases": ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard"],
            "nation": "Russia", "motivation": "espionage",
            "targets": ["government", "think tanks", "healthcare", "energy"],
            "primary_ttps": ["T1566", "T1195", "T1071", "T1027", "T1550"],
        },
        "APT41": {
            "aliases": ["Double Dragon", "Winnti", "Barium"],
            "nation": "China", "motivation": "espionage+financial",
            "targets": ["healthcare", "gaming", "telecom", "technology"],
            "primary_ttps": ["T1566", "T1059", "T1190", "T1486", "T1133"],
        },
        "Lazarus": {
            "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
            "nation": "North Korea", "motivation": "financial+espionage",
            "targets": ["cryptocurrency", "finance", "defense", "aerospace"],
            "primary_ttps": ["T1566", "T1059", "T1486", "T1190", "T1027"],
        },
        "FIN7": {
            "aliases": ["Carbanak", "Anunak"],
            "nation": "Unknown/Russia", "motivation": "financial",
            "targets": ["retail", "hospitality", "finance"],
            "primary_ttps": ["T1566", "T1059", "T1055", "T1486", "T1078"],
        },
    }

    ACTOR_PATTERN = re.compile(
        r'\b(apt\s*\d{1,3}|lazarus|kimsuky|sandworm|cozy\s?bear|fancy\s?bear|'
        r'fin\d|carbanak|anunak|darkside|revil|lockbit|conti|cl0p|clop|'
        r'hafnium|equation\s?group|turla|gamaredon|nobelium|midnight\s?blizzard|'
        r'scattered\s?spider|scattered\sspider)\b',
        re.IGNORECASE
    )

    def extract_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text."""
        found = self.ACTOR_PATTERN.findall(text)
        normalized = []
        for a in found:
            a_norm = a.strip()
            # Normalize aliases
            a_lower = a_norm.lower().replace(" ", "")
            if a_lower in ("cozybear", "cozy bear"):
                a_norm = "APT29"
            elif a_lower in ("fancybear", "fancy bear", "sofacy"):
                a_norm = "APT28"
            normalized.append(a_norm.upper() if len(a_norm) <= 8 else a_norm.title())
        return list(set(normalized))[:10]

    def get_actor_profile(self, actor: str) -> Dict:
        """Get detailed actor profile."""
        profile = self.ACTOR_PROFILE.get(actor.upper(), {})
        if not profile:
            # Return minimal profile for unknown actors
            return {
                "actor_id": actor,
                "aliases": [],
                "nation": "Unknown",
                "motivation": "Unknown",
                "targets": [],
                "primary_ttps": ACTOR_TECHNIQUE_MAP.get(actor, []),
            }
        return {**profile, "actor_id": actor.upper()}

    def correlate_actors(self, actors: List[str], ttps: List[str]) -> List[Dict]:
        """Correlate actors with TTP overlap scoring."""
        enriched = []
        for actor in actors:
            profile = self.get_actor_profile(actor)
            actor_ttps = set(profile.get("primary_ttps", []))
            input_ttps = set(ttps)
            overlap = actor_ttps & input_ttps
            confidence = min(0.95, 0.3 + len(overlap) * 0.13)
            enriched.append({
                **profile,
                "ttp_overlap": list(overlap),
                "ttp_overlap_count": len(overlap),
                "attribution_confidence": round(confidence, 2),
            })
        return sorted(enriched, key=lambda x: x["attribution_confidence"], reverse=True)


# ════════════════════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class RiskScoringEngine:
    """
    Multi-factor risk scoring (0-100) with temporal decay.

    Score components:
      - CVE CVSS base score        (0-30 points)
      - EPSS exploitation prob     (0-20 points)
      - KEV active exploitation    (0-25 points)
      - Malware family severity    (0-15 points)
      - IOC density                (0-5 points)
      - Actor sophistication       (0-5 points)
    Total: 0-100, then temporal decay applied

    Decay: score × e^(-λt) where λ=0.1/day, t=days since published
    """

    MALWARE_SEVERITY: Dict[str, float] = {
        "lockbit": 15.0, "blackcat": 15.0, "conti": 14.0, "revil": 14.0,
        "cl0p": 14.0, "darkside": 13.0, "ryuk": 13.0, "emotet": 11.0,
        "cobalt strike": 10.0, "trickbot": 9.0, "mimikatz": 7.0,
        "log4j": 8.0, "wannacry": 12.0, "notpetya": 15.0,
    }

    ACTOR_SOPHISTICATION: Dict[str, float] = {
        "APT28": 5.0, "APT29": 5.0, "APT41": 5.0, "Lazarus": 4.5,
        "FIN7": 4.0, "Sandworm": 5.0, "Equation Group": 5.0,
        "LockBit": 3.5, "Conti": 3.5,
    }

    DECAY_LAMBDA = 0.05  # Slower decay for threat intel (more persistent than news)
    MAX_DECAY_DAYS = 90  # Beyond 90 days, score floor kicks in

    def compute_score(
        self,
        cve_enrichment: Dict,
        exploit_correlation: Dict,
        malware_correlation: Dict,
        actor_correlation: List[Dict],
        iocs: Dict,
        published_date: str = "",
    ) -> Dict:
        """
        Compute composite risk score with full breakdown.
        Returns score dict with component breakdown + final score.
        """
        components = {}

        # ── CVE CVSS component (0-30) ──────────────────────────────────────
        cvss = cve_enrichment.get("cvss_score", 0.0)
        components["cvss"] = round(min(30.0, cvss * 3.0), 1)

        # ── EPSS component (0-20) ──────────────────────────────────────────
        epss = cve_enrichment.get("epss_score", 0.0)
        components["epss"] = round(epss * 20.0, 1)

        # ── KEV component (0-25) ───────────────────────────────────────────
        kev = cve_enrichment.get("kev_status", False)
        components["kev"] = 25.0 if kev else 0.0

        # ── Exploit maturity component (bonus within KEV/EPSS) ─────────────
        exploit_maturity = exploit_correlation.get("exploit_maturity", "none")
        maturity_bonus = {"in_wild": 5.0, "weaponized": 3.0, "poc": 1.5, "none": 0.0}
        components["exploit_maturity_bonus"] = maturity_bonus.get(exploit_maturity, 0.0)

        # ── Malware severity component (0-15) ─────────────────────────────
        malware_families = malware_correlation.get("families", [])
        max_malware_sev = max(
            (self.MALWARE_SEVERITY.get(f.lower(), 0.0) for f in malware_families),
            default=0.0
        )
        components["malware"] = round(min(15.0, max_malware_sev), 1)

        # ── IOC density component (0-5) ────────────────────────────────────
        ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
        components["ioc_density"] = round(min(5.0, ioc_count * 0.1), 1)

        # ── Actor sophistication component (0-5) ───────────────────────────
        actor_scores = [
            self.ACTOR_SOPHISTICATION.get(a.get("actor_id", ""), 2.0)
            for a in actor_correlation[:3]
        ]
        components["actor"] = round(max(actor_scores, default=0.0), 1)

        # ── Raw score ─────────────────────────────────────────────────────
        raw_score = sum(components.values())
        raw_score = min(100.0, raw_score)

        # ── Temporal decay ────────────────────────────────────────────────
        age_days = self._compute_age_days(published_date)
        decay_factor = self._decay(age_days)
        floor = 10.0 if kev else 0.0  # KEV items never go below 10
        decayed = max(floor, raw_score * decay_factor)

        final_score = round(decayed, 1)
        severity = self._score_to_severity(final_score)

        return {
            "risk_score": final_score,
            "severity": severity,
            "components": components,
            "raw_score": round(raw_score, 1),
            "decay_factor": round(decay_factor, 3),
            "age_days": age_days,
            "scoring_version": "v82.0",
        }

    def _decay(self, age_days: int) -> float:
        """Exponential decay: score × e^(-λt), floored at 0.1 for recent."""
        if age_days <= 0:
            return 1.0
        capped = min(age_days, self.MAX_DECAY_DAYS)
        return max(0.1, math.exp(-self.DECAY_LAMBDA * capped))

    def _compute_age_days(self, published_date: str) -> int:
        if not published_date:
            return 0
        try:
            pub = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - pub).days
        except Exception:
            return 0

    def _score_to_severity(self, score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFORMATIONAL"


# ════════════════════════════════════════════════════════════════════════════════
# CONTEXT ENRICHER — Geo/ASN/Tag enrichment for IOCs
# ════════════════════════════════════════════════════════════════════════════════

class ContextEnricher:
    """
    Enriches IOCs with geolocation, ASN, and behavioral tags.
    Uses ip-api.com (free) with aggressive caching.
    Graceful: returns empty enrichment if network unavailable.
    """

    IP_API_URL = "http://ip-api.com/batch"
    CACHE: Dict[str, Dict] = {}
    BATCH_SIZE = 100

    PRIVATE_RANGES = [
        re.compile(r'^10\.'), re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
        re.compile(r'^192\.168\.'), re.compile(r'^127\.'), re.compile(r'^0\.'),
        re.compile(r'^169\.254\.'), re.compile(r'^::1$'), re.compile(r'^fc00:'),
    ]

    def enrich_iocs(self, iocs: Dict) -> Dict:
        """Enrich IPs with geo/ASN, return enriched context dict."""
        context = {"ips": {}, "domains": {}, "tags": []}

        ips = [ip for ip in iocs.get("ipv4", []) if not self._is_private(ip)][:50]
        if ips and _REQUESTS_AVAILABLE:
            context["ips"] = self._batch_geo_lookup(ips)

        # Tag generation from IOC patterns
        context["tags"] = self._generate_tags(iocs, context["ips"])
        return context

    def _is_private(self, ip: str) -> bool:
        return any(p.match(ip) for p in self.PRIVATE_RANGES)

    def _batch_geo_lookup(self, ips: List[str]) -> Dict[str, Dict]:
        result = {}
        uncached = [ip for ip in ips if ip not in self.CACHE]

        if uncached:
            try:
                payload = [{"query": ip, "fields": "status,country,regionName,city,isp,org,as,threat"} for ip in uncached[:self.BATCH_SIZE]]
                resp = _requests.post(self.IP_API_URL, json=payload, timeout=8)
                if resp.status_code == 200:
                    for i, geo in enumerate(resp.json()):
                        if i < len(uncached) and geo.get("status") == "success":
                            self.CACHE[uncached[i]] = geo
            except Exception as e:
                logger.debug(f"Geo lookup failed: {e}")

        for ip in ips:
            result[ip] = self.CACHE.get(ip, {"status": "unavailable"})

        return result

    def _generate_tags(self, iocs: Dict, geo_data: Dict) -> List[str]:
        tags = []
        countries = Counter()
        for ip_data in geo_data.values():
            country = ip_data.get("country")
            if country:
                countries[country] += 1

        for country, count in countries.most_common(3):
            tags.append(f"geo:{country.lower().replace(' ', '_')}")

        if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
            tags.append("has_file_hashes")
        if iocs.get("domain"):
            tags.append("has_domains")
        if iocs.get("url"):
            tags.append("has_urls")
        if iocs.get("ipv4"):
            tags.append("has_ips")
        if iocs.get("cve"):
            tags.append("has_cves")
        return tags


# ════════════════════════════════════════════════════════════════════════════════
# STIX BUNDLE BUILDER
# ════════════════════════════════════════════════════════════════════════════════

class STIXBundleBuilder:
    """
    Builds STIX 2.1 bundles from correlated intelligence objects.
    Produces structured bundles without requiring stix2 library.
    """

    STIX_VERSION = "2.1"
    STIX_SPEC_URL = "https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html"

    def build_bundle(self, correlation_result: Dict) -> Dict:
        """Build STIX 2.1 bundle from correlation result."""
        bundle_id = f"bundle--{hashlib.sha256(json.dumps(correlation_result, default=str, sort_keys=True).encode()).hexdigest()[:32]}"

        objects = []
        intel_id = correlation_result.get("intel_id", "unknown")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # ── Vulnerability objects (CVEs) ──────────────────────────────────
        for cve_id, cve_data in correlation_result.get("cve_enrichments", {}).items():
            vuln_id = f"vulnerability--{hashlib.sha256(cve_id.encode()).hexdigest()[:32]}"
            objects.append({
                "type": "vulnerability",
                "spec_version": self.STIX_VERSION,
                "id": vuln_id,
                "created": now,
                "modified": now,
                "name": cve_id,
                "description": cve_data.get("description", ""),
                "external_references": [
                    {"source_name": "cve", "external_id": cve_id,
                     "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
                ],
                "labels": [cve_data.get("cvss_severity", "unknown").lower()],
                "x_cdb_cvss_score": cve_data.get("cvss_score", 0.0),
                "x_cdb_epss_score": cve_data.get("epss_score", 0.0),
                "x_cdb_kev_status": cve_data.get("kev_status", False),
                "x_cdb_risk_score": correlation_result.get("risk_scoring", {}).get("risk_score", 0),
            })

        # ── Indicator objects (IOCs) ─────────────────────────────────────
        iocs = correlation_result.get("iocs", {})
        for ip in iocs.get("ipv4", [])[:20]:
            ind_id = f"indicator--{hashlib.sha256(ip.encode()).hexdigest()[:32]}"
            objects.append({
                "type": "indicator",
                "spec_version": self.STIX_VERSION,
                "id": ind_id,
                "created": now,
                "modified": now,
                "name": f"Malicious IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "labels": ["malicious-ip"],
            })

        for domain in iocs.get("domain", [])[:20]:
            ind_id = f"indicator--{hashlib.sha256(domain.encode()).hexdigest()[:32]}"
            objects.append({
                "type": "indicator",
                "spec_version": self.STIX_VERSION,
                "id": ind_id,
                "created": now,
                "modified": now,
                "name": f"Malicious Domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "labels": ["malicious-domain"],
            })

        for sha256 in iocs.get("sha256", [])[:20]:
            ind_id = f"indicator--{hashlib.sha256(sha256.encode()).hexdigest()[:32]}"
            objects.append({
                "type": "indicator",
                "spec_version": self.STIX_VERSION,
                "id": ind_id,
                "created": now,
                "modified": now,
                "name": f"Malicious File: {sha256[:16]}...",
                "pattern": f"[file:hashes.SHA-256 = '{sha256}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "labels": ["malicious-hash"],
            })

        # ── Threat actor objects ──────────────────────────────────────────
        for actor in correlation_result.get("actor_correlation", [])[:5]:
            actor_id = f"threat-actor--{hashlib.sha256(actor.get('actor_id', 'unknown').encode()).hexdigest()[:32]}"
            objects.append({
                "type": "threat-actor",
                "spec_version": self.STIX_VERSION,
                "id": actor_id,
                "created": now,
                "modified": now,
                "name": actor.get("actor_id", "Unknown"),
                "aliases": actor.get("aliases", []),
                "labels": ["nation-state"] if actor.get("nation") not in ("Unknown", "") else ["criminal"],
                "primary_motivation": actor.get("motivation", "unknown"),
                "x_cdb_nation": actor.get("nation", "Unknown"),
                "x_cdb_attribution_confidence": actor.get("attribution_confidence", 0.0),
            })

        # ── Attack pattern objects (TTPs) ─────────────────────────────────
        all_ttps = correlation_result.get("malware_correlation", {}).get("ttps", [])
        for ttp in all_ttps[:10]:
            ap_id = f"attack-pattern--{hashlib.sha256(ttp.encode()).hexdigest()[:32]}"
            objects.append({
                "type": "attack-pattern",
                "spec_version": self.STIX_VERSION,
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": ttp,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": ttp,
                     "url": f"https://attack.mitre.org/techniques/{ttp.replace('.', '/')}"}
                ],
            })

        # ── Report object (top-level) ─────────────────────────────────────
        report_id = f"report--{hashlib.sha256(intel_id.encode()).hexdigest()[:32]}"
        objects.append({
            "type": "report",
            "spec_version": self.STIX_VERSION,
            "id": report_id,
            "created": now,
            "modified": now,
            "name": correlation_result.get("title", intel_id),
            "description": f"CDB SENTINEL APEX correlation report for {intel_id}",
            "published": now,
            "report_types": ["threat-report"],
            "object_refs": [obj["id"] for obj in objects],
            "x_cdb_risk_score": correlation_result.get("risk_scoring", {}).get("risk_score", 0),
            "x_cdb_severity": correlation_result.get("risk_scoring", {}).get("severity", "UNKNOWN"),
            "x_cdb_platform_version": "v82.0",
        })

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": self.STIX_VERSION,
            "objects": objects,
        }


# ════════════════════════════════════════════════════════════════════════════════
# THREAT CORRELATION ENGINE — Master Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class ThreatCorrelationEngine:
    """
    Master correlation engine linking:
      CVE → EPSS → KEV → Exploit → Malware Family → Threat Actor → IOC → Detection → Risk Score

    Usage:
        engine = ThreatCorrelationEngine()
        result = engine.correlate(intel_item)
        # result contains: cve_enrichments, exploit_correlation, malware_correlation,
        #                  actor_correlation, risk_scoring, context, stix_bundle
    """

    def __init__(self):
        self.cve_enricher     = CVEEnricher()
        self.exploit_corr     = ExploitCorrelator()
        self.malware_corr     = MalwareCorrelator()
        self.actor_corr       = ActorCorrelator()
        self.risk_engine      = RiskScoringEngine()
        self.context_enricher = ContextEnricher()
        self.stix_builder     = STIXBundleBuilder()
        self._stats           = {"items_correlated": 0, "cves_enriched": 0, "errors": 0}
        logger.info("ThreatCorrelationEngine initialized")

    def correlate(self, intel_item: Dict) -> Dict:
        """
        Full correlation chain for a single intelligence item.

        Input: intel item dict with fields:
          - title, content, iocs, published, source_url

        Output: enriched correlation result with:
          - cve_enrichments, exploit_correlation, malware_correlation,
            actor_correlation, risk_scoring, context, stix_bundle
        """
        try:
            return self._correlate_internal(intel_item)
        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"Correlation failed for {intel_item.get('title', 'unknown')[:50]}: {e}")
            return self._empty_result(intel_item, str(e))

    def correlate_batch(self, items: List[Dict]) -> List[Dict]:
        """Correlate a batch of intelligence items."""
        results = []
        for item in items:
            result = self.correlate(item)
            results.append(result)
        logger.info(f"Batch correlation complete: {len(results)} items")
        return results

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "kev_catalog_size": len(self.cve_enricher._kev_set),
            "epss_cache_size": len(self.cve_enricher._epss_cache),
            "nvd_cache_size": len(self.cve_enricher._nvd_cache),
        }

    # ── Internal ─────────────────────────────────────────────────────────────

    def _correlate_internal(self, intel_item: Dict) -> Dict:
        text = f"{intel_item.get('title', '')} {intel_item.get('content', '')} {intel_item.get('description', '')}"
        iocs = intel_item.get("iocs", {})
        intel_id = intel_item.get("intel_id", intel_item.get("id", hashlib.sha256(text[:100].encode()).hexdigest()[:12]))

        # ── Step 1: Extract CVEs ────────────────────────────────────────
        text_cves = self.cve_enricher.extract_cves(text)
        ioc_cves = iocs.get("cve", [])
        all_cves = list(set(text_cves + ioc_cves))[:10]  # Cap at 10 CVEs per item

        # ── Step 2: Enrich CVEs (NVD + EPSS + KEV) ─────────────────────
        cve_enrichments = self.cve_enricher.enrich_batch(all_cves) if all_cves else {}
        self._stats["cves_enriched"] += len(cve_enrichments)

        # ── Step 3: Exploit correlation ─────────────────────────────────
        exploit_correlations = {}
        for cve_id in all_cves:
            exploit_correlations[cve_id] = self.exploit_corr.correlate_cve_exploits(cve_id, text)

        # Aggregate exploit correlation
        agg_exploit = self._aggregate_exploit_correlation(exploit_correlations)

        # ── Step 4: Malware family extraction + correlation ─────────────
        malware_families = self.malware_corr.extract_malware_families(text)
        malware_correlation = self.malware_corr.correlate_malware(malware_families, iocs)

        # ── Step 5: Actor extraction + correlation ─────────────────────
        text_actors = self.actor_corr.extract_actors(text)
        exploit_actors = agg_exploit.get("associated_actors", [])
        malware_actors = malware_correlation.get("actors", [])
        all_actors = list(set(text_actors + exploit_actors + malware_actors))[:10]

        all_ttps = malware_correlation.get("ttps", [])
        actor_correlation = self.actor_corr.correlate_actors(all_actors, all_ttps)

        # ── Step 6: Risk scoring ────────────────────────────────────────
        # Use highest-risk CVE for scoring (worst-case)
        primary_cve_enrich = {}
        if cve_enrichments:
            primary_cve_enrich = max(
                cve_enrichments.values(),
                key=lambda c: c.get("risk_multiplier", 1.0)
            )

        risk_scoring = self.risk_engine.compute_score(
            cve_enrichment=primary_cve_enrich,
            exploit_correlation=agg_exploit,
            malware_correlation=malware_correlation,
            actor_correlation=actor_correlation,
            iocs=iocs,
            published_date=intel_item.get("published", ""),
        )

        # ── Step 7: Context enrichment (Geo/ASN/Tags) ───────────────────
        context = self.context_enricher.enrich_iocs(iocs)

        # ── Step 8: Build STIX bundle ───────────────────────────────────
        correlation_result = {
            "intel_id": intel_id,
            "title": intel_item.get("title", ""),
            "cves": all_cves,
            "cve_enrichments": cve_enrichments,
            "exploit_correlation": agg_exploit,
            "malware_correlation": malware_correlation,
            "actor_correlation": actor_correlation,
            "risk_scoring": risk_scoring,
            "context": context,
            "iocs": iocs,
            "correlated_at": datetime.now(timezone.utc).isoformat(),
        }

        stix_bundle = self.stix_builder.build_bundle(correlation_result)
        correlation_result["stix_bundle"] = stix_bundle
        correlation_result["stix_object_count"] = len(stix_bundle.get("objects", []))

        self._stats["items_correlated"] += 1
        logger.debug(
            f"Correlated: {intel_id[:20]} | CVEs: {len(all_cves)} | "
            f"Risk: {risk_scoring['risk_score']} ({risk_scoring['severity']}) | "
            f"STIX objects: {len(stix_bundle.get('objects', []))}"
        )
        return correlation_result

    def _aggregate_exploit_correlation(self, exploit_correlations: Dict) -> Dict:
        """Aggregate multiple CVE exploit correlations into summary."""
        if not exploit_correlations:
            return {
                "exploit_available": False,
                "exploit_maturity": "none",
                "associated_malware": [],
                "associated_actors": [],
            }

        all_malware = []
        all_actors = []
        worst_maturity = "none"
        maturity_order = ["none", "poc", "weaponized", "in_wild"]

        for corr in exploit_correlations.values():
            all_malware.extend(corr.get("associated_malware", []))
            all_actors.extend(corr.get("associated_actors", []))
            m = corr.get("exploit_maturity", "none")
            if maturity_order.index(m) > maturity_order.index(worst_maturity):
                worst_maturity = m

        return {
            "exploit_available": worst_maturity != "none",
            "exploit_maturity": worst_maturity,
            "associated_malware": list(set(all_malware))[:10],
            "associated_actors": list(set(all_actors))[:5],
        }

    def _empty_result(self, intel_item: Dict, error: str) -> Dict:
        return {
            "intel_id": intel_item.get("intel_id", "error"),
            "title": intel_item.get("title", ""),
            "cves": [],
            "cve_enrichments": {},
            "exploit_correlation": {"exploit_available": False, "exploit_maturity": "none"},
            "malware_correlation": {"families": [], "ttps": [], "actors": []},
            "actor_correlation": [],
            "risk_scoring": {"risk_score": 0, "severity": "INFORMATIONAL", "components": {}},
            "context": {"ips": {}, "domains": {}, "tags": []},
            "iocs": intel_item.get("iocs", {}),
            "error": error,
            "correlated_at": datetime.now(timezone.utc).isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ════════════════════════════════════════════════════════════════════════════════

correlation_engine = ThreatCorrelationEngine()


# ════════════════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    # Demo correlation
    demo_item = {
        "intel_id": "DEMO-001",
        "title": "Critical Log4Shell Exploitation by APT41 — Active Ransomware Deployment",
        "content": (
            "Threat actors including APT41 and LockBit are actively exploiting CVE-2021-44228 "
            "Log4Shell vulnerability. Observed deployment of Cobalt Strike beacons, followed by "
            "LockBit ransomware. IOCs include 192.168.1.100, malicious-c2.example.com, "
            "and SHA256: a3f1d2c4e5b6789012345678901234567890123456789012345678901234abcd. "
            "Exploit is in the wild with multiple PoC and weaponized exploit kits available. "
            "CVE-2021-44228 has CVSS 10.0 and is in CISA KEV catalog."
        ),
        "iocs": {
            "ipv4": ["198.51.100.10", "203.0.113.50"],
            "domain": ["malicious-c2.example.com", "evil-payload.net"],
            "sha256": ["a3f1d2c4e5b6789012345678901234567890123456789012345678901234abcd"],
            "cve": ["CVE-2021-44228"],
        },
        "published": "2024-01-15T10:00:00Z",
    }

    print("\n" + "="*70)
    print("CYBERDUDEBIVASH® SENTINEL APEX — THREAT CORRELATION ENGINE v82.0")
    print("="*70)

    result = correlation_engine.correlate(demo_item)

    # Print summary
    risk = result.get("risk_scoring", {})
    print(f"\n✅ CORRELATION COMPLETE")
    print(f"   CVEs Found:       {len(result['cves'])}")
    print(f"   Risk Score:       {risk.get('risk_score', 0)} / 100")
    print(f"   Severity:         {risk.get('severity', 'N/A')}")
    print(f"   STIX Objects:     {result.get('stix_object_count', 0)}")
    print(f"   Malware Families: {result['malware_correlation']['families']}")
    print(f"   Actors:           {[a['actor_id'] for a in result['actor_correlation'][:3]]}")
    print(f"\nScore Components: {json.dumps(risk.get('components', {}), indent=2)}")
    print("\nStats:", json.dumps(correlation_engine.get_stats(), indent=2))
