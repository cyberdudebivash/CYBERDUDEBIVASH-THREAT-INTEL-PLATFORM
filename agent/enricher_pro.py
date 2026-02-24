#!/usr/bin/env python3
"""
enricher_pro.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
PRODUCTION UPGRADE: Advanced Multi-Source Intelligence Enrichment Engine.

v22.0 CAPABILITIES (new, fully additive):
  - EPSS auto-fetch from FIRST API (api.first.org) for CVE risk probability
  - NVD CVE metadata enrichment (CVSS v3.1 vectors, CWE, references)
  - Domain Generating Algorithm (DGA) detection via Shannon entropy
  - Supply chain attack indicator correlation
  - IP ASN / geolocation context (ip-api.com — preserved from v1.0)
  - Automated confidence score synthesis (multi-source weighted)
  - Response caching with TTL to prevent redundant API calls
  - Full backward compatibility: get_ip_context() and get_whois_domain() preserved

v1.0 (preserved):
  - Geo-IP lookup (ip-api.com)
  - Domain to IP resolution
"""
import socket
import logging
import math
import re
import os
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from agent.config import (
    EPSS_API_URL,
    NVD_CVE_API_URL,
    EPSS_FETCH_ENABLED,
    EPSS_FETCH_TIMEOUT,
    SUPPLY_CHAIN_SIGNALS,
)

logger = logging.getLogger("CDB-ENRICHER-PRO")

# In-memory caches with TTL
_EPSS_CACHE: Dict[str, Tuple[Dict, float]] = {}
_GEO_CACHE:  Dict[str, Tuple[Dict, float]] = {}
_NVD_CACHE:  Dict[str, Tuple[Dict, float]] = {}
CACHE_TTL_EPSS = 3600
CACHE_TTL_GEO  = 1800
CACHE_TTL_NVD  = 7200


def _make_session() -> requests.Session:
    """Build a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "CDB-Sentinel-APEX/22.0 (intel.cyberdudebivash.com; security research)"
    })
    return session


class ProEnricher:
    """
    Production-grade multi-source intelligence enrichment engine.
    Provides EPSS, NVD, Geo-IP, DGA, supply-chain, and confidence scoring.
    """

    def __init__(self):
        self.geo_url = "http://ip-api.com/json/"
        self.session = _make_session()

    # ── PRESERVED v1.0 METHODS ──────────────────────────────────

    def get_ip_context(self, ip: str) -> Dict[str, str]:
        """Gathers Geographic and ISP context for a specific IPv4 address."""
        if ip in _GEO_CACHE:
            cached, ts = _GEO_CACHE[ip]
            if time.time() - ts < CACHE_TTL_GEO:
                return cached
        try:
            response = self.session.get(f"{self.geo_url}{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result = {
                        "location":     f"{data.get('city','Unknown')}, {data.get('country','Unknown')}",
                        "isp":          data.get("isp", "Unknown"),
                        "asn":          data.get("as", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                        "region":       data.get("regionName", ""),
                        "timezone":     data.get("timezone", ""),
                        "org":          data.get("org", ""),
                        "latitude":     data.get("lat", 0),
                        "longitude":    data.get("lon", 0),
                    }
                    _GEO_CACHE[ip] = (result, time.time())
                    return result
            return {"location": "Unknown", "isp": "Unknown", "asn": "Unknown"}
        except Exception as e:
            logger.error(f"Geo-IP lookup failed for {ip}: {e}")
            return {"location": "Error", "isp": "Error", "asn": "Error"}

    def get_whois_domain(self, domain: str) -> Optional[str]:
        """Resolves a domain to its IP address for basic infrastructure mapping."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    # ── v22.0 NEW: EPSS AUTO-FETCH ───────────────────────────────

    def fetch_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """
        Fetch EPSS scores from FIRST API (api.first.org).
        Returns: {CVE_ID: epss_probability (0.0-1.0)}
        """
        if not EPSS_FETCH_ENABLED or not cve_ids:
            return {}

        results = {}
        uncached = []
        for cve in cve_ids:
            cve_upper = cve.upper()
            if cve_upper in _EPSS_CACHE:
                data, ts = _EPSS_CACHE[cve_upper]
                if time.time() - ts < CACHE_TTL_EPSS:
                    results[cve_upper] = data.get("epss", 0.0)
                    continue
            uncached.append(cve_upper)

        batches = [uncached[i:i+100] for i in range(0, len(uncached), 100)]
        for batch in batches:
            try:
                resp = self.session.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch)},
                    timeout=EPSS_FETCH_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        cid = item.get("cve", "").upper()
                        epss_val = float(item.get("epss", 0.0))
                        percentile = float(item.get("percentile", 0.0))
                        entry = {
                            "epss": epss_val,
                            "percentile": percentile,
                            "epss_pct": round(epss_val * 100, 2),
                            "date": item.get("date", ""),
                        }
                        _EPSS_CACHE[cid] = (entry, time.time())
                        results[cid] = epss_val
                    logger.info(f"EPSS: fetched {len(data.get('data',[]))} scores")
            except requests.exceptions.Timeout:
                logger.warning(f"EPSS API timeout for batch of {len(batch)}")
            except Exception as e:
                logger.error(f"EPSS fetch error: {e}")

        return results

    def get_epss_detail(self, cve_id: str) -> Optional[Dict]:
        """Get full EPSS detail (score + percentile) for a single CVE."""
        cve_upper = cve_id.upper()
        if cve_upper in _EPSS_CACHE:
            data, ts = _EPSS_CACHE[cve_upper]
            if time.time() - ts < CACHE_TTL_EPSS:
                return data
        self.fetch_epss_scores([cve_upper])
        if cve_upper in _EPSS_CACHE:
            return _EPSS_CACHE[cve_upper][0]
        return None

    # ── v22.0 NEW: NVD CVE METADATA ─────────────────────────────

    def fetch_nvd_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch CVE metadata from NVD (NIST).
        Returns: {cvss_score, cvss_vector, severity, cwe_ids, description, ...}
        """
        cve_upper = cve_id.upper()
        if cve_upper in _NVD_CACHE:
            data, ts = _NVD_CACHE[cve_upper]
            if time.time() - ts < CACHE_TTL_NVD:
                return data
        try:
            nvd_key = os.environ.get("NVD_API_KEY", "")
            headers = {"apiKey": nvd_key} if nvd_key else {}
            resp = self.session.get(
                NVD_CVE_API_URL,
                params={"cveId": cve_upper},
                headers=headers,
                timeout=EPSS_FETCH_TIMEOUT,
            )
            if resp.status_code == 200:
                raw = resp.json()
                vulns = raw.get("vulnerabilities", [])
                if not vulns:
                    return None
                cve_data = vulns[0].get("cve", {})
                desc = next(
                    (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                cvss_score, cvss_vector, cvss_severity = None, None, None
                for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metrics = cve_data.get("metrics", {}).get(mk, [])
                    if metrics:
                        cd = metrics[0].get("cvssData", {})
                        cvss_score    = cd.get("baseScore")
                        cvss_vector   = cd.get("vectorString")
                        cvss_severity = cd.get("baseSeverity") or metrics[0].get("baseSeverity")
                        break
                cwe_ids = []
                for w in cve_data.get("weaknesses", []):
                    for d in w.get("description", []):
                        if d.get("lang") == "en":
                            cwe_ids.append(d["value"])
                result = {
                    "cve_id":       cve_upper,
                    "cvss_score":   cvss_score,
                    "cvss_vector":  cvss_vector,
                    "cvss_severity":cvss_severity,
                    "cwe_ids":      list(set(cwe_ids)),
                    "description":  desc[:500] if desc else "",
                    "published":    cve_data.get("published", ""),
                    "last_modified":cve_data.get("lastModified", ""),
                    "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_upper}",
                    "source":       "NVD",
                    "fetched_at":   datetime.now(timezone.utc).isoformat(),
                }
                _NVD_CACHE[cve_upper] = (result, time.time())
                logger.info(f"NVD: {cve_upper} | CVSS={cvss_score} | Sev={cvss_severity}")
                return result
        except requests.exceptions.Timeout:
            logger.warning(f"NVD timeout for {cve_upper}")
        except Exception as e:
            logger.error(f"NVD fetch error for {cve_upper}: {e}")
        return None

    # ── v22.0 NEW: DOMAIN ANALYSIS (DGA DETECTION) ──────────────

    def analyze_domain(self, domain: str) -> Dict:
        """
        Analyze a domain for DGA patterns and suspicious characteristics.
        Returns: {entropy, dga_probability, dga_signals, risk_label, ...}
        """
        sld = domain.lower().split(".")[0] if "." in domain else domain.lower()
        tld = domain.lower().split(".")[-1] if "." in domain else ""

        entropy      = self._shannon_entropy(sld)
        length       = len(sld)
        digit_ratio  = sum(c.isdigit() for c in sld) / max(length, 1)
        c_ratio      = self._consonant_ratio(sld)

        dga_score = 0.0
        signals = []

        if entropy > 3.8:
            dga_score += 0.35; signals.append("HIGH_ENTROPY")
        if length > 18:
            dga_score += 0.15; signals.append("LONG_SUBDOMAIN")
        if digit_ratio > 0.25:
            dga_score += 0.20; signals.append("HIGH_DIGIT_RATIO")
        if c_ratio > 0.75:
            dga_score += 0.15; signals.append("CONSONANT_HEAVY")
        if re.search(r'[0-9]{4,}', sld):
            dga_score += 0.10; signals.append("NUMERIC_CLUSTER")

        suspicious_tlds = {"xyz","top","club","online","site","icu","pw","cc",
                           "tk","ml","ga","cf","work","review","bid","trade",
                           "science","accountant","gq","men","loan"}
        if tld in suspicious_tlds:
            dga_score += 0.15; signals.append(f"SUSPICIOUS_TLD:{tld}")

        dga_prob = min(round(dga_score, 2), 1.0)
        risk_label = ("HIGH_RISK_DGA" if dga_prob >= 0.60 else
                      "MEDIUM_RISK"   if dga_prob >= 0.35 else "LOW_RISK")

        return {
            "domain":          domain,
            "entropy":         round(entropy, 3),
            "dga_probability": dga_prob,
            "dga_signals":     signals,
            "length":          length,
            "digit_ratio":     round(digit_ratio, 3),
            "consonant_ratio": round(c_ratio, 3),
            "suspicious_tld":  tld in suspicious_tlds,
            "tld":             tld,
            "risk_label":      risk_label,
        }

    def bulk_analyze_domains(self, domains: List[str]) -> List[Dict]:
        """Analyze multiple domains, sorted by DGA probability."""
        results = [self.analyze_domain(d) for d in domains[:50]]
        return sorted(results, key=lambda x: x["dga_probability"], reverse=True)

    # ── v22.0 NEW: SUPPLY CHAIN CORRELATION ─────────────────────

    def detect_supply_chain_indicators(
        self,
        headline: str,
        content: str,
        iocs: Optional[Dict] = None,
    ) -> Dict:
        """
        Detect supply chain attack indicators in threat content.
        Returns: {is_supply_chain, confidence, matched_signals, attack_vector}
        """
        text_lower = f"{headline} {content}".lower()
        matched    = [sig for sig in SUPPLY_CHAIN_SIGNALS if sig in text_lower]

        ioc_signals = []
        if iocs:
            for art in iocs.get("artifacts", []):
                al = art.lower()
                if any(ext in al for ext in [".whl",".tar.gz",".tgz","setup.py",
                                              "package.json","requirements.txt"]):
                    ioc_signals.append(f"PACKAGE_ARTIFACT:{art}")

        total = len(matched) + len(ioc_signals)
        confidence = min(total * 25, 95)

        vector = "UNKNOWN"
        if any(s in matched for s in ["npm package","pypi package","dependency confusion"]):
            vector = "PACKAGE_REGISTRY"
        elif any(s in matched for s in ["github action","ci/cd pipeline","build pipeline"]):
            vector = "CI_CD_PIPELINE"
        elif any(s in matched for s in ["malicious update","backdoored library","poisoned"]):
            vector = "SOFTWARE_UPDATE"
        elif any(s in matched for s in ["solarwinds","3cx","xz utils","polyfill.io"]):
            vector = "TRUSTED_VENDOR"
        elif matched:
            vector = "SUPPLY_CHAIN_GENERIC"

        return {
            "is_supply_chain": total > 0,
            "confidence":      confidence,
            "matched_signals": matched + ioc_signals,
            "attack_vector":   vector,
            "signal_count":    total,
        }

    # ── v22.0 NEW: SYNTHESIZED CONFIDENCE SCORE ─────────────────

    def compute_enriched_confidence(
        self,
        ioc_confidence:  float,
        epss_score:      Optional[float] = None,
        cvss_score:      Optional[float] = None,
        kev_present:     bool = False,
        mitre_count:     int  = 0,
        source_count:    int  = 1,
        actor_known:     bool = False,
        supply_chain:    bool = False,
        nvd_enriched:    bool = False,
    ) -> Dict:
        """
        Synthesize comprehensive confidence score from all available signals.
        Returns: {score, label, components, reasoning}
        """
        score      = ioc_confidence
        components = {"ioc_base": round(ioc_confidence, 1)}

        if epss_score is not None:
            ep = min(epss_score * 30, 20)
            score += ep; components["epss"] = round(ep, 1)

        if cvss_score is not None:
            cv = min((cvss_score / 10) * 15, 15)
            score += cv; components["cvss"] = round(cv, 1)

        if kev_present:
            score += 20; components["kev"] = 20

        mc = min(mitre_count * 3, 12)
        score += mc
        if mc > 0:
            components["mitre"] = round(mc, 1)

        sc = min((source_count - 1) * 5, 10)
        score += sc
        if sc > 0:
            components["multi_source"] = round(sc, 1)

        if actor_known:
            score += 8;  components["actor_known"] = 8
        if supply_chain:
            score += 5;  components["supply_chain"] = 5
        if nvd_enriched:
            score += 5;  components["nvd_enriched"] = 5

        final = min(round(score, 1), 100.0)
        label = ("VERY HIGH" if final >= 80 else "HIGH"  if final >= 60 else
                 "MEDIUM"    if final >= 40 else "LOW"   if final >= 20 else "VERY LOW")

        return {
            "score":      final,
            "label":      label,
            "components": components,
            "reasoning":  (f"Confidence {final}% ({label}) based on "
                           f"{len(components)} contributing signals."),
        }

    # ── INTERNAL HELPERS ─────────────────────────────────────────

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for c in text.lower():
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    def _consonant_ratio(self, text: str) -> float:
        consonants = set("bcdfghjklmnpqrstvwxyz")
        letters = [c for c in text.lower() if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c in consonants) / len(letters)

    def clear_cache(self):
        _EPSS_CACHE.clear(); _GEO_CACHE.clear(); _NVD_CACHE.clear()
        logger.info("ProEnricher: all caches cleared")

    def cache_stats(self) -> Dict:
        return {"epss_cached": len(_EPSS_CACHE),
                "geo_cached":  len(_GEO_CACHE),
                "nvd_cached":  len(_NVD_CACHE)}


# Global Instance (backward compatible — same variable name as v1.0)
enricher_pro = ProEnricher()
