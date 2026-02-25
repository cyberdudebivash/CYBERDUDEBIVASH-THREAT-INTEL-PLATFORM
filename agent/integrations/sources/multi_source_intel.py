#!/usr/bin/env python3
"""
multi_source_intel.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
Multi-Source Intelligence Expansion Module.

Non-Breaking Addition: New intelligence source adapters.
Does NOT modify existing RSS feed pipeline or sentinel_blogger.py.

New Sources Added (additive only):
    1. Shodan InternetDB — exposure signals for IPs/domains
    2. Exploit-DB RSS — exploit publication monitoring
    3. GitHub Security Advisories — GHSA CVE feed
    4. CISA Known Exploited Vulnerabilities (KEV) — live pull
    5. Microsoft MSRC — Security Update Guide
    6. Vendor Advisory Aggregator (Apple, Google, Cisco, VMware, Apache)
    7. Ransomware.live — ransomware gang victim tracking
    8. AlienVault OTX — open threat exchange pulses
    9. GreyNoise Community — benign vs threat IP classification
   10. URLhaus — malicious URL/domain feed

Author: CyberDudeBivash Pvt. Ltd.
Platform: https://intel.cyberdudebivash.com
"""

import re
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import feedparser
    _FEEDPARSER_AVAILABLE = True
except ImportError:
    _FEEDPARSER_AVAILABLE = False

logger = logging.getLogger("CDB-MultiSource-Intel")

MODULE_VERSION = "1.0.0"
DEFAULT_TIMEOUT = 20

# ─────────────────────────────────────────────────────────
# Additional RSS/Feed Sources (drop-in additions to RSS_FEEDS)
# These can be appended to RSS_FEEDS in config.py non-destructively
# ─────────────────────────────────────────────────────────

ADDITIONAL_RSS_FEEDS = [
    # Exploit tracking
    "https://www.exploit-db.com/rss.xml",
    # Vendor advisories
    "https://msrc.microsoft.com/update-guide/releaseNote/rss",
    "https://feeds.feedburner.com/cisco-security-advisories",
    # Research
    "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "https://www.synacktiv.com/feed",
    "https://www.crowdstrike.com/blog/feed/",
    # Threat feeds
    "https://otx.alienvault.com/api/v1/pulses/subscribed?format=json",
    # APT tracking
    "https://feeds.talosintelligence.com/feeds/blogs",
    "https://research.checkpoint.com/feed/",
    "https://www.mandiant.com/resources/blog/rss.xml",
]

VENDOR_ADVISORY_FEEDS = {
    "microsoft_msrc": {
        "url": "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        "description": "Microsoft Security Response Center",
        "priority": "tier1",
    },
    "cisco_psirt": {
        "url": "https://tools.cisco.com/security/center/publicationListing.x?product=Cisco&sort=-day_sir&limit=20&format=json",
        "description": "Cisco Product Security Incident Response Team",
        "priority": "tier1",
    },
    "vmware_sa": {
        "url": "https://www.vmware.com/security/advisories.rss",
        "description": "VMware Security Advisories",
        "priority": "tier2",
    },
    "apache_security": {
        "url": "https://httpd.apache.org/security/vulnerabilities_24.xml",
        "description": "Apache HTTP Server Security Reports",
        "priority": "tier2",
    },
    "redhat_errata": {
        "url": "https://access.redhat.com/security/cve.json",
        "description": "Red Hat Security Advisories",
        "priority": "tier2",
    },
}


# ─────────────────────────────────────────────────────────
# Shodan InternetDB Adapter
# ─────────────────────────────────────────────────────────

class ShodanInternetDBAdapter:
    """
    Query Shodan InternetDB (FREE, no API key) for exposure signals.
    Returns: open ports, CVEs, tags (honeypot, cdn, cloud, etc.)
    """

    BASE_URL = "https://internetdb.shodan.io"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def enrich_ip(self, ip: str) -> Optional[Dict]:
        """
        Enrich an IP address with Shodan exposure data.

        Args:
            ip: IPv4 address to look up.

        Returns:
            dict with ports, cpes, hostnames, tags, vulns, or None on error.
        """
        if not _REQUESTS_AVAILABLE:
            logger.warning("requests not available. pip install requests")
            return None

        try:
            r = requests.get(
                f"{self.BASE_URL}/{ip}",
                timeout=self.timeout,
                headers={"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"},
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip":          ip,
                    "ports":       data.get("ports", []),
                    "hostnames":   data.get("hostnames", []),
                    "cpes":        data.get("cpes", []),
                    "tags":        data.get("tags", []),
                    "vulns":       data.get("vulns", []),
                    "is_cdn":      "cdn" in data.get("tags", []),
                    "is_honeypot": "honeypot" in data.get("tags", []),
                    "source":      "shodan-internetdb",
                    "queried_at":  datetime.now(timezone.utc).isoformat(),
                }
            elif r.status_code == 404:
                return {"ip": ip, "ports": [], "tags": [], "vulns": [], "note": "no data"}
        except Exception as e:
            logger.error(f"Shodan InternetDB error for {ip}: {e}")
        return None

    def enrich_ip_list(self, ip_list: List[str], delay: float = 0.5) -> List[Dict]:
        """Enrich multiple IPs with rate limiting."""
        results = []
        for ip in ip_list:
            data = self.enrich_ip(ip)
            if data:
                results.append(data)
            time.sleep(delay)  # Be polite to the free API
        return results

    def extract_exposure_signals(self, enriched: Dict) -> Dict:
        """Convert Shodan data into CDB exposure signal scores."""
        signals = {
            "exposure_score": 0,
            "risk_addons": [],
            "open_port_count": len(enriched.get("ports", [])),
            "has_known_vulns": bool(enriched.get("vulns")),
            "vuln_count": len(enriched.get("vulns", [])),
            "is_cdn": enriched.get("is_cdn", False),
            "is_honeypot": enriched.get("is_honeypot", False),
        }

        score = 0
        if enriched.get("vulns"):
            score += min(len(enriched["vulns"]) * 1.5, 5.0)
            signals["risk_addons"].append("shodan_vulns_present")

        dangerous_ports = {22, 23, 3389, 5900, 6379, 27017, 9200, 8080, 4444}
        exposed = set(enriched.get("ports", [])) & dangerous_ports
        if exposed:
            score += len(exposed) * 0.5
            signals["risk_addons"].append(f"dangerous_ports:{','.join(map(str, exposed))}")

        if enriched.get("is_honeypot"):
            score = 0  # Honeypot — skip
            signals["risk_addons"].append("honeypot_skip")

        signals["exposure_score"] = round(min(score, 3.0), 2)
        return signals


# ─────────────────────────────────────────────────────────
# CISA KEV Live Puller
# ─────────────────────────────────────────────────────────

class CISAKEVAdapter:
    """
    Live pull from CISA Known Exploited Vulnerabilities catalog.
    Used to cross-reference CVEs with confirmed exploitation.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, cache_ttl_seconds: int = 3600, timeout: int = DEFAULT_TIMEOUT):
        self.cache_ttl = cache_ttl_seconds
        self.timeout   = timeout
        self._cache: Optional[List[Dict]] = None
        self._cache_ts: float = 0.0

    def fetch_kev_catalog(self, force_refresh: bool = False) -> List[Dict]:
        """
        Fetch the full CISA KEV catalog.

        Returns:
            List of KEV entries with cveID, vendorProject, product, dateAdded, etc.
        """
        now = time.time()
        if not force_refresh and self._cache and (now - self._cache_ts) < self.cache_ttl:
            return self._cache

        if not _REQUESTS_AVAILABLE:
            logger.warning("requests not available")
            return []

        try:
            r = requests.get(
                self.KEV_URL,
                timeout=self.timeout,
                headers={"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"},
            )
            if r.status_code == 200:
                data = r.json()
                vulnerabilities = data.get("vulnerabilities", [])
                self._cache    = vulnerabilities
                self._cache_ts = now
                logger.info(f"CISA KEV: fetched {len(vulnerabilities)} entries")
                return vulnerabilities
        except Exception as e:
            logger.error(f"CISA KEV fetch error: {e}")

        return self._cache or []

    def check_cve_in_kev(self, cve_id: str) -> Optional[Dict]:
        """
        Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2024-1234')

        Returns:
            KEV entry dict if found, None otherwise.
        """
        catalog = self.fetch_kev_catalog()
        for entry in catalog:
            if entry.get("cveID", "").upper() == cve_id.upper():
                return entry
        return None

    def check_cves_batch(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """Batch KEV check for multiple CVE IDs."""
        catalog  = self.fetch_kev_catalog()
        kev_map  = {e.get("cveID", "").upper(): e for e in catalog}
        return {cve: kev_map.get(cve.upper()) for cve in cve_ids}

    def get_recent_kev(self, days: int = 7) -> List[Dict]:
        """Get KEV entries added in the last N days."""
        from datetime import timedelta
        cutoff   = datetime.now(timezone.utc) - timedelta(days=days)
        catalog  = self.fetch_kev_catalog()
        recent   = []
        for entry in catalog:
            date_str = entry.get("dateAdded", "")
            try:
                date_obj = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if date_obj >= cutoff:
                    recent.append(entry)
            except Exception:
                pass
        return recent

    def get_kev_by_vendor(self, vendor: str) -> List[Dict]:
        """Get KEV entries for a specific vendor."""
        catalog = self.fetch_kev_catalog()
        return [
            e for e in catalog
            if vendor.lower() in e.get("vendorProject", "").lower()
        ]

    def get_kev_stats(self) -> Dict:
        """Get statistics about the KEV catalog."""
        catalog = self.fetch_kev_catalog()
        vendors = {}
        for entry in catalog:
            v = entry.get("vendorProject", "Unknown")
            vendors[v] = vendors.get(v, 0) + 1

        top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_kev_entries": len(catalog),
            "top_vendors":       [{"vendor": v, "count": c} for v, c in top_vendors],
            "catalog_version":   datetime.now(timezone.utc).isoformat(),
            "source":            "CISA KEV",
        }


# ─────────────────────────────────────────────────────────
# Ransomware.live Adapter
# ─────────────────────────────────────────────────────────

class RansomwareLiveAdapter:
    """
    Monitor ransomware gang activity and victim disclosures.
    Data source: ransomware.live (public API)
    """

    BASE_URL = "https://api.ransomware.live/v1"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def get_recent_victims(self, limit: int = 20) -> List[Dict]:
        """
        Get recently posted ransomware victims.

        Returns:
            List of victim entries with: post_title, group_name, discovered, website, country.
        """
        if not _REQUESTS_AVAILABLE:
            return []
        try:
            r = requests.get(
                f"{self.BASE_URL}/victims",
                timeout=self.timeout,
                headers={"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"},
            )
            if r.status_code == 200:
                victims = r.json()
                return victims[:limit] if isinstance(victims, list) else []
        except Exception as e:
            logger.error(f"Ransomware.live fetch error: {e}")
        return []

    def get_active_groups(self) -> List[Dict]:
        """Get list of currently active ransomware groups."""
        if not _REQUESTS_AVAILABLE:
            return []
        try:
            r = requests.get(
                f"{self.BASE_URL}/groups",
                timeout=self.timeout,
                headers={"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"},
            )
            if r.status_code == 200:
                return r.json() if isinstance(r.json(), list) else []
        except Exception as e:
            logger.error(f"Ransomware.live groups error: {e}")
        return []

    def get_victims_by_country(self, country_code: str) -> List[Dict]:
        """Get victims filtered by country code (e.g., 'US', 'IN', 'GB')."""
        victims = self.get_recent_victims(limit=200)
        return [v for v in victims if v.get("country", "").upper() == country_code.upper()]

    def get_victims_by_sector(self, sector_keyword: str) -> List[Dict]:
        """Get victims matching a sector keyword."""
        victims = self.get_recent_victims(limit=200)
        kw = sector_keyword.lower()
        return [
            v for v in victims
            if kw in v.get("activity", "").lower() or kw in v.get("post_title", "").lower()
        ]

    def format_as_threat_advisory(self, victim: Dict) -> Dict:
        """Convert ransomware.live victim entry into a CDB threat advisory format."""
        return {
            "title":      f"Ransomware: {victim.get('group_name', 'Unknown')} claims {victim.get('post_title', 'Unknown')}",
            "severity":   "HIGH",
            "tlp":        "AMBER",
            "risk_score": 7.5,
            "source":     "ransomware.live",
            "group":      victim.get("group_name", ""),
            "victim":     victim.get("post_title", ""),
            "country":    victim.get("country", ""),
            "sector":     victim.get("activity", ""),
            "website":    victim.get("website", ""),
            "discovered": victim.get("discovered", ""),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────
# URLhaus Feed Adapter
# ─────────────────────────────────────────────────────────

class URLhausAdapter:
    """
    Abuse.ch URLhaus — malicious URL and domain threat feed.
    Provides real-time malicious URLs used for malware distribution.
    """

    RECENT_URLS   = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    LOOKUP_URL    = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_LOOKUP   = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, limit: int = 100):
        self.timeout = timeout
        self.limit   = limit

    def get_recent_malicious_urls(self) -> List[Dict]:
        """Get recently submitted malicious URLs."""
        if not _REQUESTS_AVAILABLE:
            return []
        try:
            r = requests.post(
                self.RECENT_URLS,
                data={"limit": self.limit},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    return data.get("urls", [])
        except Exception as e:
            logger.error(f"URLhaus fetch error: {e}")
        return []

    def lookup_url(self, url: str) -> Optional[Dict]:
        """Look up a specific URL in URLhaus."""
        if not _REQUESTS_AVAILABLE:
            return None
        try:
            r = requests.post(self.LOOKUP_URL, data={"url": url}, timeout=self.timeout)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.error(f"URLhaus URL lookup error: {e}")
        return None

    def lookup_host(self, host: str) -> Optional[Dict]:
        """Look up a hostname or IP in URLhaus."""
        if not _REQUESTS_AVAILABLE:
            return None
        try:
            r = requests.post(self.HOST_LOOKUP, data={"host": host}, timeout=self.timeout)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.error(f"URLhaus host lookup error: {e}")
        return None

    def extract_iocs(self, url_entries: List[Dict]) -> List[Dict]:
        """Extract IOC records from URLhaus entries."""
        iocs = []
        for entry in url_entries:
            url   = entry.get("url", "")
            host  = entry.get("host", "")
            tags  = entry.get("tags", []) or []
            if url:
                iocs.append({
                    "type":       "url",
                    "value":      url,
                    "confidence": 85,
                    "tlp":        "GREEN",
                    "tags":       tags + ["urlhaus"],
                    "first_seen": entry.get("date_added", ""),
                    "malware":    entry.get("threat", ""),
                    "source":     "urlhaus",
                })
            if host and not any(i["value"] == host for i in iocs):
                iocs.append({
                    "type":       "domain" if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else "ipv4",
                    "value":      host,
                    "confidence": 80,
                    "tlp":        "GREEN",
                    "tags":       tags + ["urlhaus"],
                    "first_seen": entry.get("date_added", ""),
                    "source":     "urlhaus",
                })
        return iocs


# ─────────────────────────────────────────────────────────
# GreyNoise Community API
# ─────────────────────────────────────────────────────────

class GreyNoiseCommunityAdapter:
    """
    GreyNoise Community API (FREE, no key required).
    Classifies IPs as: benign (scanner/cloud), malicious, or unknown.
    """

    COMMUNITY_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def classify_ip(self, ip: str) -> Optional[Dict]:
        """
        Classify an IP address with GreyNoise community data.

        Returns:
            dict with: ip, noise, riot, classification, name, link, or None.
        """
        if not _REQUESTS_AVAILABLE:
            return None
        try:
            r = requests.get(
                f"{self.COMMUNITY_URL}/{ip}",
                timeout=self.timeout,
                headers={"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"},
            )
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                return {"ip": ip, "noise": False, "riot": False, "classification": "unknown"}
        except Exception as e:
            logger.error(f"GreyNoise error for {ip}: {e}")
        return None

    def filter_malicious_ips(self, ip_list: List[str]) -> List[str]:
        """
        Filter a list of IPs, returning only those GreyNoise considers malicious.
        Removes RIOT (benign cloud/scanner) IPs to reduce false positives.
        """
        malicious = []
        for ip in ip_list:
            data = self.classify_ip(ip)
            if data:
                if data.get("riot", False):
                    continue  # RIOT = known benign cloud infra, skip
                if data.get("classification") == "malicious":
                    malicious.append(ip)
                elif data.get("noise", False) and data.get("classification") != "benign":
                    malicious.append(ip)
            time.sleep(0.3)  # Rate limit the free API
        return malicious


# ─────────────────────────────────────────────────────────
# Exploit-DB RSS Adapter
# ─────────────────────────────────────────────────────────

class ExploitDBAdapter:
    """
    Monitor Exploit-DB for new public exploits and PoC code.
    Used to detect when CVEs have active public exploitation code.
    """

    RSS_URL = "https://www.exploit-db.com/rss.xml"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, max_entries: int = 20):
        self.timeout     = timeout
        self.max_entries = max_entries

    def get_latest_exploits(self) -> List[Dict]:
        """
        Fetch latest exploits from Exploit-DB RSS feed.

        Returns:
            List of exploit entries with: title, link, published, cve, edb_id.
        """
        if not _FEEDPARSER_AVAILABLE:
            logger.warning("feedparser not available. pip install feedparser")
            return []

        try:
            feed    = feedparser.parse(self.RSS_URL)
            entries = []
            for e in feed.entries[:self.max_entries]:
                # Extract CVE IDs from title/summary
                text    = f"{e.get('title', '')} {e.get('summary', '')}"
                cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)

                entries.append({
                    "title":     e.get("title", ""),
                    "link":      e.get("link", ""),
                    "published": e.get("published", ""),
                    "summary":   e.get("summary", "")[:500],
                    "cve_ids":   list(set(cve_ids)),
                    "has_cve":   bool(cve_ids),
                    "source":    "exploit-db",
                    "edb_id":    e.get("link", "").split("/")[-1] if e.get("link") else "",
                    "poc_public": True,
                })
            return entries
        except Exception as e:
            logger.error(f"Exploit-DB RSS error: {e}")
            return []

    def get_exploits_for_cve(self, cve_id: str) -> List[Dict]:
        """Get all Exploit-DB entries matching a specific CVE ID."""
        exploits = self.get_latest_exploits()
        return [e for e in exploits if cve_id.upper() in [c.upper() for c in e.get("cve_ids", [])]]


# ─────────────────────────────────────────────────────────
# GitHub Security Advisory Adapter
# ─────────────────────────────────────────────────────────

class GitHubSecurityAdvisoryAdapter:
    """
    Monitor GitHub Security Advisories (GHSA) for newly published CVEs.
    Especially useful for open-source software vulnerabilities.
    """

    GRAPHQL_URL = "https://api.github.com/graphql"
    REST_URL    = "https://api.github.com/advisories"

    def __init__(self, github_token: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.token   = github_token
        self.timeout = timeout

    def _headers(self) -> Dict:
        headers = {
            "Accept":     "application/vnd.github.v3+json",
            "User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get_recent_advisories(self, limit: int = 30, severity: str = "HIGH") -> List[Dict]:
        """
        Fetch recent GitHub Security Advisories.

        Args:
            limit:    Max advisories to return.
            severity: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW).
        """
        if not _REQUESTS_AVAILABLE:
            return []

        sev_filter = ["CRITICAL"]
        if severity in ("HIGH", "MEDIUM", "LOW"):
            sev_filter = {"HIGH": ["CRITICAL", "HIGH"], "MEDIUM": ["CRITICAL", "HIGH", "MEDIUM"], "LOW": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}[severity]

        try:
            r = requests.get(
                self.REST_URL,
                headers=self._headers(),
                params={
                    "per_page": min(limit, 100),
                    "direction": "desc",
                    "sort": "published",
                    "severity": severity.lower(),
                    "type": "reviewed",
                },
                timeout=self.timeout,
            )
            if r.status_code == 200:
                advisories = r.json()
                results = []
                for adv in advisories:
                    results.append({
                        "ghsa_id":    adv.get("ghsa_id", ""),
                        "cve_id":     adv.get("cve_id", ""),
                        "severity":   adv.get("severity", "").upper(),
                        "summary":    adv.get("summary", ""),
                        "description": adv.get("description", "")[:1000],
                        "cvss_score": adv.get("cvss", {}).get("score"),
                        "cvss_vector": adv.get("cvss", {}).get("vector_string"),
                        "epss_score": adv.get("epss", [{}])[0].get("percentage") if adv.get("epss") else None,
                        "cwe_ids":    [c.get("cwe_id") for c in adv.get("cwes", [])],
                        "ecosystems": [v.get("package", {}).get("ecosystem") for v in adv.get("vulnerabilities", [])],
                        "packages":   [v.get("package", {}).get("name") for v in adv.get("vulnerabilities", [])],
                        "published":  adv.get("published_at", ""),
                        "updated":    adv.get("updated_at", ""),
                        "url":        adv.get("html_url", ""),
                        "source":     "github-advisory",
                        "poc_urls":   adv.get("references", []),
                    })
                return results
        except Exception as e:
            logger.error(f"GitHub Advisory fetch error: {e}")
        return []


# ─────────────────────────────────────────────────────────
# AlienVault OTX Pulse Adapter
# ─────────────────────────────────────────────────────────

class OTXPulseAdapter:
    """
    AlienVault Open Threat Exchange (OTX) pulse feed.
    Provides community threat intelligence with IOC bundles.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict:
        headers = {"User-Agent": f"CDB-SENTINEL-APEX/{MODULE_VERSION}"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    def get_subscribed_pulses(self, limit: int = 20) -> List[Dict]:
        """Get latest subscribed OTX pulses."""
        if not _REQUESTS_AVAILABLE:
            return []
        try:
            r = requests.get(
                f"{self.BASE_URL}/pulses/subscribed",
                headers=self._headers(),
                params={"limit": limit, "page": 1},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("results", [])
        except Exception as e:
            logger.error(f"OTX pulse fetch error: {e}")
        return []

    def extract_iocs_from_pulse(self, pulse: Dict) -> List[Dict]:
        """Extract IOCs from an OTX pulse."""
        ioc_type_map = {
            "IPv4": "ipv4", "IPv6": "ipv6", "domain": "domain",
            "hostname": "domain", "URL": "url", "email": "email",
            "FileHash-MD5": "md5", "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256", "CVE": "cve",
        }
        iocs = []
        for indicator in pulse.get("indicators", []):
            ioc_type = ioc_type_map.get(indicator.get("type", ""), "unknown")
            if ioc_type == "unknown":
                continue
            iocs.append({
                "type":       ioc_type,
                "value":      indicator.get("indicator", ""),
                "confidence": 75,
                "tlp":        "GREEN",
                "tags":       pulse.get("tags", []),
                "pulse_id":   pulse.get("id", ""),
                "pulse_name": pulse.get("name", ""),
                "source":     "otx-alienvault",
                "first_seen": indicator.get("created", ""),
            })
        return iocs


# ─────────────────────────────────────────────────────────
# Source Intelligence Orchestrator
# ─────────────────────────────────────────────────────────

class SourceIntelligenceOrchestrator:
    """
    Orchestrates all additional intelligence sources.
    Provides a unified interface for multi-source enrichment.

    Non-Breaking: All enrichment is additive — results augment existing
    manifest entries without replacing any existing pipeline data.
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        otx_api_key: Optional[str] = None,
    ):
        self.shodan   = ShodanInternetDBAdapter()
        self.kev      = CISAKEVAdapter()
        self.ransomware = RansomwareLiveAdapter()
        self.urlhaus  = URLhausAdapter()
        self.greynoise = GreyNoiseCommunityAdapter()
        self.exploitdb = ExploitDBAdapter()
        self.github_sa = GitHubSecurityAdvisoryAdapter(github_token=github_token)
        self.otx       = OTXPulseAdapter(api_key=otx_api_key)

    def enrich_manifest_entry(self, entry: Dict) -> Dict:
        """
        Enrich a single manifest entry with multi-source intelligence.
        Returns the entry with additional fields — original fields untouched.
        """
        enriched = dict(entry)
        enrichments = {}

        # 1. Check CVE IDs against CISA KEV
        cve_ids = entry.get("cve_ids", [])
        if cve_ids:
            kev_results = self.kev.check_cves_batch(cve_ids)
            in_kev = [cve for cve, data in kev_results.items() if data is not None]
            if in_kev:
                enrichments["kev_confirmed_cves"] = in_kev
                enrichments["kev_confirmed"]       = True
                # Boost risk score for KEV-confirmed entries
                current_risk = float(entry.get("risk_score", 0))
                enrichments["risk_score_kev_boost"] = min(current_risk + 2.0, 10.0)

        # 2. Enrich IPs with Shodan InternetDB
        ipv4_iocs = [i["value"] for i in entry.get("iocs", []) if i.get("type") == "ipv4"][:3]
        if ipv4_iocs:
            shodan_data = self.shodan.enrich_ip_list(ipv4_iocs, delay=0.3)
            if shodan_data:
                enrichments["shodan_exposure"] = shodan_data
                total_vulns = sum(len(s.get("vulns", [])) for s in shodan_data)
                if total_vulns > 0:
                    enrichments["shodan_vuln_count"] = total_vulns

        enrichments["enrichment_sources"] = ["cisa-kev", "shodan-internetdb"]
        enrichments["enriched_at"] = datetime.now(timezone.utc).isoformat()
        enrichments["enrichment_version"] = MODULE_VERSION

        enriched["multi_source_enrichment"] = enrichments
        return enriched

    def get_fresh_intelligence_batch(self) -> Dict:
        """
        Collect fresh intelligence from all additional sources.
        Returns a structured batch ready for pipeline integration.
        """
        batch = {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "sources_polled": [],
            "kev_recent":     [],
            "ransomware_victims": [],
            "exploitdb_recent":   [],
            "github_advisories":  [],
            "urlhaus_iocs":       [],
            "kev_stats":          {},
        }

        # CISA KEV recent additions
        try:
            kev_recent = self.kev.get_recent_kev(days=7)
            batch["kev_recent"]    = kev_recent
            batch["kev_stats"]     = self.kev.get_kev_stats()
            batch["sources_polled"].append("cisa-kev")
        except Exception as e:
            logger.warning(f"KEV poll failed: {e}")

        # Ransomware victim tracking
        try:
            victims = self.ransomware.get_recent_victims(limit=10)
            batch["ransomware_victims"] = victims
            batch["sources_polled"].append("ransomware.live")
        except Exception as e:
            logger.warning(f"Ransomware.live poll failed: {e}")

        # Exploit-DB
        try:
            exploits = self.exploitdb.get_latest_exploits()
            batch["exploitdb_recent"] = exploits
            batch["sources_polled"].append("exploit-db")
        except Exception as e:
            logger.warning(f"Exploit-DB poll failed: {e}")

        # GitHub Security Advisories
        try:
            advisories = self.github_sa.get_recent_advisories(limit=15, severity="HIGH")
            batch["github_advisories"] = advisories
            batch["sources_polled"].append("github-advisory")
        except Exception as e:
            logger.warning(f"GitHub Advisory poll failed: {e}")

        # URLhaus IOCs
        try:
            url_entries = self.urlhaus.get_recent_malicious_urls()
            batch["urlhaus_iocs"] = self.urlhaus.extract_iocs(url_entries)
            batch["sources_polled"].append("urlhaus")
        except Exception as e:
            logger.warning(f"URLhaus poll failed: {e}")

        logger.info(f"Fresh intelligence batch collected from {len(batch['sources_polled'])} sources")
        return batch


if __name__ == "__main__":
    print(f"CDB Multi-Source Intelligence Module v{MODULE_VERSION}")
    print("Sources: Shodan InternetDB, CISA KEV, Ransomware.live, URLhaus, GreyNoise, Exploit-DB, GitHub Advisory, OTX")
    print()

    # Demo: CISA KEV stats
    kev = CISAKEVAdapter()
    stats = kev.get_kev_stats()
    print(f"CISA KEV: {stats['total_kev_entries']} known exploited vulnerabilities")
    print(f"Top vendors: {[v['vendor'] for v in stats['top_vendors'][:5]]}")
