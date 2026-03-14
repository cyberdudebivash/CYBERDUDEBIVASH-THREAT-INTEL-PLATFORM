"""
CYBERDUDEBIVASH SENTINEL APEX v50 — Attack Surface Scanner
Production-grade external attack surface monitoring:
  - Subdomain discovery (DNS brute-force, certificate transparency)
  - Port scanning (TCP connect scan with service fingerprinting)
  - Technology detection (HTTP header/response analysis)
  - Exposure analysis (risk scoring per discovered asset)

Output: data/intelligence/attack_surface.json
"""

import json
import socket
import ssl
import hashlib
import logging
import time
import re
import struct
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "intelligence"
OUTPUT_FILE = DATA_DIR / "attack_surface.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ASM] %(levelname)s %(message)s")
logger = logging.getLogger("asm_scanner")

# Common subdomains for brute-force enumeration
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "portal",
    "vpn", "remote", "api", "dev", "staging", "test", "uat", "qa", "demo",
    "blog", "shop", "store", "cdn", "static", "assets", "media", "img",
    "app", "mobile", "m", "beta", "alpha", "internal", "intranet", "extranet",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "deploy", "build",
    "monitor", "grafana", "prometheus", "kibana", "elastic", "logstash",
    "db", "database", "mysql", "postgres", "redis", "mongo", "sql",
    "ns1", "ns2", "ns3", "dns", "mx", "relay", "gateway",
    "auth", "sso", "oauth", "login", "accounts", "id", "identity",
    "docs", "wiki", "help", "support", "status", "health",
    "backup", "bak", "old", "legacy", "archive",
    "s3", "bucket", "cloud", "aws", "azure", "gcp",
    "vpn2", "ipsec", "ssl", "proxy", "reverse", "lb", "loadbalancer",
    "exchange", "owa", "autodiscover", "outlook",
    "jira", "confluence", "slack", "teams",
    "grafana", "zabbix", "nagios", "sentry",
]

# Common ports to scan
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 3306, 3389, 5432,
    5900, 5985, 5986, 6379, 6443, 8000, 8008, 8080, 8443, 8888, 9090,
    9200, 9300, 9443, 10000, 11211, 27017, 28017,
]

# Service fingerprints
SERVICE_FINGERPRINTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "K8s-API", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "ES-Transport", 11211: "Memcached", 27017: "MongoDB",
}

# Risk weights for exposure scoring
RISK_WEIGHTS = {
    "open_port_low": 5,       # Common web ports (80, 443)
    "open_port_medium": 15,   # Admin/management ports
    "open_port_high": 30,     # Database/sensitive service ports
    "missing_https": 20,
    "exposed_admin": 25,
    "outdated_tech": 15,
    "info_disclosure": 10,
    "default_page": 5,
    "directory_listing": 15,
}

HIGH_RISK_PORTS = {22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
MEDIUM_RISK_PORTS = {21, 25, 110, 143, 587, 993, 995, 2082, 2083, 2086, 2087, 5985, 5986, 8080, 9090, 10000}

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredSubdomain:
    subdomain: str
    ip_address: str
    resolved_at: str
    method: str  # dns_bruteforce, crt_transparency, zone_transfer

@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str
    banner: str = ""
    ssl_info: Optional[Dict] = None

@dataclass
class TechnologyFingerprint:
    name: str
    version: str = ""
    category: str = ""  # web_server, framework, cms, language, cdn, waf
    confidence: float = 0.0
    source: str = ""  # header, body, cookie

@dataclass
class AssetExposure:
    hostname: str
    ip_address: str
    subdomains: List[DiscoveredSubdomain] = field(default_factory=list)
    open_ports: List[PortResult] = field(default_factory=list)
    technologies: List[TechnologyFingerprint] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    scan_timestamp: str = ""
    scan_duration_seconds: float = 0.0

# ---------------------------------------------------------------------------
# Subdomain Discovery
# ---------------------------------------------------------------------------

class SubdomainDiscovery:
    """Multi-method subdomain enumeration."""

    def __init__(self, timeout: float = 3.0, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers

    def discover(self, domain: str) -> List[DiscoveredSubdomain]:
        results: List[DiscoveredSubdomain] = []
        seen: Set[str] = set()

        # Method 1: DNS brute-force
        dns_results = self._dns_bruteforce(domain)
        for sub in dns_results:
            if sub.subdomain not in seen:
                seen.add(sub.subdomain)
                results.append(sub)

        # Method 2: Certificate Transparency logs
        ct_results = self._crt_transparency(domain)
        for sub in ct_results:
            if sub.subdomain not in seen:
                seen.add(sub.subdomain)
                results.append(sub)

        logger.info(f"Subdomain discovery complete: {len(results)} subdomains for {domain}")
        return results

    def _dns_bruteforce(self, domain: str) -> List[DiscoveredSubdomain]:
        results = []
        ts = datetime.now(timezone.utc).isoformat()

        def resolve_subdomain(prefix: str) -> Optional[DiscoveredSubdomain]:
            fqdn = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return DiscoveredSubdomain(
                    subdomain=fqdn,
                    ip_address=ip,
                    resolved_at=ts,
                    method="dns_bruteforce",
                )
            except (socket.gaierror, socket.herror, socket.timeout):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(resolve_subdomain, prefix): prefix for prefix in SUBDOMAIN_WORDLIST}
            for future in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    result = future.result(timeout=self.timeout + 1)
                    if result:
                        results.append(result)
                except Exception:
                    continue

        return results

    def _crt_transparency(self, domain: str) -> List[DiscoveredSubdomain]:
        """Query crt.sh for certificate transparency logs."""
        results = []
        ts = datetime.now(timezone.utc).isoformat()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = Request(url, headers={"User-Agent": "CDB-SENTINEL-APEX/50.0"})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            seen_names: Set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") and name not in seen_names and "*" not in name:
                        seen_names.add(name)
                        try:
                            ip = socket.gethostbyname(name)
                            results.append(DiscoveredSubdomain(
                                subdomain=name,
                                ip_address=ip,
                                resolved_at=ts,
                                method="crt_transparency",
                            ))
                        except (socket.gaierror, socket.herror):
                            continue

        except Exception as e:
            logger.warning(f"CT log query failed for {domain}: {e}")

        return results


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------

class PortScanner:
    """TCP connect port scanner with banner grabbing and SSL inspection."""

    def __init__(self, timeout: float = 3.0, max_workers: int = 30):
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(self, host: str, ports: Optional[List[int]] = None) -> List[PortResult]:
        ports = ports or SCAN_PORTS
        results = []

        def scan_port(port: int) -> Optional[PortResult]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result_code = sock.connect_ex((host, port))

                if result_code == 0:
                    banner = ""
                    ssl_info = None
                    service = SERVICE_FINGERPRINTS.get(port, f"unknown-{port}")

                    # Banner grab
                    try:
                        if port in (443, 8443, 9443, 465, 993, 995):
                            ssl_info = self._get_ssl_info(host, port)
                        else:
                            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()[:256]
                    except Exception:
                        pass

                    sock.close()
                    return PortResult(port=port, state="open", service=service, banner=banner, ssl_info=ssl_info)
                else:
                    sock.close()
                    return None

            except socket.timeout:
                return PortResult(port=port, state="filtered", service=SERVICE_FINGERPRINTS.get(port, ""), banner="")
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures, timeout=120):
                try:
                    result = future.result(timeout=self.timeout + 2)
                    if result:
                        results.append(result)
                except Exception:
                    continue

        results.sort(key=lambda r: r.port)
        return results

    def _get_ssl_info(self, host: str, port: int) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    if cert:
                        return {
                            "subject": dict(x[0] for x in cert.get("subject", ())),
                            "issuer": dict(x[0] for x in cert.get("issuer", ())),
                            "not_before": cert.get("notBefore", ""),
                            "not_after": cert.get("notAfter", ""),
                            "serial": cert.get("serialNumber", ""),
                            "version": version,
                            "cipher": cipher[0] if cipher else "",
                        }
                    return {"version": version, "cipher": cipher[0] if cipher else ""}
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Technology Detector
# ---------------------------------------------------------------------------

class TechnologyDetector:
    """HTTP-based technology fingerprinting."""

    HEADER_SIGNATURES = {
        "server": [
            (r"nginx/?(\S*)", "Nginx", "web_server"),
            (r"Apache/?(\S*)", "Apache", "web_server"),
            (r"Microsoft-IIS/?(\S*)", "IIS", "web_server"),
            (r"LiteSpeed", "LiteSpeed", "web_server"),
            (r"cloudflare", "Cloudflare", "cdn"),
            (r"AmazonS3", "Amazon S3", "cloud"),
            (r"gunicorn/?(\S*)", "Gunicorn", "web_server"),
            (r"uvicorn", "Uvicorn", "web_server"),
        ],
        "x-powered-by": [
            (r"PHP/?(\S*)", "PHP", "language"),
            (r"ASP\.NET", "ASP.NET", "framework"),
            (r"Express", "Express.js", "framework"),
            (r"Next\.js", "Next.js", "framework"),
        ],
        "x-generator": [
            (r"WordPress\s*(\S*)", "WordPress", "cms"),
            (r"Drupal\s*(\S*)", "Drupal", "cms"),
        ],
    }

    BODY_SIGNATURES = [
        (r"wp-content|wp-includes", "WordPress", "cms", 0.9),
        (r"Joomla!", "Joomla", "cms", 0.9),
        (r"drupal\.js|Drupal\.settings", "Drupal", "cms", 0.9),
        (r"/__next/", "Next.js", "framework", 0.8),
        (r"react", "React", "framework", 0.5),
        (r"angular", "Angular", "framework", 0.5),
        (r"vue\.js|vuejs", "Vue.js", "framework", 0.6),
        (r"jquery", "jQuery", "library", 0.4),
        (r"bootstrap", "Bootstrap", "css_framework", 0.4),
        (r"tailwindcss|tailwind", "Tailwind CSS", "css_framework", 0.5),
        (r"cloudflare", "Cloudflare", "cdn", 0.7),
        (r"gtag|google-analytics|ga\.js", "Google Analytics", "analytics", 0.8),
    ]

    COOKIE_SIGNATURES = [
        (r"PHPSESSID", "PHP", "language"),
        (r"ASP\.NET_SessionId", "ASP.NET", "framework"),
        (r"JSESSIONID", "Java", "language"),
        (r"__cfduid|cf_clearance", "Cloudflare", "cdn"),
        (r"wordpress_logged_in", "WordPress", "cms"),
    ]

    def detect(self, hostname: str) -> List[TechnologyFingerprint]:
        results: List[TechnologyFingerprint] = []
        seen: Set[str] = set()

        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{hostname}/"
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; CDB-SENTINEL-APEX/50.0; +https://cyberdudebivash.com)",
                })
                with urlopen(req, timeout=10) as resp:
                    headers = dict(resp.headers)
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    cookies = headers.get("Set-Cookie", "")

                    # Header analysis
                    for header_name, patterns in self.HEADER_SIGNATURES.items():
                        header_val = headers.get(header_name, "")
                        if not header_val:
                            # Try case-insensitive
                            for k, v in headers.items():
                                if k.lower() == header_name.lower():
                                    header_val = v
                                    break
                        if header_val:
                            for pattern, name, category in patterns:
                                match = re.search(pattern, header_val, re.IGNORECASE)
                                if match and name not in seen:
                                    seen.add(name)
                                    version = match.group(1) if match.lastindex else ""
                                    results.append(TechnologyFingerprint(
                                        name=name, version=version,
                                        category=category, confidence=0.95,
                                        source=f"header:{header_name}",
                                    ))

                    # Body analysis
                    for pattern, name, category, confidence in self.BODY_SIGNATURES:
                        if name not in seen and re.search(pattern, body, re.IGNORECASE):
                            seen.add(name)
                            results.append(TechnologyFingerprint(
                                name=name, version="", category=category,
                                confidence=confidence, source="body",
                            ))

                    # Cookie analysis
                    for pattern, name, category in self.COOKIE_SIGNATURES:
                        if name not in seen and re.search(pattern, cookies, re.IGNORECASE):
                            seen.add(name)
                            results.append(TechnologyFingerprint(
                                name=name, version="", category=category,
                                confidence=0.85, source="cookie",
                            ))

                break  # Success, don't try the other scheme

            except Exception:
                continue

        return results


# ---------------------------------------------------------------------------
# Exposure Analyzer
# ---------------------------------------------------------------------------

class ExposureAnalyzer:
    """Calculate risk score based on discovered attack surface."""

    def analyze(self, asset: AssetExposure) -> Tuple[float, List[str]]:
        score = 0.0
        factors = []

        # Port-based risk
        for port_result in asset.open_ports:
            if port_result.state != "open":
                continue
            port = port_result.port
            if port in HIGH_RISK_PORTS:
                score += RISK_WEIGHTS["open_port_high"]
                factors.append(f"HIGH_RISK_PORT:{port} ({port_result.service})")
            elif port in MEDIUM_RISK_PORTS:
                score += RISK_WEIGHTS["open_port_medium"]
                factors.append(f"MEDIUM_RISK_PORT:{port} ({port_result.service})")
            else:
                score += RISK_WEIGHTS["open_port_low"]

        # HTTPS check
        open_ports = {p.port for p in asset.open_ports if p.state == "open"}
        if 80 in open_ports and 443 not in open_ports:
            score += RISK_WEIGHTS["missing_https"]
            factors.append("NO_HTTPS_DETECTED")

        # Admin exposure
        admin_ports = {2082, 2083, 2086, 2087, 8080, 8443, 9090, 10000}
        exposed_admin = admin_ports & open_ports
        if exposed_admin:
            score += RISK_WEIGHTS["exposed_admin"]
            factors.append(f"EXPOSED_ADMIN_PANELS:{sorted(exposed_admin)}")

        # Technology risk
        for tech in asset.technologies:
            # Outdated or risky technologies
            if tech.name in ("PHP", "ASP.NET") and tech.version:
                try:
                    major = int(tech.version.split(".")[0])
                    if tech.name == "PHP" and major < 8:
                        score += RISK_WEIGHTS["outdated_tech"]
                        factors.append(f"OUTDATED_PHP:{tech.version}")
                except (ValueError, IndexError):
                    pass

        # Information disclosure via headers
        for tech in asset.technologies:
            if tech.source.startswith("header:") and tech.version:
                score += RISK_WEIGHTS["info_disclosure"]
                factors.append(f"VERSION_DISCLOSURE:{tech.name}/{tech.version}")
                break  # Count once

        # Subdomain count factor
        if len(asset.subdomains) > 50:
            score += 10
            factors.append(f"LARGE_ATTACK_SURFACE:{len(asset.subdomains)}_subdomains")

        # Cap at 100
        score = min(round(score, 1), 100.0)
        return score, factors


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

class AttackSurfaceScanner:
    """Orchestrates the full attack surface scan pipeline."""

    def __init__(self, scan_ports: bool = True, scan_subdomains: bool = True,
                 detect_tech: bool = True, port_timeout: float = 3.0,
                 max_workers: int = 20):
        self.scan_ports_enabled = scan_ports
        self.scan_subdomains_enabled = scan_subdomains
        self.detect_tech_enabled = detect_tech
        self.subdomain_scanner = SubdomainDiscovery(timeout=3.0, max_workers=max_workers)
        self.port_scanner = PortScanner(timeout=port_timeout, max_workers=max_workers)
        self.tech_detector = TechnologyDetector()
        self.exposure_analyzer = ExposureAnalyzer()

    def scan(self, target: str) -> AssetExposure:
        """Execute full attack surface scan on target domain."""
        start_time = time.time()
        logger.info(f"Starting attack surface scan: {target}")

        # Resolve primary IP
        try:
            primary_ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Cannot resolve {target}")
            primary_ip = "unresolved"

        asset = AssetExposure(
            hostname=target,
            ip_address=primary_ip,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Phase 1: Subdomain Discovery
        if self.scan_subdomains_enabled:
            logger.info(f"[1/4] Subdomain discovery for {target}")
            asset.subdomains = self.subdomain_scanner.discover(target)
            logger.info(f"  → Found {len(asset.subdomains)} subdomains")

        # Phase 2: Port Scanning (primary host)
        if self.scan_ports_enabled and primary_ip != "unresolved":
            logger.info(f"[2/4] Port scanning {target} ({primary_ip})")
            asset.open_ports = self.port_scanner.scan(primary_ip)
            open_count = sum(1 for p in asset.open_ports if p.state == "open")
            logger.info(f"  → {open_count} open ports detected")

        # Phase 3: Technology Detection
        if self.detect_tech_enabled:
            logger.info(f"[3/4] Technology fingerprinting {target}")
            asset.technologies = self.tech_detector.detect(target)
            logger.info(f"  → {len(asset.technologies)} technologies identified")

        # Phase 4: Exposure Analysis
        logger.info(f"[4/4] Exposure analysis")
        asset.risk_score, asset.risk_factors = self.exposure_analyzer.analyze(asset)
        asset.scan_duration_seconds = round(time.time() - start_time, 2)

        logger.info(
            f"Scan complete: {target} | Risk: {asset.risk_score}/100 | "
            f"Duration: {asset.scan_duration_seconds}s"
        )

        return asset

    def scan_and_save(self, target: str) -> Dict:
        """Scan target and persist results."""
        asset = self.scan(target)
        result = self._serialize(asset)

        # Load existing results
        existing = []
        if OUTPUT_FILE.exists():
            try:
                with open(OUTPUT_FILE, "r") as f:
                    data = json.load(f)
                    existing = data.get("scans", []) if isinstance(data, dict) else data
            except Exception:
                existing = []

        # Append or update
        updated = False
        for i, scan in enumerate(existing):
            if scan.get("hostname") == target:
                existing[i] = result
                updated = True
                break
        if not updated:
            existing.append(result)

        output = {
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "module": "v50_attack_surface",
            "version": "50.0.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "scan_count": len(existing),
            "scans": existing,
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"Results saved to {OUTPUT_FILE}")
        return result

    def _serialize(self, asset: AssetExposure) -> Dict:
        return {
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "subdomains": [asdict(s) for s in asset.subdomains],
            "open_ports": [asdict(p) for p in asset.open_ports],
            "technologies": [asdict(t) for t in asset.technologies],
            "risk_score": asset.risk_score,
            "risk_factors": asset.risk_factors,
            "scan_timestamp": asset.scan_timestamp,
            "scan_duration_seconds": asset.scan_duration_seconds,
        }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CDB SENTINEL APEX — Attack Surface Scanner v50")
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain discovery")
    parser.add_argument("--no-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--no-tech", action="store_true", help="Skip technology detection")
    parser.add_argument("--timeout", type=float, default=3.0, help="Port scan timeout (seconds)")
    parser.add_argument("--workers", type=int, default=20, help="Max concurrent workers")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    args = parser.parse_args()

    scanner = AttackSurfaceScanner(
        scan_ports=not args.no_ports,
        scan_subdomains=not args.no_subdomains,
        detect_tech=not args.no_tech,
        port_timeout=args.timeout,
        max_workers=args.workers,
    )

    result = scanner.scan_and_save(args.target)

    if args.json:
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
