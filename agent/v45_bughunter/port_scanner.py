"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Port Scanner Engine
============================================================
High-performance async TCP port scanner with banner grabbing
and service identification.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("CDB-BH-PORTSCAN")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# High-risk services that warrant CRITICAL findings
HIGH_RISK_SERVICES = {"Redis", "MongoDB", "Elasticsearch", "MySQL", "PostgreSQL", "MSSQL", "SMB"}


class PortScanner:
    """Async TCP port scanner with banner grabbing."""

    def __init__(self, ports: Optional[List[int]] = None,
                 concurrency: int = 500, timeout: float = 3.0):
        self.ports = ports or list(COMMON_PORTS.keys())
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    async def scan_port(self, host: str, port: int) -> Optional[Dict]:
        async with self.sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                    banner = data.decode(errors="ignore").strip()
                except Exception:
                    pass
                finally:
                    writer.close()

                service = COMMON_PORTS.get(port, "unknown")
                severity = "HIGH" if service in HIGH_RISK_SERVICES else "MEDIUM"
                return {
                    "host": host, "port": port, "service": service,
                    "banner": banner[:256], "status": "open", "severity": severity,
                    "type": "OPEN_PORT",
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan_host(self, host: str) -> List[Dict]:
        tasks = [self.scan_port(host, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        open_ports = [r for r in results if r]
        if open_ports:
            logger.info(f"[PORT] {host}: {len(open_ports)} open ports")
        return open_ports

    async def run(self, hosts: List[str]) -> List[Dict]:
        tasks = [self.scan_host(h) for h in hosts]
        all_results = await asyncio.gather(*tasks)
        flat = [port for host_results in all_results for port in host_results]
        logger.info(f"[PORT] Total: {len(flat)} open ports across {len(hosts)} hosts")
        return flat


async def scan_ports(hosts: List[str], ports=None, concurrency=500) -> List[Dict]:
    scanner = PortScanner(ports=ports, concurrency=concurrency)
    return await scanner.run(hosts)
