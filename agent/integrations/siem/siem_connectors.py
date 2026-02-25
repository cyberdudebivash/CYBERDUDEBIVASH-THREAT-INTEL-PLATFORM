#!/usr/bin/env python3
"""
siem_connectors.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
Official SIEM/SOAR Integration Connectors.

Non-Breaking Addition: Standalone connector module.
Does NOT modify any existing platform modules.

Supported Integrations:
    1. Splunk HTTP Event Collector (HEC)
    2. Microsoft Sentinel (Log Analytics Workspace)
    3. Elastic SIEM (Elasticsearch)
    4. IBM QRadar (REST API)
    5. Cortex XSOAR (REST API)
    6. Generic Webhook (Slack, Teams, custom)

Usage:
    from agent.integrations.siem.siem_connectors import SIEMConnectorFactory

    # Splunk
    connector = SIEMConnectorFactory.create("splunk",
        hec_url="https://splunk.company.com:8088",
        hec_token="your-hec-token"
    )
    connector.send_threats(manifest_entries)

    # Microsoft Sentinel
    connector = SIEMConnectorFactory.create("sentinel",
        workspace_id="your-workspace-id",
        shared_key="your-shared-key"
    )
    connector.send_iocs(ioc_list)

Author: CyberDudeBivash Pvt. Ltd.
"""

import json
import time
import hmac
import hashlib
import base64
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger("CDB-SIEM-Connectors")

CONNECTOR_VERSION = "1.0.0"


# ──────────────────────────────────────────────────────
# Base Connector
# ──────────────────────────────────────────────────────

class BaseSIEMConnector(ABC):
    """Abstract base class for all SIEM connectors."""

    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout     = timeout
        self._sent_count = 0
        self._error_count = 0

    @abstractmethod
    def test_connection(self) -> bool:
        """Test connectivity to the SIEM platform."""
        pass

    @abstractmethod
    def send_event(self, event: Dict) -> bool:
        """Send a single event to the SIEM."""
        pass

    def send_threats(self, manifest_entries: List[Dict]) -> Dict:
        """Bulk-send threat advisories to SIEM."""
        results = {"sent": 0, "failed": 0, "errors": []}
        for entry in manifest_entries:
            event = self._format_threat_event(entry)
            try:
                if self.send_event(event):
                    results["sent"] += 1
                else:
                    results["failed"] += 1
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(str(e))
        logger.info(f"[{self.__class__.__name__}] Sent {results['sent']}/{len(manifest_entries)} threats")
        return results

    def send_iocs(self, ioc_list: List[Dict]) -> Dict:
        """Bulk-send IOCs to SIEM."""
        results = {"sent": 0, "failed": 0, "errors": []}
        for ioc in ioc_list:
            event = self._format_ioc_event(ioc)
            try:
                if self.send_event(event):
                    results["sent"] += 1
                else:
                    results["failed"] += 1
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(str(e))
        logger.info(f"[{self.__class__.__name__}] Sent {results['sent']}/{len(ioc_list)} IOCs")
        return results

    def _format_threat_event(self, entry: Dict) -> Dict:
        """Format a manifest entry as a normalized SIEM event."""
        return {
            "timestamp":      entry.get("generated_at", datetime.now(timezone.utc).isoformat()),
            "source":         "CDB-SENTINEL-APEX",
            "source_version": CONNECTOR_VERSION,
            "event_type":     "threat_advisory",
            "severity":       entry.get("severity", "UNKNOWN"),
            "tlp":            entry.get("tlp", "GREEN"),
            "risk_score":     entry.get("risk_score", 0),
            "title":          entry.get("title", ""),
            "bundle_id":      entry.get("bundle_id", ""),
            "cvss_score":     entry.get("cvss_score"),
            "epss_score":     entry.get("epss_score"),
            "kev_present":    entry.get("kev_present", False),
            "actor_tag":      entry.get("actor_tag", ""),
            "mitre_tactics":  entry.get("mitre_tactics", []),
            "cve_ids":        entry.get("cve_ids", []),
            "ioc_count":      entry.get("ioc_count", 0),
            "confidence":     entry.get("confidence_score", 0),
            "data_quality":   entry.get("data_quality", "RAW"),
            "source_url":     entry.get("source_url", ""),
            "blog_url":       entry.get("blog_url", ""),
        }

    def _format_ioc_event(self, ioc: Dict) -> Dict:
        """Format an IOC as a normalized SIEM event."""
        return {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "source":      "CDB-SENTINEL-APEX",
            "event_type":  "ioc",
            "ioc_type":    ioc.get("type", ""),
            "ioc_value":   ioc.get("value", ""),
            "confidence":  ioc.get("confidence", 0),
            "tlp":         ioc.get("tlp", "GREEN"),
            "bundle_id":   ioc.get("bundle_id", ""),
            "first_seen":  ioc.get("first_seen", ""),
            "tags":        ioc.get("tags", []),
        }

    def get_stats(self) -> Dict:
        return {
            "connector":    self.__class__.__name__,
            "sent":         self._sent_count,
            "errors":       self._error_count,
            "version":      CONNECTOR_VERSION,
        }


# ──────────────────────────────────────────────────────
# Splunk HEC Connector
# ──────────────────────────────────────────────────────

class SplunkHECConnector(BaseSIEMConnector):
    """
    Splunk HTTP Event Collector (HEC) integration.
    Sends CDB threat intelligence to Splunk for indexing and alerting.

    Setup in Splunk:
        Settings → Data Inputs → HTTP Event Collector → New Token
        Assign to index: cdb_threat_intel (recommended)
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "cdb_threat_intel",
        sourcetype: str = "cdb:threat:advisory",
        verify_ssl: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.hec_url   = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.index     = index
        self.sourcetype = sourcetype
        self.verify_ssl = verify_ssl

    def test_connection(self) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")
        try:
            r = requests.get(
                f"{self.hec_url}/services/collector/health",
                headers={"Authorization": f"Splunk {self.hec_token}"},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Splunk connection test failed: {e}")
            return False

    def send_event(self, event: Dict) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        payload = {
            "time":       time.time(),
            "host":       "CDB-SENTINEL-APEX",
            "source":     "cdb_threat_intel",
            "sourcetype": self.sourcetype,
            "index":      self.index,
            "event":      event,
        }

        for attempt in range(self.max_retries):
            try:
                r = requests.post(
                    f"{self.hec_url}/services/collector/event",
                    headers={
                        "Authorization": f"Splunk {self.hec_token}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if r.status_code == 200:
                    self._sent_count += 1
                    return True
                logger.warning(f"Splunk HEC returned {r.status_code}: {r.text}")
            except Exception as e:
                logger.error(f"Splunk send attempt {attempt+1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        self._error_count += 1
        return False

    def send_batch(self, events: List[Dict]) -> Dict:
        """
        Batch send events using Splunk HEC batch endpoint.
        More efficient than individual sends for large volumes.
        """
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        payload_lines = []
        for event in events:
            payload_lines.append(json.dumps({
                "time":       time.time(),
                "host":       "CDB-SENTINEL-APEX",
                "sourcetype": self.sourcetype,
                "index":      self.index,
                "event":      event,
            }))

        batch_payload = "\n".join(payload_lines)

        try:
            r = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers={
                    "Authorization": f"Splunk {self.hec_token}",
                    "Content-Type": "application/json",
                },
                data=batch_payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if r.status_code == 200:
                self._sent_count += len(events)
                return {"sent": len(events), "failed": 0}
        except Exception as e:
            logger.error(f"Splunk batch send failed: {e}")

        self._error_count += len(events)
        return {"sent": 0, "failed": len(events)}


# ──────────────────────────────────────────────────────
# Microsoft Sentinel Connector
# ──────────────────────────────────────────────────────

class MicrosoftSentinelConnector(BaseSIEMConnector):
    """
    Microsoft Sentinel / Azure Log Analytics integration.
    Uses the Data Collector API to push CDB threat intelligence.

    Setup:
        Azure Portal → Log Analytics Workspace → Agents → Workspace ID + Primary Key
        Custom log table: CDB_ThreatIntel_CL
    """

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        log_type: str = "CDB_ThreatIntel",
        **kwargs
    ):
        super().__init__(**kwargs)
        self.workspace_id = workspace_id
        self.shared_key   = shared_key
        self.log_type     = log_type
        self._endpoint = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    def _build_signature(self, date: str, content_length: int) -> str:
        """Build HMAC-SHA256 authorization signature for Azure Log Analytics."""
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key   = base64.b64decode(self.shared_key)
        encoded_hash  = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    def test_connection(self) -> bool:
        test_event = [{"test": True, "timestamp": datetime.now(timezone.utc).isoformat()}]
        try:
            return self.send_event(test_event[0])
        except Exception:
            return False

    def send_event(self, event: Dict) -> bool:
        return self._send_batch([event])

    def _send_batch(self, events: List[Dict]) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        body       = json.dumps(events)
        rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_len = len(body.encode("utf-8"))
        signature  = self._build_signature(rfc1123date, content_len)

        headers = {
            "Content-Type":  "application/json",
            "Authorization": signature,
            "Log-Type":      self.log_type,
            "x-ms-date":     rfc1123date,
            "time-generated-field": "timestamp",
        }

        for attempt in range(self.max_retries):
            try:
                r = requests.post(
                    self._endpoint,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                )
                if r.status_code in (200, 202):
                    self._sent_count += len(events)
                    return True
                logger.warning(f"Sentinel returned {r.status_code}: {r.text}")
            except Exception as e:
                logger.error(f"Sentinel attempt {attempt+1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        self._error_count += 1
        return False

    def send_threats(self, manifest_entries: List[Dict]) -> Dict:
        """Optimized bulk send using Azure batch API."""
        events = [self._format_threat_event(e) for e in manifest_entries]
        # Azure accepts up to 30MB per request; batch in chunks of 100
        results = {"sent": 0, "failed": 0, "errors": []}
        for i in range(0, len(events), 100):
            chunk = events[i:i+100]
            if self._send_batch(chunk):
                results["sent"] += len(chunk)
            else:
                results["failed"] += len(chunk)
                results["errors"].append(f"Batch {i//100 + 1} failed")
        return results


# ──────────────────────────────────────────────────────
# Elastic SIEM Connector
# ──────────────────────────────────────────────────────

class ElasticSIEMConnector(BaseSIEMConnector):
    """
    Elastic SIEM / Elasticsearch integration.
    Indexes CDB threat intelligence into Elasticsearch for Kibana/SIEM dashboards.

    Recommended indices:
        cdb-threats-YYYY.MM.dd
        cdb-iocs-YYYY.MM.dd
    """

    def __init__(
        self,
        es_url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "cdb-threats",
        verify_ssl: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.es_url       = es_url.rstrip("/")
        self.api_key      = api_key
        self.username     = username
        self.password     = password
        self.index_prefix = index_prefix
        self.verify_ssl   = verify_ssl

    def _headers(self) -> Dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    def _auth(self):
        if self.username and self.password:
            return (self.username, self.password)
        return None

    def _index_name(self) -> str:
        return f"{self.index_prefix}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    def test_connection(self) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")
        try:
            r = requests.get(
                f"{self.es_url}/_cluster/health",
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Elastic connection test failed: {e}")
            return False

    def send_event(self, event: Dict) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        for attempt in range(self.max_retries):
            try:
                r = requests.post(
                    f"{self.es_url}/{self._index_name()}/_doc",
                    headers=self._headers(),
                    auth=self._auth(),
                    json=event,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if r.status_code in (200, 201):
                    self._sent_count += 1
                    return True
                logger.warning(f"Elastic returned {r.status_code}: {r.text}")
            except Exception as e:
                logger.error(f"Elastic attempt {attempt+1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        self._error_count += 1
        return False

    def send_bulk(self, events: List[Dict]) -> Dict:
        """Elastic bulk API for high-throughput indexing."""
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        index_name = self._index_name()
        bulk_body  = ""
        for event in events:
            bulk_body += json.dumps({"index": {"_index": index_name}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        try:
            r = requests.post(
                f"{self.es_url}/_bulk",
                headers={**self._headers(), "Content-Type": "application/x-ndjson"},
                auth=self._auth(),
                data=bulk_body,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if r.status_code in (200, 201):
                resp  = r.json()
                sent  = sum(1 for i in resp.get("items", []) if i.get("index", {}).get("status") in (200, 201))
                failed = len(events) - sent
                self._sent_count  += sent
                self._error_count += failed
                return {"sent": sent, "failed": failed}
        except Exception as e:
            logger.error(f"Elastic bulk send failed: {e}")

        self._error_count += len(events)
        return {"sent": 0, "failed": len(events)}


# ──────────────────────────────────────────────────────
# IBM QRadar Connector
# ──────────────────────────────────────────────────────

class QRadarConnector(BaseSIEMConnector):
    """
    IBM QRadar SIEM integration via REST API.
    Pushes CDB threat intelligence as QRadar reference sets and log events.
    """

    def __init__(
        self,
        qradar_url: str,
        sec_token: str,
        reference_set_prefix: str = "CDB_Threats",
        verify_ssl: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.qradar_url          = qradar_url.rstrip("/")
        self.sec_token           = sec_token
        self.reference_set_prefix = reference_set_prefix
        self.verify_ssl          = verify_ssl

    def _headers(self) -> Dict:
        return {
            "SEC":          self.sec_token,
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "Version":      "14.0",
        }

    def test_connection(self) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")
        try:
            r = requests.get(
                f"{self.qradar_url}/api/system/about",
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            return r.status_code == 200
        except Exception as e:
            logger.error(f"QRadar connection test failed: {e}")
            return False

    def send_event(self, event: Dict) -> bool:
        """Send event to QRadar via syslog endpoint."""
        # QRadar is primarily log-based; events are sent via syslog or log source
        # This implementation uses the reference data API for IOC sets
        try:
            set_name = f"{self.reference_set_prefix}_IOCs"
            value    = event.get("ioc_value") or event.get("title", "unknown")[:100]
            r = requests.post(
                f"{self.qradar_url}/api/reference_data/sets/{set_name}",
                headers=self._headers(),
                params={"value": value},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if r.status_code in (200, 201):
                self._sent_count += 1
                return True
        except Exception as e:
            logger.error(f"QRadar send failed: {e}")

        self._error_count += 1
        return False

    def push_ioc_reference_set(self, ioc_list: List[Dict], ioc_type: str) -> Dict:
        """
        Push a batch of IOCs to a QRadar reference set.
        Creates the set if it doesn't exist.
        """
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        set_name = f"{self.reference_set_prefix}_{ioc_type.upper()}"
        values   = [i.get("value", "") for i in ioc_list if i.get("value")]

        # Bulk update reference set
        try:
            r = requests.post(
                f"{self.qradar_url}/api/reference_data/sets/bulk_load/{set_name}",
                headers=self._headers(),
                json=values,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if r.status_code in (200, 201):
                self._sent_count += len(values)
                return {"sent": len(values), "failed": 0, "set_name": set_name}
        except Exception as e:
            logger.error(f"QRadar bulk load failed: {e}")

        self._error_count += len(values)
        return {"sent": 0, "failed": len(values)}


# ──────────────────────────────────────────────────────
# Cortex XSOAR Connector
# ──────────────────────────────────────────────────────

class CortexXSOARConnector(BaseSIEMConnector):
    """
    Palo Alto Cortex XSOAR integration.
    Creates incidents and indicators from CDB threat intelligence.
    """

    def __init__(
        self,
        xsoar_url: str,
        api_key: str,
        verify_ssl: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.xsoar_url = xsoar_url.rstrip("/")
        self.api_key   = api_key
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict:
        return {
            "Authorization": self.api_key,
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    def test_connection(self) -> bool:
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")
        try:
            r = requests.get(
                f"{self.xsoar_url}/info",
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            return r.status_code == 200
        except Exception as e:
            logger.error(f"XSOAR connection test failed: {e}")
            return False

    def send_event(self, event: Dict) -> bool:
        """Create an incident in Cortex XSOAR from a CDB threat event."""
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        incident = {
            "name":        f"[CDB] {event.get('title', 'Unknown Threat')}",
            "type":        "Threat Intelligence",
            "severity":    severity_map.get(event.get("severity", "LOW"), 1),
            "details":     json.dumps(event, indent=2),
            "labels": [
                {"type": "CDB-Source",    "value": "SENTINEL-APEX"},
                {"type": "TLP",           "value": event.get("tlp", "GREEN")},
                {"type": "Risk-Score",    "value": str(event.get("risk_score", 0))},
                {"type": "Data-Quality",  "value": event.get("data_quality", "RAW")},
            ],
            "occurred":    event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "rawJSON":     json.dumps(event),
        }

        for attempt in range(self.max_retries):
            try:
                r = requests.post(
                    f"{self.xsoar_url}/incident",
                    headers=self._headers(),
                    json=incident,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if r.status_code in (200, 201):
                    self._sent_count += 1
                    return True
                logger.warning(f"XSOAR returned {r.status_code}: {r.text}")
            except Exception as e:
                logger.error(f"XSOAR attempt {attempt+1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        self._error_count += 1
        return False

    def push_indicators(self, ioc_list: List[Dict]) -> Dict:
        """Push IOCs as threat indicators to XSOAR."""
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")

        type_map = {
            "ipv4": "IP", "domain": "Domain", "url": "URL",
            "sha256": "File SHA-256", "sha1": "File SHA-1", "md5": "File MD5",
            "email": "Email", "cve": "CVE",
        }

        indicators = []
        for ioc in ioc_list:
            indicators.append({
                "value":          ioc.get("value", ""),
                "indicator_type": type_map.get(ioc.get("type", "").lower(), "Unknown"),
                "score":          3 if ioc.get("confidence", 0) > 70 else 2,
                "comment":        f"CDB SENTINEL APEX — Confidence: {ioc.get('confidence', 0)}%",
                "fields": {
                    "tags":      ["CDB-APEX", f"TLP:{ioc.get('tlp', 'GREEN')}"],
                    "tlp":       ioc.get("tlp", "GREEN"),
                    "firstseenbysource": ioc.get("first_seen", ""),
                },
                "rawJSON": json.dumps(ioc),
            })

        try:
            r = requests.post(
                f"{self.xsoar_url}/indicators/batch",
                headers=self._headers(),
                json={"indicators": indicators},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if r.status_code in (200, 201):
                sent = len(indicators)
                self._sent_count += sent
                return {"sent": sent, "failed": 0}
        except Exception as e:
            logger.error(f"XSOAR indicator push failed: {e}")

        self._error_count += len(indicators)
        return {"sent": 0, "failed": len(indicators)}


# ──────────────────────────────────────────────────────
# Generic Webhook Connector (Slack, Teams, Discord, etc.)
# ──────────────────────────────────────────────────────

class WebhookConnector(BaseSIEMConnector):
    """
    Generic webhook connector for custom integrations.
    Supports Slack, Microsoft Teams, Discord, and custom HTTP endpoints.
    """

    def __init__(
        self,
        webhook_url: str,
        platform: str = "generic",
        severity_filter: Optional[List[str]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.webhook_url     = webhook_url
        self.platform        = platform.lower()
        self.severity_filter = severity_filter or ["CRITICAL", "HIGH"]

    def test_connection(self) -> bool:
        test_payload = self._build_payload({
            "title": "CDB SENTINEL APEX — Connection Test",
            "severity": "LOW",
            "risk_score": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        try:
            r = requests.post(self.webhook_url, json=test_payload, timeout=self.timeout)
            return r.status_code in (200, 204)
        except Exception:
            return False

    def _build_payload(self, event: Dict) -> Dict:
        """Build platform-specific payload."""
        severity  = event.get("severity", "UNKNOWN")
        title     = event.get("title", "")
        score     = event.get("risk_score", 0)
        timestamp = event.get("timestamp", "")
        tlp       = event.get("tlp", "GREEN")

        color_map = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a"}
        color     = color_map.get(severity, "#64748b")

        if self.platform == "slack":
            return {
                "attachments": [{
                    "color":  color,
                    "title":  f"🚨 [{severity}] {title}",
                    "text":   f"*Risk Score:* {score}/10 | *TLP:* {tlp} | *Time:* {timestamp}",
                    "footer": "CyberDudeBivash SENTINEL APEX",
                    "fields": [
                        {"title": "CVEs",      "value": ", ".join(event.get("cve_ids", [])) or "N/A", "short": True},
                        {"title": "IOC Count", "value": str(event.get("ioc_count", 0)), "short": True},
                        {"title": "Actor",     "value": event.get("actor_tag", "Unknown"), "short": True},
                        {"title": "Quality",   "value": event.get("data_quality", "RAW"), "short": True},
                    ],
                }]
            }

        elif self.platform == "teams":
            return {
                "@type":    "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.lstrip("#"),
                "summary": f"[CDB] {severity} Threat: {title}",
                "sections": [{
                    "activityTitle":    f"🛡️ CDB SENTINEL APEX — {severity} Threat",
                    "activitySubtitle": title,
                    "facts": [
                        {"name": "Risk Score", "value": f"{score}/10"},
                        {"name": "TLP",        "value": tlp},
                        {"name": "Actor",      "value": event.get("actor_tag", "Unknown")},
                        {"name": "IOC Count",  "value": str(event.get("ioc_count", 0))},
                        {"name": "Timestamp",  "value": timestamp},
                    ],
                }],
                "potentialAction": [{
                    "@type": "OpenUri",
                    "name":  "View in Dashboard",
                    "targets": [{"os": "default", "uri": "https://intel.cyberdudebivash.com"}],
                }],
            }

        elif self.platform == "discord":
            return {
                "embeds": [{
                    "title":       f"🚨 [{severity}] Threat Alert",
                    "description": title,
                    "color":       int(color.lstrip("#"), 16),
                    "fields": [
                        {"name": "Risk Score", "value": f"{score}/10",                         "inline": True},
                        {"name": "TLP",        "value": tlp,                                   "inline": True},
                        {"name": "Actor",      "value": event.get("actor_tag", "Unknown"),     "inline": True},
                    ],
                    "footer": {"text": "CyberDudeBivash SENTINEL APEX"},
                    "timestamp": timestamp,
                }]
            }

        else:
            # Generic JSON payload
            return {"source": "CDB-SENTINEL-APEX", "event": event}

    def send_event(self, event: Dict) -> bool:
        severity = event.get("severity", "")
        if self.severity_filter and severity not in self.severity_filter:
            return True  # Skip silently — not in filter

        payload = self._build_payload(event)
        for attempt in range(self.max_retries):
            try:
                r = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout,
                )
                if r.status_code in (200, 204):
                    self._sent_count += 1
                    return True
                logger.warning(f"Webhook returned {r.status_code}: {r.text}")
            except Exception as e:
                logger.error(f"Webhook attempt {attempt+1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        self._error_count += 1
        return False


# ──────────────────────────────────────────────────────
# Connector Factory
# ──────────────────────────────────────────────────────

class SIEMConnectorFactory:
    """
    Factory for creating SIEM connector instances.

    Usage:
        connector = SIEMConnectorFactory.create("splunk",
            hec_url="https://splunk.company.com:8088",
            hec_token="your-token"
        )
    """

    _REGISTRY = {
        "splunk":    SplunkHECConnector,
        "sentinel":  MicrosoftSentinelConnector,
        "elastic":   ElasticSIEMConnector,
        "qradar":    QRadarConnector,
        "xsoar":     CortexXSOARConnector,
        "webhook":   WebhookConnector,
        "slack":     lambda **kw: WebhookConnector(platform="slack", **kw),
        "teams":     lambda **kw: WebhookConnector(platform="teams", **kw),
        "discord":   lambda **kw: WebhookConnector(platform="discord", **kw),
    }

    @classmethod
    def create(cls, connector_type: str, **kwargs) -> BaseSIEMConnector:
        """
        Create a SIEM connector instance.

        Args:
            connector_type: One of splunk, sentinel, elastic, qradar, xsoar,
                            webhook, slack, teams, discord
            **kwargs: Connector-specific configuration parameters.

        Returns:
            BaseSIEMConnector: Configured connector instance.
        """
        ct = connector_type.lower()
        if ct not in cls._REGISTRY:
            raise ValueError(
                f"Unknown connector type: {ct}. "
                f"Available: {', '.join(cls._REGISTRY.keys())}"
            )
        return cls._REGISTRY[ct](**kwargs)

    @classmethod
    def list_connectors(cls) -> List[str]:
        """List all available connector types."""
        return list(cls._REGISTRY.keys())


# ──────────────────────────────────────────────────────
# Multi-SIEM Fan-out
# ──────────────────────────────────────────────────────

class MultiSIEMFanout:
    """
    Fan-out threat intelligence to multiple SIEMs simultaneously.

    Usage:
        fanout = MultiSIEMFanout()
        fanout.add_connector("splunk", SplunkHECConnector(...))
        fanout.add_connector("sentinel", MicrosoftSentinelConnector(...))
        fanout.broadcast_threats(manifest_entries)
    """

    def __init__(self):
        self._connectors: Dict[str, BaseSIEMConnector] = {}

    def add_connector(self, name: str, connector: BaseSIEMConnector):
        self._connectors[name] = connector
        logger.info(f"Added connector: {name} ({connector.__class__.__name__})")

    def remove_connector(self, name: str):
        self._connectors.pop(name, None)

    def broadcast_threats(self, manifest_entries: List[Dict]) -> Dict:
        """Send threat advisories to ALL registered SIEMs."""
        results = {}
        for name, connector in self._connectors.items():
            try:
                results[name] = connector.send_threats(manifest_entries)
            except Exception as e:
                results[name] = {"sent": 0, "failed": len(manifest_entries), "error": str(e)}
        return results

    def broadcast_iocs(self, ioc_list: List[Dict]) -> Dict:
        """Send IOCs to ALL registered SIEMs."""
        results = {}
        for name, connector in self._connectors.items():
            try:
                results[name] = connector.send_iocs(ioc_list)
            except Exception as e:
                results[name] = {"sent": 0, "failed": len(ioc_list), "error": str(e)}
        return results

    def health_check_all(self) -> Dict:
        """Test connectivity to all registered SIEMs."""
        return {
            name: connector.test_connection()
            for name, connector in self._connectors.items()
        }

    def get_all_stats(self) -> Dict:
        return {
            name: connector.get_stats()
            for name, connector in self._connectors.items()
        }


if __name__ == "__main__":
    print("CDB SIEM Connectors v1.0.0")
    print(f"Available connectors: {', '.join(SIEMConnectorFactory.list_connectors())}")
    print("Usage: from agent.integrations.siem.siem_connectors import SIEMConnectorFactory")
