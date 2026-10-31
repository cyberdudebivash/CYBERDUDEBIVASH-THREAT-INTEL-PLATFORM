"""Bounded, allowlisted HTTPS advisory collector.

This collector retrieves source metadata ONLY. It never creates or confirms incidents.
No automatic publication. Network fetches require an injected, audited transport\nthat pins the resolved public IP to prevent DNS rebinding, verifies TLS hostname,\nand refuses redirects and proxy bypasses. The default path fails closed.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_BYTES = 256 * 1024
TIMEOUT_SECONDS = 8
USER_AGENT = "SENTINEL-APEX-GCII/1.0 (+https://intel.cyberdudebivash.com/)"

class CollectionError(ValueError):
    pass

def _public_ips(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise CollectionError("DNS resolution failed") from exc
    if not answers:
        raise CollectionError("no DNS answers")
    addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
    if not all(address.is_global for address in addresses):
        raise CollectionError("non-public DNS answer")
    return addresses

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectionError("redirect forbidden")

def collect(url, allowed_hosts, *, opener=None):
    if not isinstance(url, str) or len(url) > 2048:
        raise CollectionError("invalid URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CollectionError("invalid URL") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = {h.lower().rstrip(".") for h in allowed_hosts}
    if (parsed.scheme != "https" or not host or host not in allowed or
        parsed.username or parsed.password or port not in (None, 443) or
        parsed.fragment):
        raise CollectionError("source not allowlisted HTTPS")
    _public_ips(host)
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/xml, text/xml, text/plain, application/rss+xml"
    })
    if opener is None:\n        raise CollectionError("network adapter not configured: pinned-DNS transport required")\n    client = opener
    try:
        with client.open(request, timeout=TIMEOUT_SECONDS) as response:
            if getattr(response, "status", 200) != 200:
                raise CollectionError("unexpected HTTP status")
            content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if content_type not in {"application/json", "application/xml", "text/xml", "text/plain", "application/rss+xml", "application/atom+xml"}:
                raise CollectionError("unsupported content type")
            size = response.headers.get("Content-Length")
            if size and int(size) > MAX_BYTES:
                raise CollectionError("oversized response")
            body = response.read(MAX_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise CollectionError("source retrieval failed") from exc
    if len(body) > MAX_BYTES:
        raise CollectionError("oversized response")
    return {
        "url": url,
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
        "content_type": content_type,
        "size_bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "verification_state": "unreviewed",
    }
