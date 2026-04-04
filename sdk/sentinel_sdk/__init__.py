"""
sentinel_sdk — CYBERDUDEBIVASH® Sentinel APEX Python SDK v100.0
================================================================
Official Python client for the Sentinel APEX Threat Intelligence API.

Quick start::

    from sentinel_sdk import SentinelClient

    client = SentinelClient(api_key="sa_live_xxxx")

    # Get CRITICAL advisories
    page = client.get_advisories(severity="CRITICAL", limit=10)
    for advisory in page.items:
        print(f"{advisory.title} — score={advisory.risk_score}")

    # Search
    results = client.search_advisories("log4shell")

    # Stream all advisories (auto-paginate)
    for item in client.iter_advisories(severity="HIGH"):
        process(item)

    # Health check
    assert client.ping()

Installation::

    pip install sentinel-apex-sdk

    # Or from source:
    cd sdk/ && pip install -e .
"""

from .client import SentinelClient
from .models import (
    AdvisoryItem,
    ApiKeyInfo,
    FeedMetadata,
    HealthStatus,
    Page,
    StixBundle,
)
from .exceptions import (
    SentinelError,
    AuthenticationError,
    RateLimitError,
    TierPermissionError,
    NotFoundError,
    ValidationError,
    ServerError,
    NetworkError,
    SDKConfigurationError,
)

__version__ = "100.0.0"
__author__  = "CYBERDUDEBIVASH Pvt. Ltd."
__all__ = [
    # Client
    "SentinelClient",
    # Models
    "AdvisoryItem",
    "ApiKeyInfo",
    "FeedMetadata",
    "HealthStatus",
    "Page",
    "StixBundle",
    # Exceptions
    "SentinelError",
    "AuthenticationError",
    "RateLimitError",
    "TierPermissionError",
    "NotFoundError",
    "ValidationError",
    "ServerError",
    "NetworkError",
    "SDKConfigurationError",
]
