"""
sdk/sentinel_sdk/exceptions.py — CYBERDUDEBIVASH® Sentinel APEX Python SDK
Structured exception hierarchy for clean error handling in client code.
"""


class SentinelError(Exception):
    """Base exception for all Sentinel SDK errors."""

    def __init__(self, message: str, status_code: int = 0,
                 response_body: dict = None) -> None:
        super().__init__(message)
        self.status_code   = status_code
        self.response_body = response_body or {}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={str(self)!r}, "
            f"status_code={self.status_code})"
        )


class AuthenticationError(SentinelError):
    """API key missing, invalid, or revoked. HTTP 401/403."""


class RateLimitError(SentinelError):
    """Request quota exceeded for this tier. HTTP 429."""

    def __init__(self, message: str, retry_after_s: int = 60,
                 **kwargs) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_s = retry_after_s


class TierPermissionError(SentinelError):
    """Feature not available on current tier. HTTP 403."""

    def __init__(self, message: str, required_tier: str = "",
                 **kwargs) -> None:
        super().__init__(message, **kwargs)
        self.required_tier = required_tier


class NotFoundError(SentinelError):
    """Requested resource not found. HTTP 404."""


class ValidationError(SentinelError):
    """Request payload failed server-side validation. HTTP 422."""


class ServerError(SentinelError):
    """Sentinel API server error. HTTP 5xx."""


class NetworkError(SentinelError):
    """Connection timeout or DNS failure — no HTTP response received."""


class SDKConfigurationError(SentinelError):
    """SDK misconfiguration (missing API key, invalid base URL, etc.)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=0)
