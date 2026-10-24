"""Pure, fail-closed contract for the public feed-manifest smoke probe.

The legacy TLP:WHITE summary is deliberately withheld by the Worker until
its label is migrated. A 200 policy tombstone is not a broken endpoint, but
neither is it a publicly accessible feed manifest.
"""
from __future__ import annotations

import json

MAX_BODY_BYTES = 64 * 1024
EXPECTED_POLICY = "config/tlp_publication_policy.json"


def classify_manifest_response(status: int, body: bytes) -> str:
    """Return PUBLIC_SUMMARY, POLICY_WITHHELD, or INVALID (never guess)."""
    if status != 200 or not isinstance(body, bytes) or not 0 < len(body) <= MAX_BODY_BYTES:
        return "INVALID"
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError):
        return "INVALID"
    if not isinstance(data, dict):
        return "INVALID"

    # Exact shape prevents a malformed policy response or leaked extra data
    # from being misclassified as an intentional denial.
    if set(data) == {"tlp_boundary"}:
        boundary = data["tlp_boundary"]
        if (
            isinstance(boundary, dict)
            and set(boundary) == {"withheld", "reason_code", "policy"}
            and boundary.get("withheld") is True
            and boundary.get("reason_code") == "LEGACY_LABEL_UNMIGRATED"
            and boundary.get("policy") == EXPECTED_POLICY
        ):
            return "POLICY_WITHHELD"
        return "INVALID"

    # Do not accept the retired TLP:WHITE public summary as a release pass.
    if (
        data.get("tlp") == "TLP:CLEAR"
        and isinstance(data.get("platform"), str)
        and data["platform"].strip()
        and isinstance(data.get("api"), dict)
        and isinstance(data["api"].get("endpoints"), dict)
        and data["api"]["endpoints"].get("live_feed") in ("/api/feed", "/api/feed.json")
    ):
        return "PUBLIC_SUMMARY"
    return "INVALID"
