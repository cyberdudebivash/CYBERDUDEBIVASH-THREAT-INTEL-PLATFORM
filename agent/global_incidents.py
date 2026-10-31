"""Evidence-governed global critical incident feed. No network or write side effects."""
from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import urlsplit
import hashlib
import json

STATUSES = {"investigating", "confirmed", "disputed", "resolved"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCES = {"low", "medium", "high"}
VERIFICATIONS = {"reported", "corroborated", "confirmed", "disputed"}
MAX_INCIDENTS = 500
MAX_SOURCES = 20
MAX_CLAIMS = 100

class IncidentValidationError(ValueError):
    pass

def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise IncidentValidationError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IncidentValidationError("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IncidentValidationError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)

def _https(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise IncidentValidationError("invalid source URL")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise IncidentValidationError("invalid URL") from exc
    if (parts.scheme != "https" or not parts.hostname or parts.username or
            parts.password or port not in (None, 443) or
            parts.hostname in ("localhost",) or
            parts.hostname.endswith((".local", ".internal"))):
        raise IncidentValidationError("source must be public HTTPS URL")
    return value

def _string(value, name, limit=500):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise IncidentValidationError("invalid " + name)
    return value.strip()

def validate_incident(event):
    if not isinstance(event, dict):
        raise IncidentValidationError("incident must be an object")
    for field in ("id", "title", "category"):
        _string(event.get(field), field)
    for field, options in (("status", STATUSES), ("severity", SEVERITIES), ("confidence", CONFIDENCES)):
        if event.get(field) not in options:
            raise IncidentValidationError("invalid " + field)
    first = _time(event.get("first_seen_utc"))
    updated = _time(event.get("updated_utc"))
    if updated < first:
        raise IncidentValidationError("updated before first seen")
    sources = event.get("sources")
    claims = event.get("claims")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise IncidentValidationError("invalid sources")
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_CLAIMS:
        raise IncidentValidationError("invalid claims")
    urls = set()
    for source in sources:
        if not isinstance(source, dict):
            raise IncidentValidationError("invalid source")
        url = _https(source.get("url"))
        _string(source.get("publisher"), "publisher")
        _time(source.get("published_at_utc"))
        _time(source.get("retrieved_at_utc"))
        if url in urls:
            raise IncidentValidationError("duplicate source")
        urls.add(url)
    for claim in claims:
        if not isinstance(claim, dict):
            raise IncidentValidationError("invalid claim")
        _string(claim.get("text"), "claim", 2000)
        if claim.get("verification_state") not in VERIFICATIONS:
            raise IncidentValidationError("invalid verification")
        references = claim.get("source_urls")
        if not isinstance(references, list) or not references or any(u not in urls for u in references):
            raise IncidentValidationError("claim lacks evidence")
    if event["status"] == "confirmed" and not any(c["verification_state"] == "confirmed" for c in claims):
        raise IncidentValidationError("confirmed incident requires confirmed claim")
    return event

def build_feed(incidents, generated_at=None):
    if not isinstance(incidents, list) or len(incidents) > MAX_INCIDENTS:
        raise IncidentValidationError("invalid incident collection")
    by_id = {}
    for event in incidents:
        validate_incident(event)
        identifier = event["id"]
        if identifier in by_id:
            raise IncidentValidationError("duplicate incident id")
        by_id[identifier] = event
    ordered = sorted(by_id.values(), key=lambda x: (_time(x["updated_utc"]), x["id"]), reverse=True)
    payload = {"schema": "cdb.global-incidents.v1", "generated_at_utc": generated_at or datetime.now(timezone.utc).isoformat(), "incidents": ordered}
    _time(payload["generated_at_utc"])
    payload["sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return payload
