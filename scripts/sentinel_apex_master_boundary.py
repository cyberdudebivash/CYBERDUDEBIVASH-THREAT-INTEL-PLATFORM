"""Flag-gated boundary in front of the existing public freshness gate.

Uses the merged adapter at integrations/sentinel-apex-ai-intel.
Does not open the platform database, write api/feed.json, or upload to R2.
A caller-supplied freshness word, timestamp, or public-feed-{timestamp}
generation is not publication authority. This module does not hold the
existing publisher's release evidence, so it cannot grant eligibility.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = REPO_ROOT / "integrations" / "sentinel-apex-ai-intel" / "sentinel_apex_intel.py"
SCRIPTS_DIR = Path(__file__).resolve().parent
SCHEMA = "sentinel-apex.intel.v1"


def _adapter():
    spec = importlib.util.spec_from_file_location("sentinel_apex_intel_merged", ADAPTER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("merged SENTINEL APEX adapter is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _freshness_contract():
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    import public_freshness_contract as contract
    return contract


def activation_status(env: dict) -> dict:
    enabled = env.get("SENTINEL_APEX_AI_INTEL") == "1"
    base = str(env.get("SENTINEL_APEX_AI_INTEL_BASE_URL") or "").strip()
    common = {"schema": SCHEMA, "customer_visible": False, "public_feed_write": False, "end_to_end_verified": False}
    if not enabled:
        return {**common, "status": "NOT_CONFIGURED", "enabled": False, "reason": "SENTINEL_APEX_AI_INTEL is not 1"}
    if not base:
        return {**common, "status": "NOT_CONFIGURED", "enabled": False, "reason": "SENTINEL_APEX_AI_INTEL_BASE_URL is unset"}
    parsed = urlparse(base)
    if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname:
        return {**common, "status": "FAILED", "enabled": True, "reason": "base url must be https without credentials"}
    return {**common, "status": "CONFIGURED", "enabled": True, "base_host": parsed.hostname}


def freshness_from_feed(feed, now=None) -> dict:
    """Bind freshness to one feed generation. A label, a cached state, or a timestamp alone is unbound."""
    unbound = {"state": "unbound", "bound_to": None, "generation": None}
    if not isinstance(feed, dict) or not isinstance(feed.get("generated_at"), str) or not isinstance(feed.get("generation"), str):
        return unbound
    generated_at = feed["generated_at"]
    generation = feed["generation"]
    if generation != f"public-feed-{generated_at}":
        return unbound
    classified = _freshness_contract().classify_manifest_freshness(generated_at, now=now)
    if "state" in feed and feed.get("state") != classified["state"]:
        return unbound
    return {"state": classified["state"], "bound_to": generated_at, "generation": generation}


def publication_decision(adapter_error: str | None, freshness: dict | None = None, publisher_release: dict | None = None) -> str:
    """Caller documents cannot authorize publication.

    freshness and publisher_release are ignored on purpose. A matching
    public-feed-{generated_at} pair is caller-controlled. The existing
    public_feed_freshness_gate.py remains the publisher authority and is
    not invoked, bypassed, or rewritten here.
    """
    del freshness, publisher_release
    if adapter_error:
        return "FAILED"
    return "BLOCKED_BY_FRESHNESS_GATE"


def stage_page(env: dict, state: dict, page: dict, feed=None, now=None) -> dict:
    status = activation_status(env)
    if status["status"] != "CONFIGURED":
        return {**status, "state": state, "applied": 0, "removed": 0, "release": "NOT_AUTHORIZED", "freshness_decision": "BLOCKED_BY_FRESHNESS_GATE"}
    result = _adapter().apply_master_page(state, page)
    observation = freshness_from_feed(feed, now=now)
    decision = publication_decision(result["error"], observation)
    return {
        "status": "CONTRACT_VERIFIED" if result["error"] is None else "FAILED",
        "schema": SCHEMA,
        "customer_visible": False,
        "public_feed_write": False,
        "end_to_end_verified": False,
        "freshness_decision": decision,
        "freshness_observation": observation.get("state"),
        "freshness_bound_to": None,
        "release": "NOT_AUTHORIZED",
        "error": result["error"],
        "applied": result["applied"] if result["error"] is None else 0,
        "removed": result["removed"] if result["error"] is None else 0,
        "state": result["state"],
        "base_host": status.get("base_host"),
    }


def stage_report(env: dict) -> str:
    """Operator telemetry. Does not fetch and does not publish."""
    return json.dumps(activation_status(env), sort_keys=True)
