#!/usr/bin/env python3
"""
Platform version loader — single entry point for every Python module.
All version strings, anywhere in the platform, read from config/version.json
through this module. Never hardcode a version.

CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
from __future__ import annotations

import functools
import json
import os
import pathlib
from typing import Any, Dict


# Repo root detection:  core/utils/version.py -> parents[2] = repo root
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CONFIG_PATH = _REPO_ROOT / "config" / "version.json"


@functools.lru_cache(maxsize=1)
def get_version() -> Dict[str, Any]:
    """Load and cache config/version.json."""
    try:
        return json.loads(_CONFIG_PATH.read_text(encoding='utf-8'))
    except FileNotFoundError:
        # fall-through — return safe defaults so import never fails the pipeline
        return _safe_defaults()
    except json.JSONDecodeError:
        return _safe_defaults()


def _safe_defaults() -> Dict[str, Any]:
    return {
        "platform": "134.0.0",
        "platform_label": "v134.0",
        "platform_full": "SENTINEL APEX v134.0.0",
        "api_gateway": "SENTINEL-APEX/134.0.0",
        "version": "134.0.0",
        "version_display": "v134.0.0",
        "version_full": "SENTINEL APEX v134.0.0",
        "components": {"platform": "CYBERDUDEBIVASH SENTINEL APEX v134.0.0"},
        "ui": {"copyright": "(c) 2026 CyberDudeBivash Pvt. Ltd."},
    }


def platform_version() -> str:
    """e.g. '134.0.0'"""
    v = get_version()
    return str(v.get("platform") or v.get("version") or "134.0.0")


def platform_label() -> str:
    """e.g. 'v134.0'"""
    v = get_version()
    return str(v.get("platform_label") or v.get("version_short") or "v134.0")


def platform_full() -> str:
    """e.g. 'SENTINEL APEX v134.0.0'"""
    v = get_version()
    return str(v.get("platform_full") or v.get("version_full")
               or f"SENTINEL APEX v{platform_version()}")


def api_gateway_string() -> str:
    """e.g. 'SENTINEL-APEX/134.0.0'"""
    v = get_version()
    return str(v.get("api_gateway") or f"SENTINEL-APEX/{platform_version()}")


def component_version(name: str, default: str | None = None) -> str:
    """Lookup a named component version (pipeline, worker, nexus, ...)."""
    v = get_version()
    if name in v and isinstance(v[name], str):
        return v[name]
    comps = v.get("components", {}) or {}
    return str(comps.get(name, default or platform_version()))


def platform_copyright() -> str:
    v = get_version()
    return str(v.get("ui", {}).get("copyright") or "(c) 2026 CyberDudeBivash Pvt. Ltd.")


def report_footer() -> str:
    """Standard report footer string."""
    return f"{platform_copyright()} — {platform_full()}"


if __name__ == "__main__":  # pragma: no cover
    print("platform_version :", platform_version())
    print("platform_label   :", platform_label())
    print("platform_full    :", platform_full())
    print("api_gateway      :", api_gateway_string())
    print("component(worker):", component_version("worker"))
    print("copyright        :", platform_copyright())
    print("report_footer    :", report_footer())
