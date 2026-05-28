#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — Runtime Version Engine
core/version-governance/runtime_version_engine.py

PHASE 73 — GLOBAL VERSION AUTHORITY ENGINE

PURPOSE:
    Single runtime entry point for ALL version queries across the platform.
    Every component, dashboard, API, and workflow that needs a version string
    reads it through this module. NEVER hardcode versions in consuming files.

ARCHITECTURE:
    Registry chain (first found wins):
    1. core/version-governance/version_registry.json   ← Phase 73 authority
    2. config/platform_version.json                    ← CI SSOT fallback
    3. config/version.json                             ← legacy fallback
    4. VERSION                                         ← bare semver fallback
    5. Compiled defaults                               ← last-resort guard

USAGE:
    from core.version_governance.runtime_version_engine import VersionEngine
    v = VersionEngine.get()
    print(v.version)          # "166.2"
    print(v.full)             # "SENTINEL APEX v166.2"
    print(v.display)          # "CYBERDUDEBIVASH® SENTINEL APEX v166.2"
    print(v.cache_buster)     # "v166.2"
    print(v.api_gateway)      # "SENTINEL-APEX/166.2"
    print(v.as_dict())        # full dict for API injection

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import functools
import json
import logging
import os
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

log = logging.getLogger("CDB-VERSION-ENGINE")

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Registry chain — ordered by authority
_REGISTRY_PATH      = _REPO_ROOT / "core" / "version-governance" / "version_registry.json"
_PLATFORM_SSOT_PATH = _REPO_ROOT / "config" / "platform_version.json"
_VERSION_JSON_PATH  = _REPO_ROOT / "config" / "version.json"
_VERSION_FILE_PATH  = _REPO_ROOT / "VERSION"

_COMPILED_DEFAULT_VERSION = "166.2"
_COMPILED_DEFAULT_CODENAME = "SOVEREIGN SYNC"


# ─────────────────────────────────────────────────────────────────────────────
# Version data class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlatformVersion:
    """Immutable platform version descriptor — single source for all runtime queries."""

    version: str            # "166.2"
    version_semver: str     # "166.2.0"
    label: str              # "v166"
    full: str               # "SENTINEL APEX v166.2"
    codename: str           # "SOVEREIGN SYNC"
    display: str            # "CYBERDUDEBIVASH® SENTINEL APEX v166.2"
    schema_version: str     # "v166.2"
    release_date: str       # "2026-05-28"
    release_type: str       # "enterprise"
    api_gateway: str        # "SENTINEL-APEX/166.2"
    cache_buster: str       # "v166.2"
    copyright: str          # "(c) 2026 ..."
    source: str             # which registry file loaded this
    loaded_at: str          # ISO timestamp of load
    components: Dict[str, str] = field(default_factory=dict)

    @property
    def major(self) -> int:
        try:
            return int(self.version.split(".")[0])
        except (ValueError, IndexError):
            return 166

    @property
    def minor(self) -> int:
        try:
            return int(self.version.split(".")[1]) if "." in self.version else 0
        except (ValueError, IndexError):
            return 2

    def as_dict(self) -> Dict[str, Any]:
        """Full version dict — inject into API responses, health endpoints, dashboards."""
        return {
            "version":         self.version,
            "version_semver":  self.version_semver,
            "label":           self.label,
            "full":            self.full,
            "codename":        self.codename,
            "display":         self.display,
            "schema_version":  self.schema_version,
            "release_date":    self.release_date,
            "release_type":    self.release_type,
            "api_gateway":     self.api_gateway,
            "cache_buster":    self.cache_buster,
            "copyright":       self.copyright,
            "platform":        "CYBERDUDEBIVASH® SENTINEL APEX",
            "api_version":     "v1",
            "stix_version":    "2.1",
            "source":          self.source,
            "loaded_at":       self.loaded_at,
            "components":      self.components,
        }

    def as_api_response(self) -> Dict[str, Any]:
        """Minimal dict for API /version endpoint."""
        return {
            "version":        self.version,
            "label":          self.label,
            "full":           self.full,
            "codename":       self.codename,
            "schema_version": self.schema_version,
            "api_gateway":    self.api_gateway,
            "platform":       "CYBERDUDEBIVASH® SENTINEL APEX",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Registry loaders
# ─────────────────────────────────────────────────────────────────────────────

def _load_from_registry() -> Optional[PlatformVersion]:
    """Load from Phase 73 version_registry.json — highest authority."""
    if not _REGISTRY_PATH.is_file():
        return None
    try:
        raw = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
        p = raw.get("platform", {})
        ver = str(p.get("version", "")).strip()
        if not ver:
            return None
        return _build_pv(
            version=ver,
            label=str(p.get("label", f"v{ver.split('.')[0]}")),
            full=str(p.get("full", f"SENTINEL APEX v{ver}")),
            codename=str(p.get("codename", "SOVEREIGN SYNC")),
            display=str(p.get("display", f"CYBERDUDEBIVASH® SENTINEL APEX v{ver}")),
            schema_version=str(p.get("schema_version", f"v{ver}")),
            release_date=str(p.get("release_date", "2026-05-28")),
            release_type=str(p.get("release_type", "enterprise")),
            copyright=str(p.get("copyright", "(c) 2026 CyberDudeBivash Pvt. Ltd.")),
            components=dict(raw.get("components", {})),
            source=str(_REGISTRY_PATH),
        )
    except Exception as exc:
        log.warning("version_registry.json load error: %s", exc)
        return None


def _load_from_platform_ssot() -> Optional[PlatformVersion]:
    """Load from config/platform_version.json — CI SSOT fallback."""
    if not _PLATFORM_SSOT_PATH.is_file():
        return None
    try:
        raw = json.loads(_PLATFORM_SSOT_PATH.read_text(encoding="utf-8"))
        p = raw.get("platform", {})
        ver = str(p.get("version", "")).strip()
        if not ver:
            return None
        return _build_pv(
            version=ver,
            label=str(p.get("label", f"v{ver.split('.')[0]}")),
            full=str(p.get("full", f"SENTINEL APEX v{ver}")),
            codename=str(p.get("codename", "APEX SOVEREIGN")),
            display=str(p.get("display", f"CYBERDUDEBIVASH® SENTINEL APEX v{ver}")),
            schema_version=str(raw.get("components", {}).get("api_gateway", ver)),
            release_date=str(p.get("release_date", "2026-05-28")),
            release_type=str(p.get("release_type", "enterprise")),
            copyright=str(p.get("copyright", "(c) 2026 CyberDudeBivash Pvt. Ltd.")),
            components=dict(raw.get("components", {})),
            source=str(_PLATFORM_SSOT_PATH),
        )
    except Exception as exc:
        log.warning("platform_version.json load error: %s", exc)
        return None


def _load_from_version_json() -> Optional[PlatformVersion]:
    """Load from config/version.json — legacy fallback."""
    if not _VERSION_JSON_PATH.is_file():
        return None
    try:
        raw = json.loads(_VERSION_JSON_PATH.read_text(encoding="utf-8"))
        ver = str(raw.get("version", "")).strip()
        if not ver:
            return None
        return _build_pv(
            version=ver,
            label=str(raw.get("label", f"v{ver.split('.')[0]}")),
            full=str(raw.get("full", f"SENTINEL APEX v{ver}")),
            codename=str(raw.get("codename", "APEX SOVEREIGN")),
            display=str(raw.get("display", f"CYBERDUDEBIVASH® SENTINEL APEX v{ver}")),
            schema_version=str(raw.get("schema_version", f"v{ver}")),
            release_date=str(raw.get("release_date", "2026-05-28")),
            release_type=str(raw.get("release_type", "enterprise")),
            copyright=str(raw.get("copyright", "(c) 2026 CyberDudeBivash Pvt. Ltd.")),
            components={},
            source=str(_VERSION_JSON_PATH),
        )
    except Exception as exc:
        log.warning("config/version.json load error: %s", exc)
        return None


def _load_from_version_file() -> Optional[PlatformVersion]:
    """Load from VERSION plain-text file — bare semver fallback."""
    if not _VERSION_FILE_PATH.is_file():
        return None
    try:
        ver = _VERSION_FILE_PATH.read_text(encoding="utf-8").strip()
        if not ver:
            return None
        return _build_pv(
            version=ver,
            label=f"v{ver.split('.')[0]}",
            full=f"SENTINEL APEX v{ver}",
            codename="APEX SOVEREIGN",
            display=f"CYBERDUDEBIVASH® SENTINEL APEX v{ver}",
            schema_version=f"v{ver}",
            release_date="2026-05-28",
            release_type="enterprise",
            copyright="(c) 2026 CyberDudeBivash Pvt. Ltd.",
            components={},
            source=str(_VERSION_FILE_PATH),
        )
    except Exception as exc:
        log.warning("VERSION file load error: %s", exc)
        return None


def _build_pv(**kwargs) -> PlatformVersion:
    ver = kwargs["version"]
    # Ensure semver (166.2 → 166.2.0)
    parts = ver.split(".")
    semver = ".".join((parts + ["0", "0"])[:3])
    return PlatformVersion(
        version=ver,
        version_semver=semver,
        label=kwargs.get("label", f"v{parts[0]}"),
        full=kwargs.get("full", f"SENTINEL APEX v{ver}"),
        codename=kwargs.get("codename", "SOVEREIGN SYNC"),
        display=kwargs.get("display", f"CYBERDUDEBIVASH® SENTINEL APEX v{ver}"),
        schema_version=kwargs.get("schema_version", f"v{ver}"),
        release_date=kwargs.get("release_date", "2026-05-28"),
        release_type=kwargs.get("release_type", "enterprise"),
        api_gateway=f"SENTINEL-APEX/{ver}",
        cache_buster=f"v{ver}",
        copyright=kwargs.get("copyright", "(c) 2026 CyberDudeBivash Pvt. Ltd."),
        source=kwargs.get("source", "compiled_default"),
        loaded_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        components=kwargs.get("components", {}),
    )


def _compiled_default() -> PlatformVersion:
    """Last-resort compiled-in default — never reaches production if CI is healthy."""
    return _build_pv(
        version=_COMPILED_DEFAULT_VERSION,
        codename=_COMPILED_DEFAULT_CODENAME,
        source="compiled_default",
    )


# ─────────────────────────────────────────────────────────────────────────────
# VersionEngine — cached singleton
# ─────────────────────────────────────────────────────────────────────────────

class VersionEngine:
    """
    Thread-safe cached version authority.
    All platform code calls VersionEngine.get() — never reads files directly.
    """

    _instance: Optional[PlatformVersion] = None

    @classmethod
    @functools.lru_cache(maxsize=1)
    def get(cls) -> PlatformVersion:
        """Return the authoritative PlatformVersion (cached after first load)."""
        loaders = [
            _load_from_registry,
            _load_from_platform_ssot,
            _load_from_version_json,
            _load_from_version_file,
        ]
        for loader in loaders:
            try:
                pv = loader()
                if pv is not None:
                    log.debug("Version loaded from: %s → %s", pv.source, pv.version)
                    return pv
            except Exception as exc:
                log.warning("Loader %s failed: %s", loader.__name__, exc)
        log.error("All version loaders failed — using compiled default %s", _COMPILED_DEFAULT_VERSION)
        return _compiled_default()

    @classmethod
    def reload(cls) -> PlatformVersion:
        """Force reload — call when registry files are updated mid-process."""
        cls.get.cache_clear()
        return cls.get()

    @classmethod
    def version(cls) -> str:
        return cls.get().version

    @classmethod
    def full(cls) -> str:
        return cls.get().full

    @classmethod
    def display(cls) -> str:
        return cls.get().display

    @classmethod
    def api_gateway(cls) -> str:
        return cls.get().api_gateway

    @classmethod
    def cache_buster(cls) -> str:
        return cls.get().cache_buster

    @classmethod
    def as_dict(cls) -> Dict[str, Any]:
        return cls.get().as_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience exports (drop-in for legacy imports)
# ─────────────────────────────────────────────────────────────────────────────

def get_version() -> str:
    return VersionEngine.version()

def get_full() -> str:
    return VersionEngine.full()

def get_display() -> str:
    return VersionEngine.display()

def get_api_gateway() -> str:
    return VersionEngine.api_gateway()

def get_cache_buster() -> str:
    return VersionEngine.cache_buster()

def get_version_dict() -> Dict[str, Any]:
    return VersionEngine.as_dict()


if __name__ == "__main__":
    import sys
    pv = VersionEngine.get()
    print(f"CYBERDUDEBIVASH® {pv.full}")
    print(f"Codename:    {pv.codename}")
    print(f"Schema:      {pv.schema_version}")
    print(f"API Gateway: {pv.api_gateway}")
    print(f"Cache bust:  {pv.cache_buster}")
    print(f"Source:      {pv.source}")
    print(f"Loaded at:   {pv.loaded_at}")
    sys.exit(0)
