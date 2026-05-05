#!/usr/bin/env python3
"""
scripts/sovereign_mssp_router.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — Sovereign MSSP Router
==================================================================
Implements Sovereign Mode white-label routing ($1,999/mo MSSP tier).
Dynamically maps Knowledge Graph nodes to tenant-specific domains.

SOVEREIGN MODE CAPABILITIES:
  - Per-tenant domain aliasing (custom FQDN → SENTINEL APEX backend)
  - Knowledge Graph tenant namespace isolation
  - White-label branding payload per tenant (logo, colors, API prefix)
  - Tenant-scoped feed filtering (TLP, severity, threat type)
  - JWT sub-claim isolation per tenant
  - Tenant API key rotation + audit trail
  - Output: data/sovereign/tenant_manifests/{tenant_id}.json (R2-uploadable)

USAGE IN PIPELINE (run_pipeline.py):
    from scripts.sovereign_mssp_router import SovereignRouter

    router = SovereignRouter()
    router.load_tenant_config()
    router.generate_tenant_manifests(feed_items)
    router.write_all()

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [sovereign_router] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.sovereign")

REPO = Path(__file__).resolve().parent.parent

TENANT_CONFIG_PATH  = REPO / "config" / "sovereign_tenants.json"
SOVEREIGN_DIR       = REPO / "data" / "sovereign"
TENANT_MANIFEST_DIR = SOVEREIGN_DIR / "tenant_manifests"
TENANT_AUDIT_PATH   = SOVEREIGN_DIR / "tenant_audit.jsonl"
FEED_PATH           = REPO / "api" / "feed.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    tmp.rename(path)


def _generate_tenant_api_key(tenant_id: str, secret: str) -> str:
    """Generate a deterministic but secret API key for a tenant."""
    msg = f"{tenant_id}:{secret}:{_utc_now()[:10]}".encode()
    digest = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"cdb-{tenant_id[:8]}-{digest[:24]}"


def _generate_jwt_payload(tenant_id: str, domain: str, ttl_hours: int = 24) -> dict:
    """Generate a JWT payload for tenant authentication (unsigned — sign with CDB_JWT_SECRET)."""
    now = int(time.time())
    return {
        "iss":       "SENTINEL-APEX/143.1.0",
        "sub":       f"tenant:{tenant_id}",
        "aud":       domain,
        "iat":       now,
        "exp":       now + ttl_hours * 3600,
        "tenant_id": tenant_id,
        "tier":      "SOVEREIGN_MSSP",
        "price_usd": 1999,
    }


# ── Tenant Configuration Schema ───────────────────────────────────────────────

class TenantConfig:
    """
    Represents one MSSP tenant in Sovereign Mode.

    Fields:
        tenant_id     : unique slug (e.g., 'acme-security')
        domain        : white-label domain (e.g., 'intel.acme-security.com')
        display_name  : UI display name (e.g., 'Acme Security Operations')
        logo_url      : URL to tenant logo (for white-label dashboard)
        primary_color : hex color for branding
        tlp_filter    : list of TLP levels allowed (e.g., ['TLP:WHITE', 'TLP:GREEN'])
        severity_filter: list of severity levels (e.g., ['CRITICAL', 'HIGH'])
        threat_type_filter: list of threat types (or [] for all)
        kg_namespace  : Knowledge Graph node prefix for this tenant
        api_prefix    : API URL prefix (e.g., '/api/v1/acme/')
        active        : bool
    """

    __slots__ = (
        "tenant_id", "domain", "display_name", "logo_url", "primary_color",
        "tlp_filter", "severity_filter", "threat_type_filter",
        "kg_namespace", "api_prefix", "active", "contact_email",
    )

    def __init__(self, raw: dict):
        self.tenant_id          = str(raw.get("tenant_id", ""))
        self.domain             = str(raw.get("domain", ""))
        self.display_name       = str(raw.get("display_name", self.tenant_id))
        self.logo_url           = str(raw.get("logo_url", ""))
        self.primary_color      = str(raw.get("primary_color", "#00ff88"))
        self.tlp_filter         = list(raw.get("tlp_filter", []))
        self.severity_filter    = list(raw.get("severity_filter", []))
        self.threat_type_filter = list(raw.get("threat_type_filter", []))
        self.kg_namespace       = str(raw.get("kg_namespace", f"tenant/{self.tenant_id}"))
        self.api_prefix         = str(raw.get("api_prefix", f"/api/v1/{self.tenant_id}/"))
        self.active             = bool(raw.get("active", True))
        self.contact_email      = str(raw.get("contact_email", ""))

    def to_dict(self) -> dict:
        return {slot: getattr(self, slot) for slot in self.__slots__}

    def validate(self) -> list[str]:
        errors = []
        if not self.tenant_id or not re.match(r"^[a-z0-9\-]{3,64}$", self.tenant_id):
            errors.append(f"Invalid tenant_id: '{self.tenant_id}' (must be lowercase alphanumeric, 3-64 chars)")
        if not self.domain or "." not in self.domain:
            errors.append(f"Invalid domain: '{self.domain}'")
        return errors


class SovereignRouter:
    """
    Core Sovereign Mode MSSP routing engine.
    Maps Knowledge Graph nodes to per-tenant namespaces.
    Generates scoped feed manifests for each active tenant.
    """

    def __init__(self, sovereign_key: Optional[str] = None):
        self.sovereign_key = sovereign_key or os.environ.get("CDB_SOVEREIGN_KEY", "")
        self.tenants: list[TenantConfig] = []
        self._tenant_results: dict[str, dict] = {}

    def load_tenant_config(self) -> None:
        """Load tenant configuration from config/sovereign_tenants.json."""
        if not TENANT_CONFIG_PATH.exists():
            log.warning(
                "sovereign_tenants.json not found at %s — "
                "creating default config template", TENANT_CONFIG_PATH,
            )
            self._write_default_config()

        try:
            raw = json.loads(TENANT_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            log.error("Failed to parse sovereign_tenants.json: %s", e)
            return

        tenants_raw = raw if isinstance(raw, list) else raw.get("tenants", [])
        for t in tenants_raw:
            cfg = TenantConfig(t)
            errors = cfg.validate()
            if errors:
                log.error("Tenant config invalid [%s]: %s", cfg.tenant_id, errors)
                continue
            if cfg.active:
                self.tenants.append(cfg)
                log.info("Loaded tenant: %s → %s", cfg.tenant_id, cfg.domain)

        log.info("Sovereign Router: %d active tenants loaded", len(self.tenants))

    def _write_default_config(self) -> None:
        """Write a default sovereign_tenants.json template."""
        template = {
            "tenants": [
                {
                    "tenant_id":          "example-mssp",
                    "domain":             "intel.example-mssp.com",
                    "display_name":       "Example MSSP Operations",
                    "logo_url":           "https://example-mssp.com/logo.png",
                    "primary_color":      "#1a73e8",
                    "tlp_filter":         ["TLP:WHITE", "TLP:GREEN"],
                    "severity_filter":    ["CRITICAL", "HIGH", "MEDIUM"],
                    "threat_type_filter": [],
                    "kg_namespace":       "tenant/example-mssp",
                    "api_prefix":         "/api/v1/example-mssp/",
                    "active":             False,
                    "contact_email":      "soc@example-mssp.com",
                }
            ]
        }
        TENANT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(TENANT_CONFIG_PATH, template)

    def _filter_items_for_tenant(
        self,
        items: list[dict],
        tenant: TenantConfig,
    ) -> list[dict]:
        """Apply per-tenant TLP, severity, and threat-type filters."""
        filtered = []
        for item in items:
            # TLP filter
            if tenant.tlp_filter:
                tlp = str(item.get("tlp") or item.get("tlp_level") or "TLP:WHITE").upper()
                if not any(tlp == f.upper() for f in tenant.tlp_filter):
                    continue

            # Severity filter
            if tenant.severity_filter:
                sev = str(item.get("severity") or "").upper()
                if not any(sev == s.upper() for s in tenant.severity_filter):
                    continue

            # Threat type filter
            if tenant.threat_type_filter:
                tt = str(item.get("threat_type") or "").lower()
                if not any(tt == f.lower() for f in tenant.threat_type_filter):
                    continue

            filtered.append(item)

        return filtered

    def _map_kg_nodes(self, items: list[dict], tenant: TenantConfig) -> list[dict]:
        """
        Remap Knowledge Graph node IDs to tenant-specific namespace.
        Original stix_id preserved as source_stix_id.
        """
        mapped = []
        for item in items:
            original_id = item.get("stix_id") or item.get("id") or str(uuid.uuid4())
            tenant_node_id = f"{tenant.kg_namespace}/{original_id}"

            mapped_item = {
                **item,
                "stix_id":           tenant_node_id,
                "source_stix_id":    original_id,
                "tenant_id":         tenant.tenant_id,
                "tenant_domain":     tenant.domain,
                "kg_namespace":      tenant.kg_namespace,
                "api_prefix":        tenant.api_prefix,
                "report_url":        f"{tenant.api_prefix}reports/{original_id}.html",
                "stix_bundle":       f"https://{tenant.domain}{tenant.api_prefix}stix/{original_id}.json",
                "_white_label":      True,
            }
            mapped.append(mapped_item)

        return mapped

    def generate_tenant_manifests(self, feed_items: list[dict]) -> None:
        """Generate per-tenant scoped manifests from the master feed."""
        for tenant in self.tenants:
            t_start = time.monotonic()

            filtered = self._filter_items_for_tenant(feed_items, tenant)
            mapped   = self._map_kg_nodes(filtered, tenant)

            jwt_payload = _generate_jwt_payload(tenant.tenant_id, tenant.domain)

            manifest = {
                "generated_at":   _utc_now(),
                "engine":         "SENTINEL-APEX/143.1.0",
                "sovereign_mode": True,
                "tier":           "SOVEREIGN_MSSP ($1,999/mo)",
                "tenant": {
                    "id":           tenant.tenant_id,
                    "domain":       tenant.domain,
                    "display_name": tenant.display_name,
                    "logo_url":     tenant.logo_url,
                    "primary_color": tenant.primary_color,
                    "api_prefix":   tenant.api_prefix,
                    "kg_namespace": tenant.kg_namespace,
                    "contact_email": tenant.contact_email,
                },
                "feed_stats": {
                    "total_master_items":  len(feed_items),
                    "tenant_scoped_items": len(mapped),
                    "filter_pass_rate":    round(len(mapped) / max(len(feed_items), 1) * 100, 1),
                },
                "jwt_template": jwt_payload,
                "advisories":   mapped,
            }

            self._tenant_results[tenant.tenant_id] = manifest

            elapsed = time.monotonic() - t_start
            log.info(
                "Tenant [%s]: %d/%d items scoped | domain=%s | %.3fs",
                tenant.tenant_id, len(mapped), len(feed_items), tenant.domain, elapsed,
            )

    def write_all(self) -> None:
        """Write all tenant manifests atomically."""
        TENANT_MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

        for tenant_id, manifest in self._tenant_results.items():
            out_path = TENANT_MANIFEST_DIR / f"{tenant_id}.json"
            _atomic_write(out_path, manifest)
            log.info("Tenant manifest written: %s", out_path)

            # Append to audit trail
            audit_entry = {
                "ts":         _utc_now(),
                "tenant_id":  tenant_id,
                "items":      manifest["feed_stats"]["tenant_scoped_items"],
                "domain":     manifest["tenant"]["domain"],
                "action":     "manifest_generated",
            }
            with open(TENANT_AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_entry) + "\n")

        log.info(
            "Sovereign Router: %d tenant manifests written to %s",
            len(self._tenant_results), TENANT_MANIFEST_DIR,
        )


# ── Standalone CLI ────────────────────────────────────────────────────────────

def main() -> int:
    log.info("SENTINEL APEX v143.1.0 — Sovereign MSSP Router starting")
    t0 = time.time()

    if not FEED_PATH.exists():
        log.error("api/feed.json not found")
        return 1

    try:
        items: list[dict] = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Feed parse error: %s", e)
        return 1

    router = SovereignRouter()
    router.load_tenant_config()

    if not router.tenants:
        log.warning("No active tenants — Sovereign Mode inactive. "
                    "Add tenant configs to config/sovereign_tenants.json")
        return 0

    router.generate_tenant_manifests(items)
    router.write_all()

    log.info(
        "DONE: %d active tenants processed | %.2fs",
        len(router.tenants), time.time() - t0,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
