#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — Sovereign Mode MSSP Configuration Layer v143.0.0          ║
║  Phase IV Asset 3 — White-Label Managed Service ($1,999/mo)               ║
║                                                                            ║
║  Activates ENABLE_SOVEREIGN_MODE and provisions a fully white-labeled      ║
║  MSSP tenant with custom branding, isolated API scope, domain CORS,        ║
║  and report watermarking.                                                  ║
║                                                                            ║
║  Usage:                                                                    ║
║    python scripts/sovereign_config.py provision --mssp "AcmeSec GmbH"     ║
║    python scripts/sovereign_config.py list                                 ║
║    python scripts/sovereign_config.py revoke --contract-id MSSP-00042     ║
║                                                                            ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import secrets
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SOVEREIGN")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

ROOT           = Path(__file__).parent.parent
CONFIG_DIR     = ROOT / "config"
DATA_DIR       = ROOT / "data"
SOVEREIGN_DIR  = DATA_DIR / "sovereign"
FLAGS_PATH     = CONFIG_DIR / "feature_flags.json"
SOVEREIGN_DB   = SOVEREIGN_DIR / "tenants.json"
AUDIT_LOG      = SOVEREIGN_DIR / "audit.jsonl"

SOVEREIGN_DIR.mkdir(parents=True, exist_ok=True)

MSSP_PRICE_USD     = 1999
MSSP_API_RATE_MIN  = 2000
SUPPORTED_COLORS   = re.compile(r"^#[0-9a-fA-F]{6}$")


# ── Atomic helpers ────────────────────────────────────────────────────────────

def _atomic_read(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes().decode("utf-8")) if path.exists() else None
    except Exception as e:
        logger.error(f"atomic_read({path.name}): {e}")
        return None


def _atomic_write(path: Path, data: Any) -> None:
    """Write via temp → rename — zero-regression guarantee on flags file."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.rename(path)


def _append_audit(event: Dict) -> None:
    event["_ts"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# ── Tenant DB ─────────────────────────────────────────────────────────────────

def _load_tenants() -> Dict:
    return _atomic_read(SOVEREIGN_DB) or {}


def _save_tenants(tenants: Dict) -> None:
    _atomic_write(SOVEREIGN_DB, tenants)


# ── Feature Flags ──────────────────────────────────────────────────────────────

def activate_sovereign_mode(tenant: Dict) -> None:
    """
    Patch feature_flags.json to activate SOVEREIGN_MODE for this tenant.
    Uses atomic write pattern — zero regression on existing config.
    """
    flags = _atomic_read(FLAGS_PATH) or {}

    flags["ENABLE_SOVEREIGN_MODE"]       = True
    flags["SOVEREIGN_BRAND_NAME"]        = tenant["brand_name"]
    flags["SOVEREIGN_LOGO_URL"]          = tenant.get("logo_url", "")
    flags["SOVEREIGN_PRIMARY_COLOR"]     = tenant.get("primary_color", "#0ea5e9")
    flags["SOVEREIGN_DOMAIN"]            = tenant["domain"]
    flags["SOVEREIGN_TIER"]              = "MSSP"
    flags["SOVEREIGN_API_RATE_LIMIT_MIN"] = MSSP_API_RATE_MIN
    flags["SOVEREIGN_HIDE_POWERED_BY"]   = tenant.get("hide_powered_by", True)
    flags["SOVEREIGN_CUSTOM_FOOTER"]     = tenant.get("custom_footer", "")
    flags["SOVEREIGN_REPORT_WATERMARK"]  = True
    flags["SOVEREIGN_CONTRACT_ID"]       = tenant["contract_id"]
    flags["_last_updated"]               = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    _atomic_write(FLAGS_PATH, flags)
    logger.info(f"feature_flags.json updated: SOVEREIGN_MODE=True [{tenant['brand_name']}]")


def deactivate_sovereign_mode() -> None:
    flags = _atomic_read(FLAGS_PATH) or {}
    flags["ENABLE_SOVEREIGN_MODE"]   = False
    flags["SOVEREIGN_BRAND_NAME"]    = ""
    flags["SOVEREIGN_DOMAIN"]        = ""
    flags["SOVEREIGN_CONTRACT_ID"]   = ""
    flags["_last_updated"]           = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _atomic_write(FLAGS_PATH, flags)
    logger.info("feature_flags.json: SOVEREIGN_MODE deactivated")


# ── Tenant Provisioning ───────────────────────────────────────────────────────

def provision_tenant(
    brand_name: str,
    domain: str,
    primary_color: str = "#0ea5e9",
    logo_url: str = "",
    custom_footer: str = "",
    hide_powered_by: bool = True,
    contact_email: str = "",
    notes: str = "",
) -> Dict:
    """
    Provision a new MSSP sovereign tenant.

    Returns the full tenant record including API key and contract ID.
    """
    # Validation
    if not brand_name or len(brand_name) < 2:
        raise ValueError("brand_name must be at least 2 characters")
    if not domain or "." not in domain:
        raise ValueError("domain must be a valid FQDN (e.g. security.acme.com)")
    if primary_color and not SUPPORTED_COLORS.match(primary_color):
        raise ValueError("primary_color must be a valid hex color (#RRGGBB)")

    # Generate contract + API key
    contract_id = f"MSSP-{uuid.uuid4().hex[:8].upper()}"
    api_key     = f"cdb-sovereign-{secrets.token_hex(24)}"
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    tenant = {
        "contract_id":      contract_id,
        "brand_name":       brand_name.strip(),
        "domain":           domain.strip().lower(),
        "primary_color":    primary_color,
        "logo_url":         logo_url,
        "custom_footer":    custom_footer or f"Powered by {brand_name} Security Platform",
        "hide_powered_by":  hide_powered_by,
        "contact_email":    contact_email,
        "notes":            notes,
        "tier":             "MSSP",
        "price_usd_month":  MSSP_PRICE_USD,
        "api_rate_limit_min": MSSP_API_RATE_MIN,
        "api_key_hash":     api_key_hash,    # store only hash — never plaintext
        "api_key_prefix":   api_key[:20] + "...",
        "status":           "active",
        "provisioned_at":   datetime.now(timezone.utc).isoformat(),
        "activated_by":     "sovereign_config.py",
        "billing_cycle":    "monthly",
        "features": {
            "white_label_ui":     True,
            "custom_domain_cors": True,
            "report_watermark":   True,
            "api_isolation":      True,
            "dedicated_support":  True,
            "sla_99_9":           True,
        }
    }

    # Save to tenant DB
    tenants = _load_tenants()
    tenants[contract_id] = tenant
    _save_tenants(tenants)

    # Activate sovereign mode in feature_flags.json
    activate_sovereign_mode(tenant)

    # Audit trail
    _append_audit({
        "action":      "provision",
        "contract_id": contract_id,
        "brand_name":  brand_name,
        "domain":      domain,
        "operator":    "sovereign_config.py",
    })

    logger.info(
        f"MSSP tenant provisioned | "
        f"contract={contract_id} | "
        f"brand={brand_name} | "
        f"domain={domain} | "
        f"price=${MSSP_PRICE_USD}/mo"
    )

    return {
        "status":        "provisioned",
        "contract_id":   contract_id,
        "brand_name":    brand_name,
        "domain":        domain,
        "api_key":       api_key,         # SHOWN ONCE — never stored plaintext
        "api_key_hint":  tenant["api_key_prefix"],
        "tier":          "MSSP",
        "price":         f"${MSSP_PRICE_USD}/month",
        "rate_limit":    f"{MSSP_API_RATE_MIN} req/min",
        "features":      tenant["features"],
        "activation_note": (
            "SOVEREIGN_MODE is now active in feature_flags.json. "
            "Deploy to take effect. API key shown once — save securely."
        ),
        "_security_note": "Store the API key now. Only the hash is retained."
    }


def revoke_tenant(contract_id: str) -> Dict:
    """Revoke a sovereign MSSP contract."""
    tenants = _load_tenants()
    if contract_id not in tenants:
        raise ValueError(f"Contract {contract_id} not found")

    tenants[contract_id]["status"]    = "revoked"
    tenants[contract_id]["revoked_at"] = datetime.now(timezone.utc).isoformat()
    _save_tenants(tenants)
    deactivate_sovereign_mode()

    _append_audit({"action": "revoke", "contract_id": contract_id})
    logger.info(f"MSSP contract revoked: {contract_id}")
    return {"status": "revoked", "contract_id": contract_id}


def list_tenants() -> List[Dict]:
    tenants = _load_tenants()
    return [
        {
            "contract_id":   v["contract_id"],
            "brand_name":    v["brand_name"],
            "domain":        v["domain"],
            "status":        v["status"],
            "provisioned_at": v["provisioned_at"],
            "price":         f"${v.get('price_usd_month', MSSP_PRICE_USD)}/mo",
        }
        for v in tenants.values()
    ]


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Sovereign Mode MSSP Configuration"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # provision
    prov = sub.add_parser("provision", help="Provision a new MSSP tenant")
    prov.add_argument("--mssp",         required=True, help="MSSP brand name")
    prov.add_argument("--domain",       required=True, help="MSSP customer domain (FQDN)")
    prov.add_argument("--color",        default="#0ea5e9", help="Primary hex color")
    prov.add_argument("--logo",         default="", help="Logo URL")
    prov.add_argument("--footer",       default="", help="Custom footer text")
    prov.add_argument("--show-powered", action="store_true",
                      help="Show 'Powered by CDB' attribution")
    prov.add_argument("--email",        default="", help="MSSP contact email")
    prov.add_argument("--notes",        default="", help="Contract notes")

    # revoke
    rev = sub.add_parser("revoke", help="Revoke an MSSP contract")
    rev.add_argument("--contract-id", required=True)

    # list
    sub.add_parser("list", help="List all sovereign tenants")

    args = parser.parse_args()

    if args.command == "provision":
        result = provision_tenant(
            brand_name=args.mssp,
            domain=args.domain,
            primary_color=args.color,
            logo_url=args.logo,
            custom_footer=args.footer,
            hide_powered_by=not args.show_powered,
            contact_email=args.email,
            notes=args.notes,
        )
        print(json.dumps(result, indent=2))

    elif args.command == "revoke":
        result = revoke_tenant(args.contract_id)
        print(json.dumps(result, indent=2))

    elif args.command == "list":
        tenants = list_tenants()
        if tenants:
            print(f"{'CONTRACT ID':<20} {'BRAND':<30} {'DOMAIN':<30} {'STATUS':<10}")
            print("-" * 90)
            for t in tenants:
                print(
                    f"{t['contract_id']:<20} {t['brand_name']:<30} "
                    f"{t['domain']:<30} {t['status']:<10}"
                )
        else:
            print("No sovereign tenants provisioned.")


if __name__ == "__main__":
    main()
