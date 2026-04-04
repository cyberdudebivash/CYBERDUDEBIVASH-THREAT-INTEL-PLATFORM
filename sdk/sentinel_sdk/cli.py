"""
sdk/sentinel_sdk/cli.py — CYBERDUDEBIVASH® Sentinel APEX Python SDK
Command-line interface for the Sentinel APEX API.

Usage:
    sentinel advisories --severity CRITICAL --limit 10
    sentinel search "log4shell"
    sentinel health
    sentinel ioc 1.2.3.4
    sentinel stix-export --severity HIGH --out bundle.json
    sentinel key-info
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional


def _get_client():
    """Build client from SENTINEL_API_KEY env var or ~/.sentinel/config."""
    api_key = os.environ.get("SENTINEL_API_KEY", "")
    base_url = os.environ.get("SENTINEL_BASE_URL", "")

    # Try config file fallback
    if not api_key:
        config_path = os.path.expanduser("~/.sentinel/config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                    api_key  = cfg.get("api_key", "")
                    base_url = base_url or cfg.get("base_url", "")
            except Exception:
                pass

    if not api_key:
        print(
            "ERROR: No API key found.\n"
            "Set SENTINEL_API_KEY environment variable or run:\n"
            "  sentinel configure",
            file=sys.stderr,
        )
        sys.exit(1)

    from .client import SentinelClient
    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return SentinelClient(**kwargs)


def _print_json(obj) -> None:
    if hasattr(obj, "to_dict"):
        print(json.dumps(obj.to_dict(), indent=2))
    elif hasattr(obj, "__dict__"):
        print(json.dumps(obj.__dict__, indent=2, default=str))
    else:
        print(json.dumps(obj, indent=2, default=str))


def cmd_advisories(args) -> None:
    client = _get_client()
    page = client.get_advisories(
        severity=args.severity,
        threat_type=args.threat_type,
        limit=args.limit,
        kev_only=args.kev_only,
    )
    print(f"Returned {len(page.items)} of {page.metadata.total} advisories\n")
    for item in page.items:
        kev = " [KEV]" if item.kev_present else ""
        epss = f" EPSS={item.epss_score:.3f}" if item.epss_score else ""
        print(f"  [{item.severity:8s}] {item.risk_score:4.1f}  {item.title[:70]}{kev}{epss}")


def cmd_search(args) -> None:
    client = _get_client()
    page = client.search_advisories(query=args.query, limit=args.limit)
    print(f"Search: '{args.query}' — {len(page.items)} results\n")
    for item in page.items:
        print(f"  [{item.severity:8s}] {item.title[:80]}")
        print(f"           {item.stix_id}  score={item.risk_score}")


def cmd_health(args) -> None:
    client = _get_client()
    status = client.health()
    icon = "✅" if status.is_healthy else "❌"
    print(f"{icon} Status: {status.status}  Platform: {status.platform}  Version: {status.version}")
    if status.components:
        print("\nComponents:")
        for comp, state in status.components.items():
            icon2 = "✅" if state in ("ok", "healthy") else "⚠️ "
            print(f"  {icon2} {comp}: {state}")


def cmd_ioc(args) -> None:
    client = _get_client()
    result = client.lookup_ioc(args.ioc, ioc_type=args.ioc_type)
    _print_json(result)


def cmd_stix_export(args) -> None:
    client = _get_client()
    bundle = client.export_stix(severity=args.severity, limit=args.limit)
    output = json.dumps(
        {"type": bundle.type, "id": bundle.id,
         "spec_version": bundle.spec_version, "objects": bundle.objects},
        indent=2,
    )
    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"STIX bundle written to {args.out} ({bundle.object_count} objects)")
    else:
        print(output)


def cmd_key_info(args) -> None:
    client = _get_client()
    info = client.get_key_info()
    print(f"Key:   {info.key[:12]}****")
    print(f"Tier:  {info.tier}")
    print(f"Owner: {info.owner}")
    print(f"Usage: {info.usage_today}/{info.daily_limit} today ({info.usage_pct}%)")
    if info.expires_at:
        print(f"Expires: {info.expires_at}")


def cmd_configure(args) -> None:
    import getpass
    api_key = getpass.getpass("Enter your Sentinel APEX API key: ").strip()
    if not api_key:
        print("Aborted — no key entered.", file=sys.stderr)
        sys.exit(1)

    config_dir = os.path.expanduser("~/.sentinel")
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    config_path = os.path.join(config_dir, "config.json")
    cfg = {"api_key": api_key}
    if args.base_url:
        cfg["base_url"] = args.base_url

    tmp = config_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, config_path)
    print(f"Configuration saved to {config_path}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="CYBERDUDEBIVASH® Sentinel APEX CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # advisories
    p_adv = sub.add_parser("advisories", help="List threat advisories")
    p_adv.add_argument("--severity", help="CRITICAL|HIGH|MEDIUM|LOW")
    p_adv.add_argument("--threat-type", dest="threat_type")
    p_adv.add_argument("--limit", type=int, default=20)
    p_adv.add_argument("--kev-only", dest="kev_only", action="store_true")

    # search
    p_srch = sub.add_parser("search", help="Full-text search (PRO+)")
    p_srch.add_argument("query", help="Search query")
    p_srch.add_argument("--limit", type=int, default=20)

    # health
    sub.add_parser("health", help="Check API health")

    # ioc
    p_ioc = sub.add_parser("ioc", help="Look up an IOC (PRO+)")
    p_ioc.add_argument("ioc", help="IP, hash, domain, or CVE ID")
    p_ioc.add_argument("--type", dest="ioc_type", default="auto")

    # stix-export
    p_stix = sub.add_parser("stix-export", help="Export STIX bundle (PRO+)")
    p_stix.add_argument("--severity")
    p_stix.add_argument("--limit", type=int, default=50)
    p_stix.add_argument("--out", help="Output file path (default: stdout)")

    # key-info
    sub.add_parser("key-info", help="Show API key info and usage")

    # configure
    p_cfg = sub.add_parser("configure", help="Save API key to ~/.sentinel/config.json")
    p_cfg.add_argument("--base-url", dest="base_url", help="Override API base URL")

    args = parser.parse_args()
    dispatch = {
        "advisories":  cmd_advisories,
        "search":      cmd_search,
        "health":      cmd_health,
        "ioc":         cmd_ioc,
        "stix-export": cmd_stix_export,
        "key-info":    cmd_key_info,
        "configure":   cmd_configure,
    }
    handler = dispatch.get(args.command)
    if handler:
        try:
            handler(args)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
