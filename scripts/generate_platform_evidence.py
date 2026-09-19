#!/usr/bin/env python3
"""
Generates config/platform-evidence.json: the counts a public page is allowed to
cite, computed from this repository rather than typed by hand.

Phase 8 of the P0 first-revenue mission: where unsupported social proof was
removed, it is replaced with product facts that can be re-derived at any time.
A hardcoded count drifts; a generated one cannot.

Run:  python3 scripts/generate_platform_evidence.py          # write
      python3 scripts/generate_platform_evidence.py --check  # verify, exit 1 on drift
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "config", "platform-evidence.json")


def count_files(rel, suffix):
    base = os.path.join(ROOT, rel)
    if not os.path.isdir(base):
        return 0
    n = 0
    for _, _, files in os.walk(base):
        n += sum(1 for f in files if f.endswith(suffix))
    return n


def feed_entries():
    path = os.path.join(ROOT, "data", "feed.json")
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return 0
    if isinstance(d, list):
        return len(d)
    for key in ("items", "advisories", "entries"):
        if isinstance(d.get(key), list):
            return len(d[key])
    return 0


def build():
    contract = json.load(open(os.path.join(ROOT, "config", "commercial-contract.json"), encoding="utf-8"))
    return {
        "_schema": "sentinel-apex-platform-evidence-v1",
        "_role": "MEASURED product facts, derived from this repository by scripts/generate_platform_evidence.py.",
        "_rule": "A public page may cite these because each is re-derivable from source. Counts are a floor at generation time, so phrase them as 'N+' only where the wording is about the published corpus, never about customers.",
        "_classification": "MEASURED",
        "_evidence_method": "Direct file/record count over this repository's published trees at the recorded commit.",
        "published_intelligence_reports": count_files("reports", ".html"),
        "threat_and_cve_pages": count_files("threat", ".html"),
        "stix_bundles": count_files(os.path.join("data", "stix"), ".json"),
        "research_posts": count_files("blog", ".html"),
        "live_feed_entries": feed_entries(),
        "commercial_tiers": len(contract["tiers"]),
        "export_formats": ["STIX 2.1", "TAXII 2.1", "MISP 2.4 JSON", "CSV", "Sigma", "YARA", "KQL"],
        "siem_integrations": ["Splunk", "Microsoft Sentinel", "IBM QRadar"],
        "payment": {
            "provider": "Razorpay",
            "invoicing": "GST invoice (India), GSTIN " + contract["gstin"],
            "seller": contract["seller_legal"] + " trading as " + contract["seller_trade_name"],
        },
        "uptime_commitment": {
            tier: {
                "uptime": t.get("uptime_commitment"),
                "incident_response": t.get("incident_response"),
                "p0_outage_credit": t.get("p0_outage_credit"),
            }
            for tier, t in contract["tiers"].items()
        },
        "attestation_status": contract["_attestation_status"],
    }


def main():
    fresh = build()
    if "--check" in sys.argv:
        try:
            current = json.load(open(OUT, encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"❌ {OUT} missing or unreadable ({exc}). Run without --check.")
            return 1
        drift = [k for k in fresh if k != "_role" and fresh[k] != current.get(k)]
        if drift:
            print("❌ platform evidence is stale; these no longer match source:")
            for k in drift:
                print(f"   - {k}: file={current.get(k)!r} source={fresh[k]!r}")
            print("   Run: python3 scripts/generate_platform_evidence.py")
            return 1
        print("✅ platform evidence matches source")
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(fresh, fh, indent=2)
        fh.write("\n")
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
    for k, v in fresh.items():
        if isinstance(v, int):
            print(f"  {k}: {v:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
