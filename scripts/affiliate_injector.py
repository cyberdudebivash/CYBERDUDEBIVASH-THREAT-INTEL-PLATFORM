#!/usr/bin/env python3
"""
scripts/affiliate_injector.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Affiliate Revenue Injector v1.0
====================================================================
Injects affiliate/referral revenue links into threat intel outputs.

Revenue mechanics:
  - Contextual affiliate links based on threat type (IOC → AbuseIPDB Pro,
    CVE → VulnDB Pro, MITRE ATT&CK → partner tools, Ransomware → backup solutions)
  - UTM-tagged upgrade CTAs for all outbound links (revenue attribution)
  - Partner referral codes (MSSP white-label program)
  - Click-tracking stubs for A/B testing
  - Affiliate link injection into: API responses, PDF reports, Telegram alerts,
    email templates, Gumroad product descriptions

Affiliate partner registry:
  - AbuseIPDB Pro      ($20/mo CPA — IP reputation)
  - VirusTotal Premium ($35/mo CPA — malware analysis)
  - Shodan Premium     ($60/mo CPA — attack surface)
  - MISP Platform      (lead gen — open source ISAC)
  - Recorded Future    (enterprise referral — ~$5K ACV)
  - CrowdStrike        (enterprise referral — ~$15K ACV)
  - Tailscale          (network security — $20 CPA)
  - 1Password Business (credential security — $36 CPA)

All links are UTM-tagged:
  utm_source=sentinel_apex
  utm_medium=affiliate
  utm_campaign=<threat_type>
  utm_content=<placement>

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AFFILIATE %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-AFFILIATE")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).resolve().parent.parent
CLICK_LOG     = BASE_DIR / "data" / "affiliate_clicks.jsonl"
INJECT_LOG    = BASE_DIR / "data" / "affiliate_injections.jsonl"

# ---------------------------------------------------------------------------
# Affiliate Partner Registry
# ---------------------------------------------------------------------------
# CPA = Cost Per Acquisition (estimated commission per conversion)
# ACV = Annual Contract Value (for enterprise leads)

AFFILIATE_PARTNERS: Dict[str, Dict] = {
    "abuseipdb_pro": {
        "name":        "AbuseIPDB Pro",
        "base_url":    "https://www.abuseipdb.com/pricing",
        "referral_id": os.environ.get("AFF_ABUSEIPDB_REF", "cyberdudebivash"),
        "cpa_usd":     20,
        "tier":        "SMB",
        "category":    "ip_reputation",
        "match_tags":  ["ip", "ioc", "abuse", "botnet", "spam"],
        "cta_text":    "Check IPs at scale — AbuseIPDB Pro",
        "monthly_price": "$20/mo",
    },
    "virustotal_premium": {
        "name":        "VirusTotal Premium",
        "base_url":    "https://www.virustotal.com/gui/sign-in",
        "referral_id": os.environ.get("AFF_VT_REF", "cdb_sentinel"),
        "cpa_usd":     35,
        "tier":        "SMB",
        "category":    "malware_analysis",
        "match_tags":  ["hash", "malware", "ransomware", "trojan", "file"],
        "cta_text":    "Analyze malware — VirusTotal Premium",
        "monthly_price": "$35/mo",
    },
    "shodan_pro": {
        "name":        "Shodan Pro",
        "base_url":    "https://account.shodan.io/billing",
        "referral_id": os.environ.get("AFF_SHODAN_REF", ""),
        "cpa_usd":     60,
        "tier":        "SMB",
        "category":    "attack_surface",
        "match_tags":  ["exposure", "port", "banner", "network", "iot", "scada"],
        "cta_text":    "Map your attack surface — Shodan Pro",
        "monthly_price": "$60/mo",
    },
    "tailscale_business": {
        "name":        "Tailscale Business",
        "base_url":    "https://tailscale.com/kb/1095/pricing/",
        "referral_id": os.environ.get("AFF_TAILSCALE_REF", ""),
        "cpa_usd":     20,
        "tier":        "SMB",
        "category":    "network_security",
        "match_tags":  ["lateral_movement", "vpn", "remote_access", "zero_trust"],
        "cta_text":    "Zero-trust networking — Tailscale",
        "monthly_price": "$18/user/mo",
    },
    "1password_business": {
        "name":        "1Password Business",
        "base_url":    "https://1password.com/teams/",
        "referral_id": os.environ.get("AFF_1PASSWORD_REF", ""),
        "cpa_usd":     36,
        "tier":        "SMB",
        "category":    "credential_security",
        "match_tags":  ["credential", "phishing", "password", "breach", "infostealer"],
        "cta_text":    "Protect credentials — 1Password Business",
        "monthly_price": "$8/user/mo",
    },
    "crowdstrike_falcon": {
        "name":        "CrowdStrike Falcon",
        "base_url":    "https://www.crowdstrike.com/products/",
        "referral_id": os.environ.get("AFF_CROWDSTRIKE_REF", ""),
        "cpa_usd":     500,    # Enterprise lead gen
        "tier":        "ENTERPRISE",
        "category":    "endpoint_detection",
        "match_tags":  ["apt", "nation_state", "ransomware", "p1", "critical"],
        "cta_text":    "Enterprise EDR — CrowdStrike Falcon",
        "monthly_price": "Contact sales",
    },
    "recorded_future": {
        "name":        "Recorded Future",
        "base_url":    "https://www.recordedfuture.com/demo/",
        "referral_id": os.environ.get("AFF_RF_REF", ""),
        "cpa_usd":     300,    # Enterprise referral
        "tier":        "ENTERPRISE",
        "category":    "threat_intelligence",
        "match_tags":  ["threat_actor", "apt", "intelligence", "darkweb", "ttps"],
        "cta_text":    "Enterprise Threat Intel — Recorded Future",
        "monthly_price": "Contact sales",
    },
    "veeam_backup": {
        "name":        "Veeam Backup & Replication",
        "base_url":    "https://www.veeam.com/vm-backup-recovery-replication-software.html",
        "referral_id": os.environ.get("AFF_VEEAM_REF", ""),
        "cpa_usd":     150,
        "tier":        "SMB",
        "category":    "backup_recovery",
        "match_tags":  ["ransomware", "data_destruction", "wiper", "backup"],
        "cta_text":    "Ransomware-proof backup — Veeam",
        "monthly_price": "From $150/yr",
    },
}

# Platform self-promotion upgrade CTAs (internal — not affiliate)
INTERNAL_CTAs: Dict[str, Dict] = {
    "free_to_pro": {
        "url":  "https://intel.cyberdudebivash.com/get-api-key.html?plan=pro&utm_source=sentinel_apex&utm_medium=in_product&utm_campaign=upgrade_cta",
        "text": "Unlock PRO — $49/mo. Full IOC intel, STIX bundles, EPSS scores.",
    },
    "pro_to_enterprise": {
        "url":  "https://intel.cyberdudebivash.com/contact-enterprise.html?utm_source=sentinel_apex&utm_medium=in_product&utm_campaign=enterprise_cta",
        "text": "Enterprise SOC API — 50K req/day, webhooks, bulk export, dedicated support.",
    },
    "detection_packs": {
        "url":  "https://cyberdudebivash.gumroad.com/?utm_source=sentinel_apex&utm_medium=in_product&utm_campaign=detection_packs",
        "text": "Detection Packs — Sigma + YARA + KQL rules for today's top threats.",
    },
    "monthly_report": {
        "url":  "https://cyberdudebivash.gumroad.com/l/sentinel-monthly-report?utm_source=sentinel_apex&utm_medium=affiliate&utm_campaign=report",
        "text": "Monthly Threat Intelligence Report — C-suite ready PDF. $99/month.",
    },
}

# ---------------------------------------------------------------------------
# UTM Builder
# ---------------------------------------------------------------------------

def build_utm_url(
    base_url: str,
    source: str = "sentinel_apex",
    medium: str = "affiliate",
    campaign: str = "threat_intel",
    content: str = "",
    term: str = "",
    referral_id: str = "",
) -> str:
    """Build a UTM-tagged URL with optional referral parameters."""
    parsed = urllib.parse.urlparse(base_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    params["utm_source"]   = source
    params["utm_medium"]   = medium
    params["utm_campaign"] = campaign
    if content:
        params["utm_content"] = content
    if term:
        params["utm_term"] = term
    if referral_id:
        params["ref"] = referral_id

    new_query = urllib.parse.urlencode(params)
    new_url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )
    return new_url


# ---------------------------------------------------------------------------
# Tag-Based Partner Matching
# ---------------------------------------------------------------------------

def _extract_content_tags(intel_item: Dict) -> List[str]:
    """
    Extract matching tags from a threat intel item for affiliate matching.
    Considers: severity, ioc types, apex_ai tactics, title keywords, MITRE tags.
    """
    tags: List[str] = []

    # Severity/priority tags
    severity = intel_item.get("severity", "").upper()
    if severity == "CRITICAL":
        tags.extend(["critical", "p1"])
    soc_pri = intel_item.get("apex_ai", {}).get("soc_priority", "")
    if soc_pri == "P1":
        tags.append("p1")

    # IOC type tags
    iocs = intel_item.get("iocs", [])
    if iocs:
        tags.append("ioc")
    if intel_item.get("ioc_count", 0) > 0:
        tags.append("ioc")

    # Title keyword scanning
    title = intel_item.get("title", "").lower()
    keyword_tag_map = {
        "ransomware":    ["ransomware", "backup"],
        "apt":           ["apt", "nation_state", "threat_actor"],
        "infostealer":   ["infostealer", "credential"],
        "phishing":      ["phishing", "credential"],
        "botnet":        ["botnet", "ip", "abuse"],
        "malware":       ["malware", "hash"],
        "backdoor":      ["malware", "lateral_movement"],
        "exploit":       ["exposure"],
        "zero-day":      ["critical", "p1"],
        "vulnerability": ["exposure"],
        "data breach":   ["credential", "breach"],
        "wiper":         ["data_destruction", "ransomware"],
        "lateral":       ["lateral_movement"],
        "credential":    ["credential", "phishing"],
    }
    for kw, kw_tags in keyword_tag_map.items():
        if kw in title:
            tags.extend(kw_tags)

    # MITRE tactic tags
    tactics = intel_item.get("apex_ai", {}).get("mitre_tactics", [])
    tactic_tag_map = {
        "Credential Access":    ["credential"],
        "Initial Access":       ["phishing", "exposure"],
        "Lateral Movement":     ["lateral_movement", "zero_trust"],
        "Exfiltration":         ["data_destruction"],
        "Impact":               ["ransomware", "backup"],
        "Persistence":          ["malware"],
        "Command and Control":  ["botnet", "network"],
    }
    for tactic in tactics:
        for tact_name, tact_tags in tactic_tag_map.items():
            if tact_name.lower() in tactic.lower():
                tags.extend(tact_tags)

    # Behavioral tags
    behavioral = intel_item.get("behavioral_tags", [])
    for bt in behavioral:
        tags.append(bt.lower().replace(" ", "_").replace("-", "_"))

    return list(set(tags))


def match_affiliates(tags: List[str], tier: str = "FREE", max_affiliates: int = 3) -> List[Dict]:
    """
    Match relevant affiliate partners based on content tags.
    Prioritizes by CPA value descending (maximize revenue potential).
    Excludes enterprise-tier affiliates for FREE content.
    """
    matched: List[Dict] = []

    for partner_id, partner in AFFILIATE_PARTNERS.items():
        partner_tags = partner.get("match_tags", [])
        overlap = set(tags) & set(partner_tags)

        if not overlap:
            continue

        # Skip enterprise-tier affiliates for mass content
        if partner.get("tier") == "ENTERPRISE" and tier == "FREE":
            continue

        score = len(overlap) * partner.get("cpa_usd", 0)
        matched.append({
            "partner_id": partner_id,
            "partner":    partner,
            "overlap":    list(overlap),
            "score":      score,
        })

    # Sort by score (highest CPA × relevance first)
    matched.sort(key=lambda x: x["score"], reverse=True)
    return matched[:max_affiliates]


# ---------------------------------------------------------------------------
# Injection Functions
# ---------------------------------------------------------------------------

def inject_into_api_response(
    response: Dict,
    intel_items: List[Dict],
    tier: str = "FREE",
    placement: str = "api_response",
) -> Dict:
    """
    Inject affiliate links and upgrade CTAs into API response dict.
    Returns new dict with affiliate_links key added (never mutates source).
    """
    import copy
    enriched = copy.deepcopy(response)

    # Collect all tags across returned items
    all_tags: List[str] = []
    for item in intel_items[:10]:
        all_tags.extend(_extract_content_tags(item))

    matched = match_affiliates(all_tags, tier=tier, max_affiliates=2)

    affiliate_links = []
    for m in matched:
        partner = m["partner"]
        utm_url = build_utm_url(
            base_url=partner["base_url"],
            campaign=",".join(m["overlap"][:2]),
            content=placement,
            referral_id=partner.get("referral_id", ""),
        )
        affiliate_links.append({
            "partner":      partner["name"],
            "url":          utm_url,
            "cta":          partner["cta_text"],
            "price":        partner["monthly_price"],
            "relevance":    m["overlap"][:3],
            "category":     partner["category"],
        })
        _log_injection(partner_id=m["partner_id"], placement=placement, tier=tier)

    # Internal upgrade CTA
    if tier == "FREE":
        enriched["upgrade_cta"] = INTERNAL_CTAs["free_to_pro"]
    elif tier == "PRO":
        enriched["upgrade_cta"] = INTERNAL_CTAs["pro_to_enterprise"]

    if affiliate_links:
        enriched["sponsored_tools"] = {
            "label":   "Recommended Security Tools",
            "note":    "Contextually matched to this threat intelligence",
            "tools":   affiliate_links,
            "disclosure": "CYBERDUDEBIVASH may receive a commission on qualifying purchases.",
        }

    return enriched


def inject_into_telegram_message(
    message: str,
    tags: List[str],
    tier: str = "FREE",
    max_affiliates: int = 1,
) -> str:
    """
    Append affiliate link to Telegram message text.
    Returns modified message string.
    Limits to 1 affiliate to avoid message clutter.
    """
    matched = match_affiliates(tags, tier=tier, max_affiliates=max_affiliates)
    if not matched:
        return message

    partner = matched[0]["partner"]
    utm_url = build_utm_url(
        base_url=partner["base_url"],
        campaign=",".join(matched[0]["overlap"][:2]),
        content="telegram",
        referral_id=partner.get("referral_id", ""),
    )

    affiliate_line = f"\n\n🔧 *Tool Recommendation:* [{partner['cta_text']}]({utm_url}) _{partner['monthly_price']}_"
    _log_injection(partner_id=matched[0]["partner_id"], placement="telegram", tier=tier)
    return message + affiliate_line


def inject_into_report_section(
    tags: List[str],
    section: str = "recommendations",
    tier: str = "PRO",
) -> List[Dict]:
    """
    Generate affiliate recommendation list for PDF/HTML report insertion.
    Returns list of tool recommendation dicts with full metadata.
    """
    matched = match_affiliates(tags, tier=tier, max_affiliates=3)
    recommendations = []

    for m in matched:
        partner = m["partner"]
        utm_url = build_utm_url(
            base_url=partner["base_url"],
            campaign=f"report_{section}",
            content="pdf_report",
            referral_id=partner.get("referral_id", ""),
        )
        recommendations.append({
            "name":        partner["name"],
            "url":         utm_url,
            "description": partner["cta_text"],
            "price":       partner["monthly_price"],
            "category":    partner["category"],
            "relevance":   m["overlap"][:3],
        })
        _log_injection(partner_id=m["partner_id"], placement=f"report_{section}", tier=tier)

    return recommendations


def generate_partner_referral_code(
    partner_email: str,
    tier: str = "MSSP",
    commission_rate: float = 0.20,
) -> Dict:
    """
    Generate a referral code for MSSP partners who refer customers.
    Commission: 20% of referred customer MRR (monthly recurring revenue).
    """
    raw = f"{partner_email.lower()}:{tier}:{int(time.time() // 86400)}"
    code = "CDB-" + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()

    record = {
        "referral_code":    code,
        "partner_email":    partner_email,
        "tier":             tier,
        "commission_rate":  commission_rate,
        "referral_url":     f"https://intel.cyberdudebivash.com/get-api-key.html?ref={code}&utm_source=partner&utm_medium=referral",
        "created_at":       datetime.now(timezone.utc).isoformat(),
        "estimated_commission": f"{commission_rate * 100:.0f}% of referred MRR",
        "note":             "Share this link with your clients. Commission tracked automatically.",
    }

    # Persist to referral registry
    _save_referral_code(record)
    return record


def _save_referral_code(record: Dict) -> None:
    ref_file = BASE_DIR / "data" / "affiliate_referral_codes.json"
    try:
        existing = {}
        if ref_file.exists():
            existing = json.loads(ref_file.read_text(encoding="utf-8"))
        existing[record["referral_code"]] = record
        tmp = ref_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ref_file)
    except Exception as e:
        logger.warning(f"Referral code save failed: {e}")


# ---------------------------------------------------------------------------
# Click / Injection Logging
# ---------------------------------------------------------------------------

def _log_injection(partner_id: str, placement: str, tier: str) -> None:
    """Append-only log of affiliate link injections for reporting."""
    try:
        INJECT_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts":         datetime.now(timezone.utc).isoformat(),
            "partner_id": partner_id,
            "placement":  placement,
            "tier":       tier,
        }
        with open(INJECT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def log_click(partner_id: str, placement: str, referrer: str = "") -> None:
    """Log a click event (called from web API click-tracking endpoint)."""
    try:
        CLICK_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts":         datetime.now(timezone.utc).isoformat(),
            "partner_id": partner_id,
            "placement":  placement,
            "referrer":   referrer[:100],
        }
        with open(CLICK_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Revenue Analytics
# ---------------------------------------------------------------------------

def get_affiliate_stats() -> Dict:
    """Return injection and click stats for reporting."""
    stats: Dict[str, Any] = {
        "injections": {},
        "clicks": {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    for log_file, key in [(INJECT_LOG, "injections"), (CLICK_LOG, "clicks")]:
        if not log_file.exists():
            continue
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    pid = entry.get("partner_id", "unknown")
                    bucket = stats[key]
                    bucket[pid] = bucket.get(pid, 0) + 1
        except Exception as e:
            logger.warning(f"Stats read error ({key}): {e}")

    stats["estimated_cpa_revenue_usd"] = sum(
        AFFILIATE_PARTNERS.get(pid, {}).get("cpa_usd", 0) * count * 0.01  # assume 1% conversion
        for pid, count in stats["injections"].items()
    )

    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, sys

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — Affiliate Revenue Injector",
    )
    parser.add_argument("--stats",    action="store_true", help="Show affiliate injection stats")
    parser.add_argument("--partners", action="store_true", help="List all affiliate partners")
    parser.add_argument("--referral", type=str, help="Generate referral code for partner email")
    parser.add_argument("--tier",     type=str, default="MSSP")
    parser.add_argument("--tags",     type=str, help="Comma-separated tags for match test")
    args = parser.parse_args()

    if args.stats:
        print(json.dumps(get_affiliate_stats(), ensure_ascii=False, indent=2, default=str))
    elif args.partners:
        for pid, p in AFFILIATE_PARTNERS.items():
            print(f"  {pid}: {p['name']} | CPA=${p['cpa_usd']} | {p['monthly_price']}")
    elif args.referral:
        code = generate_partner_referral_code(args.referral, tier=args.tier)
        print(json.dumps(code, indent=2, ensure_ascii=False))
    elif args.tags:
        tags = [t.strip() for t in args.tags.split(",")]
        matched = match_affiliates(tags, tier="PRO", max_affiliates=5)
        for m in matched:
            print(f"  {m['partner']['name']} | score={m['score']} | overlap={m['overlap']}")
    else:
        parser.print_help()
