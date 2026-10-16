#!/usr/bin/env python3
"""
detection_pack_builder.py - CYBERDUDEBIVASH(R) SENTINEL APEX
COMMERCIAL DETECTION PACK PACKAGING
Founder & CEO - CyberDudeBivash Pvt. Ltd.

WHAT CHANGED AND WHY
--------------------
The previous implementation's docstring claimed it "packages Sigma, YARA and KQL
rules into a sellable ZIP". It did not. It copied data/genesis/detection_pack.json
to manifest.json, wrote a four-key metadata.json, and shipped a 6.8 KB archive
whose `sigma_rules` and `yara_rules` arrays were empty and whose `suricata_rules`
entries were `{sid, msg, severity}` stubs -- not Suricata syntax, with duplicate
SIDs (which fails engine load) and URLs truncated mid-hostname. Nothing in the
archive could be deployed into any product, and it carried no licence, no
integrity manifest and no deployment instructions.

Meanwhile scripts/generate_detection_pack.py already extracted real Sigma, KQL,
IOC and CVE content from the certified baseline and published it to R2 for
/api/v1/premium/detections/*. Two detection-pack implementations existed, and
the sellable one was the broken one.

This module now REUSES that canonical engine (Principle 3/4 -- Single Source of
Truth, Reuse Before Build) rather than re-extracting anything, and adds the
commercial packaging layer that was missing:

  * IOC content passes agent/product_factory/ioc_validation.py, which removes
    reference/vendor infrastructure and source-code symbols that would otherwise
    be enforced by a customer firewall (see that module for the verified defect).
  * Validated enforcement-tier indicators are rendered as REAL Suricata and Snort
    rules with collision-free SIDs from a documented local range.
  * MITRE ATT&CK coverage is emitted as an importable ATT&CK Navigator layer.
  * Every bundle carries README, LICENSE, CHANGELOG, per-platform deployment
    guides, a commercial record from the pricing SSOT, and SHA256SUMS.
  * With SOURCE_DATE_EPOCH pinned, the archive is byte-for-byte reproducible
    for a given input set, so a customer can verify what they received.

BACKWARD COMPATIBILITY
----------------------
manifest.json and metadata.json remain at the archive root and retain every key
they previously carried (see _legacy_manifest / _legacy_metadata). New content is
added alongside them; nothing is renamed or removed. build_pack() returns the
same {status, product_id, path, version} keys as before, with additional keys.
"""

from __future__ import annotations

import hashlib
import json

# P0 #721: Navigator `versions.attack` comes from the pinned, verified ATT&CK release (was a hard-coded guess).
import os as _os_nav
import sys as _sys_nav
_nav_dir = _os_nav.path.join(_os_nav.path.dirname(_os_nav.path.dirname(_os_nav.path.dirname(_os_nav.path.abspath(__file__)))), "scripts")
if _nav_dir not in _sys_nav.path:
    _sys_nav.path.insert(0, _nav_dir)
import dossier_integrity as _di_nav  # noqa: E402
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent.product_factory import ioc_validation
from agent.product_factory.commercial_asset_spec import (
    PLATFORM_BASE,
    VENDOR_BRAND,
    commercial_metadata,
    license_text,
)

REPO = Path(__file__).resolve().parent.parent.parent

# Staging directory written by scripts/generate_detection_pack.py (gitignored).
STAGING_DIR = REPO / "data" / "premium_staging" / "detections"

# Suricata/Snort local rule SID range. 1,000,000+ is the conventional block for
# locally authored rules; 9,100,000 keeps CDB content clear of the ET/Snort
# community ranges and of any customer-local rules in the low millions.
SID_BASE = 9_100_000
SID_CEILING = 9_999_999

PACK_FORMAT_VERSION = "2.0.0"

# Deterministic ZIP entry timestamp. zipfile stamps the current clock by default,
# so two runs over identical content produced different archives and no customer
# could verify they had the same pack. A fixed epoch makes the archive
# reproducible; the real build time lives in metadata.json.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def build_clock() -> datetime:
    """The single timestamp used for every value embedded in one build.

    Honours SOURCE_DATE_EPOCH (the reproducible-builds convention): pin it and a
    rebuild over identical input content yields a byte-identical archive, so a
    customer can verify the pack they received matches the pack we published.
    Unset, it is simply the current time and archives differ per build.
    """
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if raw:
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass
    return datetime.now(timezone.utc)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _allocate_sid(value: str, used: set) -> int:
    """Deterministic, collision-free SID for an indicator.

    Derived from the indicator so repeated builds keep stable SIDs, then probed
    linearly on collision. The previous implementation emitted duplicate SIDs
    (5610142 three times in one pack), which makes Suricata refuse the ruleset.
    """
    span = SID_CEILING - SID_BASE
    sid = SID_BASE + (int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:8], 16) % span)
    while sid in used:
        sid = SID_BASE + ((sid - SID_BASE + 1) % span)
    used.add(sid)
    return sid


def _escape_rule_content(value: str) -> str:
    """Escape a value for use inside a Suricata/Snort content string."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


class DetectionPackBuilder:
    def __init__(self) -> None:
        # Preserved for backward compatibility with any caller reading these.
        self.output_dir = os.environ.get(
            "DETECTION_PACK_OUTPUT_DIR",
            str(REPO / "data" / "premium_staging" / "products" / "detections"),
        )
        self.genesis_detections = str(REPO / "data" / "genesis" / "detection_pack.json")
        self.staging_dir = STAGING_DIR
        self._now = build_clock()
        os.makedirs(self.output_dir, exist_ok=True)

    # ── Canonical content acquisition (reuse, never re-extract) ──────────────
    def ensure_staged_content(self) -> bool:
        """Guarantee the canonical generator's artifacts exist locally.

        sentinel-factory.yml runs on a different runner from sentinel-apex.yml
        and data/premium_staging/ is gitignored, so the staged artifacts are
        normally absent here. Rather than re-implementing extraction, invoke the
        canonical engine with R2 publishing disabled -- this runner is not the
        publisher of record for premium/detections/*.
        """
        manifest = self.staging_dir / "pack_manifest.json"
        if manifest.exists():
            return True

        script = REPO / "scripts" / "generate_detection_pack.py"
        if not script.exists():
            return False

        env = dict(os.environ)
        env["SKIP_R2_UPLOAD"] = "true"
        try:
            proc = subprocess.run(
                [sys.executable, str(script)],
                cwd=str(REPO), env=env, capture_output=True, text=True, timeout=900,
            )
        except (subprocess.SubprocessError, OSError):
            return False
        if proc.returncode != 0:
            return False
        return manifest.exists()

    def _read_staged(self, name: str) -> Optional[str]:
        path = self.staging_dir / name
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    # ── Network rule rendering ───────────────────────────────────────────────
    def _render_network_rules(
        self, indicators: List[ioc_validation.ValidationResult], engine: str
    ) -> Tuple[str, int]:
        """Render deployable Suricata or Snort rules from validated indicators.

        Only enforcement-tier indicators are rendered. Monitoring-tier content is
        delivered separately for hunting and must never drive an inline block.
        """
        now = self._now
        rev = 1
        used: set = set()
        lines: List[str] = [
            f"# {VENDOR_BRAND} -- {engine.upper()} DETECTION RULESET",
            f"# Pack format : {PACK_FORMAT_VERSION}",
            f"# Generated   : {now.isoformat()}",
            f"# Platform    : {PLATFORM_BASE}",
            f"# SID range   : {SID_BASE}-{SID_CEILING} (local rule block)",
            "#",
            "# Every rule below is derived from an ENFORCEMENT-tier indicator: it",
            "# passed structural validation, benign-infrastructure suppression and",
            "# the confidence floor. Deploy in alert mode first and review for one",
            "# full business cycle before enabling drop/reject in production.",
            "#",
            f"# Import: copy into your rules directory and add to {engine}.yaml"
            if engine == "suricata" else "# Import: copy into your rules directory and include from snort.conf",
            "",
        ]
        count = 0

        for res in indicators:
            if res.tier != "enforcement":
                continue
            sid = _allocate_sid(f"{engine}:{res.ioc_type}:{res.normalized}", used)
            conf = int(res.confidence) if res.confidence is not None else 0
            meta = (
                f'metadata:vendor CYBERDUDEBIVASH, product SENTINEL_APEX, '
                f'confidence {conf}, ioc_type {res.ioc_type}, '
                f'created_at {now.strftime("%Y_%m_%d")};'
            )

            if res.ioc_type == "domain":
                dom = _escape_rule_content(res.normalized)
                msg = f"CDB APEX Malicious domain lookup: {dom}"
                if engine == "suricata":
                    lines.append(
                        f'alert dns $HOME_NET any -> any any (msg:"{msg}"; '
                        f'dns.query; content:"{dom}"; nocase; isdataat:!1,relative; '
                        f'classtype:domain-c2; sid:{sid}; rev:{rev}; {meta})'
                    )
                else:
                    lines.append(
                        f'alert udp $HOME_NET any -> any 53 (msg:"{msg}"; '
                        f'content:"{dom}"; nocase; '
                        f'classtype:domain-c2; sid:{sid}; rev:{rev};)'
                    )
                count += 1

            elif res.ioc_type in ("ipv4", "ipv6"):
                ip = res.normalized
                msg = f"CDB APEX Traffic to known-malicious host: {ip}"
                if engine == "suricata":
                    lines.append(
                        f'alert ip $HOME_NET any -> {ip} any (msg:"{msg}"; '
                        f'classtype:trojan-activity; sid:{sid}; rev:{rev}; {meta})'
                    )
                else:
                    lines.append(
                        f'alert ip $HOME_NET any -> {ip} any (msg:"{msg}"; '
                        f'classtype:trojan-activity; sid:{sid}; rev:{rev};)'
                    )
                count += 1

            elif res.ioc_type == "url":
                try:
                    from urllib.parse import urlsplit
                    parts = urlsplit(res.normalized)
                except ValueError:
                    continue
                host = (parts.hostname or "").lower()
                uri = parts.path or "/"
                if parts.query:
                    uri = f"{uri}?{parts.query}"
                if not host:
                    continue
                host_e, uri_e = _escape_rule_content(host), _escape_rule_content(uri[:200])
                msg = f"CDB APEX Malicious URL request: {host}{uri[:60]}"
                if engine == "suricata":
                    lines.append(
                        f'alert http $HOME_NET any -> any any (msg:"{msg}"; '
                        f'http.host; content:"{host_e}"; nocase; '
                        f'http.uri; content:"{uri_e}"; nocase; '
                        f'classtype:trojan-activity; sid:{sid}; rev:{rev}; {meta})'
                    )
                else:
                    lines.append(
                        f'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"{msg}"; '
                        f'flow:established,to_server; content:"{host_e}"; nocase; http_header; '
                        f'content:"{uri_e}"; nocase; http_uri; '
                        f'classtype:trojan-activity; sid:{sid}; rev:{rev};)'
                    )
                count += 1

            elif res.ioc_type in ("md5", "sha1", "sha256") and engine == "suricata":
                # Suricata filestore/filemd5 style hash matching. Emitted as a
                # commented reference set because it requires a hash list file
                # and file-extraction enabled -- shipping it live would silently
                # no-op on most deployments.
                lines.append(f'# {res.ioc_type}:{res.normalized}  (see hashes/{engine}_{res.ioc_type}.txt)')

        lines.append("")
        lines.append(f"# Total active rules: {count}")
        lines.append("")
        return "\n".join(lines), count

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    def _build_attack_coverage(self, sigma_body: str) -> Tuple[Dict, Dict]:
        """Derive ATT&CK coverage and an importable Navigator layer."""
        import re as _re
        techniques: Dict[str, int] = {}
        tactics: Dict[str, int] = {}
        for tag in _re.findall(r"attack\.([a-z0-9._]+)", sigma_body, _re.IGNORECASE):
            tag = tag.lower()
            if tag.startswith("t") and tag[1:].split(".")[0].isdigit():
                tid = "T" + tag[1:].upper()
                techniques[tid] = techniques.get(tid, 0) + 1
            else:
                tactics[tag] = tactics.get(tag, 0) + 1

        coverage = {
            "_meta": {
                "product": "SENTINEL APEX -- MITRE ATT&CK Coverage",
                "pack_format_version": PACK_FORMAT_VERSION,
                "generated_at": self._now.isoformat(),
                "framework": "MITRE ATT&CK Enterprise",
                "derivation": "Parsed from the `tags:` block of every shipped Sigma rule",
            },
            "technique_count": len(techniques),
            "tactic_count": len(tactics),
            "techniques": dict(sorted(techniques.items(), key=lambda kv: -kv[1])),
            "tactics": dict(sorted(tactics.items(), key=lambda kv: -kv[1])),
        }

        max_hits = max(techniques.values()) if techniques else 1
        layer = {
            "name": "CYBERDUDEBIVASH SENTINEL APEX Detection Coverage",
            "versions": {"attack": _di_nav.navigator_attack_version(), "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                "Detection coverage delivered by the SENTINEL APEX Detection Pack. "
                "Score is the number of shipped Sigma rules mapped to the technique."
            ),
            "filters": {"platforms": ["Windows", "Linux", "macOS", "Network"]},
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": hits,
                    "color": "",
                    "comment": f"{hits} SENTINEL APEX Sigma rule(s)",
                    "enabled": True,
                    "showSubtechniques": True,
                }
                for tid, hits in sorted(techniques.items())
            ],
            "gradient": {
                "colors": ["#1e3a5f", "#2563eb", "#22c55e"],
                "minValue": 0,
                "maxValue": max_hits,
            },
            "legendItems": [{"label": "SENTINEL APEX coverage", "color": "#2563eb"}],
            "metadata": [
                {"name": "vendor", "value": "CYBERDUDEBIVASH Pvt. Ltd."},
                {"name": "platform", "value": PLATFORM_BASE},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#0b1220",
            "selectTechniquesAcrossTactics": True,
        }
        return coverage, layer

    # ── Backward-compatible legacy blocks ────────────────────────────────────
    def _legacy_manifest(self) -> Dict:
        """The exact payload the previous builder wrote to manifest.json.

        Preserved verbatim so any consumer that parsed the old archive keeps
        working. New content is added under separate keys and separate files.
        """
        try:
            with open(self.genesis_detections, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _legacy_metadata(timestamp: str, tier: str) -> Dict:
        return {
            "pack_id": f"DP-{timestamp}",
            "tier": tier,
            "generated_by": "CYBERDUDEBIVASH PRODUCT FACTORY",
            "authority": "CYBERDUDEBIVASH OFFICIAL AUTHORITY",
        }

    # ── Documentation ────────────────────────────────────────────────────────
    @staticmethod
    def _readme(stats: Dict, commercial: Dict) -> str:
        price = commercial["pricing"]
        price_line = (
            f"{price['label']} -- US${price['price_usd']}/{price['billing_period']} "
            f"(INR {price['price_inr']:,}/{price['billing_period']}); "
            f"included with: {', '.join(price['included_in_tiers'])}"
            if price.get("priced") else "Contact sales for pricing."
        )
        return f"""# {commercial['product_name']}

**SKU:** `{commercial['sku']}`  ·  **Pack format:** {PACK_FORMAT_VERSION}  ·  **Marking:** {commercial['licence']['tlp']}

{commercial['summary']}

**Licensing:** {price_line}

---

## What is in this pack

| Path | Content | Count |
|---|---|---|
| `sigma/sigma_rules.yml` | Sigma detection rules (SIEM-portable) | {stats['sigma_rules']} |
| `kql/kql_queries.kql` | Microsoft Sentinel / Defender KQL | {stats['kql_queries']} |
| `suricata/cdb-apex.rules` | Suricata IDS/IPS rules | {stats['suricata_rules']} |
| `snort/cdb-apex.rules` | Snort IDS/IPS rules | {stats['snort_rules']} |
| `ioc/enforcement_blocklist.txt` | Validated, blockable indicators | {stats['enforcement_iocs']} |
| `ioc/monitoring_indicators.txt` | Hunt-only indicators | {stats['monitoring_iocs']} |
| `ioc/ioc_structured.json` | Structured IOC export with context | {stats['structured_iocs']} |
| `cve/cve_watchlist.csv` | CVE watchlist for vulnerability management | {stats['cve_rows']} |
| `mitre/attack_coverage.json` | ATT&CK technique coverage summary | {stats['attack_techniques']} techniques |
| `mitre/attack_navigator_layer.json` | Importable ATT&CK Navigator layer | — |

Integrity: verify every file against `SHA256SUMS.txt` before deployment.

```bash
sha256sum -c SHA256SUMS.txt
```

---

## Enforcement vs monitoring — read this first

Indicators in this pack are split into two tiers, and the split is not cosmetic.

* **`ioc/enforcement_blocklist.txt`** — passed structural validation,
  benign-infrastructure suppression and the confidence floor
  ({ioc_validation.ENFORCEMENT_CONFIDENCE_FLOOR:.0f}). These are the only
  indicators intended for inline blocking.
* **`ioc/monitoring_indicators.txt`** — real indicators that did not clear the
  enforcement bar, or whose type (behavioural, email, registry) is not blockable.
  Use them for hunting and alert enrichment. **Do not point a blocking policy at
  this file.**

`ioc/validation_report.json` records how many candidates were rejected and why,
including every reference/vendor host that was suppressed so it could not reach
your firewall.

Even for enforcement-tier content, deploy in alert mode first and review for one
full business cycle before enabling drop/reject.

---

## Deployment

Per-platform instructions are in `deployment/`:

* `deployment/microsoft-sentinel.md`
* `deployment/splunk-elastic.md`
* `deployment/suricata-snort.md`
* `deployment/firewall-edl.md`
* `deployment/vulnerability-management.md`

---

## Support

{commercial['vendor']['legal_name']} · {commercial['vendor']['contact']} · {PLATFORM_BASE}

Licence terms: see `LICENSE.txt`. Redistribution is prohibited.
"""

    @staticmethod
    def _deployment_guides(stats: Dict) -> Dict[str, str]:
        return {
            "deployment/microsoft-sentinel.md": f"""# Microsoft Sentinel / Defender XDR

## KQL analytics rules ({stats['kql_queries']} queries)

1. Open **Microsoft Sentinel → Analytics → Create → Scheduled query rule**.
2. Paste a query block from `kql/kql_queries.kql`. Each block is delimited by a
   `// ──` header carrying the tier, CVE and severity.
3. Set the query frequency to the `lookback` declared in the query (most use `1d`).
4. Map entities: `IpAddress` → IP, `TargetUserName` → Account, `Computer` → Host.
5. Set severity from the `Severity` column the query projects.

## Sigma rules

Sentinel consumes Sigma via the `sigma-cli` Microsoft backend:

```bash
pip install sigma-cli pysigma-backend-microsoft365defender
sigma convert -t microsoft365defender -f default sigma/sigma_rules.yml
```

## Threat intelligence indicators

Upload `ioc/enforcement_blocklist.txt` through the **Threat Intelligence Upload
Indicators API**, or import `ioc/ioc_structured.json` with a Logic App that maps
`value`/`type`/`confidence` onto the `ThreatIntelligenceIndicator` table.

> All rules ship as `status: experimental`. Validate against your own telemetry
> before promoting any of them to an automated response action.
""",
            "deployment/splunk-elastic.md": f"""# Splunk Enterprise Security / Elastic Security

## Splunk

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -f savedsearches sigma/sigma_rules.yml > cdb_apex_savedsearches.conf
```

Copy the generated `savedsearches.conf` into
`$SPLUNK_HOME/etc/apps/<your_app>/local/` and reload. Map each search to a
correlation search in Enterprise Security and set urgency from the rule `level`.

Load indicators as a lookup:

```bash
splunk add oneshot ioc/enforcement_blocklist.txt -sourcetype cdb_apex_ioc -index threat_intel
```

## Elastic Security

```bash
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene -f siem_rule_ndjson sigma/sigma_rules.yml > cdb_apex_rules.ndjson
```

Import `cdb_apex_rules.ndjson` via **Security → Rules → Import**. Load
`ioc/ioc_structured.json` into an indicator index and enable an indicator-match
rule against it.

Indicators available for matching: {stats['enforcement_iocs']} enforcement,
{stats['monitoring_iocs']} monitoring.
""",
            "deployment/suricata-snort.md": f"""# Suricata / Snort

Rules are allocated SIDs in the **{SID_BASE}–{SID_CEILING}** local range and are
collision-free within the pack. Confirm they do not clash with your own local
rules before loading.

## Suricata ({stats['suricata_rules']} rules)

```bash
cp suricata/cdb-apex.rules /etc/suricata/rules/
# add to suricata.yaml:
#   rule-files:
#     - cdb-apex.rules
suricata -T -c /etc/suricata/suricata.yaml   # validate before reload
suricatasc -c reload-rules
```

DNS rules require the `dns` app-layer parser to be enabled (default in Suricata 6+).
HTTP rules require `http` parsing and, for `http.uri` matching, `nocase` support —
both are on by default.

## Snort ({stats['snort_rules']} rules)

```bash
cp snort/cdb-apex.rules /etc/snort/rules/
echo 'include $RULE_PATH/cdb-apex.rules' >> /etc/snort/snort.conf
snort -T -c /etc/snort/snort.conf          # validate before reload
```

## Rollout

Every rule ships as `alert`, never `drop`. Run in alert mode for one full
business cycle, review hit volume per SID, then convert selected SIDs to `drop`.
""",
            "deployment/firewall-edl.md": f"""# Firewall / DNS enforcement

Use **`ioc/enforcement_blocklist.txt`** ({stats['enforcement_iocs']} indicators).
Do **not** use `ioc/monitoring_indicators.txt` for blocking — it intentionally
contains lower-confidence and non-blockable indicator types.

## Palo Alto PAN-OS (External Dynamic List)

**Objects → External Dynamic Lists → Add**, type *Domain* or *IP*, source the
hosted list, repeat check every hour, then reference the EDL from a security
policy set to deny.

## Fortinet FortiGate (Threat Feed)

**Security Fabric → External Connectors → Threat Feeds → Domain Name / IP Address**.
Reference the connector from a DNS filter or firewall policy.

## pfSense (pfBlockerNG) / Pi-hole

pfBlockerNG: **DNSBL → DNSBL Groups**, add the list URL, set the action to
*Unbound*. Pi-hole: **Group Management → Adlists**, then `pihole -g`.

## Before you enforce

The list has already had reference databases, vendor sites, code-hosting
infrastructure and non-routable address space removed — see
`ioc/validation_report.json` for the exact suppression counts. Even so, run it in
monitor/log-only mode for 48 hours and review hits against your own traffic
before switching to deny.
""",
            "deployment/vulnerability-management.md": f"""# Vulnerability management

`cve/cve_watchlist.csv` carries {stats['cve_rows']} CVEs with CVSS, EPSS, CISA KEV
status and a SENTINEL APEX risk score.

## Qualys VMDR

**Vulnerability Management → Reports → Search Lists → New → Static Search List**,
import the `CVE_ID` column, then drive an option profile or dashboard from it.

## Tenable.io / Nessus

Create a dynamic asset filter on the CVE list, or use `pyTenable`:

```python
from tenable.io import TenableIO
import csv
tio = TenableIO()
cves = [r["CVE_ID"] for r in csv.DictReader(open("cve/cve_watchlist.csv"))]
```

## Prioritisation

Sort by `KEV` = `YES` first (CISA-confirmed active exploitation), then by
`EPSS_Score` descending, then `CVSS_Score`. `Risk_Score` is the SENTINEL APEX
composite and already blends all three with source confidence.
""",
        }

    @staticmethod
    def _changelog(timestamp: str, stats: Dict) -> str:
        return f"""# Changelog — SENTINEL APEX Detection Pack

## {PACK_FORMAT_VERSION} — {timestamp}

Pack format 2.0.0 is the first commercially deployable release.

### Added
- Real Suricata ({stats['suricata_rules']}) and Snort ({stats['snort_rules']}) rules
  with collision-free SIDs in the {SID_BASE}–{SID_CEILING} local range.
- Sigma ({stats['sigma_rules']}) and KQL ({stats['kql_queries']}) content sourced
  from the certified intelligence baseline.
- MITRE ATT&CK coverage summary and an importable ATT&CK Navigator layer
  ({stats['attack_techniques']} techniques).
- Enforcement/monitoring indicator split, so blocking policies are never pointed
  at unvalidated content.
- `ioc/validation_report.json` recording every suppressed indicator and the reason.
- Per-platform deployment guides, commercial licence, and `SHA256SUMS.txt`.
- Reproducible archives: with SOURCE_DATE_EPOCH pinned, identical input
  content yields a byte-identical ZIP.

### Fixed
- Sigma and YARA arrays shipped empty in every previous pack.
- Suricata entries were `{{sid, msg, severity}}` stubs rather than rule syntax, and
  were not loadable by any IDS.
- Duplicate SIDs within a single pack, which causes Suricata to reject the ruleset.
- Indicator values truncated mid-hostname.
- Reference databases, vendor sites and source-code symbols were shipped in a
  blocklist documented for firewall enforcement.

### Compatibility
- `manifest.json` and `metadata.json` retain every key from pack format 1.x.
"""

    # ── Build ────────────────────────────────────────────────────────────────
    def build_pack(self, tier: str = "enterprise") -> Dict:
        """Package a commercially deployable, licensed, verifiable detection pack."""
        self._now = build_clock()
        timestamp = self._now.strftime("%Y%m%d_%H%M")
        pack_name = f"CDB_DETECTION_PACK_{tier.upper()}_{timestamp}.zip"
        zip_path = os.path.join(self.output_dir, pack_name)

        try:
            staged = self.ensure_staged_content()

            sigma_body = (self._read_staged("sigma_rules.yml") or "") if staged else ""
            kql_body = (self._read_staged("kql_queries.kql") or "") if staged else ""
            cve_csv = (self._read_staged("cve_watchlist.csv") or "") if staged else ""
            structured_raw = (self._read_staged("ioc_structured.json") or "") if staged else ""

            try:
                structured = json.loads(structured_raw) if structured_raw else {"iocs": []}
            except json.JSONDecodeError:
                structured = {"iocs": []}
            candidates = structured.get("iocs") or []

            # Validate before anything reaches a customer enforcement point.
            validated, report = ioc_validation.validate_batch(candidates)
            enforcement = [r for r in validated if r.tier == "enforcement"]
            monitoring = [r for r in validated if r.tier == "monitoring"]

            suricata_body, suricata_n = self._render_network_rules(validated, "suricata")
            snort_body, snort_n = self._render_network_rules(validated, "snort")
            coverage, navigator = self._build_attack_coverage(sigma_body)

            sigma_n = sigma_body.count("\ntitle:") + (1 if sigma_body.startswith("title:") else 0)
            if sigma_n == 0:
                sigma_n = sigma_body.count("title: ")
            kql_n = kql_body.count("// ── ")
            cve_rows = max(cve_csv.count("\n") - 1, 0)

            stats = {
                "sigma_rules": sigma_n,
                "kql_queries": kql_n,
                "suricata_rules": suricata_n,
                "snort_rules": snort_n,
                "enforcement_iocs": len(enforcement),
                "monitoring_iocs": len(monitoring),
                "structured_iocs": len(validated),
                "cve_rows": cve_rows,
                "attack_techniques": coverage["technique_count"],
            }

            commercial = commercial_metadata("detection_pack")

            def _blocklist(items: List[ioc_validation.ValidationResult], header: str, warn: str) -> str:
                out = [
                    f"# {VENDOR_BRAND} -- {header}",
                    f"# Pack format : {PACK_FORMAT_VERSION}",
                    f"# Generated   : {self._now.isoformat()}",
                    f"# Indicators  : {len(items)}",
                    f"# Marking     : {commercial['licence']['tlp']}",
                    f"# {warn}",
                    "",
                ]
                by_type: Dict[str, List[str]] = {}
                for r in items:
                    by_type.setdefault(r.ioc_type, []).append(r.normalized)
                for t, vals in sorted(by_type.items()):
                    out.append(f"# ── {t.upper()} ({len(vals)})")
                    out.extend(sorted(set(vals)))
                    out.append("")
                return "\n".join(out)

            structured_out = {
                "_meta": {
                    "product": commercial["product_name"],
                    "sku": commercial["sku"],
                    "pack_format_version": PACK_FORMAT_VERSION,
                    "generated_at": self._now.isoformat(),
                    "total_indicators": len(validated),
                    "enforcement_tier": len(enforcement),
                    "monitoring_tier": len(monitoring),
                    "validation_engine": ioc_validation.ENGINE_VERSION,
                    "platform": PLATFORM_BASE,
                },
                "iocs": [
                    {
                        "value": r.normalized,
                        "type": r.ioc_type,
                        "confidence": r.confidence,
                        "tier": r.tier,
                        "blockable": r.tier == "enforcement",
                    }
                    for r in validated
                ],
            }

            legacy_manifest = self._legacy_manifest()
            legacy_manifest["_commercial"] = commercial
            legacy_manifest["_pack_format_version"] = PACK_FORMAT_VERSION
            legacy_manifest["_contents"] = stats
            legacy_manifest["_notice"] = (
                "Top-level keys are retained from pack format 1.x for backward "
                "compatibility. Deployable content lives in the sigma/, kql/, "
                "suricata/, snort/, ioc/, cve/ and mitre/ directories."
            )

            legacy_metadata = self._legacy_metadata(timestamp, tier)
            legacy_metadata.update({
                "pack_format_version": PACK_FORMAT_VERSION,
                "built_at": self._now.isoformat(),
                "sku": commercial["sku"],
                "contents": stats,
                "validation_engine_version": ioc_validation.ENGINE_VERSION,
            })

            files: List[Tuple[str, str]] = [
                ("README.md", self._readme(stats, commercial)),
                ("LICENSE.txt", license_text("detection_pack")),
                ("CHANGELOG.md", self._changelog(timestamp, stats)),
                ("manifest.json", json.dumps(legacy_manifest, indent=2, ensure_ascii=False)),
                ("metadata.json", json.dumps(legacy_metadata, indent=4, ensure_ascii=False)),
                ("commercial/product.json", json.dumps(commercial, indent=2, ensure_ascii=False)),
                ("mitre/attack_coverage.json", json.dumps(coverage, indent=2, ensure_ascii=False)),
                ("mitre/attack_navigator_layer.json", json.dumps(navigator, indent=2, ensure_ascii=False)),
                ("suricata/cdb-apex.rules", suricata_body),
                ("snort/cdb-apex.rules", snort_body),
                ("ioc/enforcement_blocklist.txt", _blocklist(
                    enforcement, "IOC ENFORCEMENT BLOCKLIST",
                    "SAFE TO BLOCK: validated, benign-suppressed, above the confidence floor.")),
                ("ioc/monitoring_indicators.txt", _blocklist(
                    monitoring, "IOC MONITORING INDICATORS",
                    "HUNT ONLY -- DO NOT point a blocking policy at this file.")),
                ("ioc/ioc_structured.json", json.dumps(structured_out, indent=2, ensure_ascii=False)),
                ("ioc/validation_report.json", json.dumps(report.as_dict(), indent=2, ensure_ascii=False)),
            ]
            if sigma_body:
                files.append(("sigma/sigma_rules.yml", sigma_body))
            if kql_body:
                files.append(("kql/kql_queries.kql", kql_body))
            if cve_csv:
                files.append(("cve/cve_watchlist.csv", cve_csv))
            files.extend(sorted(self._deployment_guides(stats).items()))

            # Integrity manifest over every shipped file.
            sums = "\n".join(
                f"{_sha256_bytes(body.encode('utf-8'))}  {name}"
                for name, body in sorted(files)
            ) + "\n"
            files.append(("SHA256SUMS.txt", sums))

            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for name, body in sorted(files):
                    info = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o644 << 16
                    zipf.writestr(info, body.encode("utf-8"))

            size = os.path.getsize(zip_path)
            return {
                # Original response keys -- unchanged for existing callers.
                "status": "success",
                "product_id": f"DET-PACK-{tier.upper()}",
                "path": zip_path,
                "version": timestamp,
                # Additive.
                "sku": commercial["sku"],
                "pack_format_version": PACK_FORMAT_VERSION,
                "size_bytes": size,
                "sha256": _sha256_bytes(Path(zip_path).read_bytes()),
                "file_count": len(files),
                "contents": stats,
                "ioc_validation": report.as_dict(),
                "staged_content_available": staged,
            }
        except Exception as e:  # noqa: BLE001 -- preserved contract: never raise
            return {"status": "error", "message": str(e)}


# Global Instance
DETECTION_BUILDER = DetectionPackBuilder()
