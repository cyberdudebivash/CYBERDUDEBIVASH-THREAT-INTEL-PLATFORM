
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : How to manage the lifecycle of Amazon Machine Images using AMI Lineage for AWS
STIX ID : bundle--072217dd-e500-48f4-9ef0-bc7e85c4db37
SCENARIO: GENERIC
RISK    : 10.0/10  |  SEVERITY: CRITICAL  |  TLP: TLP:RED
CVEs    : None identified
IOCs    : domain: 8 | url: 4 | artifacts: 1
REPORT  : https://blog.cyberdudebivash.com/2026/03/how-to-manage-lifecycle-of-amazon_0363747064.html
PLATFORM: https://intel.cyberdudebivash.com

PACK CONTENTS
─────────────
  ioc_feed.csv          IOC indicators (IPs, domains, hashes, CVEs)
  detection_sigma.yml   Sigma rules — real IOC + scenario-specific behavioral
  detection_yara.yar    YARA rules — file/memory/EDR scanning
  detection_kql.txt     Microsoft Sentinel KQL Analytics queries
  detection_spl.txt     Splunk SPL Correlation Search queries
  metadata.json         CVSS, EPSS, KEV, MITRE, TLP metadata
  README.txt            This file

DEPLOYMENT
──────────
  Sigma → sigma-cli: sigma convert -t splunk detection_sigma.yml
  YARA  → EDR (CrowdStrike, Defender ATP, Carbon Black)
  KQL   → Sentinel → Analytics → + Create → Scheduled Query
  SPL   → Splunk ES → Correlation Searches → New

OPERATOR NOTES
──────────────
  1. Block all IPs/domains from ioc_feed.csv at perimeter firewall
  2. Import Sigma via sigma-cli or Uncoder.io for your SIEM
  3. Deploy YARA in EDR for real-time and retro file scanning
  4. Run KQL/SPL for 90-day retrospective threat hunt
  5. Check metadata.json for CVSS/EPSS to prioritize patches

LICENSE  Enterprise Defensive Use Only
SUPPORT  bivash@cyberdudebivash.com | +91 8179881447
