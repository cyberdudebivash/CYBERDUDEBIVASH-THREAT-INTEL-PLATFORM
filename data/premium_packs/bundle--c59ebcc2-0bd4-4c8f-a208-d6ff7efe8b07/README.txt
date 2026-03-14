
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : Google fixed two new actively exploited flaws in the Chrome browser
STIX ID : bundle--c59ebcc2-0bd4-4c8f-a208-d6ff7efe8b07
SCENARIO: GENERIC
RISK    : 10.0/10  |  SEVERITY: CRITICAL  |  TLP: TLP:RED
CVEs    : None identified
IOCs    : cve: 3
REPORT  : https://blog.cyberdudebivash.com/2026/03/google-fixed-two-new-actively-exploited_01870795060.html
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
