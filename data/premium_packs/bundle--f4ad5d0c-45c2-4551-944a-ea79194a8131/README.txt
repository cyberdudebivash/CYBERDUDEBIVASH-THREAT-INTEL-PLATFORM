
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : Microsoft seizes 338 websites to disrupt rapidly growing ‘RaccoonO365’ phishing service
STIX ID : bundle--f4ad5d0c-45c2-4551-944a-ea79194a8131
SCENARIO: PHISHING
RISK    : 10.0/10  |  SEVERITY: CRITICAL  |  TLP: TLP:RED
CVEs    : None identified
IOCs    : See ioc_feed.csv
REPORT  : https://blog.cyberdudebivash.com/2026/03/microsoft-seizes-338-websites-to_01403223917.html
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
