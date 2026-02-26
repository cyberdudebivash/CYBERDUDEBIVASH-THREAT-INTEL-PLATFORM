
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : CVE-2026-27963 - Audiobookshelf has Stored XSS in Tooltip.vue via Audiobook Metadata
STIX ID : bundle--6435844f-633b-48a8-b2c7-845f3f8ff98a
SCENARIO: XSS
RISK    : 5.3/10  |  SEVERITY: MEDIUM  |  TLP: TLP:GREEN
CVEs    : None identified
IOCs    : cve: 1
REPORT  : https://cyberbivash.blogspot.com/2026/02/cve-2026-27963-audiobookshelf-has.html
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
