
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : CVE-2026-30920 - OneUptime has broken access control in GitHub App installation flow that allows unauthorized project binding
STIX ID : bundle--5df3e4ec-bcf2-46df-8466-c5c082f67307
SCENARIO: VULNERABILITY
RISK    : 4.2/10  |  SEVERITY: MEDIUM  |  TLP: TLP:GREEN
CVEs    : None identified
IOCs    : cve: 1
REPORT  : https://blog.cyberdudebivash.com/2026/03/cve-2026-30920-oneuptime-has-broken.html
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
