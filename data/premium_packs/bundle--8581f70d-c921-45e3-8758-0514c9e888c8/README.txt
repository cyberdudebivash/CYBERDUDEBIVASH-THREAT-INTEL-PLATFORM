
CyberDudeBivash SENTINEL APEX v20.0 — Detection Pack
======================================================

THREAT  : Important: Red Hat Security Advisory: kpatch-patch-4_18_0-477_107_1, kpatch-patch-4_18_0-477_120_1, kpatch-patch-4_18_0-477_81_1, kpatch-patch-4_18_0-477_89_1, and kpatch-patch-4_18_0-477_97_1 security update
STIX ID : bundle--8581f70d-c921-45e3-8758-0514c9e888c8
SCENARIO: VULNERABILITY
RISK    : 4.0/10  |  SEVERITY: MEDIUM  |  TLP: TLP:GREEN
CVEs    : None identified
IOCs    : cve: 1
REPORT  : https://cyberbivash.blogspot.com/2026/03/important-red-hat-security-advisory.html
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
