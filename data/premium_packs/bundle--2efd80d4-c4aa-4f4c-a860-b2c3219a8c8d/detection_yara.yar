// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Iran-linked MuddyWater deploys Dindoor malware against US organizations
// STIX ID  : bundle--2efd80d4-c4aa-4f4c-a860-b2c3219a8c8d
// Scenario : MALWARE
// Generated: 2026-03-06T20:54:58.265754 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Iran_linked_MuddyWater_deploys_Dindoor_malware_aga_Generic {
    meta:
        description = "Generic behavioral detection for: Iran-linked MuddyWater deploys Dindoor malware against US organizations"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-06"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
