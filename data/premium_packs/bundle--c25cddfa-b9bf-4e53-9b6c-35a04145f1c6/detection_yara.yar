// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30847 - Wekan Credential Leak via notificationUsers Publication Exposes
// STIX ID  : bundle--c25cddfa-b9bf-4e53-9b6c-35a04145f1c6
// Scenario : VULNERABILITY
// Generated: 2026-03-06T22:18:27.111387 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30847___Wekan_Credential_Leak_via_notific_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30847 - Wekan Credential Leak via notificationUsers Publication Exposes"
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
