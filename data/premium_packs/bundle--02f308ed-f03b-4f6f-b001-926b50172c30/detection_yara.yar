// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-29121 sbinip Binary given SETUID Permissions on IDC SFX2100 Leading to 
// STIX ID  : bundle--02f308ed-f03b-4f6f-b001-926b50172c30
// Scenario : VULNERABILITY
// Generated: 2026-03-05T01:22:47.470591 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_29121_sbinip_Binary_given_SETUID_Permissi_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-29121 sbinip Binary given SETUID Permissions on IDC SFX2100 Leading to "
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-05"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
