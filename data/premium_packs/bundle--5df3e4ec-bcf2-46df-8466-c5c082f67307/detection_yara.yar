// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30920 - OneUptime has broken access control in GitHub App installation 
// STIX ID  : bundle--5df3e4ec-bcf2-46df-8466-c5c082f67307
// Scenario : VULNERABILITY
// Generated: 2026-03-10T01:19:19.425555 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30920___OneUptime_has_broken_access_contr_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30920 - OneUptime has broken access control in GitHub App installation "
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-10"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
