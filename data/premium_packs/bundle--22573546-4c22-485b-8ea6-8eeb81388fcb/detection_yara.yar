// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-30863 - Parse Server JWT audience validation bypass in Google Apple and
// STIX ID  : bundle--22573546-4c22-485b-8ea6-8eeb81388fcb
// Scenario : APT
// Generated: 2026-03-07T20:20:06.436827 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_30863___Parse_Server_JWT_audience_validat_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-30863 - Parse Server JWT audience validation bypass in Google Apple and"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-07"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
