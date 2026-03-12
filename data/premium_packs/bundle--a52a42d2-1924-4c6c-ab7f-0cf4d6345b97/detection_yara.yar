// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-31988 - yauzl 320 - Denial of Service via Off-by-One Error in NTFS Time
// STIX ID  : bundle--a52a42d2-1924-4c6c-ab7f-0cf4d6345b97
// Scenario : VULNERABILITY
// Generated: 2026-03-12T01:18:46.816920 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_31988___yauzl_320___Denial_of_Service_via_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-31988 - yauzl 320 - Denial of Service via Off-by-One Error in NTFS Time"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-12"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
