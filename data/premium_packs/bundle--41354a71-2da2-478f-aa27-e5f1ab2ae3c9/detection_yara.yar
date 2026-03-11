// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3824 - WellChooseIFTOP - Open redirect
// STIX ID  : bundle--41354a71-2da2-478f-aa27-e5f1ab2ae3c9
// Scenario : VULNERABILITY
// Generated: 2026-03-11T07:31:48.417122 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3824___WellChooseIFTOP___Open_redirect_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3824 - WellChooseIFTOP - Open redirect"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-11"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
