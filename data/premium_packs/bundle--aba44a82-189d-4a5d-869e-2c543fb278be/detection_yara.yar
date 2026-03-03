// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-29022
// STIX ID  : bundle--aba44a82-189d-4a5d-869e-2c543fb278be
// Scenario : VULNERABILITY
// Generated: 2026-03-03T20:29:19.780675 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_29022_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-29022"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-03"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
