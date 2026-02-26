// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-1198 - SQL Injection in SIMPLEERP
// STIX ID  : bundle--ae458314-52f5-42df-8451-c6ce88681e49
// Scenario : VULNERABILITY
// Generated: 2026-02-26T13:23:31.326272 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_1198___SQL_Injection_in_SIMPLEERP_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-1198 - SQL Injection in SIMPLEERP"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-26"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
