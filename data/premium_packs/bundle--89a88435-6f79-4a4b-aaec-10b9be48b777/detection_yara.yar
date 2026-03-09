// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : 2nd March  Threat Intelligence Report
// STIX ID  : bundle--89a88435-6f79-4a4b-aaec-10b9be48b777
// Scenario : GENERIC
// Generated: 2026-03-09T01:23:34.080131 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_2nd_March__Threat_Intelligence_Report_Generic {
    meta:
        description = "Generic behavioral detection for: 2nd March  Threat Intelligence Report"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-09"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
