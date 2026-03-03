// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : 2nd March  Threat Intelligence Report
// STIX ID  : bundle--5742a48c-2ff1-4292-835e-e9862b9f2bd2
// Scenario : GENERIC
// Generated: 2026-03-03T08:18:00.697053 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_2nd_March__Threat_Intelligence_Report_Generic {
    meta:
        description = "Generic behavioral detection for: 2nd March  Threat Intelligence Report"
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
