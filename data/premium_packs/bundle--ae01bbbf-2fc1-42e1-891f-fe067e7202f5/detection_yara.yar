// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : SentinelOne Intelligence Brief Iranian Cyber Activity Outlook
// STIX ID  : bundle--ae01bbbf-2fc1-42e1-891f-fe067e7202f5
// Scenario : GENERIC
// Generated: 2026-03-13T19:37:34.224037 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_SentinelOne_Intelligence_Brief_Iranian_Cyber_Activ_Generic {
    meta:
        description = "Generic behavioral detection for: SentinelOne Intelligence Brief Iranian Cyber Activity Outlook"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-13"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
