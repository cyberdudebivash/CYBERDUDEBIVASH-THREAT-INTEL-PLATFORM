// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Reading White House President Trumps Cyber Strategy for America March 2026
// STIX ID  : bundle--08e5c73f-cbfb-44ac-a965-b1e23a56036b
// Scenario : MALWARE
// Generated: 2026-03-07T18:04:54.469418 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Reading_White_House_President_Trumps_Cyber_Strateg_Generic {
    meta:
        description = "Generic behavioral detection for: Reading White House President Trumps Cyber Strategy for America March 2026"
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
