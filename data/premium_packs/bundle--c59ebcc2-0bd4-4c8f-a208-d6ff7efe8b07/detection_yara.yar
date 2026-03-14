// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Google fixed two new actively exploited flaws in the Chrome browser
// STIX ID  : bundle--c59ebcc2-0bd4-4c8f-a208-d6ff7efe8b07
// Scenario : GENERIC
// Generated: 2026-03-14T03:14:52.302184 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Google_fixed_two_new_actively_exploited_flaws_in_t_Generic {
    meta:
        description = "Generic behavioral detection for: Google fixed two new actively exploited flaws in the Chrome browser"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-14"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
