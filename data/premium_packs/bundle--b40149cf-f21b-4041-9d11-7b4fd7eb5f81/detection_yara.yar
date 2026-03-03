// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Silver Dragon Targets Organizations in Southeast Asia and Europe
// STIX ID  : bundle--b40149cf-f21b-4041-9d11-7b4fd7eb5f81
// Scenario : GENERIC
// Generated: 2026-03-03T16:41:20.710789 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Silver_Dragon_Targets_Organizations_in_Southeast_A_Generic {
    meta:
        description = "Generic behavioral detection for: Silver Dragon Targets Organizations in Southeast Asia and Europe"
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
