// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Silver Dragon Targets Organizations in Southeast Asia and Europe
// STIX ID  : bundle--65c5d11a-c0ea-4bbc-9ab6-5cbc8894a916
// Scenario : GENERIC
// Generated: 2026-03-09T20:30:30.242798 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Silver_Dragon_Targets_Organizations_in_Southeast_A_Generic {
    meta:
        description = "Generic behavioral detection for: Silver Dragon Targets Organizations in Southeast Asia and Europe"
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
