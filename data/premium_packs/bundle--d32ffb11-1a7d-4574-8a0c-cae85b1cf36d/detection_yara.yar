// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Who is the Kimwolf Botmaster Dort
// STIX ID  : bundle--d32ffb11-1a7d-4574-8a0c-cae85b1cf36d
// Scenario : GENERIC
// Generated: 2026-03-14T01:55:11.731826 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Who_is_the_Kimwolf_Botmaster_Dort_Generic {
    meta:
        description = "Generic behavioral detection for: Who is the Kimwolf Botmaster Dort"
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
