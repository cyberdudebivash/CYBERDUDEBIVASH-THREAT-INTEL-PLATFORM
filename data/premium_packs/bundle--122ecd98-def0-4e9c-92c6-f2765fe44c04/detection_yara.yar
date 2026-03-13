// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Arkanix Stealer a C  Python infostealer
// STIX ID  : bundle--122ecd98-def0-4e9c-92c6-f2765fe44c04
// Scenario : MALWARE
// Generated: 2026-03-13T23:02:32.630173 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Arkanix_Stealer_a_C__Python_infostealer_Generic {
    meta:
        description = "Generic behavioral detection for: Arkanix Stealer a C  Python infostealer"
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
