// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Arkanix Stealer a C  Python infostealer
// STIX ID  : bundle--a50f0fd2-591f-428c-9d86-53b923721a3f
// Scenario : MALWARE
// Generated: 2026-03-13T08:02:06.557923 UTC
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
