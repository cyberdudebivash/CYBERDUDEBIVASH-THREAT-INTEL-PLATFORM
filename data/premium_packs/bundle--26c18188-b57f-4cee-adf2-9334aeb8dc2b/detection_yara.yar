// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Arkanix Stealer a C  Python infostealer
// STIX ID  : bundle--26c18188-b57f-4cee-adf2-9334aeb8dc2b
// Scenario : MALWARE
// Generated: 2026-02-28T13:00:54.679073 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Arkanix_Stealer_a_C__Python_infostealer_Generic {
    meta:
        description = "Generic behavioral detection for: Arkanix Stealer a C  Python infostealer"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-28"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
