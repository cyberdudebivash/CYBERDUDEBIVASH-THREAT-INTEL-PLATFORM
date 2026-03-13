// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Who is the Kimwolf Botmaster Dort
// STIX ID  : bundle--45b80f97-cef2-4cae-ab1a-5649a273db1f
// Scenario : GENERIC
// Generated: 2026-03-13T08:44:33.928374 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Who_is_the_Kimwolf_Botmaster_Dort_Generic {
    meta:
        description = "Generic behavioral detection for: Who is the Kimwolf Botmaster Dort"
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
