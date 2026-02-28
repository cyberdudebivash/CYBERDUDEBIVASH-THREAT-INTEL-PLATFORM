// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Metasploit Wrap-Up 02272026
// STIX ID  : bundle--9619f30c-06a1-4096-95a0-472e3fe98dea
// Scenario : GENERIC
// Generated: 2026-02-28T02:28:17.962867 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Metasploit_Wrap_Up_02272026_Generic {
    meta:
        description = "Generic behavioral detection for: Metasploit Wrap-Up 02272026"
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
