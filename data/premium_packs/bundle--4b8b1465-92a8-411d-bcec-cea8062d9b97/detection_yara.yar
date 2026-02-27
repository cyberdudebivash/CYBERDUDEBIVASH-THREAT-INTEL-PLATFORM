// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Stan Ghouls targeting Russia and Uzbekistan with NetSupport RAT
// STIX ID  : bundle--4b8b1465-92a8-411d-bcec-cea8062d9b97
// Scenario : MALWARE
// Generated: 2026-02-27T13:15:09.890920 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Stan_Ghouls_targeting_Russia_and_Uzbekistan_with_N_Generic {
    meta:
        description = "Generic behavioral detection for: Stan Ghouls targeting Russia and Uzbekistan with NetSupport RAT"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-27"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
