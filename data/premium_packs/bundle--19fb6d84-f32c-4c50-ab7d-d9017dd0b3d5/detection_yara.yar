// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Astra Linux -   linux-510 linux-61 linux linux-515
// STIX ID  : bundle--19fb6d84-f32c-4c50-ab7d-d9017dd0b3d5
// Scenario : GENERIC
// Generated: 2026-03-10T08:37:44.515697 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Astra_Linux_____linux_510_linux_61_linux_linux_515_Generic {
    meta:
        description = "Generic behavioral detection for: Astra Linux -   linux-510 linux-61 linux linux-515"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-10"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
