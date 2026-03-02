// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : Cyber Essentials Plus in 2026 Strengthened Controls UK Cyber Reality  How Qualys
// STIX ID  : bundle--4a63ab1f-98a3-4d81-87a8-b96fe9bbbef2
// Scenario : GENERIC
// Generated: 2026-03-02T20:29:52.128726 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_Cyber_Essentials_Plus_in_2026_Strengthened_Control_Generic {
    meta:
        description = "Generic behavioral detection for: Cyber Essentials Plus in 2026 Strengthened Controls UK Cyber Reality  How Qualys"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-02"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
