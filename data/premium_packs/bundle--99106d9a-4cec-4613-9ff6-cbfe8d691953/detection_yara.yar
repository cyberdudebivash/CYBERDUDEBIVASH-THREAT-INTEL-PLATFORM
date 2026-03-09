// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : 2025 The Untold Stories of Check Point Research
// STIX ID  : bundle--99106d9a-4cec-4613-9ff6-cbfe8d691953
// Scenario : GENERIC
// Generated: 2026-03-09T05:20:29.902489 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_2025_The_Untold_Stories_of_Check_Point_Research_Generic {
    meta:
        description = "Generic behavioral detection for: 2025 The Untold Stories of Check Point Research"
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
