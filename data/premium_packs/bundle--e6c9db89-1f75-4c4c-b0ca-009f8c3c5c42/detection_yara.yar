// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : New Report The Digital Footprints of Many Executives Can Leave Their Companies S
// STIX ID  : bundle--e6c9db89-1f75-4c4c-b0ca-009f8c3c5c42
// Scenario : GENERIC
// Generated: 2026-02-24T14:34:53.104307 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_New_Report_The_Digital_Footprints_of_Many_Executiv_Generic {
    meta:
        description = "Generic behavioral detection for: New Report The Digital Footprints of Many Executives Can Leave Their Companies S"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-02-24"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
