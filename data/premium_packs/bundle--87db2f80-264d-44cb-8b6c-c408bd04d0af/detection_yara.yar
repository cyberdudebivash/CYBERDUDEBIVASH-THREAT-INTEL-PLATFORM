// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-3463 xlnt-community xlnt Compound Document binaryhpp append heap-based 
// STIX ID  : bundle--87db2f80-264d-44cb-8b6c-c408bd04d0af
// Scenario : VULNERABILITY
// Generated: 2026-03-03T12:41:00.710510 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_3463_xlnt_community_xlnt_Compound_Documen_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-3463 xlnt-community xlnt Compound Document binaryhpp append heap-based "
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-03"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
