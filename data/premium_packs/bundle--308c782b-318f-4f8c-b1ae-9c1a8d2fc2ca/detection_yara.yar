// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-28696 Craft affected by IDOR via GraphQL parseRefs
// STIX ID  : bundle--308c782b-318f-4f8c-b1ae-9c1a8d2fc2ca
// Scenario : VULNERABILITY
// Generated: 2026-03-04T16:38:29.834732 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_28696_Craft_affected_by_IDOR_via_GraphQL__Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-28696 Craft affected by IDOR via GraphQL parseRefs"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-04"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
