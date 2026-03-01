// ================================================================
// CyberDudeBivash SENTINEL APEX v20.0 — YARA Rules
// Threat   : CVE-2026-28559 - wpForo Forum 2414 Information Disclosure via Global RSS Feed
// STIX ID  : bundle--92582c0e-eded-4895-a98b-cb5b8b6be0e8
// Scenario : VULNERABILITY
// Generated: 2026-03-01T01:15:58.581432 UTC
// Authority: CyberDudeBivash Pvt. Ltd. | intel.cyberdudebivash.com
// ================================================================

rule CDB_CVE_2026_28559___wpForo_Forum_2414_Information_Dis_Generic {
    meta:
        description = "Generic behavioral detection for: CVE-2026-28559 - wpForo Forum 2414 Information Disclosure via Global RSS Feed"
        author = "CyberDudeBivash GOC (Automated)"
        date = "2026-03-01"
        reference = "https://intel.cyberdudebivash.com"
    strings:
        $ps_enc = "powershell -enc" ascii wide nocase
        $ps_iex = "IEX(" ascii wide nocase
        $dl     = "DownloadFile" ascii wide nocase
        $wc     = "WebClient" ascii wide nocase
    condition:
        2 of them
}
